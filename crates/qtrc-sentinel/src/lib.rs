//! # qtrc-sentinel: HYDRA-X Sentinel
//!
//! A recovery and rate-limiting layer for Quantar Network accounts.
//!
//! HYDRA-X requires ML-DSA-87 AND SLH-DSA-SHA2-256s, which defends against
//! one signature family falling. Sentinel adds protection for a different
//! failure: the owner's main key leaking. It also limits, but does not
//! eliminate, the damage if both signature families fall at once (see
//! "Limits" below).
//!
//! ## Mechanism
//!
//! 1. An account stores a recovery commitment
//!    `R = SHA3-256(DOM || chain_id || account || recovery_address || cold_dest || salt)`,
//!    every field length-prefixed.
//! 2. Outflows within `allowance_per_window` over a sliding window of
//!    `delay_blocks` settle at once. Anything above waits `delay_blocks`
//!    in public.
//! 3. During the delay, a recovery opens `R`, proves control of the
//!    recovery key with a HYDRA-X signature over a message bound to the
//!    chain, the account and the current `R`, cancels every pending
//!    operation and moves the whole balance to `cold_dest`. Later credits
//!    to the account are forwarded to `cold_dest`.
//! 4. Replacing `R` is delayed as well, so a thief holding the main key
//!    cannot swap the guardian silently. At most one rotation is pending.
//! 5. The rate-limit policy can change, asymmetrically: a change that is
//!    at least as strict on both axes (allowance not higher, delay not
//!    shorter) applies at once, since a thief gains nothing from it. Any
//!    other change waits the *current* `delay_blocks` in public, like a
//!    large transfer, so the guardian can veto it. At most one policy
//!    change is pending.
//!
//! ## What is and is not guaranteed
//!
//! * Redirecting a recovery to any address other than the committed
//!   `cold_dest` needs a SHA3-256 preimage (second preimage once the
//!   opening is known), generically about 2^256 classical work and about
//!   2^128 quantum work. This holds even against an adversary that forges
//!   every signature scheme in use.
//! * It does not protect funds once they sit in `cold_dest`: that is an
//!   ordinary account guarded by the same signature schemes. Use a
//!   never-used address so its public key is not yet exposed.
//! * If both ML-DSA-87 and SLH-DSA fall, Sentinel caps immediate loss and
//!   buys time for a hard fork. It is not a substitute for one.
//! * The recovery public key is off chain until recovery, but any
//!   [`watchtower::RecoveryKit`] contains it together with the full
//!   opening. Whoever holds a kit can force a recovery (griefing, not
//!   theft).
//!
//! ## Integration notes
//!
//! The state machine is pure and deterministic. Consensus integration
//! needs:
//!
//! * transaction types for set-guardian, rotation, recovery and finalize;
//! * [`Vault::charge_fee`] for the fee of every transaction the account
//!   itself sends, **except recovery**: the recovery fee must be paid by
//!   whoever submits it (owner's other wallet or watchtower), otherwise a
//!   thief who reserves the whole balance blocks the recovery;
//! * before executing a recovery, [`ensure_recovery_target`] on the
//!   `cold_dest` account: a recovery may not point at an already recovered
//!   vault. Every forwarding edge then points at a vault with no outgoing
//!   edge, so the forwarding graph can never contain a cycle;
//! * credits routed through [`Vault::credit`]; when it returns
//!   [`Credit::Forward`], resolve the final recipient with
//!   [`resolve_forward`] (terminates because of the rule above, and is
//!   capped at [`MAX_FORWARD_HOPS`] as a second line of defence);
//! * [`Vault::validate`] on every state load. It checks internal
//!   consistency only: the rotation `epoch` and the other fields must be
//!   covered by the consensus state root, since nothing inside one vault
//!   can tell a tampered epoch from a real one;
//! * `overflow-checks = true` in release builds.
//!
//! `finalize` takes no authorization on purpose: once a time lock expires,
//! anyone may settle it. Policy changes go through [`Vault::request_policy`]
//! and are time-locked unless they only tighten.

pub mod watchtower;

use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub type Hash = [u8; 32];

const DOM_COMMIT: &[u8] = b"QTR/SENTINEL/COMMIT/v2";
/// Domain of the legacy recovery digest. Kept only so blocks from before
/// the v3 activation replay unchanged.
const DOM_RECOVER_V2: &[u8] = b"QTR/SENTINEL/RECOVER/v2";
const DOM_RECOVER: &[u8] = b"QTR/SENTINEL/RECOVER/v3";

/// Smallest allowed time lock. Must exceed realistic inclusion latency.
pub const MIN_DELAY_BLOCKS: u64 = 10;
/// Largest allowed time lock, keeps `height + delay` far from overflow.
pub const MAX_DELAY_BLOCKS: u64 = 10_000_000;
/// Maximum queued operations per account (bounds state and work).
pub const MAX_PENDING: usize = 64;
/// Maximum allowance outflows remembered per window. Once full, further
/// outflows are queued instead of settling.
pub const MAX_RECENT: usize = 64;
/// How many `delay_blocks` windows of finalized outflows are remembered,
/// so watchtowers can see thefts carried out one transfer at a time.
pub const HISTORY_WINDOWS: u64 = 4;
/// Maximum finalized outflows remembered (oldest dropped first).
pub const MAX_HISTORY: usize = 512;
/// Upper bound for [`resolve_forward`].
pub const MAX_FORWARD_HOPS: usize = 64;

// An attacker can finalize at most MAX_PENDING transfers per window. The
// history must outlast that over its whole span, or a large theft could be
// evicted by filler before the watchtower sees it.
const _: () = assert!(MAX_HISTORY as u64 > MAX_PENDING as u64 * (HISTORY_WINDOWS + 1));

/// Length-prefixed absorb, so `"ab"||"c"` and `"a"||"bc"` never collide.
fn absorb(h: &mut Sha3_256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

/// Recovery commitment, computed offline by the wallet. Bound to one chain
/// and one account, so an opening never transfers to another vault.
/// Pass `qtrc_common::tx::CHAIN_ID` as `chain_id`.
#[must_use]
pub fn recovery_commitment(
    chain_id: &[u8],
    account: &Address,
    recovery_address: &Address,
    cold_dest: &Address,
    salt: &[u8; 32],
) -> Hash {
    let mut h = Sha3_256::new();
    absorb(&mut h, DOM_COMMIT);
    absorb(&mut h, chain_id);
    absorb(&mut h, &account.0);
    absorb(&mut h, &recovery_address.0);
    absorb(&mut h, &cold_dest.0);
    absorb(&mut h, salt);
    h.finalize().into()
}

/// Length-prefixed append, the byte-string twin of [`absorb`].
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
    buf.extend_from_slice(field);
}

/// Which encoding of the recovery message the chain verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryFormat {
    /// Before the v3 activation: the recovery key signed a 32-byte SHA3-256
    /// digest of the fields. Accepted only so old blocks replay.
    LegacyDigest,
    /// From the v3 activation on: the recovery key signs the full
    /// length-prefixed encoding, with no pre-hash outside SLH-DSA.
    Full,
}

/// Message the recovery key signs. Bound to the chain, the account, the
/// current commitment and the guardian epoch (number of finalized
/// rotations), so a recovery signature dies when the guardian is rotated,
/// even if a later rotation returns to the same commitment, and never
/// replays across networks or accounts.
///
/// These are the full bytes, not a digest of them. SLH-DSA-SHA2-256s and
/// ML-DSA-87 hash the message internally at their own security level;
/// signing a 32-byte SHA3-256 digest instead caps collision resistance at
/// about 128 bits, below the category 5 the parameter sets are chosen for,
/// and is the external pre-hash FIPS 205 section 10.2 asks to avoid with
/// short digests on the 256-bit sets.
#[must_use]
pub fn recovery_message(chain_id: &[u8], account: &Address, commitment: &Hash, epoch: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(5 * 8 + DOM_RECOVER.len() + chain_id.len() + 32 + 32 + 8);
    push_field(&mut m, DOM_RECOVER);
    push_field(&mut m, chain_id);
    push_field(&mut m, &account.0);
    push_field(&mut m, commitment);
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

/// The pre-v3 recovery message: a SHA3-256 digest of the fields. Only for
/// verifying recoveries in blocks from before the v3 activation; never sign
/// with it.
#[must_use]
pub fn recovery_message_legacy(chain_id: &[u8], account: &Address, commitment: &Hash, epoch: u64) -> Hash {
    let mut h = Sha3_256::new();
    absorb(&mut h, DOM_RECOVER_V2);
    absorb(&mut h, chain_id);
    absorb(&mut h, &account.0);
    absorb(&mut h, commitment);
    h.update(epoch.to_le_bytes());
    h.finalize().into()
}

/// The recovery message in the encoding `format` asks for.
#[must_use]
pub fn recovery_message_for(
    format: RecoveryFormat,
    chain_id: &[u8],
    account: &Address,
    commitment: &Hash,
    epoch: u64,
) -> Vec<u8> {
    match format {
        RecoveryFormat::Full => recovery_message(chain_id, account, commitment, epoch),
        RecoveryFormat::LegacyDigest => recovery_message_legacy(chain_id, account, commitment, epoch).to_vec(),
    }
}

/// Proof that the holder of the recovery key authorized a recovery.
///
/// Production uses [`HydraXSignature`]; the trait lets the state machine be
/// tested without paying for SLH-DSA signing on every case.
pub trait RecoveryProof {
    /// Address of the key that produced the proof.
    fn signer(&self) -> Address;
    /// Whether the proof is a valid signature over `msg`.
    fn verify(&self, msg: &[u8]) -> bool;
}

impl RecoveryProof for HydraXSignature {
    fn signer(&self) -> Address {
        self.signer_address()
    }
    fn verify(&self, msg: &[u8]) -> bool {
        HydraXSignature::verify(self, msg).is_ok()
    }
}

/// Validated rate-limit parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    delay_blocks: u64,
    allowance_per_window: u64,
}

impl Policy {
    /// # Errors
    /// [`SentinelError::InvalidPolicy`] if `delay_blocks` is outside
    /// `MIN_DELAY_BLOCKS..=MAX_DELAY_BLOCKS`.
    pub fn new(delay_blocks: u64, allowance_per_window: u64) -> Result<Self, SentinelError> {
        let p = Self { delay_blocks, allowance_per_window };
        p.check()?;
        Ok(p)
    }

    fn check(self) -> Result<(), SentinelError> {
        if (MIN_DELAY_BLOCKS..=MAX_DELAY_BLOCKS).contains(&self.delay_blocks) {
            Ok(())
        } else {
            Err(SentinelError::InvalidPolicy)
        }
    }

    #[must_use]
    pub fn delay_blocks(&self) -> u64 {
        self.delay_blocks
    }

    #[must_use]
    pub fn allowance_per_window(&self) -> u64 {
        self.allowance_per_window
    }

    /// Whether `self` is at least as strict as `current` on both axes:
    /// no higher allowance and no shorter delay. Only such a change may
    /// skip the time lock.
    #[must_use]
    pub fn is_at_least_as_strict_as(&self, current: &Policy) -> bool {
        self.allowance_per_window <= current.allowance_per_window && self.delay_blocks >= current.delay_blocks
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    Transfer { to: Address, amount: u64 },
    RotateCommitment { new_commitment: Hash },
    /// Loosening policy change, waiting for its time lock.
    ChangePolicy { policy: Policy },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub id: u64,
    pub kind: PendingKind,
    pub created_height: u64,
    pub unlock_height: u64,
}

/// An outflow that settled immediately under the allowance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outflow {
    pub height: u64,
    pub to: Address,
    pub amount: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SentinelError {
    #[error("insufficient available balance")]
    InsufficientFunds,
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("account has no recovery commitment")]
    NoCommitment,
    #[error("recovery data does not open the stored commitment")]
    CommitmentMismatch,
    #[error("recovery signature is invalid")]
    BadRecoverySignature,
    #[error("account was already recovered")]
    Recovered,
    #[error("no pending operation with that id")]
    NotFound,
    #[error("pending operation is still time-locked")]
    StillLocked,
    #[error("too many pending operations")]
    TooManyPending,
    #[error("policy parameters out of range")]
    InvalidPolicy,
    #[error("cold_dest must differ from the account")]
    SelfRecovery,
    #[error("cold_dest is an already recovered vault")]
    DestinationRecovered,
    #[error("credit forwarding exceeded the hop limit")]
    ForwardLoop,
    #[error("vault state violates an invariant")]
    InvalidState,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("outflows in the current window exceed the new allowance; wait for the window to pass")]
    AllowanceInUse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Left immediately, within the allowance.
    Settled { to: Address, amount: u64 },
    /// Queued behind the time lock.
    Queued { id: u64, unlock_height: u64 },
    /// First guardian set, applied at once (nothing to protect yet).
    CommitmentSet,
    /// Stricter (or equal) policy, applied at once.
    PolicyApplied,
}

/// Where an incoming credit ends up.
#[derive(Debug, PartialEq, Eq)]
pub enum Credit {
    /// Added to this vault.
    Held,
    /// Vault is recovered: consensus must credit this address instead.
    Forward(Address),
}

/// Per-account Sentinel state.
///
/// Invariants, checked by [`Vault::validate`]:
/// `reserved == sum of pending transfers <= balance`, at most
/// [`MAX_PENDING`] pending transfers plus one pending rotation and one
/// pending policy change (each has its own slot, so a flood of transfers
/// cannot block them),
/// consistent unlock heights, and a clean state after recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vault {
    address: Address,
    balance: u64,
    reserved: u64,
    commitment: Option<Hash>,
    pending: Vec<Pending>,
    recent: Vec<Outflow>,
    #[serde(default)]
    finalized: Vec<Outflow>,
    recovered_to: Option<Address>,
    policy: Policy,
    next_id: u64,
    #[serde(default)]
    epoch: u64,
}

/// Consensus check before any recovery: `cold_dest` must not be a vault
/// that was already recovered. Pass the destination's vault, if it has one.
///
/// # Errors
/// [`SentinelError::DestinationRecovered`].
pub fn ensure_recovery_target(dest: Option<&Vault>) -> Result<(), SentinelError> {
    if dest.is_some_and(Vault::is_recovered) {
        Err(SentinelError::DestinationRecovered)
    } else {
        Ok(())
    }
}

/// Follow forwarding from `start` to the account that finally holds a
/// credit. `forward_of` returns the forward target of a recovered vault,
/// or `None` for an account that keeps credits.
///
/// # Errors
/// [`SentinelError::ForwardLoop`] after [`MAX_FORWARD_HOPS`] hops.
pub fn resolve_forward(
    start: &Address,
    mut forward_of: impl FnMut(&Address) -> Option<Address>,
) -> Result<Address, SentinelError> {
    let mut at = start.clone();
    for _ in 0..MAX_FORWARD_HOPS {
        match forward_of(&at) {
            Some(next) => at = next,
            None => return Ok(at),
        }
    }
    Err(SentinelError::ForwardLoop)
}

impl Vault {
    #[must_use]
    pub fn new(address: Address, balance: u64, commitment: Option<Hash>, policy: Policy) -> Self {
        Self {
            address,
            balance,
            reserved: 0,
            commitment,
            pending: Vec::new(),
            recent: Vec::new(),
            finalized: Vec::new(),
            recovered_to: None,
            policy,
            next_id: 0,
            epoch: 0,
        }
    }

    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }
    #[must_use]
    pub fn balance(&self) -> u64 {
        self.balance
    }
    #[must_use]
    pub fn reserved(&self) -> u64 {
        self.reserved
    }
    #[must_use]
    pub fn commitment(&self) -> Option<&Hash> {
        self.commitment.as_ref()
    }
    #[must_use]
    pub fn pending(&self) -> &[Pending] {
        &self.pending
    }
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }
    /// Number of finalized guardian rotations. Part of the recovery message.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    #[must_use]
    pub fn is_recovered(&self) -> bool {
        self.recovered_to.is_some()
    }
    #[must_use]
    pub fn recovered_to(&self) -> Option<&Address> {
        self.recovered_to.as_ref()
    }

    /// Point the forwarding of an already recovered vault somewhere else.
    /// Consensus uses it for path compression: when the vault this one
    /// forwards to is itself recovered, every vault pointing at it is
    /// redirected to the new destination, so forwarding is always a single
    /// hop. No effect on a vault that is not recovered.
    pub fn redirect_forward(&mut self, to: Address) {
        if self.recovered_to.is_some() {
            self.recovered_to = Some(to);
        }
    }

    /// Balance not locked by pending transfers.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.balance.saturating_sub(self.reserved)
    }

    /// Allowance outflows still inside the sliding window ending at `height`.
    pub fn recent_outflows(&self, height: u64) -> impl Iterator<Item = &Outflow> {
        let delay = self.policy.delay_blocks;
        self.recent.iter().filter(move |o| o.height.saturating_add(delay) > height)
    }

    /// Finalized (time-locked) outflows within the last
    /// `HISTORY_WINDOWS * delay_blocks` blocks before `height`.
    pub fn finalized_outflows(&self, height: u64) -> impl Iterator<Item = &Outflow> {
        let span = self.history_span();
        self.finalized.iter().filter(move |o| o.height.saturating_add(span) > height)
    }

    fn history_span(&self) -> u64 {
        self.policy.delay_blocks.saturating_mul(HISTORY_WINDOWS)
    }

    fn pending_transfers(&self) -> usize {
        self.pending.iter().filter(|p| matches!(p.kind, PendingKind::Transfer { .. })).count()
    }

    fn ensure_active(&self) -> Result<(), SentinelError> {
        if self.is_recovered() { Err(SentinelError::Recovered) } else { Ok(()) }
    }

    fn prune_recent(&mut self, height: u64) {
        let delay = self.policy.delay_blocks;
        self.recent.retain(|o| o.height.saturating_add(delay) > height);
        let span = self.history_span();
        self.finalized.retain(|o| o.height.saturating_add(span) > height);
    }

    fn next_unlock(&self, height: u64) -> Result<u64, SentinelError> {
        height.checked_add(self.policy.delay_blocks).ok_or(SentinelError::Overflow)
    }

    /// Route an incoming credit.
    ///
    /// # Errors
    /// [`SentinelError::Overflow`] if the balance would overflow.
    pub fn credit(&mut self, amount: u64) -> Result<Credit, SentinelError> {
        if let Some(to) = &self.recovered_to {
            return Ok(Credit::Forward(to.clone()));
        }
        self.balance = self.balance.checked_add(amount).ok_or(SentinelError::Overflow)?;
        Ok(Credit::Held)
    }

    /// Debit a protocol fee (burned) from the available balance. Consensus
    /// calls this for every transaction the account sends, before the
    /// transaction's own effect.
    ///
    /// # Errors
    /// [`SentinelError::Recovered`] or [`SentinelError::InsufficientFunds`].
    pub fn charge_fee(&mut self, fee: u64) -> Result<(), SentinelError> {
        self.ensure_active()?;
        if fee > self.available() {
            return Err(SentinelError::InsufficientFunds);
        }
        self.balance -= fee;
        Ok(())
    }

    /// Outflow authorized by the main key. The HYDRA-X signature is checked
    /// by consensus before this is called.
    ///
    /// # Errors
    /// Recovered, zero amount, insufficient funds, too many pending.
    pub fn transfer(&mut self, height: u64, to: Address, amount: u64) -> Result<Outcome, SentinelError> {
        self.ensure_active()?;
        if amount == 0 {
            return Err(SentinelError::ZeroAmount);
        }
        if amount > self.available() {
            return Err(SentinelError::InsufficientFunds);
        }
        // Without a guardian nobody can veto, so delaying would only hurt.
        if self.commitment.is_none() {
            self.balance -= amount;
            return Ok(Outcome::Settled { to, amount });
        }
        self.prune_recent(height);
        let spent: u64 = self.recent.iter().map(|o| o.amount).fold(0, u64::saturating_add);
        let fits = spent.checked_add(amount).is_some_and(|s| s <= self.policy.allowance_per_window)
            && self.recent.len() < MAX_RECENT;
        if fits {
            self.balance -= amount;
            self.recent.push(Outflow { height, to: to.clone(), amount });
            return Ok(Outcome::Settled { to, amount });
        }
        // Compute everything fallible before mutating.
        if self.pending_transfers() >= MAX_PENDING {
            return Err(SentinelError::TooManyPending);
        }
        let unlock_height = self.next_unlock(height)?;
        let id = self.next_id;
        self.next_id += 1;
        self.reserved += amount;
        self.pending.push(Pending {
            id,
            kind: PendingKind::Transfer { to, amount },
            created_height: height,
            unlock_height,
        });
        Ok(Outcome::Queued { id, unlock_height })
    }

    /// Replace the recovery commitment. Delayed whenever a guardian already
    /// exists, so the current guardian can veto a hostile swap. A new
    /// request for a different commitment replaces any rotation already
    /// pending and restarts the delay; repeating the same request keeps
    /// the original deadline. Repeated replacement means the main key is compromised; the
    /// correct response is recovery, which watchtowers do automatically
    /// for any rotation they were not told to expect.
    ///
    /// # Errors
    /// Recovered, overflow.
    pub fn request_rotation(&mut self, height: u64, new_commitment: Hash) -> Result<Outcome, SentinelError> {
        self.ensure_active()?;
        if self.commitment.is_none() {
            self.commitment = Some(new_commitment);
            return Ok(Outcome::CommitmentSet);
        }
        // Re-requesting the rotation already pending is a no-op, so nobody
        // can push its deadline back by repeating it.
        if let Some(p) = self.pending.iter().find(|p| {
            matches!(&p.kind, PendingKind::RotateCommitment { new_commitment: c } if *c == new_commitment)
        }) {
            return Ok(Outcome::Queued { id: p.id, unlock_height: p.unlock_height });
        }
        // The rotation has its own slot, outside MAX_PENDING.
        let unlock_height = self.next_unlock(height)?;
        self.pending.retain(|p| !matches!(p.kind, PendingKind::RotateCommitment { .. }));
        let id = self.next_id;
        self.next_id += 1;
        self.pending.push(Pending {
            id,
            kind: PendingKind::RotateCommitment { new_commitment },
            created_height: height,
            unlock_height,
        });
        Ok(Outcome::Queued { id, unlock_height })
    }

    /// Change the rate-limit policy.
    ///
    /// A policy at least as strict as the current one on both axes applies
    /// at once. Anything else (including a mix, such as a lower allowance
    /// with a shorter delay) is queued behind the *current* delay, so a
    /// thief cannot shorten the veto window in the same step that loosens
    /// it. A new request replaces any policy change already pending;
    /// repeating the pending one keeps its deadline.
    ///
    /// Every pending operation is re-timed to `created_height + delay` of
    /// the policy in force, so tightening the delay also extends what is
    /// already queued.
    ///
    /// # Errors
    /// Recovered, overflow, or [`SentinelError::AllowanceInUse`] when the
    /// new allowance is below what already left in the current window.
    pub fn request_policy(&mut self, height: u64, new: Policy) -> Result<Outcome, SentinelError> {
        self.ensure_active()?;
        new.check()?;
        // Without a guardian nobody can veto, so delaying would only hurt.
        if self.commitment.is_none() || new.is_at_least_as_strict_as(&self.policy) {
            self.prune_recent(height);
            let mut next = self.clone();
            next.pending.retain(|p| !matches!(p.kind, PendingKind::ChangePolicy { .. }));
            next.apply_policy(height, new)?;
            *self = next;
            return Ok(Outcome::PolicyApplied);
        }
        if let Some(p) = self.pending.iter().find(|p| {
            matches!(&p.kind, PendingKind::ChangePolicy { policy } if *policy == new)
        }) {
            return Ok(Outcome::Queued { id: p.id, unlock_height: p.unlock_height });
        }
        let unlock_height = self.next_unlock(height)?;
        self.pending.retain(|p| !matches!(p.kind, PendingKind::ChangePolicy { .. }));
        let id = self.next_id;
        self.next_id += 1;
        self.pending.push(Pending {
            id,
            kind: PendingKind::ChangePolicy { policy: new },
            created_height: height,
            unlock_height,
        });
        Ok(Outcome::Queued { id, unlock_height })
    }

    /// Install `policy` at `height` and re-time every pending operation to
    /// it. The window spend is measured with the new policy's window, the
    /// one it will be enforced over. Callers apply this to a clone and
    /// keep it only on success.
    fn apply_policy(&mut self, height: u64, policy: Policy) -> Result<(), SentinelError> {
        let unlocks = self
            .pending
            .iter()
            .map(|p| p.created_height.checked_add(policy.delay_blocks).ok_or(SentinelError::Overflow))
            .collect::<Result<Vec<_>, _>>()?;
        for (p, unlock) in self.pending.iter_mut().zip(unlocks) {
            p.unlock_height = unlock;
        }
        self.policy = policy;
        self.prune_recent(height);
        let spent = self.recent.iter().try_fold(0u64, |a, o| a.checked_add(o.amount));
        if spent.is_none_or(|s| s > policy.allowance_per_window) {
            return Err(SentinelError::AllowanceInUse);
        }
        Ok(())
    }

    /// Settle a pending operation whose time lock expired. Returns the
    /// transfer, if the operation was one.
    ///
    /// # Errors
    /// Recovered, not found, still locked, invariant violation.
    pub fn finalize(&mut self, height: u64, id: u64) -> Result<Option<(Address, u64)>, SentinelError> {
        self.ensure_active()?;
        let idx = self.pending.iter().position(|p| p.id == id).ok_or(SentinelError::NotFound)?;
        if height < self.pending[idx].unlock_height {
            return Err(SentinelError::StillLocked);
        }
        match &self.pending[idx].kind {
            PendingKind::Transfer { to, amount } => {
                let to = to.clone();
                let amount = *amount;
                let reserved = self.reserved.checked_sub(amount).ok_or(SentinelError::InvalidState)?;
                let balance = self.balance.checked_sub(amount).ok_or(SentinelError::InvalidState)?;
                self.pending.remove(idx);
                self.reserved = reserved;
                self.balance = balance;
                self.prune_recent(height);
                if self.finalized.len() >= MAX_HISTORY {
                    self.finalized.remove(0);
                }
                self.finalized.push(Outflow { height, to: to.clone(), amount });
                Ok(Some((to, amount)))
            }
            PendingKind::RotateCommitment { new_commitment } => {
                self.commitment = Some(*new_commitment);
                self.pending.remove(idx);
                self.epoch += 1;
                Ok(None)
            }
            PendingKind::ChangePolicy { policy } => {
                let policy = *policy;
                self.prune_recent(height);
                let mut next = self.clone();
                next.pending.remove(idx);
                next.apply_policy(height, policy)?;
                *self = next;
                Ok(None)
            }
        }
    }

    /// Check a recovery without changing state (used by watchtowers to
    /// detect a stale kit before they need it). Verifies the current
    /// ([`RecoveryFormat::Full`]) message.
    ///
    /// # Errors
    /// Recovered, no commitment, self recovery, mismatch, bad signature.
    pub fn check_recovery<P: RecoveryProof>(
        &self,
        chain_id: &[u8],
        cold_dest: &Address,
        salt: &[u8; 32],
        proof: &P,
    ) -> Result<(), SentinelError> {
        self.check_recovery_with(RecoveryFormat::Full, chain_id, cold_dest, salt, proof)
    }

    /// [`Vault::check_recovery`] against the message encoding the chain
    /// uses at the height being checked.
    ///
    /// # Errors
    /// Same as [`Vault::check_recovery`].
    pub fn check_recovery_with<P: RecoveryProof>(
        &self,
        format: RecoveryFormat,
        chain_id: &[u8],
        cold_dest: &Address,
        salt: &[u8; 32],
        proof: &P,
    ) -> Result<(), SentinelError> {
        self.ensure_active()?;
        let expected = self.commitment.ok_or(SentinelError::NoCommitment)?;
        // A vault forwarding to itself would make credits loop forever.
        if *cold_dest == self.address {
            return Err(SentinelError::SelfRecovery);
        }
        let opened = recovery_commitment(chain_id, &self.address, &proof.signer(), cold_dest, salt);
        if expected != opened {
            return Err(SentinelError::CommitmentMismatch);
        }
        let msg = recovery_message_for(format, chain_id, &self.address, &expected, self.epoch);
        if !proof.verify(&msg) {
            return Err(SentinelError::BadRecoverySignature);
        }
        Ok(())
    }

    /// Emergency recovery: cancels every pending operation, moves the
    /// entire balance to the committed `cold_dest` and forwards later
    /// credits there. Terminal.
    ///
    /// # Errors
    /// Same as [`Vault::check_recovery`].
    pub fn recover<P: RecoveryProof>(
        &mut self,
        chain_id: &[u8],
        cold_dest: &Address,
        salt: &[u8; 32],
        proof: &P,
    ) -> Result<(Address, u64), SentinelError> {
        self.recover_with(RecoveryFormat::Full, chain_id, cold_dest, salt, proof)
    }

    /// [`Vault::recover`] against the message encoding the chain uses at
    /// the height being applied.
    ///
    /// # Errors
    /// Same as [`Vault::check_recovery`].
    pub fn recover_with<P: RecoveryProof>(
        &mut self,
        format: RecoveryFormat,
        chain_id: &[u8],
        cold_dest: &Address,
        salt: &[u8; 32],
        proof: &P,
    ) -> Result<(Address, u64), SentinelError> {
        self.check_recovery_with(format, chain_id, cold_dest, salt, proof)?;
        self.pending.clear();
        self.recent.clear();
        self.finalized.clear();
        self.reserved = 0;
        let amount = self.balance;
        self.balance = 0;
        self.commitment = None;
        self.recovered_to = Some(cold_dest.clone());
        Ok((cold_dest.clone(), amount))
    }

    /// Canonical, versioned byte encoding of the whole vault, used to
    /// commit it in the chain's state root. Independent of serde and
    /// bincode, so changing how the vault is stored can never change the
    /// state root of past blocks. The exhaustive destructuring makes any new
    /// field a compile error here until it is given an encoding (and the
    /// version bumped). Locked by a fixed test vector.
    #[must_use]
    pub fn canonical_encoding(&self) -> Vec<u8> {
        fn u64le(out: &mut Vec<u8>, v: u64) {
            out.extend_from_slice(&v.to_le_bytes());
        }
        fn outflows(out: &mut Vec<u8>, list: &[Outflow]) {
            u64le(out, list.len() as u64);
            for Outflow { height, to, amount } in list {
                u64le(out, *height);
                out.extend_from_slice(&to.0);
                u64le(out, *amount);
            }
        }
        let Vault {
            address,
            balance,
            reserved,
            commitment,
            pending,
            recent,
            finalized,
            recovered_to,
            policy: Policy { delay_blocks, allowance_per_window },
            next_id,
            epoch,
        } = self;
        let mut out = b"QTR/VAULT/v1".to_vec();
        out.extend_from_slice(&address.0);
        u64le(&mut out, *balance);
        u64le(&mut out, *reserved);
        match commitment {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(c);
            }
            None => out.push(0),
        }
        u64le(&mut out, pending.len() as u64);
        for Pending { id, kind, created_height, unlock_height } in pending {
            u64le(&mut out, *id);
            u64le(&mut out, *created_height);
            u64le(&mut out, *unlock_height);
            match kind {
                PendingKind::Transfer { to, amount } => {
                    out.push(1);
                    out.extend_from_slice(&to.0);
                    u64le(&mut out, *amount);
                }
                PendingKind::RotateCommitment { new_commitment } => {
                    out.push(2);
                    out.extend_from_slice(new_commitment);
                }
                // New tag: vaults that never queued a policy change encode
                // exactly as before, so past state roots are unchanged.
                PendingKind::ChangePolicy { policy: Policy { delay_blocks, allowance_per_window } } => {
                    out.push(3);
                    u64le(&mut out, *delay_blocks);
                    u64le(&mut out, *allowance_per_window);
                }
            }
        }
        outflows(&mut out, recent);
        outflows(&mut out, finalized);
        match recovered_to {
            Some(a) => {
                out.push(1);
                out.extend_from_slice(&a.0);
            }
            None => out.push(0),
        }
        u64le(&mut out, *delay_blocks);
        u64le(&mut out, *allowance_per_window);
        u64le(&mut out, *next_id);
        u64le(&mut out, *epoch);
        out
    }

    /// Verify every invariant. Call after deserializing a vault from
    /// storage or from the network.
    ///
    /// # Errors
    /// [`SentinelError::InvalidPolicy`] or [`SentinelError::InvalidState`].
    pub fn validate(&self) -> Result<(), SentinelError> {
        self.policy.check()?;
        let bad = SentinelError::InvalidState;
        let mut sum: u64 = 0;
        let mut rotations = 0;
        let mut changes = 0;
        for (i, p) in self.pending.iter().enumerate() {
            let expected_unlock = p.created_height.checked_add(self.policy.delay_blocks);
            if p.id >= self.next_id
                || self.pending[..i].iter().any(|q| q.id == p.id)
                || expected_unlock != Some(p.unlock_height)
            {
                return Err(bad);
            }
            match p.kind {
                PendingKind::Transfer { amount, .. } => {
                    sum = sum.checked_add(amount).ok_or(SentinelError::InvalidState)?;
                }
                PendingKind::RotateCommitment { .. } => rotations += 1,
                PendingKind::ChangePolicy { policy } => {
                    policy.check()?;
                    changes += 1;
                }
            }
        }
        let recent_sum = self.recent.iter().try_fold(0u64, |a, o| a.checked_add(o.amount));
        let ok = sum == self.reserved
            && self.reserved <= self.balance
            && self.pending.len() - rotations - changes <= MAX_PENDING
            && rotations <= 1
            && changes <= 1
            && self.recent.len() <= MAX_RECENT
            && self.finalized.len() <= MAX_HISTORY
            && recent_sum.is_some_and(|s| s <= self.policy.allowance_per_window)
            && self.recent.iter().chain(&self.finalized).all(|o| o.amount > 0)
            && (self.commitment.is_some() || (self.pending.is_empty() && self.recent.is_empty()))
            && (!self.is_recovered()
                || (self.balance == 0
                    && self.commitment.is_none()
                    && self.pending.is_empty()
                    && self.recent.is_empty()
                    && self.finalized.is_empty()));
        if ok { Ok(()) } else { Err(bad) }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Fast stand-in for a HYDRA-X signature: `sig = SHA3(signer || msg)`.
    /// Exercises the state machine only; the real scheme is tested below.
    #[derive(Clone, Debug)]
    pub struct MockProof {
        pub signer: Address,
        pub sig: Hash,
    }

    impl MockProof {
        pub fn sign(signer: &Address, msg: &[u8]) -> Self {
            let mut h = Sha3_256::new();
            h.update(signer.0);
            h.update(msg);
            Self { signer: signer.clone(), sig: h.finalize().into() }
        }
    }

    impl RecoveryProof for MockProof {
        fn signer(&self) -> Address {
            self.signer.clone()
        }
        fn verify(&self, msg: &[u8]) -> bool {
            Self::sign(&self.signer, msg).sig == self.sig
        }
    }

    pub const CHAIN: &[u8] = b"quantar-testnet-2";
    pub const SALT: [u8; 32] = [7u8; 32];
    pub fn me() -> Address { Address([1u8; 32]) }
    pub fn cold() -> Address { Address([9u8; 32]) }
    pub fn thief() -> Address { Address([6u8; 32]) }
    pub fn rec_key() -> Address { Address([4u8; 32]) }

    pub fn policy() -> Policy {
        Policy::new(100, 50).unwrap()
    }

    pub fn commit(salt: &[u8; 32]) -> Hash {
        recovery_commitment(CHAIN, &me(), &rec_key(), &cold(), salt)
    }

    pub fn vault() -> Vault {
        Vault::new(me(), 1_000, Some(commit(&SALT)), policy())
    }

    /// Recovery proof for a given commitment and guardian epoch.
    pub fn proof_for(c: &Hash, epoch: u64) -> MockProof {
        MockProof::sign(&rec_key(), &recovery_message(CHAIN, &me(), c, epoch))
    }

    pub fn rec_proof() -> MockProof {
        proof_for(&commit(&SALT), 0)
    }

    pub fn queued(o: Outcome) -> (u64, u64) {
        match o {
            Outcome::Queued { id, unlock_height } => (id, unlock_height),
            other => panic!("expected Queued, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use qtrc_crypto::HydraXKeypair;

    // ---- basic flow -------------------------------------------------------

    #[test]
    fn small_transfer_settles_immediately() {
        let mut v = vault();
        assert_eq!(v.transfer(10, thief(), 30).unwrap(), Outcome::Settled { to: thief(), amount: 30 });
        assert_eq!(v.balance(), 970);
        v.validate().unwrap();
    }

    #[test]
    fn allowance_exact_fit_settles() {
        let mut v = vault();
        assert!(matches!(v.transfer(10, thief(), 50).unwrap(), Outcome::Settled { .. }));
        assert!(matches!(v.transfer(10, thief(), 1).unwrap(), Outcome::Queued { .. }));
    }

    #[test]
    fn allowance_cannot_be_split_to_drain() {
        let mut v = vault();
        v.transfer(10, thief(), 30).unwrap();
        v.transfer(11, thief(), 20).unwrap();
        assert!(matches!(v.transfer(12, thief(), 1).unwrap(), Outcome::Queued { .. }));
    }

    #[test]
    fn sliding_window_boundaries() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap();
        // Still inside the window at 10 + 100 - 1.
        assert!(matches!(v.transfer(109, thief(), 1).unwrap(), Outcome::Queued { .. }));
        // Expired exactly at 10 + 100.
        assert!(matches!(v.transfer(110, thief(), 50).unwrap(), Outcome::Settled { .. }));
    }

    /// Regression M1: the old fixed window allowed 2x allowance in two
    /// consecutive blocks across a boundary chosen by the attacker.
    #[test]
    fn no_double_allowance_across_boundary() {
        let mut v = vault();
        v.transfer(99, thief(), 50).unwrap();
        assert!(matches!(v.transfer(100, thief(), 50).unwrap(), Outcome::Queued { .. }));
        assert!(matches!(v.transfer(198, thief(), 1).unwrap(), Outcome::Queued { .. }));
    }

    #[test]
    fn zero_amount_rejected() {
        let mut v = vault();
        assert_eq!(v.transfer(10, thief(), 0), Err(SentinelError::ZeroAmount));
    }

    #[test]
    fn recent_outflow_list_is_bounded() {
        let mut v = Vault::new(me(), 1_000, Some(commit(&SALT)), Policy::new(100, 500).unwrap());
        for _ in 0..MAX_RECENT {
            assert!(matches!(v.transfer(10, thief(), 1).unwrap(), Outcome::Settled { .. }));
        }
        assert!(matches!(v.transfer(10, thief(), 1).unwrap(), Outcome::Queued { .. }));
    }

    #[test]
    fn no_guardian_means_no_delay() {
        let mut v = Vault::new(me(), 1_000, None, policy());
        assert!(matches!(v.transfer(10, thief(), 900).unwrap(), Outcome::Settled { .. }));
    }

    #[test]
    fn large_transfer_waits_then_settles() {
        let mut v = vault();
        let (id, unlock) = queued(v.transfer(10, thief(), 500).unwrap());
        assert_eq!(v.finalize(unlock - 1, id), Err(SentinelError::StillLocked));
        assert_eq!(v.finalize(unlock, id).unwrap(), Some((thief(), 500)));
        assert_eq!((v.balance(), v.reserved()), (500, 0));
        assert_eq!(v.finalize(unlock, id), Err(SentinelError::NotFound));
        v.validate().unwrap();
    }

    #[test]
    fn finalize_unknown_id() {
        let mut v = vault();
        assert_eq!(v.finalize(10, 42), Err(SentinelError::NotFound));
    }

    #[test]
    fn reserved_funds_cannot_be_double_spent() {
        let mut v = vault();
        v.transfer(10, thief(), 900).unwrap();
        assert_eq!(v.transfer(11, thief(), 200), Err(SentinelError::InsufficientFunds));
    }

    // ---- fees and balance invariants (regression A3) ----------------------

    #[test]
    fn fee_cannot_touch_reserved_funds() {
        let mut v = vault();
        let (id, unlock) = queued(v.transfer(10, thief(), 1_000).unwrap());
        assert_eq!(v.charge_fee(10), Err(SentinelError::InsufficientFunds));
        assert_eq!(v.available(), 0);
        assert_eq!(v.finalize(unlock, id).unwrap(), Some((thief(), 1_000)));
        assert_eq!(v.balance(), 0);
        v.validate().unwrap();
    }

    #[test]
    fn fee_is_debited_from_available() {
        let mut v = vault();
        v.transfer(10, thief(), 900).unwrap();
        v.charge_fee(10).unwrap();
        assert_eq!((v.balance(), v.reserved(), v.available()), (990, 900, 90));
        v.validate().unwrap();
    }

    #[test]
    fn credit_overflow_rejected() {
        let mut v = Vault::new(me(), u64::MAX, None, policy());
        assert_eq!(v.credit(1), Err(SentinelError::Overflow));
    }

    // ---- policy validation (regression M3) --------------------------------

    #[test]
    fn policy_rejects_out_of_range_delay() {
        assert_eq!(Policy::new(0, 50), Err(SentinelError::InvalidPolicy));
        assert_eq!(Policy::new(MIN_DELAY_BLOCKS - 1, 50), Err(SentinelError::InvalidPolicy));
        assert_eq!(Policy::new(u64::MAX, 50), Err(SentinelError::InvalidPolicy));
        assert!(Policy::new(MIN_DELAY_BLOCKS, 0).is_ok());
    }

    #[test]
    fn overflow_does_not_leave_funds_locked() {
        let mut v = vault();
        assert_eq!(v.transfer(u64::MAX - 5, thief(), 500), Err(SentinelError::Overflow));
        assert_eq!((v.reserved(), v.pending().len()), (0, 0));
        v.validate().unwrap();
    }

    #[test]
    fn pending_queue_is_bounded() {
        let mut v = Vault::new(me(), 1_000_000, Some(commit(&SALT)), Policy::new(100, 0).unwrap());
        for i in 0..MAX_PENDING as u64 {
            v.transfer(10 + i, thief(), 1).unwrap();
        }
        assert_eq!(v.transfer(99, thief(), 1), Err(SentinelError::TooManyPending));
        v.validate().unwrap();
    }

    // ---- recovery ---------------------------------------------------------

    #[test]
    fn recovery_vetoes_stolen_key_drain() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap(); // allowance lost, but bounded
        let (id, _) = queued(v.transfer(11, thief(), 950).unwrap());
        let (to, amount) = v.recover(CHAIN, &cold(), &SALT, &rec_proof()).unwrap();
        assert_eq!((to, amount), (cold(), 950));
        assert!(v.pending().is_empty());
        assert_eq!(v.finalize(500, id), Err(SentinelError::Recovered));
        v.validate().unwrap();
    }

    #[test]
    fn recover_without_guardian() {
        let mut v = Vault::new(me(), 1_000, None, policy());
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &rec_proof()), Err(SentinelError::NoCommitment));
    }

    #[test]
    fn forged_recovery_cannot_redirect_funds() {
        let mut v = vault();
        assert_eq!(v.recover(CHAIN, &thief(), &SALT, &rec_proof()), Err(SentinelError::CommitmentMismatch));
    }

    #[test]
    fn wrong_recovery_key_rejected() {
        let mut v = vault();
        let c = commit(&SALT);
        let other = MockProof::sign(&thief(), &recovery_message(CHAIN, &me(), &c, 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &other), Err(SentinelError::CommitmentMismatch));
    }

    #[test]
    fn bad_signature_rejected() {
        let mut v = vault();
        let mut p = rec_proof();
        p.sig[0] ^= 1;
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &p), Err(SentinelError::BadRecoverySignature));
    }

    #[test]
    fn cross_chain_replay_rejected() {
        let mut v = vault();
        let p = MockProof::sign(&rec_key(), &recovery_message(b"quantar-mainnet", &me(), &commit(&SALT), 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &p), Err(SentinelError::BadRecoverySignature));
    }

    #[test]
    fn opening_does_not_transfer_to_other_account() {
        let other = Address([5u8; 32]);
        // Same (recovery key, cold, salt) reused for a second account.
        let c_other = recovery_commitment(CHAIN, &other, &rec_key(), &cold(), &SALT);
        assert_ne!(c_other, commit(&SALT));
        let mut v = Vault::new(other, 1_000, Some(c_other), policy());
        // Proof made for `me` does not recover `other`.
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &rec_proof()), Err(SentinelError::BadRecoverySignature));
    }

    #[test]
    fn recovery_is_terminal_and_forwards_credits() {
        let mut v = vault();
        v.recover(CHAIN, &cold(), &SALT, &rec_proof()).unwrap();
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &rec_proof()), Err(SentinelError::Recovered));
        // Regression M4: later deposits are not frozen.
        assert_eq!(v.credit(777).unwrap(), Credit::Forward(cold()));
        assert_eq!(v.balance(), 0);
        assert_eq!(v.transfer(1, cold(), 1), Err(SentinelError::Recovered));
        assert_eq!(v.charge_fee(1), Err(SentinelError::Recovered));
        v.validate().unwrap();
    }

    // ---- rotation ---------------------------------------------------------

    #[test]
    fn thief_cannot_swap_guardian_silently() {
        let mut v = vault();
        let evil = recovery_commitment(CHAIN, &me(), &thief(), &thief(), &SALT);
        let (id, unlock) = queued(v.request_rotation(10, evil).unwrap());
        assert_eq!(v.finalize(unlock - 1, id), Err(SentinelError::StillLocked));
        v.recover(CHAIN, &cold(), &SALT, &rec_proof()).unwrap();
        assert_eq!(v.finalize(unlock, id), Err(SentinelError::Recovered));
    }

    #[test]
    fn legit_rotation_applies_after_delay() {
        let mut v = vault();
        let new_c = commit(&[3u8; 32]);
        let (id, unlock) = queued(v.request_rotation(10, new_c).unwrap());
        v.finalize(unlock, id).unwrap();
        assert_eq!(v.commitment(), Some(&new_c));
    }

    /// Regression B1: an abandoned rotation must not resurrect.
    #[test]
    fn newer_rotation_replaces_older() {
        let mut v = vault();
        let r2 = commit(&[2u8; 32]);
        let r3 = commit(&[3u8; 32]);
        let (a, _) = queued(v.request_rotation(10, r2).unwrap());
        let (b, unlock_b) = queued(v.request_rotation(20, r3).unwrap());
        assert_eq!(v.pending().len(), 1);
        v.finalize(unlock_b, b).unwrap();
        assert_eq!(v.finalize(unlock_b + 1, a), Err(SentinelError::NotFound));
        assert_eq!(v.commitment(), Some(&r3));
        v.validate().unwrap();
    }

    /// Regression B2: proofs for the old guardian die with the rotation.
    #[test]
    fn rotation_revokes_old_proofs() {
        let mut v = vault();
        let old = rec_proof();
        let new_salt = [3u8; 32];
        let (id, unlock) = queued(v.request_rotation(10, commit(&new_salt)).unwrap());
        v.finalize(unlock, id).unwrap();
        assert_eq!(v.recover(CHAIN, &cold(), &new_salt, &old), Err(SentinelError::BadRecoverySignature));
        assert!(v.recover(CHAIN, &cold(), &new_salt, &proof_for(&commit(&new_salt), 1)).is_ok());
    }

    // ---- encoding and persistence -----------------------------------------

    #[test]
    fn length_prefix_prevents_field_shifting() {
        let mut a = Sha3_256::new();
        absorb(&mut a, b"ab");
        absorb(&mut a, b"c");
        let mut b = Sha3_256::new();
        absorb(&mut b, b"a");
        absorb(&mut b, b"bc");
        assert_ne!(a.finalize(), b.finalize());
    }

    #[test]
    fn commit_and_recover_domains_are_separate() {
        let c = commit(&SALT);
        assert_ne!(c.to_vec(), recovery_message(CHAIN, &me(), &c, 0));
        assert_ne!(c, recovery_message_legacy(CHAIN, &me(), &c, 0));
    }

    #[test]
    fn recovery_message_is_the_full_encoding_not_a_digest() {
        let c = commit(&SALT);
        let m = recovery_message(CHAIN, &me(), &c, 7);
        let mut want = Vec::new();
        for f in [DOM_RECOVER, CHAIN, &me().0[..], &c[..]] {
            want.extend_from_slice(&(f.len() as u64).to_le_bytes());
            want.extend_from_slice(f);
        }
        want.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(m, want);
        assert!(m.len() > 64, "must not be a short digest");
    }

    #[test]
    fn recovery_v3_and_legacy_never_share_a_signature() {
        let c = commit(&SALT);
        assert_ne!(
            recovery_message(CHAIN, &me(), &c, 0),
            recovery_message_legacy(CHAIN, &me(), &c, 0).to_vec()
        );
        assert_ne!(DOM_RECOVER, DOM_RECOVER_V2);
    }

    #[test]
    fn each_format_only_accepts_its_own_message() {
        let c = commit(&SALT);
        let mut v = vault();
        let full = MockProof::sign(&rec_key(), &recovery_message(CHAIN, &me(), &c, 0));
        let legacy = MockProof::sign(&rec_key(), &recovery_message_legacy(CHAIN, &me(), &c, 0));
        assert_eq!(
            v.check_recovery_with(RecoveryFormat::Full, CHAIN, &cold(), &SALT, &legacy),
            Err(SentinelError::BadRecoverySignature),
            "a pre-v3 kit must not open a vault after the activation"
        );
        assert_eq!(
            v.check_recovery_with(RecoveryFormat::LegacyDigest, CHAIN, &cold(), &SALT, &full),
            Err(SentinelError::BadRecoverySignature)
        );
        assert!(v.check_recovery_with(RecoveryFormat::LegacyDigest, CHAIN, &cold(), &SALT, &legacy).is_ok());
        assert!(v.recover_with(RecoveryFormat::Full, CHAIN, &cold(), &SALT, &full).is_ok());
    }

    #[test]
    fn recovery_message_vector() {
        // Pins the v3 wire format: changing it is a consensus change.
        let c = [0x11u8; 32];
        let m = recovery_message(b"quantar-testnet-2", &Address([0x22u8; 32]), &c, 3);
        let digest: [u8; 32] = Sha3_256::digest(&m).into();
        assert_eq!(m.len(), 8 + DOM_RECOVER.len() + 8 + 17 + 8 + 32 + 8 + 32 + 8);
        assert_eq!(hex_of(&digest), RECOVERY_V3_VECTOR, "canonical recovery message changed");
    }

    #[test]
    fn vault_survives_serde_roundtrip() {
        let mut v = vault();
        v.transfer(10, thief(), 30).unwrap();
        v.transfer(11, thief(), 500).unwrap();
        let json = serde_json::to_string(&v).unwrap();
        let back: Vault = serde_json::from_str(&json).unwrap();
        back.validate().unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn validate_rejects_tampered_state() {
        let mut v = vault();
        v.transfer(10, thief(), 500).unwrap();
        let json = serde_json::to_string(&v).unwrap().replace("\"reserved\":500", "\"reserved\":5000");
        let bad: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(bad.validate(), Err(SentinelError::InvalidState));
        let json = serde_json::to_string(&v).unwrap().replace("\"delay_blocks\":100", "\"delay_blocks\":0");
        let bad: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(bad.validate(), Err(SentinelError::InvalidPolicy));
    }

    /// Pseudo-random operation sequences must never break the invariants.
    #[test]
    fn invariants_hold_under_random_ops() {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), Policy::new(20, 300).unwrap());
            let mut h = 0u64;
            for _ in 0..300 {
                h += next() % 5;
                let ids: Vec<u64> = v.pending().iter().map(|p| p.id).collect();
                match next() % 6 {
                    0 | 1 => { let _ = v.transfer(h, thief(), next() % 700); }
                    2 => { let _ = v.charge_fee(next() % 50); }
                    3 => { let _ = v.credit(next() % 400); }
                    4 if !ids.is_empty() => { let _ = v.finalize(h, ids[usize::try_from(next() % ids.len() as u64).unwrap()]); }
                    _ => { let _ = v.request_rotation(h, commit(&[(next() % 3) as u8; 32])); }
                }
                v.validate().unwrap();
            }
        }
    }

    // ---- audit round 2 ----------------------------------------------------

    /// Regression N2: a vault must not forward credits to itself.
    #[test]
    fn self_recovery_rejected() {
        let c = recovery_commitment(CHAIN, &me(), &rec_key(), &me(), &SALT);
        let mut v = Vault::new(me(), 1_000, Some(c), policy());
        let p = proof_for(&c, 0);
        assert_eq!(v.recover(CHAIN, &me(), &SALT, &p), Err(SentinelError::SelfRecovery));
        assert!(!v.is_recovered());
    }

    /// Regression N4: a flood of transfers cannot block the guardian rotation.
    #[test]
    fn rotation_has_reserved_slot() {
        let mut v = Vault::new(me(), 1_000_000, Some(commit(&SALT)), Policy::new(100, 0).unwrap());
        for i in 0..MAX_PENDING as u64 {
            v.transfer(10 + i, thief(), 1).unwrap();
        }
        assert_eq!(v.transfer(99, thief(), 1), Err(SentinelError::TooManyPending));
        assert!(matches!(v.request_rotation(99, commit(&[3u8; 32])).unwrap(), Outcome::Queued { .. }));
        v.validate().unwrap();
    }

    /// Regression N6: returning to an old commitment does not revive old proofs.
    #[test]
    fn epoch_kills_proofs_after_round_trip() {
        let mut v = vault();
        let old = rec_proof();
        let (a, ua) = queued(v.request_rotation(10, commit(&[3u8; 32])).unwrap());
        v.finalize(ua, a).unwrap();
        let (b, ub) = queued(v.request_rotation(ua, commit(&SALT)).unwrap());
        v.finalize(ub, b).unwrap();
        assert_eq!(v.commitment(), Some(&commit(&SALT)));
        assert_eq!(v.epoch(), 2);
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &old), Err(SentinelError::BadRecoverySignature));
        assert!(v.recover(CHAIN, &cold(), &SALT, &proof_for(&commit(&SALT), 2)).is_ok());
    }

    #[test]
    fn finalized_transfers_are_remembered_then_expire() {
        let mut v = vault();
        let (id, u) = queued(v.transfer(10, thief(), 300).unwrap());
        v.finalize(u, id).unwrap();
        assert_eq!(v.finalized_outflows(u).count(), 1);
        let span = 100 * HISTORY_WINDOWS;
        assert_eq!(v.finalized_outflows(u + span - 1).count(), 1);
        assert_eq!(v.finalized_outflows(u + span).count(), 0);
    }

    #[test]
    fn finalized_history_is_bounded() {
        let mut v = Vault::new(me(), 1_000_000, Some(commit(&SALT)), Policy::new(100, 0).unwrap());
        for _ in 0..(MAX_HISTORY + 10) {
            let (id, u) = queued(v.transfer(10, thief(), 1).unwrap());
            v.finalize(u, id).unwrap();
        }
        assert_eq!(v.finalized_outflows(110).count(), MAX_HISTORY);
        v.validate().unwrap();
    }

    /// Regression N7: validate catches tampered unlock heights and a dirty
    /// recovered state.
    #[test]
    fn validate_catches_more_tampering() {
        let mut v = vault();
        v.transfer(10, thief(), 500).unwrap();
        let json = serde_json::to_string(&v).unwrap().replace("\"unlock_height\":110", "\"unlock_height\":0");
        let bad: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(bad.validate(), Err(SentinelError::InvalidState));

        let mut r = vault();
        r.transfer(10, thief(), 30).unwrap();
        r.recover(CHAIN, &cold(), &SALT, &rec_proof()).unwrap();
        let c = hex_bytes(&commit(&SALT));
        let json = serde_json::to_string(&r).unwrap().replace("\"commitment\":null", &format!("\"commitment\":{c}"));
        let bad: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(bad.validate(), Err(SentinelError::InvalidState));
    }

    fn hex_bytes(h: &Hash) -> String {
        serde_json::to_string(h).unwrap()
    }

    #[test]
    fn invariants_hold_with_recovery_in_the_mix() {
        let mut recoveries = 0;
        let mut seed: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), Policy::new(20, 300).unwrap());
            let mut h = 0u64;
            for _ in 0..200 {
                h += next() % 5;
                let ids: Vec<u64> = v.pending().iter().map(|p| p.id).collect();
                match next() % 8 {
                    0 | 1 => { let _ = v.transfer(h, thief(), next() % 700); }
                    2 => { let _ = v.charge_fee(next() % 50); }
                    3 => {
                        let before = v.balance();
                        match v.credit(next() % 400) {
                            Ok(Credit::Forward(to)) => { assert_eq!(to, cold()); assert_eq!(v.balance(), before); }
                            Ok(Credit::Held) | Err(_) => {}
                        }
                    }
                    4 if !ids.is_empty() => { let _ = v.finalize(h, ids[usize::try_from(next() % ids.len() as u64).unwrap()]); }
                    5 => { let _ = v.request_rotation(h, commit(&[(next() % 3) as u8; 32])); }
                    6 if next() % 20 == 0 => {
                        if let Some(c) = v.commitment().copied() {
                            // Commitments in play: SALT, or [b; 32] for b in 0..3.
                            let salt = (0u8..3).map(|b| [b; 32]).find(|x| commit(x) == c).unwrap_or(SALT);
                            if v.recover(CHAIN, &cold(), &salt, &proof_for(&c, v.epoch())).is_ok() {
                                recoveries += 1;
                            }
                        }
                    }
                    _ => {}
                }
                v.validate().unwrap();
            }
        }
        assert!(recoveries > 20, "only {recoveries} recoveries exercised");
    }

    // ---- audit round 3 ----------------------------------------------------

    /// Regression R6: two vaults cannot end up forwarding to each other,
    /// and forwarding chains resolve to the final holder.
    #[test]
    fn forwarding_graph_stays_acyclic() {
        let b = Address([5u8; 32]);
        let cb = recovery_commitment(CHAIN, &b, &rec_key(), &me(), &SALT);
        let va = vault();
        let mut vb = Vault::new(b.clone(), 1_000, Some(cb), policy());
        let pb = MockProof::sign(&rec_key(), &recovery_message(CHAIN, &b, &cb, 0));

        // A recovers into B (B still active): allowed.
        let ca_cold = recovery_commitment(CHAIN, &me(), &rec_key(), &b, &SALT);
        let mut va2 = Vault::new(me(), 1_000, Some(ca_cold), policy());
        ensure_recovery_target(Some(&vb)).unwrap();
        va2.recover(CHAIN, &b, &SALT, &proof_for(&ca_cold, 0)).unwrap();

        // B now wants to recover into A, which is recovered: rejected.
        assert_eq!(ensure_recovery_target(Some(&va2)), Err(SentinelError::DestinationRecovered));
        // Into a plain active account it is fine.
        ensure_recovery_target(Some(&va)).unwrap();
        ensure_recovery_target(None).unwrap();
        vb.recover(CHAIN, &me(), &SALT, &pb).unwrap();

        // A credit to va2 forwards to B, which forwards to `me`'s address
        // (here an active account): the resolver follows to the end.
        let fwd = |a: &Address| -> Option<Address> {
            if *a == me() { None } else if *a == b { Some(me()) } else { None }
        };
        assert_eq!(resolve_forward(&b, fwd).unwrap(), me());
        let looping = |a: &Address| -> Option<Address> { Some(if *a == me() { b.clone() } else { me() }) };
        assert_eq!(resolve_forward(&me(), looping), Err(SentinelError::ForwardLoop));
    }

    /// Regression R2: repeating the pending rotation cannot delay it.
    #[test]
    fn repeated_rotation_keeps_deadline() {
        let mut v = vault();
        let mine = commit(&[3u8; 32]);
        let (id, unlock) = queued(v.request_rotation(10, mine).unwrap());
        for h in [50, 100, 109] {
            assert_eq!(queued(v.request_rotation(h, mine).unwrap()), (id, unlock));
        }
        v.finalize(unlock, id).unwrap();
        assert_eq!(v.epoch(), 1);
    }

    /// R3: state written before `finalized`/`epoch` existed still loads.
    #[test]
    fn old_state_without_history_fields_loads() {
        let v = vault();
        let mut json: serde_json::Value = serde_json::to_value(&v).unwrap();
        let obj = json.as_object_mut().unwrap();
        obj.remove("finalized");
        obj.remove("epoch");
        let back: Vault = serde_json::from_value(json).unwrap();
        back.validate().unwrap();
        assert_eq!(back.epoch(), 0);
    }

    /// Locks the canonical encoding used by the chain's state root. If this
    /// fails, past state roots would change: do not update the vector, add a
    /// new encoding version instead.
    #[test]
    fn canonical_encoding_test_vector() {
        let mut v = vault();
        v.transfer(10, thief(), 30).unwrap();
        v.transfer(11, thief(), 500).unwrap();
        queued(v.request_rotation(12, commit(&[3u8; 32])).unwrap());
        let enc = v.canonical_encoding();
        let digest: [u8; 32] = Sha3_256::digest(&enc).into();
        assert_eq!(hex_of(&digest), VAULT_VECTOR, "canonical vault encoding changed");
        assert!(enc.starts_with(b"QTR/VAULT/v1"));
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const RECOVERY_V3_VECTOR: &str = "98b8e6686d6e5c2e3dc31443d8e135caf108bdbb6cce89bc3d430aeb32501e53";
    const VAULT_VECTOR: &str = "b62cde142bcd35f49c3f1d52cc072d85a3342cfd2e465c40f58428734a0394ee";

    // ---- policy change ----------------------------------------------------

    fn pol(delay: u64, allowance: u64) -> Policy {
        Policy::new(delay, allowance).unwrap()
    }

    #[test]
    fn stricter_policy_applies_at_once() {
        let mut v = vault();
        assert_eq!(v.request_policy(10, pol(200, 20)).unwrap(), Outcome::PolicyApplied);
        assert_eq!(v.policy(), pol(200, 20));
        assert!(v.pending().is_empty());
        v.validate().unwrap();
        // The new allowance is in force right away.
        assert!(matches!(v.transfer(11, thief(), 30).unwrap(), Outcome::Queued { unlock_height: 211, .. }));
        v.validate().unwrap();
    }

    #[test]
    fn equal_policy_is_a_no_op_that_applies() {
        let mut v = vault();
        assert_eq!(v.request_policy(10, policy()).unwrap(), Outcome::PolicyApplied);
        assert_eq!(v.policy(), policy());
    }

    /// A thief with the main key loosens the limits: it waits the OLD
    /// delay, not the shorter one it asked for.
    #[test]
    fn loosening_waits_the_current_delay() {
        let mut v = vault();
        let (id, unlock) = queued(v.request_policy(10, pol(MIN_DELAY_BLOCKS, 1_000)).unwrap());
        assert_eq!(unlock, 110);
        assert_eq!(v.policy(), policy(), "nothing changes before the unlock");
        assert_eq!(v.finalize(109, id), Err(SentinelError::StillLocked));
        // Still limited by the old allowance while queued.
        assert!(matches!(v.transfer(50, thief(), 60).unwrap(), Outcome::Queued { .. }));
        v.validate().unwrap();
        assert_eq!(v.finalize(110, id).unwrap(), None);
        assert_eq!(v.policy(), pol(MIN_DELAY_BLOCKS, 1_000));
        v.validate().unwrap();
    }

    #[test]
    fn mixed_change_counts_as_loosening() {
        let mut v = vault();
        // Lower allowance but shorter delay.
        assert!(matches!(v.request_policy(10, pol(50, 10)).unwrap(), Outcome::Queued { unlock_height: 110, .. }));
        // Higher allowance but longer delay.
        assert!(matches!(v.request_policy(10, pol(500, 60)).unwrap(), Outcome::Queued { unlock_height: 110, .. }));
        assert_eq!(v.policy(), policy());
    }

    #[test]
    fn repeating_the_pending_change_keeps_its_deadline() {
        let mut v = vault();
        let first = queued(v.request_policy(10, pol(100, 500)).unwrap());
        assert_eq!(queued(v.request_policy(90, pol(100, 500)).unwrap()), first);
        v.validate().unwrap();
    }

    #[test]
    fn new_request_replaces_the_pending_change() {
        let mut v = vault();
        queued(v.request_policy(10, pol(100, 500)).unwrap());
        let (id, unlock) = queued(v.request_policy(20, pol(100, 700)).unwrap());
        assert_eq!(unlock, 120);
        assert_eq!(v.pending().len(), 1);
        assert_eq!(v.pending()[0].id, id);
        v.validate().unwrap();
    }

    /// The owner, seeing a hostile loosening, can also simply tighten: the
    /// pending change is dropped. (Recovery remains the real answer.)
    #[test]
    fn tightening_drops_a_pending_loosening() {
        let mut v = vault();
        queued(v.request_policy(10, pol(10, 1_000)).unwrap());
        assert_eq!(v.request_policy(11, pol(100, 50)).unwrap(), Outcome::PolicyApplied);
        assert!(v.pending().is_empty());
        v.validate().unwrap();
    }

    #[test]
    fn lower_allowance_than_window_spend_is_refused() {
        let mut v = vault();
        v.transfer(10, thief(), 40).unwrap();
        let before = v.canonical_encoding();
        assert_eq!(v.request_policy(20, pol(100, 30)), Err(SentinelError::AllowanceInUse));
        assert_eq!(v.canonical_encoding(), before, "a refused change leaves no trace");
        // Once the outflow leaves the window, the same request works.
        assert_eq!(v.request_policy(110, pol(100, 30)).unwrap(), Outcome::PolicyApplied);
        v.validate().unwrap();
    }

    #[test]
    fn longer_delay_extends_everything_already_queued() {
        let mut v = vault();
        let (t, _) = queued(v.transfer(10, thief(), 500).unwrap());
        let (r, _) = queued(v.request_rotation(12, commit(&[3u8; 32])).unwrap());
        v.request_policy(20, pol(300, 50)).unwrap();
        let unlock = |id| v.pending().iter().find(|p| p.id == id).unwrap().unlock_height;
        assert_eq!(unlock(t), 310);
        assert_eq!(unlock(r), 312);
        v.validate().unwrap();
        assert_eq!(v.finalize(309, t), Err(SentinelError::StillLocked));
    }

    #[test]
    fn finalized_shorter_delay_retimes_the_queue() {
        let mut v = vault();
        let (t, _) = queued(v.transfer(10, thief(), 500).unwrap());
        let (c, _) = queued(v.request_policy(20, pol(40, 50)).unwrap());
        v.finalize(120, c).unwrap();
        assert_eq!(v.pending()[0].unlock_height, 50);
        v.validate().unwrap();
        assert_eq!(v.finalize(120, t).unwrap(), Some((thief(), 500)));
    }

    #[test]
    fn finalize_refuses_while_the_window_is_over_the_new_allowance() {
        let mut v = vault();
        let (c, _) = queued(v.request_policy(10, pol(50, 10)).unwrap());
        v.transfer(105, thief(), 40).unwrap(); // under the old allowance
        assert_eq!(v.finalize(110, c), Err(SentinelError::AllowanceInUse));
        assert_eq!(v.pending().len(), 1, "stays queued, anyone may retry");
        v.validate().unwrap();
        // Measured over the new 50-block window: the outflow at 105 still
        // counts at 154 and is gone at 155.
        assert_eq!(v.finalize(154, c), Err(SentinelError::AllowanceInUse));
        assert_eq!(v.finalize(155, c).unwrap(), None);
        assert_eq!(v.policy(), pol(50, 10));
        v.validate().unwrap();
    }

    #[test]
    fn policy_change_has_its_own_slot() {
        let mut v = Vault::new(me(), 1_000_000, Some(commit(&SALT)), pol(100, 0));
        for i in 0..MAX_PENDING as u64 {
            queued(v.transfer(10 + i, thief(), 1).unwrap());
        }
        queued(v.request_rotation(80, commit(&[3u8; 32])).unwrap());
        queued(v.request_policy(81, pol(100, 10)).unwrap());
        v.validate().unwrap();
    }

    #[test]
    fn recovery_cancels_a_pending_change() {
        let mut v = vault();
        queued(v.request_policy(10, pol(10, 1_000)).unwrap());
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &rec_proof()).unwrap(), (cold(), 1_000));
        v.validate().unwrap();
        assert_eq!(v.request_policy(20, policy()), Err(SentinelError::Recovered));
    }

    #[test]
    fn out_of_range_policy_is_rejected() {
        let mut v = vault();
        let bad = Policy { delay_blocks: MIN_DELAY_BLOCKS - 1, allowance_per_window: 0 };
        assert_eq!(v.request_policy(10, bad), Err(SentinelError::InvalidPolicy));
    }

    #[test]
    fn without_guardian_any_change_applies() {
        let mut v = Vault::new(me(), 1_000, None, policy());
        assert_eq!(v.request_policy(10, pol(10, 1_000)).unwrap(), Outcome::PolicyApplied);
    }

    #[test]
    fn validate_rejects_two_pending_changes_and_bad_policies() {
        let mut v = vault();
        queued(v.request_policy(10, pol(100, 500)).unwrap());
        let mut two = v.clone();
        let mut dup = two.pending[0].clone();
        dup.id = two.next_id;
        two.next_id += 1;
        two.pending.push(dup);
        assert_eq!(two.validate(), Err(SentinelError::InvalidState));
        let mut bad = v.clone();
        bad.pending[0].kind = PendingKind::ChangePolicy { policy: Policy { delay_blocks: 0, allowance_per_window: 1 } };
        assert_eq!(bad.validate(), Err(SentinelError::InvalidPolicy));
    }

    /// Locks the encoding of the new pending kind. The v1 vector above is
    /// untouched, so vaults without a policy change keep their state root.
    #[test]
    fn canonical_encoding_with_policy_change_vector() {
        let mut v = vault();
        v.transfer(10, thief(), 30).unwrap();
        queued(v.request_policy(12, pol(100, 500)).unwrap());
        let digest: [u8; 32] = Sha3_256::digest(v.canonical_encoding()).into();
        assert_eq!(hex_of(&digest), POLICY_CHANGE_VECTOR, "canonical vault encoding changed");
        let mut other = v.clone();
        other.pending[0].kind = PendingKind::ChangePolicy { policy: pol(100, 501) };
        assert_ne!(other.canonical_encoding(), v.canonical_encoding());
    }

    const POLICY_CHANGE_VECTOR: &str = "3c32c18280c48511e2294bd2de0a649644f7d11370b79a708fd494e057fcfa5a";

    // ---- real HYDRA-X -----------------------------------------------------

    /// End to end with the real scheme (ML-DSA-87 AND SLH-DSA-256s).
    #[test]
    fn real_hydrax_recovery() {
        let rec = HydraXKeypair::generate();
        let c = recovery_commitment(CHAIN, &me(), &rec.address(), &cold(), &SALT);
        let mut v = Vault::new(me(), 1_000, Some(c), policy());
        v.transfer(10, thief(), 800).unwrap();

        // Real signature from the right key but for another account.
        let wrong_acct = rec.sign(&recovery_message(CHAIN, &thief(), &c, 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &wrong_acct), Err(SentinelError::BadRecoverySignature));

        // Real signature over the right message from a different key.
        let impostor = HydraXKeypair::generate().sign(&recovery_message(CHAIN, &me(), &c, 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &impostor), Err(SentinelError::CommitmentMismatch));

        let sig = rec.sign(&recovery_message(CHAIN, &me(), &c, 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &sig).unwrap(), (cold(), 1_000));
    }
}
