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
//! needs: transaction types for set-guardian, rotation, recovery and
//! finalize; a call to [`Vault::charge_fee`] for every transaction's fee;
//! routing credits through [`Vault::credit`]; [`Vault::validate`] on every
//! state load; and `overflow-checks = true` in release builds.
//! `finalize` takes no authorization on purpose: once a time lock expires,
//! anyone may settle it.

pub mod watchtower;

use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub type Hash = [u8; 32];

const DOM_COMMIT: &[u8] = b"QTR/SENTINEL/COMMIT/v2";
const DOM_RECOVER: &[u8] = b"QTR/SENTINEL/RECOVER/v2";

/// Smallest allowed time lock. Must exceed realistic inclusion latency.
pub const MIN_DELAY_BLOCKS: u64 = 10;
/// Largest allowed time lock, keeps `height + delay` far from overflow.
pub const MAX_DELAY_BLOCKS: u64 = 10_000_000;
/// Maximum queued operations per account (bounds state and work).
pub const MAX_PENDING: usize = 64;
/// Maximum allowance outflows remembered per window. Once full, further
/// outflows are queued instead of settling.
pub const MAX_RECENT: usize = 64;

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

/// Message the recovery key signs. Bound to the chain, the account and the
/// current commitment, so a recovery signature dies when the guardian is
/// rotated and never replays across networks or accounts.
#[must_use]
pub fn recovery_message(chain_id: &[u8], account: &Address, commitment: &Hash) -> Hash {
    let mut h = Sha3_256::new();
    absorb(&mut h, DOM_RECOVER);
    absorb(&mut h, chain_id);
    absorb(&mut h, &account.0);
    absorb(&mut h, commitment);
    h.finalize().into()
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    Transfer { to: Address, amount: u64 },
    RotateCommitment { new_commitment: Hash },
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
    #[error("vault state violates an invariant")]
    InvalidState,
    #[error("arithmetic overflow")]
    Overflow,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Left immediately, within the allowance.
    Settled { to: Address, amount: u64 },
    /// Queued behind the time lock.
    Queued { id: u64, unlock_height: u64 },
    /// First guardian set, applied at once (nothing to protect yet).
    CommitmentSet,
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
/// `reserved == sum of pending transfers`, `reserved <= balance`,
/// at most [`MAX_PENDING`] pending and one pending rotation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vault {
    address: Address,
    balance: u64,
    reserved: u64,
    commitment: Option<Hash>,
    pending: Vec<Pending>,
    recent: Vec<Outflow>,
    recovered_to: Option<Address>,
    policy: Policy,
    next_id: u64,
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
            recovered_to: None,
            policy,
            next_id: 0,
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
    #[must_use]
    pub fn is_recovered(&self) -> bool {
        self.recovered_to.is_some()
    }
    #[must_use]
    pub fn recovered_to(&self) -> Option<&Address> {
        self.recovered_to.as_ref()
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

    fn ensure_active(&self) -> Result<(), SentinelError> {
        if self.is_recovered() { Err(SentinelError::Recovered) } else { Ok(()) }
    }

    fn prune_recent(&mut self, height: u64) {
        let delay = self.policy.delay_blocks;
        self.recent.retain(|o| o.height.saturating_add(delay) > height);
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
        if self.pending.len() >= MAX_PENDING {
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
    /// request replaces any rotation already pending.
    ///
    /// # Errors
    /// Recovered, too many pending, overflow.
    pub fn request_rotation(&mut self, height: u64, new_commitment: Hash) -> Result<Outcome, SentinelError> {
        self.ensure_active()?;
        if self.commitment.is_none() {
            self.commitment = Some(new_commitment);
            return Ok(Outcome::CommitmentSet);
        }
        let had_rotation = self.pending.iter().any(|p| matches!(p.kind, PendingKind::RotateCommitment { .. }));
        if !had_rotation && self.pending.len() >= MAX_PENDING {
            return Err(SentinelError::TooManyPending);
        }
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
                Ok(Some((to, amount)))
            }
            PendingKind::RotateCommitment { new_commitment } => {
                self.commitment = Some(*new_commitment);
                self.pending.remove(idx);
                Ok(None)
            }
        }
    }

    /// Check a recovery without changing state (used by watchtowers to
    /// detect a stale kit before they need it).
    ///
    /// # Errors
    /// Recovered, no commitment, mismatch, bad signature.
    pub fn check_recovery<P: RecoveryProof>(
        &self,
        chain_id: &[u8],
        cold_dest: &Address,
        salt: &[u8; 32],
        proof: &P,
    ) -> Result<(), SentinelError> {
        self.ensure_active()?;
        let expected = self.commitment.ok_or(SentinelError::NoCommitment)?;
        let opened = recovery_commitment(chain_id, &self.address, &proof.signer(), cold_dest, salt);
        if expected != opened {
            return Err(SentinelError::CommitmentMismatch);
        }
        let msg = recovery_message(chain_id, &self.address, &expected);
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
        self.check_recovery(chain_id, cold_dest, salt, proof)?;
        self.pending.clear();
        self.recent.clear();
        self.reserved = 0;
        let amount = self.balance;
        self.balance = 0;
        self.commitment = None;
        self.recovered_to = Some(cold_dest.clone());
        Ok((cold_dest.clone(), amount))
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
        for (i, p) in self.pending.iter().enumerate() {
            if p.id >= self.next_id || self.pending[..i].iter().any(|q| q.id == p.id) {
                return Err(bad);
            }
            match p.kind {
                PendingKind::Transfer { amount, .. } => {
                    sum = sum.checked_add(amount).ok_or(SentinelError::InvalidState)?;
                }
                PendingKind::RotateCommitment { .. } => rotations += 1,
            }
        }
        let ok = sum == self.reserved
            && self.reserved <= self.balance
            && self.pending.len() <= MAX_PENDING
            && self.recent.len() <= MAX_RECENT
            && rotations <= 1
            && (self.commitment.is_some() || self.pending.is_empty())
            && (!self.is_recovered() || (self.balance == 0 && self.pending.is_empty()));
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

    /// Recovery proof for whatever commitment the vault holds now.
    pub fn proof_for(c: &Hash) -> MockProof {
        MockProof::sign(&rec_key(), &recovery_message(CHAIN, &me(), c))
    }

    pub fn rec_proof() -> MockProof {
        proof_for(&commit(&SALT))
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
        let other = MockProof::sign(&thief(), &recovery_message(CHAIN, &me(), &c));
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
        let p = MockProof::sign(&rec_key(), &recovery_message(b"quantar-mainnet", &me(), &commit(&SALT)));
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
        assert!(v.recover(CHAIN, &cold(), &new_salt, &proof_for(&commit(&new_salt))).is_ok());
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
        assert_ne!(c, recovery_message(CHAIN, &me(), &c));
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

    // ---- real HYDRA-X -----------------------------------------------------

    /// End to end with the real scheme (ML-DSA-87 AND SLH-DSA-256s).
    #[test]
    fn real_hydrax_recovery() {
        let rec = HydraXKeypair::generate();
        let c = recovery_commitment(CHAIN, &me(), &rec.address(), &cold(), &SALT);
        let mut v = Vault::new(me(), 1_000, Some(c), policy());
        v.transfer(10, thief(), 800).unwrap();

        // Real signature from the right key but for another account.
        let wrong_acct = rec.sign(&recovery_message(CHAIN, &thief(), &c));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &wrong_acct), Err(SentinelError::BadRecoverySignature));

        // Real signature over the right message from a different key.
        let impostor = HydraXKeypair::generate().sign(&recovery_message(CHAIN, &me(), &c));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &impostor), Err(SentinelError::CommitmentMismatch));

        let sig = rec.sign(&recovery_message(CHAIN, &me(), &c));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &sig).unwrap(), (cold(), 1_000));
    }
}
