//! # qtrc-sentinel: HYDRA-X Sentinel
//!
//! A third security layer for Quantar Network that does not depend on any
//! signature scheme being unbroken.
//!
//! HYDRA-X already requires ML-DSA-87 AND SLH-DSA-SHA2-256s. That defends
//! against one family falling. It does not help when the owner's key leaks,
//! or when both families fall together. Sentinel covers those two cases.
//!
//! ## Mechanism
//!
//! 1. An account stores a recovery commitment
//!    `R = SHA3-256(DOM || recovery_address || cold_dest || salt)`,
//!    every field length-prefixed. The recovery key's public key never
//!    appears on chain until it is used, so there is nothing to attack.
//! 2. Outflows within `allowance_per_window` settle at once. Anything above
//!    waits `delay_blocks` and is visible on chain the whole time.
//! 3. During the delay, a recovery reveals the recovery address, opens the
//!    commitment, proves control of the recovery key with a HYDRA-X
//!    signature over a chain-, account- and nonce-bound message, cancels
//!    every pending operation and sends the whole balance to `cold_dest`.
//! 4. Replacing the commitment is delayed as well, so a thief holding the
//!    main key cannot swap the guardian silently.
//!
//! The key property: `cold_dest` is inside a hash. Sending a recovery
//! anywhere else needs a SHA3-256 second preimage, even for an adversary
//! that can forge every signature in use.
//!
//! The state machine is pure and deterministic and the [`Vault`] is
//! serde-serializable, so it can live next to `AccountState` in
//! `ChainState` once a recovery transaction type is added to consensus.

pub mod watchtower;

use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub type Hash = [u8; 32];

const DOM_COMMIT: &[u8] = b"QTR/SENTINEL/COMMIT/v1";
const DOM_RECOVER: &[u8] = b"QTR/SENTINEL/RECOVER/v1";

/// Length-prefixed absorb, so `"ab"||"c"` and `"a"||"bc"` never collide.
fn absorb(h: &mut Sha3_256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

/// Recovery commitment, computed offline by the wallet.
pub fn recovery_commitment(recovery_address: &Address, cold_dest: &Address, salt: &[u8; 32]) -> Hash {
    let mut h = Sha3_256::new();
    absorb(&mut h, DOM_COMMIT);
    absorb(&mut h, &recovery_address.0);
    absorb(&mut h, &cold_dest.0);
    absorb(&mut h, salt);
    h.finalize().into()
}

/// Message the recovery key signs. Binds chain, account and a nonce, so a
/// recovery signature cannot be replayed across networks, accounts or uses.
/// Pass `qtrc_common::tx::CHAIN_ID` as `chain_id`.
pub fn recovery_message(chain_id: &[u8], account: &Address, nonce: u64) -> Hash {
    let mut h = Sha3_256::new();
    absorb(&mut h, DOM_RECOVER);
    absorb(&mut h, chain_id);
    absorb(&mut h, &account.0);
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

/// Proof that the holder of the recovery key authorized a recovery.
///
/// Production uses [`HydraXSignature`]; the trait exists so the state
/// machine can be tested without paying for SLH-DSA signing on every case.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Blocks a large outflow or a guardian rotation must wait.
    pub delay_blocks: u64,
    /// Micro-QTR that may leave immediately per window of `delay_blocks`.
    pub allowance_per_window: u64,
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SentinelError {
    #[error("insufficient available balance")]
    InsufficientFunds,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vault {
    pub address: Address,
    pub balance: u64,
    /// Balance locked by pending transfers.
    pub reserved: u64,
    pub commitment: Option<Hash>,
    pub pending: Vec<Pending>,
    pub recovered: bool,
    pub policy: Policy,
    window_start: u64,
    spent_in_window: u64,
    next_id: u64,
    recovery_nonce: u64,
}

impl Vault {
    pub fn new(address: Address, balance: u64, commitment: Option<Hash>, policy: Policy) -> Self {
        Self {
            address,
            balance,
            reserved: 0,
            commitment,
            pending: Vec::new(),
            recovered: false,
            policy,
            window_start: 0,
            spent_in_window: 0,
            next_id: 0,
            recovery_nonce: 0,
        }
    }

    pub fn available(&self) -> u64 {
        self.balance - self.reserved
    }

    pub fn recovery_nonce(&self) -> u64 {
        self.recovery_nonce
    }

    fn roll_window(&mut self, height: u64) {
        if height >= self.window_start.saturating_add(self.policy.delay_blocks) {
            self.window_start = height;
            self.spent_in_window = 0;
        }
    }

    fn queue(&mut self, height: u64, kind: PendingKind) -> Result<Outcome, SentinelError> {
        let id = self.next_id;
        self.next_id += 1;
        let unlock_height = height.checked_add(self.policy.delay_blocks).ok_or(SentinelError::Overflow)?;
        self.pending.push(Pending { id, kind, created_height: height, unlock_height });
        Ok(Outcome::Queued { id, unlock_height })
    }

    /// Outflow authorized by the main key. The HYDRA-X signature is checked
    /// by consensus before this is called.
    pub fn transfer(&mut self, height: u64, to: Address, amount: u64) -> Result<Outcome, SentinelError> {
        if self.recovered {
            return Err(SentinelError::Recovered);
        }
        if amount > self.available() {
            return Err(SentinelError::InsufficientFunds);
        }
        self.roll_window(height);
        let fits = self
            .spent_in_window
            .checked_add(amount)
            .is_some_and(|s| s <= self.policy.allowance_per_window);
        // Without a guardian nobody can veto, so delaying would only hurt.
        if self.commitment.is_none() || fits {
            self.spent_in_window = self.spent_in_window.saturating_add(amount);
            self.balance -= amount;
            return Ok(Outcome::Settled { to, amount });
        }
        self.reserved += amount;
        self.queue(height, PendingKind::Transfer { to, amount })
    }

    /// Replace the recovery commitment. Delayed whenever a guardian already
    /// exists, so the current guardian can veto a hostile swap.
    pub fn request_rotation(&mut self, height: u64, new_commitment: Hash) -> Result<Outcome, SentinelError> {
        if self.recovered {
            return Err(SentinelError::Recovered);
        }
        if self.commitment.is_none() {
            self.commitment = Some(new_commitment);
            return Ok(Outcome::CommitmentSet);
        }
        self.queue(height, PendingKind::RotateCommitment { new_commitment })
    }

    /// Settle a pending operation whose time lock expired. Returns the
    /// transfer, if the operation was one.
    pub fn finalize(&mut self, height: u64, id: u64) -> Result<Option<(Address, u64)>, SentinelError> {
        if self.recovered {
            return Err(SentinelError::Recovered);
        }
        let idx = self.pending.iter().position(|p| p.id == id).ok_or(SentinelError::NotFound)?;
        if height < self.pending[idx].unlock_height {
            return Err(SentinelError::StillLocked);
        }
        let p = self.pending.remove(idx);
        match p.kind {
            PendingKind::Transfer { to, amount } => {
                self.reserved -= amount;
                self.balance -= amount;
                Ok(Some((to, amount)))
            }
            PendingKind::RotateCommitment { new_commitment } => {
                self.commitment = Some(new_commitment);
                Ok(None)
            }
        }
    }

    /// Emergency recovery. Opens the commitment, checks the recovery key's
    /// signature, cancels every pending operation and moves the entire
    /// balance to the committed `cold_dest`. Single use.
    pub fn recover<P: RecoveryProof>(
        &mut self,
        chain_id: &[u8],
        cold_dest: &Address,
        salt: &[u8; 32],
        proof: &P,
    ) -> Result<(Address, u64), SentinelError> {
        if self.recovered {
            return Err(SentinelError::Recovered);
        }
        let expected = self.commitment.ok_or(SentinelError::NoCommitment)?;
        let opened = recovery_commitment(&proof.signer(), cold_dest, salt);
        if !ct_eq(&expected, &opened) {
            return Err(SentinelError::CommitmentMismatch);
        }
        let msg = recovery_message(chain_id, &self.address, self.recovery_nonce);
        if !proof.verify(&msg) {
            return Err(SentinelError::BadRecoverySignature);
        }
        self.recovery_nonce += 1;
        self.pending.clear();
        self.reserved = 0;
        let amount = self.balance;
        self.balance = 0;
        self.commitment = None;
        self.recovered = true;
        Ok((cold_dest.clone(), amount))
    }
}

/// Constant-time equality for 32-byte digests.
fn ct_eq(a: &Hash, b: &Hash) -> bool {
    let mut d = 0u8;
    for i in 0..32 {
        d |= a[i] ^ b[i];
    }
    d == 0
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
        Policy { delay_blocks: 100, allowance_per_window: 50 }
    }

    pub fn vault() -> Vault {
        let c = recovery_commitment(&rec_key(), &cold(), &SALT);
        Vault::new(me(), 1_000, Some(c), policy())
    }

    pub fn rec_proof(nonce: u64) -> MockProof {
        MockProof::sign(&rec_key(), &recovery_message(CHAIN, &me(), nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use qtrc_crypto::HydraXKeypair;

    #[test]
    fn small_transfer_settles_immediately() {
        let mut v = vault();
        assert_eq!(v.transfer(10, thief(), 30).unwrap(), Outcome::Settled { to: thief(), amount: 30 });
        assert_eq!(v.balance, 970);
    }

    #[test]
    fn allowance_cannot_be_split_to_drain() {
        let mut v = vault();
        v.transfer(10, thief(), 30).unwrap();
        v.transfer(11, thief(), 20).unwrap();
        assert!(matches!(v.transfer(12, thief(), 1).unwrap(), Outcome::Queued { .. }));
    }

    #[test]
    fn allowance_resets_after_window() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap();
        assert!(matches!(v.transfer(110, thief(), 50).unwrap(), Outcome::Settled { .. }));
    }

    #[test]
    fn no_guardian_means_no_delay() {
        let mut v = Vault::new(me(), 1_000, None, policy());
        assert!(matches!(v.transfer(10, thief(), 900).unwrap(), Outcome::Settled { .. }));
    }

    #[test]
    fn large_transfer_waits_then_settles() {
        let mut v = vault();
        let Outcome::Queued { id, unlock_height } = v.transfer(10, thief(), 500).unwrap() else { panic!() };
        assert_eq!(v.finalize(unlock_height - 1, id), Err(SentinelError::StillLocked));
        assert_eq!(v.finalize(unlock_height, id).unwrap(), Some((thief(), 500)));
        assert_eq!(v.balance, 500);
        assert_eq!(v.reserved, 0);
    }

    #[test]
    fn recovery_vetoes_stolen_key_drain() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap(); // allowance lost, but bounded
        v.transfer(11, thief(), 950).unwrap(); // queued
        let (to, amount) = v.recover(CHAIN, &cold(), &SALT, &rec_proof(0)).unwrap();
        assert_eq!((to, amount), (cold(), 950));
        assert!(v.pending.is_empty());
        assert_eq!(v.finalize(500, 1), Err(SentinelError::Recovered));
    }

    #[test]
    fn forged_recovery_cannot_redirect_funds() {
        let mut v = vault();
        let r = v.recover(CHAIN, &thief(), &SALT, &rec_proof(0));
        assert_eq!(r, Err(SentinelError::CommitmentMismatch));
    }

    #[test]
    fn wrong_recovery_key_rejected() {
        let mut v = vault();
        let other = MockProof::sign(&thief(), &recovery_message(CHAIN, &me(), 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &other), Err(SentinelError::CommitmentMismatch));
    }

    #[test]
    fn bad_signature_rejected() {
        let mut v = vault();
        let mut p = rec_proof(0);
        p.sig[0] ^= 1;
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &p), Err(SentinelError::BadRecoverySignature));
    }

    #[test]
    fn cross_chain_replay_rejected() {
        let mut v = vault();
        let p = MockProof::sign(&rec_key(), &recovery_message(b"quantar-mainnet", &me(), 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &p), Err(SentinelError::BadRecoverySignature));
    }

    #[test]
    fn recovery_is_single_use() {
        let mut v = vault();
        v.recover(CHAIN, &cold(), &SALT, &rec_proof(0)).unwrap();
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &rec_proof(1)), Err(SentinelError::Recovered));
    }

    #[test]
    fn thief_cannot_swap_guardian_silently() {
        let mut v = vault();
        let evil = recovery_commitment(&thief(), &thief(), &SALT);
        let Outcome::Queued { id, unlock_height } = v.request_rotation(10, evil).unwrap() else { panic!() };
        assert_eq!(v.finalize(unlock_height - 1, id), Err(SentinelError::StillLocked));
        v.recover(CHAIN, &cold(), &SALT, &rec_proof(0)).unwrap();
        assert_eq!(v.finalize(unlock_height, id), Err(SentinelError::Recovered));
    }

    #[test]
    fn legit_rotation_applies_after_delay() {
        let mut v = vault();
        let new_c = recovery_commitment(&rec_key(), &cold(), &[3u8; 32]);
        let Outcome::Queued { id, unlock_height } = v.request_rotation(10, new_c).unwrap() else { panic!() };
        v.finalize(unlock_height, id).unwrap();
        assert_eq!(v.commitment, Some(new_c));
    }

    #[test]
    fn reserved_funds_cannot_be_double_spent() {
        let mut v = vault();
        v.transfer(10, thief(), 900).unwrap();
        assert_eq!(v.transfer(11, thief(), 200), Err(SentinelError::InsufficientFunds));
    }

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
    fn vault_survives_serde_roundtrip() {
        let mut v = vault();
        v.transfer(10, thief(), 500).unwrap();
        let json = serde_json::to_string(&v).unwrap();
        let back: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pending, v.pending);
        assert_eq!(back.reserved, 500);
    }

    /// End to end with the real HYDRA-X scheme (ML-DSA-87 AND SLH-DSA-256s).
    #[test]
    fn real_hydrax_recovery() {
        let rec = HydraXKeypair::generate();
        let c = recovery_commitment(&rec.address(), &cold(), &SALT);
        let mut v = Vault::new(me(), 1_000, Some(c), policy());
        v.transfer(10, thief(), 800).unwrap();

        // Signature over the wrong nonce must fail with the real scheme too.
        let stale = rec.sign(&recovery_message(CHAIN, &me(), 1));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &stale), Err(SentinelError::BadRecoverySignature));

        let sig = rec.sign(&recovery_message(CHAIN, &me(), 0));
        assert_eq!(v.recover(CHAIN, &cold(), &SALT, &sig).unwrap(), (cold(), 1_000));
    }
}
