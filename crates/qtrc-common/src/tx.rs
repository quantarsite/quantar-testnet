//! Transaction types and hashing.

use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// 32-byte SHA3-256 hash of a serialized transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxHash(#[serde(with = "hex::serde")] pub [u8; 32]);

impl std::fmt::Display for TxHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Error)]
pub enum TxError {
    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("Signer address does not match `from` field")]
    SignerMismatch,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
}

/// A Quantar Network transfer transaction.
///
/// Every transaction carries a HYDRA-X AND-composed signature.
/// There is no transaction type that bypasses dual-signature
/// verification — this is enforced at the consensus layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender address (must match signature's verifying key)
    pub from:      Address,
    /// Recipient address
    pub to:        Address,
    /// Amount in micro-QTR (1 QTR = 1_000_000 µQTR)
    pub amount:    u64,
    /// Sender nonce — prevents replay attacks
    pub nonce:     u64,
    /// Unix timestamp (seconds)
    pub timestamp: i64,
    /// HYDRA-X AND-composed signature over the canonical payload
    pub signature: HydraXSignature,
}

impl Transaction {
    /// Canonical payload: fields signed by the sender.
    /// The signature itself is excluded from the payload.
    pub fn signing_payload(
        from: &Address,
        to: &Address,
        amount: u64,
        nonce: u64,
        timestamp: i64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&from.0);
        buf.extend_from_slice(&to.0);
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&timestamp.to_le_bytes());
        buf
    }

    /// Compute the SHA3-256 hash of this transaction.
    pub fn hash(&self) -> TxHash {
        let encoded = serde_json::to_vec(self).expect("tx serialization");
        let digest: [u8; 32] = Sha3_256::digest(&encoded).into();
        TxHash(digest)
    }

    /// Verify the HYDRA-X AND-composed signature.
    ///
    /// Checks:
    ///   1. Both ML-DSA-87 and SLH-DSA signatures are valid.
    ///   2. The signing key's derived address matches `self.from`.
    pub fn verify(&self) -> Result<(), TxError> {
        let payload = Self::signing_payload(
            &self.from,
            &self.to,
            self.amount,
            self.nonce,
            self.timestamp,
        );

        // AND-composition check
        self.signature
            .verify(&payload)
            .map_err(|e| TxError::SignatureInvalid(e.to_string()))?;

        // Address binding check
        if self.signature.signer_address() != self.from {
            return Err(TxError::SignerMismatch);
        }

        Ok(())
    }
}
