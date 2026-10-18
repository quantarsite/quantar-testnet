//! Transaction types and hashing.

use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};
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

/// Protocol fee per transaction, in micro-QTR: 0.01 QTR. It is burned
/// (removed from supply), charged on top of the amount, and is a consensus
/// rule, so it is not part of the signed payload.
pub const TX_FEE: u64 = 10_000;

/// Protocol tag prepended to every signed transaction payload (HYDRA-X v2).
pub const SIGNING_DOMAIN: &[u8] = b"QTR-HYDRAX-V2";

/// Network every signature is bound to.
pub const CHAIN_ID: &str = "quantar-testnet-2";

/// `SIGNING_DOMAIN || len(CHAIN_ID) as u8 || CHAIN_ID`
///
/// Binds a signature to the protocol version and the network, so a
/// signature made for v1 or for another chain never verifies here.
/// Must stay byte-identical to `hx_mempool::types::signing_domain_prefix`
/// (checked by a test in qtrc-consensus).
pub fn signing_domain_prefix() -> Vec<u8> {
    let mut p = Vec::with_capacity(SIGNING_DOMAIN.len() + 1 + CHAIN_ID.len());
    p.extend_from_slice(SIGNING_DOMAIN);
    p.push(CHAIN_ID.len() as u8);
    p.extend_from_slice(CHAIN_ID.as_bytes());
    p
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
    /// Unix timestamp (seconds). Informational only: it is NOT signed and
    /// NOT part of the transaction ID, so consensus must never rely on it.
    pub timestamp: i64,
    /// HYDRA-X AND-composed signature over the canonical payload
    pub signature: HydraXSignature,
}

impl Transaction {
    /// Canonical payload: fields signed by the sender.
    ///
    /// Layout matches hx-mempool `RawTransaction::signing_bytes()` with
    /// fixed sentinel values for fee_per_gas=0, gas_limit=21_000, data=[]:
    ///   domain_prefix || nonce(8) || sender(32) || recipient(32) || value(16)
    ///   || fee_per_gas(8) || gas_limit(8) || data_len(8)
    pub fn signing_payload(from: &Address, to: &Address, amount: u64, nonce: u64) -> Vec<u8> {
        const GAS_LIMIT: u64 = 21_000;
        let prefix = signing_domain_prefix();
        let mut buf = Vec::with_capacity(prefix.len() + 8 + 32 + 32 + 16 + 8 + 8 + 8);
        buf.extend_from_slice(&prefix);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&from.0);
        buf.extend_from_slice(&to.0);
        buf.extend_from_slice(&(amount as u128).to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());       // fee_per_gas
        buf.extend_from_slice(&GAS_LIMIT.to_le_bytes()); // gas_limit
        buf.extend_from_slice(&0u64.to_le_bytes());       // data_len
        buf
    }

    /// Transaction ID: BLAKE3 of the signed payload.
    ///
    /// HYDRA-X v2: the ID covers exactly the bytes the sender signed, and
    /// nothing else. Unsigned fields (`timestamp`) and the signature itself
    /// are left out, so a relayer cannot change the ID of a valid
    /// transaction (the malleability problem Bitcoin had before SegWit).
    /// It is the same hash hx-mempool computes from `signing_bytes()`.
    pub fn hash(&self) -> TxHash {
        let payload = Self::signing_payload(&self.from, &self.to, self.amount, self.nonce);
        TxHash(*blake3::hash(&payload).as_bytes())
    }

    /// Verify the HYDRA-X AND-composed signature.
    ///
    /// Checks:
    ///   1. Both ML-DSA-87 and SLH-DSA signatures are valid.
    ///   2. The signing key's derived address matches `self.from`.
    pub fn verify(&self) -> Result<(), TxError> {
        let payload = Self::signing_payload(&self.from, &self.to, self.amount, self.nonce);

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
