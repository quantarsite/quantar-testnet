//! Sentinel operations carried in a transaction's signed `data` field.
//!
//! Encoding: `MAGIC || bincode(SentinelOp)`. Decoding re-encodes the value
//! and requires the exact same bytes, so every operation has exactly one
//! valid encoding.
//!
//! | Operation        | `from`        | `to`             | `amount` |
//! |------------------|---------------|------------------|----------|
//! | `SetGuardian`    | account owner | same as `from`   | 0        |
//! | `RotateGuardian` | account owner | same as `from`   | 0        |
//! | `Finalize`       | anyone (pays the fee) | guarded account | 0 |
//! | `Recover`        | anyone (pays the fee) | guarded account | 0 |
//!
//! `Finalize` and `Recover` are paid by whoever submits them, never by the
//! guarded account, so a thief who reserves the account's whole balance
//! cannot block them.

use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};

/// Marks a Sentinel payload (version 1).
pub const MAGIC: &[u8; 4] = b"QSN1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SentinelOp {
    /// Create the account's vault with its first recovery commitment.
    SetGuardian { commitment: [u8; 32], delay_blocks: u64, allowance_per_window: u64 },
    /// Queue a replacement of the recovery commitment (time-locked).
    RotateGuardian { commitment: [u8; 32] },
    /// Settle a matured pending operation of the account in `to`.
    Finalize { id: u64 },
    /// Recover the account in `to` to its committed cold destination.
    /// The proof is boxed: it is ~37 KB, the other variants are tiny.
    Recover { cold_dest: Address, salt: [u8; 32], proof: Box<HydraXSignature> },
}

impl SentinelOp {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(bincode::serialize(self).expect("SentinelOp serializes"));
        out
    }

    /// Decode a `data` field. Rejects unknown magic, trailing bytes and any
    /// non-canonical encoding.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let body = data.strip_prefix(MAGIC.as_slice()).ok_or("unknown data payload")?;
        let op: SentinelOp = bincode::deserialize(body).map_err(|e| format!("bad Sentinel payload: {e}"))?;
        if op.encode() != data {
            return Err("non-canonical Sentinel payload".into());
        }
        Ok(op)
    }

    /// Whether the guarded account is `from` (owner operations) rather
    /// than `to` (operations anyone may submit).
    pub fn is_owner_op(&self) -> bool {
        matches!(self, Self::SetGuardian { .. } | Self::RotateGuardian { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_canonical() {
        let op = SentinelOp::Finalize { id: 7 };
        let bytes = op.encode();
        assert!(matches!(SentinelOp::decode(&bytes).unwrap(), SentinelOp::Finalize { id: 7 }));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SentinelOp::decode(&trailing).is_err());
        assert!(SentinelOp::decode(b"XXXX").is_err());
        assert!(SentinelOp::decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
