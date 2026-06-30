//! Type bridge between `qtrc-common::Transaction` and `hx-mempool` types.
//!
//! `to_ingest_item` converts a validated qtrc transaction into the
//! `(RawTransaction, HydraXSignature)` pair expected by `IngestionPipeline`.
//!
//! Layout contract:
//!   `RawTransaction::signing_bytes()` in hx-mempool uses:
//!     nonce(8) || sender(32) || recipient(32) || value(16)
//!     || fee_per_gas(8) || gas_limit(8) || data_len(8) || data
//!
//!   `Transaction::signing_payload()` in qtrc-common uses the same layout
//!   with fixed sentinels: fee_per_gas=0, gas_limit=21_000, data=[].
//!   This alignment ensures the pipeline's PqCryptoVerifier verifies the
//!   same bytes that the client originally signed.

use hx_mempool::{
    ingestion::IngestItem,
    types::{HydraXSignature as HxSig, RawTransaction},
};
use qtrc_common::tx::{Transaction, TxHash};

use crate::ConsensusError;

/// Convert a `qtrc-common::Transaction` into an `hx-mempool` `IngestItem`.
///
/// # Errors
///
/// Returns `ConsensusError::InvalidTx` if the signature byte lengths don't
/// match hx-mempool's expected constants (ML-DSA-87: 4595 bytes,
/// SLH-DSA-256s: 29792 bytes).  A correctly signed qtrc transaction will
/// always have the right lengths.
pub fn to_ingest_item(tx: &Transaction) -> Result<IngestItem, ConsensusError> {
    let ml_pk = tx.signature.verifying_key.ml_dsa_pk_bytes().to_vec();
    let slh_pk = tx.signature.verifying_key.slh_dsa_pk_bytes().to_vec();

    let raw = RawTransaction {
        nonce: tx.nonce,
        // Address is [u8; 32] in hx-mempool; qtrc Address wraps [u8; 32].
        sender: tx.from.0,
        sender_ml_dsa_pk: ml_pk,
        sender_slh_dsa_pk: slh_pk,
        recipient: tx.to.0,
        value: tx.amount as u128,
        fee_per_gas: 0,
        gas_limit: 21_000,
        data: vec![],
    };

    let sig = HxSig::new(
        tx.signature.ml_dsa_sig.clone(),
        tx.signature.slh_dsa_sig.clone(),
    )
    .map_err(|e| ConsensusError::InvalidTx(e.to_string()))?;

    Ok((raw, sig))
}

/// Convert an hx-mempool `TxHash` (`[u8; 32]`) to a qtrc `TxHash`.
#[inline]
pub fn hx_hash_to_qtrc(hash: [u8; 32]) -> TxHash {
    TxHash(hash)
}
