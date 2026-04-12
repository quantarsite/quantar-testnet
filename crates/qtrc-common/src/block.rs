//! Block and BlockHeader types.

use crate::tx::{Transaction, TxHash};
use qtrc_crypto::{Address, HydraXSignature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// 32-byte SHA3-256 hash of a block header.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockHash(#[serde(with = "hex::serde")] pub [u8; 32]);

impl BlockHash {
    pub fn zero() -> Self {
        BlockHash([0u8; 32])
    }
}

impl std::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Block header — the minimal commitment signed by validators.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Chain height (genesis = 0)
    pub height:      u64,
    /// Hash of the previous block header
    pub prev_hash:   BlockHash,
    /// Merkle root of transactions in this block
    pub merkle_root: TxHash,
    /// Unix timestamp (seconds)
    pub timestamp:   i64,
    /// Address of the validator that proposed this block
    pub proposer:    Address,
}

impl BlockHeader {
    /// Canonical bytes signed by the proposer.
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("header serialization")
    }

    /// SHA3-256 hash of the header.
    pub fn hash(&self) -> BlockHash {
        let bytes = self.signing_bytes();
        let digest: [u8; 32] = Sha3_256::digest(&bytes).into();
        BlockHash(digest)
    }
}

/// A validator's HYDRA-X signature over a block header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSig {
    pub validator: Address,
    pub signature: HydraXSignature,
}

/// A complete block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header:         BlockHeader,
    pub transactions:   Vec<Transaction>,
    /// Signatures from ≥ 2/3 of the validator set
    pub validator_sigs: Vec<ValidatorSig>,
}

impl Block {
    /// Compute the transaction Merkle root (SHA3-256 of all tx hashes).
    pub fn compute_merkle_root(txs: &[Transaction]) -> TxHash {
        if txs.is_empty() {
            return TxHash([0u8; 32]);
        }
        let mut hasher = Sha3_256::new();
        for tx in txs {
            hasher.update(tx.hash().0);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        TxHash(digest)
    }

    /// Hash of this block's header.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Verify all transactions and validator signatures.
    pub fn verify_transactions(&self) -> bool {
        self.transactions.iter().all(|tx| tx.verify().is_ok())
    }
}
