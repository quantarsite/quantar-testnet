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
    /// State root after applying this block (`crate::state_root`). Present
    /// from the state-root activation height on. Left out of the JSON when
    /// absent, so headers from before activation keep their exact signing
    /// bytes and hashes.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::state_root::opt_hex")]
    pub state_root:  Option<[u8; 32]>,
    /// Commitment to every byte of every transaction, signatures and
    /// timestamps included ([`Block::compute_witness_root`]). `merkle_root`
    /// covers only tx IDs, which leave those out on purpose (IDs must not
    /// change when a relay re-encodes a signature), so without this a
    /// stored or relayed block could change under the same header. Present
    /// from its activation height on, left out of the JSON before it.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::state_root::opt_hex")]
    pub witness_root: Option<[u8; 32]>,
}

impl BlockHeader {
    /// Canonical bytes signed by the proposer.
    ///
    /// HYDRA-X v2: `domain_prefix || b"BLK" || json(header)`, so a validator
    /// signature is bound to this chain and can never be read as a tx.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = crate::tx::signing_domain_prefix();
        buf.extend_from_slice(b"BLK");
        buf.extend_from_slice(&serde_json::to_vec(self).expect("header serialization"));
        buf
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

    /// Commitment to the full contents of `txs`:
    /// `SHA3(DOM || count || leaf_1 || ... || leaf_n)` with
    /// `leaf = SHA3(len(payload) || payload || timestamp || len(ml_dsa_sig) ||
    /// ml_dsa_sig || len(slh_dsa_sig) || slh_dsa_sig || signer_address)`.
    /// The signer address binds the public keys (it is their hash). Every
    /// field is length-prefixed, so no two transactions share an encoding.
    pub fn compute_witness_root(txs: &[Transaction]) -> [u8; 32] {
        const DOM: &[u8] = b"QTR/TXWITNESS/v1";
        let mut outer = Sha3_256::new();
        outer.update(DOM);
        outer.update((txs.len() as u64).to_le_bytes());
        for tx in txs {
            let mut h = Sha3_256::new();
            let payload = tx.payload();
            h.update((payload.len() as u64).to_le_bytes());
            h.update(&payload);
            h.update(tx.timestamp.to_le_bytes());
            h.update((tx.signature.ml_dsa_sig.len() as u64).to_le_bytes());
            h.update(&tx.signature.ml_dsa_sig);
            h.update((tx.signature.slh_dsa_sig.len() as u64).to_le_bytes());
            h.update(&tx.signature.slh_dsa_sig);
            h.update(tx.signature.signer_address().0);
            let leaf: [u8; 32] = h.finalize().into();
            outer.update(leaf);
        }
        outer.finalize().into()
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
