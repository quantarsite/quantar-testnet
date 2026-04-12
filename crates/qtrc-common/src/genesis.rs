//! Genesis configuration — initial balances and validator set.

use crate::block::{Block, BlockHash, BlockHeader};
use crate::state::{AccountState, ChainState, ValidatorInfo};
use crate::tx::TxHash;
use qtrc_crypto::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 1 QTR = 1_000_000 micro-QTR
pub const MICRO_QTR: u64 = 1_000_000;

/// Genesis allocation entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAlloc {
    pub address: String,
    pub balance: u64,
}

/// Genesis configuration file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id:   String,
    pub timestamp:  i64,
    pub allocations: Vec<GenesisAlloc>,
    pub validators:  Vec<GenesisValidator>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: String,
    pub stake:   u64,
}

impl Genesis {
    /// Quantar Testnet genesis configuration.
    pub fn testnet() -> Self {
        Genesis {
            chain_id:  "quantar-testnet-1".into(),
            timestamp: 1_745_000_000, // fixed genesis time
            allocations: vec![
                // Faucet wallet — 10M QTR for testnet distribution
                GenesisAlloc {
                    address: "faucet_placeholder_replace_with_real_address".into(),
                    balance: 10_000_000 * MICRO_QTR,
                },
            ],
            validators: vec![],
        }
    }

    /// Build the genesis ChainState from this configuration.
    pub fn initial_state(&self) -> ChainState {
        let mut accounts = HashMap::new();

        for alloc in &self.allocations {
            accounts.insert(
                alloc.address.clone(),
                AccountState {
                    balance: alloc.balance,
                    nonce:   0,
                },
            );
        }

        let validators = self
            .validators
            .iter()
            .map(|v| ValidatorInfo {
                address: Address::from_hex(&v.address)
                    .expect("invalid validator address in genesis"),
                stake: v.stake,
            })
            .collect();

        ChainState {
            height:     0,
            block_hash: BlockHash::zero(),
            accounts,
            validators,
        }
    }

    /// Build the genesis block (height 0, no transactions).
    pub fn genesis_block(&self) -> Block {
        use qtrc_crypto::Address;

        // Proposer in genesis block = zero address (no proposer)
        let proposer = Address([0u8; 32]);

        let header = BlockHeader {
            height:      0,
            prev_hash:   BlockHash::zero(),
            merkle_root: TxHash([0u8; 32]),
            timestamp:   self.timestamp,
            proposer,
        };

        Block {
            header,
            transactions:   vec![],
            validator_sigs: vec![],
        }
    }
}
