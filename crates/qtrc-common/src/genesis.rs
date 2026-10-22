//! Genesis configuration — initial balances and validator set.

use crate::block::{Block, BlockHash, BlockHeader};
use crate::state::{AccountState, ChainState, ValidatorInfo};
use crate::tx::TxHash;
use qtrc_crypto::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Genesis time of quantar-testnet-2: 2026-10-18 00:00:00 UTC.
pub const TESTNET2_TIMESTAMP: i64 = 1_792_281_600;

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
    /// Quantar Testnet v2 genesis configuration.
    ///
    /// The faucet allocation goes to the address in `QTR_FAUCET_ADDRESS`,
    /// or, without it, to the live network's faucet, so a new node joins
    /// the real chain with no configuration.
    pub fn testnet() -> Self {
        let env = std::env::var("QTR_FAUCET_ADDRESS").ok();
        let live = Some(crate::chain::TESTNET2_FAUCET).filter(|a| !a.is_empty());
        Self::testnet_with_faucet(env.as_deref().or(live))
    }

    /// Same as [`Genesis::testnet`] with the faucet address passed in.
    pub fn testnet_with_faucet(faucet_address: Option<&str>) -> Self {
        let allocations = match faucet_address {
            Some(addr) if Address::from_hex(addr.trim()).is_ok() => vec![
                // Faucet wallet: 10M QTR for testnet distribution
                GenesisAlloc {
                    address: addr.trim().to_lowercase(),
                    balance: 10_000_000 * MICRO_QTR,
                },
            ],
            _ => vec![],
        };

        Genesis {
            chain_id:  crate::tx::CHAIN_ID.into(),
            timestamp: TESTNET2_TIMESTAMP,
            allocations,
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
            fee_from_height: 1,
            burned: 0,
            sentinel_from_height: 1,
            state_root_from_height: 1,
            witness_root_from_height: 1,
            vaults: Default::default(),
            touched: Default::default(),
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
            state_root:  None,
            witness_root: None,
        };

        Block {
            header,
            transactions:   vec![],
            validator_sigs: vec![],
        }
    }
}
