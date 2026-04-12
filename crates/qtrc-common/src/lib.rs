//! # qtrc-common — Shared types
//!
//! Block, Transaction, Genesis, and ChainState definitions shared
//! across all Quantar Network crates.

pub mod block;
pub mod genesis;
pub mod state;
pub mod tx;

pub use block::{Block, BlockHash, BlockHeader};
pub use genesis::Genesis;
pub use qtrc_crypto::Address;
pub use state::{AccountState, ChainState};
pub use tx::{Transaction, TxHash};
