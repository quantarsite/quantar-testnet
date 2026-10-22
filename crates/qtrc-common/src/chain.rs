//! Fixed parameters of the live network, so any node, including a new
//! validator on another provider, rebuilds exactly the same chain from the
//! code alone: the genesis faucet and the heights where each rule turned on.
//!
//! Before this, activation heights were recorded per data directory when a
//! node first saw a release. That was right for one node but cannot work
//! for a second one: an empty data dir would turn every rule on at block 1
//! and reject the real blocks 1 to 14.

use crate::genesis::{Genesis, MICRO_QTR};

/// Heights from which each consensus rule applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activations {
    pub fee: u64,
    pub sentinel: u64,
    pub state_root: u64,
    pub witness_root: u64,
}

/// Genesis faucet of quantar-testnet-2, the live network.
pub const TESTNET2_FAUCET: &str = "9b7eb38c5f5b8fa2248fa761a4ec4730554aed10b9a6a9069c9e2db3ea1f7aaf";

/// Rules of quantar-testnet-2 as they happened on the live node: fee from
/// block 5 (v2.0.2), Sentinel from 6 (v2.1.0), state root from 15
/// (v2.3.0), witness root from 20 (v2.4.0).
pub const TESTNET2: Activations = Activations { fee: 5, sentinel: 6, state_root: 15, witness_root: 20 };

/// The fixed activations of `genesis`, if it is a known network.
#[must_use]
pub fn known_activations(genesis: &Genesis) -> Option<Activations> {
    let live = !TESTNET2_FAUCET.is_empty()
        && genesis.chain_id == crate::tx::CHAIN_ID
        && genesis.timestamp == crate::genesis::TESTNET2_TIMESTAMP
        && genesis.validators.is_empty()
        && genesis.allocations.len() == 1
        && genesis.allocations[0].address == TESTNET2_FAUCET
        && genesis.allocations[0].balance == 10_000_000 * MICRO_QTR;
    live.then_some(TESTNET2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_live_genesis_is_known() {
        assert_eq!(known_activations(&Genesis::testnet_with_faucet(None)), None);
        let other = "11".repeat(32);
        assert_eq!(known_activations(&Genesis::testnet_with_faucet(Some(&other))), None);
        if !TESTNET2_FAUCET.is_empty() {
            assert_eq!(known_activations(&Genesis::testnet_with_faucet(Some(TESTNET2_FAUCET))), Some(TESTNET2));
        }
    }
}
