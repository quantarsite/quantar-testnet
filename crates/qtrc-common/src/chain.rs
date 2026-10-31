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
    /// Sentinel recoveries signed over the full message (no 32-byte digest).
    pub recovery_v3: u64,
    /// Sentinel `UpdatePolicy` operations accepted.
    pub policy_update: u64,
}

/// Genesis faucet of quantar-testnet-2, the live network.
pub const TESTNET2_FAUCET: &str = "9b7eb38c5f5b8fa2248fa761a4ec4730554aed10b9a6a9069c9e2db3ea1f7aaf";

/// The only validator of quantar-testnet-2 so far: it proposed and signed
/// every block. Fixing it here lets a node with another key (a follower, or
/// a future validator) check the history instead of expecting its own
/// signature on every block.
pub const TESTNET2_VALIDATOR: &str = "809ae6fb45d3d7c9a2c2f3968c58cc55ad6bb2ca2cfe84f65619c013bbcbbbff";

/// Rules of quantar-testnet-2 as they happened on the live node: fee from
/// block 5 (v2.0.2), Sentinel from 6 (v2.1.0), state root from 15
/// (v2.3.0), witness root from 20 (v2.4.0), policy changes from 40
/// (v2.8.0), full-message recoveries from 60 (v2.9.0).
///
/// Every node must ship the same numbers, so each one is fixed in the
/// release that turns its rule on, above the live tip at that moment.
pub const TESTNET2: Activations =
    Activations {
        fee: 5,
        sentinel: 6,
        state_root: 15,
        witness_root: 20,
        recovery_v3: RECOVERY_V3_TESTNET2,
        policy_update: POLICY_UPDATE_TESTNET2,
    };

/// Height at which quantar-testnet-2 switches Sentinel recoveries to the
/// full-message (v3) encoding. Fixed in v2.9.0 above the live tip (21 when
/// it was chosen, with the policy change at 40 still ahead), leaving room
/// to remake the watchtower's kits after the deploy and before the switch.
pub const RECOVERY_V3_TESTNET2: u64 = 60;

/// Height at which quantar-testnet-2 starts accepting Sentinel policy
/// changes. Fixed in v2.8.0 above the live tip (21 when it was chosen),
/// the same on every node.
pub const POLICY_UPDATE_TESTNET2: u64 = 40;

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

/// The validator set of `genesis`, if it is a known network.
#[must_use]
pub fn known_validators(genesis: &Genesis) -> Option<Vec<qtrc_crypto::Address>> {
    known_activations(genesis)?;
    Some(vec![qtrc_crypto::Address::from_hex(TESTNET2_VALIDATOR).expect("valid constant")])
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
            let live = Genesis::testnet_with_faucet(Some(TESTNET2_FAUCET));
            assert_eq!(known_activations(&live), Some(TESTNET2));
            assert_eq!(known_validators(&live).unwrap()[0].as_hex(), TESTNET2_VALIDATOR);
        }
        assert!(known_validators(&Genesis::testnet_with_faucet(None)).is_none());
    }
}
