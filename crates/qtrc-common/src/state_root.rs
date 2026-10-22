//! State root: a Merkle commitment to every account, so anyone holding a
//! validator-signed block header can check one account's balance, nonce
//! and Sentinel vault without trusting the node that served them.
//!
//! Leaves are the non-empty accounts sorted by address bytes:
//! `H(0x00 || DOM_LEAF || address || balance || nonce || vault_flag || vault_hash)`,
//! internal nodes are `H(0x01 || left || right)`, and an odd node at the end
//! of a level is promoted unchanged (never duplicated, which would allow two
//! different leaf sets with the same root). The root binds the tree top to
//! the leaf count and the burned total:
//! `H(DOM_ROOT || count || burned || top)`.
//!
//! An account is empty, and left out, when its balance and nonce are zero
//! and it has no vault.

use crate::state::ChainState;
use qtrc_crypto::Address;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub type Hash = [u8; 32];

const DOM_LEAF: &[u8] = b"QTR/STATE/LEAF/v1";
const DOM_ROOT: &[u8] = b"QTR/STATE/ROOT/v1";
const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

/// One account as committed in the state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    pub address: Address,
    pub balance: u64,
    pub nonce: u64,
    /// SHA3-256 of the account's Sentinel vault (bincode), if it has one.
    #[serde(with = "opt_hex")]
    pub vault_hash: Option<Hash>,
}

impl Leaf {
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut h = Sha3_256::new();
        h.update([LEAF]);
        h.update(DOM_LEAF);
        h.update(self.address.0);
        h.update(self.balance.to_le_bytes());
        h.update(self.nonce.to_le_bytes());
        match &self.vault_hash {
            Some(v) => {
                h.update([1u8]);
                h.update(v);
            }
            None => h.update([0u8]),
        }
        h.finalize().into()
    }
}

fn node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha3_256::new();
    h.update([NODE]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn finish(count: u64, burned: u64, top: &Hash) -> Hash {
    let mut h = Sha3_256::new();
    h.update(DOM_ROOT);
    h.update(count.to_le_bytes());
    h.update(burned.to_le_bytes());
    h.update(top);
    h.finalize().into()
}

/// Inclusion proof for one account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub leaf: Leaf,
    /// Position of the leaf among the sorted non-empty accounts
    pub index: u64,
    /// Number of leaves in the tree
    pub count: u64,
    /// Total micro-QTR burned, committed in the root
    pub burned: u64,
    /// Sibling hashes from the leaf up; levels where the node was promoted
    /// have no sibling. Sides are derived from `index` and `count`.
    #[serde(with = "vec_hex")]
    pub siblings: Vec<Hash>,
}

impl Proof {
    /// Root this proof leads to, or None if its shape is inconsistent.
    #[must_use]
    pub fn root(&self) -> Option<Hash> {
        if self.count == 0 || self.index >= self.count {
            return None;
        }
        let mut acc = self.leaf.hash();
        let (mut idx, mut len) = (self.index, self.count);
        let mut sib = self.siblings.iter();
        while len > 1 {
            let promoted = idx == len - 1 && len % 2 == 1;
            if !promoted {
                let s = sib.next()?;
                acc = if idx % 2 == 0 { node(&acc, s) } else { node(s, &acc) };
            }
            idx /= 2;
            len = len.div_ceil(2);
        }
        if sib.next().is_some() {
            return None; // extra siblings: malformed
        }
        Some(finish(self.count, self.burned, &acc))
    }

    /// Whether this proof shows `leaf` is in the state committed by `root`.
    #[must_use]
    pub fn verify(&self, root: &Hash) -> bool {
        self.root().as_ref() == Some(root)
    }
}

/// The full tree for one state: built once per committed block and kept,
/// so proofs cost O(log n) and never touch the live chain state.
#[derive(Clone, Debug, Default)]
pub struct StateTree {
    leaves: Vec<Leaf>,
    /// `levels[0]` are the leaf hashes, the last level is the top.
    levels: Vec<Vec<Hash>>,
    burned: u64,
}

impl StateTree {
    fn build(leaves: Vec<Leaf>, burned: u64) -> Self {
        let mut levels = vec![leaves.iter().map(Leaf::hash).collect::<Vec<Hash>>()];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let next = levels
                .last()
                .expect("non-empty")
                .chunks(2)
                .map(|p| if p.len() == 2 { node(&p[0], &p[1]) } else { p[0] })
                .collect();
            levels.push(next);
        }
        Self { leaves, levels, burned }
    }

    /// The state root.
    #[must_use]
    pub fn root(&self) -> Hash {
        let top = self.levels.last().and_then(|l| l.first()).copied().unwrap_or([0u8; 32]);
        finish(self.leaves.len() as u64, self.burned, &top)
    }

    /// Inclusion proof for `addr`, or None if the account is empty.
    #[must_use]
    pub fn proof(&self, addr: &Address) -> Option<Proof> {
        let index = self.leaves.binary_search_by(|l| l.address.0.cmp(&addr.0)).ok()?;
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let len = level.len();
            let promoted = idx == len - 1 && len % 2 == 1;
            if !promoted {
                siblings.push(level[idx ^ 1]);
            }
            idx /= 2;
        }
        Some(Proof {
            leaf: self.leaves[index].clone(),
            index: index as u64,
            count: self.leaves.len() as u64,
            burned: self.burned,
            siblings,
        })
    }
}

impl ChainState {
    /// Non-empty accounts as leaves, sorted by address bytes.
    #[must_use]
    pub fn leaves(&self) -> Vec<Leaf> {
        let mut keys: Vec<&String> = self.accounts.keys().chain(self.vaults.keys()).collect();
        keys.sort();
        keys.dedup();
        let mut out: Vec<Leaf> = keys
            .into_iter()
            .filter_map(|k| {
                let address = Address::from_hex(k).ok()?;
                let acct = self.account(&address);
                // Canonical, versioned encoding: storage format changes can
                // never alter past roots.
                let vault_hash = self.vaults.get(k).map(|v| -> Hash { Sha3_256::digest(v.canonical_encoding()).into() });
                if acct.balance == 0 && acct.nonce == 0 && vault_hash.is_none() {
                    return None;
                }
                Some(Leaf { address, balance: acct.balance, nonce: acct.nonce, vault_hash })
            })
            .collect();
        out.sort_by_key(|l| l.address.0);
        out
    }

    /// Full tree of this state (for serving many proofs).
    #[must_use]
    pub fn state_tree(&self) -> StateTree {
        StateTree::build(self.leaves(), self.burned)
    }

    /// The state root of this state.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        self.state_tree().root()
    }

    /// Inclusion proof for `addr`, or None if the account is empty.
    #[must_use]
    pub fn state_proof(&self, addr: &Address) -> Option<Proof> {
        self.state_tree().proof(addr)
    }
}

pub(crate) mod opt_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(h) => s.serialize_some(&hex::encode(h)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let o: Option<String> = Option::deserialize(d)?;
        o.map(|s| {
            hex::decode(&s)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| serde::de::Error::custom("expected 32-byte hex"))
        })
        .transpose()
    }
}

mod vec_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        v.iter()
            .map(|s| {
                hex::decode(s)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| serde::de::Error::custom("expected 32-byte hex"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AccountState;

    fn addr(i: u8) -> Address {
        let mut a = [0u8; 32];
        a[0] = i;
        a[31] = i.wrapping_mul(7);
        Address(a)
    }

    fn state(n: u8) -> ChainState {
        let mut st = crate::genesis::Genesis::testnet_with_faucet(None).initial_state();
        for i in 1..=n {
            st.accounts.insert(addr(i).as_hex(), AccountState { balance: u64::from(i) * 100, nonce: u64::from(i % 3) });
        }
        st
    }

    #[test]
    fn every_account_proves_for_many_tree_sizes() {
        for n in 1..=33u8 {
            let st = state(n);
            let root = st.state_root();
            for i in 1..=n {
                let p = st.state_proof(&addr(i)).unwrap();
                assert!(p.verify(&root), "n={n} i={i}");
                assert_eq!(p.leaf.balance, u64::from(i) * 100);
            }
        }
    }

    #[test]
    fn tampered_proofs_fail() {
        let st = state(9);
        let root = st.state_root();
        let good = st.state_proof(&addr(5)).unwrap();
        let mut p = good.clone();
        p.leaf.balance += 1;
        assert!(!p.verify(&root), "balance changed");
        let mut p = good.clone();
        p.leaf.nonce += 1;
        assert!(!p.verify(&root), "nonce changed");
        let mut p = good.clone();
        p.index ^= 1;
        assert!(!p.verify(&root), "position changed");
        let mut p = good.clone();
        p.count += 1;
        assert!(!p.verify(&root), "count changed");
        let mut p = good.clone();
        p.burned += 1;
        assert!(!p.verify(&root), "burned changed");
        let mut p = good.clone();
        p.siblings[0][0] ^= 1;
        assert!(!p.verify(&root), "sibling changed");
        let mut p = good.clone();
        p.siblings.push([0u8; 32]);
        assert!(!p.verify(&root), "extra sibling");
        let mut p = good;
        p.siblings.pop();
        assert!(!p.verify(&root), "missing sibling");
    }

    #[test]
    fn root_changes_with_any_account_and_ignores_empty_ones() {
        let st = state(6);
        let r = st.state_root();
        let mut s2 = st.clone();
        s2.accounts.get_mut(&addr(3).as_hex()).unwrap().balance += 1;
        assert_ne!(s2.state_root(), r);
        let mut s3 = st.clone();
        s3.accounts.insert(addr(99).as_hex(), AccountState::default());
        assert_eq!(s3.state_root(), r, "empty account does not count");
        let mut s4 = st.clone();
        s4.burned += 1;
        assert_ne!(s4.state_root(), r);
        assert!(st.state_proof(&addr(99)).is_none());
    }

    #[test]
    fn promoted_node_cannot_be_forged_by_duplication() {
        // With duplication-style trees, [a,b,c] and [a,b,c,c] share a root.
        let st3 = state(3);
        let mut st4 = st3.clone();
        let c = st3.accounts[&addr(3).as_hex()].clone();
        st4.accounts.insert(addr(4).as_hex(), c);
        assert_ne!(st3.state_root(), st4.state_root());
    }

    #[test]
    fn proof_roundtrips_as_json() {
        let st = state(5);
        let p = st.state_proof(&addr(2)).unwrap();
        let back: Proof = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert!(back.verify(&st.state_root()));
    }
}
