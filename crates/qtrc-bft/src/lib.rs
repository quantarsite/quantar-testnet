//! # qtrc-bft
//!
//! Multi-validator consensus for Quantar: the Tendermint algorithm as
//! implemented by Malachite's core crates (state machine, driver, vote
//! keeper), with every proposal and every vote signed by HYDRA-X
//! (ML-DSA-87 AND SLH-DSA-SHA2-256s).
//!
//! Only Malachite's core is used. It has no networking and no crypto of its
//! own: it asks the host, through effects, to sign, verify, publish and
//! schedule timeouts. This crate is that host's vocabulary: the types
//! Malachite is generic over, the bytes each signature covers, and the
//! checks a commit certificate must pass.
//!
//! What a decision means: a block (identified by its hash) is final once
//! validators holding more than two thirds of the voting power have signed
//! a precommit for it in the same round. With 4 validators that is 3, and
//! the network keeps deciding with one of them down or lying.
//!
//! Proposals carry only the block hash (`ValuePayload::ProposalAndParts`);
//! the block travels over the node's own transport and the node reports its
//! validity with `Input::ProposedValue`. Do not use `ProposalOnly`: in
//! Malachite 0.8.2 that mode marks every received proposal valid without
//! asking the host (a TODO in `handle/proposal.rs`), so an invalid block
//! could be decided. The `a_bad_proposal_is_never_decided` test fails in
//! that mode.
//!
//! Status: not wired into the node yet. Malachite has not been externally
//! audited, and neither has this integration; both need an independent
//! review before a network depends on them.

use malachitebft_core_types as mc;
use mc::{NilOrVal, Round, SignedExtension, SignedMessage, VoteType};
use qtrc_crypto::{HydraXKeypair, HydraXSignature};
use std::fmt;
use std::sync::Arc;

pub use malachitebft_core_consensus as consensus;
pub use malachitebft_core_types as types;
pub use malachitebft_metrics as metrics;

// ---------------------------------------------------------------------------
// Address, height, value
// ---------------------------------------------------------------------------

/// A validator's Quantar address: BLAKE3 of its HYDRA-X public keys.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValAddr(pub [u8; 32]);

impl From<&qtrc_crypto::Address> for ValAddr {
    fn from(a: &qtrc_crypto::Address) -> Self {
        ValAddr(a.0)
    }
}

impl fmt::Display for ValAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..6]))
    }
}

impl fmt::Debug for ValAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValAddr({self})")
    }
}

impl mc::Address for ValAddr {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Height(pub u64);

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl mc::Height for Height {
    const ZERO: Self = Height(0);
    const INITIAL: Self = Height(1);

    fn increment_by(&self, n: u64) -> Self {
        Height(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0.checked_sub(n).map(Height)
    }

    fn as_u64(&self) -> u64 {
        self.0
    }
}

/// The hash of a proposed block header. Consensus agrees on this; the block
/// itself travels separately and is checked by the node before it says the
/// proposal is valid.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub [u8; 32]);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..6]))
    }
}

impl fmt::Debug for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockId({self})")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Value(pub BlockId);

impl mc::Value for Value {
    type Id = BlockId;

    fn id(&self) -> BlockId {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Signed messages and the bytes they sign
// ---------------------------------------------------------------------------

/// `chain domain || tag || fields`, fixed-width, so a vote can never be read
/// as a proposal, a transaction or a block header, nor on another chain.
fn sign_prefix(tag: &[u8]) -> Vec<u8> {
    let mut b = qtrc_common::tx::signing_domain_prefix();
    b.extend_from_slice(tag);
    b
}

fn push_round(b: &mut Vec<u8>, r: Round) {
    b.extend_from_slice(&r.as_i64().to_be_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub typ:       VoteType,
    pub height:    Height,
    pub round:     Round,
    pub value:     NilOrVal<BlockId>,
    pub validator: ValAddr,
    pub extension: Option<SignedExtension<Ctx>>,
}

impl Vote {
    /// What a validator signs. The extension is not covered (unused).
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut b = sign_prefix(b"BFTVOTE1");
        b.push(match self.typ {
            VoteType::Prevote => 1,
            VoteType::Precommit => 2,
        });
        b.extend_from_slice(&self.height.0.to_be_bytes());
        push_round(&mut b, self.round);
        match &self.value {
            NilOrVal::Nil => b.push(0),
            NilOrVal::Val(id) => {
                b.push(1);
                b.extend_from_slice(&id.0);
            }
        }
        b.extend_from_slice(&self.validator.0);
        b
    }
}

impl mc::Vote<Ctx> for Vote {
    fn height(&self) -> Height {
        self.height
    }
    fn round(&self) -> Round {
        self.round
    }
    fn value(&self) -> &NilOrVal<BlockId> {
        &self.value
    }
    fn take_value(self) -> NilOrVal<BlockId> {
        self.value
    }
    fn vote_type(&self) -> VoteType {
        self.typ
    }
    fn validator_address(&self) -> &ValAddr {
        &self.validator
    }
    fn extension(&self) -> Option<&SignedExtension<Ctx>> {
        self.extension.as_ref()
    }
    fn take_extension(&mut self) -> Option<SignedExtension<Ctx>> {
        self.extension.take()
    }
    fn extend(self, extension: SignedExtension<Ctx>) -> Self {
        Self { extension: Some(extension), ..self }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub height:    Height,
    pub round:     Round,
    pub value:     Value,
    pub pol_round: Round,
    pub proposer:  ValAddr,
}

impl Proposal {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut b = sign_prefix(b"BFTPROP1");
        b.extend_from_slice(&self.height.0.to_be_bytes());
        push_round(&mut b, self.round);
        b.extend_from_slice(&(self.value.0).0);
        push_round(&mut b, self.pol_round);
        b.extend_from_slice(&self.proposer.0);
        b
    }
}

impl mc::Proposal<Ctx> for Proposal {
    fn height(&self) -> Height {
        self.height
    }
    fn round(&self) -> Round {
        self.round
    }
    fn value(&self) -> &Value {
        &self.value
    }
    fn take_value(self) -> Value {
        self.value
    }
    fn pol_round(&self) -> Round {
        self.pol_round
    }
    fn validator_address(&self) -> &ValAddr {
        &self.proposer
    }
}

/// Blocks travel over the node's transport, not as Malachite proposal
/// parts; the type has to exist but is never used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoParts;

impl mc::ProposalPart<Ctx> for NoParts {
    fn is_first(&self) -> bool {
        true
    }
    fn is_last(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// HYDRA-X as Malachite's signing scheme
// ---------------------------------------------------------------------------

/// A HYDRA-X signature, kept encoded so it can be compared and ordered.
/// It carries the signer's ML-DSA-87 and SLH-DSA public keys.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature(pub Vec<u8>);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HydraX({} bytes)", self.0.len())
    }
}

impl Signature {
    pub fn from_hydrax(s: &HydraXSignature) -> Self {
        Signature(bincode::serialize(s).expect("signature encodes"))
    }

    pub fn decode(&self) -> Option<HydraXSignature> {
        // Bounded: a signature is ~37 KB, refuse anything absurd.
        if self.0.len() > 64 * 1024 {
            return None;
        }
        bincode::deserialize(&self.0).ok()
    }

    /// True only if this signature was made by `signer`'s keys over `msg`.
    /// The address is BLAKE3 of the public keys inside the signature, so the
    /// address check is what binds the keys to the validator.
    pub fn verifies(&self, msg: &[u8], signer: &ValAddr) -> bool {
        let Some(sig) = self.decode() else { return false };
        ValAddr::from(&sig.signer_address()) == *signer && sig.verify(msg).is_ok()
    }
}

/// A validator's private key.
#[derive(Clone)]
pub struct PrivateKey(pub Arc<HydraXKeypair>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraX;

impl mc::SigningScheme for HydraX {
    type DecodingError = String;
    type Signature = Signature;
    /// The public keys travel inside every signature, so a validator's
    /// "public key" here is its address, the hash that binds them.
    type PublicKey = ValAddr;
    type PrivateKey = PrivateKey;

    fn decode_signature(bytes: &[u8]) -> Result<Signature, String> {
        let s = Signature(bytes.to_vec());
        s.decode().map(|_| s).ok_or_else(|| "not a HYDRA-X signature".into())
    }

    fn encode_signature(signature: &Signature) -> Vec<u8> {
        signature.0.clone()
    }

    fn decode_public_key(bytes: &[u8]) -> Result<ValAddr, String> {
        <[u8; 32]>::try_from(bytes).map(ValAddr).map_err(|_| "address must be 32 bytes".into())
    }

    fn encode_public_key(public_key: &ValAddr) -> Vec<u8> {
        public_key.0.to_vec()
    }
}

pub fn sign_vote(key: &HydraXKeypair, vote: Vote) -> SignedMessage<Ctx, Vote> {
    let sig = Signature::from_hydrax(&key.sign(&vote.sign_bytes()));
    SignedMessage::new(vote, sig)
}

pub fn sign_proposal(key: &HydraXKeypair, p: Proposal) -> SignedMessage<Ctx, Proposal> {
    let sig = Signature::from_hydrax(&key.sign(&p.sign_bytes()));
    SignedMessage::new(p, sig)
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub address: ValAddr,
    pub power:   u64,
}

impl mc::Validator<Ctx> for Validator {
    fn address(&self) -> &ValAddr {
        &self.address
    }
    fn public_key(&self) -> &ValAddr {
        &self.address
    }
    fn voting_power(&self) -> u64 {
        self.power
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
}

impl ValidatorSet {
    /// Sorted by address, duplicates and zero-power entries refused, so every
    /// node derives the same order (and the same proposer schedule).
    pub fn new(mut validators: Vec<Validator>) -> Result<Self, String> {
        validators.sort_by_key(|v| v.address);
        if validators.is_empty() {
            return Err("empty validator set".into());
        }
        if validators.windows(2).any(|w| w[0].address == w[1].address) {
            return Err("duplicate validator".into());
        }
        if validators.iter().any(|v| v.power == 0) {
            return Err("validator with zero voting power".into());
        }
        Ok(Self { validators })
    }

    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }
}

impl mc::ValidatorSet<Ctx> for ValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }
    fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.power).sum()
    }
    fn get_by_address(&self, address: &ValAddr) -> Option<&Validator> {
        self.validators.iter().find(|v| v.address == *address)
    }
    fn get_by_index(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Ctx;

impl mc::Context for Ctx {
    type Address = ValAddr;
    type Height = Height;
    type ProposalPart = NoParts;
    type Proposal = Proposal;
    type Validator = Validator;
    type ValidatorSet = ValidatorSet;
    type Timeouts = mc::LinearTimeouts;
    type Value = Value;
    type Vote = Vote;
    type Extension = bytes::Bytes;
    type SigningScheme = HydraX;

    /// Round robin over the sorted set, shifted by height and round, so a
    /// proposer that is down only costs one round.
    fn select_proposer<'a>(&self, vs: &'a ValidatorSet, height: Height, round: Round) -> &'a Validator {
        let n = vs.validators.len();
        let r = round.as_i64().max(0) as u64;
        let i = (height.0.saturating_sub(1).wrapping_add(r) % n as u64) as usize;
        &vs.validators[i]
    }

    fn new_proposal(&self, height: Height, round: Round, value: Value, pol_round: Round, address: ValAddr) -> Proposal {
        Proposal { height, round, value, pol_round, proposer: address }
    }

    fn new_prevote(&self, height: Height, round: Round, value_id: NilOrVal<BlockId>, address: ValAddr) -> Vote {
        Vote { typ: VoteType::Prevote, height, round, value: value_id, validator: address, extension: None }
    }

    fn new_precommit(&self, height: Height, round: Round, value_id: NilOrVal<BlockId>, address: ValAddr) -> Vote {
        Vote { typ: VoteType::Precommit, height, round, value: value_id, validator: address, extension: None }
    }
}

// ---------------------------------------------------------------------------
// Checks the host runs for the consensus core
// ---------------------------------------------------------------------------

/// Verify a signed vote or proposal against the address that claims it.
pub fn verify_consensus_msg(msg: &consensus::ConsensusMsg<Ctx>, sig: &Signature, signer: &ValAddr) -> bool {
    match msg {
        consensus::ConsensusMsg::Vote(v) => v.validator == *signer && sig.verifies(&v.sign_bytes(), signer),
        consensus::ConsensusMsg::Proposal(p) => p.proposer == *signer && sig.verifies(&p.sign_bytes(), signer),
    }
}

/// A commit certificate is valid if distinct validators of `vs` holding
/// more than two thirds of the voting power signed a precommit for exactly
/// this height, round and block.
pub fn verify_commit(cert: &mc::CommitCertificate<Ctx>, vs: &ValidatorSet) -> Result<(), String> {
    use mc::ValidatorSet as _;
    let total = vs.total_voting_power();
    let mut seen = std::collections::BTreeSet::new();
    let mut power = 0u64;
    for cs in &cert.commit_signatures {
        let v = vs
            .get_by_address(&cs.address)
            .ok_or_else(|| format!("{} is not a validator", cs.address))?;
        if !seen.insert(cs.address) {
            return Err(format!("{} signed twice", cs.address));
        }
        let precommit = Vote {
            typ: VoteType::Precommit,
            height: cert.height,
            round: cert.round,
            value: NilOrVal::Val(cert.value_id),
            validator: cs.address,
            extension: None,
        };
        if !cs.signature.verifies(&precommit.sign_bytes(), &cs.address) {
            return Err(format!("bad signature from {}", cs.address));
        }
        power += v.power;
    }
    // Strictly more than 2/3, without rounding: 3 * power > 2 * total.
    if (power as u128) * 3 <= (total as u128) * 2 {
        return Err(format!("only {power} of {total} voting power signed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<HydraXKeypair> {
        (0..n).map(|_| HydraXKeypair::generate()).collect()
    }

    fn addr(k: &HydraXKeypair) -> ValAddr {
        ValAddr::from(&k.address())
    }

    fn vote(k: &HydraXKeypair, id: u8) -> Vote {
        Vote {
            typ: VoteType::Precommit,
            height: Height(7),
            round: Round::new(1),
            value: NilOrVal::Val(BlockId([id; 32])),
            validator: addr(k),
            extension: None,
        }
    }

    #[test]
    fn a_vote_verifies_and_any_change_breaks_it() {
        let k = HydraXKeypair::generate();
        let signed = sign_vote(&k, vote(&k, 1));
        let msg = consensus::ConsensusMsg::Vote(signed.message.clone());
        assert!(verify_consensus_msg(&msg, &signed.signature, &addr(&k)));

        for change in 0..4 {
            let mut v = signed.message.clone();
            match change {
                0 => v.height = Height(8),
                1 => v.round = Round::new(2),
                2 => v.value = NilOrVal::Nil,
                _ => v.typ = VoteType::Prevote,
            }
            let msg = consensus::ConsensusMsg::Vote(v);
            assert!(!verify_consensus_msg(&msg, &signed.signature, &addr(&k)), "change {change} verified");
        }
    }

    #[test]
    fn a_vote_signed_by_another_key_is_refused() {
        let (alice, mallory) = (HydraXKeypair::generate(), HydraXKeypair::generate());
        // Mallory signs a vote that claims to be Alice's.
        let forged = sign_vote(&mallory, vote(&alice, 1));
        let msg = consensus::ConsensusMsg::Vote(forged.message.clone());
        assert!(!verify_consensus_msg(&msg, &forged.signature, &addr(&alice)));
    }

    #[test]
    fn votes_and_proposals_sign_different_bytes() {
        let k = HydraXKeypair::generate();
        let p = Proposal { height: Height(7), round: Round::new(1), value: Value(BlockId([1; 32])), pol_round: Round::Nil, proposer: addr(&k) };
        assert_ne!(p.sign_bytes()[..], vote(&k, 1).sign_bytes()[..]);
        // A proposal signature is no good as a vote signature.
        let sp = sign_proposal(&k, p);
        let msg = consensus::ConsensusMsg::Vote(vote(&k, 1));
        assert!(!verify_consensus_msg(&msg, &sp.signature, &addr(&k)));
    }

    #[test]
    fn commit_needs_more_than_two_thirds_of_distinct_validators() {
        let ks = keys(4);
        let vs = ValidatorSet::new(ks.iter().map(|k| Validator { address: addr(k), power: 1 }).collect()).unwrap();
        let id = BlockId([9; 32]);
        let sig = |k: &HydraXKeypair| {
            let v = Vote { typ: VoteType::Precommit, height: Height(7), round: Round::new(0), value: NilOrVal::Val(id), validator: addr(k), extension: None };
            mc::CommitSignature::new(addr(k), sign_vote(k, v).signature)
        };
        let cert = |sigs: Vec<mc::CommitSignature<Ctx>>| mc::CommitCertificate {
            height: Height(7),
            round: Round::new(0),
            value_id: id,
            commit_signatures: sigs,
        };
        assert!(verify_commit(&cert(vec![sig(&ks[0]), sig(&ks[1]), sig(&ks[2])]), &vs).is_ok());
        // 2 of 4 is not enough.
        assert!(verify_commit(&cert(vec![sig(&ks[0]), sig(&ks[1])]), &vs).is_err());
        // The same validator twice does not count twice.
        assert!(verify_commit(&cert(vec![sig(&ks[0]), sig(&ks[0]), sig(&ks[1])]), &vs).is_err());
        // An outsider does not count at all.
        let outsider = HydraXKeypair::generate();
        assert!(verify_commit(&cert(vec![sig(&ks[0]), sig(&ks[1]), sig(&outsider)]), &vs).is_err());
    }

    #[test]
    fn validator_set_order_is_canonical() {
        let ks = keys(3);
        let a: Vec<_> = ks.iter().map(|k| Validator { address: addr(k), power: 1 }).collect();
        let mut b = a.clone();
        b.reverse();
        assert_eq!(ValidatorSet::new(a.clone()).unwrap(), ValidatorSet::new(b).unwrap());
        let mut dup = a.clone();
        dup.push(a[0].clone());
        assert!(ValidatorSet::new(dup).is_err());
    }
}
