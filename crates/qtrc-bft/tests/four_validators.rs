//! Four validators running Malachite's Tendermint with real HYDRA-X
//! signatures, connected by an in-memory network.
//!
//! Every proposal and vote is signed with ML-DSA-87 AND SLH-DSA-SHA2-256s
//! and verified by every receiver; every decision's commit certificate is
//! checked with `verify_commit`. Timeouts fire when the network goes quiet,
//! which is how a round with a missing or bad proposer ends.

use qtrc_bft::consensus::{process, Effect, Input, LocallyProposedValue, Params, ProposedValue, Resumable, Resume, SignedConsensusMsg, State};
use qtrc_bft::types::{CommitCertificate, Round, Timeout, Validity, ValueOrigin, ValuePayload};
use qtrc_bft::*;
use qtrc_crypto::HydraXKeypair;
use std::collections::{BTreeSet, HashMap, VecDeque};

type Metrics = qtrc_bft::metrics::Metrics;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    Honest,
    /// Receives and sends nothing.
    Offline,
    /// Proposes a block nobody else considers valid.
    BadProposer,
    /// Signs a vote for one block to half the network and for another block
    /// to the other half (double voting).
    Equivocator,
}

struct Node {
    key:       HydraXKeypair,
    addr:      ValAddr,
    state:     State<Ctx>,
    behaviour: Behaviour,
    timeouts:  BTreeSet<(i64, u8)>,
    decided:   Vec<CommitCertificate<Ctx>>,
    finalized: bool,
    wants_value: Option<(Height, Round)>,
    /// Metrics track one node's steps, so each node has its own.
    metrics:   Metrics,
}

struct Net {
    nodes:  Vec<Node>,
    vs:     ValidatorSet,
    queue:  VecDeque<(usize, Input<Ctx>)>,
    /// Blocks every honest node accepts as valid at each height.
    good:   HashMap<u64, BlockId>,
    signed: usize,
    verified: usize,
}

fn timeout_key(t: &Timeout) -> (i64, u8) {
    use qtrc_bft::types::TimeoutKind::*;
    let k = match t.kind {
        Propose => 0,
        Prevote => 1,
        Precommit => 2,
        _ => 3,
    };
    (t.round.as_i64(), k)
}

fn timeout_from_key((r, k): (i64, u8)) -> Timeout {
    use qtrc_bft::types::TimeoutKind::*;
    let kind = match k {
        0 => Propose,
        1 => Prevote,
        _ => Precommit,
    };
    Timeout::new(Round::new(r as u32), kind)
}

impl Net {
    fn new(behaviours: &[Behaviour]) -> Self {
        let keys: Vec<HydraXKeypair> = behaviours.iter().map(|_| HydraXKeypair::generate()).collect();
        let vs = ValidatorSet::new(keys.iter().map(|k| Validator { address: ValAddr::from(&k.address()), power: 1 }).collect()).unwrap();
        // Order nodes like the validator set, so index i is validator i.
        let mut pairs: Vec<(HydraXKeypair, ValAddr)> = keys.into_iter().map(|k| { let a = ValAddr::from(&k.address()); (k, a) }).collect();
        pairs.sort_by_key(|(_, a)| *a);
        let nodes = pairs
            .into_iter()
            .zip(behaviours)
            .map(|((key, addr), &behaviour)| Node {
                state: State::new(
                    Ctx,
                    Height(1),
                    vs.clone(),
                    Params { address: addr, threshold_params: Default::default(), value_payload: ValuePayload::ProposalAndParts, enabled: true },
                    1000,
                    1000,
                ),
                key,
                addr,
                behaviour,
                timeouts: BTreeSet::new(),
                decided: Vec::new(),
                finalized: false,
                wants_value: None,
                metrics: Metrics::new(),
            })
            .collect();
        Net { nodes, vs, queue: VecDeque::new(), good: HashMap::new(), signed: 0, verified: 0 }
    }

    fn good_block(&mut self, h: u64) -> BlockId {
        *self.good.entry(h).or_insert_with(|| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&h.to_be_bytes());
            b[8] = 0x60;
            BlockId(b)
        })
    }

    /// Feed one input to one node, handle its effects, queue what it sends.
    fn step(&mut self, i: usize, input: Input<Ctx>) {
        if self.nodes[i].behaviour == Behaviour::Offline {
            return;
        }
        let vs = self.vs.clone();
        let mut outbox: Vec<SignedConsensusMsg<Ctx>> = Vec::new();
        let (mut signed, mut verified) = (0, 0);
        let node = &mut self.nodes[i];
        let key = &node.key;
        let timeouts = &mut node.timeouts;
        let decided = &mut node.decided;
        let finalized = &mut node.finalized;
        let wants = &mut node.wants_value;
        let r: Result<(), qtrc_bft::consensus::Error<Ctx>> = process!(
            input: input,
            state: &mut node.state,
            metrics: &node.metrics,
            with: effect => {
                let resume: Result<Resume<Ctx>, ()> = Ok(match effect {
                    Effect::ScheduleTimeout(t, r) => { timeouts.insert(timeout_key(&t)); r.resume_with(()) }
                    Effect::CancelTimeout(t, r) => { timeouts.remove(&timeout_key(&t)); r.resume_with(()) }
                    Effect::CancelAllTimeouts(r) => { timeouts.clear(); r.resume_with(()) }
                    Effect::PublishConsensusMsg(m, r) => { outbox.push(m); r.resume_with(()) }
                    Effect::GetValue(h, round, _, r) => { *wants = Some((h, round)); r.resume_with(()) }
                    Effect::SignVote(v, r) => { signed += 1; r.resume_with(sign_vote(key, v)) }
                    Effect::SignProposal(p, r) => { signed += 1; r.resume_with(sign_proposal(key, p)) }
                    Effect::VerifySignature(m, signer, r) => {
                        verified += 1;
                        r.resume_with(verify_consensus_msg(&m.message, &m.signature, &signer))
                    }
                    Effect::VerifyCommitCertificate(c, set, _, r) => {
                        let ok = verify_commit(&c, &set).is_ok();
                        assert!(ok, "unexpected bad certificate");
                        r.resume_with(Ok(()))
                    }
                    Effect::Decide(c, _, r) => {
                        verify_commit(&c, &vs).expect("decided on an invalid certificate");
                        decided.push(c);
                        r.resume_with(())
                    }
                    Effect::Finalize(_, _, _, r) => { *finalized = true; r.resume_with(()) }
                    Effect::ExtendVote(_, _, _, _, r) => r.resume_with(None),
                    Effect::VerifyVoteExtension(_, _, _, _, _, _, r) => r.resume_with(Ok(())),
                    _ => Resume::Continue,
                });
                resume
            }
        );
        if let Err(e) = r {
            panic!("node {i}: consensus error: {e:?}");
        }
        self.signed += signed;
        self.verified += verified;

        for m in outbox {
            for j in 0..self.nodes.len() {
                if j == i {
                    continue;
                }
                match &m {
                    SignedConsensusMsg::Vote(v) if self.nodes[i].behaviour == Behaviour::Equivocator && j % 2 == 1 => {
                        let mut other = v.message.clone();
                        other.value = qtrc_bft::types::NilOrVal::Val(BlockId([0xEE; 32]));
                        self.signed += 1;
                        self.queue.push_back((j, Input::Vote(sign_vote(&self.nodes[i].key, other))));
                    }
                    SignedConsensusMsg::Vote(v) => self.queue.push_back((j, Input::Vote(v.clone()))),
                    SignedConsensusMsg::Proposal(p) => {
                        self.queue.push_back((j, Input::Proposal(p.clone())));
                        // The block travels with the proposal; the receiver
                        // checks it and tells consensus whether it is valid.
                        let p = &p.message;
                        let valid = self.good.get(&p.height.0) == Some(&p.value.0);
                        self.queue.push_back((
                            j,
                            Input::ProposedValue(
                                ProposedValue {
                                    height: p.height,
                                    round: p.round,
                                    valid_round: p.pol_round,
                                    proposer: p.proposer,
                                    value: p.value.clone(),
                                    validity: if valid { Validity::Valid } else { Validity::Invalid },
                                },
                                ValueOrigin::Consensus,
                            ),
                        ));
                    }
                }
            }
        }

        // Asked for a block: build one (or, if misbehaving, a bad one).
        if let Some((h, round)) = self.nodes[i].wants_value.take() {
            let id = match self.nodes[i].behaviour {
                Behaviour::BadProposer => BlockId([0xBA; 32]),
                _ => self.good_block(h.0),
            };
            self.step(i, Input::Propose(LocallyProposedValue::new(h, round, Value(id))));
        }
    }

    /// Run one height on every node until every running node finalizes it.
    fn run_height(&mut self, h: u64) {
        self.good_block(h);
        for n in &mut self.nodes {
            n.finalized = false;
            n.timeouts.clear();
        }
        for i in 0..self.nodes.len() {
            let input = Input::StartHeight(Height(h), self.vs.clone(), false, None, Default::default());
            self.step(i, input);
        }
        let mut quiet_rounds = 0;
        loop {
            while let Some((i, input)) = self.queue.pop_front() {
                self.step(i, input);
            }
            let running: Vec<usize> = (0..self.nodes.len()).filter(|&i| self.nodes[i].behaviour != Behaviour::Offline).collect();
            if running.iter().all(|&i| self.nodes[i].finalized) {
                return;
            }
            // Network quiet and not done: the scheduled timeouts fire.
            quiet_rounds += 1;
            assert!(quiet_rounds < 20, "height {h} did not finish");
            for i in running {
                let fire: Vec<_> = std::mem::take(&mut self.nodes[i].timeouts).into_iter().collect();
                for k in fire {
                    self.step(i, Input::TimeoutElapsed(timeout_from_key(k)));
                }
            }
        }
    }

    fn decided_at(&self, i: usize, h: u64) -> Option<&CommitCertificate<Ctx>> {
        self.nodes[i].decided.iter().find(|c| c.height == Height(h))
    }
}

#[test]
fn four_honest_validators_agree_on_three_blocks() {
    let mut net = Net::new(&[Behaviour::Honest; 4]);
    for h in 1..=3 {
        net.run_height(h);
        for i in 0..4 {
            let c = net.decided_at(i, h).expect("every node decides");
            assert_eq!(c.value_id, net.good[&h], "node {i} decided another block at {h}");
            assert_eq!(c.round, Round::new(0), "no round should be lost");
            assert!(c.commit_signatures.len() >= 3);
        }
    }
    eprintln!("HYDRA-X signatures: {} made, {} verified", net.signed, net.verified);
}

#[test]
fn one_validator_offline_does_not_stop_the_network() {
    // Whichever validator this is, it is the proposer for some round, so
    // over three heights at least one round has to time out.
    let mut net = Net::new(&[Behaviour::Offline, Behaviour::Honest, Behaviour::Honest, Behaviour::Honest]);
    for h in 1..=3 {
        net.run_height(h);
        for i in 1..4 {
            let c = net.decided_at(i, h).expect("the three others decide");
            assert_eq!(c.value_id, net.good[&h]);
            assert!(!c.commit_signatures.iter().any(|s| s.address == net.nodes[0].addr), "offline node cannot have signed");
        }
    }
    // Height 1's proposer is validator 0 (round 0): that round was lost.
    assert!(net.decided_at(1, 1).unwrap().round > Round::new(0));
}

#[test]
fn a_bad_proposal_is_never_decided() {
    let mut net = Net::new(&[Behaviour::BadProposer, Behaviour::Honest, Behaviour::Honest, Behaviour::Honest]);
    net.run_height(1);
    for i in 1..4 {
        let c = net.decided_at(i, 1).expect("decides in a later round");
        assert_eq!(c.value_id, net.good[&1]);
        assert_ne!(c.value_id, BlockId([0xBA; 32]));
        assert!(c.round > Round::new(0));
    }
}

#[test]
fn two_offline_validators_halt_safely() {
    // With 2 of 4 down nobody can reach 3 votes: no decision, and above all
    // no conflicting ones. Tendermint stops rather than fork.
    let mut net = Net::new(&[Behaviour::Offline, Behaviour::Offline, Behaviour::Honest, Behaviour::Honest]);
    for i in 0..4 {
        let input = Input::StartHeight(Height(1), net.vs.clone(), false, None, Default::default());
        net.step(i, input);
    }
    for _ in 0..6 {
        while let Some((i, input)) = net.queue.pop_front() {
            net.step(i, input);
        }
        for i in 2..4 {
            let fire: Vec<_> = std::mem::take(&mut net.nodes[i].timeouts).into_iter().collect();
            for k in fire {
                net.step(i, Input::TimeoutElapsed(timeout_from_key(k)));
            }
        }
    }
    assert!(net.decided_at(2, 1).is_none() && net.decided_at(3, 1).is_none());
}

#[test]
fn a_double_voting_validator_cannot_split_the_network() {
    let mut net = Net::new(&[Behaviour::Honest, Behaviour::Equivocator, Behaviour::Honest, Behaviour::Honest]);
    for h in 1..=2 {
        net.run_height(h);
        let decided: Vec<BlockId> = [0, 2, 3].iter().map(|&i| net.decided_at(i, h).expect("honest nodes decide").value_id).collect();
        assert!(decided.iter().all(|d| *d == net.good[&h]), "honest nodes disagree at {h}: {decided:?}");
    }
}

#[test]
fn forged_votes_do_not_count() {
    // Two validators down, so the two honest ones cannot decide on their
    // own. An attacker without their keys sends precommits in their name
    // for the honest block. If forged votes counted, this would decide.
    let mut net = Net::new(&[Behaviour::Offline, Behaviour::Offline, Behaviour::Honest, Behaviour::Honest]);
    let mallory = HydraXKeypair::generate();
    let good = net.good_block(1);
    for i in 0..4 {
        let input = Input::StartHeight(Height(1), net.vs.clone(), false, None, Default::default());
        net.step(i, input);
    }
    for _ in 0..4 {
        while let Some((i, input)) = net.queue.pop_front() {
            net.step(i, input);
        }
        for victim in 0..2 {
            for typ in [qtrc_bft::types::VoteType::Prevote, qtrc_bft::types::VoteType::Precommit] {
                for round in 0..4 {
                    let forged = Vote {
                        typ,
                        height: Height(1),
                        round: Round::new(round),
                        value: qtrc_bft::types::NilOrVal::Val(good),
                        validator: net.nodes[victim].addr,
                        extension: None,
                    };
                    let signed = sign_vote(&mallory, forged);
                    for target in 2..4 {
                        net.queue.push_back((target, Input::Vote(signed.clone())));
                    }
                }
            }
        }
        while let Some((i, input)) = net.queue.pop_front() {
            net.step(i, input);
        }
        for i in 2..4 {
            let fire: Vec<_> = std::mem::take(&mut net.nodes[i].timeouts).into_iter().collect();
            for k in fire {
                net.step(i, Input::TimeoutElapsed(timeout_from_key(k)));
            }
        }
    }
    assert!(net.decided_at(2, 1).is_none() && net.decided_at(3, 1).is_none(), "a forged vote was counted");
}
