//! Four validators make a real chain together: real blocks with real
//! HYDRA-X transactions, built and checked by `ConsensusEngine`, decided by
//! Malachite's Tendermint through `qtrc_bft::runner`, and committed only
//! with a commit proof. Then an outside node replays the chain from the
//! blocks alone, and blocks with missing or short proofs are refused.

use qtrc_bft::runner::{Action, Runner, SignGuard};
use qtrc_bft::types::{LinearTimeouts, Round, SignedProposal, Timeout};
use qtrc_bft::{commit_proof, BlockId, Height};
use qtrc_common::block::Block;
use qtrc_common::genesis::{Genesis, MICRO_QTR};
use qtrc_common::state::{ChainState, ValidatorInfo};
use qtrc_common::tx::Transaction;
use qtrc_consensus::ConsensusEngine;
use qtrc_crypto::HydraXKeypair;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

enum Msg {
    Vote(qtrc_bft::types::SignedVote<qtrc_bft::Ctx>),
    /// A proposal travels with the block it names.
    Proposal(SignedProposal<qtrc_bft::Ctx>, Box<Block>),
}

struct Val {
    engine:   ConsensusEngine,
    runner:   Runner,
    timeouts: Vec<Timeout>,
    done:     bool,
    online:   bool,
}

struct Net {
    vals:  Vec<Val>,
    queue: VecDeque<(usize, Msg)>,
    built: HashMap<BlockId, Block>,
    committed: Vec<Block>,
}

fn setup(n: usize) -> (Net, HydraXKeypair, ChainState) {
    let faucet = HydraXKeypair::generate();
    let keys: Vec<Arc<HydraXKeypair>> = (0..n).map(|_| Arc::new(HydraXKeypair::generate())).collect();
    let mut start = Genesis::testnet_with_faucet(Some(&faucet.address().as_hex())).initial_state();
    start.validators = keys.iter().map(|k| ValidatorInfo { address: k.address(), stake: 1 }).collect();
    start.bft_from_height = 1;
    let vals = keys
        .iter()
        .map(|k| {
            let kp = HydraXKeypair::from_bytes(&k.to_bytes()).unwrap();
            let engine = ConsensusEngine::new(start.clone(), kp);
            let vs = engine.bft_validator_set().unwrap();
            let runner = Runner::new(k.clone(), vs, Height(1), SignGuard::ephemeral(), LinearTimeouts::default());
            Val { engine, runner, timeouts: vec![], done: false, online: true }
        })
        .collect();
    (Net { vals, queue: VecDeque::new(), built: HashMap::new(), committed: vec![] }, faucet, start)
}

fn transfer(from: &HydraXKeypair, nonce: u64) -> Transaction {
    let to = HydraXKeypair::generate().address();
    let p = Transaction::signing_payload(&from.address(), &to, MICRO_QTR, nonce);
    Transaction { from: from.address(), to, amount: MICRO_QTR, nonce, timestamp: 0, signature: from.sign(&p), data: vec![] }
}

impl Net {
    fn act(&mut self, i: usize, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Publish(m) => {
                    let msg_for = |m: &qtrc_bft::consensus::SignedConsensusMsg<qtrc_bft::Ctx>, built: &HashMap<BlockId, Block>| match m {
                        qtrc_bft::consensus::SignedConsensusMsg::Vote(v) => Msg::Vote(v.clone()),
                        qtrc_bft::consensus::SignedConsensusMsg::Proposal(p) => {
                            let block = built.get(&p.message.value.0).expect("proposer built this block").clone();
                            Msg::Proposal(p.clone(), Box::new(block))
                        }
                    };
                    for j in 0..self.vals.len() {
                        if j != i {
                            self.queue.push_back((j, msg_for(&m, &self.built)));
                        }
                    }
                }
                Action::BuildBlock { height, round } => {
                    let block = self.vals[i].engine.propose_block().expect("proposer builds a block");
                    assert_eq!(block.header.height, height.0);
                    let id = BlockId(block.hash().0);
                    self.built.insert(id, block);
                    let more = self.vals[i].runner.propose(height, round, id);
                    self.act(i, more);
                }
                Action::ScheduleTimeout(t, _) => self.vals[i].timeouts.push(t),
                Action::CancelTimeout(t) => self.vals[i].timeouts.retain(|x| *x != t),
                Action::CancelAllTimeouts => self.vals[i].timeouts.clear(),
                Action::Decided(cert) => {
                    let mut block = self.built.get(&cert.value_id).expect("decided block is known").clone();
                    block.commit = Some(commit_proof(&cert).expect("proof"));
                    self.vals[i].engine.commit_block(block.clone()).expect("decided block commits");
                    if i == self.first_online() {
                        self.committed.push(block);
                    }
                }
                Action::Finalized(_) => self.vals[i].done = true,
            }
        }
    }

    fn first_online(&self) -> usize {
        self.vals.iter().position(|v| v.online).unwrap()
    }

    fn deliver(&mut self, j: usize, msg: Msg) {
        if !self.vals[j].online {
            return;
        }
        let actions = match msg {
            Msg::Vote(v) => self.vals[j].runner.vote(v),
            Msg::Proposal(p, block) => {
                // The block must be the one the proposal names, and valid.
                let valid = BlockId(block.hash().0) == p.message.value.0 && self.vals[j].engine.check_proposal(&block).is_ok();
                self.built.entry(BlockId(block.hash().0)).or_insert(*block);
                self.vals[j].runner.proposal(p, valid)
            }
        };
        self.act(j, actions);
    }

    fn run_height(&mut self, h: u64) {
        for i in 0..self.vals.len() {
            self.vals[i].done = false;
            self.vals[i].timeouts.clear();
            if self.vals[i].online {
                let vs = self.vals[i].engine.bft_validator_set().unwrap();
                let a = self.vals[i].runner.start_height(Height(h), vs);
                self.act(i, a);
            }
        }
        for _ in 0..30 {
            while let Some((j, m)) = self.queue.pop_front() {
                self.deliver(j, m);
            }
            if self.vals.iter().filter(|v| v.online).all(|v| v.done) {
                return;
            }
            for i in 0..self.vals.len() {
                if !self.vals[i].online {
                    continue;
                }
                for t in std::mem::take(&mut self.vals[i].timeouts) {
                    let a = self.vals[i].runner.timeout(t);
                    self.act(i, a);
                }
            }
        }
        panic!("height {h} not finished");
    }
}

#[test]
fn four_validators_build_the_same_chain_and_an_outsider_can_check_it() {
    let (mut net, faucet, start) = setup(4);
    for (h, nonce) in (1..=3).zip(0u64..) {
        // Every validator hears about the transaction (gossip, in the node).
        let tx = transfer(&faucet, nonce);
        for v in &net.vals {
            v.engine.submit_tx(tx.clone()).unwrap();
        }
        net.run_height(h);
    }
    let tips: Vec<_> = net.vals.iter().map(|v| (v.engine.state.read().height, v.engine.state.read().block_hash.clone(), v.engine.state.read().state_root())).collect();
    assert!(tips.iter().all(|t| *t == tips[0]), "validators disagree: {tips:?}");
    assert_eq!(tips[0].0, 3);
    for v in &net.vals {
        assert!(v.engine.mempool.read().is_empty(), "included txs must leave every mempool");
        assert!(v.engine.state.read().account(&faucet.address()).nonce == 3);
    }

    // An outsider with no vote replays the chain from the blocks alone.
    let outsider = ConsensusEngine::new(start.clone(), HydraXKeypair::generate());
    for b in &net.committed {
        outsider.commit_block(b.clone()).expect("outsider accepts proven blocks");
    }
    assert_eq!(outsider.state.read().block_hash, tips[0].1);

    // A block without its proof, or with too few precommits, is refused.
    let fresh = || ConsensusEngine::new(start.clone(), HydraXKeypair::generate());
    let mut bare = net.committed[0].clone();
    bare.commit = None;
    assert!(fresh().commit_block(bare).is_err(), "no proof");
    let mut short = net.committed[0].clone();
    short.commit.as_mut().unwrap().precommits.truncate(2);
    assert!(fresh().commit_block(short).is_err(), "2 of 4 is not a majority");
    let mut dup = net.committed[0].clone();
    let p = dup.commit.as_mut().unwrap();
    let first = p.precommits[0].clone();
    p.precommits.truncate(2);
    p.precommits.push(first);
    assert!(fresh().commit_block(dup).is_err(), "one validator counted twice");
}

#[test]
fn the_chain_goes_on_with_one_validator_down() {
    let (mut net, faucet, _) = setup(4);
    net.vals[1].online = false;
    for (h, nonce) in (1..=4).zip(0u64..) {
        let tx = transfer(&faucet, nonce);
        for v in &net.vals {
            v.engine.submit_tx(tx.clone()).unwrap();
        }
        net.run_height(h);
    }
    let online: Vec<_> = net.vals.iter().filter(|v| v.online).map(|v| v.engine.state.read().block_hash.clone()).collect();
    assert!(online.iter().all(|h| *h == online[0]));
    assert_eq!(net.vals[0].engine.state.read().height, 4);
    // Validator 1 proposes in some round of these heights: at least one
    // block needed a later round.
    assert!(net.committed.iter().any(|b| b.commit.as_ref().unwrap().round > 0));
    let _ = Round::new(0);
}
