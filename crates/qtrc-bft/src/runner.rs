//! One validator's consensus: Malachite's state machine plus everything it
//! asks its host for that does not involve the network or the chain.
//!
//! The runner signs (through the double-sign guard), verifies signatures
//! and commit certificates, and turns the rest of Malachite's effects into
//! [`Action`]s for the node: messages to send, a block to build, timers,
//! and decisions. It holds no sockets and no clock, so the same code runs
//! in the node and in the in-memory tests.

use crate::*;
use malachitebft_core_consensus::{
    process, Effect, Error, Input, LocallyProposedValue, Params, ProposedValue, Resumable, Resume, SignedConsensusMsg, State,
};
use mc::{CommitCertificate, Timeout, Validity, ValueOrigin, ValuePayload};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What the node has to do after the runner handled an input.
#[derive(Debug)]
pub enum Action {
    /// Send this signed vote or proposal to the other validators.
    Publish(SignedConsensusMsg<Ctx>),
    /// We propose in this round: build a block and call
    /// [`Runner::propose`] with its hash (and send the block along).
    BuildBlock { height: Height, round: Round },
    /// Start a timer; when it fires, feed `Input::TimeoutElapsed`.
    ScheduleTimeout(Timeout, Duration),
    CancelTimeout(Timeout),
    CancelAllTimeouts,
    /// The validators decided this block. Commit it with this certificate
    /// as its proof.
    Decided(CommitCertificate<Ctx>),
    /// The height is over: call [`Runner::start_height`] for the next one.
    Finalized(Height),
}

/// Refuses to sign two different things for the same height, round and
/// step, even across restarts: the last signature is written to disk
/// before it is used. This is what keeps a crashed and restarted validator
/// from double voting, the one thing that would let it be blamed for a
/// fork. (Same rule as Tendermint's privval.)
pub struct SignGuard {
    path: Option<PathBuf>,
    last: Option<Signed>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Signed {
    height:    u64,
    round:     i64,
    /// 1 proposal, 2 prevote, 3 precommit
    step:      u8,
    bytes:     Vec<u8>,
    signature: Vec<u8>,
}

impl SignGuard {
    /// In-memory only (tests).
    pub fn ephemeral() -> Self {
        SignGuard { path: None, last: None }
    }

    /// Load the last signature from `path` (a new validator has none).
    pub fn open(path: &Path) -> Result<Self, String> {
        let last = match std::fs::read(path) {
            Ok(b) => Some(bincode::deserialize(&b).map_err(|e| format!("{}: {e}", path.display()))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(SignGuard { path: Some(path.to_path_buf()), last })
    }

    fn sign(&mut self, key: &HydraXKeypair, height: u64, round: i64, step: u8, bytes: Vec<u8>) -> Result<Signature, String> {
        if let Some(l) = &self.last {
            let (new, old) = ((height, round, step), (l.height, l.round, l.step));
            if new < old {
                return Err(format!("refusing to sign {new:?}: already signed at {old:?}"));
            }
            if new == old {
                // Signing the same thing again (e.g. after a restart) is fine
                // and gives the same signature; anything else is a double vote.
                return if l.bytes == bytes {
                    Ok(Signature(l.signature.clone()))
                } else {
                    Err(format!("refusing to sign something else at {new:?}"))
                };
            }
        }
        let signature = Signature::from_hydrax(&key.sign(&bytes));
        let rec = Signed { height, round, step, bytes, signature: signature.0.clone() };
        if let Some(path) = &self.path {
            write_durably(path, &bincode::serialize(&rec).map_err(|e| e.to_string())?)?;
        }
        self.last = Some(rec);
        Ok(signature)
    }
}

/// Write, fsync, rename, fsync the directory: after a crash the file holds
/// either the old record or the new one, never a torn mix.
fn write_durably(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

pub struct Runner {
    state:    State<Ctx>,
    metrics:  metrics::Metrics,
    key:      Arc<HydraXKeypair>,
    guard:    SignGuard,
    timeouts: mc::LinearTimeouts,
}

impl Runner {
    pub fn new(key: Arc<HydraXKeypair>, vs: ValidatorSet, height: Height, guard: SignGuard, timeouts: mc::LinearTimeouts) -> Self {
        let address = ValAddr::from(&key.address());
        // ProposalAndParts: proposals carry the block hash and the node
        // reports each block's validity. (ProposalOnly would accept any.)
        let params = Params { address, threshold_params: Default::default(), value_payload: ValuePayload::ProposalAndParts, enabled: true };
        Runner {
            state: State::new(Ctx, height, vs, params, 1000, 1000),
            metrics: metrics::Metrics::new(),
            key,
            guard,
            timeouts,
        }
    }

    /// Give back the sign guard, to build a new runner at another height
    /// (after catching up blocks this one did not vote on).
    pub fn into_guard(self) -> SignGuard {
        self.guard
    }

    pub fn address(&self) -> ValAddr {
        ValAddr::from(&self.key.address())
    }

    pub fn height(&self) -> Height {
        self.state.height()
    }

    pub fn start_height(&mut self, height: Height, vs: ValidatorSet) -> Vec<Action> {
        self.handle(Input::StartHeight(height, vs, false, None, Default::default()))
    }

    /// Our block for a round we propose in (after [`Action::BuildBlock`]).
    pub fn propose(&mut self, height: Height, round: Round, block: BlockId) -> Vec<Action> {
        self.handle(Input::Propose(LocallyProposedValue::new(height, round, Value(block))))
    }

    /// A proposal arrived and the node checked the block it names.
    pub fn proposal(&mut self, p: SignedMessage<Ctx, Proposal>, valid: bool) -> Vec<Action> {
        let value = ProposedValue {
            height: p.message.height,
            round: p.message.round,
            valid_round: p.message.pol_round,
            proposer: p.message.proposer,
            value: p.message.value.clone(),
            validity: if valid { Validity::Valid } else { Validity::Invalid },
        };
        let mut out = self.handle(Input::Proposal(p));
        out.extend(self.handle(Input::ProposedValue(value, ValueOrigin::Consensus)));
        out
    }

    pub fn vote(&mut self, v: SignedMessage<Ctx, Vote>) -> Vec<Action> {
        self.handle(Input::Vote(v))
    }

    pub fn timeout(&mut self, t: Timeout) -> Vec<Action> {
        self.handle(Input::TimeoutElapsed(t))
    }

    /// Feed any input. Errors inside the consensus (e.g. the sign guard
    /// refusing) are logged by Malachite and drop that input.
    pub fn handle(&mut self, input: Input<Ctx>) -> Vec<Action> {
        let mut out = Vec::new();
        let key = self.key.clone();
        let guard = &mut self.guard;
        let lt = self.timeouts;
        let vs = self.state.validator_set().clone();
        let r: Result<(), Error<Ctx>> = process!(
            input: input,
            state: &mut self.state,
            metrics: &self.metrics,
            with: effect => handle_effect(effect, &key, guard, &lt, &vs, &mut out)
        );
        let _ = r;
        out
    }
}

fn handle_effect(
    effect: Effect<Ctx>,
    key: &HydraXKeypair,
    guard: &mut SignGuard,
    lt: &mc::LinearTimeouts,
    vs: &ValidatorSet,
    out: &mut Vec<Action>,
) -> Result<Resume<Ctx>, String> {
    Ok(match effect {
        Effect::ScheduleTimeout(t, r) => {
            out.push(Action::ScheduleTimeout(t, lt.duration_for(t)));
            r.resume_with(())
        }
        Effect::CancelTimeout(t, r) => {
            out.push(Action::CancelTimeout(t));
            r.resume_with(())
        }
        Effect::CancelAllTimeouts(r) => {
            out.push(Action::CancelAllTimeouts);
            r.resume_with(())
        }
        Effect::PublishConsensusMsg(m, r) => {
            out.push(Action::Publish(m));
            r.resume_with(())
        }
        Effect::GetValue(height, round, _, r) => {
            out.push(Action::BuildBlock { height, round });
            r.resume_with(())
        }
        Effect::SignVote(v, r) => {
            let step = match v.typ {
                VoteType::Prevote => 2,
                VoteType::Precommit => 3,
            };
            let sig = guard.sign(key, v.height.0, v.round.as_i64(), step, v.sign_bytes())?;
            r.resume_with(SignedMessage::new(v, sig))
        }
        Effect::SignProposal(p, r) => {
            let sig = guard.sign(key, p.height.0, p.round.as_i64(), 1, p.sign_bytes())?;
            r.resume_with(SignedMessage::new(p, sig))
        }
        Effect::VerifySignature(m, signer, r) => r.resume_with(verify_consensus_msg(&m.message, &m.signature, &signer)),
        Effect::VerifyCommitCertificate(c, set, _, r) => match verify_commit(&c, &set) {
            Ok(()) => r.resume_with(Ok(())),
            Err(_) => {
                let bad = c.commit_signatures.first().cloned();
                match bad {
                    Some(s) => r.resume_with(Err(mc::CertificateError::InvalidCommitSignature(s))),
                    None => return Err("empty commit certificate".into()),
                }
            }
        },
        Effect::Decide(c, _, r) => {
            // Belt and braces: never hand the node a decision whose proof
            // would not verify on its own.
            verify_commit(&c, vs)?;
            out.push(Action::Decided(c));
            r.resume_with(())
        }
        Effect::Finalize(c, _, _, r) => {
            out.push(Action::Finalized(c.height));
            r.resume_with(())
        }
        // Malachite re-sends our last vote when a round stalls, so a lost
        // message does not stall it forever.
        Effect::RepublishVote(v, r) => {
            out.push(Action::Publish(SignedConsensusMsg::Vote(v)));
            r.resume_with(())
        }
        Effect::ExtendVote(_, _, _, _, r) => r.resume_with(None),
        Effect::VerifyVoteExtension(_, _, _, _, _, _, r) => r.resume_with(Ok(())),
        _ => Resume::Continue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guard_never_signs_two_things_at_one_step_even_after_a_restart() {
        let dir = std::env::temp_dir().join(format!("qtrc-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sign-state");
        let k = HydraXKeypair::generate();

        let mut g = SignGuard::open(&path).unwrap();
        let first = g.sign(&k, 5, 0, 2, b"prevote for A".to_vec()).unwrap();
        // Same height, round and step, other content: a double vote.
        assert!(g.sign(&k, 5, 0, 2, b"prevote for B".to_vec()).is_err());

        // Restart: the record comes back from disk.
        let mut g = SignGuard::open(&path).unwrap();
        assert!(g.sign(&k, 5, 0, 2, b"prevote for B".to_vec()).is_err());
        // The same vote again is allowed and is the same signature.
        assert_eq!(g.sign(&k, 5, 0, 2, b"prevote for A".to_vec()).unwrap(), first);
        // Going back is refused; going forward is fine.
        assert!(g.sign(&k, 4, 9, 3, b"older".to_vec()).is_err());
        assert!(g.sign(&k, 5, 0, 1, b"proposal, earlier step".to_vec()).is_err());
        assert!(g.sign(&k, 5, 0, 3, b"precommit for A".to_vec()).is_ok());
        assert!(g.sign(&k, 5, 1, 1, b"next round".to_vec()).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
