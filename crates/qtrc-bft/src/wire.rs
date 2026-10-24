//! What validators send each other, as bytes (bincode). Nothing here is
//! trusted: every vote and proposal carries its HYDRA-X signature and is
//! verified by the consensus before it counts, and every block is checked
//! by the node before anyone votes for it.

use crate::*;
use serde::{Deserialize, Serialize};

/// Largest message accepted: a proposal carries its block, up to 500
/// transactions of about 38 KB each.
pub const MAX_MESSAGE: usize = 24 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireVote {
    /// 1 prevote, 2 precommit
    pub typ:       u8,
    pub height:    u64,
    pub round:     u32,
    pub value:     Option<[u8; 32]>,
    pub validator: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireProposal {
    pub height:    u64,
    pub round:     u32,
    pub block_id:  [u8; 32],
    /// -1 when there is no proof-of-lock round
    pub pol_round: i64,
    pub proposer:  [u8; 32],
    pub signature: Vec<u8>,
    /// The block the proposal names (its header hash is `block_id`), in the
    /// node's storage encoding: `Block` itself skips absent fields when
    /// serialized, which bincode cannot read back.
    pub block:     Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMsg {
    Vote(WireVote),
    Proposal(Box<WireProposal>),
}

impl WireMsg {
    pub fn height(&self) -> u64 {
        match self {
            WireMsg::Vote(v) => v.height,
            WireMsg::Proposal(p) => p.height,
        }
    }

    /// Who claims to have signed it.
    pub fn sender(&self) -> ValAddr {
        match self {
            WireMsg::Vote(v) => ValAddr(v.validator),
            WireMsg::Proposal(p) => ValAddr(p.proposer),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("wire message encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        use bincode::Options;
        if bytes.len() > MAX_MESSAGE {
            return Err("message too large".into());
        }
        // Same encoding as `bincode::serialize`, but a length field cannot
        // make the decoder allocate more than the message itself.
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE as u64)
            .deserialize(bytes)
            .map_err(|e| e.to_string())
    }
}

fn round(r: Round) -> u32 {
    r.as_i64().max(0) as u32
}

impl From<&SignedMessage<Ctx, Vote>> for WireMsg {
    fn from(v: &SignedMessage<Ctx, Vote>) -> Self {
        let m = &v.message;
        WireMsg::Vote(WireVote {
            typ: match m.typ {
                VoteType::Prevote => 1,
                VoteType::Precommit => 2,
            },
            height: m.height.0,
            round: round(m.round),
            value: match m.value {
                NilOrVal::Nil => None,
                NilOrVal::Val(id) => Some(id.0),
            },
            validator: m.validator.0,
            signature: v.signature.0.clone(),
        })
    }
}

pub fn proposal_msg(p: &SignedMessage<Ctx, Proposal>, block: Vec<u8>) -> WireMsg {
    let m = &p.message;
    WireMsg::Proposal(Box::new(WireProposal {
        height: m.height.0,
        round: round(m.round),
        block_id: (m.value.0).0,
        pol_round: m.pol_round.as_i64(),
        proposer: m.proposer.0,
        signature: p.signature.0.clone(),
        block,
    }))
}

impl WireVote {
    pub fn into_signed(self) -> Result<SignedMessage<Ctx, Vote>, String> {
        let typ = match self.typ {
            1 => VoteType::Prevote,
            2 => VoteType::Precommit,
            t => return Err(format!("unknown vote type {t}")),
        };
        let vote = Vote {
            typ,
            height: Height(self.height),
            round: Round::new(self.round),
            value: self.value.map_or(NilOrVal::Nil, |v| NilOrVal::Val(BlockId(v))),
            validator: ValAddr(self.validator),
            extension: None,
        };
        Ok(SignedMessage::new(vote, Signature(self.signature)))
    }
}

impl WireProposal {
    pub fn into_signed(self) -> Result<(SignedMessage<Ctx, Proposal>, Vec<u8>), String> {
        let pol_round = match self.pol_round {
            -1 => Round::Nil,
            r if (0..=u32::MAX as i64).contains(&r) => Round::new(r as u32),
            r => return Err(format!("bad pol round {r}")),
        };
        let p = Proposal {
            height: Height(self.height),
            round: Round::new(self.round),
            value: Value(BlockId(self.block_id)),
            pol_round,
            proposer: ValAddr(self.proposer),
        };
        Ok((SignedMessage::new(p, Signature(self.signature)), self.block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vote_survives_the_wire_and_still_verifies() {
        let k = HydraXKeypair::generate();
        let v = Vote {
            typ: VoteType::Precommit,
            height: Height(3),
            round: Round::new(2),
            value: NilOrVal::Val(BlockId([4; 32])),
            validator: ValAddr::from(&k.address()),
            extension: None,
        };
        let signed = sign_vote(&k, v);
        let bytes = WireMsg::from(&signed).encode();
        let WireMsg::Vote(w) = WireMsg::decode(&bytes).unwrap() else { panic!() };
        let back = w.into_signed().unwrap();
        assert_eq!(back.message, signed.message);
        let msg = consensus::ConsensusMsg::Vote(back.message.clone());
        assert!(verify_consensus_msg(&msg, &back.signature, &back.message.validator));
    }

    #[test]
    fn garbage_and_huge_length_prefixes_are_refused_without_allocating() {
        assert!(WireMsg::decode(&[0xff; 40]).is_err());
        // A vote whose signature claims to be 2^60 bytes long.
        let mut b = vec![0u8, 0, 0, 0];
        b.extend([1u8]);
        b.extend(3u64.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.push(0);
        b.extend([7u8; 32]);
        b.extend((1u64 << 60).to_le_bytes());
        assert!(WireMsg::decode(&b).is_err());
    }
}
