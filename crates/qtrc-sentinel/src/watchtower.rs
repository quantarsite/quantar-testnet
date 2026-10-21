//! Watchtower: watches Sentinel vaults and vetoes hostile operations
//! before their time lock expires.
//!
//! ## Trust model
//!
//! The owner gives the watchtower a [`RecoveryKit`]: the commitment opening
//! (`cold_dest`, `salt`) and a recovery signature made in advance over the
//! current recovery nonce. The watchtower never holds a secret key.
//!
//! Worst case, a malicious or buggy watchtower fires the recovery early.
//! Even then the funds can only go to the owner's own `cold_dest`, because
//! that address is fixed inside the on-chain commitment. A watchtower can
//! be annoying; it cannot steal.

use crate::{PendingKind, RecoveryProof, SentinelError, Vault};
use qtrc_crypto::Address;

/// What the owner considers normal.
#[derive(Clone, Debug, Default)]
pub struct WatchPolicy {
    /// Destinations that never trigger an alert (exchange, own wallets).
    pub trusted: Vec<Address>,
    /// Untrusted transfers at or above this amount trigger recovery.
    /// Below it, the watchtower only alerts.
    pub recover_at: u64,
    /// Rotation the owner announced off-chain and expects. Any other
    /// rotation is treated as hostile.
    pub expected_rotation: Option<crate::Hash>,
}

/// Material that lets a watchtower veto without any secret key.
#[derive(Clone, Debug)]
pub struct RecoveryKit<P: RecoveryProof> {
    pub cold_dest: Address,
    pub salt: [u8; 32],
    /// Recovery signature over `recovery_message(chain, account, nonce)`.
    pub proof: P,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Known destination or expected rotation.
    Info,
    /// Unknown destination, small amount: notify the owner.
    Alert,
    /// Hostile: veto now.
    Recover,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub pending_id: u64,
    pub severity: Severity,
    /// Blocks left before the operation can settle.
    pub blocks_left: u64,
    pub reason: &'static str,
}

/// Classify every pending operation of a vault, most urgent first.
pub fn inspect(vault: &Vault, policy: &WatchPolicy, height: u64) -> Vec<Finding> {
    let mut out: Vec<Finding> = vault
        .pending
        .iter()
        .map(|p| {
            let blocks_left = p.unlock_height.saturating_sub(height);
            let (severity, reason) = match &p.kind {
                PendingKind::Transfer { to, .. } if policy.trusted.contains(to) => {
                    (Severity::Info, "transfer to trusted destination")
                }
                PendingKind::Transfer { amount, .. } if *amount >= policy.recover_at => {
                    (Severity::Recover, "large transfer to unknown destination")
                }
                PendingKind::Transfer { .. } => (Severity::Alert, "transfer to unknown destination"),
                PendingKind::RotateCommitment { new_commitment }
                    if policy.expected_rotation.as_ref() == Some(new_commitment) =>
                {
                    (Severity::Info, "expected guardian rotation")
                }
                PendingKind::RotateCommitment { .. } => (Severity::Recover, "unexpected guardian rotation"),
            };
            Finding { pending_id: p.id, severity, blocks_left, reason }
        })
        .collect();
    out.sort_by_key(|f| (f.severity != Severity::Recover, f.blocks_left));
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing hostile.
    Idle,
    /// Something to tell the owner, no veto.
    Notify(Vec<Finding>),
    /// Recovery executed: everything went to `cold_dest`.
    Recovered { to: Address, amount: u64, cause: Finding },
}

/// One watchtower tick: inspect and, if anything is hostile, recover.
pub fn tick<P: RecoveryProof>(
    vault: &mut Vault,
    policy: &WatchPolicy,
    kit: &RecoveryKit<P>,
    chain_id: &[u8],
    height: u64,
) -> Result<Action, SentinelError> {
    if vault.recovered {
        return Ok(Action::Idle);
    }
    let findings = inspect(vault, policy, height);
    if let Some(hostile) = findings.iter().find(|f| f.severity == Severity::Recover) {
        let cause = hostile.clone();
        let (to, amount) = vault.recover(chain_id, &kit.cold_dest, &kit.salt, &kit.proof)?;
        return Ok(Action::Recovered { to, amount, cause });
    }
    let alerts: Vec<Finding> = findings.into_iter().filter(|f| f.severity == Severity::Alert).collect();
    Ok(if alerts.is_empty() { Action::Idle } else { Action::Notify(alerts) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::{recovery_commitment, Outcome};

    fn exchange() -> Address {
        Address([2u8; 32])
    }

    fn policy_wt() -> WatchPolicy {
        WatchPolicy { trusted: vec![exchange()], recover_at: 200, expected_rotation: None }
    }

    fn kit() -> RecoveryKit<MockProof> {
        RecoveryKit { cold_dest: cold(), salt: SALT, proof: rec_proof(0) }
    }

    #[test]
    fn quiet_vault_is_idle() {
        let mut v = vault();
        assert_eq!(tick(&mut v, &policy_wt(), &kit(), CHAIN, 10).unwrap(), Action::Idle);
    }

    #[test]
    fn trusted_large_transfer_is_left_alone() {
        let mut v = vault();
        v.transfer(10, exchange(), 900).unwrap();
        assert_eq!(tick(&mut v, &policy_wt(), &kit(), CHAIN, 20).unwrap(), Action::Idle);
        assert_eq!(v.pending.len(), 1);
    }

    #[test]
    fn small_unknown_transfer_only_alerts() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap(); // allowance, settles
        v.transfer(11, thief(), 100).unwrap(); // queued, below recover_at
        let Action::Notify(f) = tick(&mut v, &policy_wt(), &kit(), CHAIN, 20).unwrap() else { panic!() };
        assert_eq!(f[0].severity, Severity::Alert);
        assert_eq!(f[0].blocks_left, 91);
        assert!(!v.recovered);
    }

    #[test]
    fn large_unknown_transfer_is_vetoed() {
        let mut v = vault();
        v.transfer(10, thief(), 900).unwrap();
        let a = tick(&mut v, &policy_wt(), &kit(), CHAIN, 50).unwrap();
        let Action::Recovered { to, amount, cause } = a else { panic!() };
        assert_eq!((to, amount), (cold(), 1_000));
        assert_eq!(cause.reason, "large transfer to unknown destination");
    }

    #[test]
    fn hostile_rotation_is_vetoed() {
        let mut v = vault();
        v.request_rotation(10, recovery_commitment(&thief(), &thief(), &SALT)).unwrap();
        assert!(matches!(tick(&mut v, &policy_wt(), &kit(), CHAIN, 11).unwrap(), Action::Recovered { .. }));
    }

    #[test]
    fn expected_rotation_passes() {
        let mut v = vault();
        let new_c = recovery_commitment(&rec_key(), &cold(), &[3u8; 32]);
        let Outcome::Queued { id, unlock_height } = v.request_rotation(10, new_c).unwrap() else { panic!() };
        let p = WatchPolicy { expected_rotation: Some(new_c), ..policy_wt() };
        assert_eq!(tick(&mut v, &p, &kit(), CHAIN, 11).unwrap(), Action::Idle);
        v.finalize(unlock_height, id).unwrap();
        assert_eq!(v.commitment, Some(new_c));
    }

    #[test]
    fn hostile_findings_sorted_first() {
        let mut v = vault();
        v.transfer(10, exchange(), 300).unwrap();
        v.transfer(11, thief(), 100).unwrap();
        v.transfer(12, thief(), 400).unwrap();
        let f = inspect(&v, &policy_wt(), 20);
        assert_eq!(f[0].severity, Severity::Recover);
    }

    /// A malicious watchtower can only fire early; funds still reach the owner.
    #[test]
    fn rogue_watchtower_cannot_steal() {
        let mut v = vault();
        // Tries to redirect the recovery to itself.
        let evil = RecoveryKit { cold_dest: thief(), salt: SALT, proof: rec_proof(0) };
        let paranoid = WatchPolicy { recover_at: 0, ..Default::default() };
        v.transfer(10, exchange(), 900).unwrap();
        assert_eq!(tick(&mut v, &paranoid, &evil, CHAIN, 11), Err(SentinelError::CommitmentMismatch));
        // Fires early with the honest kit: money lands in cold storage.
        let Action::Recovered { to, .. } = tick(&mut v, &paranoid, &kit(), CHAIN, 11).unwrap() else { panic!() };
        assert_eq!(to, cold());
    }

    #[test]
    fn already_recovered_vault_is_idle() {
        let mut v = vault();
        v.recover(CHAIN, &cold(), &SALT, &rec_proof(0)).unwrap();
        assert_eq!(tick(&mut v, &policy_wt(), &kit(), CHAIN, 99).unwrap(), Action::Idle);
    }
}
