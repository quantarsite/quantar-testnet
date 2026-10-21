//! Watchtower: watches Sentinel vaults and vetoes hostile activity before
//! a time lock expires.
//!
//! ## Trust model
//!
//! The owner gives the watchtower a [`RecoveryKit`]: the commitment opening
//! (`cold_dest`, `salt`) and a recovery signature made in advance over the
//! current commitment. The watchtower never holds a secret key.
//!
//! A malicious or leaked kit cannot redirect funds: the destination is
//! fixed inside the on-chain commitment. It can, however, force a
//! recovery at any moment, which is terminal for the account (later
//! credits are forwarded to `cold_dest`). Treat the kit as sensitive.
//!
//! A kit stops working when the guardian is rotated. Every tick checks it
//! and reports [`Action::KitStale`] so the owner can issue a new one.
//!
//! ## Detection
//!
//! Untrusted value is summed across all pending transfers and all
//! allowance outflows still inside the window, so splitting a theft into
//! parts below `recover_at` does not avoid the veto. Allowance outflows to
//! untrusted destinations always produce at least an alert. Set
//! `recover_at <= allowance_per_window` to veto on any untrusted outflow.
//!
//! Operations become final at exactly `unlock_height`, so the useful
//! reaction window is `delay_blocks` minus inclusion latency. Findings are
//! sorted by severity, then by fewest blocks left.

use crate::{Hash, PendingKind, RecoveryProof, Vault};
use qtrc_crypto::Address;
use std::cmp::Reverse;

/// What the owner considers normal.
#[derive(Clone, Debug, Default)]
pub struct WatchPolicy {
    /// Destinations that never count as hostile (own wallets, exchange).
    /// Never put an address here that someone else could control.
    pub trusted: Vec<Address>,
    /// Once untrusted value in flight reaches this amount, recover.
    pub recover_at: u64,
    /// Rotation the owner announced off-chain. Any other rotation is
    /// hostile. Hand the watchtower a new kit for it before it finalizes.
    pub expected_rotation: Option<Hash>,
}

/// Material that lets a watchtower veto without any secret key.
#[derive(Clone, Debug)]
pub struct RecoveryKit<P: RecoveryProof> {
    pub cold_dest: Address,
    pub salt: [u8; 32],
    /// Recovery signature over `recovery_message(chain, account, commitment)`.
    pub proof: P,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Known destination or expected rotation.
    Info,
    /// Notify the owner.
    Alert,
    /// Hostile: veto now.
    Recover,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A queued operation, by id.
    Pending(u64),
    /// An allowance outflow that already settled at this height.
    Settled { height: u64, to: Address, amount: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub subject: Subject,
    pub severity: Severity,
    /// Blocks left before a pending operation can settle (0 for settled).
    pub blocks_left: u64,
    pub reason: &'static str,
}

/// Total untrusted value in flight: pending transfers plus allowance
/// outflows still inside the window.
#[must_use]
pub fn untrusted_total(vault: &Vault, policy: &WatchPolicy, height: u64) -> u64 {
    let pending = vault.pending().iter().filter_map(|p| match &p.kind {
        PendingKind::Transfer { to, amount } if !policy.trusted.contains(to) => Some(*amount),
        _ => None,
    });
    let settled = vault
        .recent_outflows(height)
        .filter(|o| !policy.trusted.contains(&o.to))
        .map(|o| o.amount);
    pending.chain(settled).fold(0, u64::saturating_add)
}

/// Classify vault activity, most urgent first.
#[must_use]
pub fn inspect(vault: &Vault, policy: &WatchPolicy, height: u64) -> Vec<Finding> {
    let escalate = untrusted_total(vault, policy, height) >= policy.recover_at;
    let untrusted = if escalate { Severity::Recover } else { Severity::Alert };

    let mut out: Vec<Finding> = vault
        .pending()
        .iter()
        .map(|p| {
            let (severity, reason) = match &p.kind {
                PendingKind::Transfer { to, .. } if policy.trusted.contains(to) => {
                    (Severity::Info, "transfer to trusted destination")
                }
                PendingKind::Transfer { .. } => (untrusted, "transfer to unknown destination"),
                PendingKind::RotateCommitment { new_commitment }
                    if policy.expected_rotation.as_ref() == Some(new_commitment) =>
                {
                    (Severity::Info, "expected guardian rotation")
                }
                PendingKind::RotateCommitment { .. } => (Severity::Recover, "unexpected guardian rotation"),
            };
            Finding { subject: Subject::Pending(p.id), severity, blocks_left: p.unlock_height.saturating_sub(height), reason }
        })
        .collect();

    out.extend(vault.recent_outflows(height).filter(|o| !policy.trusted.contains(&o.to)).map(|o| Finding {
        subject: Subject::Settled { height: o.height, to: o.to.clone(), amount: o.amount },
        severity: untrusted,
        blocks_left: 0,
        reason: "allowance outflow to unknown destination",
    }));

    out.sort_by_key(|f| (Reverse(f.severity), f.blocks_left));
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing to report.
    Idle,
    /// Suspicious activity, below the veto threshold.
    Notify(Vec<Finding>),
    /// The kit no longer opens the vault's commitment or its signature is
    /// invalid. The watchtower is disarmed until the owner sends a new
    /// kit. Carries every finding, hostile ones first.
    KitStale(Vec<Finding>),
    /// Recovery executed: everything went to `cold_dest`.
    Recovered { to: Address, amount: u64, cause: Finding },
}

/// One watchtower tick: inspect, check the kit, and recover if anything
/// is hostile. Never fails silently: a broken kit is reported, with the
/// findings it would have acted on.
pub fn tick<P: RecoveryProof>(
    vault: &mut Vault,
    policy: &WatchPolicy,
    kit: &RecoveryKit<P>,
    chain_id: &[u8],
    height: u64,
) -> Action {
    if vault.is_recovered() {
        return Action::Idle;
    }
    let findings = inspect(vault, policy, height);
    if vault.check_recovery(chain_id, &kit.cold_dest, &kit.salt, &kit.proof).is_err() {
        return Action::KitStale(findings);
    }
    if let Some(cause) = findings.iter().find(|f| f.severity == Severity::Recover).cloned() {
        return match vault.recover(chain_id, &kit.cold_dest, &kit.salt, &kit.proof) {
            Ok((to, amount)) => Action::Recovered { to, amount, cause },
            // Unreachable after a successful check, but never swallow findings.
            Err(_) => Action::KitStale(findings),
        };
    }
    let alerts: Vec<Finding> = findings.into_iter().filter(|f| f.severity == Severity::Alert).collect();
    if alerts.is_empty() { Action::Idle } else { Action::Notify(alerts) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use crate::{recovery_commitment, Policy};

    fn exchange() -> Address {
        Address([2u8; 32])
    }

    fn wpol() -> WatchPolicy {
        WatchPolicy { trusted: vec![exchange()], recover_at: 200, expected_rotation: None }
    }

    fn kit() -> RecoveryKit<MockProof> {
        RecoveryKit { cold_dest: cold(), salt: SALT, proof: rec_proof() }
    }

    #[test]
    fn quiet_vault_is_idle() {
        let mut v = vault();
        assert_eq!(tick(&mut v, &wpol(), &kit(), CHAIN, 10), Action::Idle);
    }

    #[test]
    fn trusted_large_transfer_is_left_alone() {
        let mut v = vault();
        v.transfer(10, exchange(), 900).unwrap();
        assert_eq!(tick(&mut v, &wpol(), &kit(), CHAIN, 20), Action::Idle);
        assert_eq!(v.pending().len(), 1);
    }

    #[test]
    fn small_unknown_transfer_only_alerts() {
        let mut v = vault();
        v.transfer(11, thief(), 100).unwrap(); // queued, total 100 < 200
        let Action::Notify(f) = tick(&mut v, &wpol(), &kit(), CHAIN, 20) else { panic!() };
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].severity, f[0].blocks_left), (Severity::Alert, 91));
        assert!(!v.is_recovered());
    }

    #[test]
    fn large_unknown_transfer_is_vetoed() {
        let mut v = vault();
        v.transfer(10, thief(), 900).unwrap();
        let Action::Recovered { to, amount, cause } = tick(&mut v, &wpol(), &kit(), CHAIN, 50) else { panic!() };
        assert_eq!((to, amount), (cold(), 1_000));
        assert_eq!(cause.reason, "transfer to unknown destination");
    }

    /// Regression A1: splitting the theft below `recover_at` no longer works.
    #[test]
    fn split_theft_is_summed_and_vetoed() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap(); // allowance
        for _ in 0..4 {
            v.transfer(10, thief(), 199).unwrap();
        }
        let a = tick(&mut v, &wpol(), &kit(), CHAIN, 11);
        assert!(matches!(a, Action::Recovered { amount: 950, .. }), "{a:?}");
    }

    #[test]
    fn many_small_parts_still_escalate() {
        let mut v = vault();
        v.transfer(10, thief(), 120).unwrap();
        assert!(matches!(tick(&mut v, &wpol(), &kit(), CHAIN, 11), Action::Notify(_)));
        v.transfer(12, thief(), 80).unwrap(); // total 200
        assert!(matches!(tick(&mut v, &wpol(), &kit(), CHAIN, 13), Action::Recovered { .. }));
    }

    /// Regression A2: after a rotation the old kit is reported as stale,
    /// with the hostile finding attached, instead of an error.
    #[test]
    fn stale_kit_is_reported_not_swallowed() {
        let mut v = vault();
        let new_c = commit(&[3u8; 32]);
        let (id, unlock) = queued(v.request_rotation(10, new_c).unwrap());
        let p = WatchPolicy { expected_rotation: Some(new_c), ..wpol() };
        assert_eq!(tick(&mut v, &p, &kit(), CHAIN, 11), Action::Idle);
        v.finalize(unlock, id).unwrap();

        v.transfer(200, thief(), 900).unwrap();
        let Action::KitStale(f) = tick(&mut v, &p, &kit(), CHAIN, 201) else { panic!() };
        assert_eq!(f[0].severity, Severity::Recover);

        // With a fresh kit for the new guardian, the veto works again.
        let fresh = RecoveryKit { cold_dest: cold(), salt: [3u8; 32], proof: proof_for(&new_c) };
        assert!(matches!(tick(&mut v, &p, &fresh, CHAIN, 202), Action::Recovered { .. }));
    }

    #[test]
    fn stale_kit_reported_even_when_quiet() {
        let mut v = vault();
        let bad = RecoveryKit { cold_dest: cold(), salt: [0u8; 32], proof: rec_proof() };
        assert_eq!(tick(&mut v, &wpol(), &bad, CHAIN, 10), Action::KitStale(vec![]));
    }

    /// Regression M2: allowance drains are visible.
    #[test]
    fn allowance_drain_alerts() {
        let mut v = vault();
        for w in 0..5u64 {
            let h = 10 + w * 100;
            v.transfer(h, thief(), 50).unwrap();
            let Action::Notify(f) = tick(&mut v, &wpol(), &kit(), CHAIN, h) else { panic!() };
            assert!(matches!(f[0].subject, Subject::Settled { amount: 50, .. }));
        }
    }

    #[test]
    fn strict_policy_vetoes_any_untrusted_allowance_outflow() {
        let mut v = vault();
        v.transfer(10, thief(), 10).unwrap();
        let strict = WatchPolicy { recover_at: 1, ..wpol() };
        assert!(matches!(tick(&mut v, &strict, &kit(), CHAIN, 10), Action::Recovered { amount: 990, .. }));
    }

    #[test]
    fn hostile_rotation_is_vetoed() {
        let mut v = vault();
        v.request_rotation(10, recovery_commitment(CHAIN, &me(), &thief(), &thief(), &SALT)).unwrap();
        assert!(matches!(tick(&mut v, &wpol(), &kit(), CHAIN, 11), Action::Recovered { .. }));
    }

    #[test]
    fn findings_sorted_by_severity_then_urgency() {
        let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), Policy::new(100, 0).unwrap());
        v.transfer(10, exchange(), 300).unwrap();
        v.transfer(30, thief(), 150).unwrap();
        v.transfer(20, thief(), 150).unwrap();
        let f = inspect(&v, &wpol(), 40);
        let got: Vec<_> = f.iter().map(|x| (x.severity, x.blocks_left)).collect();
        assert_eq!(got, vec![(Severity::Recover, 80), (Severity::Recover, 90), (Severity::Info, 70)]);
    }

    /// A malicious watchtower cannot redirect; firing early still pays the owner.
    #[test]
    fn rogue_watchtower_cannot_steal() {
        let mut v = vault();
        v.transfer(10, exchange(), 900).unwrap();
        let evil = RecoveryKit { cold_dest: thief(), salt: SALT, proof: rec_proof() };
        let paranoid = WatchPolicy { recover_at: 0, ..Default::default() };
        assert!(matches!(tick(&mut v, &paranoid, &evil, CHAIN, 11), Action::KitStale(_)));
        assert!(!v.is_recovered());
        let Action::Recovered { to, .. } = tick(&mut v, &paranoid, &kit(), CHAIN, 11) else { panic!() };
        assert_eq!(to, cold());
    }

    #[test]
    fn trusted_cold_dest_is_not_hostile() {
        let mut v = vault();
        v.transfer(10, cold(), 900).unwrap();
        let p = WatchPolicy { trusted: vec![cold()], ..wpol() };
        assert_eq!(tick(&mut v, &p, &kit(), CHAIN, 11), Action::Idle);
    }

    #[test]
    fn already_recovered_vault_is_idle() {
        let mut v = vault();
        v.recover(CHAIN, &cold(), &SALT, &rec_proof()).unwrap();
        assert_eq!(tick(&mut v, &wpol(), &kit(), CHAIN, 99), Action::Idle);
    }
}
