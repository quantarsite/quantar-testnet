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
//! A kit stops working when the guardian is rotated (the recovery message
//! includes the rotation epoch, so returning to an old commitment does not
//! revive old kits). Every tick checks it and reports [`Action::KitStale`]
//! so the owner can issue a new one.
//!
//! ## Detection
//!
//! Untrusted value is summed across pending transfers, allowance outflows
//! still inside the window, and transfers finalized in the last
//! `HISTORY_WINDOWS * delay_blocks` blocks. Splitting a theft into parallel
//! parts, or running it one transfer at a time, therefore still reaches
//! `recover_at`. The residual rate an attacker can sustain without a veto
//! is below `recover_at` per `HISTORY_WINDOWS * delay_blocks` blocks, and
//! every such outflow raises an alert. Set
//! `recover_at <= allowance_per_window` to veto on any untrusted outflow
//! (the owner's own payments to untrusted addresses then count too).
//!
//! [`FLOOD_PENDING`] or more pending transfers, to any destination, are
//! treated as hostile regardless of value: they exist to exhaust the
//! queue. An owner who legitimately queues that many payments at once
//! will trigger a recovery; batch them instead.
//!
//! Operations become final at exactly `unlock_height`, so the useful
//! reaction window is `delay_blocks` minus inclusion latency. Findings are
//! sorted by severity, then by fewest blocks left.

use crate::{Hash, PendingKind, RecoveryFormat, RecoveryProof, Vault, MAX_PENDING};
use qtrc_crypto::Address;
use std::cmp::Reverse;

/// Pending transfers (any destination) at or above this count trigger recovery.
pub const FLOOD_PENDING: usize = MAX_PENDING / 2;

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
    /// An outflow that already left the vault at this height, either under
    /// the allowance or by finalizing a time-locked transfer.
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

/// Untrusted value pending or recently gone: pending transfers, allowance
/// outflows inside the window, and recently finalized transfers.
#[must_use]
pub fn untrusted_total(vault: &Vault, policy: &WatchPolicy, height: u64) -> u64 {
    let pending = vault.pending().iter().filter_map(|p| match &p.kind {
        PendingKind::Transfer { to, amount } if !policy.trusted.contains(to) => Some(*amount),
        _ => None,
    });
    let settled = vault
        .recent_outflows(height)
        .chain(vault.finalized_outflows(height))
        .filter(|o| !policy.trusted.contains(&o.to))
        .map(|o| o.amount);
    pending.chain(settled).fold(0, u64::saturating_add)
}

fn pending_transfer_count(vault: &Vault) -> usize {
    vault.pending().iter().filter(|p| matches!(p.kind, PendingKind::Transfer { .. })).count()
}

/// Classify vault activity, most urgent first.
#[must_use]
pub fn inspect(vault: &Vault, policy: &WatchPolicy, height: u64) -> Vec<Finding> {
    let flood = pending_transfer_count(vault) >= FLOOD_PENDING;
    let escalate = flood || untrusted_total(vault, policy, height) >= policy.recover_at;
    let untrusted = if escalate { Severity::Recover } else { Severity::Alert };
    let trusted_sev = if flood { Severity::Recover } else { Severity::Info };

    let mut out: Vec<Finding> = vault
        .pending()
        .iter()
        .map(|p| {
            let (severity, reason) = match &p.kind {
                PendingKind::Transfer { to, .. } if policy.trusted.contains(to) => {
                    (trusted_sev, if flood { "queue flood" } else { "transfer to trusted destination" })
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

    let settled = |reason: &'static str| {
        move |o: &crate::Outflow| Finding {
            subject: Subject::Settled { height: o.height, to: o.to.clone(), amount: o.amount },
            severity: untrusted,
            blocks_left: 0,
            reason,
        }
    };
    out.extend(
        vault
            .recent_outflows(height)
            .filter(|o| !policy.trusted.contains(&o.to))
            .map(settled("allowance outflow to unknown destination")),
    );
    out.extend(
        vault
            .finalized_outflows(height)
            .filter(|o| !policy.trusted.contains(&o.to))
            .map(settled("finalized transfer to unknown destination")),
    );

    // Severity first; on a tie, pending operations (still preventable)
    // before settled ones, then the most urgent first.
    out.sort_by_key(|f| (Reverse(f.severity), matches!(f.subject, Subject::Settled { .. }), f.blocks_left));
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing to report.
    Idle,
    /// The vault has no guardian: nothing can be vetoed.
    NoGuardian,
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
    tick_with(RecoveryFormat::Full, vault, policy, kit, chain_id, height)
}

/// [`tick`] checking the kit against the recovery message encoding the
/// chain verifies in its next block.
pub fn tick_with<P: RecoveryProof>(
    format: RecoveryFormat,
    vault: &mut Vault,
    policy: &WatchPolicy,
    kit: &RecoveryKit<P>,
    chain_id: &[u8],
    height: u64,
) -> Action {
    if vault.is_recovered() {
        return Action::Idle;
    }
    if vault.commitment().is_none() {
        return Action::NoGuardian;
    }
    let findings = inspect(vault, policy, height);
    if vault.check_recovery_with(format, chain_id, &kit.cold_dest, &kit.salt, &kit.proof).is_err() {
        return Action::KitStale(findings);
    }
    if let Some(cause) = findings.iter().find(|f| f.severity == Severity::Recover).cloned() {
        return match vault.recover_with(format, chain_id, &kit.cold_dest, &kit.salt, &kit.proof) {
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
        let fresh = RecoveryKit { cold_dest: cold(), salt: [3u8; 32], proof: proof_for(&new_c, 1) };
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

    /// Regression N1: a theft run one transfer at a time is vetoed.
    #[test]
    fn serial_theft_is_vetoed() {
        let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), policy());
        let (id, u) = queued(v.transfer(10, thief(), 199).unwrap());
        assert!(matches!(tick(&mut v, &wpol(), &kit(), CHAIN, 11), Action::Notify(_)));
        v.finalize(u, id).unwrap();
        v.transfer(u, thief(), 199).unwrap();
        let a = tick(&mut v, &wpol(), &kit(), CHAIN, u + 1);
        assert!(matches!(a, Action::Recovered { amount: 9_801, .. }), "{a:?}");
    }

    #[test]
    fn finalized_theft_alerts_even_below_threshold() {
        let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), policy());
        let (id, u) = queued(v.transfer(10, thief(), 150).unwrap());
        v.finalize(u, id).unwrap();
        let Action::Notify(f) = tick(&mut v, &wpol(), &kit(), CHAIN, u + 1) else { panic!() };
        assert_eq!(f[0].reason, "finalized transfer to unknown destination");
    }

    /// Regression N4: dust flooding the queue is hostile regardless of value.
    #[test]
    fn queue_flood_is_vetoed() {
        let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), Policy::new(100, 0).unwrap());
        let p = WatchPolicy { recover_at: 1_000_000, ..wpol() };
        for i in 0..(FLOOD_PENDING as u64 - 1) {
            v.transfer(10 + i, thief(), 1).unwrap();
        }
        assert!(matches!(tick(&mut v, &p, &kit(), CHAIN, 50), Action::Notify(_)));
        v.transfer(60, thief(), 1).unwrap();
        assert!(matches!(tick(&mut v, &p, &kit(), CHAIN, 61), Action::Recovered { .. }));
    }

    /// N5: a thief replacing the owner's rotation is itself an unexpected
    /// rotation, so the watchtower recovers.
    #[test]
    fn rotation_ping_pong_is_vetoed() {
        let mut v = vault();
        let mine = commit(&[3u8; 32]);
        let p = WatchPolicy { expected_rotation: Some(mine), ..wpol() };
        v.request_rotation(10, mine).unwrap();
        assert_eq!(tick(&mut v, &p, &kit(), CHAIN, 11), Action::Idle);
        v.request_rotation(12, recovery_commitment(CHAIN, &me(), &thief(), &thief(), &SALT)).unwrap();
        assert!(matches!(tick(&mut v, &p, &kit(), CHAIN, 13), Action::Recovered { .. }));
    }

    /// Regression N8.
    #[test]
    fn vault_without_guardian_is_reported() {
        let mut v = Vault::new(me(), 1_000, None, policy());
        assert_eq!(tick(&mut v, &wpol(), &kit(), CHAIN, 10), Action::NoGuardian);
    }

    /// Regression N9: the cause points at the pending transfer the
    /// recovery actually prevents, not at money already gone.
    #[test]
    fn cause_prefers_preventable_pending() {
        let mut v = vault();
        v.transfer(10, thief(), 50).unwrap(); // settled
        let (id, _) = queued(v.transfer(11, thief(), 300).unwrap());
        let Action::Recovered { cause, .. } = tick(&mut v, &wpol(), &kit(), CHAIN, 12) else { panic!() };
        assert_eq!(cause.subject, Subject::Pending(id));
    }

    /// Regression R1: dust flooding toward a trusted address is caught too.
    #[test]
    fn trusted_dust_flood_is_vetoed() {
        let mut v = Vault::new(me(), 10_000, Some(commit(&SALT)), Policy::new(100, 0).unwrap());
        for i in 0..(FLOOD_PENDING as u64 - 1) {
            v.transfer(10 + i, exchange(), 1).unwrap();
        }
        assert_eq!(tick(&mut v, &wpol(), &kit(), CHAIN, 50), Action::Idle);
        v.transfer(60, exchange(), 1).unwrap();
        let Action::Recovered { cause, .. } = tick(&mut v, &wpol(), &kit(), CHAIN, 61) else { panic!() };
        assert_eq!(cause.reason, "queue flood");
    }
}
