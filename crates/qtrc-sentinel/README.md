# qtrc-sentinel: HYDRA-X Sentinel

A recovery and rate-limiting layer for Quantar Network accounts.

HYDRA-X requires ML-DSA-87 AND SLH-DSA-SHA2-256s, which defends against one signature family falling. Sentinel targets a different failure: the owner's main key leaking. It also limits, but does not eliminate, the damage if both families fall at once.

## Mechanism

1. **Recovery commitment.** Each account stores `R = SHA3-256(DOM || chain_id || account || recovery_address || cold_dest || salt)`, every field length-prefixed. Bound to one chain and one account. `cold_dest` must differ from the account.
2. **Rate-limited outflows.** With a guardian set, transfers within `allowance_per_window` over a sliding window of `delay_blocks` settle immediately; larger ones wait `delay_blocks`, visible on chain. Without a guardian there is no limit. Zero-amount transfers are rejected.
3. **Veto.** During the delay, a recovery opens `R`, proves control of the recovery key with a HYDRA-X signature over a message bound to chain, account, current `R` and the rotation epoch, cancels every pending operation and moves the full balance to `cold_dest`. Recovery is terminal; later credits are forwarded to `cold_dest`. Consensus rejects a recovery into an already recovered vault (`ensure_recovery_target`), so forwarding can never loop, and `resolve_forward` follows a chain to its final holder (capped at `MAX_FORWARD_HOPS`).
4. **Delayed guardian rotation.** A thief with the main key cannot replace `R` silently. One rotation pending at a time, in its own slot so a transfer flood cannot block it. Repeating the pending request keeps its original deadline, so nobody can postpone it; a request for a different commitment restarts the delay and is vetoed by the watchtower unless announced. Each finalized rotation bumps the epoch, which invalidates every earlier recovery signature, even if a later rotation returns to an old `R`.
5. **Invariants enforced in code.** (`validate` checks internal consistency; the rotation epoch and other fields must also be covered by the consensus state root, since a single vault cannot tell a tampered epoch from a real one.) `reserved == sum of pending transfers <= balance`, bounded queues and history, validated `Policy`, fees only from the available balance, `Vault::validate` for loaded state (balances, queues, unlock heights, allowance window, clean recovered state), and `overflow-checks = true` in release.

## Watchtower

`watchtower::tick` sums untrusted value across pending transfers, allowance outflows in the window, and transfers finalized in the last `HISTORY_WINDOWS * delay_blocks` blocks. Splitting a theft into parallel parts or running it one transfer at a time still reaches `recover_at`. The residual rate an attacker can sustain without a veto is below `recover_at` per `HISTORY_WINDOWS * delay_blocks` blocks, and each such outflow raises an alert. Set `recover_at <= allowance_per_window` to veto on any untrusted outflow; the owner's own payments to untrusted addresses then count too, so add regular payees to `trusted`.

Also vetoed: `FLOOD_PENDING` or more pending transfers to any destination, trusted ones included (queue flooding), and any rotation the owner did not announce. An owner who queues that many payments at once triggers a recovery too; batch them. A vault without a guardian is reported as `NoGuardian`.

Each tick checks that the kit still opens the current commitment for the current epoch. After a rotation the old kit is reported as `KitStale`, with the findings attached, instead of failing silently.

The watchtower holds no secret key, only a `RecoveryKit` (opening plus a pre-made recovery signature). A rogue or leaked kit cannot redirect funds, but it can force a recovery at any time, which ends the account. Treat the kit as sensitive.

## What is guaranteed, and what is not

Adversary: holds the main key, or forges both ML-DSA-87 and SLH-DSA.

| Goal | Result |
| --- | --- |
| Drain fast | With a guardian, in any span of `delay_blocks` at most `allowance_per_window` leaves without delay; everything else waits in public |
| Drain slowly | Alerts on every untrusted outflow; vetoed once the remembered total reaches `recover_at` |
| Redirect the recovery | Blocked. `cold_dest` is inside `R`: a SHA3-256 preimage (second preimage once the opening is known), generically about 2^256 classical and about 2^128 quantum. Holds even if every signature scheme is broken |
| Swap the guardian | Delayed and vetoable; old proofs die with each rotation |
| Replay a recovery | Message binds chain, account, commitment and epoch |
| Block the recovery by exhausting fees | Prevented only if consensus has the submitter pay the recovery fee (see integration notes) |
| Reach funds in `cold_dest` | **Not prevented.** `cold_dest` is an ordinary account under the same signature schemes. Use a never-used address. If both families fall, Sentinel buys time for a hard fork; it is not a substitute for one |
| Force a recovery (griefing) | Possible for anyone holding a kit, or the recovery key if its public key is exposed elsewhere |

Timing: an operation can finalize at exactly `unlock_height`, so the useful reaction window is `delay_blocks` minus inclusion latency. This applies to large transfers and rotations.

| Layer | Assumption |
| --- | --- |
| ML-DSA-87 | Module-LWE / Module-SIS |
| SLH-DSA-SHA2-256s | Hash function properties |
| Sentinel (recovery destination) | SHA3-256 preimage resistance + bounded reaction time |

## Status

Library only, not wired into consensus. Integration requirements are in the crate docs (`src/lib.rs`, "Integration notes"): new transaction types, recovery fee paid by the submitter, `ensure_recovery_target` before recovery, `resolve_forward` for credits, `validate` on every state load, vault state under the state root. It changes state layout, so it needs a testnet reset or an activation height. `finalize` is intentionally permissionless.

`overflow-checks = true` applies to the whole workspace: arithmetic overflow anywhere now stops the node instead of wrapping.

`cargo test -p qtrc-sentinel`: 67 tests, including regression tests for every confirmed finding of three audit rounds, two randomized invariant tests (one with recoveries and post-recovery credits), and end-to-end recovery with real HYDRA-X keys.
