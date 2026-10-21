# qtrc-sentinel: HYDRA-X Sentinel

A recovery and rate-limiting layer for Quantar Network accounts.

HYDRA-X requires ML-DSA-87 AND SLH-DSA-SHA2-256s, which defends against one signature family falling. Sentinel targets a different failure: the owner's main key leaking. It also limits, but does not eliminate, the damage if both families fall at once.

## Mechanism

1. **Recovery commitment.** Each account stores `R = SHA3-256(DOM || chain_id || account || recovery_address || cold_dest || salt)`, every field length-prefixed. Bound to one chain and one account.
2. **Rate-limited outflows.** Transfers within `allowance_per_window` over a sliding window of `delay_blocks` settle immediately. Larger ones wait `delay_blocks`, visible on chain. Zero-amount transfers are rejected.
3. **Veto.** During the delay, a recovery opens `R`, proves control of the recovery key with a HYDRA-X signature over a message bound to chain, account and the current `R`, cancels every pending operation and moves the full balance to `cold_dest`. Recovery is terminal; later credits are forwarded to `cold_dest`.
4. **Delayed guardian rotation.** A thief with the main key cannot replace `R` silently. At most one rotation is pending; a new one replaces the old. Rotation invalidates every recovery signature made for the previous `R`.
5. **Invariants enforced in code.** `reserved == sum of pending transfers <= balance`, bounded queues (`MAX_PENDING`, `MAX_RECENT`), validated `Policy` (`MIN_DELAY_BLOCKS..=MAX_DELAY_BLOCKS`), fees only from available balance, `Vault::validate` for state loaded from disk or network, and `overflow-checks = true` in release.

## Watchtower

`watchtower::tick` sums untrusted value in flight (pending transfers plus allowance outflows still in the window), so splitting a theft into parts below `recover_at` does not avoid the veto. Allowance outflows to untrusted destinations always alert; set `recover_at <= allowance_per_window` to veto on any of them. Unexpected rotations always trigger recovery.

Each tick checks that the kit still opens the current commitment. After a rotation the old kit is reported as `KitStale`, with the findings attached, instead of failing silently.

The watchtower holds no secret key, only a `RecoveryKit` (opening plus a pre-made recovery signature). A rogue or leaked kit cannot redirect funds, but it can force a recovery at any time, which ends the account. Treat the kit as sensitive.

## What is guaranteed, and what is not

Adversary: holds the main key, or forges both ML-DSA-87 and SLH-DSA.

| Goal | Result |
| --- | --- |
| Drain fast | In any span of `delay_blocks`, at most `allowance_per_window` leaves without delay; everything else waits in public |
| Redirect the recovery | Blocked. `cold_dest` is inside `R`: a SHA3-256 preimage (second preimage once the opening is known), generically about 2^256 classical and about 2^128 quantum. Holds even if every signature scheme is broken |
| Swap the guardian | Delayed and vetoable; old proofs die with the rotation |
| Replay a recovery | Message binds chain, account and the current commitment |
| Reach funds in `cold_dest` | **Not prevented.** `cold_dest` is an ordinary account under the same signature schemes. Use a never-used address. If both families fall, Sentinel buys time for a hard fork; it is not a substitute for one |
| Force a recovery (griefing) | Possible for anyone holding a kit, or the recovery key if its public key is exposed elsewhere |

Timing: an operation can finalize at exactly `unlock_height`, so the useful reaction window is `delay_blocks` minus inclusion latency. This applies to large transfers and rotations.

| Layer | Assumption |
| --- | --- |
| ML-DSA-87 | Module-LWE / Module-SIS |
| SLH-DSA-SHA2-256s | Hash function properties |
| Sentinel (recovery destination) | SHA3-256 preimage resistance + bounded reaction time |

## Status

Library only, not wired into consensus. Integration needs new transaction types (set guardian, rotate, recover, finalize), a `Vault` next to `AccountState`, `charge_fee` for every fee, credits routed through `credit`, and `validate` on every state load. That changes state layout, so it needs a testnet reset or an activation height. `finalize` is intentionally permissionless. There is no policy-change API; if one is added it must be time-locked too.

`cargo test -p qtrc-sentinel`: 50 tests, including regression tests for every confirmed audit finding, a randomized invariant test (60,000 operations), and end-to-end recovery with real HYDRA-X keys (wrong account and impostor key rejected).
