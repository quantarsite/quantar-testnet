# qtrc-sentinel: HYDRA-X Sentinel

A third security layer for Quantar Network that does not depend on any signature scheme being unbroken.

HYDRA-X requires ML-DSA-87 AND SLH-DSA-SHA2-256s, which defends against one family falling. It does not help when the owner's key leaks, or when both families fall together. Sentinel covers those two cases.

## Mechanism

1. **Hidden recovery commitment.** Each account stores `R = SHA3-256(DOM || recovery_address || cold_dest || salt)`, every field length-prefixed. The recovery public key stays off chain until used.
2. **Rate-limited outflows.** Transfers inside `allowance_per_window` settle immediately. Larger ones wait `delay_blocks`, visible on chain.
3. **Veto.** During the delay, a recovery opens `R`, proves control of the recovery key with a HYDRA-X signature over `(chain_id, account, nonce)`, cancels every pending operation and moves the full balance to `cold_dest`. Single use.
4. **Delayed guardian rotation.** A thief with the main key cannot replace `R` silently; the current guardian can veto.

## Watchtower

`watchtower::tick` classifies pending operations (trusted destination, unknown small, unknown large, expected or unexpected rotation) and fires recovery on anything hostile.

The watchtower holds no secret key, only a `RecoveryKit`: the commitment opening plus a recovery signature made in advance. A rogue watchtower can at worst trigger recovery early, and the funds still land in the owner's `cold_dest`. It can be annoying; it cannot steal.

## Security argument (sketch)

Adversary: holds the main key, or forges both ML-DSA-87 and SLH-DSA.

| Goal | Why it fails |
| --- | --- |
| Drain fast | Loss per window is capped at `allowance_per_window`; the rest waits in public |
| Redirect the recovery | `cold_dest` is inside `R`: needs a SHA3-256 second preimage (about 2^256 classical, 2^128 with Grover), independent of signatures |
| Attack the recovery key | Its public key is behind a hash until the owner acts |
| Swap the guardian | Rotation is delayed and vetoable |
| Replay a recovery | Message binds chain id, account and nonce |

Residual risk is liveness: someone, owner or watchtower, must react within `delay_blocks`. That latency applies only to large transfers.

| Layer | Assumption |
| --- | --- |
| ML-DSA-87 | Module-LWE / Module-SIS |
| SLH-DSA-SHA2-256s | Hash function properties |
| Sentinel | SHA3-256 second-preimage resistance + bounded reaction time |

## Status

Library only. Not wired into consensus yet: enabling it on chain needs new transaction types (`SetGuardian`, `Recover`, `Finalize`) and a `Vault` next to `AccountState` in `ChainState`, which changes state layout and therefore needs a testnet reset or an activation height.

`cargo test -p qtrc-sentinel`: 26 tests, including an end-to-end recovery signed with real HYDRA-X keys.
