# qtrc-sentinel: HYDRA-X Sentinel

A recovery and rate-limiting layer for Quantar Network accounts.

HYDRA-X requires ML-DSA-87 AND SLH-DSA-SHA2-256s, which defends against one signature family falling. Sentinel targets a different failure: the owner's main key leaking. It also limits, but does not eliminate, the damage if both families fall at once.

## Mechanism

1. **Recovery commitment.** Each account stores `R = SHA3-256(DOM || chain_id || account || recovery_address || cold_dest || salt)`, every field length-prefixed. Bound to one chain and one account. `cold_dest` must differ from the account.
2. **Rate-limited outflows.** With a guardian set, transfers within `allowance_per_window` over a sliding window of `delay_blocks` settle immediately; larger ones wait `delay_blocks`, visible on chain. Without a guardian there is no limit. Zero-amount transfers are rejected.
3. **Veto.** During the delay, a recovery opens `R`, proves control of the recovery key with a HYDRA-X signature over a message bound to chain, account, current `R` and the rotation epoch, cancels every pending operation and moves the full balance to `cold_dest`. Recovery is terminal; later credits are forwarded to `cold_dest`. Consensus rejects a recovery into an already recovered vault (`ensure_recovery_target`), so forwarding can never loop, and `resolve_forward` follows a chain to its final holder (capped at `MAX_FORWARD_HOPS`).
4. **Delayed guardian rotation.** A thief with the main key cannot replace `R` silently. One rotation pending at a time, in its own slot so a transfer flood cannot block it. Repeating the pending request keeps its original deadline, so nobody can postpone it; a request for a different commitment restarts the delay and is vetoed by the watchtower unless announced. Each finalized rotation bumps the epoch, which invalidates every earlier recovery signature, even if a later rotation returns to an old `R`.
5. **Invariants enforced in code.** (`validate` checks internal consistency; the rotation epoch and other fields must also be covered by the consensus state root, since a single vault cannot tell a tampered epoch from a real one.) `reserved == sum of pending transfers <= balance`, bounded queues and history, validated `Policy`, fees only from the available balance, `Vault::validate` for loaded state (balances, queues, unlock heights, allowance window, clean recovered state), and `overflow-checks = true` in release.

### Recovery message encoding (v3)

The recovery key signs the full message `DOM || chain_id || account || R || epoch` (fields length-prefixed, epoch little-endian), not a digest of it. Earlier releases signed `SHA3-256` of the same fields, a 32-byte external pre-hash that caps collision resistance near 128 bits, below the category 5 that ML-DSA-87 and SLH-DSA-SHA2-256s are chosen for, and that FIPS 205 section 10.2 asks to avoid with short digests on the 256-bit sets. Both schemes now hash the message internally at their own level.

The switch is a consensus change with its own activation height (`recovery_v3_from_height`). Blocks before it are verified with the legacy digest so history replays unchanged; from it on only the full message is accepted. A kit signed before the activation stops opening the vault at that height: the watchtower reports it as `KitStale`, and the owner signs a new proof with `qtrc-wallet recover --recovery-key` or rotates the guardian. The encoding is pinned by the `recovery_message_vector` test.

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

Wired into consensus (`qtrc-common::state`, `qtrc-consensus`, `qtrc-node`, `qtrc-wallet`):

* Operations travel in the transaction's signed `data` field (`QSN1 || bincode(op)`), so plain transfers keep the exact signed bytes, IDs and signatures they had before, and hx-mempool verifies them unchanged.
* Activation height stored once per data directory, like the fee: block 1 on a new chain, the next block on an existing one. Earlier blocks replay unchanged.
* Blocks are stored as format `0x02`; format `0x01` blocks (pre-Sentinel) are still read, tested against a block written by the previous release.
* `apply_tx` is all-or-nothing (journal + rollback). Finalize and Recover are paid by the submitter. Recovery into a recovered vault is refused; credits follow forwarding to the final holder.
* RPC: `GET /vault/:address`; `/status` reports `sentinel_from_height`.
* Wallet: `guardian setup|rotate`, `vault`, `finalize`, `recover --kit [--recovery-key]`.

`finalize` is intentionally permissionless. There is no policy-change API; if one is added it must be time-locked too.

`cargo test -p qtrc-sentinel`: 67 tests, including regression tests for every confirmed finding of three audit rounds, two randomized invariant tests, and end-to-end recovery with real HYDRA-X keys. `cargo test -p qtrc-consensus --test sentinel`: the full flow through mempool and blocks.
