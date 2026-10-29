# Audit kit

Build steps, test commands and the exact byte encodings of every message a
HYDRA-X signature covers, with test vectors in [`vectors.json`](vectors.json).

## Build

`qtrc-consensus` depends on `hx-mempool` by relative path, so both
repositories must sit side by side:

```bash
mkdir quantar && cd quantar
git clone https://github.com/quantarsite/quantar-testnet
git clone https://github.com/quantarsite/hx-mempool
git -C hx-mempool checkout 322e088e1d59518f76fbe50da8e45ccc1ffd2d4e
cd quantar-testnet
cargo build --release --workspace
```

Layout after cloning:

```
quantar/
├── hx-mempool/
└── quantar-testnet/
```

Toolchain: tested with stable Rust 1.97.0 on Linux x86_64. No
`rust-toolchain` file is pinned. Dependencies resolve from crates.io; the
ML-DSA implementation (`pqcrypto-mldsa`) builds PQClean C code, so a C
compiler is needed.

## Tests

```bash
# everything (release is much faster: SLH-DSA-256s signing is slow in debug)
cargo test --release --workspace

# just the audit vectors
cargo test --release -p qtrc-consensus --test audit_vectors
```

The vector test fails if any encoding below changes by a single byte, if a
stored signature stops verifying, or if a negative case is accepted.

## Signature scheme (qtrc-crypto)

`HydraXKeypair::sign(m)` produces, over the same message bytes `m`:

| Component | Scheme | Crate | Mode | Size |
| --- | --- | --- | --- | --- |
| `ml_dsa_sig` | ML-DSA-87 (FIPS 204) | `pqcrypto-mldsa` 0.1 (PQClean) | detached, PQClean default (hedged) | 4627 B |
| `slh_dsa_sig` | SLH-DSA-SHA2-256s (FIPS 205) | `fips205` 0.4 | pure (no pre-hash), empty context, deterministic | 29792 B |

`HydraXSignature::verify(m)` accepts only if both components verify under
the verifying key carried in the signature. `Transaction::verify` also
requires `BLAKE3(ml_dsa_pk || slh_dsa_pk) == from`, so a valid signature
under any other key is rejected.

No caller pre-hashes `m` outside the schemes: transactions, block headers
and BFT votes sign their full encodings, and since the v3 change Sentinel
recoveries do too (see below).

## Signed encodings

All integers are fixed width. `D` is the chain domain prefix:

```
D = "QTR-HYDRAX-V2" || u8(len(chain_id)) || chain_id        chain_id = "quantar-testnet-2"
```

| Message | Bytes signed | Vector |
| --- | --- | --- |
| Transaction | `D \|\| u64le(nonce) \|\| from[32] \|\| to[32] \|\| u128le(amount) \|\| u64le(fee_per_gas = 0) \|\| u64le(gas_limit = 21000) \|\| u64le(len(data)) \|\| data` | `tx_payload_plain`, `tx_payload_with_data` |
| Block header | `D \|\| "BLK" \|\| serde_json::to_vec(header)` | `block_header_signing_bytes`, `..._pre_activation` |
| BFT vote | `D \|\| "BFTVOTE1" \|\| u8(type: 1 prevote, 2 precommit) \|\| u64be(height) \|\| i64be(round) \|\| (0 \| 1 \|\| block_id[32]) \|\| validator[32]` | `bft_prevote_nil`, `bft_precommit_value` |
| BFT proposal | `D \|\| "BFTPROP1" \|\| u64be(height) \|\| i64be(round) \|\| block_id[32] \|\| i64be(pol_round) \|\| proposer[32]` | `bft_proposal` |
| Sentinel recovery (v3) | `lp("QTR/SENTINEL/RECOVER/v3") \|\| lp(chain_id) \|\| lp(account) \|\| lp(commitment) \|\| u64le(epoch)` | `sentinel_recovery_message_v3` |

`lp(x) = u64le(len(x)) || x`. The transaction ID is `BLAKE3` of exactly the
transaction bytes signed; `timestamp` and the signature are not covered, so
relays cannot change an ID. Transaction ID and the hx-mempool
`RawTransaction::signing_bytes()` are byte-identical by design.

Block header JSON: fields serialize in struct order (`height`, `prev_hash`,
`merkle_root`, `timestamp`, `proposer`, then `state_root` and
`witness_root`, each omitted before its activation height). Hashes and
addresses are lowercase hex strings. The canonicality of this encoding rests
on `serde_json`'s struct-order output; the two header vectors pin it.

## Sentinel recovery and the v3 activation

The recovery commitment `R = SHA3-256(lp("QTR/SENTINEL/COMMIT/v2") || lp(chain_id) || lp(account) || lp(recovery_address) || lp(cold_dest) || lp(salt))`
is a hash commitment, not a signed message (vector `sentinel_commitment`).

Before `recovery_v3_from_height` the recovery key signed the 32-byte
`SHA3-256` of the recovery fields under domain `QTR/SENTINEL/RECOVER/v2`
(vector `sentinel_recovery_message_legacy`). That was an external short
pre-hash, which caps collision resistance near 128 bits. From the
activation height on, only the full v3 message verifies; the legacy digest
is kept solely so blocks from before the activation replay. New chains
activate v3 at block 1. On quantar-testnet-2 the height is
`RECOVERY_V3_TESTNET2` in `crates/qtrc-common/src/chain.rs`, set to a real
height above the live tip in the release that enables it.

## AND-composition vectors

`and_composition` in `vectors.json` holds two test keypairs (serialized key
files, public on purpose: never fund them), one message, a signature from
each key, and the cases the test runs:

| Case | Expected |
| --- | --- |
| both components from key A | accept |
| ML-DSA component from key B | reject, ML-DSA |
| SLH-DSA component from key B | reject, SLH-DSA |
| ML-DSA one bit flipped | reject, ML-DSA |
| SLH-DSA one bit flipped | reject, SLH-DSA |
| SLH-DSA truncated by one byte | reject, SLH-DSA |
| message changed | reject |
| valid signature, but `from` is key B's address | transaction rejected |

The ML-DSA component is randomized, so a re-run produces a different but
equally valid signature; the test checks that the stored one verifies. The
SLH-DSA component is deterministic and the test checks that re-signing
reproduces it exactly.

To regenerate after an intended consensus change:

```bash
AUDIT_VECTORS_WRITE=1 cargo test --release -p qtrc-consensus --test audit_vectors -- --nocapture
```

Contact: contact@quantarnetwork.com
