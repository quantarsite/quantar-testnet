# Quantar Network — Testnet

> **Post-quantum blockchain secured by HYDRA-X AND-composition from genesis.**

Every transaction on Quantar requires a valid **ML-DSA-87** (FIPS 204) signature
**AND** a valid **SLH-DSA** (FIPS 205) signature — enforced at the consensus
layer with no ECDSA fallback, no legacy path, no retrofitting.

---

## Architecture

```
quantar-testnet/
├── crates/
│   ├── qtrc-crypto      # HYDRA-X AND-composition (ML-DSA-87 + SLH-DSA)
│   ├── qtrc-common      # Block, Transaction, ChainState types
│   ├── qtrc-chain       # Chain storage and indexing
│   ├── qtrc-consensus   # PoA round-robin consensus engine
│   ├── qtrc-node        # Node binary + JSON-RPC
│   └── qtrc-faucet      # Testnet faucet (100 QTR/hour per address)
```

---

## Quick Start

### Prerequisites

- Rust 1.78+ (`rustup update stable`)
- Linux / macOS

### Build

```bash
git clone https://github.com/quantarsite/quantar-testnet
cd quantar-testnet
cargo build --release
```

### Generate a keypair

```bash
./target/release/qtrc-node keygen
```

Output:
```
HYDRA-X keypair generated
Address : qtr1<hex>
```

### Start a node

```bash
./target/release/qtrc-node start \
  --rpc 0.0.0.0:8545 \
  --data-dir ./data
```

### Start the faucet

```bash
./target/release/qtrc-faucet \
  --listen 0.0.0.0:8546 \
  --node-rpc http://127.0.0.1:8545 \
  --faucet-address <genesis-faucet-address>
```

---

## JSON-RPC API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Node status, height, hash |
| GET | `/account/:address` | Balance + nonce |
| POST | `/tx` | Submit signed transaction |
| POST | `/faucet` | Request 100 QTR (faucet only) |

### Example — query account

```bash
curl http://localhost:8545/account/<address-hex>
```

### Example — request faucet drip

```bash
curl -X POST http://localhost:8546/faucet \
  -H 'Content-Type: application/json' \
  -d '{"address":"<your-address-hex>"}'
```

---

## HYDRA-X Protocol

HYDRA-X is the AND-composition protocol at the core of Quantar Network.

A signature `σ = (σ_ML, σ_SLH)` is valid iff:

```
Verify_ML-DSA-87(pk_ML, m, σ_ML) = 1
  AND
Verify_SLH-DSA(pk_SLH, m, σ_SLH) = 1
```

This is enforced for every transaction and block proposal.
Breaking Quantar's signature scheme requires simultaneously breaking
both ML-DSA-87 **and** SLH-DSA — two independent hardness assumptions
(module lattice and hash function collision resistance).

Academic paper: [ePrint 2026/108782](https://eprint.iacr.org/xxxx/108782)

---

## Chain Parameters (Testnet v1)

| Parameter | Value |
|-----------|-------|
| Chain ID | `quantar-testnet-1` |
| Block time | 5 seconds |
| Max tx/block | 500 |
| Native token | QTR |
| Micro unit | µQTR (1 QTR = 1,000,000 µQTR) |
| Faucet drip | 100 QTR / hour / address |

---

## Contributing

Quantar is open for validator participation.
Contact: contact@quantarnetwork.com
Website: https://quantarnetwork.com
