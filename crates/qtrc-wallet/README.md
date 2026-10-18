# qtrc-wallet

Command-line wallet for the Quantar testnet (`quantar-testnet-2`).

Every key is a HYDRA-X keypair: ML-DSA-87 (FIPS 204) and SLH-DSA-SHA2-256s
(FIPS 205). Every transaction carries both signatures, and both must verify.
There is no ECDSA anywhere, so Ethereum, Bitcoin and Solana wallets cannot hold
QTR.

## Quick start

```
qtrc-wallet new          # create your wallet
qtrc-wallet faucet       # get 50 testnet QTR (once per hour)
qtrc-wallet balance      # check your balance
qtrc-wallet send <ADDRESS> 10.5
qtrc-wallet status       # network height and tip
```

On Windows, run it from PowerShell as `.\qtrc-wallet.exe new`. On macOS, if
Gatekeeper blocks it, run `xattr -d com.apple.quarantine qtrc-wallet` once.

## Where the key lives

`~/.quantar/wallet.key` (on Windows, `C:\Users\<you>\.quantar\wallet.key`).
Use `--key <file>` to keep several wallets. Back the file up: whoever has it
controls the address.

This is a testnet wallet. The key file is not encrypted (it is owner-only on
Linux and macOS). Testnet QTR has no monetary value; do not reuse this key for
anything that does.

## Verify your download

Each release ships a `SHA256SUMS` file. Compare it with
`sha256sum <file>` (Linux), `shasum -a 256 <file>` (macOS) or
`Get-FileHash <file>` (PowerShell).

## Options

`--rpc` (default `https://testnet.quantarnetwork.com/rpc`), `--faucet`
(default `https://faucet.quantarnetwork.com`), `--key`. Each can also be set
with `QTR_RPC`, `QTR_FAUCET` and `QTR_WALLET`.

Questions: contact@quantarnetwork.com
