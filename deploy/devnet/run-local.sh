#!/usr/bin/env bash
# Four BFT validators on this machine, a faucet key, and one transaction.
# Usage: deploy/devnet/run-local.sh [workdir]   (stop with Ctrl+C)
#
# Validator N: RPC on 127.0.0.1:860N, p2p on 127.0.0.1:960N, log in
# <workdir>/nodeN.log. Send more with:
#   target/release/qtrc-wallet --key <workdir>/faucet.key \
#     --rpc http://127.0.0.1:8601 send <address> 1
# Stop one validator (kill its process) and the other three keep deciding;
# start it again with the same command and it catches up.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --release -p qtrc-node -p qtrc-wallet
B=$PWD/target/release
D=${1:-$(mktemp -d)}
mkdir -p "$D"
addr() { "$B/qtrc-node" keygen --out "$1" | awk '/^Address/ {print $3}'; }
[ -f "$D/faucet.key" ] || addr "$D/faucet.key" > "$D/faucet.addr"
for i in 1 2 3 4; do [ -f "$D/v$i.key" ] || addr "$D/v$i.key" > "$D/v$i.addr"; done
{
  echo '{"bft_from_height": 1, "validators": ['
  for i in 1 2 3 4; do
    sep=","; [ "$i" -eq 4 ] && sep=""
    echo "  {\"address\": \"$(cat "$D/v$i.addr")\", \"p2p\": \"http://127.0.0.1:960$i\"}$sep"
  done
  echo ']}'
} > "$D/bft.json"
export QTR_FAUCET_ADDRESS=$(cat "$D/faucet.addr")
trap 'kill $(jobs -p) 2>/dev/null' EXIT
for i in 1 2 3 4; do
  "$B/qtrc-node" start --data-dir "$D/data$i" --rpc "127.0.0.1:860$i" --key-file "$D/v$i.key" \
    --p2p "127.0.0.1:960$i" --bft-config "$D/bft.json" > "$D/node$i.log" 2>&1 &
done
sleep 3
"$B/qtrc-wallet" --key "$D/faucet.key" --rpc http://127.0.0.1:8601 send "$(cat "$D/v2.addr")" 5
echo "Devnet in $D. Height and block hash of each validator (Ctrl+C to stop):"
while sleep 5; do
  for i in 1 2 3 4; do
    curl -s "127.0.0.1:860$i/status" | sed 's/.*"height":\([0-9]*\),"block_hash":"\(.\{12\}\).*/\1:\2/'
    printf ' '
  done
  echo
done
