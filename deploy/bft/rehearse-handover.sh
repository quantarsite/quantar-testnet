#!/usr/bin/env bash
# Local rehearsal of the quantar-testnet-2 switch to votes: validator 1 makes
# blocks alone up to H-1, validators 2-4 copy them, from H all four vote.
# Then one is killed, the other three keep deciding, and it catches up.
# Usage: deploy/bft/rehearse-handover.sh [workdir]   (H=5 by default)
set -uo pipefail
cd "$(dirname "$0")/../.." && cargo build --release -p qtrc-node -p qtrc-wallet >/dev/null
B=$PWD/target/release
D=${1:-$(mktemp -d)}
H=${H:-5}
if [ -e "$D" ] && [ -n "$(ls -A "$D")" ]; then echo "$D is not empty; pass a new or empty folder"; exit 1; fi
mkdir -p "$D"
addr() { "$B/qtrc-node" keygen --out "$1" | awk '/^Address/ {print $3}'; }
addr "$D/faucet.key" > "$D/faucet.addr"
for i in 1 2 3 4; do addr "$D/v$i.key" > "$D/v$i.addr"; done
addr "$D/user.key" > "$D/user.addr"
{
  echo "{\"bft_from_height\": $H, \"validators\": ["
  for i in 1 2 3 4; do
    sep=","; [ "$i" -eq 4 ] && sep=""
    echo "  {\"address\": \"$(cat "$D/v$i.addr")\", \"p2p\": \"http://127.0.0.1:970$i\"}$sep"
  done
  echo ']}'
} > "$D/bft.json"
export QTR_FAUCET_ADDRESS=$(cat "$D/faucet.addr")
V1=$(cat "$D/v1.addr")
start() {
  local i=$1
  "$B/qtrc-node" start --data-dir "$D/data$i" --rpc "127.0.0.1:870$i" --key-file "$D/v$i.key" \
    --p2p "127.0.0.1:970$i" --bft-config "$D/bft.json" --validator "$V1" >> "$D/node$i.log" 2>&1 &
  echo $! > "$D/pid$i"
}
for i in 1 2 3 4; do start $i; done
# A public follower that verifies everything (pre-BFT signatures, then commit proofs).
"$B/qtrc-node" start --data-dir "$D/dataF" --rpc 127.0.0.1:8709 --follow http://127.0.0.1:8701 \
  --validator "$V1" --bft-config "$D/bft.json" >> "$D/nodeF.log" 2>&1 &
echo $! > "$D/pidF"
trap 'kill $(cat "$D"/pid* 2>/dev/null) 2>/dev/null' EXIT
sleep 4

st() { curl -s "127.0.0.1:$1/status" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["height"], s["block_hash"][:10])' 2>/dev/null || echo down; }
show() { printf '%s |' "$1"; for p in 8701 8702 8703 8704 8709; do printf ' %s |' "$(st $p)"; done; echo; }
send() { # send via validator $1's RPC
  "$B/qtrc-wallet" --key "$D/faucet.key" --rpc "http://127.0.0.1:870$1" send "$(cat "$D/user.addr")" 1 2>&1 | tail -1
}
wait_height() { # port target timeout
  for _ in $(seq 1 "$3"); do h=$(st "$1" | cut -d' ' -f1); [ "$h" != down ] && [ "$h" -ge "$2" ] && return 0; sleep 1; done; return 1
}

n=0
for k in $(seq 1 $((H - 1))); do
  # pre-BFT: send through a non-proposer to exercise the relay too
  send $(( (k % 3) + 2 )) >/dev/null; n=$((n+1))
  wait_height 8701 "$k" 40 || { echo "FAIL: v1 did not make block $k alone"; show "pre $k"; exit 1; }
done
show "pre-BFT (v1 alone up to $((H-1)))"
for p in 8702 8703 8704 8709; do wait_height $p $((H - 1)) 40 || { echo "FAIL: $p did not copy pre-BFT blocks"; show x; exit 1; }; done
show "others copied"

send 2 >/dev/null
for p in 8701 8702 8703 8704 8709; do wait_height $p "$H" 90 || { echo "FAIL: height $H not decided on $p"; show x; exit 1; }; done
show "height $H decided by votes"
grep -h "block decided by the validators" "$D"/node[1-4].log | head -4

kill "$(cat "$D/pid3")"; rm "$D/pid3"; sleep 1
send 1 >/dev/null
for p in 8701 8702 8704 8709; do wait_height $p $((H + 1)) 120 || { echo "FAIL: 3 of 4 did not decide $((H+1))"; show x; exit 1; }; done
show "v3 down, $((H+1)) decided by 3"
send 4 >/dev/null
for p in 8701 8702 8704; do wait_height $p $((H + 2)) 120 || { echo "FAIL: $((H+2))"; show x; exit 1; }; done
start 3
wait_height 8703 $((H + 2)) 90 || { echo "FAIL: v3 did not catch up"; show x; exit 1; }
show "v3 back, caught up"
send 3 >/dev/null
for p in 8701 8702 8703 8704 8709; do wait_height $p $((H + 3)) 120 || { echo "FAIL: $((H+3)) after rejoin"; show x; exit 1; }; done
show "all four again"

# Same tip everywhere.
tips=$(for p in 8701 8702 8703 8704 8709; do st $p; done | sort -u | wc -l)
[ "$tips" -eq 1 ] && echo "PASS: one chain on all nodes" || { echo "FAIL: nodes disagree"; show x; exit 1; }

# A restart replays the whole mixed history (solo blocks, then voted ones).
kill "$(cat "$D/pid2")"; sleep 1; start 2
wait_height 8702 $((H + 3)) 60 && sed "s/\x1b\[[0-9;]*m//g" "$D/node2.log" | grep -q "Chain state restored from disk height=$((H + 3))" \
  && echo "PASS: restart replays solo + voted history" || { echo "FAIL: replay"; tail -5 "$D/node2.log"; exit 1; }
grep -hiE "panic|failed replay" "$D"/node*.log && echo "WARN: see above" || true
# The proof RPC carries the commit proof of a voted block.
curl -s "127.0.0.1:8701/proof/$(cat "$D/user.addr")" | python3 -c '
import json,sys; r=json.load(sys.stdin); c=r.get("commit")
print("PASS: /proof carries a commit proof with", len(c["precommits"]), "precommits") if c else print("FAIL: no commit in /proof")'
