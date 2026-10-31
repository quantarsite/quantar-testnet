#!/usr/bin/env bash
# Turn one of the four quantar-testnet-2 servers into a BFT validator (v0.10.0).
#
#   testnet2-validator.sh sf    San Francisco (164.90.145.184): the current
#                               validator. Run from ~/quantar-testnet after
#                               `cargo build --release`.
#   testnet2-validator.sh fra   Frankfurt (207.154.219.21)
#   testnet2-validator.sh sp    Sao Paulo (172.233.12.117)
#   testnet2-validator.sh tyo   Tokyo (45.76.102.102)
#                               For these three, put qtrc-node (v0.10.0) next
#                               to this script first.
#
# Until block 100 San Francisco keeps making the blocks alone and the others
# copy them over port 9545; from block 100 all four vote. Safe to run again.
#
# What it does: writes /etc/quantar/bft.json (the four validators, the same
# file on every server), opens 9545 only to the other three, removes the old
# devnet (service and its 9646 firewall rules), installs the binary, points
# the node service at the BFT config, restarts it and shows its status.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROLE=${1:-}
FAUCET=9b7eb38c5f5b8fa2248fa761a4ec4730554aed10b9a6a9069c9e2db3ea1f7aaf
IPS="164.90.145.184 207.154.219.21 172.233.12.117 45.76.102.102"
case "$ROLE" in
  sf)  ME=164.90.145.184 ;;
  fra) ME=207.154.219.21 ;;
  sp)  ME=172.233.12.117 ;;
  tyo) ME=45.76.102.102 ;;
  *)   sed -n '2,19p' "$0"; exit 1 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

# 1. Binary
if [ "$ROLE" = sf ]; then
  BIN_DIR=$HERE/../../target/release
  [ -x "$BIN_DIR/qtrc-node" ] || { echo "build first: cd ~/quantar-testnet && cargo build --release"; exit 1; }
else
  BIN_DIR=$HERE
  [ -x "$BIN_DIR/qtrc-node" ] || chmod 755 "$BIN_DIR/qtrc-node" 2>/dev/null || true
  [ -f "$BIN_DIR/qtrc-node" ] || { echo "missing $BIN_DIR/qtrc-node: copy it here first"; exit 1; }
fi
VER=$("$BIN_DIR/qtrc-node" --version | awk '{print $2}')
[ "$VER" = 0.10.0 ] || { echo "qtrc-node is $VER, expected 0.10.0"; exit 1; }

# 2. Key: San Francisco keeps its key; the others use the one made with keygen.
if [ "$ROLE" = sf ]; then KEY=/etc/quantar/node.key; else KEY=/etc/quantar/validator.key; fi
[ -f "$KEY" ] || { echo "missing $KEY"; exit 1; }

# 3. The four validators (must match the code; the node refuses otherwise).
mkdir -p /etc/quantar /var/lib/quantar
cat > /etc/quantar/bft.json <<'EOF'
{
  "bft_from_height": 100,
  "validators": [
    { "address": "809ae6fb45d3d7c9a2c2f3968c58cc55ad6bb2ca2cfe84f65619c013bbcbbbff", "p2p": "http://164.90.145.184:9545" },
    { "address": "fbeef7f77c020ebedf27417e1eaa4c1676b4bd2e192692db35a914b5c178b59c", "p2p": "http://207.154.219.21:9545" },
    { "address": "da14876269335bb687049d73033210845006eb1544803fd9f969f4a3c541f3df", "p2p": "http://172.233.12.117:9545" },
    { "address": "a9705f52efea161c8f6a55bd30c2b093260783002993b7e71bf918c3713b73da", "p2p": "http://45.76.102.102:9545" }
  ]
}
EOF

# 4. Old devnet out of the way: service and its firewall rules.
systemctl disable --now quantar-devnet 2>/dev/null || true
while ufw status numbered | grep -q '9646/tcp'; do
  n=$(ufw status numbered | grep '9646/tcp' | head -1 | sed 's/^\[ *\([0-9]*\)\].*/\1/')
  ufw --force delete "$n" >/dev/null
done

# 5. Port 9545 only from the other three validators.
while ufw status numbered | grep -E '9545/tcp( \(v6\))? +ALLOW IN +Anywhere' >/dev/null; do
  n=$(ufw status numbered | grep -E '9545/tcp( \(v6\))? +ALLOW IN +Anywhere' | head -1 | sed 's/^\[ *\([0-9]*\)\].*/\1/')
  ufw --force delete "$n" >/dev/null
done
for ip in $IPS; do
  [ "$ip" = "$ME" ] && continue
  ufw allow from "$ip" to any port 9545 proto tcp >/dev/null
done

# 6. Install and point the service at the BFT config.
ARGS="start --data-dir /var/lib/quantar --rpc 127.0.0.1:8545 --key-file $KEY --p2p 0.0.0.0:9545 --bft-config /etc/quantar/bft.json"
if [ "$ROLE" = sf ]; then
  systemctl stop quantar-watchtower quantar-faucet quantar-node
  install -m 755 "$BIN_DIR"/qtrc-{node,faucet,wallet,watchtower} /usr/local/bin/
  mkdir -p /etc/systemd/system/quantar-node.service.d
  cat > /etc/systemd/system/quantar-node.service.d/bft.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/qtrc-node $ARGS
EOF
  SVC=quantar-node
  systemctl daemon-reload
  systemctl start quantar-node
  sleep 8
  systemctl start quantar-faucet quantar-watchtower
else
  systemctl disable --now quantar-follower 2>/dev/null || true
  install -m 755 "$BIN_DIR/qtrc-node" /usr/local/bin/qtrc-node
  [ -f "$BIN_DIR/qtrc-wallet" ] && install -m 755 "$BIN_DIR/qtrc-wallet" /usr/local/bin/qtrc-wallet
  cat > /etc/systemd/system/quantar-validator.service <<EOF
[Unit]
Description=Quantar testnet-2 validator (BFT from block 100)
After=network-online.target
Wants=network-online.target

[Service]
Environment=QTR_FAUCET_ADDRESS=$FAUCET
ExecStart=/usr/local/bin/qtrc-node $ARGS
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/quantar
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  SVC=quantar-validator
  systemctl daemon-reload
  systemctl enable --now quantar-validator
  sleep 8
fi

# 7. Status
echo
echo "== $ROLE ($ME): $SVC is $(systemctl is-active "$SVC")"
journalctl -u "$SVC" -n 8 --no-pager -o cat | sed 's/\x1b\[[0-9;]*m//g'
echo
curl -s http://127.0.0.1:8545/status; echo
