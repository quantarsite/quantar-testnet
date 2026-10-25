#!/usr/bin/env bash
# One validator of the public BFT devnet, side by side with anything else on
# the server (the live testnet node keeps its own binary, data and ports).
#
#   devnet-node.sh init                 install the binary next to this script,
#                                       create this validator's key, print its address
#   devnet-node.sh start <faucet-addr>  needs /etc/quantar-devnet/bft.json; opens the
#                                       p2p port to the other validators only and
#                                       starts the quantar-devnet service
#   devnet-node.sh status               height and block hash
#
# Paths: binary /usr/local/bin/qtrc-node-devnet, key /etc/quantar-devnet/validator.key
# (never leaves this server), data /var/lib/quantar-devnet, RPC 127.0.0.1:8645 (local
# only), p2p 0.0.0.0:9646.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=/usr/local/bin/qtrc-node-devnet
ETC=/etc/quantar-devnet
DATA=/var/lib/quantar-devnet
P2P_PORT=9646
RPC=127.0.0.1:8645

case "${1:-}" in
  init)
    install -m 755 "$HERE/qtrc-node" "$BIN"
    mkdir -p "$ETC" "$DATA"
    chmod 700 "$ETC"
    if [ ! -f "$ETC/validator.key" ]; then
      # keygen writes the key with mode 0600 and never overwrites one.
      "$BIN" keygen --out "$ETC/validator.key" | awk '/^Address/ {print $3}' > "$ETC/validator.addr"
    fi
    echo "validator address: $(cat "$ETC/validator.addr")"
    ;;
  start)
    faucet=${2:?usage: devnet-node.sh start <faucet-address>}
    [ -f "$ETC/bft.json" ] || { echo "missing $ETC/bft.json"; exit 1; }
    # The other validators' addresses, from the config.
    ips=$(python3 -c '
import json, socket, sys, urllib.parse
for v in json.load(open(sys.argv[1]))["validators"]:
    host = urllib.parse.urlparse(v["p2p"]).hostname
    print(socket.gethostbyname(host))
' "$ETC/bft.json")
    for ip in $ips; do ufw allow from "$ip" to any port "$P2P_PORT" proto tcp >/dev/null; done
    cat > /etc/systemd/system/quantar-devnet.service <<EOF
[Unit]
Description=Quantar BFT devnet validator
After=network-online.target
Wants=network-online.target

[Service]
Environment=QTR_FAUCET_ADDRESS=$faucet
ExecStart=$BIN start --data-dir $DATA --rpc $RPC --key-file $ETC/validator.key --p2p 0.0.0.0:$P2P_PORT --bft-config $ETC/bft.json
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now quantar-devnet
    sleep 5
    curl -s "http://$RPC/status"; echo
    ;;
  status)
    curl -s "http://$RPC/status"; echo
    ;;
  *)
    sed -n '2,15p' "$0"; exit 1 ;;
esac
