#!/usr/bin/env bash
# CVE-2026-98432 mitigation (Ubuntu / Debian)
#  - drop incoming TCP packets with IPv4 options (nftables, prerouting/raw)
#  - net.ipv4.tcp_migrate_req=0
# Usage:
#   bash cve98432.sh            # apply + verify
#   bash cve98432.sh --check    # verify only
#   bash cve98432.sh --remove   # remove mitigation (after kernel is patched)
set -u
UNIT=/etc/systemd/system/cve98432.service
SYSCTL=/etc/sysctl.d/99-cve98432.conf
MIG=/proc/sys/net/ipv4/tcp_migrate_req
H=$(hostname)
R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'
FAILED=0
ok()   { echo "${G}[OK]${N}   $*"; }
warn() { echo "${Y}[WARN]${N} $*"; }
fail() { echo "${R}[FAIL]${N} $*"; FAILED=1; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 2; }
MODE=${1:-apply}

# ---------- remove ----------
if [ "$MODE" = "--remove" ]; then
  systemctl disable --now cve98432 </dev/null >/dev/null 2>&1
  rm -f "$UNIT" "$SYSCTL"
  systemctl daemon-reload </dev/null
  if nft list table inet cve98432 </dev/null >/dev/null 2>&1; then
    fail "$H: table inet cve98432 still present"
  else
    ok "$H: mitigation removed"
  fi
  exit $FAILED
fi

# ---------- apply ----------
if [ "$MODE" = "apply" ]; then
  if ! command -v nft >/dev/null 2>&1; then
    echo "Installing nftables..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables </dev/null >/dev/null 2>&1
  fi
  NFT=$(command -v nft) || { fail "$H: nft not available"; exit 1; }

  cat > "$UNIT" <<EOF
[Unit]
Description=Mitigation CVE-2026-98432 (drop TCP with IPv4 options)
After=network-pre.target nftables.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-$NFT delete table inet cve98432
ExecStart=$NFT add table inet cve98432
ExecStart=$NFT add chain inet cve98432 pre { type filter hook prerouting priority -300 \; policy accept \; }
ExecStart=$NFT add rule inet cve98432 pre ip protocol tcp ip hdrlength != 5 counter drop
ExecStop=$NFT delete table inet cve98432

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload </dev/null
  systemctl enable cve98432 </dev/null >/dev/null 2>&1
  systemctl restart cve98432 </dev/null

  if [ -e "$MIG" ]; then
    echo 'net.ipv4.tcp_migrate_req=0' > "$SYSCTL"
    sysctl -q -w net.ipv4.tcp_migrate_req=0 >/dev/null 2>&1
  fi
fi

# ---------- verify ----------
echo "== $H | kernel $(uname -r) =="

systemctl is-enabled cve98432 </dev/null >/dev/null 2>&1 && ok "service enabled (survives reboot)" || fail "service not enabled"
systemctl is-active  cve98432 </dev/null >/dev/null 2>&1 && ok "service active" || fail "service not active (journalctl -u cve98432)"

if nft list chain inet cve98432 pre </dev/null 2>/dev/null | grep -q 'hdrlength != 5'; then
  ok "nft rule present"
else
  fail "nft rule missing"
fi

if [ -e "$MIG" ]; then
  [ "$(cat $MIG)" = "0" ] && ok "tcp_migrate_req = 0" || fail "tcp_migrate_req = $(cat $MIG)"
else
  ok "tcp_migrate_req not in this kernel (n/a)"
fi

# functional test: normal SYN must pass, SYN with IPv4 options must be dropped
cnt() { nft list chain inet cve98432 pre </dev/null 2>/dev/null | grep -o 'packets [0-9]*' | awk '{print $2}'; }
if command -v python3 >/dev/null 2>&1; then
  BEFORE=$(cnt); BEFORE=${BEFORE:-0}
  RES=$(python3 -c '
import socket
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
port = srv.getsockname()[1]
def t(opts):
    s = socket.socket(); s.settimeout(2)
    if opts:
        s.setsockopt(socket.IPPROTO_IP, 4, b"\x07\x07\x04\x00\x00\x00\x00\x00")  # IP_OPTIONS: Record Route
    try:
        s.connect(("127.0.0.1", port)); return 1
    except Exception:
        return 0
    finally:
        s.close()
print(t(False), t(True))
' </dev/null 2>/dev/null)
  AFTER=$(cnt); AFTER=${AFTER:-0}
  NORMAL=${RES%% *}; WITHOPT=${RES##* }
  [ "$NORMAL" = "1" ] && ok "normal TCP connect works" || fail "normal TCP connect failed (check firewall on lo)"
  if [ "$WITHOPT" = "0" ] && [ "$AFTER" -gt "$BEFORE" ]; then
    ok "TCP with IPv4 options dropped (counter $BEFORE -> $AFTER)"
  else
    fail "TCP with IPv4 options NOT dropped (connect=$WITHOPT, counter $BEFORE -> $AFTER)"
  fi
else
  warn "python3 not found, functional test skipped"
fi

if [ $FAILED -eq 0 ]; then
  echo "${G}RESULT $H: OK — CVE-2026-98432 mitigated${N}"
else
  echo "${R}RESULT $H: NOT OK${N}"
fi
exit $FAILED
