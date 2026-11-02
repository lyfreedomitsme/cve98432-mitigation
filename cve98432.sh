#!/usr/bin/env bash
# CVE-2026-98432 mitigation
#   Ubuntu / Debian / RHEL-family (incl. CentOS 7)
#   - drop incoming TCP packets with IPv4 options (prerouting, before conntrack)
#       backend nft       : nftables table inet cve98432 (systemd unit)
#       backend iptables  : iptables raw PREROUTING u32 rule (systemd unit)
#       backend firewalld : same iptables rule as a permanent firewalld direct rule
#   - net.ipv4.tcp_migrate_req=0 and net.mptcp.enabled=0 (if the kernel has them)
# Usage:
#   bash cve98432.sh            # apply + verify
#   bash cve98432.sh --check    # verify only
#   bash cve98432.sh --remove   # remove mitigation (after kernel is patched)
set -u
UNIT=/etc/systemd/system/cve98432.service
RULES=/etc/cve98432.nft
HELPER=/usr/local/sbin/cve98432-iptables
SYSCTL=/etc/sysctl.d/99-cve98432.conf
STATE=/etc/cve98432.backend
MIG=/proc/sys/net/ipv4/tcp_migrate_req
MPTCP=/proc/sys/net/mptcp/enabled
U32='0>>24&0x0F=6:15'                       # IPv4 IHL 6..15 = header has options
IPT_ARGS=(-p tcp -m u32 --u32 "$U32" -j DROP)
H=$(hostname)
R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'
FAILED=0
ok()   { echo "${G}[OK]${N}   $*"; }
warn() { echo "${Y}[WARN]${N} $*"; }
fail() { echo "${R}[FAIL]${N} $*"; FAILED=1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 2; }
MODE=${1:-apply}

fw_active()   { have firewall-cmd && systemctl is-active firewalld </dev/null >/dev/null 2>&1; }
nft_present() { have nft && nft list table inet cve98432 </dev/null >/dev/null 2>&1; }
ipt_present() { have iptables && iptables -t raw -S 2>/dev/null | grep -Eq 'u32.*(0x6:0xf|6:15)'; }

detect_backend() {
  if [ -s "$STATE" ]; then cat "$STATE"; return; fi
  if nft_present; then echo nft; return; fi
  if ipt_present; then fw_active && echo firewalld || echo iptables; return; fi
  echo none
}

write_unit() {   # $1 = ExecStart, $2 = ExecStop, $3 = optional ExecStartPre
  cat > "$UNIT" <<EOF
[Unit]
Description=Mitigation CVE-2026-98432 (drop TCP with IPv4 options)
After=network-pre.target nftables.service iptables.service firewalld.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
${3:+ExecStartPre=$3}
ExecStart=$1
ExecStop=$2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload </dev/null
  systemctl enable cve98432 </dev/null >/dev/null 2>&1
  systemctl restart cve98432 </dev/null
}

remove_all() {
  systemctl disable --now cve98432 </dev/null >/dev/null 2>&1
  have nft && nft delete table inet cve98432 </dev/null >/dev/null 2>&1
  if fw_active; then
    firewall-cmd --permanent --direct --remove-rule ipv4 raw PREROUTING 0 "${IPT_ARGS[@]}" >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
  fi
  if have iptables; then
    while iptables -t raw -D PREROUTING "${IPT_ARGS[@]}" 2>/dev/null; do :; done
  fi
  rm -f "$UNIT" "$RULES" "$HELPER" "$SYSCTL" "$STATE"
  systemctl daemon-reload </dev/null
}

# ---------- remove ----------
if [ "$MODE" = "--remove" ]; then
  remove_all
  if nft_present || ipt_present; then
    fail "$H: rule still present"
  else
    ok "$H: mitigation removed"
  fi
  exit $FAILED
fi

# ---------- apply ----------
apply_nft() {
  NFT=$(command -v nft)
  cat > "$RULES" <<'EOF'
table inet cve98432 {
  chain pre {
    type filter hook prerouting priority -300; policy accept;
    ip protocol tcp ip hdrlength != 5 counter drop
  }
}
EOF
  write_unit "$NFT -f $RULES" "-$NFT delete table inet cve98432" "-$NFT delete table inet cve98432"
  nft_present
}

apply_iptables() {
  IPT=$(command -v iptables)
  cat > "$HELPER" <<EOF
#!/bin/sh
# CVE-2026-98432 mitigation helper
case "\$1" in
  start) $IPT -t raw -C PREROUTING -p tcp -m u32 --u32 '$U32' -j DROP 2>/dev/null || \\
         $IPT -t raw -I PREROUTING -p tcp -m u32 --u32 '$U32' -j DROP ;;
  stop)  while $IPT -t raw -D PREROUTING -p tcp -m u32 --u32 '$U32' -j DROP 2>/dev/null; do :; done ;;
esac
EOF
  chmod 755 "$HELPER"
  write_unit "$HELPER start" "$HELPER stop"
  ipt_present
}

apply_firewalld() {
  firewall-cmd --permanent --direct --query-rule ipv4 raw PREROUTING 0 "${IPT_ARGS[@]}" >/dev/null 2>&1 || \
    firewall-cmd --permanent --direct --add-rule ipv4 raw PREROUTING 0 "${IPT_ARGS[@]}" >/dev/null
  firewall-cmd --reload >/dev/null
  ipt_present
}

if [ "$MODE" = "apply" ]; then
  KMAJ=$(uname -r | cut -d. -f1)
  # clean previous install of any backend, then choose one
  remove_all
  if [ "$KMAJ" -ge 4 ] && ! have nft && have apt-get; then
    echo "Installing nftables..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables </dev/null >/dev/null 2>&1
  fi

  BACKEND=none
  if [ "$KMAJ" -ge 4 ] && have nft && apply_nft; then
    BACKEND=nft
  else
    systemctl disable --now cve98432 </dev/null >/dev/null 2>&1; rm -f "$UNIT" "$RULES"
    if ! have iptables; then
      fail "$H: neither working nft nor iptables found"; exit 1
    fi
    if fw_active; then
      apply_firewalld && BACKEND=firewalld
    else
      apply_iptables && BACKEND=iptables
    fi
  fi
  [ "$BACKEND" = none ] && { fail "$H: could not install rule (journalctl -u cve98432)"; }
  echo "$BACKEND" > "$STATE"

  : > "$SYSCTL"
  if [ -e "$MIG" ]; then
    echo 'net.ipv4.tcp_migrate_req=0' >> "$SYSCTL"
    sysctl -q -w net.ipv4.tcp_migrate_req=0 >/dev/null 2>&1
  fi
  if [ -e "$MPTCP" ]; then
    echo 'net.mptcp.enabled=0' >> "$SYSCTL"
    sysctl -q -w net.mptcp.enabled=0 >/dev/null 2>&1
  fi
  [ -s "$SYSCTL" ] || rm -f "$SYSCTL"
fi

# ---------- verify ----------
BACKEND=$(detect_backend)
echo "== $H | kernel $(uname -r) | backend $BACKEND =="

case "$BACKEND" in
  nft|iptables)
    systemctl is-enabled cve98432 </dev/null >/dev/null 2>&1 && ok "service enabled (survives reboot)" || fail "service not enabled"
    systemctl is-active  cve98432 </dev/null >/dev/null 2>&1 && ok "service active" || fail "service not active (journalctl -u cve98432)"
    ;;
  firewalld)
    firewall-cmd --permanent --direct --query-rule ipv4 raw PREROUTING 0 "${IPT_ARGS[@]}" >/dev/null 2>&1 \
      && ok "firewalld permanent direct rule (survives reboot)" || fail "firewalld permanent rule missing"
    ;;
  *) fail "mitigation not installed" ;;
esac

if [ "$BACKEND" = nft ]; then
  nft list chain inet cve98432 pre </dev/null 2>/dev/null | grep -q 'hdrlength != 5' && ok "nft rule present" || fail "nft rule missing"
elif [ "$BACKEND" != none ]; then
  ipt_present && ok "iptables raw rule present" || fail "iptables raw rule missing"
fi

if [ -e "$MIG" ]; then
  [ "$(cat $MIG)" = "0" ] && ok "tcp_migrate_req = 0" || fail "tcp_migrate_req = $(cat $MIG)"
else
  ok "tcp_migrate_req not in this kernel (n/a)"
fi

if [ -e "$MPTCP" ]; then
  [ "$(cat $MPTCP)" = "0" ] && ok "mptcp.enabled = 0" || fail "mptcp.enabled = $(cat $MPTCP)"
  # only public listeners matter; localhost ones (e.g. containerd: Go >= 1.24 enables MPTCP by default) are not reachable remotely
  PUB_MPTCP=$(have ss && ss -lnMHp 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\]|::1)/')
  if [ -n "$PUB_MPTCP" ]; then
    warn "public MPTCP listeners still open (opened before disable) — restart: $(echo "$PUB_MPTCP" | grep -o '(("[^"]*"' | tr -d '("' | sort -u | tr '\n' ' ')"
  fi
else
  ok "MPTCP not in this kernel (n/a)"
fi

# functional test: normal SYN must pass, SYN with IPv4 options must be dropped
cnt() {
  if [ "$BACKEND" = nft ]; then
    nft list chain inet cve98432 pre </dev/null 2>/dev/null | grep -o 'packets [0-9]*' | awk '{print $2; exit}'
  else
    iptables -t raw -L -v -n -x 2>/dev/null | awk '/u32/ {print $1; exit}'
  fi
}
PY=$(command -v python3 || command -v python || command -v python2 || true)
if [ -n "$PY" ] && [ "$BACKEND" != none ]; then
  BEFORE=$(cnt); BEFORE=${BEFORE:-0}
  RES=$("$PY" -c '
import socket
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
port = srv.getsockname()[1]
def t(opts):
    s = socket.socket(); s.settimeout(2)
    if opts:
        s.setsockopt(socket.IPPROTO_IP, 4, b"\x07\x07\x04\x00\x00\x00\x00\x00")  # IP_OPTIONS: Record Route
    try:
        s.connect(("127.0.0.1", port)); r = 1
    except Exception:
        r = 0
    s.close()
    return r
print("%d %d" % (t(False), t(True)))
' </dev/null 2>/dev/null)
  AFTER=$(cnt); AFTER=${AFTER:-0}
  NORMAL=${RES%% *}; WITHOPT=${RES##* }
  [ "$NORMAL" = "1" ] && ok "normal TCP connect works" || fail "normal TCP connect failed (check firewall on lo)"
  if [ "$WITHOPT" = "0" ] && [ "$AFTER" -gt "$BEFORE" ]; then
    ok "TCP with IPv4 options dropped (counter $BEFORE -> $AFTER)"
  else
    fail "TCP with IPv4 options NOT dropped (connect=$WITHOPT, counter $BEFORE -> $AFTER)"
  fi
elif [ -z "$PY" ]; then
  warn "python not found, functional test skipped"
fi

if [ $FAILED -eq 0 ]; then
  echo "${G}RESULT $H: OK — CVE-2026-98432 mitigated${N}"
else
  echo "${R}RESULT $H: NOT OK${N}"
fi

# ---------- system info + official kernel fix status (as of 2026-11-02) ----------
# upgrades only the installed kernel metapackage(s) (linux-image-amd64 / -cloud-amd64 / -6.12-amd64)
KERNEL_ONLY_CMD='apt update && apt install -y --only-upgrade $(dpkg-query -W -f='"'"'${db:Status-Abbrev}${Package}\n'"'"' '"'"'linux-image-*'"'"' | awk '"'"'/^ii/{print $2}'"'"' | grep -vE '"'"'^linux-image-[0-9]+\.[0-9]+\.[0-9]+[-+]'"'"') && reboot'
OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
OSID=$(. /etc/os-release 2>/dev/null; echo "${ID:-?}:${VERSION_ID:-?}")
case "$OSID" in
  debian:13*)           FIX="available: linux 6.12.113-1 (DSA-6568-1)"; KUPD=1 ;;
  debian:12*)           FIX="available: linux 6.1.190-1 / linux-6.12 6.12.113-1~deb12u1"; KUPD=1 ;;
  debian:11*|debian:10*) FIX="none (Debian LTS ended) -> keep mitigation" ;;
  ubuntu:2[0-9].04|ubuntu:2[0-9].10)
    case "${OSID#ubuntu:}" in
      20.04|18.04|16.04) FIX="none (end of standard support, Pro/ESM only) -> keep mitigation" ;;
      *)                 FIX="not released yet (Ubuntu: work in progress) -> keep mitigation, check later" ;;
    esac ;;
  ubuntu:1[0-9].*)      FIX="none (end of standard support, Pro/ESM only) -> keep mitigation" ;;
  almalinux:9*)         FIX="testing repo only: kernel-5.14.0-687.61.2.el9_8 (almalinux-testing)" ;;
  almalinux:8*)         FIX="testing repo only: kernel-4.18.0-553.180.2.el8_10 (almalinux-testing)" ;;
  almalinux:10*)        FIX="testing repo only: kernel-6.12.0-211.69.2.el10_2 (almalinux-testing)" ;;
  centos:7*|centos:6*)  FIX="none (CentOS EOL) -> keep mitigation" ;;
  *)                    FIX="unknown for this OS -> check vendor advisory" ;;
esac
echo "OS:         $OS"
echo "Kernel:     $(uname -r)"
echo "Kernel fix: $FIX"
if [ "${KUPD:-0}" = 1 ]; then
  echo "Kernel-only update (does not touch PHP/DB/etc.), then remove mitigation:"
  echo "  $KERNEL_ONLY_CMD"
fi
exit $FAILED
