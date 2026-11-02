# CVE-2026-98432 mitigation (Ubuntu / Debian / CentOS 7 / RHEL-family)

Drops incoming TCP packets with IPv4 options (nftables, or iptables u32 / firewalld direct rule on CentOS 7 and old kernels, before conntrack) and sets `net.ipv4.tcp_migrate_req=0` and `net.mptcp.enabled=0`, then verifies the result.
This is a temporary mitigation until a patched kernel is installed.

Apply + verify:
```bash
curl -fsSL https://raw.githubusercontent.com/lyfreedomitsme/cve98432-mitigation/main/cve98432.sh | bash
```

Verify only:
```bash
curl -fsSL https://raw.githubusercontent.com/lyfreedomitsme/cve98432-mitigation/main/cve98432.sh | bash -s -- --check
```

Remove (after kernel update + reboot):
```bash
curl -fsSL https://raw.githubusercontent.com/lyfreedomitsme/cve98432-mitigation/main/cve98432.sh | bash -s -- --remove
```
