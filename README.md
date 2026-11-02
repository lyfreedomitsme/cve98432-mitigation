# CVE-2026-98432 mitigation (Ubuntu / Debian)

Drops incoming TCP packets with IPv4 options (nftables, prerouting/raw) and sets `net.ipv4.tcp_migrate_req=0`, then verifies the result.
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
