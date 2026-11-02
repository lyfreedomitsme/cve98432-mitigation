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

## Patched kernel on Debian 12 / 13

Fixed: Debian 13 `linux 6.12.113-1` (DSA-6568-1), Debian 12 `linux 6.1.190-1` / `linux-6.12 6.12.113-1~deb12u1`.
Requires `security.debian.org` in apt sources.

### Kernel only (recommended)

Upgrades only the installed kernel metapackage (`linux-image-amd64`, `linux-image-cloud-amd64` or `linux-image-6.12-amd64`). PHP, MariaDB, web and mail servers are not touched.

```bash
apt update && apt install -y --only-upgrade $(dpkg-query -W -f='${db:Status-Abbrev}${Package}\n' 'linux-image-*' | awk '/^ii/{print $2}' | grep -vE '^linux-image-[0-9]+\.[0-9]+\.[0-9]+[-+]') && reboot
```

### Full system upgrade (only if the client asks for it)

Upgrades every package (PHP, MariaDB, Apache/Nginx, Dovecot…). Make a VPS snapshot first and run it inside `screen`, so a dropped SSH session does not interrupt it:

```bash
apt install -y screen && screen -S upd
apt update && apt full-upgrade -y && reboot
```
Reconnect after a disconnect with `screen -r upd`.

If it hangs on `mariadb-server` with MariaDB stuck in `deactivating` (socket activation restarts it during upgrade):
```bash
systemctl stop mariadb.socket
kill -9 $(pgrep -x mariadbd)
```
`apt` then continues; MariaDB is started again by the package and InnoDB recovers on start.

### After reboot

```bash
grep -o 'Debian 6[^ ]*' /proc/version
```
Must show `Debian 6.1.190-1` / `6.12.113-1` or newer. Then remove the mitigation (`--remove` above).
