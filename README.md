# Server Doctor

A single-file, interactive bash script for diagnosing and fixing common Linux
server problems: high CPU/load, low memory, full disks, failed services, an
open firewall, SSH brute-force attacks, cryptominers, and general malware.
No dependencies beyond bash and core Linux tools — missing helpers (like
`iostat`, `iotop`, or `fail2ban`) are offered for install on demand.

## Supported systems

- **Distros:** Debian/Ubuntu, RHEL/AlmaLinux/Rocky/CentOS/Fedora, openSUSE, Arch, Alpine
- **Init systems:** systemd, OpenRC, SysV
- **Firewalls:** ufw, firewalld, CSF, nftables, iptables
- **Malware scanners:** Imunify360, ClamAV, Linux Malware Detect, rkhunter
- **Control panels:** detects Plesk, cPanel, DirectAdmin, CyberPanel, Webmin

## Usage

```bash
sudo bash "Server doctor.sh"            # interactive menu
sudo bash "Server doctor.sh" --report   # read-only full report, saved to /root/server-report-<date>.txt
```

Must be run as root — it reads logs, restarts services, and manages the
firewall. `--report` mode never changes anything: every prompt is skipped
and every action that would modify the system is disabled.

## Menu

1. System info — OS, kernel, package manager, init system, firewall, panel, web folders
2. CPU & memory — load average, CPU breakdown (user/sys/idle/iowait/steal), OOM check
3. Top processes — by CPU and by memory
4. Docker — container stats, logs, restart
5. Disk — space, inode usage, disk speed (iostat), disk hogs (iotop), cleanup (package cache, journal, Docker prune)
6. Services — failed units, restart/enable/view logs for any service
7. Firewall — status, ports open to the internet, enable/open/close ports, block an IP
8. Login security — SSH brute-force attempts, top attacking IPs, fail2ban status/install
9. Zombie processes — lists zombies and their parents
10. Suspicious processes — processes running from temp/hidden folders, deleted binaries, unpackaged binaries, connections on common miner ports
11. Cron & startup check — malicious cron/systemd patterns, recently changed SSH keys, `/etc/ld.so.preload` tampering
12. Malware — scanner results, on-demand scan (Imunify/maldet/ClamAV), npm file-vs-registry verification
13. System updates — check and optionally install
14. Full report — runs everything read-only and saves it to a file

## Safety

Every action that changes the system (restarting a service, opening a port,
blocking an IP, installing a package, killing a process) requires an
explicit `y` confirmation. Nothing destructive ever runs automatically.
