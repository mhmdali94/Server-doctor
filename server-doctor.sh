#!/usr/bin/env bash
# =====================================================================
#  server-doctor.sh — interactive health check, fix & malware scan
#  Works on: Debian/Ubuntu, RHEL/Alma/Rocky/CentOS/Fedora, openSUSE,
#            Arch, Alpine (bash required)
#  Firewalls: ufw, firewalld, CSF, nftables, iptables
#  Init:      systemd, OpenRC, SysV
#  Scanners:  Imunify360, ClamAV, Linux Malware Detect, rkhunter
#
#  Usage:  sudo bash server-doctor.sh            (interactive menu)
#          sudo bash server-doctor.sh --report   (read-only full report)
# =====================================================================

# ---------- colors & helpers ----------
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; W=$'\e[1m'; N=$'\e[0m'
else
  R=; G=; Y=; B=; C=; W=; N=
fi
ok()   { echo "${G}[ OK ]${N} $*"; }
warn() { echo "${Y}[WARN]${N} $*"; }
bad()  { echo "${R}[BAD ]${N} $*"; }
info() { echo "${C}[INFO]${N} $*"; }
hdr()  { echo; echo "${W}${B}==== $* ====${N}"; }
has()  { command -v "$1" >/dev/null 2>&1; }
REPORT_MODE=0
confirm() {   # never change anything without a clear "y"
  [[ $REPORT_MODE -eq 1 ]] && return 1
  local a; read -rp "${Y}$* [y/N]: ${N}" a; [[ $a =~ ^[Yy]$ ]]
}
ask() { local a; read -rp "$1" a; echo "$a"; }
pause() { [[ $REPORT_MODE -eq 1 ]] || read -rp "Press Enter to continue..." _; }

[[ $EUID -ne 0 ]] && { bad "Please run as root: sudo bash $0"; exit 1; }

# =====================================================================
#  Detection: distro, package manager, init system, firewall, panel
# =====================================================================
detect_system() {
  OS_NAME="Unknown Linux"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_NAME=${PRETTY_NAME:-$NAME}
  fi

  PM=""
  for p in apt-get dnf yum zypper pacman apk xbps-install; do has "$p" && { PM=$p; break; }; done

  if [[ -d /run/systemd/system ]]; then INIT=systemd
  elif has rc-service; then INIT=openrc
  elif has sv && [[ -d /run/runit || -d /etc/runit ]]; then INIT=runit
  else INIT=sysv; fi

  FIREWALL=none
  if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then FIREWALL=ufw
  elif has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then FIREWALL=firewalld
  elif has csf && csf -l >/dev/null 2>&1 && [[ -f /etc/csf/csf.conf ]]; then FIREWALL=csf
  elif has nft && [[ $(nft list ruleset 2>/dev/null | grep -c 'hook input') -gt 0 ]]; then FIREWALL=nftables
  elif has iptables && [[ $(iptables -S INPUT 2>/dev/null | wc -l) -gt 1 ]]; then FIREWALL=iptables
  fi
  FW_INSTALLED=""
  for f in ufw firewall-cmd csf nft iptables; do has "$f" && FW_INSTALLED+="${f/firewall-cmd/firewalld} "; done

  PANEL=none
  [[ -d /usr/local/psa ]] && PANEL=Plesk
  [[ -d /usr/local/cpanel ]] && PANEL=cPanel
  [[ -d /usr/local/directadmin ]] && PANEL=DirectAdmin
  [[ -d /usr/local/CyberCP ]] && PANEL=CyberPanel
  [[ -d /usr/share/webmin || -d /usr/libexec/webmin ]] && [[ $PANEL == none ]] && PANEL=Webmin

  WEBROOTS=()
  for d in /var/www/vhosts /home/*/public_html /var/www /srv/www /usr/share/nginx/html; do
    [[ -d $d ]] && WEBROOTS+=("$d")
  done

  # procps tools (Alpine/BusyBox 'ps' does not support --sort)
  PS_OK=0; ps -eo pid= --sort=-%cpu >/dev/null 2>&1 && PS_OK=1
}

show_system() {
  hdr "System"
  echo "  OS:            $OS_NAME"
  echo "  Kernel:        $(uname -r)"
  echo "  Package tool:  ${PM:-unknown}"
  echo "  Init system:   $INIT"
  echo "  Firewall:      $FIREWALL   (installed: ${FW_INSTALLED:-none})"
  echo "  Control panel: $PANEL"
  echo "  Web folders:   ${WEBROOTS[*]:-none found}"
  echo "  Uptime:        $(uptime -p 2>/dev/null || uptime)"
  if has systemd-detect-virt; then echo "  Virtualization: $(systemd-detect-virt 2>/dev/null)"; fi
}

# =====================================================================
#  Cross-distro wrappers
# =====================================================================
APT_UPDATED=0
pkg_install() {
  case $PM in
    apt-get) [[ $APT_UPDATED -eq 0 ]] && { apt-get update -qq; APT_UPDATED=1; }
             DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf|yum) $PM install -y "$@" ;;
    zypper)  zypper -n install "$@" ;;
    pacman)  pacman -S --noconfirm --needed "$@" ;;
    apk)     apk add "$@" ;;
    xbps-install) xbps-install -Sy "$@" ;;
    *) bad "No known package manager. Install manually: $*"; return 1 ;;
  esac
}
need() {  # need <command> <package> — offer to install a missing tool
  has "$1" && return 0
  warn "'$1' is not installed (package: $2)."
  confirm "Install $2 now?" && pkg_install "$2" && has "$1"
}
pkg_owner() {  # prints the package that owns a file; fails if none
  local f=$1
  case $PM in
    dnf|yum|zypper) rpm -qf "$f" 2>/dev/null ;;
    apt-get) dpkg -S "$f" 2>/dev/null || dpkg -S "${f#/usr}" 2>/dev/null ;;
    pacman)  pacman -Qo "$f" 2>/dev/null ;;
    apk)     apk info --who-owns "$f" 2>/dev/null | grep -q 'owned by' && apk info --who-owns "$f" ;;
    xbps-install) xbps-query -o "$f" 2>/dev/null ;;
    *) return 1 ;;
  esac
}
svc_restart() {
  case $INIT in
    systemd) systemctl restart "$1" ;;
    openrc)  rc-service "$1" restart ;;
    runit)   sv restart "$1" ;;
    *)       service "$1" restart ;;
  esac
}
listening_ports() {  # proto  local-address  process
  if has ss; then ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}'
  elif has netstat; then netstat -tulnp 2>/dev/null | awk 'NR>2{print $1, $4, $NF}'
  fi
}
auth_log() {  # print ~24h of SSH/auth log lines
  if [[ $INIT == systemd ]] && has journalctl; then
    journalctl -u ssh -u sshd --since "24 hours ago" --no-pager -q 2>/dev/null
    return
  fi
  for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    [[ -r $f ]] && tail -n 20000 "$f"
  done
}
ssh_port() {
  local p; p=$(grep -hiE '^\s*Port\s+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | head -1)
  echo "${p:-22}"
}

# =====================================================================
#  1. CPU health
# =====================================================================
cpu_sample() { awk '/^cpu /{print $2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat; }
check_cpu() {
  hdr "CPU health"
  local cores load; cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
  load=$(cut -d' ' -f1-3 /proc/loadavg)
  info "CPU cores: $cores   Load (1/5/15 min): $load"
  info "Measuring CPU for 5 seconds..."
  local u1 n1 s1 i1 w1 q1 sq1 st1 u2 n2 s2 i2 w2 q2 sq2 st2
  read -r u1 n1 s1 i1 w1 q1 sq1 st1 <<<"$(cpu_sample)"; sleep 5
  read -r u2 n2 s2 i2 w2 q2 sq2 st2 <<<"$(cpu_sample)"
  local du=$(( (u2-u1)+(n2-n1) )) ds=$(( (s2-s1)+(q2-q1)+(sq2-sq1) ))
  local di=$((i2-i1)) dw=$((w2-w1)) dst=$(( ${st2:-0}-${st1:-0} ))
  local tot=$((du+ds+di+dw+dst)); [[ $tot -eq 0 ]] && tot=1
  local US=$((100*du/tot)) SY=$((100*ds/tot)) ID=$((100*di/tot)) WA=$((100*dw/tot)) ST=$((100*dst/tot))
  echo "  us (apps): ${W}$US%${N}  sy (kernel): $SY%  id (idle): $ID%  wa (disk wait): ${W}$WA%${N}  st (steal): ${W}$ST%${N}"

  local l1raw=${load%% *}
  local l1; l1=$(awk -v v="$l1raw" 'BEGIN{printf "%d", v+0.5}')
  if (( l1 > cores * 2 )); then bad "Load $l1raw is very high for $cores cores (tasks are waiting)."
  elif (( l1 > cores )); then warn "Load $l1raw is above $cores cores."
  else ok "Load is fine."; fi

  local problem=0
  if (( ST >= 20 )); then bad "STEAL ${ST}% → the HOST is taking your CPU. Contact your hosting provider."; problem=1
  elif (( ST >= 5 )); then warn "Steal ${ST}% (normal is under 5%)."; fi
  if (( US + SY >= 70 )); then bad "Your apps are busy (us+sy = $((US+SY))%). See menu 2 and 3."; problem=1; fi
  if (( WA >= 10 )); then bad "Disk wait ${WA}% → disk is slow or busy. See menu 4."; problem=1; fi
  (( problem == 0 )) && ok "CPU looks healthy."

  hdr "Memory"
  free -h 2>/dev/null
  local avail total
  avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo); total=$(awk '/MemTotal/{print $2}' /proc/meminfo)
  if [[ -n $avail && -n $total ]] && (( avail * 100 / total < 10 )); then bad "Less than 10% memory available!"
  else ok "Memory is fine."; fi
  if dmesg 2>/dev/null | grep -qi 'out of memory'; then warn "The kernel killed processes for lack of memory (OOM). Check: dmesg | grep -i 'out of memory'"; fi
}

# =====================================================================
#  2. Top processes
# =====================================================================
check_procs() {
  if [[ $PS_OK -eq 0 ]]; then
    warn "Your 'ps' is limited (BusyBox)."; need ps procps && detect_system
    [[ $PS_OK -eq 0 ]] && { top -b -n 1 | head -20; return; }
  fi
  hdr "Top 10 processes by CPU"
  ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu | head -11
  hdr "Top 5 processes by memory"
  ps -eo pid,user,%cpu,%mem,rss,comm --sort=-%mem | head -6
}

# =====================================================================
#  3. Docker
# =====================================================================
check_docker() {
  hdr "Docker containers"
  if ! has docker; then info "Docker is not installed."; return; fi
  docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}" 2>/dev/null
  local stopped restarting
  stopped=$(docker ps -a --filter status=exited --format '{{.Names}}' 2>/dev/null | xargs)
  restarting=$(docker ps --filter status=restarting --format '{{.Names}}' 2>/dev/null | xargs)
  [[ -n $stopped ]] && warn "Stopped containers: $stopped"
  [[ -n $restarting ]] && bad "Containers stuck restarting: $restarting"
  [[ $REPORT_MODE -eq 1 ]] && return

  echo; echo "  1) Show logs of a container   2) Restart a container   0) Back"
  local c; c=$(ask "Choose: ")
  [[ $c == 1 || $c == 2 ]] || return
  local names; mapfile -t names < <(docker ps -a --format '{{.Names}}')
  local i=1 n; for n in "${names[@]}"; do echo "  $i) $n"; ((i++)); done
  local pick; pick=$(ask "Container number: ")
  [[ $pick =~ ^[0-9]+$ ]] || { warn "Invalid choice."; return; }
  local name=${names[$((pick-1))]:-}
  [[ -z $name ]] && { warn "Invalid choice."; return; }
  if [[ $c == 1 ]]; then
    docker logs --tail 100 "$name" 2>&1
    echo; info "Error lines in the last 500 log lines:"
    docker logs --tail 500 "$name" 2>&1 | grep -iE 'error|exception|fatal|refused|timeout' | tail -15
  else
    confirm "Restart $name?" && docker restart "$name" && ok "$name restarted."
  fi
}

# =====================================================================
#  4. Disk
# =====================================================================
check_disk() {
  hdr "Disk space"
  df -h -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null || df -h
  local use mnt
  while read -r use mnt; do
    use=${use%\%}; [[ $use =~ ^[0-9]+$ ]] || continue
    if (( use >= 90 )); then bad "$mnt is ${use}% full!"
    elif (( use >= 80 )); then warn "$mnt is ${use}% full."; fi
  done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5, $6}')
  df -i -x tmpfs -x devtmpfs -x overlay 2>/dev/null | awk 'NR>1 && $5+0>=90{print "[BAD ] Inodes almost full on "$6" ("$5")"}'

  hdr "Disk speed"
  if need iostat sysstat; then
    iostat -x 2 2 | awk '/^Device/{h++} h==2'
    info "r_await / w_await (ms): under 10 good, over 20 slow. %util near 100 = overloaded."
  fi

  hdr "Who is using the disk"
  if need iotop iotop; then
    iotop -o -b -n 3 -d 1 2>/dev/null | grep -vE '^(Total|Actual|Current)|^ *TID' | head -15
  fi

  hdr "Biggest folders in /var"
  du -xh --max-depth=1 /var 2>/dev/null | sort -rh | head -8

  if [[ $REPORT_MODE -eq 0 ]]; then
    echo; echo "  Cleanup options:"
    echo "  1) Clean package cache   2) Shrink system logs to 200MB   3) Clean unused Docker data   0) Skip"
    case $(ask "Choose: ") in
      1) confirm "Clean package cache?" && case $PM in
           apt-get) apt-get clean ;; dnf|yum) $PM clean all ;; zypper) zypper clean -a ;;
           pacman) pacman -Sc --noconfirm ;; apk) apk cache clean ;; esac && ok "Done." ;;
      2) has journalctl && confirm "Shrink journal logs to 200MB?" && journalctl --vacuum-size=200M ;;
      3) has docker && confirm "Remove unused images, stopped containers, build cache? (running ones are safe)" \
           && docker system prune -f && ok "Docker cleaned." ;;
    esac
  fi
}

# =====================================================================
#  5. Services
# =====================================================================
check_services() {
  hdr "Failed services"
  case $INIT in
    systemd) local f; f=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}')
             if [[ -z $f ]]; then ok "No failed services."; else bad "Failed:"; echo "$f"; fi ;;
    openrc)  rc-status --crashed 2>/dev/null || true ;;
    runit)   info "Failed-service detection isn't implemented for runit (paths vary by system). Try: sv status /var/service/* or /etc/runit/runsvdir/current/*" ;;
    *)       info "Stopped services (may be normal):"; service --status-all 2>/dev/null | grep -F '[ - ]' | head -20 ;;
  esac

  hdr "Important services"
  local s
  for s in sshd ssh nginx apache2 httpd mysqld mariadb mysql postgresql redis redis-server php-fpm \
           docker fail2ban ufw firewalld csf lfd imunify360 psa sw-engine cron crond clamav-daemon; do
    if [[ $INIT == systemd ]]; then
      systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q . || continue
      local st; st=$(systemctl is-active "$s" 2>/dev/null)
      if [[ $st == active ]]; then ok "$s is running"; else bad "$s is $st"; fi
    elif [[ $INIT == openrc && -e /etc/init.d/$s ]]; then
      rc-service "$s" status >/dev/null 2>&1 && ok "$s is running" || bad "$s is stopped"
    fi
  done
  [[ $REPORT_MODE -eq 1 ]] && return

  echo
  local name; name=$(ask "Type a service name to restart or view logs (Enter to skip): ")
  [[ -z $name ]] && return
  echo "  1) Restart   2) Show last 50 log lines   3) Start at boot (enable)"
  case $(ask "Choose: ") in
    1) confirm "Restart $name?" && svc_restart "$name" && ok "$name restarted." ;;
    2) if [[ $INIT == systemd ]]; then journalctl -u "$name" -n 50 --no-pager
       else tail -50 "/var/log/$name.log" 2>/dev/null || tail -50 /var/log/messages; fi ;;
    3) case $INIT in
         runit) warn "Enabling at boot under runit means symlinking its 'sv' directory into the active service dir (e.g. ln -s /etc/sv/$name /var/service/) — the exact path varies by system, so do this manually." ;;
         *) confirm "Enable $name at boot?" && case $INIT in
              systemd) systemctl enable "$name" ;; openrc) rc-update add "$name" default ;;
              *) if has update-rc.d; then update-rc.d "$name" enable; else chkconfig "$name" on; fi ;; esac ;;
       esac ;;
  esac
}

# =====================================================================
#  6. Firewall
# =====================================================================
fw_status() {
  hdr "Firewall ($FIREWALL)"
  case $FIREWALL in
    ufw)       ufw status verbose ;;
    firewalld) echo "Zone: $(firewall-cmd --get-default-zone)"; firewall-cmd --list-all ;;
    csf)       grep -E '^(TCP_IN|TCP_OUT|UDP_IN|TESTING) ' /etc/csf/csf.conf ;;
    nftables)  nft list ruleset | head -60 ;;
    iptables)  iptables -S INPUT | head -40 ;;
    none)      bad "No active firewall! Installed tools: ${FW_INSTALLED:-none}" ;;
  esac
}

fw_open_ports_check() {
  hdr "Ports open to the internet"
  local lines; lines=$(listening_ports | grep -vE '127\.0\.0\.|\[::1\]|::1:' )
  if [[ -z $lines ]] && ! has ss && ! has netstat; then
    local pk=iproute2; [[ $PM == dnf || $PM == yum ]] && pk=iproute
    need ss "$pk" && lines=$(listening_ports | grep -vE '127\.0\.0\.|\[::1\]|::1:')
  fi
  if [[ -z $lines ]]; then info "No listening ports found or could not list them."; return; fi
  echo "$lines" | awk '{printf "  %-5s %-28s %s\n", $1, $2, $3}' | sort -u
  local risky
  risky=$(echo "$lines" | grep -E ':(3306|5432|6379|27017|9200|11211|2375|5984|8086) ' )
  [[ -n $risky ]] && bad "Databases/services listening publicly (should usually be local only or firewalled):" && echo "$risky"

  if [[ $FIREWALL == ufw ]] && has docker && docker ps --format '{{.Ports}}' 2>/dev/null | grep -q '0.0.0.0:'; then
    warn "Docker publishes ports that BYPASS ufw. Bind them to 127.0.0.1 in docker-compose (e.g. \"127.0.0.1:6379:6379\")."
  fi
}

fw_allow_port() {
  local port=$1 proto=${2:-tcp}
  case $FIREWALL in
    ufw)       ufw allow "$port/$proto" ;;
    firewalld) firewall-cmd --permanent --add-port="$port/$proto" && firewall-cmd --reload ;;
    csf)       warn "CSF: add $port to TCP_IN in /etc/csf/csf.conf, then run: csf -r" ;;
    nftables)  nft add rule inet filter input "$proto" dport "$port" accept 2>/dev/null \
                 || warn "No 'inet filter input' chain. Add the rule in /etc/nftables.conf." ;;
    iptables)  iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT && warn "Save it to survive reboot (iptables-save)." ;;
    none)      bad "No active firewall." ;;
  esac
}
fw_close_port() {
  local port=$1 proto=${2:-tcp}
  case $FIREWALL in
    ufw)       ufw delete allow "$port/$proto" ;;
    firewalld) firewall-cmd --permanent --remove-port="$port/$proto" && firewall-cmd --reload ;;
    csf)       warn "CSF: remove $port from TCP_IN in /etc/csf/csf.conf, then run: csf -r" ;;
    iptables)  iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT ;;
    *)         warn "Remove the rule manually for $FIREWALL." ;;
  esac
}
fw_block_ip() {
  local ip=$1
  case $FIREWALL in
    ufw)       ufw insert 1 deny from "$ip" ;;
    firewalld) firewall-cmd --permanent --add-rich-rule="rule family=$( [[ $ip == *:* ]] && echo ipv6 || echo ipv4 ) source address=$ip drop" && firewall-cmd --reload ;;
    csf)       csf -d "$ip" "blocked by server-doctor" ;;
    nftables)  nft insert rule inet filter input ip saddr "$ip" drop 2>/dev/null || warn "Add the drop rule in /etc/nftables.conf." ;;
    iptables)  iptables -I INPUT -s "$ip" -j DROP ;;
    none)      bad "No active firewall to block with." ; return 1 ;;
  esac
}
fw_enable() {
  local sp; sp=$(ssh_port)
  info "Your SSH port is $sp. It will be allowed FIRST so you don't lock yourself out."
  if has ufw; then
    confirm "Enable ufw (allow SSH $sp, 80, 443)?" || return
    ufw allow "$sp/tcp"; ufw allow 80/tcp; ufw allow 443/tcp; ufw --force enable
  elif has firewall-cmd; then
    confirm "Start firewalld (allow SSH $sp, http, https)?" || return
    [[ $INIT == systemd ]] && systemctl enable --now firewalld
    firewall-cmd --permanent --add-port="$sp/tcp"; firewall-cmd --permanent --add-service=http --add-service=https
    firewall-cmd --reload
  else
    local pkg=ufw; [[ $PM == dnf || $PM == yum || $PM == zypper ]] && pkg=firewalld
    confirm "No firewall tool found. Install $pkg?" && pkg_install "$pkg" && detect_system && fw_enable
    return
  fi
  detect_system; ok "Firewall is now: $FIREWALL"
  [[ -n $PANEL && $PANEL != none ]] && warn "$PANEL needs extra ports (e.g. Plesk 8443/8447, cPanel 2083/2087). Allow them with option 2."
}

check_firewall() {
  fw_status
  fw_open_ports_check
  [[ $REPORT_MODE -eq 1 ]] && return
  echo
  echo "  1) Enable a firewall safely   2) Open a port   3) Close a port   4) Block an IP   0) Back"
  case $(ask "Choose: ") in
    1) fw_enable ;;
    2) local p pr; p=$(ask "Port number: "); pr=$(ask "Protocol tcp/udp [tcp]: ")
       [[ $p =~ ^[0-9]+$ ]] && confirm "Open $p/${pr:-tcp}?" && fw_allow_port "$p" "${pr:-tcp}" && ok "Opened." ;;
    3) local p pr; p=$(ask "Port number: "); pr=$(ask "Protocol tcp/udp [tcp]: ")
       [[ $p == "$(ssh_port)" ]] && bad "That is your SSH port! Closing it can lock you out." && return
       [[ $p =~ ^[0-9]+$ ]] && confirm "Close $p/${pr:-tcp}?" && fw_close_port "$p" "${pr:-tcp}" && ok "Closed." ;;
    4) local ip; ip=$(ask "IP to block: ")
       [[ $ip =~ ^[0-9a-fA-F.:/]+$ ]] && confirm "Block $ip?" && fw_block_ip "$ip" && ok "Blocked $ip." ;;
  esac
}

# =====================================================================
#  7. Login security (SSH attacks, fail2ban)
# =====================================================================
check_logins() {
  hdr "SSH login attacks (last ~24h)"
  local log; log=$(auth_log)
  local fails; fails=$(echo "$log" | grep -cE 'Failed password|Invalid user|authentication failure')
  if (( fails > 100 )); then warn "$fails failed login attempts."; else ok "$fails failed login attempts."; fi
  local top; top=$(echo "$log" | grep -E 'Failed password|Invalid user' | grep -oE 'from [0-9a-fA-F.:]+' \
                   | awk '{print $2}' | sort | uniq -c | sort -rn | head -10)
  [[ -n $top ]] && { info "Top attacking IPs:"; echo "$top"; }
  info "Last successful logins:"
  last -n 5 -a 2>/dev/null | head -6 || echo "$log" | grep 'Accepted' | tail -5

  hdr "SSH settings"
  local cfg; cfg=$(sshd -T 2>/dev/null)
  if [[ -n $cfg ]]; then
    grep -qE '^permitrootlogin yes' <<<"$cfg" && warn "Root can log in with a password. Safer: 'PermitRootLogin prohibit-password'."
    grep -qE '^passwordauthentication yes' <<<"$cfg" && warn "Password login is on. SSH keys are safer."
    grep -qE '^permitrootlogin (no|prohibit-password|without-password)' <<<"$cfg" && ok "Root password login is disabled."
  fi

  hdr "fail2ban"
  if has fail2ban-client; then
    fail2ban-client status 2>/dev/null || bad "fail2ban installed but not running."
  else
    warn "fail2ban is not installed (it auto-blocks attacking IPs)."
    [[ $PANEL == cPanel || $FIREWALL == csf ]] && info "CSF/LFD already does this job on your server."
  fi
  [[ $REPORT_MODE -eq 1 ]] && return

  if [[ -n $top ]] && confirm "Block the top attacking IPs (more than 20 attempts) in $FIREWALL?"; then
    local cnt ip
    while read -r cnt ip; do (( cnt > 20 )) && fw_block_ip "$ip" && ok "Blocked $ip ($cnt attempts)"; done <<<"$top"
  fi
  if ! has fail2ban-client && [[ $FIREWALL != csf ]] && confirm "Install fail2ban with SSH protection?"; then
    pkg_install fail2ban || { [[ $PM == dnf || $PM == yum ]] && pkg_install epel-release && pkg_install fail2ban; }
    if has fail2ban-client; then
      local action=iptables-multiport
      [[ $FIREWALL == ufw ]] && action=ufw
      [[ $FIREWALL == firewalld ]] && action=firewallcmd-rich-rules
      [[ $FIREWALL == nftables ]] && action=nftables-multiport
      cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = $action

[sshd]
enabled = true
port = $(ssh_port)
backend = $( [[ $INIT == systemd ]] && echo systemd || echo auto )
EOF
      case $INIT in systemd) systemctl enable --now fail2ban ;; openrc) rc-update add fail2ban default; rc-service fail2ban start ;; *) service fail2ban start ;; esac
      ok "fail2ban installed and protecting SSH (5 tries → 1 hour ban)."
    fi
  fi
}

# =====================================================================
#  8. Zombies
# =====================================================================
check_zombies() {
  hdr "Zombie processes"
  local z; z=$(ps -eo pid,ppid,stat,comm 2>/dev/null | awk '$3 ~ /Z/')
  if [[ -z $z ]]; then ok "No zombies."; return; fi
  warn "Zombies (harmless in small numbers):"; echo "$z"
  info "Their parents:"
  local pp; for pp in $(awk '{print $2}' <<<"$z" | sort -u); do ps -o pid=,args= -p "$pp" | cut -c1-120; done
  info "Parent is chromium/node in Docker? Add 'init: true' to that service in docker-compose.yml"
}

# =====================================================================
#  9. Suspicious processes
# =====================================================================
MINER_PORTS='3333|4444|5555|6666|7777|8888|9999|14444|14433|45700|45560|20580'
check_suspicious() {
  hdr "Suspicious process scan"
  local found=0 p pid exe reason
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    reason=""
    [[ $exe =~ ^(/tmp|/var/tmp|/dev/shm|/run/shm) ]] && reason="runs from a temp folder"
    [[ $exe == *"(deleted)"* && $exe != *memfd:* && $exe != /usr/* ]] && reason="its program file was deleted"
    [[ $exe =~ /\.[^/]+/ && ! $exe =~ ^/(usr|opt|snap|var/lib/docker|root/\.vscode-server|home/[^/]+/\.(vscode-server|nvm|npm|cargo|rustup|rbenv|pyenv|sdkman|asdf|rvm|deno|bun|pm2|local|volta|docker)) ]] && reason="runs from a hidden folder"
    if [[ -n $reason ]]; then
      found=1; bad "PID $pid: $reason"
      echo "      exe: $exe"
      echo "      cmd: $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-150)"
      confirm "Kill PID $pid now?" && kill -9 "$pid" && ok "Killed. Check menu 10 (cron) so it doesn't come back."
    fi
  done

  if [[ $PS_OK -eq 1 && -n $PM ]]; then
    info "Checking busy programs come from an installed package..."
    local cpu comm
    while read -r pid cpu comm; do
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
      [[ -e $exe ]] || continue   # container programs are not visible to the host package db
      [[ $exe =~ ^/(opt|usr/local|snap|home|var/lib/docker)/ ]] && { info "PID $pid ($comm): $exe (custom install location — check you know it)"; continue; }
      pkg_owner "$exe" >/dev/null || { warn "PID $pid ($comm, ${cpu}% CPU): $exe is NOT from any package."; found=1; }
    done < <(ps -eo pid=,%cpu=,comm= --sort=-%cpu | awk '$2>=5' | head -10)
  fi

  info "Checking connections on common crypto-miner ports..."
  local conns=""
  if has ss; then conns=$(ss -tnpH state established 2>/dev/null | awk '{print $4, $5}' | grep -E ":($MINER_PORTS)( |$)")
  elif has netstat; then conns=$(netstat -tnp 2>/dev/null | awk '/ESTABLISHED/{print $5, $7}' | grep -E ":($MINER_PORTS) ")
  fi
  [[ -n $conns ]] && { found=1; bad "Connections to common miner ports:"; echo "$conns"; }

  (( found == 0 )) && ok "No suspicious processes found."
}

# =====================================================================
#  10. Cron & startup
# =====================================================================
check_cron() {
  hdr "Cron jobs and startup entries"
  local pat='curl |wget |base64|/tmp/|/dev/shm|\| *(ba)?sh|python[0-9]* -c|nc -|xmrig|minerd'
  local normal='/tmp/\.(X11|ICE|font|XIM|Test)-unix'
  local hits; hits=$(grep -rIHnE "$pat" /etc/crontab /etc/cron.* /var/spool/cron /etc/periodic /etc/rc.local 2>/dev/null | grep -vE ':\s*#' | grep -vE "$normal")
  if [[ -n $hits ]]; then warn "Cron lines worth checking (download or run scripts — may be normal):"; echo "$hits" | cut -c1-200
  else ok "No suspicious cron lines."; fi

  local upat='curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d|/dev/shm/|xmrig|minerd|ExecStart=/tmp/|ExecStart=/var/tmp/'
  local units; units=$(grep -rIHE "$upat" /etc/systemd/system /etc/init.d /etc/local.d 2>/dev/null | grep -vE "$normal" | cut -d: -f1 | sort -u | head | xargs)
  [[ -n $units ]] && warn "Startup files worth checking: $units"
  local keys; keys=$(find /root/.ssh /home/*/.ssh -name authorized_keys -mtime -7 2>/dev/null)
  [[ -n $keys ]] && warn "SSH keys changed in the last 7 days (was it you?): $keys"
  local ld; ld=$(cat /etc/ld.so.preload 2>/dev/null)
  [[ -n $ld ]] && bad "/etc/ld.so.preload is set ($ld) — rootkits use this. Check it!"
  [[ -z $units && -z $keys && -z $ld ]] && ok "No suspicious startup entries, new SSH keys or preload tricks."
}

# =====================================================================
#  11. Malware scanners
# =====================================================================
verify_npm_file() {  # compare a node_modules file with the official npm package
  local file=$1
  [[ -f $file ]] || { warn "Missing: $file"; return; }
  local tail=${file##*/node_modules/} pkg rel
  if [[ $tail == @* ]]; then pkg=$(cut -d/ -f1-2 <<<"$tail"); rel=$(cut -d/ -f3- <<<"$tail")
  else pkg=${tail%%/*}; rel=${tail#*/}; fi
  local pdir=${file%/"$rel"}
  local ver; ver=$(grep -m1 -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$pdir/package.json" 2>/dev/null | cut -d'"' -f4)
  [[ -z $ver ]] && { warn "Can't read version for $pkg"; return; }
  local tmp; tmp=$(mktemp -d)
  local url="https://registry.npmjs.org/$pkg/-/${pkg##*/}-$ver.tgz"
  if ! curl -fsSL "$url" -o "$tmp/p.tgz" 2>/dev/null || ! tar xzf "$tmp/p.tgz" -C "$tmp" "package/$rel" 2>/dev/null; then
    warn "Could not download $pkg@$ver from npm to compare."; rm -rf "$tmp"; return
  fi
  local a b; a=$(sha256sum "$file" | cut -c1-64); b=$(sha256sum "$tmp/package/$rel" | cut -c1-64)
  if [[ $a == "$b" ]]; then ok "$pkg@$ver/$rel is IDENTICAL to official npm → false alarm."
  else bad "$pkg@$ver/$rel is DIFFERENT from official npm → file was changed! Check: $file"; fi
  rm -rf "$tmp"
}

check_malware() {
  hdr "Malware scanners"
  local any=0
  if has imunify360-agent; then
    any=1; info "Imunify360 results:"
    local out; out=$(imunify360-agent malware malicious list 2>/dev/null)
    local files; files=$(grep -oE '/[^ ]+' <<<"$out" | grep -vE '^/(var/imunify360)' | sort -u)
    if [[ -z $files ]]; then ok "Imunify: no malicious files."
    else
      warn "Imunify flagged:"; echo "$files" | sed 's/^/   - /'
      local f; while read -r f; do [[ $f == */node_modules/* ]] && verify_npm_file "$f"; done <<<"$files"
      info "False alarm? Ignore it in your panel: Imunify360 → Malware Scanner → Files."
    fi
  fi
  if has maldet; then any=1; info "Linux Malware Detect — last report:"; maldet --report list 2>/dev/null | tail -5; fi
  if has rkhunter; then any=1; info "rkhunter warnings (last run):"; grep -i warning /var/log/rkhunter.log 2>/dev/null | tail -10 || echo "  none"; fi
  if has clamscan; then any=1; ok "ClamAV is installed (use 'Run a scan' to scan)."; fi
  (( any == 0 )) && warn "No malware scanner installed. Menu 12 → 'Run a scan' can install ClamAV for you."
}

run_scan() {
  local def=${WEBROOTS[0]:-/var/www}
  local path; path=$(ask "Folder to scan [$def]: "); path=${path:-$def}
  [[ -d $path ]] || { bad "Folder not found."; return; }
  if has imunify360-agent && confirm "Use Imunify360 (runs in background)?"; then
    imunify360-agent malware on-demand start --path "$path" && ok "Started. Check: imunify360-agent malware on-demand status"
    return
  fi
  if has maldet && confirm "Use Linux Malware Detect?"; then maldet -a "$path"; return; fi
  if ! has clamscan; then
    confirm "ClamAV is not installed. Install it?" || return
    case $PM in
      dnf|yum) pkg_install clamav clamav-update || { pkg_install epel-release && pkg_install clamav clamav-update; } ;;
      *) pkg_install clamav ;;
    esac
  fi
  has clamscan || return
  info "Updating virus signatures..."; freshclam --quiet 2>/dev/null || warn "freshclam failed (maybe already running as a service)."
  confirm "Scan $path now? (can take a while and use CPU)" || return
  local log; log="/root/clamscan-$(date +%F-%H%M).log"
  nice -n 19 clamscan -r -i --exclude-dir='node_modules|\.git|\.cache' "$path" | tee "$log"
  ok "Scan log saved: $log"
}

malware_menu() {
  check_malware
  [[ $REPORT_MODE -eq 1 ]] && return
  echo; echo "  1) Run a scan (Imunify / maldet / ClamAV)   2) Check a node_modules file vs npm   0) Back"
  case $(ask "Choose: ") in
    1) run_scan ;;
    2) verify_npm_file "$(ask 'Full path of the file: ')" ;;
  esac
}

# =====================================================================
#  12. Updates
# =====================================================================
check_updates() {
  hdr "System updates"
  local n=""
  case $PM in
    apt-get) apt-get update -qq 2>/dev/null; n=$(apt list --upgradable 2>/dev/null | grep -c upgradable) ;;
    dnf|yum) n=$($PM -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]') ;;
    zypper)  n=$(zypper -q lu 2>/dev/null | grep -c '^v ') ;;
    pacman)  has checkupdates && n=$(checkupdates 2>/dev/null | wc -l) ;;
    apk)     apk update -q; n=$(apk version -l '<' 2>/dev/null | tail -n +2 | wc -l) ;;
  esac
  if [[ -z $n ]]; then info "Could not check updates."
  elif (( n > 0 )); then warn "$n package updates available."
  else ok "System is up to date."; fi
  [[ -f /var/run/reboot-required ]] && warn "A reboot is required to finish earlier updates."
  [[ $REPORT_MODE -eq 1 || -z $n || $n -eq 0 ]] && return
  confirm "Install all updates now? (take a backup/snapshot first)" || return
  case $PM in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get -y upgrade ;;
    dnf|yum) $PM -y upgrade ;; zypper) zypper -n update ;;
    pacman) pacman -Syu --noconfirm ;; apk) apk upgrade ;;
  esac
}

# =====================================================================
#  Full report
# =====================================================================
full_report() {
  local out; out="/root/server-report-$(date +%F-%H%M).txt"
  local raw; raw=$(mktemp)
  hdr "Running full read-only check → $out"
  REPORT_MODE=1
  {
    echo "Server report: $(hostname)  $(date)"
    show_system; check_cpu; check_procs; check_docker; check_disk; check_services
    check_firewall; check_logins; check_zombies; check_suspicious; check_cron
    check_malware; check_updates
    if has vmstat; then hdr "vmstat 1 5 (for your provider)"; vmstat 1 5; fi
  } 2>&1 | tee "$raw"
  REPORT_MODE=0
  sed 's/\x1b\[[0-9;]*m//g' "$raw" > "$out"; rm -f "$raw"
  echo; ok "Report saved: $out"
}

# =====================================================================
#  Menu
# =====================================================================
detect_system
[[ -z $PM ]] && warn "No known package manager detected (apt-get/dnf/yum/zypper/pacman/apk/xbps-install). Install/update/malware-scanner features that need to install a package will not work — install tools manually."
[[ ${1:-} == "--report" ]] && { full_report; exit 0; }

while true; do
  echo
  echo "${W}${B}======= Server Doctor — $(hostname) =======${N}"
  echo "  ${OS_NAME} | pkg: ${PM:-?} | init: $INIT | firewall: $FIREWALL | panel: $PANEL"
  echo
  echo "  1) System info"
  echo "  2) CPU & memory         (is it my apps, the disk or the host?)"
  echo "  3) Top processes"
  echo "  4) Docker               (stats, logs, restart)"
  echo "  5) Disk                 (space, speed, cleanup)"
  echo "  6) Services             (failed, restart, logs)"
  echo "  7) Firewall             (ufw/firewalld/csf/nft/iptables)"
  echo "  8) Login security       (SSH attacks, fail2ban)"
  echo "  9) Zombie processes"
  echo " 10) Suspicious processes (miners, strange programs)"
  echo " 11) Cron & startup check"
  echo " 12) Malware              (results, scan, npm false-alarm check)"
  echo " 13) System updates"
  echo " 14) FULL REPORT          (everything, read-only, saved to a file)"
  echo "  0) Exit"
  case $(ask "Choose: ") in
    1) show_system ;;     2) check_cpu ;;       3) check_procs ;;
    4) check_docker ;;    5) check_disk ;;      6) check_services ;;
    7) check_firewall ;;  8) check_logins ;;    9) check_zombies ;;
    10) check_suspicious ;; 11) check_cron ;;   12) malware_menu ;;
    13) check_updates ;;  14) full_report ;;    0) exit 0 ;;
    *) warn "Invalid choice." ;;
  esac
  pause
done