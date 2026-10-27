#! /bin/bash

#********************************
# Firewall change monitor
# Companion to isolate.sh
#********************************
#
# Logs every firewall change two ways:
#   1. auditd  - the kernel's own NETFILTER_CFG records, plus who ran iptables/nft.
#                This is the ground truth: it still works if the iptables
#                binaries have been swapped out.
#   2. watcher - a service that streams `nft monitor` events and diffs the full
#                ruleset (legacy AND nft backends) every few seconds, keeping a
#                copy of every version.
#
# Changes also pop a banner onto the terminals of the users you pick at install
# (default: whoever ran sudo), so you see them live without tailing anything.
#
# Usage:  sudo ./fwmon.sh            install (safe to re-run, e.g. to change alert users)
#         sudo ./fwmon.sh --watch    run the watcher in the foreground
#         sudo ./fwmon.sh --remove   uninstall (logs and history are kept)
#
# View:   journalctl -t fwmon -f            or  tail -f /var/log/fwmon.log
#         ausearch -k fw_change -i          who ran iptables/nft, or changed legacy tables
#         ausearch -m NETFILTER_CFG -i      every table change, straight from the kernel
#         ausearch -k fw_persist -i         edits to saved rule files (survive reboot)
#         ausearch -k fw_tamper -i          edits to auditd config or this monitor
#         ls /var/lib/fwmon/history/        full copy of every ruleset version

# Check if the script is run as root.
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

INTERVAL="${FWMON_INTERVAL:-5}"                 # Seconds between ruleset diffs
LOGFILE="${FWMON_LOG:-/var/log/fwmon.log}"
STATE_DIR="${FWMON_STATE:-/var/lib/fwmon}"
INSTALL_PATH="/usr/local/sbin/fwmon.sh"
UNIT="/etc/systemd/system/fwmon.service"
AUDIT_RULES="/etc/audit/rules.d/fwmon.rules"
ALERT_USERS="${FWMON_ALERT_USERS:-}"            # Comma list of users, or "all" for wall
DEV_DIR="${FWMON_DEV:-/dev}"

# authpriv lands in auth.log / secure and the journal, which Wazuh already reads
log() {
    logger -t fwmon -p authpriv.warning -- "$*" 2>/dev/null
    echo "$(date '+%F %T') $*" >> "$LOGFILE"
}

# Drop control characters. Rule comments are attacker-controlled text, and
# escape sequences in them could otherwise mess with your terminal.
sanitize() {
    tr -cd '[:print:]\n'
}

# alert "<title>" "<body>" - banner on every terminal the alert users have open
alert() {
    local title="$1" body="$2" u tty users
    if [ "$ALERT_USERS" = "all" ]; then
        # wall shows to everyone logged in (root ignores mesg n), plain text only
        printf '[fwmon] %s\n%s\n  details: sudo journalctl -t fwmon -n 50\n' "$title" "$body" | wall 2>/dev/null
        return
    fi
    IFS=', ' read -ra users <<< "$ALERT_USERS"
    for u in "${users[@]}"; do
        [ -z "$u" ] && continue
        while read -r tty; do
            [ -w "$DEV_DIR/$tty" ] || continue
            printf '\n\a\033[1;97;41m [fwmon] %s \033[0m\n%s\n\033[2m  details: sudo journalctl -t fwmon -n 50\033[0m\n' \
                "$title" "$body" >> "$DEV_DIR/$tty" 2>/dev/null
        done < <(who 2>/dev/null | awk -v u="$u" '$1 == u {print $2}')
    done
}

#--------------------------------
# Ruleset snapshot
#--------------------------------
# Legacy and nft tables are both live in the kernel at once, and hiding rules in
# whichever backend you aren't looking at is a classic trick, so dump both.
snapshot_raw() {
    local found=0 cmd
    for cmd in iptables-legacy-save ip6tables-legacy-save iptables-nft-save ip6tables-nft-save; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "### $cmd"
            "$cmd" 2>/dev/null
            found=1
        fi
    done
    if [ "$found" -eq 0 ]; then
        for cmd in iptables-save ip6tables-save; do
            if command -v "$cmd" >/dev/null 2>&1; then
                echo "### $cmd"
                "$cmd" 2>/dev/null
            fi
        done
    fi
    if command -v nft >/dev/null 2>&1; then
        echo "### nft"
        nft list ruleset 2>/dev/null
    fi
}

# Strip timestamps and packet counters so only real rule changes show up
snapshot() {
    snapshot_raw | sed -E \
        -e '/^# (Generated|Completed)/d' \
        -e 's/\[[0-9]+:[0-9]+\]/[0:0]/g' \
        -e 's/counter packets [0-9]+ bytes [0-9]+/counter/g'
}

#--------------------------------
# Watcher (what the service runs)
#--------------------------------
watch_loop() {
    local stamp mon_pid="" changes total body
    : "${ALERT_USERS:=${SUDO_USER:-root}}"
    mkdir -p "$STATE_DIR/history"
    chmod 700 "$STATE_DIR"

    snapshot > "$STATE_DIR/baseline"
    stamp="$(date +%Y%m%d-%H%M%S)"
    cp "$STATE_DIR/baseline" "$STATE_DIR/history/$stamp-start.rules"
    log "watcher started (pid $$), baseline saved to $STATE_DIR/history/$stamp-start.rules"
    # A start you didn't cause means systemd restarted it after someone killed it
    alert "firewall monitor started at $(date +%T)" "  alerting: $ALERT_USERS"

    # Real-time events for anything going through nf_tables
    # (iptables-nft, nft, firewalld and ufw on modern distros)
    if command -v nft >/dev/null 2>&1; then
        ( nft monitor ruleset 2>/dev/null | while IFS= read -r line; do log "event: $line"; done ) &
        mon_pid=$!
    fi

    # Logged on stop, so someone killing the monitor leaves a trace
    trap 'trap - TERM INT; log "watcher stopped (pid $$)"; alert "FIREWALL MONITOR STOPPED at $(date +%T)" "  if this was not you, check: sudo ausearch -k fw_tamper -i"; [ -n "$mon_pid" ] && kill 0; exit 0' TERM INT

    while true; do
        sleep "$INTERVAL"
        snapshot > "$STATE_DIR/current"
        if ! cmp -s "$STATE_DIR/baseline" "$STATE_DIR/current"; then
            stamp="$(date +%Y%m%d-%H%M%S)"
            cp "$STATE_DIR/current" "$STATE_DIR/history/$stamp.rules"
            log "RULESET CHANGED - full copy in $STATE_DIR/history/$stamp.rules"
            # -U0 = changed lines only; skip the two header lines and the @@ hunk markers
            changes="$(diff -U0 "$STATE_DIR/baseline" "$STATE_DIR/current" | tail -n +3 | grep -E '^[+-]' | sanitize)"
            total="$(printf '%s\n' "$changes" | grep -c .)"
            printf '%s\n' "$changes" | head -n 50 | while IFS= read -r line; do log "diff: $line"; done

            body="$(printf '%s\n' "$changes" | head -n 8 | sed 's/^/  /')"
            (( total > 8 )) && body+=$'\n'"  ... $(( total - 8 )) more"
            alert "FIREWALL CHANGED at $(date +%T) - $total line(s)" "$body"
            mv "$STATE_DIR/current" "$STATE_DIR/baseline"
        fi
    done
}

#--------------------------------
# auditd rules
#--------------------------------
install_audit() {
    local arch=b64 bins=() b real f
    if ! command -v auditctl >/dev/null 2>&1; then
        echo "[!] auditd not installed - skipping kernel-level logging"
        echo "    (apt install auditd  /  dnf install audit, then re-run)"
        return
    fi
    [ "$(getconf LONG_BIT)" = "32" ] && arch=b32

    systemctl enable --now auditd >/dev/null 2>&1 || service auditd start >/dev/null 2>&1
    auditctl -e 1 >/dev/null 2>&1

    if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
        echo "[!] audit rules are LOCKED (immutable, -e 2). New rules can't load until reboot."
        echo "    If you didn't set that, someone else did: check /etc/audit/rules.d/"
        return
    fi

    # Resolve real binaries (iptables is usually a symlink to xtables-*-multi)
    for b in iptables ip6tables iptables-legacy ip6tables-legacy iptables-nft ip6tables-nft \
             iptables-restore ip6tables-restore nft; do
        command -v "$b" >/dev/null 2>&1 || continue
        real="$(readlink -f "$(command -v "$b")")"
        [[ " ${bins[*]} " == *" $real "* ]] || bins+=("$real")
    done

    {
        echo "## fwmon - firewall change auditing (generated $(date '+%F %T'))"
        echo
        echo "## Who ran a firewall tool. auid filter skips daemons (including the fwmon"
        echo "## watcher polling every few seconds) but keeps anyone who logged in, root included."
        for real in "${bins[@]}"; do
            echo "-a always,exit -F path=$real -F perm=x -F auid!=4294967295 -k fw_change"
        done
        echo
        echo "## Legacy table writes from ANY program, even a custom binary (IPT/IP6T_SO_SET_REPLACE)"
        echo "-a always,exit -F arch=$arch -S setsockopt -F a1=0 -F a2=64 -k fw_change"
        echo "-a always,exit -F arch=$arch -S setsockopt -F a1=41 -F a2=64 -k fw_change"
        echo
        echo "## Saved rule files - edits here persist through a reboot"
        for f in /etc/iptables /etc/sysconfig/iptables /etc/sysconfig/ip6tables \
                 /etc/nftables.conf /etc/ufw /etc/firewalld; do
            [ -e "$f" ] && echo "-w $f -p wa -k fw_persist"
        done
        echo
        echo "## Tampering with auditing or this monitor"
        echo "-w /etc/audit/ -p wa -k fw_tamper"
        echo "-w $INSTALL_PATH -p wa -k fw_tamper"
        echo "-w $UNIT -p wa -k fw_tamper"
    } > "$AUDIT_RULES"

    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1
    else
        auditctl -R "$AUDIT_RULES" >/dev/null 2>&1
    fi

    echo "[+] auditd: $(auditctl -l 2>/dev/null | grep -c 'key=fw_') rules loaded ($AUDIT_RULES)"
}

#--------------------------------
# Watcher service
#--------------------------------
install_watcher() {
    if [ "$(readlink -f "$0")" != "$INSTALL_PATH" ]; then
        install -m 700 "$(readlink -f "$0")" "$INSTALL_PATH"
    fi
    touch "$LOGFILE"
    chmod 600 "$LOGFILE"

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        cat > "$UNIT" <<EOF
[Unit]
Description=Firewall change monitor (fwmon)
After=network.target auditd.service

[Service]
Environment=FWMON_ALERT_USERS=$ALERT_USERS
ExecStart=$INSTALL_PATH --watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fwmon >/dev/null 2>&1
        systemctl restart fwmon
        if systemctl is-active --quiet fwmon; then
            echo "[+] watcher: fwmon.service running (diff every ${INTERVAL}s)"
        else
            echo "[!] watcher: fwmon.service failed to start - check: journalctl -u fwmon"
        fi
    else
        pkill -f "$INSTALL_PATH --watch" 2>/dev/null
        FWMON_ALERT_USERS="$ALERT_USERS" nohup "$INSTALL_PATH" --watch >/dev/null 2>&1 &
        echo "[!] watcher: no systemd, started with nohup (won't survive a reboot)"
    fi
}

#--------------------------------
# Who gets terminal alerts
#--------------------------------
prompt_alert_users() {
    local def="${SUDO_USER:-root}" input="" u list valid=""
    [ -n "$ALERT_USERS" ] && return              # already set via FWMON_ALERT_USERS
    if [ -t 0 ]; then
        echo "Users to alert on their terminals when the firewall changes (comma/space separated)."
        echo "Type 'all' to broadcast to everyone logged in - that includes the red team."
        read -rp "[$def] > " input
    fi
    input="${input:-$def}"
    if [ "$input" = "all" ]; then
        ALERT_USERS="all"
        return
    fi
    IFS=', ' read -ra list <<< "$input"
    for u in "${list[@]}"; do
        [ -z "$u" ] && continue
        if id -u "$u" >/dev/null 2>&1; then
            valid+="${valid:+,}$u"
        else
            echo "Skipping unknown user: $u"
        fi
    done
    ALERT_USERS="${valid:-$def}"
}

#--------------------------------
# Uninstall
#--------------------------------
remove() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now fwmon >/dev/null 2>&1
        rm -f "$UNIT"
        systemctl daemon-reload 2>/dev/null
    fi
    pkill -f "$INSTALL_PATH --watch" 2>/dev/null
    rm -f "$INSTALL_PATH"
    if [ -f "$AUDIT_RULES" ]; then
        rm -f "$AUDIT_RULES"
        if command -v augenrules >/dev/null 2>&1; then
            augenrules --load >/dev/null 2>&1
        else
            echo "[!] audit rule file removed; loaded rules stay until reboot or auditctl -D"
        fi
    fi
    echo "Removed. Logs kept in $LOGFILE and $STATE_DIR"
}

case "$1" in
    --watch)
        watch_loop
        ;;
    --remove)
        remove
        ;;
    ""|--install)
        prompt_alert_users
        install_audit
        install_watcher
        echo "[+] alerts: terminals of $ALERT_USERS (a 'monitor started' banner should appear now)"
        echo
        echo "View changes:"
        echo "  journalctl -t fwmon -f        (or tail -f $LOGFILE)"
        echo "  ausearch -k fw_change -i      who ran iptables/nft, legacy table writes"
        echo "  ausearch -m NETFILTER_CFG -i  every table change, from the kernel"
        echo "  ls $STATE_DIR/history/        every ruleset version"
        ;;
    *)
        echo "Usage: $0 [--install | --watch | --remove]"
        exit 1
        ;;
esac
