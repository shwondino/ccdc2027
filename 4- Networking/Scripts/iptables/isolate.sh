#! /bin/bash

#********************************
# Written by a sad Matthew Harper...
# Interactive + stateful version
#********************************
#
# Isolates the host: only SSH (plus any ports you add) is reachable, optionally
# only from the source IPs you specify. Outbound is limited to replies on those
# allowed connections; the host can't start any new outbound connections.
#
# Undo:  iptables -D INPUT -j ISOLATE-IN; iptables -D OUTPUT -j ISOLATE-OUT; iptables -D FORWARD -j ISOLATE-FWD
#        (same with ip6tables), or iptables-restore the backup in /backups/firewall

# Check if the script is run as root.
# $EUID is an env variable that contains the user's UID
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

MARK=0x8000                  # Conntrack mark bit for connections this script approved
BACKUP_DIR="/backups/firewall"

HAVE_V6=0
command -v ip6tables >/dev/null 2>&1 && HAVE_V6=1

#--------------------------------
# Determine the port SSH is using
#--------------------------------
# sshd -T prints the effective config (follows sshd_config.d/ includes, ignores comments)
SSH_PORT="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')"
if [ -z "$SSH_PORT" ]; then
    SSH_PORT="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
fi
SSH_PORT="${SSH_PORT:-22}"

#--------------------------------
# Prompts
#--------------------------------
echo "Detected SSH port: $SSH_PORT"
echo
echo "Allowed source IP(s)/CIDR(s), comma or space separated."
echo "Press Enter for any (0.0.0.0/0 and ::/0)."
read -rp "> " IP_INPUT
echo
echo "Additional inbound port(s) to allow, comma or space separated."
echo "Format: port[/tcp|/udp] or start:end ranges, e.g. 80,443,53/udp,8000:8080"
echo "Press Enter for SSH only."
read -rp "> " PORT_INPUT

#--------------------------------
# Address parsing
#--------------------------------
# Mask an IPv4 address/CIDR down to its network, the same way iptables does,
# so the summary shows what is really allowed (192.168.4.196/21 -> 192.168.0.0/21).
# Prints nothing if an octet is out of range.
norm4() {
    local addr="${1%/*}" len=32 a b c d o n mask
    [[ "$1" == */* ]] && len="${1#*/}"
    IFS=. read -r a b c d <<< "$addr"
    for o in "$a" "$b" "$c" "$d"; do (( 10#$o <= 255 )) || return; done
    n=$(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
    mask=$(( len == 0 ? 0 : (0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF ))
    n=$(( n & mask ))
    echo "$(( n >> 24 & 255 )).$(( n >> 16 & 255 )).$(( n >> 8 & 255 )).$(( n & 255 ))/$len"
}

# parse_addrs "<input>" <v4 array name> <v6 array name>
# Splits a comma/space list into the two arrays, normalized and deduplicated.
parse_addrs() {
    local input="$1" ip net list
    local -n out4="$2" out6="$3"
    IFS=', ' read -ra list <<< "$input"
    for ip in "${list[@]}"; do
        [ -z "$ip" ] && continue
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]] && net="$(norm4 "$ip")" && [ -n "$net" ]; then
            [ "$net" != "$ip" ] && [ "$net" != "$ip/32" ] && echo "Note: $ip -> $net"
            [[ " ${out4[*]} " == *" $net "* ]] || out4+=("$net")
        elif [[ "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]; then
            [[ " ${out6[*]} " == *" $ip "* ]] || out6+=("$ip")
        else
            echo "Skipping invalid address: $ip"
        fi
    done
}

V4_SRCS=(); V6_SRCS=()
if [ -z "${IP_INPUT//[[:space:],]/}" ]; then
    V4_SRCS=("0.0.0.0/0"); V6_SRCS=("::/0")
else
    parse_addrs "$IP_INPUT" V4_SRCS V6_SRCS
fi

if [ ${#V4_SRCS[@]} -eq 0 ] && [ ${#V6_SRCS[@]} -eq 0 ]; then
    echo "No valid source addresses given, refusing to lock everything out."
    exit 1
fi

#--------------------------------
# Parse ports (SSH is always included)
#--------------------------------
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

PORT_RULES=("tcp $SSH_PORT")
IFS=', ' read -ra PORT_LIST <<< "$PORT_INPUT"
for entry in "${PORT_LIST[@]}"; do
    [ -z "$entry" ] && continue
    port="${entry%%/*}"
    proto="tcp"
    [[ "$entry" == */* ]] && proto="${entry##*/}"
    proto="${proto,,}"
    if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
        echo "Skipping $entry: protocol must be tcp or udp"
        continue
    fi
    lo="${port%%:*}"
    hi="${port##*:}"
    if ! valid_port "$lo" || ! valid_port "$hi" || (( 10#$lo > 10#$hi )); then
        echo "Skipping $entry: invalid port"
        continue
    fi
    rule="$proto $port"
    [[ " ${PORT_RULES[*]} " == *" $rule "* ]] && continue   # skip duplicates
    PORT_RULES+=("$rule")
done

#--------------------------------
# Confirm
#--------------------------------
PORT_SUMMARY=""
for rule in "${PORT_RULES[@]}"; do
    read -r proto port <<< "$rule"
    PORT_SUMMARY+="$port/$proto "
done

echo
echo "=========== Isolation summary ==========="
echo "IPv4 sources : ${V4_SRCS[*]:-none (all new IPv4 inbound blocked)}"
if [ "$HAVE_V6" -eq 1 ]; then
    echo "IPv6 sources : ${V6_SRCS[*]:-none (all new IPv6 inbound blocked)}"
else
    echo "IPv6         : ip6tables not found, skipping"
fi
if [ -n "$SSH_CLIENT" ]; then
    echo
    echo "NOTE: you appear to be connected from ${SSH_CLIENT%% *}."
    echo "      If that isn't covered above, this session will drop."
fi
echo "========================================="
read -rp "Apply these rules? [y/N] " CONFIRM
if ! [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted, nothing changed."
    exit 0
fi

#--------------------------------
# Backup firewall rules (timestamped so a re-run never overwrites the good copy)
#--------------------------------
mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
iptables-save > "$BACKUP_DIR/iptables_isolate_$STAMP.rulesv4"
[ "$HAVE_V6" -eq 1 ] && ip6tables-save > "$BACKUP_DIR/iptables_isolate_$STAMP.rulesv6"

#--------------------------------
# Build the chains for one address family
#   $1 = iptables | ip6tables, $2 = source array name
#--------------------------------
isolate() {
    local ipt="$1"
    local -n srcs="$2"
    local src rule proto port t

    # Re-run safety: unhook and flush our chains if they already exist
    while $ipt -D INPUT   -j ISOLATE-IN  2>/dev/null; do :; done
    while $ipt -D OUTPUT  -j ISOLATE-OUT 2>/dev/null; do :; done
    while $ipt -D FORWARD -j ISOLATE-FWD 2>/dev/null; do :; done
    for chain in ISOLATE-IN ISOLATE-OUT ISOLATE-FWD ISOLATE-ALLOW; do
        $ipt -N "$chain" 2>/dev/null || $ipt -F "$chain"
    done

    # ISOLATE-ALLOW: tag the connection as approved, then accept it.
    # Only tagged connections get the ESTABLISHED/RELATED fast path, so
    # anything open before isolation (e.g. a red team shell) gets cut.
    $ipt -A ISOLATE-ALLOW -j CONNMARK --set-xmark "$MARK/$MARK"
    $ipt -A ISOLATE-ALLOW -j ACCEPT

    ## Inbound
    $ipt -A ISOLATE-IN -i lo -j ACCEPT
    if [ "$ipt" = "ip6tables" ]; then
        # Neighbor discovery is IPv6's ARP; nothing works without it
        for t in router-solicitation router-advertisement neighbour-solicitation neighbour-advertisement; do
            $ipt -A ISOLATE-IN -p ipv6-icmp --icmpv6-type "$t" -j ACCEPT
        done
    fi
    $ipt -A ISOLATE-IN -m conntrack --ctstate INVALID -j DROP
    $ipt -A ISOLATE-IN -m connmark --mark "$MARK/$MARK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for src in "${srcs[@]}"; do
        for rule in "${PORT_RULES[@]}"; do
            read -r proto port <<< "$rule"
            $ipt -A ISOLATE-IN -s "$src" -p "$proto" --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED -j ISOLATE-ALLOW
        done
    done
    $ipt -A ISOLATE-IN -m limit --limit 5/min -j LOG --log-prefix "ISOLATE-IN DROP: "
    $ipt -A ISOLATE-IN -j DROP

    ## Outbound
    $ipt -A ISOLATE-OUT -o lo -j ACCEPT
    if [ "$ipt" = "ip6tables" ]; then
        for t in router-solicitation router-advertisement neighbour-solicitation neighbour-advertisement; do
            $ipt -A ISOLATE-OUT -p ipv6-icmp --icmpv6-type "$t" -j ACCEPT
        done
    fi
    $ipt -A ISOLATE-OUT -m conntrack --ctstate INVALID -j DROP
    $ipt -A ISOLATE-OUT -m connmark --mark "$MARK/$MARK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    # Replies from allowed services (tags sessions that predate isolation, like yours)
    for src in "${srcs[@]}"; do
        for rule in "${PORT_RULES[@]}"; do
            read -r proto port <<< "$rule"
            $ipt -A ISOLATE-OUT -d "$src" -p "$proto" --sport "$port" -m conntrack --ctstate ESTABLISHED -j ISOLATE-ALLOW
        done
    done
    $ipt -A ISOLATE-OUT -m limit --limit 5/min -j LOG --log-prefix "ISOLATE-OUT DROP: "
    $ipt -A ISOLATE-OUT -j DROP

    ## Forward
    $ipt -A ISOLATE-FWD -m limit --limit 5/min -j LOG --log-prefix "ISOLATE-FWD DROP: "
    $ipt -A ISOLATE-FWD -j DROP

    # Insert at head of table so we can just remove these, and not have to redo all other
    $ipt -I INPUT   -j ISOLATE-IN
    $ipt -I OUTPUT  -j ISOLATE-OUT
    $ipt -I FORWARD -j ISOLATE-FWD
}

isolate iptables V4_SRCS
[ "$HAVE_V6" -eq 1 ] && isolate ip6tables V6_SRCS

echo
echo "Isolation applied."
echo "Backups: $BACKUP_DIR/iptables_isolate_$STAMP.rulesv4 (and .rulesv6)"
echo "Undo:    iptables -D INPUT -j ISOLATE-IN; iptables -D OUTPUT -j ISOLATE-OUT; iptables -D FORWARD -j ISOLATE-FWD"
echo "         (repeat with ip6tables)"