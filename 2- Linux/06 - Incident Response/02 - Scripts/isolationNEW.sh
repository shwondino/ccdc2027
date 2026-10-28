#!/usr/bin/env bash
# isolate.sh - block all traffic except inbound SSH, the Wazuh agent, and
# (optionally) the service ports the scoring engine checks.
# Saves the current rules first so they can be restored with clean.sh.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root" >&2
  exit 1
fi

# ======================= SETTINGS =======================
BACKUP_DIR=/backups/firewall

# Wazuh agent -> manager ports. Set to "" to disable.
WAZUH_PORTS="1514,1515"

# Service-check ports to keep open for the scoring engine (SLA).
# Comma-separated; ranges allowed as start:end. Max 15 entries per list
# (a range counts as 2). Leave "" to keep nothing open.

#   Examples: web "80,443"   mail "25,110,143"   DNS TCP "53"
SERVICE_TCP_PORTS=""
SERVICE_UDP_PORTS=""        # e.g. DNS "53", NTP "123"

# Allow ping (ICMP echo) in. Many scorers check ICMP. true/false.
ALLOW_PING=false

# Optional: only let these sources reach the service ports and ping.
# Comma-separated IPs or CIDRs. If BOTH are "", service ports are open to
# anyone. If either is set, each family only allows its own list (an empty
# list for one family means no service access over that family).
SCORER_SRC_V4=""            # e.g. "10.0.0.5" or "10.0.0.0/24,10.1.1.5"
SCORER_SRC_V6=""
# ========================================================

# Refuse to run twice: a second run would overwrite the clean backup
# with an already-isolated ruleset and stack duplicate rules.
for ipt in iptables ip6tables; do
  if $ipt -n -L ISOLATE-IN >/dev/null 2>&1; then
    echo "Isolation chains already exist ($ipt). Run clean.sh first." >&2
    exit 1
  fi
done

# Validate the settings before touching anything.
PORT_LIST_RE='^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$'
for name in WAZUH_PORTS SERVICE_TCP_PORTS SERVICE_UDP_PORTS; do
  val="${!name}"
  if [ -n "$val" ] && ! [[ "$val" =~ $PORT_LIST_RE ]]; then
    echo "Invalid $name: '$val' (use e.g. 80,443 or 8000:8100)" >&2
    exit 1
  fi
done
for name in SCORER_SRC_V4 SCORER_SRC_V6; do
  val="${!name}"
  if [ -n "$val" ] && ! [[ "$val" =~ ^[0-9A-Fa-f.:/,]+$ ]]; then
    echo "Invalid $name: '$val'" >&2
    exit 1
  fi
done
if [ "$ALLOW_PING" != true ] && [ "$ALLOW_PING" != false ]; then
  echo "ALLOW_PING must be true or false" >&2
  exit 1
fi

# Get the SSH port(s) from sshd's *effective* config. This handles
# Include files, commented defaults, and multiple Port lines.
PORTS="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | paste -sd, - || true)"
PORTS="${PORTS:-22}"
if ! [[ "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "Could not determine SSH port (got '$PORTS'). Aborting so you don't lock yourself out." >&2
  exit 1
fi
echo "Allowing SSH on port(s): $PORTS"
[ -n "$SERVICE_TCP_PORTS" ] && echo "Keeping service TCP port(s) open: $SERVICE_TCP_PORTS"
[ -n "$SERVICE_UDP_PORTS" ] && echo "Keeping service UDP port(s) open: $SERVICE_UDP_PORTS"
[ "$ALLOW_PING" = true ]    && echo "Allowing inbound ping"
if [ -n "$SCORER_SRC_V4$SCORER_SRC_V6" ]; then
  echo "Service access limited to: v4='${SCORER_SRC_V4:-none}' v6='${SCORER_SRC_V6:-none}'"
fi

# Back up current rules
mkdir -p "$BACKUP_DIR"
iptables-save  > "$BACKUP_DIR/iptables_isolate.rules.v4"
ip6tables-save > "$BACKUP_DIR/iptables_isolate.rules.v6"
echo "Backed up rules to $BACKUP_DIR"

# Service-check ports and ping, for the scoring engine.
service_rules() {
  local ipt="$1" src="" in_src="" out_dst=""

  if [ -n "$SCORER_SRC_V4$SCORER_SRC_V6" ]; then
    if [ "$ipt" = "iptables" ]; then src="$SCORER_SRC_V4"; else src="$SCORER_SRC_V6"; fi
    # Restriction is on, but no sources listed for this family: allow nothing.
    if [ -z "$src" ]; then return 0; fi
    in_src="-s $src"
    out_dst="-d $src"
  fi

  # Inbound requests to the service, and only replies going back out
  # (ESTABLISHED), so the service can't be used to start new outbound connections.
  if [ -n "$SERVICE_TCP_PORTS" ]; then
    $ipt -A ISOLATE-IN  -p tcp $in_src  -m multiport --dports "$SERVICE_TCP_PORTS" -j ACCEPT
    $ipt -A ISOLATE-OUT -p tcp $out_dst -m multiport --sports "$SERVICE_TCP_PORTS" \
         -m conntrack --ctstate ESTABLISHED -j ACCEPT
  fi
  if [ -n "$SERVICE_UDP_PORTS" ]; then
    $ipt -A ISOLATE-IN  -p udp $in_src  -m multiport --dports "$SERVICE_UDP_PORTS" -j ACCEPT
    $ipt -A ISOLATE-OUT -p udp $out_dst -m multiport --sports "$SERVICE_UDP_PORTS" \
         -m conntrack --ctstate ESTABLISHED -j ACCEPT
  fi

  if [ "$ALLOW_PING" = true ]; then
    if [ "$ipt" = "iptables" ]; then
      $ipt -A ISOLATE-IN  -p icmp $in_src  --icmp-type echo-request -j ACCEPT
      $ipt -A ISOLATE-OUT -p icmp $out_dst --icmp-type echo-reply   -j ACCEPT
    else
      $ipt -A ISOLATE-IN  -p ipv6-icmp $in_src  --icmpv6-type echo-request -j ACCEPT
      $ipt -A ISOLATE-OUT -p ipv6-icmp $out_dst --icmpv6-type echo-reply   -j ACCEPT
    fi
  fi
}

build_chains() {
  local ipt="$1"

  $ipt -N ISOLATE-IN
  $ipt -N ISOLATE-OUT
  $ipt -N ISOLATE-FWD

  # Loopback (many local services break without it)
  $ipt -A ISOLATE-IN  -i lo -j ACCEPT
  $ipt -A ISOLATE-OUT -o lo -j ACCEPT

  # IPv6 needs neighbor discovery to reach anything at all, SSH included
  if [ "$ipt" = "ip6tables" ]; then
    for t in 133 134 135 136; do
      $ipt -A ISOLATE-IN  -p ipv6-icmp --icmpv6-type "$t" -j ACCEPT
      $ipt -A ISOLATE-OUT -p ipv6-icmp --icmpv6-type "$t" -j ACCEPT
    done
  fi

  # Inbound SSH and its replies
  $ipt -A ISOLATE-IN  -p tcp -m multiport --dports "$PORTS" -j ACCEPT
  $ipt -A ISOLATE-OUT -p tcp -m multiport --sports "$PORTS" -j ACCEPT

  # Wazuh agent: outbound to manager, plus the manager's replies coming back in
  if [ -n "$WAZUH_PORTS" ]; then
    $ipt -A ISOLATE-OUT -p tcp -m multiport --dports "$WAZUH_PORTS" -j ACCEPT
    $ipt -A ISOLATE-IN  -p tcp -m multiport --sports "$WAZUH_PORTS" \
         -m conntrack --ctstate ESTABLISHED -j ACCEPT
  fi

  # Scoring engine service checks
  service_rules "$ipt"

  # Log (rate-limited) and drop everything else
  $ipt -A ISOLATE-IN  -m limit --limit 5/min -j LOG --log-prefix "ISOLATE-IN DROP: "
  $ipt -A ISOLATE-IN  -j DROP
  $ipt -A ISOLATE-OUT -m limit --limit 5/min -j LOG --log-prefix "ISOLATE-OUT DROP: "
  $ipt -A ISOLATE-OUT -j DROP
  $ipt -A ISOLATE-FWD -j DROP
}

hook_chains() {
  local ipt="$1"
  $ipt -I INPUT   1 -j ISOLATE-IN
  $ipt -I OUTPUT  1 -j ISOLATE-OUT
  $ipt -I FORWARD 1 -j ISOLATE-FWD
}

# Build everything first; only hook in once all chains exist,
# so a failure partway through can't leave you with DROP and no SSH rule.
build_chains iptables
build_chains ip6tables
hook_chains iptables
hook_chains ip6tables

echo "Host isolated. Run clean.sh to undo."
