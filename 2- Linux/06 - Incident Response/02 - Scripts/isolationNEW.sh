#!/usr/bin/env bash
# isolate.sh - block all traffic except inbound SSH (and optionally the Wazuh agent).
# Saves the current rules first so they can be restored later.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root" >&2
  exit 1
fi

BACKUP_DIR=/backups/firewall
WAZUH_PORTS="1514,1515"   # agent -> manager ports; set to "" to disable

# Refuse to run twice: a second run would overwrite the clean backup
# with an already-isolated ruleset and stack duplicate rules.
for ipt in iptables ip6tables; do
  if $ipt -n -L ISOLATE-IN >/dev/null 2>&1; then
    echo "Isolation chains already exist ($ipt). Run clean.sh first." >&2
    exit 1
  fi
done

# Get the SSH port(s) from sshd's *effective* config. This handles
# Include files, commented defaults, and multiple Port lines.
PORTS="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | paste -sd, - || true)"
PORTS="${PORTS:-22}"
if ! [[ "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "Could not determine SSH port (got '$PORTS'). Aborting so you don't lock yourself out." >&2
  exit 1
fi
echo "Allowing SSH on port(s): $PORTS"

# Back up current rules
mkdir -p "$BACKUP_DIR"
iptables-save  > "$BACKUP_DIR/iptables_isolate.rules.v4"
ip6tables-save > "$BACKUP_DIR/iptables_isolate.rules.v6"
echo "Backed up rules to $BACKUP_DIR"

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
