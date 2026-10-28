#!/usr/bin/env bash
# clean.sh - remove isolation rules added by isolate.sh.
#   ./clean.sh            remove only the ISOLATE chains (keeps any other changes made since)
#   ./clean.sh --restore  replace the whole ruleset with the backup taken by isolate.sh

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root" >&2
  exit 1
fi

BACKUP_DIR=/backups/firewall

if [ "${1:-}" = "--restore" ]; then
  iptables-restore  < "$BACKUP_DIR/iptables_isolate.rules.v4" &&
  ip6tables-restore < "$BACKUP_DIR/iptables_isolate.rules.v6" &&
  echo "Restored full ruleset from $BACKUP_DIR" && exit 0
  echo "Restore failed" >&2
  exit 1
fi

for ipt in iptables ip6tables; do
  # Delete the jump rules by spec, not by position, and repeat in case of duplicates
  while $ipt -D INPUT   -j ISOLATE-IN  2>/dev/null; do :; done
  while $ipt -D OUTPUT  -j ISOLATE-OUT 2>/dev/null; do :; done
  while $ipt -D FORWARD -j ISOLATE-FWD 2>/dev/null; do :; done

  for chain in ISOLATE-IN ISOLATE-OUT ISOLATE-FWD; do
    $ipt -F "$chain" 2>/dev/null
    $ipt -X "$chain" 2>/dev/null
  done
done

echo "Isolation removed."
