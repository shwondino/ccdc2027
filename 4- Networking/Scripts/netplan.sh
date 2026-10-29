#!/bin/bash
# ---- settings ----
D=${NETPLAN_DIR:-/etc/netplan}
NEWF=$D/60-new-static-netplan.yaml
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
ARMED=0

# ---- y/n question ----
ask_yn() {
    local a
    while true; do
        read -rp "$1 (y/n): " a
        [[ $a == y || $a == n ]] && { [[ $a == y ]]; return; }
        echo "Enter y or n."
    done
}

# ---- validation: IP, CIDR 1-32, same subnet, not network/broadcast address ----
valid_ip() {
    local o x
    [[ $1 =~ $IP_RE ]] || return 1
    IFS=. read -ra o <<< "$1"
    for x in "${o[@]}"; do ((10#$x <= 255)) || return 1; done
}
valid_cidr() { [[ $1 =~ ^[0-9]{1,2}$ ]] && ((10#$1 >= 1 && 10#$1 <= 32)); }
ip2int() { local o; IFS=. read -ra o <<< "$1"; echo $(( (10#${o[0]} << 24) + (10#${o[1]} << 16) + (10#${o[2]} << 8) + 10#${o[3]} )); }
mask() { echo $(( (0xFFFFFFFF << (32 - 10#$1)) & 0xFFFFFFFF )); }
same_subnet() { local m; m=$(mask "$3"); (( ($(ip2int "$1") & m) == ($(ip2int "$2") & m) )); }
usable_host() {  # not the network or broadcast address (only matters below /31)
    local m n b i; m=$(mask "$2"); i=$(ip2int "$1"); n=$((i & m)); b=$((n | (~m & 0xFFFFFFFF)))
    ((10#$2 >= 31)) || ((i != n && i != b))
}

# ---- awk: reads and edits the "ethernets:" section of one netplan file ----
#   mode=info    prints "MATCH <dhcp> <defroute> <key>" for the chosen interface and
#                "OTHER <key> <defroute> <dhcp>" for every other block
#   mode=remove  prints the file without the chosen interface; blocks named in "fix" get their
#                addresses, routes, DNS and DHCP removed (the interface stays defined, with no IP)
AWK_PROG='
function indent(s,  t){ t=s; sub(/[^ ].*$/,"",t); return length(t) }
function out(s){ if (mode=="remove") print s }
function fixblock(  j,i,pind,keep,t){
  # keep the block but drop its addresses, routes, DNS and DHCP: only match/set-name survive
  print buf[0]; pind=-1; keep=0
  for (j=1;j<n;j++) {
    if (buf[j] ~ /^[ \t]*(#|$)/) continue
    i=indent(buf[j]); if (pind<0) pind=i
    if (i==pind) { t=buf[j]; sub(/^ */,"",t); sub(/:.*$/,"",t); keep=(t=="match" || t=="set-name") }
    if (keep) print buf[j]
  }
  if (pind<0) pind=cind+4
  printf "%*s%s\n", pind, "", "dhcp4: false"
}
function flush(  m,j,d){
  if (!n) return
  d = index(" " fix " ", " " key " ")
  m = (key==iface) || (setname==iface) || (mac!="" && macaddr!="" && tolower(macaddr)==tolower(mac))
  if (mode=="info") { if (m) print "MATCH " isdhcp " " isdef " " key; else print "OTHER " key " " isdef " " isdhcp }
  else if (!m) { if (d) fixblock(); else for (j=0;j<n;j++) print buf[j] }
  n=0
}
BEGIN { inet=0; cind=0; n=0; seen=0 }
{
  if (!inet) {
    out($0)
    if (!seen && $0 ~ /^[ ]*ethernets:[ ]*(#.*)?$/) { inet=1; seen=1; eind=indent($0) }
    next
  }
  if ($0 ~ /^[ \t]*$/ || $0 ~ /^[ ]*#/) { if (n) buf[n++]=$0; else out($0); next }
  i=indent($0)
  if (cind==0) { if (i>eind) cind=i; else { inet=0; out($0); next } }
  if (i==cind) {
    flush(); key=$0; sub(/^ */,"",key); sub(/:.*$/,"",key); gsub(/["\047]/,"",key)
    setname=""; macaddr=""; isdef=0; isdhcp=0; buf[n++]=$0; next
  }
  if (i<cind) { flush(); inet=0; out($0); next }
  buf[n++]=$0
  v=$0
  if (v ~ /set-name:/)   { sub(/^.*set-name:[ ]*/,"",v);   gsub(/["\047 \r]/,"",v); setname=v }
  if (v ~ /macaddress:/) { sub(/^.*macaddress:[ ]*/,"",v); gsub(/["\047 \r]/,"",v); macaddr=v }
  if ($0 ~ /dhcp4:[ ]*(true|yes)/) isdhcp=1
  if ($0 ~ /to:[ ]*(default|0\.0\.0\.0\/0)/ || $0 ~ /gateway4:/) isdef=1
}
END { flush(); if (!seen) exit 2 }'

# ---- runs the awk on a file ----
yaml() { awk -v mode="$1" -v iface="$IFACE" -v mac="$MAC" -v fix="$FIX" "$AWK_PROG" "$2"; }

# ---- writes the chosen interface's block (DHCP or static) ----
block_text() {  # block_text CIND STEP
    local c s; c=$(printf '%*s' "$1" ''); s=$(printf '%*s' "$2" '')
    echo "${c}${IFACE}:"
    if ((DHCP)); then echo "${c}${s}dhcp4: true"; return; fi
    echo "${c}${s}dhcp4: false"
    echo "${c}${s}addresses:";   echo "${c}${s}${s}- $ADDR"
    echo "${c}${s}nameservers:"; echo "${c}${s}${s}addresses:"; echo "${c}${s}${s}${s}- $DNS"
    [[ -n $FB ]]  && echo "${c}${s}${s}${s}- $FB"
    [[ -n $DOM ]] && { echo "${c}${s}${s}search:"; echo "${c}${s}${s}${s}- $DOM"; }
    echo "${c}${s}routes:";      echo "${c}${s}${s}- to: default"; echo "${c}${s}${s}  via: $GW"
}

# ---- works out every file change in $WORK (sets CH_F = target files, CH_N = their new content) ----
# Inputs: FILES IFACE MAC FIX DHCP ADDR GW DNS FB DOM WORK
build_changes() {
    CH_F=(); CH_N=(); NEW60=0
    local f n i=0 has60=0
    for f in "${FILES[@]}"; do
        i=$((i + 1)); n=$WORK/new.$i
        sudo cat "$f" > "$WORK/old.$i"
        yaml remove "$WORK/old.$i" > "$n"
        [[ -z $(yaml info "$n") ]] && sed -i 's/^\([[:space:]]*ethernets:\).*$/\1 {}/' "$n"   # no interfaces left
        if [[ $f == "$NEWF" ]]; then has60=1; N60=$n; continue; fi
        cmp -s "$WORK/old.$i" "$n" || { CH_F+=("$f"); CH_N+=("$n"); }
    done
    local base=$WORK/new.60
    if ((has60)) && [[ -n $(yaml info "$N60") ]]; then cp "$N60" "$base"; else
        printf 'network:\n    version: 2\n    ethernets:\n' > "$base"; fi
    ((has60)) || NEW60=1
    local eind cind
    read -r eind cind < <(awk '/^[ ]*ethernets:/ && !f {match($0,/^ */); e=RLENGTH; f=1; next} f && !/^[ ]*(#|$)/ {match($0,/^ */); print e, RLENGTH; exit}' "$base")
    sed -i -e '$a\' "$base"
    block_text "${cind:-8}" "$(( ${cind:-8} - ${eind:-4} ))" >> "$base"
    CH_F+=("$NEWF"); CH_N+=("$base")
    if ((has60)); then sudo cat "$NEWF" > "$WORK/old.60"; else : > "$WORK/old.60"; fi
}

# ---- puts the backups back (or deletes the new file) and re-applies ----
rollback() {
    [[ $ARMED == 1 ]] || return
    ARMED=0
    echo "Rolling back to the original configuration..."
    local f
    for f in "${CH_F[@]}"; do
        if [[ -n ${BK[$f]} ]]; then sudo cp -p "${BK[$f]}" "$f"; else sudo rm -f "$f"; fi
    done
    sudo netplan apply
}

# ---- screen layout: bars, headers, warning banner ----
bar()  { printf '%*s\n' "${1:-88}" '' | tr ' ' "${2:-=}"; }
hdr()  { local t=" $1 " w=${2:-88} c=${3:-=} l r; l=$(( (w - ${#t}) / 2 )); r=$(( w - ${#t} - l ))
         printf '%*s' "$l" '' | tr ' ' "$c"; printf '%s' "$t"; printf '%*s\n' "$r" '' | tr ' ' "$c"; }
warn() { echo "=======================WARNING=======================WARNING=======================WARNING========================="; bar 115; }

# ---- main ----
main() {
    # setup: sudo check, netplan check, list files, temp dir
    sudo -v || exit 1
    command -v netplan >/dev/null || { echo "netplan is not installed."; exit 1; }
    shopt -s nullglob; FILES=("$D"/*.yaml); shopt -u nullglob
    WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
    FIX=""; DHCP=0; ADDR=""; GW=""; DNS=""; FB=""; DOM=""

    # pick interface: show current interfaces, ask which one, read its MAC
    echo; hdr "CURRENT INTERFACES"
    ip -br link
    bar
    echo; bar
    read -rp "Interface to configure (e.g. ens19): " IFACE
    [[ -d /sys/class/net/$IFACE ]] || { echo "No such interface."; exit 1; }
    MAC=$(cat "/sys/class/net/$IFACE/address")

    # scan files: look for the chosen interface, DHCP use, and other default gateways
    local f info t a b c on_dhcp=0 defs=() i=0
    for f in "${FILES[@]}"; do
        i=$((i + 1)); sudo cat "$f" > "$WORK/scan.$i"
        info=$(yaml info "$WORK/scan.$i")
        while read -r t a b c; do
            case $t in
                MATCH) echo "$IFACE is already defined in $f; it will be replaced."; [[ $a == 1 ]] && on_dhcp=1 ;;
                OTHER) [[ $b == 1 ]] && defs+=("$a|$f") ;;
            esac
        done <<< "$info"
    done
    ip -4 -o addr show dev "$IFACE" | grep -qw dynamic && on_dhcp=1
    bar

    # DHCP or static prompts: DHCP question, then IP, CIDR, gateway, DNS, fallback DNS, search domain
    echo; bar
    ask_yn "Enable DHCP on $IFACE?" && DHCP=1
    if ((!DHCP)); then
        if ((on_dhcp)); then
            echo "DHCP detected on $IFACE."
            ask_yn "Still set a static IP?" || { echo "Cancelled. Nothing changed."; exit 0; }
        fi
        bar
        echo; bar
        while true; do read -rp "Machine IP address (e.g. X.X.X.X): " ADDR; valid_ip "$ADDR" && break; echo "Invalid IP."; done
        while true; do read -rp "CIDR (e.g. 24): " CIDR; valid_cidr "$CIDR" && break; echo "CIDR must be 1-32."; done
        usable_host "$ADDR" "$CIDR" || { echo "$ADDR is the network or broadcast address of that subnet."; exit 1; }
        bar
        echo; bar
        while true; do
            read -rp "Default Gateway (e.g. X.X.X.X): " GW
            valid_ip "$GW" || { echo "Invalid IP."; continue; }
            same_subnet "$ADDR" "$GW" "$CIDR" || { echo "Gateway $GW is not on the same subnet as $ADDR/$CIDR."; continue; }
            [[ $GW != "$ADDR" ]] && break; echo "Gateway can't equal the machine IP."
        done
        bar
        echo; bar
        while true; do read -rp "Name Server Address (e.g. X.X.X.X): " DNS; valid_ip "$DNS" && break; echo "Invalid IP."; done
        if ask_yn "Add Fallback Name Server Address?"; then
            while true; do read -rp "    Fallback Name Server Address (e.g. 8.8.8.8): " FB; valid_ip "$FB" && break; echo "    Invalid IP."; done
        fi
        read -rp "DNS Search Domain (e.g. cyber.uml.edu): " DOM
        ADDR="$ADDR/$CIDR"
    fi
    bar

    # clear other interfaces: list them and print the banner (no question asked)
    local d names=""
    for d in "${defs[@]}"; do FIX="$FIX ${d%%|*}"; names+="${names:+, }${d%%|*}"; done
    if [[ -n $names ]]; then
        echo; warn
        echo "Interface(s) $names will be cleared of their IP address and default gateway to make $IFACE the only default route"
        bar 115; bar 115
    fi

    # SSH warning: warn if your session runs over an interface that is changing
    if [[ -n $SSH_CONNECTION ]]; then
        local lip; lip=$(awk '{print $3}' <<< "$SSH_CONNECTION")
        if ip -o -4 addr show dev "$IFACE" | grep -qF " $lip/" || [[ -n ${FIX// /} ]]; then
            echo; warn
            echo "Your SSH session may use an interface being changed. It will drop, and 'netplan try'"
            echo "cannot get your confirmation, so it will roll back. Use the console."
            bar 115
            ask_yn "Continue anyway?" || { echo "Cancelled. Nothing changed."; exit 0; }
            bar 115
        fi
    fi

    # preview: summary lines, file contents, the "Apply?" prompt
    build_changes
    local k
    local pass
    echo; bar 115
    for pass in 1 2; do          # pass 1: the new file, pass 2: edited files
        for k in "${!CH_F[@]}"; do
            if [[ ${CH_F[$k]} == "$NEWF" ]] && ((NEW60)); then ((pass == 1)) && echo "- New file \"${CH_F[$k]##*/}\" added"
            else ((pass == 2)) && echo "- \"${CH_F[$k]##*/}\" backed up & edited"; fi
        done
    done
    for pass in 1 2; do
        for k in "${!CH_F[@]}"; do
            if [[ ${CH_F[$k]} == "$NEWF" ]] && ((NEW60)); then ((pass == 1)) || continue; else ((pass == 2)) || continue; fi
            echo; hdr "${CH_F[$k]##*/}" 65 .
            cat "${CH_N[$k]}"
            bar 65 .
        done
    done
    echo; bar 115
    ask_yn "Apply this configuration?" || { echo "Cancelled. Nothing changed."; exit 0; }
    bar 115

    # backup: make the .backup copies of edited files
    declare -gA BK=()
    for k in "${!CH_F[@]}"; do
        f=${CH_F[$k]}
        [[ -f $f ]] || continue
        BK[$f]="$f.backup"
        sudo cp -p "$f" "${BK[$f]}" || { echo "Backup of $f failed. Nothing changed."; exit 1; }
    done

    # install and apply: write files, generate, try, apply (rolls back on failure or Ctrl+C)
    trap 'rollback; rm -rf "$WORK"; exit 130' INT TERM
    ARMED=1
    for k in "${!CH_F[@]}"; do sudo install -m 600 -o root -g root "${CH_N[$k]}" "${CH_F[$k]}"; done
    if ! sudo netplan generate; then echo "Invalid netplan."; rollback; exit 1; fi
    if ! sudo netplan try; then echo "Not confirmed or failed."; rollback; exit 1; fi
    sudo netplan apply
    ARMED=0

    [[ -d /etc/cloud/cloud.cfg.d ]] && echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg >/dev/null
    echo; hdr "RESULT"
    ip -br a show "$IFACE"; ip route
    bar

    # bring interface down: one-time question (lasts until reboot or the next netplan apply)
    echo; bar
    if ask_yn "Bring an interface down?"; then
        ip -br link
        read -rp "Interface to bring down: " DOWN
        [[ -d /sys/class/net/$DOWN ]] || { echo "No such interface."; exit 1; }
        if [[ -n $SSH_CONNECTION ]]; then
            local lip2; lip2=$(awk '{print $3}' <<< "$SSH_CONNECTION")
            if ip -o -4 addr show dev "$DOWN" | grep -qF " $lip2/"; then
                echo "WARNING: $DOWN carries your SSH session."
                ask_yn "Continue anyway?" || { echo "Skipped."; exit 0; }
            fi
        fi
        sudo ip link set dev "$DOWN" down && echo "$DOWN is down (until reboot or the next netplan apply)."
    fi
    bar
}

[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"