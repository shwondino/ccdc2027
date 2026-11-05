#! /bin/bash

#**********************************************************
# Written by a sad Matthew Harper...
# Edited by a disenchanted Sanjeev Shankar Vijaya Sankar
#**********************************************************

# Check if the scrip is ran as root.
# $EUID is a env variable that contains the users UID
# -ne 0 is not equal zero
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# If there exists this file, it is a debian based system. Use APT
if [ -f "/etc/debian_version" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -q install auditd audispd-plugins -y
elif [ -f "/etc/redhat-release" ]; then
    yum install audit audit-libs -y
elif [ -f "/etc/arch-release" ];then 
    echo "Arch, Will this come up -- probably should do fedora"
fi

systemctl --now enable auditd
touch /etc/audit/rules.d/ccdc.rules
chown root:root /etc/audit/rules.d/ccdc.rules

RULES=/etc/audit/rules.d/ccdc.rules

# Adds a -w rule if the path or its parent dir exists; skips it otherwise
# so a missing directory can't stop the rest of the rules from loading.
# Usage: addwatch <path> <perms or ""> <key>
addwatch() {
    local path="$1" perms="$2" key="$3"
    if [ -e "$path" ] || [ -d "$(dirname "$path")" ]; then
        if [ -n "$perms" ]; then
            echo "-w $path -p $perms -k $key" >> $RULES
        else
            echo "-w $path -k $key" >> $RULES
        fi
    else
        echo "[-] Skipping watch on $path (parent directory does not exist)"
    fi
}

# Log modifications to date and time. (2611)
# 32-64 bit
#echo -e "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change \n-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change \n-a always,exit -F arch=b64 -S clock_settime -k time-change \n-a always,exit -F arch=b32 -S clock_settime -k time-change \n-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for modifications to date and time"
echo -e "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change \n-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change \n-a always,exit -F arch=b64 -S clock_settime -k time-change \n-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/ccdc.rules 
addwatch /etc/localtime wa time-change

# Log modifications to host/domain name (2613)
#echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale   -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale       -w /etc/issue -p wa -k system-locale          -w /etc/issue.net -p wa -k system-locale           -w /etc/hosts -p wa -k system-locale         -w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/ccdc.rules 
#echo -e "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale \n-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale \n-w /etc/issue -p wa -k system-locale \n-w /etc/issue.net -p wa -k system-locale \n-w /etc/hosts -p wa -k system-locale  \n-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for modifications to host or domain names"
echo -e "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale \n-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale" >> /etc/audit/rules.d/ccdc.rules 
addwatch /etc/issue wa system-locale
addwatch /etc/issue.net wa system-locale
addwatch /etc/hosts wa system-locale
addwatch /etc/network wa system-locale

if [ "$(systemctl status apparmor | grep "active (running)" | wc -l)" -ne 0 ]; then 
    # Log modifications to AppArmor's Mandatory Acces Controls (2614)
    #echo "-w /etc/apparmor/ -p wa -k MAC-policy -w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/ccdc.rules 
    echo "[+] Create auditd rule to watch for apparmor modifications"
    addwatch /etc/apparmor/ wa MAC-policy
    addwatch /etc/apparmor.d/ wa MAC-policy
fi
# Collect login/logout information (2615)
#echo "-w /var/log/faillog -p wa -k logins | -w /var/log/lastlog -p wa -k logins | -w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/ccdc.rules
echo "[+] Create auditd rule to monitor login and logout infomtaion"
addwatch /var/log/faillog wa logins
addwatch /var/log/lastlog wa logins
addwatch /var/log/tallylog wa logins

# Collect session initiation info (2616) 
#echo "-w /var/run/utmp -p wa -k session | -w /var/log/wtmp -p wa -k logins | -w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to coleect session initalization information"
addwatch /var/run/utmp wa session
addwatch /var/log/wtmp wa logins
addwatch /var/log/btmp wa logins

# Collect file permision changes (2617)
#echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod | -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ccdc.rules 
#echo -e "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod \n -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod \n -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for file permission changes"
echo -e "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod \n-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ccdc.rules 

# Collect unsuccessful unauthorized file access attempts (2618)
#echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access | -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access | -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access | -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ccdc.rules 
#echo -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access \n-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access \n-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access \n-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for unautorized access attempts"
echo -e "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access \n-a always,exit -F arch=b32 -S creat -S open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access \n-a always,exit -F arch=b64 -S creat -S open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access \n-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ccdc.rules 

# Collect successful File system mounts (2619)
#echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts | -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for file system mounts"
echo -e "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts \n-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/ccdc.rules 

# Collect file deletion events (2620)
#echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete | -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/ccdc.rules 
#echo -e "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete \n-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for file deletion events"
echo -e "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete \n-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/ccdc.rules 

# Collect modifications to sudoers (2621)
#echo "-w /etc/sudoers -p wa -k scope | -w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/ccdc.rules 
echo "[+] Create auditd rule to watch for modifications to the sudoers file"
addwatch /etc/sudoers wa scope
addwatch /etc/sudoers.d/ wa scope

############# 2622

# Sudo log (all euid=0 from uid > 1000 that are not an unset uid.
# https://sudoedit.com/log-sudo-with-auditd/
echo "[+] Create auditd rule to watch for all sudo operations"
echo -e "-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -F key=sudo_log \n-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -F key=sudo_log" >> /etc/audit/rules.d/ccdc.rules

# Collect kernel module loading/unloading (2623)
#echo "-w /sbin/insmod -p x -k modules | -w /sbin/rmmod -p x -k modules | -w /sbin/modprobe -p x -k modules | -a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/ccdc.rules
echo "[+] Create auditd rule to watch for kernel module loading/unloading"
addwatch /sbin/insmod x modules
addwatch /sbin/rmmod x modules
addwatch /sbin/modprobe x modules
echo -e "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules \n-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules" >> /etc/audit/rules.d/ccdc.rules

# Cron Audit
echo "[+] Create auditd rule to watch for cron/at modification"
addwatch /var/spool/cron/crontabs/ wa cron
addwatch /var/spool/cron/atjobs/ wa cron
addwatch /var/spool/at/ wa cron
addwatch /etc/at.allow "" cron
addwatch /etc/at.deny "" cron
addwatch /etc/cron.allow wa cron
addwatch /etc/cron.deny wa cron
addwatch /etc/cron.d/ wa cron
addwatch /etc/cron.daily/ wa cron
addwatch /etc/cron.hourly/ wa cron
addwatch /etc/cron.monthly/ wa cron
addwatch /etc/cron.weekly/ wa cron
addwatch /etc/crontab wa cron
addwatch /var/spool/cron/root "" cron

# UserFiles
echo "[+] Create auditd rule to watch for user modifications or creations (groups, passwd, shado, ect.)"
addwatch /etc/group wa user_groups
addwatch /etc/passwd wa user_passwd
addwatch /etc/shadow wa user_shadow
addwatch /etc/login.defs wa logins

# Passwd - Ident 
echo "[+] Create auditd rule to watch for uses of programs to modify users infomration"
addwatch /usr/bin/passwd x passwd_modification
addwatch /usr/sbin/groupadd x group_modification
addwatch /usr/sbin/groupmod x group_modification
addwatch /usr/sbin/addgroup x group_modification
addwatch /usr/sbin/useradd x user_modification
addwatch /usr/sbin/userdel x user_modification
addwatch /usr/sbin/usermod x user_modification
addwatch /usr/sbin/adduser x user_modification

# Login configuration and information
echo "[+] Create auditd rule to watch for additional login information"
addwatch /etc/securetty wa logins

# root ssh key tampering
echo "[+] Create auditd rule to watch for root ssh key tampering"
addwatch /root/.ssh wa rootkey

# Systemd
echo "[+] Create auditd rule to watch for systemd and system ctl modification"
addwatch /bin/systemctl x systemd
addwatch /etc/systemd/ wa systemd
addwatch /usr/lib/systemd wa systemd

## SSH configuration
echo "[+] Create auditd rule to watch for SSH configuration changes"
addwatch /etc/ssh/sshd_config wa sshd
addwatch /etc/ssh/sshd_config.d wa sshd

## Pam configuration
echo "[+] Create auditd rule to watch for PAM configuration changes"
addwatch /etc/pam.d/ wa pam
addwatch /etc/security/limits.conf wa pam
addwatch /etc/security/limits.d wa pam
addwatch /etc/security/pam_env.conf wa pam
addwatch /etc/security/namespace.conf wa pam
addwatch /etc/security/namespace.d wa pam
addwatch /etc/security/namespace.init wa pam

## User or Process ID change (switching accounts) applications
echo "[+] Create auditd rule to watch for PID or UID changes"
addwatch /bin/su x priv_esc
addwatch /usr/bin/sudo x priv_esc

## Suspicious activity
echo "[+] Create auditd rule to watch for suspicious activity"
for b in /usr/bin/wget /usr/bin/curl /usr/bin/base64 /bin/nc /bin/netcat /usr/bin/ncat \
         /usr/bin/ss /usr/bin/netstat /usr/bin/ssh /usr/bin/scp /usr/bin/sftp /usr/bin/ftp \
         /usr/bin/socat /usr/bin/wireshark /usr/bin/tshark /usr/bin/rawshark \
         /usr/bin/wlfreerdp /usr/bin/nmap; do
    addwatch $b x susp_activity
done
for b in /usr/bin/rdesktop /usr/local/bin/rdesktop /usr/bin/xfreerdp /usr/local/bin/xfreerdp; do
    addwatch $b x T1219_Remote_Access_Tools
done

## Sbin suspicious activity
echo "[+] Create auditd rule to watch for suspicious activity with system binaries"
for b in /sbin/iptables /sbin/ip6tables /sbin/ifconfig /usr/sbin/arptables /usr/sbin/ebtables \
         /sbin/xtables-nft-multi /usr/sbin/nft /usr/sbin/tcpdump /usr/sbin/traceroute /usr/sbin/ufw; do
    addwatch $b x sbin_susp
done

## Suspicious shells ash
echo "[+] Create auditd rule to watch for suspicious shells"
for b in /bin/ash /bin/csh /bin/fish /bin/tcsh /bin/tclsh /bin/xonsh /usr/local/bin/xonsh /bin/open /bin/rbash; do
    addwatch $b x susp_shell
done
# Make audit logs immutable. (2624) -- ensure that this works
#echo "[+] Create auditd rule to make rules imutable unless there is a system restart 
#echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules 

echo "[!!] Restarting Auditd"

if [ -f "/etc/redhat-release" ]; then 
    service auditd restart
else
    systemctl restart auditd
fi