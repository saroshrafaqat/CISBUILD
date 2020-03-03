#!/bin/bash

##########################################
###This script will be used for all tasks that are having issues with ansible########
#########################################


#######TASK 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored) ################
#####################################################################################
echo "install cramfs /bin/true">>/etc/modprobe.d/cramfs.conf
rmmod cramfs


#######TASK 1.1.1.2 Ensure mounting of vFAT filesystems is limited (Not Scored) ################
#####################################################################################
#echo "install vfat /bin/true ">> /etc/modprobe.d/vfat.conf
#rmmod vfat

#######TASK 1.1.1.3 Ensure mounting of squashfs filesystems is disabled (Scored)  ################
#####################################################################################
echo "install squashfs /bin/true ">>/etc/modprobe.d/squashfs.conf
rmmod squashfs

#######TASK 1.1.1.4 Ensure mounting of udf filesystems is disabled (Scored) ################
#####################################################################################
echo "install udf /bin/true ">>/etc/modprobe.d/udf.conf
rmmod udf

#######TASK 1.1.3 Ensure nodev option set on /tmp partition (Scored) + TASK  1.1.4 Ensure nosuid option set on /tmp partition (Scored) + TASK 1.1.5 Ensure noexec option set on /tmp partition (Scored)    ##############
sed -i '16 s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
mount -o remount,nodev /tmp

#######TASK 1.1.8 Ensure nodev option set on /var/tmp partition (Scored) + TASK 1.1.9 Ensure nosuid option set on /var/tmp partition (Scored) + TASK 1.1.10 Ensure noexec option set on /var/tmp partition (Scored)
sed -i '20 s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
mount -o remount,nodev /var/tmp

#######TASK 1.1.14 Ensure nodev option set on /home partition (Scored)   ##############
sed -i '15 s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
mount -o remount,nodev /home

#######TASK 1.1.15 Ensure nodev option set on /dev/shm partition + TASK 1.1.16 Ensure nosuid option set on /dev/shm partition (Scored) + TASK 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)###
echo "none /dev/shm                                             tmpfs   defaults,nodev,nosuid,noexec 0 0">>/etc/fstab
mount -o remount /dev/shm

#######TASK 1.1.23 Disable USB Storage (Scored)   ##############
#####################################################################################
echo install usb-storage /bin/true >>/etc/modprobe.d/usb-storage.conf

#######TASK 1.3.2 Ensure sudo commands use pty##############
#####################################################################################
echo "Defaults use_pty">>/etc/sudoers

#######TASK 1.3.3 Ensure sudo log file exists##############
#####################################################################################
touch /var/log/sudo.log
echo "Defaults logfile=\"/var/log/sudo.log\"">>/etc/sudoers

#######TASK 1.2.4 Ensure gpgcheck is globally activated##############
#####################################################################################
sed -i '/gpgcheck =/c\gpgcheck = 1' /etc/yum.repos.d/redhat.repo

#######TASK 1.4.1 Ensure AIDE is installed (Scored)   ##############
#####################################################################################
dnf install aide -y
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

#######TASK 1.4.2 Ensure filesystem integrity is regularly checked  ##############
#####################################################################################
echo "0 5 * * * /usr/sbin/aide --check">>/var/spool/cron/root


####### TASK 1.5.1 Ensure permissions on bootloader config are configured (Scored)+ TASK  1.5.2 Ensure bootloader password is set  ##############
#####################################################################################
echo "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.6C05661A3820BBAEC0B4D14BC991CC496BF3FA04FC096AAE1C5E489013163A28F14F7FF533B38764BF3F2AA0DF67948CD850AB4A8A5505C204E1785B1CF14078.CBE20C8AECC97FAD61B7EB7BD122894586BA6114D1F1451D1E23BFFD95B67E5104600703733D30A9CC0CF8C9ECA090B66F5DEACC266590EA380072782AF4605A">/boot/grub2/user.cfg
grub2-mkconfig -o /boot/grub2/grub.cfg

chown root:root /boot/grub2/*
chmod og-rwx  /boot/grub2/*

#######TASK  1.8.1.1 Ensure message of the day is configured properly (Scored) + 1.8.1.2 Ensure local login warning banner is configured properly + 1.8.1.3 Ensure remote login warning banner is configured properly ##############
#####################################################################################
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

#######TASK  2.2.2 Ensure X Window System is not installed##############
#####################################################################################
dnf remove xorg-x11* -y


#######TASK 3.2.8 Ensure TCP SYN Cookies is enabled (Scored)    ##############
#####################################################################################
 grep -Els "^\s*net\.ipv4\.tcp_syncookies\s*=\s*[02]*" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.tcp_syncookies\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.tcp_syncookies=1; sysctl -w net.ipv4.route.flush=1

#######TASK 3.2.9 Ensure IPv6 router advertisements are not accepted (Scored)   ##############
#####################################################################################
echo "net.ipv6.conf.all.accept_ra = 0" >>//etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >>//etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

#######TASK 3.3.1-4 3.3.1 Ensure DCCP is disabled (Scored) + 3.3.2 Ensure SCTP is disabled (Scored) + 3.3.3 Ensure RDS is disabled (Scored) + 3.3.4 Ensure TIPC is disabled (Scored)    ##############
#####################################################################################
echo "install dccp /bin/true ">>/etc/modprobe.d/dccp.conf
echo "install sctp /bin/true ">>/etc/modprobe.d/sctp.conf
echo "install rds /bin/true ">>/etc/modprobe.d/rds.conf
echo "install tipc /bin/true ">>/etc/modprobe.d/tipc.conf

#######TASK 3.5 Ensure wireless interfaces are disabled (Scored)    ##############
#####################################################################################
nmcli radio all off

#######TASK   4.1.2.2 Ensure audit logs are not automatically deleted (Scored)##############
#####################################################################################
sed -i '/max_log_file_action = ROTATE/c\max_log_file_action = keep_logs ' /etc/audit/auditd.conf

#######TASK  4.1.2.3 Ensure system is disabled when audit logs are full (Scored)  ##############
#####################################################################################
sed -i '/space_left_action = SYSLOG/c\space_left_action = email' /etc/audit/auditd.conf
sed -i '/admin_space_left_action = SUSPEND/c\admin_space_left_action = halt' /etc/audit/auditd.conf

#######TASK  1.6.1 Ensure core dumps are restricted (Scored)  ##############
#####################################################################################
echo "*                hard    core            0">>/etc/security/limits.conf
echo "fs.suid_dumpable = 0 ">>/etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
echo "Storage=none">>/etc/systemd/coredump.conf
echo "ProcessSizeMax=0 ">>/etc/systemd/coredump.conf
systemctl daemon-reload

#######TASK 4.1.3 Ensure changes to system administration scope (sudoers) is collected (Scored)   ##############
#####################################################################################
echo "-w /etc/sudoers -p wa -k scope" >>/etc/audit/rules.d/scope.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/scope.rules

#######TASK 4.1.4 Ensure login and logout events are collected (Scored)   ##############
#####################################################################################
echo "-w /var/log/faillog -p wa -k logins " >>/etc/audit/rules.d/audit.rules
echo "-w /var/log/lastlog -p wa -k logins " >>/etc/audit/rules.d/audit.rules

#######TASK 4.1.5 Ensure session initiation information is collected (Scored)  ##############
#####################################################################################
echo "-w /var/run/utmp -p wa -k session ">>/etc/audit/rules.d/logins.rules
echo "-w /var/run/utmp -p wa -k session ">>/etc/audit/rules.d/logins.rules
echo "-w /var/run/utmp -p wa -k session ">>/etc/audit/rules.d/logins.rules

#######TASK 4.1.6 Ensure events that modify date and time information are collected  ##############
#####################################################################################
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change ">>/etc/audit/rules.d/time-change.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange ">>/etc/audit/rules.d/time-change.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change ">>/etc/audit/rules.d/time-change.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change">>/etc/audit/rules.d/time-change.rules
echo "-w /etc/localtime -p wa -k time-change ">>/etc/audit/rules.d/time-change.rules

#######TASK 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)  ##############
#####################################################################################
echo "-w /etc/selinux/ -p wa -k MAC-policy ">>/etc/audit/rules.d/MAC-policy.rules
echo "-w /usr/share/selinux/ -p wa -k MAC-policy ">>/etc/audit/rules.d/MAC-policy.rules

#######TASK 4.1.8 Ensure events that modify the system's network environment are collected (Scored)   ##############
#####################################################################################
echo "-w /etc/sysconfig/network -p wa -k system-locale ">>/etc/audit/rules.d/system-locale.rules
echo "-w /etc/hosts -p wa -k system-locale ">>/etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue.net -p wa -k system-locale">>/etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue -p wa -k system-locale ">>/etc/audit/rules.d/system-locale.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale">>/etc/audit/rules.d/system-locale.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale ">>/etc/audit/rules.d/system-locale.rules

#######TASK 4.1.11 Ensure events that modify user/group information are collected (Scored) ##############
#####################################################################################
echo "-w /etc/group -p wa -k identity ">>/etc/audit/rules.d/identity.rules
echo "-w /etc/passwd -p wa -k identity ">>/etc/audit/rules.d/identity.rules
echo "-w /etc/gshadow -p wa -k identity">>/etc/audit/rules.d/identity.rules
echo "-w /etc/shadow -p wa -k identity ">>/etc/audit/rules.d/identity.rules
echo "-w /etc/security/opasswd -p wa -k identity ">>/etc/audit/rules.d/identity.rules

#######TASK 4.1.12 Ensure successful file system mounts are collected (Scored)##############
#####################################################################################
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts">/etc/audit/rules.d/mounts.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts">/etc/audit/rules.d/mounts.rules

#######TASK  #4.2.1.3 Ensure rsyslog default file permissions configured#############
#####################################################################################
echo "\$FileCreateMode 0640">>/etc/rsyslog.conf

#######TASK  4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored)##############
#####################################################################################
echo "*. *  @170.20.76.95:514">>/etc/rsyslog.conf
systemctl restart rsyslog

#######TASK 4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)  ##############
#####################################################################################
sed -i '/#ForwardToSyslog=no/c\ForwardToSyslog=yes' /etc/systemd/journald.conf

#######TASK 4.2.2.2 Ensure journald is configured to compress large log files (Scored)  ##############
#####################################################################################
sed -i '/#Compress=yes/c\Compress=yes' /etc/systemd/journald.conf

#######TASK 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)  ##############
#####################################################################################
sed -i '/#Storage=auto/c\Storage=persistent' /etc/systemd/journald.conf

#######TASK 4.2.3 Ensure permissions on all logfiles are configured  ##############
#####################################################################################
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

#######TASK 5.1.2 Ensure permissions on /etc/crontab are configured (Scored)  ##############
#####################################################################################
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

#######TASK 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)  ##############
#####################################################################################
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

#######TASK 5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)  ##############
#####################################################################################
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

#######TASK 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored) ##############
#####################################################################################
 chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

#######TASK 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)  ##############
#####################################################################################
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

#######TASK 5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)   ##############
#####################################################################################
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

#######TASK 5.1.8 Ensure at/cron is restricted to authorized users (Scored) ##############
#####################################################################################
rm -rf /etc/cron.deny
rm -rf /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

#######TASK 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)  ##############
#####################################################################################
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
echo "this is the end of script"


#######TASK 5.2.2 Ensure SSH access is limited ##############
#####################################################################################
echo "DenyUsers billy" >>/etc/ssh/sshd_config

#######TASK 5.2.3 Ensure permissions on SSH private host key files are configured (Scored)  ##############
#####################################################################################
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;

#######TASK 5.2.5 Ensure SSH LogLevel is appropriate (Scored)  ##############
#####################################################################################
sed -i '/#LogLevel INFO/c\LogLevel INFO' /etc/ssh/sshd_config

#######TASK 5.2.6 Ensure SSH X11 forwarding is disabled (Scored)   ##############
#####################################################################################
sed -i '/X11Forwarding yes/c\X11Forwarding no' /etc/ssh/sshd_config

#######TASK 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less##############
#####################################################################################
sed -i '/#MaxAuthTries/c\MaxAuthTries 4' /etc/ssh/sshd_config

#######TASK 5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)  ##############
#####################################################################################
sed -i '/#IgnoreRhosts yes/c\IgnoreRhosts yes' /etc/ssh/sshd_config

#######TASK 5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored)  ##############
#####################################################################################
sed -i '/#HostbasedAuthentication no/c\HostbasedAuthentication no' /etc/ssh/sshd_config

#######TASK 5.2.10 Ensure SSH root login is disabled (Scored) ##############
#####################################################################################
useradd -m -p sa/oCyMkJAd/E -G wheel  Admin
usermod -a -G wheel Admin
sed -i '46 s/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config


#######TASK 5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored)  ##############
#####################################################################################
sed -i '/#PermitEmptyPasswords no/c\PermitEmptyPasswords no' /etc/ssh/sshd_config

#######TASK 5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored)   ##############
#####################################################################################
sed -i '/#PermitUserEnvironment no/c\PermitUserEnvironment no' /etc/ssh/sshd_config

#######TASK 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less (Scored)  ##############
#####################################################################################
sed -i '/#LoginGraceTime 2m/c\LoginGraceTime 60 ' /etc/ssh/sshd_config

#######TASK  5.2.15 Ensure SSH warning banner is configured (Scored) ##############
#####################################################################################
sed -i '/#Banner /c\Banner /etc/issue.net' /etc/ssh/sshd_config

#######TASK 5.2.17 Ensure SSH AllowTcpForwarding is disabled (Scored)  ##############
#####################################################################################
sed -i '/#AllowTcpForwarding yes/c\AllowTcpForwarding no' /etc/ssh/sshd_config

#######TASK 5.2.18 Ensure SSH MaxStartups is configured (Scored)   ##############
#####################################################################################
sed -i '/#MaxStartups 10:30:100/c\MaxStartups 10:30:60' /etc/ssh/sshd_config

#######TASK 5.2.19 Ensure SSH MaxSessions is set to 4 or less##############
#####################################################################################
sed -i '/#MaxSessions/c\MaxSessions 4' /etc/ssh/sshd_config

#######TASK  5.2.13 Ensure SSH Idle Timeout Interval is configured (Scored)##############
#####################################################################################
sed -i '/#ClientAliveInterval 0/c\ClientAliveInterval 300' /etc/ssh/sshd_config
sed -i '/#ClientAliveCountMax 3/c\ClientAliveCountMax 0' /etc/ssh/sshd_config

#######TASK  5.3.1 Create custom authselect profile (Scored) + 5.3.2 + 5.3.3##############
#####################################################################################
authselect create-profile CIS -b sssd --symlink-meta
authselect select custom/CIS with-sudo with-faillock without-nullok --force

#######TASK 5.4.1 Ensure password creation requirements are configured##############
#####################################################################################
sed -i '11 s/# minlen = 8/minlen = 14/' /etc/security/pwquality.conf  && sed -i '34 s/# minclass = 0/minclass = 4/' /etc/security/pwquality.conf

#######TASK 5.4.2 Ensure lockout for failed password attempts is configured (Scored)  + TASK 5.4.3 Ensure password reuse is limited (Scored) ##############
#####################################################################################

#sed -i '10 s/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass local_users_only  retry=3 remember=5/' /etc/pam.d/password-auth
#sed -i '11 s/password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow/password    sufficient    pam_unix.so sha512 shadow  try_first_pass use_authtok remember=5 /' /etc/pam.d/password-auth
#
#sed -i '10 s/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass local_users_only  retry=3 remember=5/' /etc/pam.d/system-auth
#sed -i '11 s/password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow/password    sufficient    pam_unix.so sha512 shadow  try_first_pass use_authtok remember=5 /' /etc/pam.d/system-auth
#
#
#echo "    ">>/etc/pam.d/system-auth
#echo "auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900">>/etc/pam.d/system-auth
#echo "auth        [success=1    default=bad] pam_unix.so">>/etc/pam.d/system-auth
#echo "auth        [default=die]  pam_faillock.so authfail audit deny=5 unlock_time=900">>/etc/pam.d/system-auth
#echo "auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900">>/etc/pam.d/system-auth


#echo "    ">>/etc/pam.d/password-auth
#echo "auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900">>/etc/pam.d/password-auth
#echo "auth        [success=1    default=bad] pam_unix.so">>/etc/pam.d/password-auth
#echo "auth        [default=die]  pam_faillock.so authfail audit deny=5 unlock_time=900">>/etc/pam.d/password-auth
#echo "auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900">>/etc/pam.d/password-auth


#######TASK 5.5.1.2 Ensure minimum days between password changes is 7 or more (Scored)  + TASK 5.5.1.3 Ensure password expiration warning days is 7 or more (Scored)  ##############
#####################################################################################
sed -i "\|PASS_MAX_DAYS|d" /etc/login.defs
sed -i "\|PASS_MIN_DAYS|d" /etc/login.defs
sed -i '23 i\PASS_MIN_DAYS   7' /etc/login.defs
sed -i '23 i\PASS_MAX_DAYS   90' /etc/login.defs
chage --maxdays 90 root
chage --maxdays 90 Admin
chage --mindays 7 root
chage --mindays 7 Admin




#######TASK 5.5.1.4 Ensure inactive password lock is 30 days or less (Scored) ##############
#####################################################################################
useradd -D -f 30
#chage --inactive 30 *

#######TASK 5.5.3 Ensure default user shell timeout is 900 seconds or less ##############
#####################################################################################
echo "TMOUT=300">>/etc/profile.d/autologout.sh
echo "readonly TMOUT">>/etc/profile.d/autologout.sh
echo "export TMOUT">>/etc/profile.d/autologout.sh
chmod +x /etc/profile.d/autologout.sh



#######TASK  5.5.5 Ensure default user umask is 027 or more restrictive (Scored) ##############
#####################################################################################
umask 027
sed -i '/umask 002/c\umask 027' /etc/profile
sed -i '/umask 022/c\umask 027' /etc/profile
sed -i '/umask 022/c\umask 027' /etc/bashrc
sed -i '/umask 002/c\umask 027' /etc/bashrc


#######TASK 5.7 Ensure access to the su command is restricted (Scored)   ##############
#####################################################################################
echo "auth           required        pam_wheel.so use_uid">>/etc/pam.d/su

######TASK  6.1.10 Ensure no world writable files exist##############
#####################################################################################



dnf install -y java

echo "this is the end of script"

