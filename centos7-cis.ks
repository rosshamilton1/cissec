install
lang en_GB.UTF-8
keyboard --vckeymap=gb --xlayouts='gb'
timezone Europe/London --isUtc
auth --useshadow --passalgo=sha512 			# CIS 6.3.1
firewall --enabled
services --enabled=NetworkManager,sshd
eula --agreed
ignoredisk --only-use=vda
reboot
	 
bootloader --location=mbr --append=" crashkernel=auto"
zerombr
clearpart --all --initlabel
part swap --asprimary --fstype="swap" --size=1024
part /boot --fstype xfs --size=200
part pv.01 --size=1 --grow
volgroup vg_root pv.01
logvol / --fstype xfs --name=root --vgname=vg_root --size=5120
# CIS 1.1.1-1.1.4
logvol /tmp --vgname vg_root --name tmp --size=500 --fsoptions="nodev,nosuid,noexec"
# CIS 1.1.5
logvol /var --vgname vg_root --name var --size=500
# CIS 1.1.7
logvol /var/log --vgname vg_root --name log --size=1024
# CIS 1.1.8
logvol /var/log/audit --vgname vg_root --name audit --size=1024
# CIS 1.1.9-1.1.0
logvol /home --vgname vg_root --name home --size=1024 --grow --fsoptions="nodev"
	 
rootpw yourpasswordhere

repo --name=base --baseurl="http://mirrors.kernel.org/centos/7/os/x86_64/"
url --url="http://mirrors.kernel.org/centos/7/os/x86_64/"

%packages --ignoremissing
@core
aide 				# CIS 1.3.1
setroubleshoot-server
ntp				# CIS 3.6
tcp_wrappers			# CIS 4.5.1
rsyslog				# CIS 5.1.1
cronie-anacron			# CIS 6.1.2
-setroubleshoot 		# CIS 1.4.4
-mcstrans	 		# CIS 1.4.5
-telnet 			# CIS 2.1.2
-rsh-server 			# CIS 2.1.3
-rsh				# CIS 2.1.4
-ypbind				# CIS 2.1.5
-ypserv				# CIS 2.1.6
-tftp				# CIS 2.1.7
-tftp-server			# CIS 2.1.8
-talk				# CIS 2.1.9
-talk-server			# CIS 2.1.10
-xinetd				# CIS 2.1.11
-xorg-x11-server-common		# CIS 3.2
-avahi-daemon			# CIS 3.3
-cups				# CIS 3.4
-dhcp				# CIS 3.5
-openldap			# CIS 3.7
%end

%post --log=/root/postinstall.log

###############################################################################
# /etc/fstab
# CIS 1.1.6 + 1.1.14-1.1.16
cat << EOF >> /etc/fstab
/tmp      /var/tmp    none    bind    0 0
none	/dev/shm	tmpfs	nosuid,nodev,noexec	0 0
EOF

###############################################################################

# Disable mounting of unneeded filesystems CIS 1.1.18 - 1.1.24
cat << EOF >> /etc/modprobe.d/CIS.conf
install cramfs /bin/true	# CIS 1.1.18
install freevxfs /bin/true	# CIS 1.1.19
install jffs2 /bin/true		# CIS 1.1.20
install hfs /bin/true		# CIS 1.1.21
install hfsplus /bin/true	# CIS 1.1.22
install squashfs /bin/true	# CIS 1.1.23
install udf /bin/true		# CIS 1.1.24
install dccp /bin/true		# CIS 4.6.1
install sctp /bin/true		# CIS 4.6.2
install rds /bin/true		# CIS 4.6.3
install tipc /bin/true		# CIS 4.6.18
EOF

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7	# CIS 1.2.1

/usr/bin/systemctl enable firewalld			# CIS 4.7
/usr/bin/systemctl enable rsyslog			# CIS 5.1.2
/usr/bin/systemctl enable crond				# CIS 6.1.2

# Set bootloader password				# CIS 1.5.3
cat << EOF2 >> /etc/grub.d/01_users
#!/bin/sh -e

cat << EOF
set superusers="bootuser"
password_pbkdf2 bootuser grub.pbkdf2.sha512.10000.FE4D934335A0A9CB1B8E748713D1BDE766BB4041DEB297DB11674A1270BFC9B934C054B1BFEE8839AF9AE7DAD1F70D34D919FB617F09606636AC0EBE680F48FF.E01B493CA2F06BB62E03164F97FC98D6DB6A61BA5603DB299F98B5A08DE519C48730ECBBA0EB86BCE0DCFB02AF4C6EE19D9DF17F214CAE502D2078B4B8C59AC7
EOF
EOF2

grub_cfg='/boot/grub2/grub.cfg'
grub2-mkconfig -o ${grub_cfg}

# Restrict Core Dumps					# CIS 1.6.1
echo \* hard core 0 >> /etc/security/limits.conf

cat << EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0					# CIS 1.6.1	
kernel.randomize_va_space = 2				# CIS 1.6.2
net.ipv4.ip_forward = 0					# CIS 4.1.1
net.ipv4.conf.all.send_redirects = 0			# CIS 4.1.2
net.ipv4.conf.default.send_redirects = 0		# CIS 4.1.2
net.ipv4.conf.all.accept_source_route = 0		# CIS 4.2.1
net.ipv4.conf.default.accept_source_route = 0		# CIS 4.2.1
net.ipv4.conf.all.accept_redirects = 0 			# CIS 4.2.2
net.ipv4.conf.default.accept_redirects = 0 		# CIS 4.2.2
net.ipv4.conf.all.secure_redirects = 0 			# CIS 4.2.3
net.ipv4.conf.default.secure_redirects = 0 		# CIS 4.2.3
net.ipv4.conf.all.log_martians = 0 			# CIS 4.2.4
net.ipv4.conf.default.log_martians = 0 			# CIS 4.2.4
net.ipv4.icmp_echo_ignore_broadcasts = 1		# CIS 4.2.5
net.ipv4.icmp_ignore_bogus_error_responses = 1		# CIS 4.2.6
net.ipv4.conf.all.rp_filter = 1				# CIS 4.2.7
net.ipv4.conf.default.rp_filter = 1			# CIS 4.2.7
net.ipv4.tcp_syncookies = 1				# CIS 4.2.8
net.ipv6.conf.all.accept_ra = 0				# CIS 4.4.1.1
net.ipv6.conf.default.accept_ra = 0 			# CIS 4.4.1.1
net.ipv6.conf.all.accept_redirect = 0			# CIS 4.4.1.2
net.ipv6.conf.default.accept_redirect = 0		# CIS 4.4.1.2
net.ipv6.conf.all.disable_ipv6 = 1			# CIS 4.4.2
EOF

echo umask 027 >> /etc/sysconfig/init			# CIS 3.1

cd /usr/lib/systemd/system				# CIS 3.2
rm default.target
ln -s multi-user.target default.target

ntp_conf='/etc/ntp.conf'
sed -i "s/^restrict default/restrict default kod/" ${ntp_conf}
line_num="$(grep -n "^restrict default" ${ntp_conf} | cut -f1 -d:)"
sed -i "${line_num} a restrict -6 default kod nomodify notrap nopeer noquery" ${ntp_conf}
sed -i s/'^OPTIONS="-g"'/'OPTIONS="-g -u ntp:ntp -p /var/run/ntpd.pid"'/ /etc/sysconfig/ntpd

echo "ALL: ALL" >> /etc/hosts.deny			# CIS 4.5.4
chown root:root /etc/hosts.deny				# CIS 4.5.5
chmod 644 /etc/hosts.deny				# CIS 4.5.5

chown root:root /etc/rsyslog.conf			# CIS 5.1.4
chmod 600 /etc/rsyslog.conf				# CIS 5.1.4
# CIS 5.1.3  Configure /etc/rsyslog.conf - This is environment specific 
# CIS 5.1.5  Configure rsyslog to Send Log to a Remote Log Host - This is environment specific
# CIS 5.2.1.2 Disable system on Audit Log Full - This is VERY environment specific (and likely controversial)

# CIS 6.1.2-6.1.9
chown root:root /etc/anacrontab	/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# CIS 6.1.10 + 6.1.11
[[ -w /etc/at.deny ]] && rm /etc/at.deny 
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow



sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 '/ /etc/default/grub  # CIS 5.2.3

cat << EOF >> /etc/audit/audit.rules

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity 
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity 

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale 

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/run/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \ -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \ -F auid!=4294967295 -k delete 
-w /etc/sudoers -p wa -k scope
-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-e 2 
EOF

sed -i "1 i /var/log/boot.log" /etc/logrotate.d/syslog 			# CIS 5.3

sshd_config='/etc/ssh/sshd_config'
sed -i "s/\#Protocol/Protocol/" ${sshd_config}				# CIS 6.2.1
sed -i "s/\#LogLevel/LogLevel/" ${sshd_config}				# CIS 6.2.2
chown root:root ${sshd_config}						# CIS 6.2.3
chmod 600 ${sshd_config}						# CIS 6.2.3
sed -i "s/X11Forwarding yes/X11Forwarding no/" ${sshd_config}		# CIS 6.2.4
sed -i "s/\#MaxAuthTries 6/MaxAuthTries 4/" ${sshd_config}		# CIS 6.2.5
sed -i "s/\#IgnoreRhosts yes/IgnoreRhosts yes/" ${sshd_config}		# CIS 6.2.6
sed -i "s/\#HostbasedAuthentication no/HostbasedAuthentication no/" ${sshd_config}	# CIS 6.2.7
sed -i "s/\#PermitRootLogin yes/PermitRootLogin no/" ${sshd_config}	# CIS 6.2.8
sed -i "s/\#PermitEmptyPasswords no/PermitEmptyPasswords no/" ${sshd_config}	# CIS 6.2.9
sed -i "s/\#PermitUserEnvironment no/PermitUserEnvironment no/" ${sshd_config}	# CIS 6.2.10
line_num=$(grep -n "^\# Ciphers and keying" ${sshd_config} | cut -d: -f1)
sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ${sshd_config}	# CIS 6.2.11
sed -i "s/\#ClientAliveInterval 0/ClientAliveInterval 300/" ${sshd_config}	# CIS 6.2.12
sed -i "s/\#ClientAliveCountMax 3/ClientAliveCountMax 0/" ${sshd_config}	# CIS 6.2.12
sed -i "s/\#Banner none/Banner \/etc\/issue/" ${sshd_config}    	# CIS 6.2.12


login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}		# CIS 7.1.1
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}		# CIS 7.1.2
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}		# CIS 7.1.3

usermod -g 0 root							# CIS 7.3

bashrc='/etc/bashrc'
#first umask cmd sets it for users, second umask cmd sets it for system reserved uids
#we want to alter the first one
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/077/ ${bashrc}

[[ -w /etc/issue ]] && rm /etc/issue
[[ -w /etc/issue.net ]] && rm /etc/issue.net
touch /etc/issue /etc/issue.net
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net

chown root:root ${grub_cfg}					# CIS 1.5.1
chmod 600 ${grub_cfg}						# CIS 1.5.2
chmod 644 /etc/passwd						# CIS 9.1.2
chmod 000 /etc/shadow						# CIS 9.1.3
chmod 000 /etc/gshadow						# CIS 9.1.4
chmod 644 /etc/group						# CIS 9.1.5
chown root:root /etc/passwd					# CIS 9.1.6
chown root:root /etc/shadow					# CIS 9.1.7
chown root:root /etc/gshadow					# CIS 9.1.8
chown root:root /etc/group					# CIS 9.1.9

# CIS 6.3.2
cat << EOF >> /etc/pam.d/pwquality.conf
minlen=8
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1
EOF

# CIS 6.3.3
content="$(egrep -v "^#|^auth" /etc/pam.d/password-auth)"
echo -e "auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > /etc/pam.d/password-auth

system_auth='/etc/pam.d/system-auth'
content="$(egrep -v "^#|^auth" ${system_auth})"
echo -e "auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > ${system_auth}

sed -i s/'^password sufficient pam_unix.so'/'password sufficient pam_unix.so remember=5'/ ${system_auth}

# CIS 6.4
cp /etc/securetty /etc/securetty.orig
#> /etc/securetty   
cat << EOF >> /etc/securetty
console
tty1
EOF

# CIS 6.5
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}
usermod -G wheel root

# Install AIDE     						# CIS 1.3.1
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
#echo PRELINKING=no > /etc/sysconfig/prelink
#Initialise last so it doesn't pick up changes made by the post-install of the KS
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
#/usr/sbin/prelink -ua

%end
