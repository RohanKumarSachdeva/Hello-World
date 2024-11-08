# Comprehensive Linux System Hardening Guide

## 1. User Account & Password Security

### Password Policies
```bash
# /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   7
```

### PAM Configuration
```bash
# /etc/pam.d/system-auth
password required pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password required pam_unix.so use_authtok sha512 shadow remember=5
```

### Account Lockout
```bash
# /etc/pam.d/system-auth
auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit
```

### SUDO Configuration
```bash
# /etc/sudoers.d/secure_sudo
Defaults        use_pty
Defaults        logfile="/var/log/sudo.log"
Defaults        !visiblepw
Defaults        timestamp_timeout=15
```

## 2. Filesystem Security

### Mount Point Hardening
```bash
# /etc/fstab
/dev/sda1   /tmp         ext4    defaults,nodev,nosuid,noexec    0 0
/dev/sda2   /var         ext4    defaults,nodev                  0 0
/dev/sda3   /home        ext4    defaults,nodev,nosuid          0 0
```

### File Permission Audit Script
```bash
#!/bin/bash
# Regular audit of sensitive files
find /etc -type f -perm /o+w -ls
find / -type f \( -perm -4000 -o -perm -2000 \) -ls
find / -type d \( -perm -2 -o -perm -20 \) -ls
```

### AIDE Configuration 
```bash
# /etc/aide/aide.conf
/etc    PERMS
/bin    CONTENT_EX
/sbin   CONTENT_EX
/boot   CONTENT_EX
!/var/log/.*
```

## 3. Network Security

### IPTables Base Configuration
```bash
#!/bin/bash
# Reset all rules
iptables -F
iptables -X
iptables -Z

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback and established connections
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific services
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP
```

### SSH Hardening
```bash
# /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
```

### Network Parameter Hardening
```bash
# /etc/sysctl.conf
# Network security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
```

## 4. Process and Service Hardening

### SystemD Service Hardening
```ini
# Example service hardening
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
```

### Process Accounting
```bash
# Enable process accounting
systemctl enable psacct
systemctl start psacct

# Configure audit logging
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/group -p wa -k group_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
```

## 5. Kernel Hardening

### Kernel Parameter Security
```bash
# /etc/sysctl.conf
# Core security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
```

### Module Blacklisting
```bash
# /etc/modprobe.d/blacklist.conf
blacklist usb-storage
blacklist firewire-core
blacklist thunderbolt
blacklist bluetooth
```

## 6. Logging and Monitoring

### RSyslog Configuration
```bash
# /etc/rsyslog.conf
# Log auth messages
auth,authpriv.*                 /var/log/auth.log
# Log all kernel messages
kern.*                         /var/log/kern.log
# Log all mail messages
mail.*                         /var/log/mail.log
# Log cron jobs
cron.*                         /var/log/cron.log
```

### Logrotate Configuration
```bash
# /etc/logrotate.d/custom
/var/log/custom.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
```

### Auditd Rules
```bash
# /etc/audit/rules.d/audit.rules
-w /etc/sudoers -p wa -k sudo_changes
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_insertion
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
```

## 7. SELinux/AppArmor Configuration

### SELinux Policy Example
```bash
# Enable SELinux
setenforce 1
sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

# Custom policy module
policy_module(custom, 1.0)

type custom_t;
domain_type(custom_t)
role system_r types custom_t;

allow custom_t self:process { fork exec };
allow custom_t self:fifo_file rw_file_perms;
```

### AppArmor Profile Example
```bash
# /etc/apparmor.d/usr.bin.custom
#include <tunables/global>

/usr/bin/custom {
  #include <abstractions/base>
  #include <abstractions/user-tmp>

  /usr/bin/custom mr,
  /var/log/custom.log w,
  /etc/custom.conf r,
  
  deny /etc/shadow r,
  deny /etc/** w,
}
```

## 8. Automated Security Checks

### Daily Security Scan Script
```bash
#!/bin/bash
# Check for failed login attempts
grep "Failed password" /var/log/auth.log | tail -n 10

# Check for modified system files
aide --check

# Check for listening ports
ss -tuln

# Check for processes running as root
ps -ef | grep root

# Check disk usage
df -h

# Check for updates
apt list --upgradable
```

## 9. Compliance Monitoring

### CIS Benchmark Script
```bash
#!/bin/bash
# Check filesystem configurations
echo "Checking filesystem configurations..."
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

# Check for unowned files
echo "Checking for unowned files..."
find / -xdev \( -nouser -o -nogroup \) -print

# Check password fields
echo "Checking password fields..."
awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow

# Check root PATH
echo "Checking root PATH..."
if [ "`echo $PATH | grep ::>`" != "" ]; then
    echo "Empty Directory in PATH (::)"
fi
```
