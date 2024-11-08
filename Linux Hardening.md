# Linux System Hardening Guide: Detailed Explanations

## 1. User Account & Password Security
**Purpose**: Prevent unauthorized access, enforce strong authentication, and maintain user accountability.

### Password Policies
```bash
# /etc/login.defs
PASS_MAX_DAYS   90    # Password must be changed every 90 days
PASS_MIN_DAYS   7     # Minimum days between password changes
PASS_WARN_AGE   7     # Warning 7 days before password expires
```
**Why**: Enforces regular password changes and prevents rapid password cycling. Regular changes limit the impact of compromised passwords.

### PAM Configuration
```bash
# /etc/pam.d/system-auth
password required pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
```
**Explanation**:
- retry=3: Allow 3 attempts before failing
- minlen=12: Minimum password length of 12 characters
- dcredit=-1: Require at least one digit
- ucredit=-1: Require at least one uppercase letter
- ocredit=-1: Require at least one special character
- lcredit=-1: Require at least one lowercase letter

### Account Lockout
```bash
# /etc/pam.d/system-auth
auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit
```
**Purpose**: Protects against brute-force attacks by locking accounts after 5 failed attempts for 15 minutes (900 seconds).

## 2. Filesystem Security
**Purpose**: Protect system files, prevent unauthorized execution, and maintain file integrity.

### Mount Point Hardening
```bash
# /etc/fstab
/dev/sda1   /tmp         ext4    defaults,nodev,nosuid,noexec    0 0
```
**Options Explained**:
- nodev: Prevent device file creation
- nosuid: Prevent SUID/SGID bit execution
- noexec: Prevent direct execution of binaries

### AIDE Configuration 
```bash
# /etc/aide/aide.conf
/etc    PERMS      # Monitor permission changes
/bin    CONTENT_EX # Monitor content and metadata
/sbin   CONTENT_EX
/boot   CONTENT_EX
!/var/log/.*      # Exclude log files
```
**Purpose**: File integrity monitoring to detect unauthorized changes to system files.

## 3. Network Security
**Purpose**: Protect against network-based attacks and unauthorized access.

### IPTables Base Configuration
```bash
#!/bin/bash
# Default policies
iptables -P INPUT DROP      # Drop all incoming traffic by default
iptables -P FORWARD DROP    # Drop all forwarding traffic
iptables -P OUTPUT ACCEPT   # Allow all outgoing traffic

# Rate limiting for SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent \
         --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent \
         --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP
```
**Explanation**: 
- Implements default-deny policy
- Allows established connections
- Rate limits SSH connections (prevents brute force)

### SSH Hardening
```bash
# /etc/ssh/sshd_config
Protocol 2                    # Use SSH protocol version 2 only
PermitRootLogin no           # Disable direct root login
MaxAuthTries 3               # Limit authentication attempts
PubkeyAuthentication yes     # Enable key-based authentication
PasswordAuthentication no    # Disable password authentication
```
**Purpose**: Secure remote access while preventing common attack vectors.

## 4. Process and Service Hardening
**Purpose**: Limit service privileges and protect against process-based attacks.

### SystemD Service Hardening
```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE  # Limit capabilities
PrivateTmp=yes                              # Private /tmp directory
ProtectSystem=full                          # Read-only access to /usr /boot
ProtectHome=yes                             # No access to /home
NoNewPrivileges=yes                         # Prevent privilege escalation
```
**Explanation**: Implements service isolation and principle of least privilege.

## 5. Kernel Hardening
**Purpose**: Protect the kernel from exploitation and limit attack surface.

### Kernel Parameter Security
```bash
# /etc/sysctl.conf
kernel.randomize_va_space = 2    # Enable ASLR
kernel.kptr_restrict = 2         # Hide kernel pointers
kernel.yama.ptrace_scope = 1     # Restrict ptrace
kernel.dmesg_restrict = 1        # Restrict kernel messages
```
**Why**: Makes kernel exploitation more difficult and limits information leakage.

## 6. Logging and Monitoring
**Purpose**: Maintain audit trail and detect security incidents.

### RSyslog Configuration
```bash
# /etc/rsyslog.conf
auth,authpriv.*   /var/log/auth.log    # Authentication events
kern.*            /var/log/kern.log    # Kernel messages
mail.*            /var/log/mail.log    # Mail server logs
```
**Purpose**: Centralized logging for security events and system activities.

### Auditd Rules
```bash
# /etc/audit/rules.d/audit.rules
-w /etc/sudoers -p wa -k sudo_changes              # Monitor sudo config
-w /sbin/insmod -p x -k module_insertion          # Monitor module loading
-a always,exit -F arch=b64 -S mount -F auid>=1000 # Monitor mount operations
```
**Explanation**: Track critical system changes and privileged operations.

## 7. SELinux/AppArmor Configuration
**Purpose**: Mandatory Access Control for additional security layers.

### SELinux Policy Example
```bash
policy_module(custom, 1.0)
type custom_t;
domain_type(custom_t)
```
**Purpose**: Define fine-grained access controls for processes and files.

### AppArmor Profile
```bash
/usr/bin/custom {
  /usr/bin/custom mr,        # Allow read/execute
  /var/log/custom.log w,     # Allow write to log
  deny /etc/shadow r,        # Explicitly deny shadow access
}
```
**Explanation**: Defines allowed operations for specific applications.

## 8. Automated Security Checks
**Purpose**: Regular security validation and monitoring.

### Daily Security Scan
```bash
#!/bin/bash
# Security checks
grep "Failed password" /var/log/auth.log    # Check login failures
aide --check                                # File integrity check
ss -tuln                                    # List listening ports
ps -ef | grep root                          # Check root processes
```
**Purpose**: Automate routine security checks and alert on anomalies.

## 9. Core Security Best Practices

### File Permission Management
```bash
# Regular permission audits
find /etc -type f -perm /o+w               # World-writable files
find / -type f \( -perm -4000 -o -perm -2000 \) # SUID/SGID files
chmod 600 /etc/shadow                      # Secure shadow file
```
**Why**: Prevents unauthorized access and modification of critical files.

### Process Isolation
```bash
# Process security
nice -n 10 process_name     # Adjust process priority
chroot /path/to/jail        # Create process jail
ulimit -n 64               # Limit open files
```
**Purpose**: Contain processes and limit resource usage.

### Network Hardening
```bash
# Network security
tcp_wrappers
hosts.allow
hosts.deny
```
**Explanation**: Additional network access control layer.
