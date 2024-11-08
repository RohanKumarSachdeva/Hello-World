# System Hardening Guide: Linux, Windows, and macOS

## Linux System Hardening

### 1. Access Control & Authentication
- Implement strong password policies using PAM
  ```bash
  # /etc/security/pwquality.conf
  minlen = 12
  minclass = 3
  maxrepeat = 3
  enforce_for_root
  ```
- Configure account lockout policies
- Implement 2FA (Google Authenticator, Yubikey)
- Remove/disable unused accounts
- Set appropriate umask (e.g., 027 or 022)

### 2. File System Security
- Enable mandatory access controls (SELinux/AppArmor)
- Mount partitions with appropriate options:
  ```bash
  # /etc/fstab
  /dev/sda1 /tmp defaults,nodev,nosuid,noexec 0 0
  ```
- Implement file system quotas
- Regular file permission audits
- Enable AIDE (Advanced Intrusion Detection Environment)

### 3. Network Security
- Configure iptables/nftables rules
  ```bash
  # Basic iptables rules
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -P INPUT DROP
  ```
- Disable unused network services
- Configure TCP wrappers (/etc/hosts.allow, /etc/hosts.deny)
- Implement fail2ban
- Enable and configure system firewall

### 4. Service Hardening
- Disable unnecessary services
  ```bash
  systemctl disable <service_name>
  systemctl mask <service_name>
  ```
- Configure SSH security:
  ```conf
  # /etc/ssh/sshd_config
  PermitRootLogin no
  PasswordAuthentication no
  X11Forwarding no
  MaxAuthTries 3
  ```
- Implement service-specific chroot jails
- Use systemd sandboxing features

### 5. Kernel Security
- Configure sysctl parameters
  ```bash
  # /etc/sysctl.conf
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.all.send_redirects = 0
  kernel.randomize_va_space = 2
  ```
- Enable SecureBoot
- Configure kernel module blacklisting
- Implement kernel hardening (grsecurity, PaX)

## Windows System Hardening

### 1. Group Policy Settings
- Configure via Local Security Policy or GPO:
  - Password policies
  - Account lockout policies
  - Audit policies
  - User rights assignments
  - Security options

### 2. Security Features
- Enable Windows Defender
  - Real-time protection
  - Cloud-delivered protection
  - Controlled folder access
- Configure Windows Firewall
- Enable BitLocker encryption
- Implement AppLocker policies
- Enable Secure Boot

### 3. Network Security
- Disable unused network protocols
- Configure IPSec policies
- Enable Network Level Authentication
- Implement 802.1x authentication
- Configure SMB signing and encryption

### 4. Service Hardening
- Disable unnecessary services
- Configure service accounts
- Implement service isolation
- Enable Service Guard
- Configure service trigger events

### 5. Access Control
- Implement LAPS (Local Administrator Password Solution)
- Configure UAC settings
- Enable Credential Guard
- Implement Just Enough Administration (JEA)
- Configure Remote Desktop security

## macOS System Hardening

### 1. System Security
- Enable FileVault disk encryption
- Configure Gatekeeper settings
  ```bash
  sudo spctl --master-enable
  ```
- Enable System Integrity Protection (SIP)
- Configure automatic updates
- Enable Firmware password

### 2. Network Security
- Configure built-in firewall
  ```bash
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
  ```
- Enable stealth mode
- Disable unused network services
- Configure Wi-Fi security
- Implement VPN configurations

### 3. Access Control
- Configure strong passwords
- Enable FileVault
- Implement 2FA with Apple ID
- Configure screen saver password
- Set up separate admin and user accounts

### 4. Application Security
- Configure Privacy & Security settings
- Enable app sandboxing
- Implement Gatekeeper restrictions
- Configure XProtect settings
- Enable Mandatory Access Controls (MAC)

### 5. Monitoring & Auditing
- Configure system audit logs
- Enable security auditing
  ```bash
  sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
  ```
- Monitor system logs
- Enable Terminal logging
- Configure remote logging

## Universal Hardening Practices

### 1. Regular Maintenance
- Apply security patches promptly
- Regular security audits
- Backup critical data
- Monitor system logs
- Update firmware

### 2. Network Controls
- Network segmentation
- Secure remote access
- Intrusion Detection/Prevention
- Network monitoring
- SSL/TLS configuration

### 3. Security Policies
- Documented security procedures
- Incident response plan
- Change management
- Access review process
- Security awareness training

### 4. Compliance Requirements
- Industry standards (PCI DSS, HIPAA, etc.)
- Regular compliance audits
- Documentation maintenance
- Risk assessments
- Third-party security reviews
