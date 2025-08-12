# TODO

## ProxyForge

### Bug Fixes

#### Firewall Rule Cleanup Bug
- [ ] **CRITICAL**: Fix missing firewall rule cleanup when removing configurations
  - [ ] **Root Cause**: `menu_remove_config()` calls `remove_config_files()` but doesn't clean up UFW rules
  - [ ] **Issue**: When a configuration is deleted via menu, UFW rules for the external port remain active
  - [ ] **Impact**: Orphaned firewall rules accumulate over time, potentially creating security gaps
  - [ ] **Solution**: Create `remove_firewall_rules()` function and call it from `menu_remove_config()`
  - [ ] **Implementation**: 
    - [ ] Add `remove_firewall_rules(app_port, ext_port)` function
    - [ ] Remove UFW allow rules for external port: `ufw delete allow ${ext_port}`
    - [ ] Remove localhost-specific rules for app port: `ufw delete allow from 127.0.0.1 to any port ${app_port}`
    - [ ] Handle both numbered and non-numbered rule deletion
    - [ ] Add error handling for cases where rules don't exist
    - [ ] Call `remove_firewall_rules()` from `menu_remove_config()` before `remove_config_files()`
  - [ ] **Testing**: Verify that all UFW rules are properly removed when configuration is deleted

#### Regex Pattern Fixes
- [ ] Fix regex patterns in `check_and_warn_unprotected_services()`
  - [ ] Change `:([0-9]*)` to `:([0-9]+)` to avoid empty port matches

#### Error Handling Improvements
- [ ] Improve error handling in `test_proxy_accessibility()`
  - [ ] Add more robust curl/wget error handling
  - [ ] Better timeout and retry logic

### New Features

#### Let's Encrypt Integration
- [ ] Add optional command line option `--email` for Let's Encrypt certificates
- [ ] Add new constants and variables for Let's Encrypt support
  - [ ] `CERTBOT_DIR="/etc/letsencrypt"`
  - [ ] `DOMAIN=""` and `EMAIL=""` variables
  - [ ] `USE_LETSENCRYPT="false"` flag
  - [ ] `DEFAULT_FAKE_EMAIL="admin@localhost.local"` for fallback
- [ ] Implement `detect_domain()` function
  - [ ] Auto-detect server's public IP address
  - [ ] Perform reverse DNS lookup to find domain
  - [ ] Check common domain patterns and configurations
  - [ ] Fallback to IP-based certificate if no domain found
- [ ] Implement `install_certbot_if_needed()` function
  - [ ] Auto-detect package manager and install certbot
  - [ ] Support for apt, dnf, yum, zypper, pacman, apk
- [ ] Implement `validate_domain()` function
  - [ ] Check if detected/provided domain points to server IP address
  - [ ] Validate domain format and accessibility
  - [ ] Handle cases where domain detection fails
- [ ] Implement `obtain_letsencrypt_cert()` function
  - [ ] Use HTTP-01 challenge method
  - [ ] Handle temporary nginx configuration for challenge
  - [ ] Request certificate from Let's Encrypt with auto-detected domain
  - [ ] Use fake email if none provided by user
- [ ] Implement `setup_cert_renewal()` function
  - [ ] Configure cron job for automatic certificate renewal
  - [ ] Test renewal process
- [ ] Modify existing functions for Let's Encrypt support
  - [ ] Update `parse_args()` to handle optional email option
  - [ ] Modify `generate_self_signed_cert()` to choose between self-signed or Let's Encrypt
  - [ ] Update `interactive_setup()` to optionally ask for email (with fake email fallback)
  - [ ] Update `usage()` function with new options
- [ ] Add domain auto-detection and prerequisites checking
  - [ ] Verify port 80 is accessible for HTTP-01 challenge
  - [ ] Check DNS resolution for auto-detected domain
  - [ ] Generate fake email if user doesn't provide one
  - [ ] Validate email format when provided
- [ ] Handle certificate renewal and nginx reload
  - [ ] Automatic certificate renewal via cron
  - [ ] Graceful nginx reload after certificate renewal
  - [ ] Error handling for renewal failures
- [ ] Update documentation and help text
  - [ ] Add examples for automatic Let's Encrypt usage
  - [ ] Document domain auto-detection process
  - [ ] Add troubleshooting section for certificate issues
  - [ ] Explain fake email usage for privacy

#### Multi-Firewall Support
- [ ] Replace UFW-only implementation with multi-firewall support
  - [ ] **Current Limitation**: ProxyForge only supports UFW firewall
  - [ ] **Goal**: Support multiple firewall backends with automatic detection and user choice
  - [ ] **Supported Firewalls**:
    - [ ] UFW (Ubuntu/Debian default)
    - [ ] firewalld (RHEL/CentOS/Fedora default)
    - [ ] iptables (direct, universal Linux)
    - [ ] nftables (modern replacement for iptables)
  - [ ] **Implementation Strategy**:
    - [ ] Create firewall abstraction layer with common interface
    - [ ] Implement `detect_firewall()` function to identify active firewall
    - [ ] Create firewall-specific implementation functions
    - [ ] Add user selection when no firewall is detected
  - [ ] **Core Functions to Implement**:
    - [ ] `detect_firewall()` - Auto-detect current active firewall
    - [ ] `install_firewall_if_needed(firewall_type)` - Install selected firewall
    - [ ] `firewall_allow_port(port)` - Allow port through detected firewall
    - [ ] `firewall_block_port(port)` - Block port through detected firewall
    - [ ] `firewall_allow_from_source(source, port)` - Allow from specific source
    - [ ] `firewall_remove_rule(port)` - Remove firewall rule
    - [ ] `firewall_enable()` - Enable firewall service
    - [ ] `firewall_status()` - Check firewall status
  - [ ] **Detection Logic**:
    - [ ] Check for active firewalld service: `systemctl is-active firewalld`
    - [ ] Check for UFW installation and status: `ufw status`
    - [ ] Check for nftables: `nft list tables`
    - [ ] Check for iptables rules: `iptables -L`
    - [ ] Fallback to user selection if none detected
  - [ ] **User Selection Interface**:
    - [ ] Interactive menu when no firewall detected
    - [ ] Options: UFW, firewalld, iptables, nftables, none
    - [ ] Auto-install selected firewall via package manager
    - [ ] Remember user choice for future runs
  - [ ] **Firewall-Specific Implementations**:
    - [ ] **UFW**: Keep existing implementation, refactor into functions
    - [ ] **firewalld**: Use `firewall-cmd` commands
      - [ ] `firewall-cmd --permanent --add-port=${port}/tcp`
      - [ ] `firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=127.0.0.1 port port=${port} protocol=tcp accept"`
      - [ ] `firewall-cmd --reload`
    - [ ] **iptables**: Direct iptables commands
      - [ ] `iptables -A INPUT -p tcp --dport ${port} -j ACCEPT`
      - [ ] `iptables -A INPUT -s 127.0.0.1 -p tcp --dport ${port} -j ACCEPT`
      - [ ] `iptables-save > /etc/iptables/rules.v4`
    - [ ] **nftables**: Use nft commands
      - [ ] `nft add rule inet filter input tcp dport ${port} accept`
      - [ ] `nft add rule inet filter input ip saddr 127.0.0.1 tcp dport ${port} accept`
  - [ ] **Configuration Management**:
    - [ ] Store firewall preference in config file
    - [ ] Add command-line option: `--firewall [ufw|firewalld|iptables|nftables|none]`
    - [ ] Update interactive setup to ask for firewall preference
  - [ ] **Error Handling & Fallbacks**:
    - [ ] Graceful degradation when firewall commands fail
    - [ ] Clear error messages for unsupported firewall versions
    - [ ] Option to skip firewall configuration entirely
    - [ ] Backup/restore functionality for firewall rules
  - [ ] **Testing & Validation**:
    - [ ] Test on different Linux distributions
    - [ ] Verify rule creation and removal for each firewall type
    - [ ] Ensure proper cleanup when switching firewall types
    - [ ] Validate port accessibility after rule application

### Enhancements

#### Configuration Validation
- [ ] Add configuration validation
  - [ ] Validate port ranges and conflicts
  - [ ] Check for existing certificates before generation
  - [ ] Verify nginx configuration syntax before applying