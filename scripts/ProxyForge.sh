#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# CONSTANTS AND GLOBAL VARIABLES
# ============================================================================

readonly DEFAULT_APP_PORT=7314
readonly DEFAULT_EXT_PORT=""
readonly DEFAULT_USERNAME="user"
readonly CONF_DIR="/etc/nginx/conf.d"
readonly SSL_DIR="/etc/nginx/ssl"
readonly HTPASSWD_FILE_BASE="/etc/nginx/.htpasswd"

APP_PORT="$DEFAULT_APP_PORT"
EXT_PORT="$DEFAULT_EXT_PORT"
USERNAME="$DEFAULT_USERNAME"
ASSUME_YES="false"
CERT_PATH=""
KEY_PATH=""
CONF_NAME=""
APP_BINDING=""

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Display usage information and command line options
usage() { cat <<'USAGE'
Usage: ProxyForge.sh [options]

Options:
  -a, --app-port PORT        Local app port to proxy (default: 7314)
  -e, --external-port PORT   External HTTPS port to listen on (default: same as app port)
  -u, --username NAME        Basic auth username (default: user)
  -y, --yes                  Assume yes for prompts and overwrite existing files
  --cert PATH                Use existing certificate file (PEM/CRT)
  --key PATH                 Use existing private key file (PEM/KEY)
  --conf-name NAME           Custom nginx conf name (default: app_${APP_PORT}_to_${EXT_PORT}.conf)
  -h, --help                 Show this help

Notes:
- Must be run as root (use sudo).
- Linux only. Not supported on macOS/Windows.
- Generates a self-signed certificate if no cert/key provided.
- Interactive menu mode starts by default when no arguments provided.
- Use specific options to create configurations directly via command line.
USAGE
}

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Output error message to stderr
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Output info message with green formatting
info() { echo -e "${GREEN}[INFO]${NC} $*"; }

# Output warning message with yellow formatting
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# Output menu header with cyan formatting
menu_header() { echo -e "${CYAN}[MENU]${NC} $*"; }

# Output menu item with blue formatting
menu_item() { echo -e "${BLUE}  $*${NC}"; }

# Validate root privileges
require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        error "This script must be run with root privileges. Re-run with: sudo $0 $*"
        exit 1
    fi
}

# Validate Linux operating system
require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "This script supports Linux only. Detected: $(uname -s)"
        exit 1
    fi
}

# Parse command line arguments
parse_args() {
    local has_args=false
    
    while [[ $# -gt 0 ]]; do
        has_args=true
        case "$1" in
            -a|--app-port) APP_PORT="${2:-}"; shift 2 ;;
            -e|--external-port) EXT_PORT="${2:-}"; shift 2 ;;
            -u|--username) USERNAME="${2:-}"; shift 2 ;;
            -y|--yes) ASSUME_YES="true"; shift ;;
            --cert) CERT_PATH="${2:-}"; shift 2 ;;
            --key) KEY_PATH="${2:-}"; shift 2 ;;
            --conf-name) CONF_NAME="${2:-}"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown argument: $1"; usage; exit 2 ;;
        esac
    done

    if [[ "$has_args" == "false" ]]; then
        show_main_menu
        exit 0
    fi

    if [[ -z "${EXT_PORT}" ]]; then
        EXT_PORT="${APP_PORT}"
    fi

    if [[ -z "${CONF_NAME}" ]]; then
        CONF_NAME="app_${APP_PORT}_to_${EXT_PORT}.conf"
    fi
}

# Interactive configuration setup wizard
interactive_setup() {
    info "Starting interactive setup..."
    echo
    
    local app_binding=""
    while true; do
        echo "Is your application currently listening on:"
        echo "  1) localhost/127.0.0.1 (local only)"
        echo "  2) 0.0.0.0 (all interfaces)"
        read -r -p "Select option [1-2]: " binding_choice
        
        case "$binding_choice" in
            1) app_binding="localhost"; break ;;
            2) app_binding="0.0.0.0"; break ;;
            *) echo "Please select 1 or 2." ;;
        esac
    done
    
    while true; do
        read -r -p "What port is your local application running on? [default: ${DEFAULT_APP_PORT}]: " input_port
        if [[ -z "$input_port" ]]; then
            APP_PORT="$DEFAULT_APP_PORT"
            break
        elif [[ "$input_port" =~ ^[0-9]+$ ]] && [[ "$input_port" -ge 1 ]] && [[ "$input_port" -le 65535 ]]; then
            APP_PORT="$input_port"
            break
        else
            echo "Please enter a valid port number (1-65535)."
        fi
    done
    
    if [[ "$app_binding" == "localhost" ]]; then
        while true; do
            read -r -p "What external HTTPS port should the proxy listen on? [default: same as app port (${APP_PORT})]: " input_ext_port
            if [[ -z "$input_ext_port" ]]; then
                EXT_PORT="$APP_PORT"
                break
            elif [[ "$input_ext_port" =~ ^[0-9]+$ ]] && [[ "$input_ext_port" -ge 1 ]] && [[ "$input_ext_port" -le 65535 ]]; then
                EXT_PORT="$input_ext_port"
                break
            else
                echo "Please enter a valid port number (1-65535)."
            fi
        done
    else
        local suggested_port=$((APP_PORT + 1))
        while true; do
            read -r -p "What external HTTPS port should the authenticated proxy listen on? [default: ${suggested_port}]: " input_ext_port
            if [[ -z "$input_ext_port" ]]; then
                EXT_PORT="$suggested_port"
                break
            elif [[ "$input_ext_port" =~ ^[0-9]+$ ]] && [[ "$input_ext_port" -ge 1 ]] && [[ "$input_ext_port" -le 65535 ]]; then
                EXT_PORT="$input_ext_port"
                break
            else
                echo "Please enter a valid port number (1-65535)."
            fi
        done
    fi
    
    read -r -p "Basic auth username [default: ${DEFAULT_USERNAME}]: " input_username
    if [[ -n "$input_username" ]]; then
        USERNAME="$input_username"
    fi
    
    local pass pass2
    while true; do
        read -r -s -p "Enter password for basic auth user '${USERNAME}': " pass || { echo; error "Failed to read password input"; exit 1; }; echo
        read -r -s -p "Confirm password: " pass2 || { echo; error "Failed to read password confirmation"; exit 1; }; echo
        if [[ "$pass" != "$pass2" ]]; then
            echo "Passwords do not match. Try again."
        elif [[ -z "$pass" ]]; then
            echo "Password cannot be empty."
        else
            BASIC_AUTH_PASSWORD="$pass"
            break
        fi
    done
    
    echo
    info "Configuration Summary:"
    info "  App binding: ${app_binding}"
    info "  Local app port: ${APP_PORT}"
    info "  External HTTPS port: ${EXT_PORT}"
    info "  Basic auth username: ${USERNAME}"
    info "  Nginx config file: app_${APP_PORT}_to_${EXT_PORT}.conf"
    
    if [[ "$app_binding" == "0.0.0.0" ]]; then
        echo
        warn "Firewall Configuration:"
        warn "  - Will BLOCK direct access to port ${APP_PORT}"
        warn "  - Will ALLOW authenticated access on port ${EXT_PORT}"
        warn "  - Your app will only be accessible through the authenticated proxy"
    fi
    
    echo
    
    APP_BINDING="$app_binding"
    
    if [[ "${ASSUME_YES}" != "true" ]]; then
        confirm_or_exit "Proceed with this configuration?"
    fi
}

# Prompt for user confirmation or exit
confirm_or_exit() {
    local prompt="$1"
    if [[ "${ASSUME_YES}" == "true" ]]; then
        return 0
    fi
    read -r -p "${prompt} [y/N]: " ans
    case "$ans" in
        y|Y|yes|YES) return 0 ;;
        *) echo "Aborted."; exit 1 ;;
    esac
}

# Detect available package manager
detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo ""
    fi
}

# Install UFW firewall if not present
install_ufw_if_needed() {
    if command -v ufw >/dev/null 2>&1; then
        info "ufw already installed."
        return
    fi

    local pm
    pm="$(detect_pkg_manager)"
    if [[ -z "$pm" ]]; then
        error "No supported package manager found. Install ufw manually and re-run."
        exit 1
    fi

    info "Installing ufw using ${pm}..."
    case "$pm" in
        apt)
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
            ;;
        dnf)
            dnf install -y ufw
            ;;
        yum)
            yum install -y epel-release || true
            yum install -y ufw
            ;;
        zypper)
            zypper --non-interactive refresh
            zypper --non-interactive install ufw
            ;;
        pacman)
            pacman -Sy --noconfirm ufw
            ;;
        apk)
            apk update
            apk add --no-cache ufw
            ;;
    esac
}

# Configure firewall for app protection with safety checks
configure_firewall() {
    local app_port="$1"
    local proxy_port="$2"
    local app_binding="$3"
    
    install_ufw_if_needed
    
    local ufw_was_inactive=false
    if ! ufw status | grep -q "Status: active"; then
        ufw_was_inactive=true
        
        if [[ "$app_binding" == "localhost" ]]; then
            warn "UFW firewall is currently DISABLED."
            warn "For localhost apps, we recommend enabling UFW for better security."
            echo
            warn "⚠️  SECURITY WARNING ⚠️"
            warn "Enabling UFW may lock you out if SSH or other essential services aren't allowed!"
            warn "Make sure you have:"
            warn "  - SSH access configured (usually port 22)"
            warn "  - Any other services you need to access this server"
            echo
            
            check_and_warn_unprotected_services
            
            echo
            read -r -p "Enable UFW firewall? [y/N]: " enable_ufw
            case "$enable_ufw" in
                y|Y|yes|YES)
                    info "Enabling UFW firewall..."
                    ufw --force enable
                    ;;
                *)
                    warn "UFW remains disabled. Your server security may be compromised."
                    warn "Consider enabling UFW manually after reviewing your service requirements."
                    return 0
                    ;;
            esac
        else
            info "Enabling UFW firewall (required for 0.0.0.0 app protection)..."
            ufw --force enable
        fi
    fi
    
    if [[ "$app_binding" == "localhost" ]]; then
        info "Configuring firewall for localhost app..."
        
        info "Allowing access to authenticated proxy on port ${proxy_port}..."
        ufw allow "${proxy_port}"
        
        if [[ "$ufw_was_inactive" == "true" ]]; then
            info "Adding common service ports to UFW for safety..."
            add_common_service_ports
        fi
        
        info "Firewall configured for localhost app!"
        info "  - Allowed: port ${proxy_port} (authenticated HTTPS proxy)"
        info "  - Original app on port ${app_port} remains on localhost (secure by default)"
        
    else
        info "Configuring firewall to protect 0.0.0.0 app on port ${app_port}..."
        
        info "Allowing access to authenticated proxy on port ${proxy_port}..."
        ufw allow "${proxy_port}"
        
        info "Testing authenticated proxy accessibility..."
        if test_proxy_accessibility "${proxy_port}"; then
            info "Authenticated proxy is working correctly."
            
            if ufw status numbered | grep -q "ALLOW.*${app_port}"; then
                info "Found existing UFW rule allowing port ${app_port}, removing it..."
                
                local rule_num
                rule_num=$(ufw status numbered | grep "ALLOW.*${app_port}" | head -1 | grep -o '^\[[0-9]*\]' | tr -d '[]')
                if [[ -n "$rule_num" ]]; then
                    ufw --force delete "${rule_num}"
                    info "Removed existing allow rule for port ${app_port}"
                fi
            fi
            
            info "Removing any existing broad allow rules for port ${app_port}..."
            ufw delete allow "${app_port}" 2>/dev/null || true
            ufw delete allow "${app_port}/tcp" 2>/dev/null || true
            ufw delete allow "${app_port}/udp" 2>/dev/null || true
            info "Removed any existing broad allow rules for port ${app_port}"
            
            info "Allowing localhost access to port ${app_port}..."
            ufw allow from 127.0.0.1 to any port "${app_port}"
            
            info "Firewall configured successfully!"
            info "  - Blocked: port ${app_port} (direct app access)"
            info "  - Allowed: port ${proxy_port} (authenticated proxy)"
        else
            warn "Authenticated proxy test failed! NOT blocking original app port for safety."
            warn "Your app remains accessible on port ${app_port} without authentication."
            warn "Please check the nginx configuration and try again."
            return 1
        fi
    fi
}

# Check for unprotected services and warn user
check_and_warn_unprotected_services() {
    info "Scanning for services that may need UFW rules..."
    
    local unprotected_services=()
    
    if command -v ss >/dev/null 2>&1; then
        local listening_ports
        listening_ports=$(ss -tulpn | grep "LISTEN.*0.0.0.0:" | grep -o ":([0-9]*)" | tr -d ":(" | tr -d ")" | sort -n | uniq)
        
        for port in $listening_ports; do
            if ! ufw status | grep -q "ALLOW.*${port}"; then
                local service_info
                service_info=$(ss -tulpn | grep ":${port}" | head -1)
                unprotected_services+=("Port ${port}: ${service_info}")
            fi
        done
    elif command -v netstat >/dev/null 2>&1; then
        local listening_ports
        listening_ports=$(netstat -tulpn | grep "LISTEN.*0.0.0.0:" | grep -o ":([0-9]*)" | tr -d ":(" | tr -d ")" | sort -n | uniq)
        
        for port in $listening_ports; do
            if ! ufw status | grep -q "ALLOW.*${port}"; then
                local service_info
                service_info=$(netstat -tulpn | grep ":${port}" | head -1)
                unprotected_services+=("Port ${port}: ${service_info}")
            fi
        done
    fi
    
    if [[ ${#unprotected_services[@]} -gt 0 ]]; then
        warn "Found services listening on 0.0.0.0 that are NOT in UFW allow list:"
        for service in "${unprotected_services[@]}"; do
            warn "  - ${service}"
        done
        echo
        warn "These services will be BLOCKED when UFW is enabled!"
        warn "Add UFW rules for essential services before enabling UFW:"
        warn "  Example: ufw allow 22/tcp    # for SSH"
        warn "  Example: ufw allow 80/tcp    # for HTTP"
        warn "  Example: ufw allow 443/tcp   # for HTTPS"
    else
        info "No unprotected services found listening on 0.0.0.0"
    fi
}

# Add common service ports to UFW for safety
add_common_service_ports() {
    local common_ports=("22" "80" "443")
    local added_ports=()
    
    for port in "${common_ports[@]}"; do
        if command -v ss >/dev/null 2>&1; then
            if ss -tulpn | grep -q "LISTEN.*:${port}"; then
                if ! ufw status | grep -q "ALLOW.*${port}"; then
                    info "Adding UFW rule for commonly used port ${port}..."
                    ufw allow "${port}"
                    added_ports+=("${port}")
                fi
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -tulpn | grep -q "LISTEN.*:${port}"; then
                if ! ufw status | grep -q "ALLOW.*${port}"; then
                    info "Adding UFW rule for commonly used port ${port}..."
                    ufw allow "${port}"
                    added_ports+=("${port}")
                fi
            fi
        fi
    done
    
    if [[ ${#added_ports[@]} -gt 0 ]]; then
        info "Added UFW rules for ports: ${added_ports[*]}"
    fi
}

# Test if the authenticated proxy is accessible
test_proxy_accessibility() {
    local proxy_port="$1"
    
    info "Testing proxy on port ${proxy_port}..."
    
    if command -v curl >/dev/null 2>&1; then
        local response_code
        response_code=$(curl -k -s -o /dev/null -w "%{http_code}" "https://localhost:${proxy_port}/" --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")
        
        if [[ "$response_code" == "401" ]]; then
            info "Proxy responding correctly with 401 Unauthorized (authentication required)"
            return 0
        elif [[ "$response_code" == "200" ]]; then
            warn "Proxy responding with 200 OK (authentication may not be working)"
            return 1
        else
            warn "Proxy test failed with response code: ${response_code}"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget --no-check-certificate --timeout=10 --tries=1 -q -O /dev/null "https://localhost:${proxy_port}/" 2>/dev/null; then
            warn "Proxy responding but authentication status unclear (wget doesn't show auth errors clearly)"
            return 0
        else
            local wget_exit_code=$?
            if [[ "$wget_exit_code" == "6" ]]; then
                info "Proxy responding correctly with authentication required"
                return 0
            else
                warn "Proxy test failed with wget exit code: ${wget_exit_code}"
                return 1
            fi
        fi
    elif command -v nc >/dev/null 2>&1; then
        if timeout 5 nc -z localhost "${proxy_port}" 2>/dev/null; then
            info "Proxy port is accessible (basic connectivity test)"
            return 0
        else
            warn "Cannot connect to proxy port ${proxy_port}"
            return 1
        fi
    else
        warn "No testing tools available (curl, wget, nc). Skipping proxy test."
        warn "Proceeding with firewall configuration (use with caution)"
        return 0
    fi
}

# ============================================================================
# MENU SYSTEM FUNCTIONS
# ============================================================================

# Display ASCII art banner for menu system
draw_ascii_art() {
    echo -e "

 ░▒▓███████▓▒░  ░▒▓█▓▒░        ░▒▓████████▓▒░ ░▒▓████████▓▒░ ░▒▓████████▓▒░
 ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░           ░▒▓█▓▒░            ░▒▓█▓▒░ ░▒▓█▓▒░
 ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░           ░▒▓█▓▒░          ░▒▓██▓▒░  ░▒▓█▓▒░
 ░▒▓███████▓▒░  ░▒▓█▓▒░           ░▒▓█▓▒░        ░▒▓██▓▒░    ░▒▓██████▓▒░
 ░▒▓█▓▒░        ░▒▓█▓▒░           ░▒▓█▓▒░      ░▒▓██▓▒░      ░▒▓█▓▒░
 ░▒▓█▓▒░        ░▒▓█▓▒░           ░▒▓█▓▒░     ░▒▓█▓▒░        ░▒▓█▓▒░
 ░▒▓█▓▒░        ░▒▓█▓▒░           ░▒▓█▓▒░     ░▒▓████████▓▒░ ░▒▓████████▓▒░
                                                                                                                                                                                                
"
}

# Display main menu and handle user selections
show_main_menu() {
    while true; do
        clear
        draw_ascii_art
        echo "============================================================================"
        menu_header "ProxyForge Configuration Manager"
        echo "============================================================================"
        echo
        menu_item "1) Setup new configuration"
        menu_item "2) List all configurations"
        menu_item "3) Modify existing configuration"
        menu_item "4) Remove configuration"
        menu_item "5) View configuration details"
        menu_item "6) Test nginx configuration"
        menu_item "7) Reload nginx"
        menu_item "0) Exit"
        echo
        read -r -p "Select an option [0-7]: " choice
        
        case "$choice" in
            1) menu_setup_new_config ;;
            2) menu_list_configs ;;
            3) menu_modify_config ;;
            4) menu_remove_config ;;
            5) menu_view_config_details ;;
            6) menu_test_nginx ;;
            7) menu_reload_nginx ;;
            0) echo "Sihdir."; exit 0 ;;
            *) echo "Invalid option. Press Enter to continue..."; read -r ;;
        esac
    done
}

# Setup new proxy configuration through interactive menu
menu_setup_new_config() {
    clear
    menu_header "Setup New Configuration"
    echo "============================================================================"
    echo
    
    APP_PORT="$DEFAULT_APP_PORT"
    EXT_PORT="$DEFAULT_EXT_PORT"
    USERNAME="$DEFAULT_USERNAME"
    CERT_PATH=""
    KEY_PATH=""
    CONF_NAME=""
    
    interactive_setup
    
    if [[ -z "${CONF_NAME}" ]]; then
        CONF_NAME="app_${APP_PORT}_to_${EXT_PORT}.conf"
    fi
    
    check_port_conflict
    install_nginx_if_needed
    ensure_dirs
    ensure_nginx_running
    write_htpasswd
    generate_self_signed_cert
    write_nginx_conf
    
    # Configure firewall
    if [[ -n "$APP_BINDING" ]]; then
        configure_firewall "$APP_PORT" "$EXT_PORT" "$APP_BINDING"
    fi
    
    info "Configuration created successfully!"
    echo "Press Enter to return to menu..."
    read -r
}

# List all existing ProxyForge configurations
menu_list_configs() {
    clear
    menu_header "All ProxyForge Configurations"
    echo "============================================================================"
    echo
    
    if [[ ! -d "$CONF_DIR" ]]; then
        warn "Nginx configuration directory not found: $CONF_DIR"
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    local configs
    configs=($(find "$CONF_DIR" -name "app_*_to_*.conf" -type f 2>/dev/null | sort))
    
    if [[ ${#configs[@]} -eq 0 ]]; then
        info "No ProxyForge configurations found."
    else
        echo "No.  Config File                    App Port  Ext Port  Status"
        echo "------------------------------------------------------------------------"
        
        local i=1
        for config in "${configs[@]}"; do
            local config_basename
            config_basename="$(basename "$config")"
            local app_port ext_port
            
            if [[ "$config_basename" =~ app_([0-9]+)_to_([0-9]+)\.conf ]]; then
                app_port="${BASH_REMATCH[1]}"
                ext_port="${BASH_REMATCH[2]}"
            else
                app_port="N/A"
                ext_port="N/A"
            fi
            
            local status="Unknown"
            if nginx -t -c /etc/nginx/nginx.conf >/dev/null 2>&1; then
                status="Valid"
            else
                status="Invalid"
            fi
            
            echo "$i    $config_basename    $app_port    $ext_port    $status"
            ((i++))
        done
    fi
    
    echo
    echo "Press Enter to continue..."
    read -r
}

# Modify existing configuration through interactive menu
menu_modify_config() {
    clear
    menu_header "Modify Existing Configuration"
    echo "============================================================================"
    echo
    
    if ! check_configs_exist; then
        return
    fi
    
    local config_file
    config_file="$(select_config_file)"
    if [[ -z "$config_file" ]]; then
        return
    fi
    
    local config_basename
    config_basename="$(basename "$config_file")"
    
    if [[ "$config_basename" =~ app_([0-9]+)_to_([0-9]+)\.conf ]]; then
        APP_PORT="${BASH_REMATCH[1]}"
        EXT_PORT="${BASH_REMATCH[2]}"
    else
        error "Cannot parse configuration file name: $config_basename"
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    local htpasswd_file="${HTPASSWD_FILE_BASE}-${APP_PORT}"
    if [[ -f "$htpasswd_file" ]]; then
        USERNAME="$(cut -d: -f1 "$htpasswd_file" 2>/dev/null || echo "$DEFAULT_USERNAME")"
    else
        USERNAME="$DEFAULT_USERNAME"
    fi
    
    info "Current configuration for $config_basename:"
    info "  App Port: $APP_PORT"
    info "  External Port: $EXT_PORT"
    info "  Username: $USERNAME"
    echo
    
    echo "What would you like to modify?"
    menu_item "1) Change app port"
    menu_item "2) Change external port"
    menu_item "3) Change username"
    menu_item "4) Change password"
    menu_item "5) Regenerate SSL certificate"
    menu_item "0) Back to main menu"
    echo
    
    read -r -p "Select option [0-5]: " mod_choice
    
    case "$mod_choice" in
        1) modify_app_port "$config_file" ;;
        2) modify_external_port "$config_file" ;;
        3) modify_username "$config_file" ;;
        4) modify_password "$config_file" ;;
        5) regenerate_ssl_cert "$config_file" ;;
        0) return ;;
        *) echo "Invalid option. Press Enter to continue..."; read -r ;;
    esac
}

# Remove existing configuration and associated files
menu_remove_config() {
    clear
    menu_header "Remove Configuration"
    echo "============================================================================"
    echo
    
    if ! check_configs_exist; then
        return
    fi
    
    local config_file
    config_file="$(select_config_file)"
    if [[ -z "$config_file" ]]; then
        return
    fi
    
    local config_basename
    config_basename="$(basename "$config_file")"
    
    if [[ "$config_basename" =~ app_([0-9]+)_to_([0-9]+)\.conf ]]; then
        local app_port="${BASH_REMATCH[1]}"
        local ext_port="${BASH_REMATCH[2]}"
    else
        error "Cannot parse configuration file name: $config_basename"
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    warn "This will remove the following files:"
    warn "  - Nginx config: $config_file"
    warn "  - SSL certificate: ${SSL_DIR}/app_${ext_port}.crt"
    warn "  - SSL key: ${SSL_DIR}/app_${ext_port}.key"
    warn "  - htpasswd file: ${HTPASSWD_FILE_BASE}-${app_port}"
    echo
    
    read -r -p "Are you sure you want to remove this configuration? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]([eE][sS])?$ ]]; then
        remove_config_files "$app_port" "$ext_port"
        reload_nginx_safe
        info "Configuration removed successfully!"
    else
        info "Removal cancelled."
    fi
    
    echo "Press Enter to continue..."
    read -r
}

# View detailed configuration file contents
menu_view_config_details() {
    clear
    menu_header "Configuration Details"
    echo "============================================================================"
    echo
    
    if ! check_configs_exist; then
        return
    fi
    
    local config_file
    config_file="$(select_config_file)"
    if [[ -z "$config_file" ]]; then
        return
    fi
    
    local config_basename
    config_basename="$(basename "$config_file")"
    
    info "Configuration file: $config_basename"
    info "Full path: $config_file"
    echo
    
    if [[ -f "$config_file" ]]; then
        echo "Configuration content:"
        echo "----------------------------------------"
        cat "$config_file"
        echo "----------------------------------------"
    else
        error "Configuration file not found!"
    fi
    
    echo
    echo "Press Enter to continue..."
    read -r
}

# Test nginx configuration validity
menu_test_nginx() {
    clear
    menu_header "Test Nginx Configuration"
    echo "============================================================================"
    echo
    
    info "Testing nginx configuration..."
    if nginx -t; then
        info "Nginx configuration test passed!"
    else
        error "Nginx configuration test failed!"
    fi
    
    echo
    echo "Press Enter to continue..."
    read -r
}

# Reload nginx service safely
menu_reload_nginx() {
    clear
    menu_header "Reload Nginx"
    echo "============================================================================"
    echo
    
    info "Reloading nginx..."
    if reload_nginx_safe; then
        info "Nginx reloaded successfully!"
    else
        error "Failed to reload nginx!"
    fi
    
    echo
    echo "Press Enter to continue..."
    read -r
}

# Check if any configurations exist and show appropriate message
check_configs_exist() {
    if [[ ! -d "$CONF_DIR" ]]; then
        warn "Nginx configuration directory not found: $CONF_DIR"
        echo "Press Enter to return to main menu..."
        read -r
        return 1
    fi
    
    local configs
    configs=($(find "$CONF_DIR" -name "app_*_to_*.conf" -type f 2>/dev/null | sort))
    
    if [[ ${#configs[@]} -eq 0 ]]; then
        info "No ProxyForge configurations found."
        info "Create a new configuration first using option 1 from the main menu."
        echo
        echo "Press Enter to return to main menu..."
        read -r
        return 1
    fi
    
    return 0
}

# Select configuration file from available options
select_config_file() {
    local configs
    configs=($(find "$CONF_DIR" -name "app_*_to_*.conf" -type f 2>/dev/null | sort))
    
    echo "Available configurations:"
    echo
    local i=1
    for config in "${configs[@]}"; do
        local config_basename
        config_basename="$(basename "$config")"
        menu_item "$i) $config_basename"
        ((i++))
    done
    menu_item "0) Cancel"
    echo
    
    while true; do
        read -r -p "Select configuration [0-${#configs[@]}]: " choice
        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#configs[@]} ]]; then
            echo "${configs[$((choice-1))]}"
            return
        else
            echo "Invalid selection. Please try again."
        fi
    done
}

# ============================================================================
# CONFIGURATION MODIFICATION FUNCTIONS
# ============================================================================

# Modify application port in existing configuration
modify_app_port() {
    local config_file="$1"
    local old_app_port="$APP_PORT"
    
    while true; do
        read -r -p "Enter new app port [current: $APP_PORT]: " new_port
        if [[ -z "$new_port" ]]; then
            info "No changes made."
            echo "Press Enter to continue..."
            read -r
            return
        elif [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]]; then
            APP_PORT="$new_port"
            break
        else
            echo "Please enter a valid port number (1-65535)."
        fi
    done
    
    sed -i "s|proxy_pass http://127.0.0.1:${old_app_port};|proxy_pass http://127.0.0.1:${APP_PORT};|" "$config_file"
    
    local old_htpasswd="${HTPASSWD_FILE_BASE}-${old_app_port}"
    local new_htpasswd="${HTPASSWD_FILE_BASE}-${APP_PORT}"
    if [[ -f "$old_htpasswd" ]]; then
        mv "$old_htpasswd" "$new_htpasswd"
    fi
    
    sed -i "s|auth_basic_user_file ${old_htpasswd};|auth_basic_user_file ${new_htpasswd};|" "$config_file"
    
    reload_nginx_safe
    info "App port updated to $APP_PORT"
    echo "Press Enter to continue..."
    read -r
}

# Modify external port in existing configuration
modify_external_port() {
    local config_file="$1"
    local old_ext_port="$EXT_PORT"
    
    while true; do
        read -r -p "Enter new external port [current: $EXT_PORT]: " new_port
        if [[ -z "$new_port" ]]; then
            info "No changes made."
            echo "Press Enter to continue..."
            read -r
            return
        elif [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]]; then
            EXT_PORT="$new_port"
            break
        else
            echo "Please enter a valid port number (1-65535)."
        fi
    done
    
    sed -i "s|listen 0.0.0.0:${old_ext_port} ssl http2;|listen 0.0.0.0:${EXT_PORT} ssl http2;|" "$config_file"
    
    local old_crt="${SSL_DIR}/app_${old_ext_port}.crt"
    local old_key="${SSL_DIR}/app_${old_ext_port}.key"
    local new_crt="${SSL_DIR}/app_${EXT_PORT}.crt"
    local new_key="${SSL_DIR}/app_${EXT_PORT}.key"
    
    if [[ -f "$old_crt" ]]; then
        mv "$old_crt" "$new_crt"
    fi
    if [[ -f "$old_key" ]]; then
        mv "$old_key" "$new_key"
    fi
    
    sed -i "s|ssl_certificate ${old_crt};|ssl_certificate ${new_crt};|" "$config_file"
    sed -i "s|ssl_certificate_key ${old_key};|ssl_certificate_key ${new_key};|" "$config_file"
    
    reload_nginx_safe
    info "External port updated to $EXT_PORT"
    echo "Press Enter to continue..."
    read -r
}

# Modify basic auth username in existing configuration
modify_username() {
    local config_file="$1"
    
    read -r -p "Enter new username [current: $USERNAME]: " new_username
    if [[ -z "$new_username" ]]; then
        info "No changes made."
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    USERNAME="$new_username"
    
    prompt_password
    write_htpasswd
    
    info "Username updated to $USERNAME"
    echo "Press Enter to continue..."
    read -r
}

# Modify basic auth password in existing configuration
modify_password() {
    local config_file="$1"
    
    info "Changing password for user: $USERNAME"
    prompt_password
    write_htpasswd
    
    info "Password updated successfully"
    echo "Press Enter to continue..."
    read -r
}

# Regenerate SSL certificate for existing configuration
regenerate_ssl_cert() {
    local config_file="$1"
    
    info "Regenerating SSL certificate for port $EXT_PORT..."
    
    local crt="${SSL_DIR}/app_${EXT_PORT}.crt"
    local key="${SSL_DIR}/app_${EXT_PORT}.key"
    
    rm -f "$crt" "$key"
    generate_self_signed_cert
    
    reload_nginx_safe
    info "SSL certificate regenerated successfully"
    echo "Press Enter to continue..."
    read -r
}

# Remove all configuration files for a proxy
remove_config_files() {
    local app_port="$1"
    local ext_port="$2"
    
    local config_file="${CONF_DIR}/app_${app_port}_to_${ext_port}.conf"
    rm -f "$config_file"
    rm -f "${SSL_DIR}/app_${ext_port}.crt"
    rm -f "${SSL_DIR}/app_${ext_port}.key"
    rm -f "${HTPASSWD_FILE_BASE}-${app_port}"
}

# Safely reload nginx after configuration test
reload_nginx_safe() {
    if nginx -t >/dev/null 2>&1; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload nginx
        elif command -v service >/dev/null 2>&1; then
            service nginx reload || service nginx restart
        elif [[ -x /etc/init.d/nginx ]]; then
            /etc/init.d/nginx reload || /etc/init.d/nginx restart
        fi
        return 0
    else
        error "Nginx configuration test failed. Not reloading."
        return 1
    fi
}

# ============================================================================
# CORE BUSINESS LOGIC
# ============================================================================

# Install nginx and openssl if not present
install_nginx_if_needed() {
    if command -v nginx >/dev/null 2>&1; then
        info "nginx already installed."
        return
    fi

    local pm
    pm="$(detect_pkg_manager)"
    if [[ -z "$pm" ]]; then
        error "No supported package manager found. Install nginx manually and re-run."
        exit 1
    fi

    info "Installing nginx using ${pm}..."
    case "$pm" in
        apt)
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl
            ;;
        dnf)
            dnf install -y nginx openssl
            ;;
        yum)
            yum install -y epel-release || true
            yum install -y nginx openssl
            ;;
        zypper)
            zypper --non-interactive refresh
            zypper --non-interactive install nginx openssl
            ;;
        pacman)
            pacman -Sy --noconfirm nginx openssl
            ;;
        apk)
            apk update
            apk add --no-cache nginx openssl
            ;;
    esac
}

# Validate nginx installation and main configuration
validate_nginx_setup() {
    info "Validating nginx setup..."
    
    if ! command -v nginx >/dev/null 2>&1; then
        error "nginx binary not found in PATH"
        return 1
    fi
    
    info "Testing nginx main configuration..."
    if ! nginx -t 2>/dev/null; then
        error "nginx main configuration is invalid. Showing detailed error:"
        nginx -t
        error "Please fix nginx main configuration before proceeding"
        return 1
    fi
    
    info "nginx main configuration is valid"
    return 0
}

# Start nginx service using available service manager
ensure_nginx_running() {
    info "Checking nginx service status..."
    
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet nginx; then
            info "nginx is already running"
            return 0
        fi
        
        info "Starting nginx service with systemctl..."
        if ! systemctl enable nginx 2>/dev/null; then
            warn "Could not enable nginx service (may already be enabled)"
        fi
        
        if ! systemctl start nginx; then
            error "Failed to start nginx service. Checking status and logs..."
            echo "=== systemctl status nginx ==="
            systemctl status nginx --no-pager -l || true
            echo "=== nginx error log (last 10 lines) ==="
            tail -n 10 /var/log/nginx/error.log 2>/dev/null || echo "No error log found"
            echo "=== nginx configuration test ==="
            nginx -t
            return 1
        fi
    elif command -v service >/dev/null 2>&1; then
        info "Starting nginx service with service command..."
        if ! service nginx start; then
            error "Failed to start nginx with service command. Trying restart..."
            if ! service nginx restart; then
                error "Failed to restart nginx. Checking configuration..."
                nginx -t
                echo "=== nginx error log (last 10 lines) ==="
                tail -n 10 /var/log/nginx/error.log 2>/dev/null || echo "No error log found"
                return 1
            fi
        fi
    elif [[ -x /etc/init.d/nginx ]]; then
        info "Starting nginx service with init.d script..."
        if ! /etc/init.d/nginx start; then
            error "Failed to start nginx with init.d. Trying restart..."
            if ! /etc/init.d/nginx restart; then
                error "Failed to restart nginx. Checking configuration..."
                nginx -t
                echo "=== nginx error log (last 10 lines) ==="
                tail -n 10 /var/log/nginx/error.log 2>/dev/null || echo "No error log found"
                return 1
            fi
        fi
    else
        warn "Could not detect service manager to start nginx. Please start it manually."
        return 1
    fi
    
    info "nginx service started successfully"
    
    sleep 2
    
    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet nginx; then
            error "nginx service started but is not active"
            systemctl status nginx --no-pager -l
            return 1
        fi
    fi
    
    return 0
}

# Prompt for password with confirmation
prompt_password() {
    if [[ "${ASSUME_YES}" == "true" && -z "${BASIC_AUTH_PASSWORD:-}" ]]; then
        BASIC_AUTH_PASSWORD="$(openssl rand -base64 12)"
        info "Generated random password for user '${USERNAME}'"
        return 0
    fi
    
    if [[ -n "${BASIC_AUTH_PASSWORD:-}" ]]; then
        return 0
    fi
    
    local pass pass2
    while true; do
        read -r -s -p "Enter password for basic auth user '${USERNAME}': " pass || { echo; error "Failed to read password input"; exit 1; }; echo
        read -r -s -p "Confirm password: " pass2 || { echo; error "Failed to read password confirmation"; exit 1; }; echo
        if [[ "$pass" != "$pass2" ]]; then
            echo "Passwords do not match. Try again."
        elif [[ -z "$pass" ]]; then
            echo "Password cannot be empty."
        else
            BASIC_AUTH_PASSWORD="$pass"
            break
        fi
    done
}

# Generate htpasswd file for basic authentication
write_htpasswd() {
    local file="${HTPASSWD_FILE_BASE}-${APP_PORT}"
    local hash
    hash="$(openssl passwd -apr1 "${BASIC_AUTH_PASSWORD}")"
    printf "%s:%s\n" "${USERNAME}" "${hash}" > "${file}"
    chmod 644 "${file}"
    chown root:www-data "${file}" || true
    info "Wrote htpasswd file: ${file}"
    
    if [[ "${ASSUME_YES}" == "true" ]]; then
        info "Basic auth credentials - Username: ${USERNAME}, Password: ${BASIC_AUTH_PASSWORD}"
    fi
}

# Create required directories with proper permissions
ensure_dirs() {
    info "Creating required directories..."
    
    if ! mkdir -p "${CONF_DIR}"; then
        error "Failed to create nginx config directory: ${CONF_DIR}"
        return 1
    fi
    
    if ! mkdir -p "${SSL_DIR}"; then
        error "Failed to create SSL directory: ${SSL_DIR}"
        return 1
    fi
    
    chmod 755 "${CONF_DIR}" 2>/dev/null || true
    chmod 755 "${SSL_DIR}" 2>/dev/null || true
    
    if [[ ! -w "${CONF_DIR}" ]]; then
        error "Cannot write to nginx config directory: ${CONF_DIR}"
        return 1
    fi
    
    if [[ ! -w "${SSL_DIR}" ]]; then
        error "Cannot write to SSL directory: ${SSL_DIR}"
        return 1
    fi
    
    info "Directories created successfully"
    return 0
}

# Remove standard nginx default configurations that cause conflicts
disable_default_nginx_configs() {
    info "Removing standard nginx default configurations..."
    
    local configs_removed=false
    
    if [[ -f "/etc/nginx/sites-enabled/default" ]]; then
        info "Removing /etc/nginx/sites-enabled/default"
        rm -f "/etc/nginx/sites-enabled/default"
        configs_removed=true
    fi
    
    if [[ -f "/etc/nginx/conf.d/default.conf" ]]; then
        info "Removing /etc/nginx/conf.d/default.conf"
        rm -f "/etc/nginx/conf.d/default.conf"
        configs_removed=true
    fi
    
    if [[ "$configs_removed" == "true" ]]; then
        info "Default configurations removed"
    else
        info "No default configurations found"
    fi
}

# Check for common nginx setup issues
check_nginx_prerequisites() {
    info "Checking nginx prerequisites..."
    
    if [[ "$(id -u)" -ne 0 ]]; then
        error "This script must be run as root for nginx configuration"
        return 1
    fi
    
    if [[ ! -d "/etc/nginx" ]]; then
        error "nginx configuration directory /etc/nginx does not exist"
        error "nginx may not be properly installed"
        return 1
    fi
    
    if [[ ! -f "/etc/nginx/nginx.conf" ]]; then
        error "nginx main configuration file /etc/nginx/nginx.conf not found"
        return 1
    fi
    
    if [[ ! -d "/etc/nginx/conf.d" ]]; then
        info "Creating /etc/nginx/conf.d directory..."
        if ! mkdir -p "/etc/nginx/conf.d"; then
            error "Failed to create /etc/nginx/conf.d directory"
            return 1
        fi
    fi
    
    if ! grep -q "include.*conf\.d.*\.conf" /etc/nginx/nginx.conf; then
        warn "nginx.conf may not include files from conf.d directory"
        warn "You may need to add: include /etc/nginx/conf.d/*.conf;"
    fi
    
    info "nginx prerequisites check passed"
    return 0
}

# Generate or use existing SSL certificate
generate_self_signed_cert() {
    local crt="${SSL_DIR}/app_${EXT_PORT}.crt"
    local key="${SSL_DIR}/app_${EXT_PORT}.key"

    if [[ -n "${CERT_PATH}" && -n "${KEY_PATH}" ]]; then
        info "Using provided certificate and key."
        ln -sf "$(readlink -f "${CERT_PATH}")" "${crt}"
        ln -sf "$(readlink -f "${KEY_PATH}")" "${key}"
    else
        if [[ -f "${crt}" && -f "${key}" ]]; then
            info "Existing self-signed certificate found for port ${EXT_PORT}."
        else
            info "Generating self-signed certificate (CN=localhost) for port ${EXT_PORT}..."
            openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
                -keyout "${key}" -out "${crt}" \
                -subj "/CN=localhost"
            chmod 600 "${key}"
            chmod 644 "${crt}"
        fi
    fi

    CERT_PATH="${crt}"
    KEY_PATH="${key}"
}

# Generate nginx configuration file
write_nginx_conf() {
    local conf_path="${CONF_DIR}/${CONF_NAME}"
    local htfile="${HTPASSWD_FILE_BASE}-${APP_PORT}"

    if [[ -f "${conf_path}" && "${ASSUME_YES}" != "true" ]]; then
        confirm_or_exit "Config ${conf_path} exists. Overwrite?"
    fi

    info "Writing nginx configuration to ${conf_path}..."
    
    if [[ ! -f "${CERT_PATH}" ]]; then
        error "SSL certificate not found: ${CERT_PATH}"
        return 1
    fi
    
    if [[ ! -f "${KEY_PATH}" ]]; then
        error "SSL key not found: ${KEY_PATH}"
        return 1
    fi
    
    if [[ ! -f "${htfile}" ]]; then
        error "htpasswd file not found: ${htfile}"
        return 1
    fi

    cat > "${conf_path}" <<EOF
server {
    listen 0.0.0.0:${EXT_PORT} ssl http2;
    server_name _;

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000" always;

    auth_basic "Restricted";
    auth_basic_user_file ${htfile};

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_cache_bypass \$http_upgrade;
        
        proxy_buffering off;
        proxy_read_timeout 86400;
    }
}
EOF

    info "Testing nginx configuration..."
    if ! nginx -t; then
        error "nginx configuration test failed!"
        return 1
    fi
    
    info "Reloading nginx with new configuration..."
    if ! reload_nginx_safe; then
        error "Failed to reload nginx!"
        return 1
    fi

    info "Wrote nginx config: ${conf_path}"
    info "Reverse proxy available at: https://<your-host>:${EXT_PORT}/ (self-signed cert)"
}

# Check for port conflicts before binding
check_port_conflict() {
    info "Checking for port conflicts on port ${EXT_PORT}..."
    
    local conflict_found=false
    local listening_process=""
    
    if command -v ss >/dev/null 2>&1; then
        listening_process=$(ss -tulpn | grep -E "LISTEN.+:${EXT_PORT}\b" || true)
        if [[ -n "$listening_process" ]]; then
            conflict_found=true
        fi
    elif command -v netstat >/dev/null 2>&1; then
        listening_process=$(netstat -tulpn | grep -E "LISTEN.+:${EXT_PORT}\b" || true)
        if [[ -n "$listening_process" ]]; then
            conflict_found=true
        fi
    else
        warn "Cannot check for port conflicts - neither ss nor netstat available"
        return 0
    fi
    
    if [[ "$conflict_found" == "true" ]]; then
        error "Port ${EXT_PORT} is already in use:"
        echo "$listening_process"
        error "nginx will fail to bind to this port. Please choose a different port or stop the conflicting service."
        return 1
    else
        info "Port ${EXT_PORT} is available"
        return 0
    fi
}

# ============================================================================
# MAIN EXECUTION LOGIC
# ============================================================================

# Main execution function
main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        exit 0
    fi
    
    require_linux
    require_root "$@"
    parse_args "$@"

    info "App port: ${APP_PORT}"
    info "External HTTPS port: ${EXT_PORT}"
    info "Username: ${USERNAME}"

    install_nginx_if_needed
    
    disable_default_nginx_configs
    
    if ! check_nginx_prerequisites; then
        error "nginx prerequisites check failed. Cannot proceed."
        exit 1
    fi
    
    if ! ensure_dirs; then
        error "Failed to create required directories. Cannot proceed."
        exit 1
    fi
    
    if ! validate_nginx_setup; then
        error "nginx setup validation failed. Cannot proceed."
        exit 1
    fi
    
    if ! check_port_conflict; then
        error "Cannot proceed due to port conflict. Exiting."
        exit 1
    fi
    
    if ! ensure_nginx_running; then
        error "Failed to start nginx service. Cannot proceed."
        exit 1
    fi
    
    prompt_password
    write_htpasswd
    generate_self_signed_cert
    
    if ! write_nginx_conf; then
        error "Failed to write nginx configuration. Exiting."
        exit 1
    fi
    
    # Always configure firewall (default to localhost if not specified)
    if [[ -z "$APP_BINDING" ]]; then
        APP_BINDING="localhost"
    fi
    configure_firewall "$APP_PORT" "$EXT_PORT" "$APP_BINDING"

    info "Done. Configuration created successfully!"
    
    if [[ "$APP_BINDING" == "0.0.0.0" ]]; then
        echo
        info "Security Summary:"
        info "  ✓ Direct access to port ${APP_PORT} is now BLOCKED"
        info "  ✓ Authenticated access available on port ${EXT_PORT}"
        info "  ✓ Your app is now protected with basic authentication"
    fi
}

main "$@"