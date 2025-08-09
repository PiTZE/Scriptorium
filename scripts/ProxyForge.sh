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

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

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

error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
menu_header() { echo -e "${CYAN}[MENU]${NC} $*"; }
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
    info "No arguments provided. Starting interactive setup..."
    echo
    
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
    info "  Local app port: ${APP_PORT}"
    info "  External HTTPS port: ${EXT_PORT}"
    info "  Basic auth username: ${USERNAME}"
    info "  Nginx config file: app_${APP_PORT}_to_${EXT_PORT}.conf"
    echo
    
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

# ============================================================================
# MENU SYSTEM FUNCTIONS
# ============================================================================

# Display ASCII art banner
draw_ascii_art() {
    echo -e "

░▒▓███████▓▒░  ░▒▓█▓▒░       ░▒▓████████▓▒░ ░▒▓████████▓▒░ ░▒▓████████▓▒░
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░            ░▒▓█▓▒░ ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░          ░▒▓██▓▒░  ░▒▓█▓▒░
░▒▓███████▓▒░  ░▒▓█▓▒░          ░▒▓█▓▒░        ░▒▓██▓▒░    ░▒▓██████▓▒░
░▒▓█▓▒░        ░▒▓█▓▒░          ░▒▓█▓▒░      ░▒▓██▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░        ░▒▓█▓▒░          ░▒▓█▓▒░     ░▒▓█▓▒░        ░▒▓█▓▒░
░▒▓█▓▒░        ░▒▓█▓▒░          ░▒▓█▓▒░     ░▒▓████████▓▒░ ░▒▓████████▓▒░
                                                                                                                                                                                                
"
}

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
            0) echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid option. Press Enter to continue..."; read -r ;;
        esac
    done
}

# Setup new proxy configuration
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
    
    check_port_conflict
    install_nginx_if_needed
    ensure_dirs
    ensure_nginx_running
    write_htpasswd
    generate_self_signed_cert
    write_nginx_conf
    
    info "Configuration created successfully!"
    echo "Press Enter to return to menu..."
    read -r
}

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
        printf "%-5s %-30s %-10s %-10s %-15s\n" "No." "Config File" "App Port" "Ext Port" "Status"
        echo "------------------------------------------------------------------------"
        
        local i=1
        for config in "${configs[@]}"; do
            local basename
            basename="$(basename "$config")"
            local app_port ext_port
            
            if [[ "$basename" =~ app_([0-9]+)_to_([0-9]+)\.conf ]]; then
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
            
            printf "%-5s %-30s %-10s %-10s %-15s\n" "$i" "$basename" "$app_port" "$ext_port" "$status"
            ((i++))
        done
    fi
    
    echo
    echo "Press Enter to continue..."
    read -r
}

menu_modify_config() {
    clear
    menu_header "Modify Existing Configuration"
    echo "============================================================================"
    echo
    
    local config_file
    config_file="$(select_config_file)"
    if [[ -z "$config_file" ]]; then
        return
    fi
    
    local basename
    basename="$(basename "$config_file")"
    
    if [[ "$basename" =~ app_([0-9]+)_to_([0-9]+)\.conf ]]; then
        APP_PORT="${BASH_REMATCH[1]}"
        EXT_PORT="${BASH_REMATCH[2]}"
    else
        error "Cannot parse configuration file name: $basename"
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
    
    info "Current configuration for $basename:"
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

menu_remove_config() {
    clear
    menu_header "Remove Configuration"
    echo "============================================================================"
    echo
    
    local config_file
    config_file="$(select_config_file)"
    if [[ -z "$config_file" ]]; then
        return
    fi
    
    local basename
    basename="$(basename "$config_file")"
    
    if [[ "$basename" =~ app_([0-9]+)_to_([0-9]+)\.conf ]]; then
        local app_port="${BASH_REMATCH[1]}"
        local ext_port="${BASH_REMATCH[2]}"
    else
        error "Cannot parse configuration file name: $basename"
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

menu_view_config_details() {
    clear
    menu_header "Configuration Details"
    echo "============================================================================"
    echo
    
    local config_file
    config_file="$(select_config_file)"
    if [[ -z "$config_file" ]]; then
        return
    fi
    
    local basename
    basename="$(basename "$config_file")"
    
    info "Configuration file: $basename"
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

select_config_file() {
    local configs
    configs=($(find "$CONF_DIR" -name "app_*_to_*.conf" -type f 2>/dev/null | sort))
    
    if [[ ${#configs[@]} -eq 0 ]]; then
        warn "No ProxyForge configurations found."
        echo "Press Enter to continue..."
        read -r
        return
    fi
    
    echo "Available configurations:"
    echo
    local i=1
    for config in "${configs[@]}"; do
        local basename
        basename="$(basename "$config")"
        menu_item "$i) $basename"
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

modify_password() {
    local config_file="$1"
    
    info "Changing password for user: $USERNAME"
    prompt_password
    write_htpasswd
    
    info "Password updated successfully"
    echo "Press Enter to continue..."
    read -r
}

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

# Start nginx service using available service manager
ensure_nginx_running() {
    info "Checking nginx service status..."
    
    if command -v systemctl >/dev/null 2>&1; then
        # Check if nginx is already running
        if systemctl is-active --quiet nginx; then
            info "nginx is already running"
            return 0
        fi
        
        info "Starting nginx service with systemctl..."
        if ! systemctl enable --now nginx; then
            error "Failed to enable and start nginx. Checking status..."
            systemctl status nginx --no-pager -l
            error "Checking nginx configuration..."
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
                return 1
            fi
        fi
    else
        warn "Could not detect service manager to start nginx. Please start it manually."
        return 1
    fi
    
    info "nginx service started successfully"
}

# Prompt for password with confirmation
prompt_password() {
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
    chmod 640 "${file}"
    chown root:root "${file}" || true
    info "Wrote htpasswd file: ${file}"
}

# Create required directories
ensure_dirs() {
    mkdir -p "${CONF_DIR}"
    mkdir -p "${SSL_DIR}"
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
    
    # Verify required files exist before writing config
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
        proxy_buffering off;
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

    # Check for port conflicts first - exit if conflict found
    if ! check_port_conflict; then
        error "Cannot proceed due to port conflict. Exiting."
        exit 1
    fi
    
    install_nginx_if_needed
    ensure_dirs
    
    # Start nginx service before creating configuration
    if ! ensure_nginx_running; then
        error "Failed to start nginx service. Cannot proceed."
        exit 1
    fi
    
    prompt_password
    write_htpasswd
    generate_self_signed_cert
    
    # Write configuration and reload nginx
    if ! write_nginx_conf; then
        error "Failed to write nginx configuration. Exiting."
        exit 1
    fi

    info "Done. Configuration created successfully!"
}

main "$@"