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
Usage: nginx_https_proxy_setup.sh [options]

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
USAGE
}

error() { echo "[ERROR] $*" >&2; }
info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    error "This script must be run with root privileges. Re-run with: sudo $0 $*"
    exit 1
  }
}

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    error "This script supports Linux only. Detected: $(uname -s)"
    exit 1
  }
}

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
    interactive_setup
  fi

  if [[ -z "${EXT_PORT}" ]]; then
    EXT_PORT="${APP_PORT}"
  fi

  if [[ -z "${CONF_NAME}" ]]; then
    CONF_NAME="app_${APP_PORT}_to_${EXT_PORT}.conf"
  fi
}

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
# CORE BUSINESS LOGIC
# ============================================================================

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

ensure_nginx_running() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now nginx || systemctl restart nginx
  elif command -v service >/dev/null 2>&1; then
    service nginx start || service nginx restart
  elif [[ -x /etc/init.d/nginx ]]; then
    /etc/init.d/nginx start || /etc/init.d/nginx restart
  else
    warn "Could not detect service manager to start nginx. Please start it manually."
  fi
}

prompt_password() {
  local pass pass2
  while true; do
    if [[ "${ASSUME_YES}" == "true" && -n "${BASIC_AUTH_PASSWORD:-}" ]]; then
      pass="$BASIC_AUTH_PASSWORD"
      pass2="$BASIC_AUTH_PASSWORD"
    else
      read -r -s -p "Enter password for basic auth user '${USERNAME}': " pass; echo
      read -r -s -p "Confirm password: " pass2; echo
    fi
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

write_htpasswd() {
  local file="${HTPASSWD_FILE_BASE}-${APP_PORT}"
  local hash
  hash="$(openssl passwd -apr1 "${BASIC_AUTH_PASSWORD}")"
  printf "%s:%s\n" "${USERNAME}" "${hash}" > "${file}"
  chmod 640 "${file}"
  chown root:root "${file}" || true
  info "Wrote htpasswd file: ${file}"
}

ensure_dirs() {
  mkdir -p "${CONF_DIR}"
  mkdir -p "${SSL_DIR}"
}

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

write_nginx_conf() {
  local conf_path="${CONF_DIR}/${CONF_NAME}"
  local htfile="${HTPASSWD_FILE_BASE}-${APP_PORT}"

  if [[ -f "${conf_path}" && "${ASSUME_YES}" != "true" ]]; then
    confirm_or_exit "Config ${conf_path} exists. Overwrite?"
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

  nginx -t
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx
  elif command -v service >/dev/null 2>&1; then
    service nginx reload || service nginx restart
  elif [[ -x /etc/init.d/nginx ]]; then
    /etc/init.d/nginx reload || /etc/init.d/nginx restart
  fi

  info "Wrote nginx config: ${conf_path}"
  info "Reverse proxy available at: https://<your-host>:${EXT_PORT}/ (self-signed cert)"
}

check_port_conflict() {
  if command -v ss >/dev/null 2>&1; then
    if ss -tulpn | grep -E "LISTEN.+:${EXT_PORT}\b" >/dev/null 2>&1; then
      warn "Something is already listening on port ${EXT_PORT}. Nginx may fail to bind."
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tulpn | grep -E "LISTEN.+:${EXT_PORT}\b" >/dev/null 2>&1; then
      warn "Something is already listening on port ${EXT_PORT}. Nginx may fail to bind."
    fi
  fi
}

# ============================================================================
# MAIN EXECUTION LOGIC
# ============================================================================

main() {
  require_linux
  require_root "$@"
  parse_args "$@"

  info "App port: ${APP_PORT}"
  info "External HTTPS port: ${EXT_PORT}"
  info "Username: ${USERNAME}"

  check_port_conflict
  install_nginx_if_needed
  ensure_dirs
  ensure_nginx_running
  prompt_password
  write_htpasswd
  generate_self_signed_cert
  write_nginx_conf

  info "Done."
}

main "$@"