# Scriptorium

A collection of utility scripts for my stuff.

## Scripts

### ProxyForge

Automatically sets up a secure HTTPS reverse proxy with basic authentication using nginx.

**Features:**
- Installs nginx, ufw and their dependencies
- Generates self-signed SSL certificates (or uses provided ones)
- Configures basic authentication
- Sets up secure reverse proxy with modern SSL settings

**Quick Install & Run:**
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PiTZE/Scriptorium/main/scripts/ProxyForge.sh)"
```

**Usage:**
```bash
# Interactive mode (prompts for configuration)
sudo ./scripts/ProxyForge.sh

# Command-line mode with custom ports and username
sudo ./scripts/ProxyForge.sh -a 3000 -e 8443 -u admin

# Use existing SSL certificate
sudo ./scripts/ProxyForge.sh --cert /path/to/cert.pem --key /path/to/key.pem

# Non-interactive mode (skip prompts)
sudo ./scripts/ProxyForge.sh -a 8080 -e 443 -y
```

**Interactive Setup:**
When run without arguments, ProxyForge will guide you through an interactive setup:
- Prompts for local application port
- Prompts for external HTTPS port
- Prompts for basic auth username
- Shows configuration summary before proceeding
- Confirms setup before making system changes

## Requirements

- Linux (Ubuntu, CentOS, RHEL, SUSE, Arch, Alpine)
- Root privileges (sudo)
- Internet connection for package installation

## License

MIT License - see [LICENSE](LICENSE) file for details.