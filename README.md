# Scriptorium

A collection of utility scripts for system administration and automation.

## Scripts

### ProxyForge

Automatically sets up a secure HTTPS reverse proxy with basic authentication using nginx.

**Features:**
- Installs nginx and dependencies
- Generates self-signed SSL certificates (or uses provided ones)
- Configures basic authentication
- Sets up secure reverse proxy with modern SSL settings

**Quick Install & Run:**
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PiTZE/Scriptorium/main/scripts/ProxyForge.sh)"
```

**Usage:**
```bash
# Basic usage (proxies port 7314 to HTTPS)
sudo ./scripts/ProxyForge.sh

# Custom ports and username
sudo ./scripts/ProxyForge.sh -a 3000 -e 8443 -u admin

# Use existing SSL certificate
sudo ./scripts/ProxyForge.sh --cert /path/to/cert.pem --key /path/to/key.pem
```

## Requirements

- Linux (Ubuntu, CentOS, RHEL, SUSE, Arch, Alpine)
- Root privileges (sudo)
- Internet connection for package installation

## License

MIT License - see [LICENSE](LICENSE) file for details.