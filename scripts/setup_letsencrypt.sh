#!/bin/bash
# =============================================================================
# Let's Encrypt Certificate Setup Script for RemotePrompt Server
# Uses Cloudflare DNS-01 challenge for certificate validation
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="${PROJECT_ROOT}/certs/commercial"
CERTBOT_CONFIG_DIR="${PROJECT_ROOT}/certs/config"

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$*${NC}"
}

print_info() { print_msg "$BLUE" "[INFO] $*"; }
print_success() { print_msg "$GREEN" "[SUCCESS] $*"; }
print_warning() { print_msg "$YELLOW" "[WARNING] $*"; }
print_error() { print_msg "$RED" "[ERROR] $*"; }

# Check if running on macOS or Linux
check_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    else
        print_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
    print_info "Detected OS: $OS"
}

# Install certbot if not present
install_certbot() {
    if command -v certbot &> /dev/null; then
        print_info "certbot is already installed"
        return
    fi

    print_info "Installing certbot..."

    if [[ "$OS" == "macos" ]]; then
        if ! command -v brew &> /dev/null; then
            print_error "Homebrew is required. Install from https://brew.sh"
            exit 1
        fi
        brew install certbot
    else
        # Linux (Debian/Ubuntu)
        sudo apt-get update
        sudo apt-get install -y certbot
    fi

    print_success "certbot installed"
}

# Install Cloudflare DNS plugin
install_cloudflare_plugin() {
    if pip3 show certbot-dns-cloudflare &> /dev/null; then
        print_info "certbot-dns-cloudflare is already installed"
        return
    fi

    print_info "Installing certbot-dns-cloudflare plugin..."
    pip3 install certbot-dns-cloudflare
    print_success "Cloudflare plugin installed"
}

# Setup Cloudflare credentials
setup_cloudflare_credentials() {
    local creds_file="${PROJECT_ROOT}/secrets/cloudflare.ini"

    if [[ -f "$creds_file" ]]; then
        print_info "Cloudflare credentials file already exists"
        return
    fi

    print_info "Setting up Cloudflare credentials..."

    mkdir -p "${PROJECT_ROOT}/secrets"

    echo ""
    print_warning "You need a Cloudflare API Token with the following permissions:"
    echo "  - Zone:DNS:Edit"
    echo "  - Zone:Zone:Read"
    echo ""
    echo "Create one at: https://dash.cloudflare.com/profile/api-tokens"
    echo ""

    read -p "Enter your Cloudflare API Token: " -s cf_token
    echo ""

    if [[ -z "$cf_token" ]]; then
        print_error "API Token cannot be empty"
        exit 1
    fi

    cat > "$creds_file" << EOF
# Cloudflare API Token
# Created: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
dns_cloudflare_api_token = ${cf_token}
EOF

    chmod 600 "$creds_file"
    print_success "Credentials saved to $creds_file"
}

# Request certificate
request_certificate() {
    local domain=$1
    local email=$2
    local creds_file="${PROJECT_ROOT}/secrets/cloudflare.ini"

    print_info "Requesting certificate for: $domain"

    mkdir -p "$CERT_DIR"
    mkdir -p "$CERTBOT_CONFIG_DIR"

    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$creds_file" \
        --dns-cloudflare-propagation-seconds 60 \
        --config-dir "$CERTBOT_CONFIG_DIR" \
        --work-dir "${PROJECT_ROOT}/certs/work" \
        --logs-dir "${PROJECT_ROOT}/logs/certbot" \
        --email "$email" \
        --agree-tos \
        --no-eff-email \
        --domain "$domain" \
        --non-interactive

    # Create symlinks to the live certificates
    ln -sf "${CERTBOT_CONFIG_DIR}/live/${domain}/fullchain.pem" "${CERT_DIR}/fullchain.pem"
    ln -sf "${CERTBOT_CONFIG_DIR}/live/${domain}/privkey.pem" "${CERT_DIR}/privkey.pem"

    print_success "Certificate obtained successfully!"
    print_info "Certificate location: ${CERTBOT_CONFIG_DIR}/live/${domain}/"
}

# Update .env file
update_env_file() {
    local domain=$1
    local env_file="${PROJECT_ROOT}/.env"

    print_info "Updating .env configuration..."

    if [[ ! -f "$env_file" ]]; then
        cp "${PROJECT_ROOT}/.env.example" "$env_file"
    fi

    # Update SSL mode
    if grep -q "^SSL_MODE=" "$env_file"; then
        sed -i.bak "s|^SSL_MODE=.*|SSL_MODE=commercial|" "$env_file"
    else
        echo "SSL_MODE=commercial" >> "$env_file"
    fi

    # Update certificate paths
    if grep -q "^COMMERCIAL_CERT_PATH=" "$env_file"; then
        sed -i.bak "s|^COMMERCIAL_CERT_PATH=.*|COMMERCIAL_CERT_PATH=./certs/commercial/fullchain.pem|" "$env_file"
    else
        echo "COMMERCIAL_CERT_PATH=./certs/commercial/fullchain.pem" >> "$env_file"
    fi

    if grep -q "^COMMERCIAL_KEY_PATH=" "$env_file"; then
        sed -i.bak "s|^COMMERCIAL_KEY_PATH=.*|COMMERCIAL_KEY_PATH=./certs/commercial/privkey.pem|" "$env_file"
    else
        echo "COMMERCIAL_KEY_PATH=./certs/commercial/privkey.pem" >> "$env_file"
    fi

    # Update hostname
    if grep -q "^SERVER_HOSTNAME=" "$env_file"; then
        sed -i.bak "s|^SERVER_HOSTNAME=.*|SERVER_HOSTNAME=${domain}|" "$env_file"
    fi

    rm -f "${env_file}.bak"
    print_success ".env updated with commercial certificate settings"
}

# Setup auto-renewal cron job
setup_renewal() {
    print_info "Setting up certificate auto-renewal..."

    local renew_script="${SCRIPT_DIR}/renew_certificate.sh"

    cat > "$renew_script" << 'EOF'
#!/bin/bash
# Auto-renewal script for Let's Encrypt certificates

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTBOT_CONFIG_DIR="${PROJECT_ROOT}/certs/config"

certbot renew \
    --config-dir "$CERTBOT_CONFIG_DIR" \
    --work-dir "${PROJECT_ROOT}/certs/work" \
    --logs-dir "${PROJECT_ROOT}/logs/certbot" \
    --quiet

# Restart server if certificate was renewed
if [[ $? -eq 0 ]]; then
    echo "[$(date)] Certificate renewal check completed"
fi
EOF

    chmod +x "$renew_script"

    print_success "Renewal script created: $renew_script"
    print_info "Add to crontab for automatic renewal:"
    echo ""
    echo "  # Run twice daily (recommended by Let's Encrypt)"
    echo "  0 0,12 * * * ${renew_script} >> ${PROJECT_ROOT}/logs/renewal.log 2>&1"
    echo ""
}

# Main
main() {
    echo ""
    echo "=============================================="
    echo " Let's Encrypt Certificate Setup"
    echo " with Cloudflare DNS-01 Challenge"
    echo "=============================================="
    echo ""

    check_os

    # Check arguments
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <domain> <email>"
        echo ""
        echo "Example:"
        echo "  $0 remoteprompt.example.com admin@example.com"
        echo ""
        exit 1
    fi

    local domain=$1
    local email=$2

    print_info "Domain: $domain"
    print_info "Email: $email"
    echo ""

    # Create required directories
    mkdir -p "${PROJECT_ROOT}/logs/certbot"
    mkdir -p "${PROJECT_ROOT}/certs/work"

    # Install dependencies
    install_certbot
    install_cloudflare_plugin

    # Setup credentials
    setup_cloudflare_credentials

    # Request certificate
    request_certificate "$domain" "$email"

    # Update configuration
    update_env_file "$domain"

    # Setup renewal
    setup_renewal

    echo ""
    print_success "=============================================="
    print_success " Setup Complete!"
    print_success "=============================================="
    echo ""
    echo "Next steps:"
    echo "  1. Restart the server: python main.py"
    echo "  2. Your server will now use the commercial certificate"
    echo "  3. Set up the cron job for auto-renewal"
    echo ""
}

main "$@"
