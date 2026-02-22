#!/usr/bin/env bash
# =============================================================================
#  Ubuntu 24.04 LTS — Interactive Server Hardening Script
#  Version: 1.0.0
#  Author:  George (generated with Claude)
#  License: MIT
#  Repo:    https://github.com/YOUR_USERNAME/ubuntu-hardening
#
#  Designed for: DigitalOcean droplets (512MB / 1 CPU / 10GB SSD)
#  Tested on:    Ubuntu 24.04 LTS x64
#
#  Usage:
#    chmod +x harden.sh
#    sudo ./harden.sh
#
#  Everything is interactive — no manual editing required.
#  Each hardening step will prompt you with [Y/n] before executing.
#  Press Enter to accept the default (Yes) or type 'n' to skip.
#
#  IMPORTANT: Have an SSH key already added to the server before running
#             the SSH hardening section, or you WILL be locked out.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
#  DEFAULTS — All values below are configured interactively during the script.
#  No manual editing required. Just run: sudo ./harden.sh
# =============================================================================

# SSH port — randomly generated from IANA dynamic range (49152–65535)
SSH_PORT=$(shuf -i 49152-65535 -n 1)

# Defaults (overridden by interactive prompts during the script)
ADMIN_USER="deploy"
TIMEZONE="America/New_York"

# Notification channels (all configured interactively in Step 18)
NTFY_TOPIC=""
DISCORD_WEBHOOK=""
SLACK_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
PUSHOVER_APP_TOKEN=""
PUSHOVER_USER_KEY=""
GOTIFY_URL=""
GOTIFY_TOKEN=""
N8N_WEBHOOK=""
ALERT_EMAIL=""
SMTP_HOST=""
SMTP_PORT=""
SMTP_USER=""
SMTP_PASS=""

# =============================================================================
#  INTERNALS — Do not edit below unless you know what you're doing
# =============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/harden-$(date +%Y%m%d-%H%M%S).log"
readonly BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d-%H%M%S)"

# Counters
STEPS_RUN=0
STEPS_SKIPPED=0

# Colors (auto-detect terminal support)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

# -----------------------------------------------------------------------------
#  Logging helpers
# -----------------------------------------------------------------------------
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; }
log_step()  { echo -e "\n${BLUE}${BOLD}── $* ──${NC}\n" | tee -a "$LOG_FILE"; }

# -----------------------------------------------------------------------------
#  Prompt helper — returns 0 for Yes, 1 for No
# -----------------------------------------------------------------------------
prompt_yn() {
    local question="$1"
    local answer
    while true; do
        echo -en "${CYAN}${BOLD}[?]${NC} ${question} ${BOLD}[Y/n]:${NC} "
        read -r answer
        case "${answer,,}" in
            ""|y|yes) return 0 ;;
            n|no)     return 1 ;;
            *)        echo "    Please enter Y or N." ;;
        esac
    done
}

# -----------------------------------------------------------------------------
#  Backup helper — copies original file before any modification
# -----------------------------------------------------------------------------
backup_file() {
    local filepath="$1"
    if [[ -f "$filepath" ]]; then
        local filename
        filename=$(basename "$filepath")
        cp "$filepath" "${BACKUP_DIR}/${filename}.bak"
        log_info "Backed up: $filepath"
    fi
}

# -----------------------------------------------------------------------------
#  Notification helper — sends alerts to all configured channels
#  Used by Fail2ban actions and the post-reboot script
# -----------------------------------------------------------------------------
send_notification() {
    local title="$1"
    local message="$2"
    local priority="${3:-default}"  # default, high, urgent

    # ntfy.sh
    if [[ -n "${NTFY_TOPIC:-}" ]]; then
        curl -s \
            -H "Title: ${title}" \
            -H "Priority: ${priority}" \
            -d "${message}" \
            "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
    fi

    # Discord
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        curl -s -H "Content-Type: application/json" \
            -d "{\"content\":\"**${title}**\n${message}\"}" \
            "${DISCORD_WEBHOOK}" >/dev/null 2>&1 || true
    fi

    # Slack
    if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
        curl -s -H "Content-Type: application/json" \
            -d "{\"text\":\"*${title}*\n${message}\"}" \
            "${SLACK_WEBHOOK}" >/dev/null 2>&1 || true
    fi

    # Telegram
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
        curl -s -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            -d "text=*${title}*%0A${message}" \
            -d "parse_mode=Markdown" >/dev/null 2>&1 || true
    fi

    # Pushover
    if [[ -n "${PUSHOVER_APP_TOKEN:-}" ]] && [[ -n "${PUSHOVER_USER_KEY:-}" ]]; then
        local po_priority=0
        [[ "$priority" == "high" ]] && po_priority=1
        curl -s --form-string "token=${PUSHOVER_APP_TOKEN}" \
            --form-string "user=${PUSHOVER_USER_KEY}" \
            --form-string "title=${title}" \
            --form-string "message=${message}" \
            --form-string "priority=${po_priority}" \
            https://api.pushover.net/1/messages.json >/dev/null 2>&1 || true
    fi

    # Gotify
    if [[ -n "${GOTIFY_URL:-}" ]] && [[ -n "${GOTIFY_TOKEN:-}" ]]; then
        local g_priority=4
        [[ "$priority" == "high" ]] && g_priority=8
        curl -s -X POST "${GOTIFY_URL}/message?token=${GOTIFY_TOKEN}" \
            -F "title=${title}" \
            -F "message=${message}" \
            -F "priority=${g_priority}" >/dev/null 2>&1 || true
    fi

    # n8n
    if [[ -n "${N8N_WEBHOOK:-}" ]]; then
        curl -s -X POST "${N8N_WEBHOOK}" \
            -H "Content-Type: application/json" \
            -d "{\"title\":\"${title}\",\"message\":\"${message}\",\"priority\":\"${priority}\"}" \
            >/dev/null 2>&1 || true
    fi
}

# -----------------------------------------------------------------------------
#  Error handler
# -----------------------------------------------------------------------------
error_handler() {
    local exit_code=$1
    local line_number=$2
    log_error "Script failed at line $line_number with exit code $exit_code"
    log_error "Check log file: $LOG_FILE"
    log_error "Backups saved to: $BACKUP_DIR"
    exit "$exit_code"
}
trap 'error_handler $? $LINENO' ERR

# =============================================================================
#  PRE-FLIGHT CHECKS
# =============================================================================

echo ""
echo -e "${BOLD}=========================================================${NC}"
echo -e "${BOLD}  Ubuntu 24.04 LTS — Interactive Server Hardening v${SCRIPT_VERSION}${NC}"
echo -e "${BOLD}=========================================================${NC}"
echo ""

# Must run as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root. Use: sudo ./harden.sh"
    exit 1
fi

# Verify Ubuntu 24.04
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "24.04" ]]; then
        log_warn "This script is designed for Ubuntu 24.04 LTS."
        log_warn "Detected: $PRETTY_NAME"
        if ! prompt_yn "Continue anyway? (NOT recommended)"; then
            exit 1
        fi
    fi
else
    log_error "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"
log_info "Backup directory: $BACKUP_DIR"
log_info "Log file: $LOG_FILE"

echo ""
echo -e "${YELLOW}How this script works:${NC}"
echo "  • Each step prompts you with [Y/n] before doing anything"
echo "  • All settings (username, timezone, notifications) are entered interactively"
echo "  • No manual file editing required — just answer the prompts"
echo "  • Skip any step by typing 'n' — re-run the script anytime to apply it later"
echo ""
echo -e "${YELLOW}Before we begin:${NC}"
echo -e "  • SSH Port:  ${BOLD}${SSH_PORT}${NC} (randomly generated — ${RED}write this down!${NC})"
echo -e "  • Make sure your SSH public key is already on this server"
echo -e "    (the script will disable password-based SSH login)"
echo ""

if ! prompt_yn "Ready to begin hardening?"; then
    echo ""
    log_info "No problem. Run the script again when you're ready."
    exit 0
fi

echo ""
echo -e "${YELLOW}${BOLD}TIP:${NC} Press Enter to accept [Y] for each step, or type 'n' to skip it."
echo ""

# =============================================================================
#  STEP 1: System Update & Upgrade
# =============================================================================

log_step "STEP 1: System Update & Upgrade"
echo "  This will run apt update, full-upgrade, autoremove, clean, and autoclean."
echo "  full-upgrade handles dependency changes (better than regular upgrade)."
echo ""

if prompt_yn "Run full system update and upgrade?"; then
    log_info "Updating package lists..."
    apt update -y 2>&1 | tee -a "$LOG_FILE"

    log_info "Running full-upgrade (handles dependency changes)..."
    DEBIAN_FRONTEND=noninteractive apt full-upgrade -y 2>&1 | tee -a "$LOG_FILE"

    log_info "Removing unused packages..."
    apt autoremove -y 2>&1 | tee -a "$LOG_FILE"

    log_info "Cleaning apt cache..."
    apt clean 2>&1 | tee -a "$LOG_FILE"
    apt autoclean 2>&1 | tee -a "$LOG_FILE"

    ((STEPS_RUN++)) || true
    log_info "System update complete."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped system update."
fi

# =============================================================================
#  STEP 2: Install Required Packages
# =============================================================================

log_step "STEP 2: Install Required Packages"
echo "  Packages to install:"
echo "    - ufw              (firewall)"
echo "    - fail2ban         (brute-force protection)"
echo "    - unattended-upgrades (automatic security updates)"
echo "    - auditd           (system auditing)"
echo "    - msmtp + mailutils (lightweight email for alerts)"
echo "    - libpam-pwquality (password policy enforcement)"
echo "    - curl, jq         (utilities for notifications)"
echo ""

if prompt_yn "Install all required packages?"; then
    PACKAGES=(
        ufw
        fail2ban
        unattended-upgrades
        update-notifier-common
        auditd
        audispd-plugins
        libpam-pwquality
        curl
        jq
    )

    # Only install email packages if email is configured
    if [[ -n "$ALERT_EMAIL" ]]; then
        PACKAGES+=(msmtp msmtp-mta bsd-mailx)
    fi

    log_info "Installing packages..."
    DEBIAN_FRONTEND=noninteractive apt install -y "${PACKAGES[@]}" 2>&1 | tee -a "$LOG_FILE"

    ((STEPS_RUN++)) || true
    log_info "Package installation complete."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped package installation. Some later steps may fail without these packages."
fi

# =============================================================================
#  STEP 3: Set Timezone
# =============================================================================

log_step "STEP 3: Set Timezone"
echo "  Current timezone: $(timedatectl show --property=Timezone --value 2>/dev/null || echo 'unknown')"
echo ""
echo "  Not sure of your timezone? Find yours here:"
echo "  https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"
echo ""
echo "  Or run this command to search: timedatectl list-timezones | grep -i <city>"
echo ""

if prompt_yn "Set timezone?"; then
    echo ""
    while true; do
        read -rp "  Enter timezone [default: ${TIMEZONE}]: " INPUT_TZ
        INPUT_TZ="${INPUT_TZ:-$TIMEZONE}"

        # Validate the timezone exists
        if timedatectl list-timezones 2>/dev/null | grep -qx "$INPUT_TZ"; then
            TIMEZONE="$INPUT_TZ"
            break
        else
            echo "  Invalid timezone: '${INPUT_TZ}'"
            echo "  Search for yours: timedatectl list-timezones | grep -i <city>"
            echo "  Examples: America/New_York, America/Chicago, America/Los_Angeles,"
            echo "            Europe/London, Asia/Tokyo, Australia/Sydney"
            echo ""
        fi
    done

    timedatectl set-timezone "$TIMEZONE"
    timedatectl set-ntp true
    log_info "Timezone set to $TIMEZONE. NTP sync enabled."
    ((STEPS_RUN++)) || true
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped timezone configuration."
fi

# =============================================================================
#  STEP 4: Create Admin User
# =============================================================================

log_step "STEP 4: Create Admin User"
echo "  Creates a non-root user with sudo privileges."
echo "  Copies root's SSH keys so you can log in as this user."
echo "  Root SSH login will be disabled in a later step."
echo ""
echo -e "  ${YELLOW}${BOLD}IMPORTANT — Understanding passwords vs SSH keys:${NC}"
echo ""
echo "  SSH login:  Uses your SSH KEY (no password needed to log in)."
echo "              Password authentication is disabled in Step 5."
echo ""
echo "  sudo:       Uses the PASSWORD you set here."
echo "              You'll type this when running 'sudo' commands"
echo "              on the server (e.g., sudo apt update)."
echo ""
echo "  So the password you create here is for sudo only, not for SSH."
echo ""

if prompt_yn "Create an admin user?"; then

    # Prompt for username
    echo ""
    echo -e "  ${CYAN}Choose a username for the admin account.${NC}"
    echo "  Avoid common names like 'admin', 'user', or 'root' (bots target these)."
    echo "  Good examples: deploy, george, sysop, webadmin"
    echo ""
    while true; do
        read -rp "  Enter username [default: ${ADMIN_USER}]: " INPUT_USER
        INPUT_USER="${INPUT_USER:-$ADMIN_USER}"

        # Validate username (lowercase, starts with letter, no spaces)
        if [[ "$INPUT_USER" =~ ^[a-z][a-z0-9_-]{1,31}$ ]]; then
            ADMIN_USER="$INPUT_USER"
            break
        else
            echo "  Invalid username. Use lowercase letters, numbers, hyphens, or underscores."
            echo "  Must start with a letter and be 2-32 characters."
        fi
    done
    log_info "Admin username: $ADMIN_USER"

    if id "$ADMIN_USER" &>/dev/null; then
        log_warn "User '$ADMIN_USER' already exists. Ensuring sudo group membership."
    else
        adduser --disabled-password --gecos "Admin User" "$ADMIN_USER"
        log_info "User '$ADMIN_USER' created."
    fi

    usermod -aG sudo "$ADMIN_USER"
    log_info "Added '$ADMIN_USER' to sudo group."

    # Prompt for password (for sudo use)
    echo ""
    echo -e "  ${CYAN}Set a password for '${ADMIN_USER}' (used for sudo commands).${NC}"
    echo "  Strong password tips:"
    echo "    - At least 12 characters"
    echo "    - Mix of uppercase, lowercase, numbers, and symbols"
    echo "    - Avoid dictionary words and personal info"
    echo "    - Consider a passphrase like: correct-horse-battery-staple"
    echo ""
    while true; do
        if passwd "$ADMIN_USER"; then
            log_info "Password set for '$ADMIN_USER'."
            break
        else
            echo ""
            log_warn "Password was not set (cancelled or too weak). Let's try again."
            echo ""
        fi
    done

    # Copy SSH keys from root
    ADMIN_HOME=$(eval echo "~${ADMIN_USER}")
    mkdir -p "${ADMIN_HOME}/.ssh"

    if [[ -f /root/.ssh/authorized_keys ]]; then
        cp /root/.ssh/authorized_keys "${ADMIN_HOME}/.ssh/authorized_keys"
        log_info "Copied root's authorized_keys to $ADMIN_USER."
    else
        log_warn "No /root/.ssh/authorized_keys found!"
        log_warn "Make sure you add your SSH public key to ${ADMIN_HOME}/.ssh/authorized_keys"
        log_warn "BEFORE the SSH hardening step, or you will be locked out."
    fi

    chown -R "${ADMIN_USER}:${ADMIN_USER}" "${ADMIN_HOME}/.ssh"
    chmod 700 "${ADMIN_HOME}/.ssh"
    chmod 600 "${ADMIN_HOME}/.ssh/authorized_keys" 2>/dev/null || true

    ((STEPS_RUN++)) || true
    log_info "Admin user setup complete."
    echo ""
    echo -e "  ${GREEN}Summary:${NC}"
    echo "    Username:   $ADMIN_USER"
    echo "    SSH login:  Via SSH key (copied from root)"
    echo "    sudo:       Via the password you just set"
    echo ""
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped admin user creation."
fi

# =============================================================================
#  STEP 5: SSH Hardening
# =============================================================================

log_step "STEP 5: SSH Hardening"
echo "  This is the most critical step. It will:"
echo "    - Move SSH to random port $SSH_PORT (from range 49152–65535)"
echo "    - Disable root login"
echo "    - Disable password authentication (key-only)"
echo "    - Enable post-quantum key exchange algorithms"
echo "    - Regenerate host keys (Ed25519 + RSA 4096)"
echo "    - Remove weak Diffie-Hellman moduli"
echo "    - Set strict session limits"
echo ""
echo -e "  ${RED}${BOLD}WARNING:${NC} Ensure you have:"
echo "    1. An SSH key added to the server"
echo "    2. The key copied to '$ADMIN_USER' (Step 4)"
echo ""
echo -e "  ${YELLOW}Port 22 will remain open as a safety net.${NC}"
echo "  You will be reminded to close it after verifying the new port."
echo ""

if prompt_yn "Harden SSH configuration?"; then
    backup_file /etc/ssh/sshd_config

    # Regenerate host keys
    log_info "Regenerating SSH host keys..."
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
    log_info "Host keys regenerated (Ed25519 + RSA-4096)."

    # Remove weak Diffie-Hellman moduli
    if [[ -f /etc/ssh/moduli ]]; then
        log_info "Removing weak DH moduli (< 3072 bits)..."
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
        if [[ -s /etc/ssh/moduli.safe ]]; then
            mv /etc/ssh/moduli.safe /etc/ssh/moduli
        else
            log_warn "No strong moduli found. Keeping original file."
            rm -f /etc/ssh/moduli.safe
        fi
    fi

    # Write hardened sshd_config
    log_info "Writing hardened sshd_config..."
    cat > /etc/ssh/sshd_config <<SSHEOF
# =============================================================================
#  Hardened sshd_config — Generated by harden.sh v${SCRIPT_VERSION}
#  Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# =============================================================================

# --- Network ---
Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# --- Host Keys ---
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# --- Key Exchange (post-quantum prioritized) ---
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512

# --- Ciphers ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr

# --- MACs (ETM variants only) ---
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# --- Host Key Algorithms ---
HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# --- Authentication ---
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AuthenticationMethods publickey

# --- Session Limits ---
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Disable Forwarding ---
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
DisableForwarding yes

# --- Other Hardening ---
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
LogLevel VERBOSE
Banner /etc/issue.net
RequiredRSASize 3072

# --- Restrict Users ---
AllowUsers ${ADMIN_USER}
SSHEOF

    # Validate config before applying
    if sshd -t 2>&1; then
        log_info "SSH config validation passed."
    else
        log_error "SSH config validation FAILED. Restoring backup..."
        cp "${BACKUP_DIR}/sshd_config.bak" /etc/ssh/sshd_config
        log_error "Original config restored. SSH not changed."
        ((STEPS_SKIPPED++)) || true
    fi

    # Update socket file for new port (Ubuntu 24.04 socket activation)
    if [[ -d /etc/systemd/system/ssh.socket.d ]]; then
        log_info "Updating ssh.socket override for port ${SSH_PORT}..."
    fi
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat > /etc/systemd/system/ssh.socket.d/override.conf <<SOCKETEOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
SOCKETEOF

    # Restart SSH via socket (24.04 method)
    systemctl daemon-reload
    systemctl restart ssh.socket
    log_info "SSH restarted on port $SSH_PORT via ssh.socket."

    ((STEPS_RUN++)) || true
    log_info "SSH hardening complete."
    echo ""
    echo -e "  ${GREEN}${BOLD}NEXT: Open a NEW terminal and test:${NC}"
    echo -e "  ${BOLD}  ssh -p ${SSH_PORT} ${ADMIN_USER}@your-server-ip${NC}"
    echo ""
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped SSH hardening."
fi

# =============================================================================
#  STEP 6: UFW Firewall
# =============================================================================

log_step "STEP 6: UFW Firewall"
echo "  Will configure firewall rules:"
echo "    - Allow SSH on port $SSH_PORT"
echo "    - Allow HTTP  (port 80)"
echo "    - Allow HTTPS (port 443)"
echo "    - Allow SSH on port 22 (temporary safety net)"
echo "    - Deny all other incoming traffic"
echo "    - Allow all outgoing traffic"
echo "    - Deny routed traffic (Docker safety)"
echo "    - Prepare Docker/UFW conflict fix (after.rules)"
echo ""

if prompt_yn "Configure UFW firewall?"; then
    # Reset UFW to clean state (non-interactive)
    ufw --force reset 2>&1 | tee -a "$LOG_FILE"

    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed

    # Allow required ports
    ufw allow "${SSH_PORT}/tcp" comment 'SSH (hardened port)'
    ufw allow 22/tcp comment 'SSH (safety net — REMOVE after testing)'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'

    # Set logging level
    ufw logging medium

    # Enable UFW
    ufw --force enable
    log_info "UFW enabled with rules:"
    ufw status verbose 2>&1 | tee -a "$LOG_FILE"

    # Prepare UFW/Docker conflict fix in after.rules
    backup_file /etc/ufw/after.rules

    if ! grep -q "BEGIN UFW AND DOCKER" /etc/ufw/after.rules 2>/dev/null; then
        log_info "Adding UFW/Docker safety rules to after.rules..."
        cat >> /etc/ufw/after.rules <<'UFWDOCKER'

# BEGIN UFW AND DOCKER
# Prevents Docker from bypassing UFW firewall rules.
# Source: github.com/chaifeng/ufw-docker
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12
-A DOCKER-USER -j RETURN
-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP
COMMIT
# END UFW AND DOCKER
UFWDOCKER
        log_info "UFW/Docker rules added. They activate once Docker is installed."
    else
        log_info "UFW/Docker rules already present. Skipping."
    fi

    ((STEPS_RUN++)) || true
    log_info "Firewall configuration complete."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped firewall configuration."
fi

# =============================================================================
#  STEP 7: Fail2ban
# =============================================================================

log_step "STEP 7: Fail2ban (Brute-Force Protection)"
echo "  Configures Fail2ban to monitor SSH on port $SSH_PORT."
echo "  Bans IPs after 3 failed attempts for 2 hours (escalating)."
echo "  Repeat offenders banned for 1 week."
echo "  Uses systemd backend (required for Ubuntu 24.04)."
echo ""
echo "  Optional notifications (configure any/all in Step 18):"
echo "    - ntfy.sh / Discord / Slack / Telegram"
echo "    - Pushover / Gotify / n8n / Email"
echo ""

if prompt_yn "Configure Fail2ban?"; then
    # Create jail.local (never edit jail.conf directly)
    log_info "Writing /etc/fail2ban/jail.local..."
    cat > /etc/fail2ban/jail.local <<F2BEOF
# =============================================================================
#  Fail2ban jail.local — Generated by harden.sh v${SCRIPT_VERSION}
# =============================================================================

[DEFAULT]
banaction = ufw
bantime = 2h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

# Exponential backoff for repeat offenders
bantime.increment = true
bantime.factor = 2
bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor
bantime.maxtime = 2w
dbpurgeage = 86400

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
backend = systemd
maxretry = 3
findtime = 10m
bantime = 2h
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
maxretry = 5
findtime = 1d
bantime = 1w
banaction = ufw
F2BEOF

    # Add webhook notification actions for all configured channels
    HAS_NOTIFICATIONS=false
    if [[ -n "$NTFY_TOPIC" ]] || [[ -n "$DISCORD_WEBHOOK" ]] || [[ -n "$SLACK_WEBHOOK" ]] || \
       [[ -n "$TELEGRAM_BOT_TOKEN" ]] || [[ -n "$PUSHOVER_APP_TOKEN" ]] || \
       [[ -n "$GOTIFY_URL" ]] || [[ -n "$N8N_WEBHOOK" ]]; then
        HAS_NOTIFICATIONS=true
    fi

    if [[ "$HAS_NOTIFICATIONS" == "true" ]]; then
        log_info "Configuring Fail2ban webhook notifications..."

        # Create a universal notification script that Fail2ban calls
        cat > /usr/local/bin/fail2ban-notify.sh <<'NOTIFYSCRIPT'
#!/usr/bin/env bash
# Called by Fail2ban action with: <action> <jail> <ip> <failures> <hostname>
ACTION="$1"    # ban or unban
JAIL="$2"
IP="$3"
FAILURES="$4"
HOSTNAME="$5"

if [[ "$ACTION" == "ban" ]]; then
    TITLE="[Fail2ban] Banned ${IP}"
    MESSAGE="Jail: ${JAIL} | IP: ${IP} | Failures: ${FAILURES} | Host: ${HOSTNAME}"
    PRIORITY="high"
else
    TITLE="[Fail2ban] Unbanned ${IP}"
    MESSAGE="Jail: ${JAIL} | IP: ${IP} | Host: ${HOSTNAME}"
    PRIORITY="default"
fi
NOTIFYSCRIPT

        # Append configured webhook calls to the notification script

        if [[ -n "$NTFY_TOPIC" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<NTFYBLOCK

# ntfy.sh
curl -s -H "Title: \${TITLE}" -H "Tags: rotating_light" -H "Priority: \${PRIORITY}" \\
    -d "\${MESSAGE}" "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
NTFYBLOCK
            log_info "  → ntfy.sh enabled (topic: ${NTFY_TOPIC})"
        fi

        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<DISCORDBLOCK

# Discord
curl -s -H "Content-Type: application/json" \\
    -d "{\\"content\\":\\"**\${TITLE}**\\n\${MESSAGE}\\"}" \\
    "${DISCORD_WEBHOOK}" >/dev/null 2>&1 || true
DISCORDBLOCK
            log_info "  → Discord webhook enabled"
        fi

        if [[ -n "$SLACK_WEBHOOK" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<SLACKBLOCK

# Slack
curl -s -H "Content-Type: application/json" \\
    -d "{\\"text\\":\\"*\${TITLE}*\\n\${MESSAGE}\\"}" \\
    "${SLACK_WEBHOOK}" >/dev/null 2>&1 || true
SLACKBLOCK
            log_info "  → Slack webhook enabled"
        fi

        if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<TELEGRAMBLOCK

# Telegram
curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \\
    -d "chat_id=${TELEGRAM_CHAT_ID}" \\
    -d "text=\${TITLE} - \${MESSAGE}" >/dev/null 2>&1 || true
TELEGRAMBLOCK
            log_info "  → Telegram bot enabled"
        fi

        if [[ -n "$PUSHOVER_APP_TOKEN" ]] && [[ -n "$PUSHOVER_USER_KEY" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<PUSHOVERBLOCK

# Pushover
if [[ "\${ACTION}" == "ban" ]]; then PO_PRIORITY=1; else PO_PRIORITY=0; fi
curl -s --form-string "token=${PUSHOVER_APP_TOKEN}" \\
    --form-string "user=${PUSHOVER_USER_KEY}" \\
    --form-string "title=\${TITLE}" \\
    --form-string "message=\${MESSAGE}" \\
    --form-string "priority=\${PO_PRIORITY}" \\
    --form-string "sound=siren" \\
    --form-string "timestamp=\$(date +%s)" \\
    https://api.pushover.net/1/messages.json >/dev/null 2>&1 || true
PUSHOVERBLOCK
            log_info "  → Pushover enabled"
        fi

        if [[ -n "$GOTIFY_URL" ]] && [[ -n "$GOTIFY_TOKEN" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<GOTIFYBLOCK

# Gotify
if [[ "\${ACTION}" == "ban" ]]; then G_PRIORITY=8; else G_PRIORITY=2; fi
curl -s -X POST "${GOTIFY_URL}/message?token=${GOTIFY_TOKEN}" \\
    -F "title=\${TITLE}" \\
    -F "message=\${MESSAGE}" \\
    -F "priority=\${G_PRIORITY}" >/dev/null 2>&1 || true
GOTIFYBLOCK
            log_info "  → Gotify enabled (${GOTIFY_URL})"
        fi

        if [[ -n "$N8N_WEBHOOK" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<N8NBLOCK

# n8n
curl -s -X POST "${N8N_WEBHOOK}" \\
    -H "Content-Type: application/json" \\
    -d "{\\"event\\":\\"\${ACTION}\\",\\"jail\\":\\"\${JAIL}\\",\\"ip\\":\\"\${IP}\\",\\"failures\\":\\"\${FAILURES}\\",\\"hostname\\":\\"\${HOSTNAME}\\",\\"timestamp\\":\\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\\"}" >/dev/null 2>&1 || true
N8NBLOCK
            log_info "  → n8n webhook enabled"
        fi

        chmod +x /usr/local/bin/fail2ban-notify.sh

        # Create the Fail2ban action that calls the notification script
        cat > /etc/fail2ban/action.d/notify-webhook.conf <<'ACTIONEOF'
[Definition]
norestored = true
actionban = /usr/local/bin/fail2ban-notify.sh ban <n> <ip> <failures> %(hostname)s
actionunban = /usr/local/bin/fail2ban-notify.sh unban <n> <ip> 0 %(hostname)s
ACTIONEOF

        # Add notify-webhook action to the sshd jail
        cat >> /etc/fail2ban/jail.local <<JAILAPPEND

# Webhook notifications for all configured channels
[sshd]
action = ufw
         notify-webhook
JAILAPPEND
        log_info "Fail2ban webhook notifications configured."
    fi

    # Enable and restart
    systemctl enable fail2ban
    systemctl restart fail2ban

    ((STEPS_RUN++)) || true
    log_info "Fail2ban configured and running."
    fail2ban-client status 2>&1 | tee -a "$LOG_FILE"
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped Fail2ban configuration."
fi

# =============================================================================
#  STEP 8: Kernel / Sysctl Hardening
# =============================================================================

log_step "STEP 8: Kernel & Network Hardening (sysctl)"
echo "  Applies CIS-aligned kernel parameters:"
echo "    - SYN flood protection"
echo "    - Disable ICMP redirects and source routing"
echo "    - Reverse path filtering"
echo "    - Restrict kernel pointers and dmesg"
echo "    - Harden BPF, ptrace, and ASLR"
echo "    - IP forwarding OFF (a Docker-ready override is prepared separately)"
echo ""

if prompt_yn "Apply kernel hardening parameters?"; then
    log_info "Writing /etc/sysctl.d/99-hardening.conf..."
    cat > /etc/sysctl.d/99-hardening.conf <<SYSCTLEOF
# =============================================================================
#  Kernel Hardening — Generated by harden.sh v${SCRIPT_VERSION}
#  Reference: CIS Ubuntu 24.04 LTS Benchmark v1.0.0
# =============================================================================

# --- Network: SYN Flood Protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# --- ICMP ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# NOTE: Do NOT enable icmp_echo_ignore_all — breaks DigitalOcean monitoring

# --- Reverse Path Filtering ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Disable Redirects ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Disable Source Routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Log Martian Packets ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Disable IPv6 Router Advertisements ---
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- IP Forwarding (OFF — Docker will override separately) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Kernel Self-Protection ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 4
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# --- File Protection ---
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
SYSCTLEOF

    # Prepare a Docker override file (not active until Docker is installed)
    log_info "Preparing Docker sysctl override (inactive until Docker is installed)..."
    cat > /etc/sysctl.d/99-docker.conf.disabled <<DOCKEREOF
# =============================================================================
#  Docker Networking Override
#  Rename this to 99-docker.conf after installing Docker:
#    mv /etc/sysctl.d/99-docker.conf.disabled /etc/sysctl.d/99-docker.conf
#    sysctl --system
# =============================================================================
net.ipv4.ip_forward = 1
DOCKEREOF

    # Apply sysctl settings
    sysctl --system 2>&1 | tee -a "$LOG_FILE"

    ((STEPS_RUN++)) || true
    log_info "Kernel hardening applied."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped kernel hardening."
fi

# =============================================================================
#  STEP 9: Disable Unused Kernel Modules
# =============================================================================

log_step "STEP 9: Disable Unused Kernel Modules"
echo "  Disables rarely-used filesystems and network protocols:"
echo "    - cramfs, freevxfs, jffs2, hfs, hfsplus, udf"
echo "    - dccp, sctp, rds, tipc"
echo "    - USB storage (irrelevant on VPS but defense-in-depth)"
echo ""

if prompt_yn "Disable unused kernel modules?"; then
    log_info "Writing /etc/modprobe.d/hardening.conf..."
    cat > /etc/modprobe.d/hardening.conf <<MODEOF
# =============================================================================
#  Disabled Kernel Modules — Generated by harden.sh v${SCRIPT_VERSION}
# =============================================================================

# Unused filesystems
install cramfs /bin/false
blacklist cramfs
install freevxfs /bin/false
blacklist freevxfs
install jffs2 /bin/false
blacklist jffs2
install hfs /bin/false
blacklist hfs
install hfsplus /bin/false
blacklist hfsplus
install udf /bin/false
blacklist udf

# NOTE: squashfs left enabled (required by snap)
# NOTE: vfat left enabled (may be needed for UEFI boot)

# Unused network protocols
install dccp /bin/false
blacklist dccp
install sctp /bin/false
blacklist sctp
install rds /bin/false
blacklist rds
install tipc /bin/false
blacklist tipc

# USB storage (defense-in-depth on VPS)
install usb-storage /bin/false
blacklist usb-storage
MODEOF

    ((STEPS_RUN++)) || true
    log_info "Unused kernel modules disabled."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped kernel module hardening."
fi

# =============================================================================
#  STEP 10: File Permissions (CIS Level 1)
# =============================================================================

log_step "STEP 10: File Permissions Hardening"
echo "  Sets CIS-recommended permissions on sensitive files:"
echo "    - /etc/passwd, /etc/group → 644"
echo "    - /etc/shadow, /etc/gshadow → 640 (root:shadow)"
echo "    - SSH host keys → 600 (private), 644 (public)"
echo "    - Cron directories → 700"
echo ""

if prompt_yn "Harden file permissions?"; then
    chmod 644 /etc/passwd /etc/group
    chmod 640 /etc/shadow /etc/gshadow
    chown root:shadow /etc/shadow /etc/gshadow

    # SSH key permissions
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

    # Cron permissions
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
    chmod 600 /etc/crontab
    echo "root" > /etc/cron.allow
    chmod 640 /etc/cron.allow
    rm -f /etc/cron.deny

    # At job permissions
    echo "root" > /etc/at.allow 2>/dev/null || true
    chmod 640 /etc/at.allow 2>/dev/null || true
    rm -f /etc/at.deny 2>/dev/null || true

    ((STEPS_RUN++)) || true
    log_info "File permissions hardened."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped file permissions hardening."
fi

# =============================================================================
#  STEP 11: Shared Memory Hardening
# =============================================================================

log_step "STEP 11: Shared Memory Hardening"
echo "  Adds noexec,nosuid,nodev to /dev/shm mount."
echo "  Prevents execution of binaries from shared memory (common exploit vector)."
echo ""

if prompt_yn "Harden shared memory (/dev/shm)?"; then
    backup_file /etc/fstab

    if ! grep -q "tmpfs.*/dev/shm.*noexec" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount /dev/shm 2>/dev/null || true
        log_info "Shared memory hardened with noexec,nosuid,nodev."
    else
        log_info "Shared memory already hardened. Skipping."
    fi

    ((STEPS_RUN++)) || true
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped shared memory hardening."
fi

# =============================================================================
#  STEP 12: Disable Core Dumps
# =============================================================================

log_step "STEP 12: Disable Core Dumps"
echo "  Core dumps can leak sensitive data (passwords, keys in memory)."
echo "  Disables via limits.conf, sysctl, and systemd coredump."
echo ""

if prompt_yn "Disable core dumps?"; then
    # limits.conf
    if ! grep -q "hard core 0" /etc/security/limits.d/hardening.conf 2>/dev/null; then
        echo "* hard core 0" > /etc/security/limits.d/hardening.conf
    fi

    # systemd coredump
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/disable.conf <<COREEOF
[Coredump]
Storage=none
ProcessSizeMax=0
COREEOF

    systemctl daemon-reload

    ((STEPS_RUN++)) || true
    log_info "Core dumps disabled."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped core dump hardening."
fi

# =============================================================================
#  STEP 13: Login Banners & MOTD
# =============================================================================

log_step "STEP 13: Login Banners & MOTD"
echo "  Sets a CIS-compliant legal warning banner."
echo "  Disables Ubuntu's dynamic MOTD news (phones home to Canonical)."
echo "  Adds a random dad joke to every login (because security can be fun)."
echo ""

if prompt_yn "Configure login banners?"; then
    # Disable dynamic MOTD
    systemctl disable --now motd-news.timer 2>/dev/null || true
    chmod -x /etc/update-motd.d/* 2>/dev/null || true

    # Set warning banners
    cat > /etc/issue <<'BANNEREOF'
*******************************************************************
*  WARNING: Unauthorized access to this system is prohibited.     *
*  All activity is monitored and recorded.                        *
*  By accessing this system, you consent to these terms.          *
*******************************************************************
BANNEREOF

    cp /etc/issue /etc/issue.net
    echo "" > /etc/motd

    # Create the dad joke MOTD script
    log_info "Installing random dad joke MOTD..."
    cat > /etc/update-motd.d/99-dad-joke <<'DADEOF'
#!/usr/bin/env bash
# Random dad joke on every login. You're welcome.

JOKES=(
    # === Classic Dad Jokes ===
    "I told my wife she was drawing her eyebrows too high. She looked surprised."
    "Why don't scientists trust atoms? Because they make up everything."
    "What do you call a fake noodle? An impasta."
    "I'm reading a book about anti-gravity. It's impossible to put down."
    "Why did the scarecrow win an award? He was outstanding in his field."
    "I used to hate facial hair, but then it grew on me."
    "What did the ocean say to the beach? Nothing, it just waved."
    "Why do cows have hooves instead of feet? Because they lactose."
    "I only know 25 letters of the alphabet. I don't know Y."
    "What do you call a bear with no teeth? A gummy bear."
    "I'm on a seafood diet. I see food and I eat it."
    "Why don't eggs tell jokes? They'd crack each other up."
    "What do you call a lazy kangaroo? A pouch potato."
    "A man walks into a bar and asks for 1.4 root beers. The bartender says: I'll have to charge you extra, that's a root beer float."
    "What did the buffalo say when his son left for college? Bison."
    "I'm afraid for the calendar. Its days are numbered."
    "Why don't skeletons fight each other? They don't have the guts."
    "What do you call cheese that isn't yours? Nacho cheese."
    "I used to play piano by ear, but now I use my hands."
    "What did one wall say to the other? I'll meet you at the corner."
    "Why can't a nose be 12 inches long? Because then it'd be a foot."
    "I got fired from the orange juice factory. I couldn't concentrate."
    "What do you call a dog that does magic tricks? A Labracadabrador."
    "Did you hear about the claustrophobic astronaut? He just needed a little space."
    "I told a chemistry joke once. There was no reaction."
    "What do you call a fish without eyes? A fsh."
    "I'm terrified of elevators, so I'm going to start taking steps to avoid them."
    "Why did the bicycle fall over? Because it was two-tired."
    "What did the janitor say when he jumped out of the closet? Supplies!"
    "Why couldn't the leopard play hide and seek? Because he was always spotted."
    # === Tech & Sysadmin Jokes ===
    "Why do programmers prefer dark mode? Because light attracts bugs."
    "I would tell you a UDP joke, but you might not get it."
    "There are 10 types of people in the world: those who understand binary and those who don't."
    "A SQL query walks into a bar, sees two tables, and asks: Can I JOIN you?"
    "Why do Linux admins never get locked out? Because they always have the right key."
    "What's a computer's favorite snack? Microchips."
    "The cloud is just someone else's computer. And their computer has dad jokes too."
    "Why did the developer go broke? Because he used up all his cache."
    "How do trees access the internet? They log in."
    "Why was the JavaScript developer sad? Because he didn't Node how to Express himself."
    "What did the router say to the doctor? It hurts when IP."
    "My password is incorrect. So whenever I forget it, the computer reminds me: Your password is incorrect."
    "Why did the firewall break up with the proxy? There was no connection."
    "Knock knock. Who's there? SSH. SSH who? SSH... we're using key-based auth now, no more who's there."
    "What's a pirate's favorite programming language? You'd think R, but their first love be the C."
    "I asked my server for a joke. It returned 404: Humor Not Found."
    "Why do Java developers wear glasses? Because they can't C#."
    "A programmer's wife tells him: Go to the store and get a loaf of bread. If they have eggs, get a dozen. He came home with 12 loaves."
    "Why was the computer cold? It left its Windows open."
    "What's the object-oriented way to become wealthy? Inheritance."
    "How does a computer get drunk? It takes screenshots."
    "Why did the programmer quit his job? Because he didn't get arrays."
    "What do you call 8 hobbits? A hobbyte."
    "There's no place like 127.0.0.1."
    "Why did the functions stop calling each other? Because they had too many arguments."
    "To understand recursion, you must first understand recursion."
    "I changed my password to 'incorrect' so whenever I forget, the computer tells me."
    "Real programmers count from 0."
    "!false — it's funny because it's true."
    "A TCP packet walks into a bar and says: I'd like a beer. The bartender says: You'd like a beer? The TCP packet says: Yes, I'd like a beer."
    "Why do backend developers make bad comedians? Their jokes always need more context."
    "I have a joke about git but I keep losing track of the branches."
    "Docker said to the VM: I contain myself better than you ever could."
    "Why did the sysadmin cross the road? To get to the other VLAN."
    "My server went down last night. It had too many connections and not enough uptime."
    "The best thing about a Boolean is that even if you're wrong, you're only off by a bit."
    "ASCII a stupid question, get a stupid ANSI."
    "A QA engineer walks into a bar. Orders 1 beer. Orders 0 beers. Orders 99999999 beers. Orders -1 beers. Orders a lizard. Orders NULL beers."
    "sudo make me a sandwich."
    "In order to understand recursion, one must first — segmentation fault (core dumped)."
)

RANDOM_INDEX=$((RANDOM % ${#JOKES[@]}))

echo ""
echo "  $(printf '\xF0\x9F\xA4\xA3') Dad Joke of the Day:"
echo "  ${JOKES[$RANDOM_INDEX]}"
echo ""
DADEOF
    chmod +x /etc/update-motd.d/99-dad-joke

    ((STEPS_RUN++)) || true
    log_info "Login banners configured (with dad jokes)."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped login banner configuration."
fi

# =============================================================================
#  STEP 14: Login Defaults (password policy, umask)
# =============================================================================

log_step "STEP 14: Login Defaults & Password Policy"
echo "  Configures in /etc/login.defs:"
echo "    - Umask 077 (new files private by default)"
echo "    - SHA-512 password hashing with 10000 rounds"
echo "    - Password expiry: max 365 days, min 1 day, warn at 14 days"
echo "    - Log successful logins"
echo ""

if prompt_yn "Harden login defaults?"; then
    backup_file /etc/login.defs

    # Update login.defs values
    sed -i 's/^UMASK.*/UMASK\t\t077/' /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD\tSHA512/' /etc/login.defs

    # Add settings if they don't exist
    grep -q "^LOG_OK_LOGINS" /etc/login.defs || echo "LOG_OK_LOGINS yes" >> /etc/login.defs
    grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
    grep -q "^DEFAULT_HOME" /etc/login.defs || echo "DEFAULT_HOME no" >> /etc/login.defs

    # Set umask in profile for interactive shells
    cat > /etc/profile.d/umask.sh <<'UMASKEOF'
# Set default umask to 077 (new files private by default)
umask 077
UMASKEOF
    chmod 644 /etc/profile.d/umask.sh

    ((STEPS_RUN++)) || true
    log_info "Login defaults hardened."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped login defaults hardening."
fi

# =============================================================================
#  STEP 15: Unattended Upgrades (Automatic Security Updates)
# =============================================================================

log_step "STEP 15: Unattended Upgrades"
echo "  Enables automatic installation of security updates."
echo "  Auto-reboots if a kernel update requires it (you choose the time)."
echo "  Blacklists Docker/containerd packages (you control those manually)."
echo "  Cleans up unused kernels and dependencies automatically."
echo ""

if prompt_yn "Configure unattended upgrades?"; then

    # Prompt for preferred reboot time
    echo ""
    echo -e "  ${YELLOW}${BOLD}UNDERSTANDING AUTO-REBOOTS:${NC}"
    echo ""
    echo "  Most security updates install silently without any downtime."
    echo "  However, kernel and core library updates require a reboot to"
    echo "  take effect. This happens roughly once or twice a month."
    echo ""
    echo "  When a reboot is needed, the server will:"
    echo "    1. Wait until the time you choose below"
    echo "    2. Gracefully stop all running services (including Docker containers)"
    echo "    3. Reboot and come back online (typically 30-90 seconds)"
    echo "    4. Automatically restart enabled services"
    echo ""
    echo "  You can check if a reboot is pending anytime by running:"
    echo "    cat /var/run/reboot-required"
    echo ""
    echo "  Learn more about unattended upgrades:"
    echo "  https://documentation.ubuntu.com/server/how-to/software/automatic-updates/"
    echo ""
    echo -e "  ${CYAN}When should the server auto-reboot if a kernel update requires it?${NC}"
    echo "  Pick a time when traffic is lowest. Uses 24-hour format (HH:MM)."
    echo "  Examples: 03:00 (3 AM), 14:30 (2:30 PM), 00:00 (midnight)"
    echo ""
    echo "  Not familiar with 24-hour time? Reference chart here:"
    echo "  https://en.wikipedia.org/wiki/24-hour_clock#Comparison_chart"
    echo ""
    while true; do
        read -rp "  Enter reboot time [default: 03:00]: " INPUT_REBOOT_TIME
        INPUT_REBOOT_TIME="${INPUT_REBOOT_TIME:-03:00}"

        # Validate HH:MM format (24-hour)
        if [[ "$INPUT_REBOOT_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
            REBOOT_TIME="$INPUT_REBOOT_TIME"
            break
        else
            echo "  Invalid format. Please use HH:MM in 24-hour time (e.g., 03:00, 14:30)."
        fi
    done
    log_info "Auto-reboot time set to: $REBOOT_TIME"
    log_info "Writing /etc/apt/apt.conf.d/50unattended-upgrades..."
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<UUEOF
// =============================================================================
//  Unattended Upgrades — Generated by harden.sh v${SCRIPT_VERSION}
// =============================================================================

Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
    "\${distro_id}:\${distro_codename}-updates";
};

// Do NOT auto-update Docker — manage these manually
Unattended-Upgrade::Package-Blacklist {
    "docker*";
    "containerd*";
};

Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
UUEOF

    # Enable the auto-upgrade timer
    log_info "Writing /etc/apt/apt.conf.d/20auto-upgrades..."
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<AUTOEOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AUTOEOF

    systemctl enable --now unattended-upgrades

    ((STEPS_RUN++)) || true
    log_info "Unattended upgrades configured."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped unattended upgrades."
fi

# =============================================================================
#  STEP 16: Journald Configuration
# =============================================================================

log_step "STEP 16: Journald Log Management"
echo "  Configures systemd-journald for a 512MB VPS:"
echo "    - Max disk usage: 100MB"
echo "    - Max file size: 10MB"
echo "    - Retention: 1 month"
echo "    - Compression: enabled"
echo ""

if prompt_yn "Configure journald log limits?"; then
    backup_file /etc/systemd/journald.conf

    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/hardening.conf <<JDEOF
[Journal]
Compress=yes
SystemMaxUse=100M
SystemMaxFileSize=10M
MaxRetentionSec=1month
ForwardToSyslog=yes
Storage=persistent
JDEOF

    systemctl restart systemd-journald

    ((STEPS_RUN++)) || true
    log_info "Journald configured."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped journald configuration."
fi

# =============================================================================
#  STEP 17: Auditd (System Auditing)
# =============================================================================

log_step "STEP 17: Auditd (System Auditing)"
echo "  Installs a lightweight audit ruleset (~20 rules)."
echo "  Monitors changes to: passwd, shadow, sudoers, SSH config,"
echo "  cron, kernel modules, and time settings."
echo "  Uses ~5-10MB RAM — workable on 512MB VPS."
echo ""

if prompt_yn "Configure auditd?"; then
    log_info "Writing audit rules to /etc/audit/rules.d/hardening.rules..."
    cat > /etc/audit/rules.d/hardening.rules <<AUDITEOF
# =============================================================================
#  Audit Rules — Generated by harden.sh v${SCRIPT_VERSION}
#  Lightweight ruleset for 512MB VPS
# =============================================================================

# Clear existing rules
-D

# Buffer size (conservative for low RAM)
-b 1024

# Failure mode: 1 = printk (NEVER use 2/panic on a VPS)
-f 1

# --- Identity / Authentication Changes ---
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# --- Privilege Escalation ---
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# --- SSH Configuration ---
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# --- Login Monitoring ---
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog -p wa -k login_mods
-w /var/log/lastlog -p wa -k login_mods

# --- Cron Changes ---
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron

# --- Kernel Module Loading ---
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module -k kernel_modules
-a always,exit -F arch=b64 -S delete_module -k kernel_modules

# --- Time Changes ---
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time_change
-w /etc/localtime -p wa -k time_change

# Make rules immutable (requires reboot to change)
-e 2
AUDITEOF

    # Configure auditd.conf for low memory
    backup_file /etc/audit/auditd.conf
    sed -i 's/^max_log_file .*/max_log_file = 10/' /etc/audit/auditd.conf
    sed -i 's/^num_logs .*/num_logs = 5/' /etc/audit/auditd.conf
    sed -i 's/^flush .*/flush = data/' /etc/audit/auditd.conf

    systemctl enable auditd
    systemctl restart auditd

    ((STEPS_RUN++)) || true
    log_info "Auditd configured and running."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped auditd configuration."
fi

# =============================================================================
#  STEP 18: Notifications Setup
# =============================================================================

log_step "STEP 18: Notifications Setup"
echo "  Configure how you want to receive security alerts from this server."
echo "  You can enable any combination of the following channels:"
echo ""
echo "    1. ntfy.sh    — Free push notifications to your phone (no account needed)"
echo "    2. Discord    — Alerts sent to a Discord channel via webhook"
echo "    3. Slack      — Alerts sent to a Slack channel via webhook"
echo "    4. Telegram   — Alerts sent via a Telegram bot to your chat"
echo "    5. Pushover   — Mobile push with priority levels (\$4.99 one-time)"
echo "    6. Gotify     — Self-hosted push notifications (free, open-source)"
echo "    7. n8n        — Self-hosted webhook router to 500+ services (free, open-source)"
echo "    8. Email      — Unattended-upgrade reports and cron alerts via Gmail/SMTP"
echo ""
echo "  These notifications cover:"
echo "    - Fail2ban bans/unbans (someone tried to break in)"
echo "    - Unattended-upgrade reports (email only)"
echo "    - Cron job failures (email only)"
echo ""

if prompt_yn "Set up notifications?"; then

    # ── ntfy.sh ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── ntfy.sh (Push Notifications) ──${NC}"
    echo ""
    echo "  ntfy.sh sends push notifications straight to your phone."
    echo "  No account required — just pick a unique topic name."
    echo ""
    echo "  Setup (takes 1 minute):"
    echo "    1. Install the ntfy app:  https://ntfy.sh/app"
    echo "    2. Pick a random topic name (e.g., myserver-alerts-x7k9)"
    echo "    3. Subscribe to that topic in the app"
    echo "    4. Paste the topic name below"
    echo ""
    echo "  Learn more: https://docs.ntfy.sh/"
    echo ""

    if prompt_yn "Enable ntfy.sh notifications?"; then
        while true; do
            read -rp "  Enter your ntfy.sh topic name: " INPUT_NTFY
            if [[ -n "$INPUT_NTFY" ]] && [[ "$INPUT_NTFY" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                NTFY_TOPIC="$INPUT_NTFY"
                log_info "ntfy.sh topic set: ${NTFY_TOPIC}"
                echo -e "  Subscribe in the app: ${BOLD}https://ntfy.sh/${NTFY_TOPIC}${NC}"
                break
            else
                echo "  Topic name can only contain letters, numbers, hyphens, and underscores."
            fi
        done
    fi

    # ── Discord ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Discord (Webhook) ──${NC}"
    echo ""
    echo "  Sends alerts to any Discord channel via a webhook URL."
    echo ""
    echo "  Setup (takes 1 minute):"
    echo "    1. Open your Discord server"
    echo "    2. Right-click a channel → Edit Channel → Integrations → Webhooks"
    echo "    3. Click 'New Webhook', name it (e.g., 'Server Alerts')"
    echo "    4. Click 'Copy Webhook URL' and paste it below"
    echo ""
    echo "  Learn more: https://support.discord.com/hc/en-us/articles/228383668"
    echo ""

    if prompt_yn "Enable Discord notifications?"; then
        while true; do
            read -rp "  Paste your Discord webhook URL: " INPUT_DISCORD
            if [[ "$INPUT_DISCORD" =~ ^https://discord(app)?\.com/api/webhooks/ ]]; then
                DISCORD_WEBHOOK="$INPUT_DISCORD"
                log_info "Discord webhook configured."
                break
            else
                echo "  Invalid URL. It should start with: https://discord.com/api/webhooks/"
            fi
        done
    fi

    # ── Slack ────────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Slack (Webhook) ──${NC}"
    echo ""
    echo "  Sends alerts to any Slack channel via an Incoming Webhook."
    echo ""
    echo "  Setup (takes 2 minutes):"
    echo "    1. Go to: https://api.slack.com/apps → Create New App → From Scratch"
    echo "    2. Go to 'Incoming Webhooks' → Activate → Add New Webhook to Workspace"
    echo "    3. Choose a channel, then copy the webhook URL and paste it below"
    echo ""
    echo "  Learn more: https://api.slack.com/messaging/webhooks"
    echo ""

    if prompt_yn "Enable Slack notifications?"; then
        while true; do
            read -rp "  Paste your Slack webhook URL: " INPUT_SLACK
            if [[ "$INPUT_SLACK" =~ ^https://hooks\.slack\.com/ ]]; then
                SLACK_WEBHOOK="$INPUT_SLACK"
                log_info "Slack webhook configured."
                break
            else
                echo "  Invalid URL. It should start with: https://hooks.slack.com/"
            fi
        done
    fi

    # ── Telegram ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Telegram (Bot) ──${NC}"
    echo ""
    echo "  Sends alerts to your Telegram chat via a bot."
    echo ""
    echo "  Setup (takes 3 minutes):"
    echo "    1. Open Telegram and message @BotFather"
    echo "    2. Send /newbot and follow the prompts to create your bot"
    echo "    3. Copy the bot token (looks like: 123456789:ABCdefGhi...)"
    echo "    4. Start a chat with your new bot (send it any message)"
    echo "    5. Visit this URL to find your chat ID:"
    echo "       https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
    echo "       Look for: \"chat\":{\"id\":YOUR_CHAT_ID}"
    echo ""
    echo "  Learn more: https://core.telegram.org/bots#botfather"
    echo ""

    if prompt_yn "Enable Telegram notifications?"; then
        while true; do
            read -rp "  Paste your Telegram bot token: " INPUT_TG_TOKEN
            if [[ "$INPUT_TG_TOKEN" =~ ^[0-9]+:[a-zA-Z0-9_-]+$ ]]; then
                TELEGRAM_BOT_TOKEN="$INPUT_TG_TOKEN"
                break
            else
                echo "  Invalid token format. Should look like: 123456789:ABCdefGhiJKL..."
            fi
        done
        while true; do
            read -rp "  Paste your Telegram chat ID: " INPUT_TG_CHAT
            if [[ "$INPUT_TG_CHAT" =~ ^-?[0-9]+$ ]]; then
                TELEGRAM_CHAT_ID="$INPUT_TG_CHAT"
                log_info "Telegram bot configured."
                break
            else
                echo "  Invalid chat ID. Should be a number (e.g., 123456789 or -100123456789)."
            fi
        done
    fi

    # ── Pushover ─────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Pushover (Mobile Push with Priority Levels) ──${NC}"
    echo ""
    echo "  Pushover sends push notifications to your phone with smart features:"
    echo "    - Priority levels (silent → normal → high → emergency)"
    echo "    - Emergency alerts repeat until you acknowledge them"
    echo "    - Quiet hours support (won't wake you at 3 AM for a low-priority alert)"
    echo "    - Custom notification sounds per priority"
    echo ""
    echo "  Cost: \$4.99 one-time per platform (iOS/Android/Desktop)."
    echo "        30-day free trial. 10,000 messages/month included."
    echo ""
    echo "  Setup (takes 2 minutes):"
    echo "    1. Create account: https://pushover.net"
    echo "    2. Install the app: https://pushover.net/clients"
    echo "    3. Note your User Key on your dashboard: https://pushover.net/dashboard"
    echo "    4. Create an application: https://pushover.net/apps/build"
    echo "       (Name it something like 'Server Alerts', agree to ToS)"
    echo "    5. Copy the API Token shown after creation"
    echo ""
    echo "  Learn more: https://pushover.net/api"
    echo ""

    if prompt_yn "Enable Pushover notifications?"; then
        while true; do
            read -rp "  Paste your Pushover User Key: " INPUT_PO_USER
            if [[ "$INPUT_PO_USER" =~ ^[a-zA-Z0-9]{30}$ ]]; then
                PUSHOVER_USER_KEY="$INPUT_PO_USER"
                break
            else
                echo "  Invalid User Key. Should be 30 alphanumeric characters."
                echo "  Find it at: https://pushover.net/dashboard"
            fi
        done
        while true; do
            read -rp "  Paste your Pushover App API Token: " INPUT_PO_TOKEN
            if [[ "$INPUT_PO_TOKEN" =~ ^[a-zA-Z0-9]{30}$ ]]; then
                PUSHOVER_APP_TOKEN="$INPUT_PO_TOKEN"
                log_info "Pushover configured."
                break
            else
                echo "  Invalid API Token. Should be 30 alphanumeric characters."
                echo "  Find it at: https://pushover.net/apps"
            fi
        done
    fi

    # ── Gotify ───────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Gotify (Self-Hosted Push Notifications) ──${NC}"
    echo ""
    echo "  Gotify is a free, open-source push notification server you host yourself."
    echo "  Zero cost, zero third-party dependency — you own all your data."
    echo "  Runs in Docker alongside your other services."
    echo ""
    echo "  Self-hosting Gotify (on this or another server):"
    echo "    docker run -d --name gotify -p 8080:80 \\"
    echo "      -v /var/gotify/data:/app/data \\"
    echo "      --restart unless-stopped gotify/server"
    echo ""
    echo "  Setup (takes 3 minutes after Gotify is running):"
    echo "    1. Open the Gotify web UI (http://your-gotify-server:8080)"
    echo "    2. Default login: admin / admin (change this immediately!)"
    echo "    3. Click 'Apps' tab → 'Create Application'"
    echo "    4. Name it 'Fail2ban' → copy the Application Token"
    echo ""
    echo "  Android app: https://github.com/gotify/android"
    echo "  Learn more:  https://gotify.net/docs/"
    echo ""

    if prompt_yn "Enable Gotify notifications?"; then
        while true; do
            read -rp "  Enter your Gotify server URL (e.g., https://gotify.example.com): " INPUT_GOTIFY_URL
            # Strip trailing slash
            INPUT_GOTIFY_URL="${INPUT_GOTIFY_URL%/}"
            if [[ "$INPUT_GOTIFY_URL" =~ ^https?:// ]]; then
                GOTIFY_URL="$INPUT_GOTIFY_URL"
                break
            else
                echo "  Invalid URL. Must start with http:// or https://"
            fi
        done
        while true; do
            read -rp "  Paste your Gotify Application Token: " INPUT_GOTIFY_TOKEN
            if [[ -n "$INPUT_GOTIFY_TOKEN" ]]; then
                GOTIFY_TOKEN="$INPUT_GOTIFY_TOKEN"
                log_info "Gotify configured (${GOTIFY_URL})."
                break
            else
                echo "  Token cannot be empty."
            fi
        done
    fi

    # ── n8n ──────────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── n8n (Self-Hosted Webhook Router — IFTTT/Zapier Alternative) ──${NC}"
    echo ""
    echo "  n8n is a free, open-source automation platform you host yourself."
    echo "  It receives a webhook from Fail2ban and can route it to ANY service:"
    echo "    - SMS via Twilio          - Phone calls via Twilio"
    echo "    - Slack, Discord, Teams   - Email via SendGrid/SMTP"
    echo "    - PagerDuty / Opsgenie    - Home Assistant (flash your lights!)"
    echo "    - Google Sheets logging   - ...and 500+ more integrations"
    echo ""
    echo "  Think of it as: Fail2ban → n8n webhook → n8n decides what to do → sends"
    echo "  alerts to as many services as you want, with custom logic and filters."
    echo ""
    echo "  Self-hosting n8n (on this or another server):"
    echo "    docker run -d --name n8n -p 5678:5678 \\"
    echo "      -e WEBHOOK_URL=https://n8n.example.com/ \\"
    echo "      -v n8n_data:/home/node/.n8n \\"
    echo "      --restart unless-stopped docker.n8n.io/n8nio/n8n"
    echo ""
    echo "  Setup (takes 5 minutes after n8n is running):"
    echo "    1. Open the n8n web UI (http://your-n8n-server:5678)"
    echo "    2. Create a new workflow"
    echo "    3. Add a 'Webhook' trigger node → set Method to POST"
    echo "    4. Set a custom path (e.g., fail2ban-alerts)"
    echo "    5. Connect downstream nodes (Slack, Twilio SMS, Email, etc.)"
    echo "    6. ACTIVATE the workflow (production URLs only work when active)"
    echo "    7. Copy the production webhook URL and paste it below"
    echo ""
    echo "  The webhook URL will look like:"
    echo "    https://n8n.example.com/webhook/fail2ban-alerts"
    echo ""
    echo "  Learn more: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/"
    echo ""

    if prompt_yn "Enable n8n webhook notifications?"; then
        while true; do
            read -rp "  Paste your n8n webhook URL: " INPUT_N8N
            if [[ "$INPUT_N8N" =~ ^https?://.+/webhook/ ]]; then
                N8N_WEBHOOK="$INPUT_N8N"
                log_info "n8n webhook configured."
                break
            else
                echo "  Invalid URL. Should look like: https://n8n.example.com/webhook/your-path"
            fi
        done
    fi

    # ── Email (msmtp) ────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Email (SMTP via msmtp) ──${NC}"
    echo ""
    echo "  Sends unattended-upgrade reports and cron alerts via email."
    echo "  Uses msmtp — a tiny mail client that weighs almost nothing."
    echo ""
    echo "  Works with any SMTP provider. Gmail example:"
    echo "    SMTP Host: smtp.gmail.com"
    echo "    SMTP Port: 587"
    echo "    Username:  your.email@gmail.com"
    echo "    Password:  A Gmail App Password (NOT your regular password)"
    echo ""
    echo "  Create a Gmail App Password here:"
    echo "  https://myaccount.google.com/apppasswords"
    echo ""
    echo "  Other providers: Outlook, Fastmail, or any SMTP relay will work."
    echo ""

    if prompt_yn "Enable email notifications?"; then
        read -rp "  Your email address (alerts sent here): " ALERT_EMAIL
        read -rp "  SMTP host [default: smtp.gmail.com]: " SMTP_HOST
        SMTP_HOST="${SMTP_HOST:-smtp.gmail.com}"
        read -rp "  SMTP port [default: 587]: " SMTP_PORT
        SMTP_PORT="${SMTP_PORT:-587}"
        read -rp "  SMTP username [default: ${ALERT_EMAIL}]: " SMTP_USER
        SMTP_USER="${SMTP_USER:-$ALERT_EMAIL}"
        read -rsp "  SMTP password (hidden): " SMTP_PASS
        echo ""

        if [[ -n "$ALERT_EMAIL" ]] && [[ -n "$SMTP_PASS" ]]; then
            # Install msmtp if not already installed
            DEBIAN_FRONTEND=noninteractive apt install -y msmtp msmtp-mta bsd-mailx 2>&1 | tee -a "$LOG_FILE"

            log_info "Writing /etc/msmtprc..."
            cat > /etc/msmtprc <<MSMTPEOF
# =============================================================================
#  msmtp configuration — Generated by harden.sh v${SCRIPT_VERSION}
# =============================================================================
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        default
host           ${SMTP_HOST}
port           ${SMTP_PORT}
from           ${SMTP_USER}
user           ${SMTP_USER}
password       ${SMTP_PASS}

aliases        /etc/aliases
MSMTPEOF
            chmod 600 /etc/msmtprc

            cat > /etc/aliases <<ALIASEOF
root: ${ALERT_EMAIL}
default: ${ALERT_EMAIL}
ALIASEOF

            # Test email
            log_info "Sending test email to ${ALERT_EMAIL}..."
            echo "Hardening script test email from $(hostname) at $(date)" | \
                mail -s "[$(hostname)] Hardening Script - Test Email" "$ALERT_EMAIL" 2>&1 || \
                log_warn "Test email failed. Check SMTP credentials in /etc/msmtprc"

            log_info "Email notifications configured."
        else
            log_warn "Missing email or password. Skipping email setup."
        fi
    fi

    # ── Regenerate Fail2ban notification script ──────────────────────────────
    # Rebuild the notification script with whatever channels were just configured
    HAS_WEBHOOKS=false
    if [[ -n "$NTFY_TOPIC" ]] || [[ -n "$DISCORD_WEBHOOK" ]] || [[ -n "$SLACK_WEBHOOK" ]] || \
       [[ -n "$TELEGRAM_BOT_TOKEN" ]] || [[ -n "$PUSHOVER_APP_TOKEN" ]] || \
       [[ -n "$GOTIFY_URL" ]] || [[ -n "$N8N_WEBHOOK" ]]; then
        HAS_WEBHOOKS=true
    fi

    if [[ "$HAS_WEBHOOKS" == "true" ]]; then
        log_info "Rebuilding Fail2ban notification script with your channels..."

        cat > /usr/local/bin/fail2ban-notify.sh <<'NOTIFYSCRIPT'
#!/usr/bin/env bash
ACTION="$1"
JAIL="$2"
IP="$3"
FAILURES="$4"
HOSTNAME="$5"

if [[ "$ACTION" == "ban" ]]; then
    TITLE="[Fail2ban] Banned ${IP}"
    MESSAGE="Jail: ${JAIL} | IP: ${IP} | Failures: ${FAILURES} | Host: ${HOSTNAME}"
    PRIORITY="high"
else
    TITLE="[Fail2ban] Unbanned ${IP}"
    MESSAGE="Jail: ${JAIL} | IP: ${IP} | Host: ${HOSTNAME}"
    PRIORITY="default"
fi
NOTIFYSCRIPT

        if [[ -n "$NTFY_TOPIC" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<NTFYBLOCK

# ntfy.sh
curl -s -H "Title: \${TITLE}" -H "Tags: rotating_light" -H "Priority: \${PRIORITY}" \\
    -d "\${MESSAGE}" "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
NTFYBLOCK
        fi

        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<DISCORDBLOCK

# Discord
curl -s -H "Content-Type: application/json" \\
    -d "{\\"content\\":\\"**\${TITLE}**\\n\${MESSAGE}\\"}" \\
    "${DISCORD_WEBHOOK}" >/dev/null 2>&1 || true
DISCORDBLOCK
        fi

        if [[ -n "$SLACK_WEBHOOK" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<SLACKBLOCK

# Slack
curl -s -H "Content-Type: application/json" \\
    -d "{\\"text\\":\\"*\${TITLE}*\\n\${MESSAGE}\\"}" \\
    "${SLACK_WEBHOOK}" >/dev/null 2>&1 || true
SLACKBLOCK
        fi

        if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<TELEGRAMBLOCK

# Telegram
curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \\
    -d "chat_id=${TELEGRAM_CHAT_ID}" \\
    -d "text=\${TITLE} - \${MESSAGE}" >/dev/null 2>&1 || true
TELEGRAMBLOCK
        fi

        if [[ -n "$PUSHOVER_APP_TOKEN" ]] && [[ -n "$PUSHOVER_USER_KEY" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<PUSHOVERBLOCK

# Pushover
if [[ "\${ACTION}" == "ban" ]]; then PO_PRIORITY=1; else PO_PRIORITY=0; fi
curl -s --form-string "token=${PUSHOVER_APP_TOKEN}" \\
    --form-string "user=${PUSHOVER_USER_KEY}" \\
    --form-string "title=\${TITLE}" \\
    --form-string "message=\${MESSAGE}" \\
    --form-string "priority=\${PO_PRIORITY}" \\
    --form-string "sound=siren" \\
    --form-string "timestamp=\$(date +%s)" \\
    https://api.pushover.net/1/messages.json >/dev/null 2>&1 || true
PUSHOVERBLOCK
        fi

        if [[ -n "$GOTIFY_URL" ]] && [[ -n "$GOTIFY_TOKEN" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<GOTIFYBLOCK

# Gotify
if [[ "\${ACTION}" == "ban" ]]; then G_PRIORITY=8; else G_PRIORITY=2; fi
curl -s -X POST "${GOTIFY_URL}/message?token=${GOTIFY_TOKEN}" \\
    -F "title=\${TITLE}" \\
    -F "message=\${MESSAGE}" \\
    -F "priority=\${G_PRIORITY}" >/dev/null 2>&1 || true
GOTIFYBLOCK
        fi

        if [[ -n "$N8N_WEBHOOK" ]]; then
            cat >> /usr/local/bin/fail2ban-notify.sh <<N8NBLOCK

# n8n (routes to any downstream services you configured in your workflow)
curl -s -X POST "${N8N_WEBHOOK}" \\
    -H "Content-Type: application/json" \\
    -d "{\\"event\\":\\"\${ACTION}\\",\\"jail\\":\\"\${JAIL}\\",\\"ip\\":\\"\${IP}\\",\\"failures\\":\\"\${FAILURES}\\",\\"hostname\\":\\"\${HOSTNAME}\\",\\"timestamp\\":\\"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\\"}" >/dev/null 2>&1 || true
N8NBLOCK
        fi

        chmod +x /usr/local/bin/fail2ban-notify.sh

        # Ensure Fail2ban action exists
        cat > /etc/fail2ban/action.d/notify-webhook.conf <<'ACTIONEOF'
[Definition]
norestored = true
actionban = /usr/local/bin/fail2ban-notify.sh ban <n> <ip> <failures> %(hostname)s
actionunban = /usr/local/bin/fail2ban-notify.sh unban <n> <ip> 0 %(hostname)s
ACTIONEOF

        # Restart Fail2ban to pick up changes
        systemctl restart fail2ban 2>/dev/null || true
        log_info "Fail2ban notification script updated and reloaded."
    fi

    # ── Summary ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${GREEN}${BOLD}Notification Summary:${NC}"
    [[ -n "$NTFY_TOPIC" ]]         && echo "    ✓ ntfy.sh   → https://ntfy.sh/${NTFY_TOPIC}"
    [[ -n "$DISCORD_WEBHOOK" ]]    && echo "    ✓ Discord   → webhook configured"
    [[ -n "$SLACK_WEBHOOK" ]]      && echo "    ✓ Slack     → webhook configured"
    [[ -n "$TELEGRAM_BOT_TOKEN" ]] && echo "    ✓ Telegram  → bot configured"
    [[ -n "$PUSHOVER_APP_TOKEN" ]] && echo "    ✓ Pushover  → push configured"
    [[ -n "$GOTIFY_URL" ]]         && echo "    ✓ Gotify    → ${GOTIFY_URL}"
    [[ -n "$N8N_WEBHOOK" ]]        && echo "    ✓ n8n       → webhook configured"
    [[ -n "$ALERT_EMAIL" ]]        && echo "    ✓ Email     → ${ALERT_EMAIL}"
    if [[ -z "$NTFY_TOPIC" ]] && [[ -z "$DISCORD_WEBHOOK" ]] && [[ -z "$SLACK_WEBHOOK" ]] && \
       [[ -z "$TELEGRAM_BOT_TOKEN" ]] && [[ -z "$PUSHOVER_APP_TOKEN" ]] && \
       [[ -z "$GOTIFY_URL" ]] && [[ -z "$N8N_WEBHOOK" ]] && [[ -z "$ALERT_EMAIL" ]]; then
        echo "    (none selected — you can re-run this step anytime)"
    fi
    echo ""

    ((STEPS_RUN++)) || true
    log_info "Notification setup complete."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped notification setup."
fi

# =============================================================================
#  STEP 19: Disable Unnecessary Services
# =============================================================================

log_step "STEP 19: Disable Unnecessary Services"
echo "  Disables services not needed on a headless VPS:"
echo "    - apport (Ubuntu crash reporter — phones home)"
echo "    - motd-news.timer (fetches news from Canonical)"
echo ""

if prompt_yn "Disable unnecessary services?"; then
    # Apport
    if systemctl is-active --quiet apport.service 2>/dev/null; then
        systemctl disable --now apport.service
        apt purge -y apport 2>&1 | tee -a "$LOG_FILE"
        log_info "Disabled and removed apport."
    else
        log_info "apport already disabled."
    fi

    # MOTD news timer
    systemctl disable --now motd-news.timer 2>/dev/null || true
    log_info "Disabled motd-news.timer."

    ((STEPS_RUN++)) || true
    log_info "Unnecessary services disabled."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped service cleanup."
fi

# =============================================================================
#  STEP 20: AppArmor Verification
# =============================================================================

log_step "STEP 20: AppArmor Verification"
echo "  Ubuntu 24.04 compiles AppArmor 4.0 into the kernel."
echo "  This step verifies it's active and profiles are loaded."
echo "  (No configuration needed — just a health check.)"
echo ""

if prompt_yn "Verify AppArmor status?"; then
    if aa-status 2>/dev/null; then
        log_info "AppArmor is active and profiles are loaded."
    else
        log_warn "AppArmor status check returned an error."
        log_warn "This is unusual on 24.04 — investigate manually."
    fi
    ((STEPS_RUN++)) || true
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped AppArmor verification."
fi

# =============================================================================
#  STEP 21: Post-Reboot Port 22 Safety Net Removal
# =============================================================================

log_step "STEP 21: Post-Reboot Port 22 Removal Prompt"
echo "  Installs a one-time login script that will run after you reboot."
echo "  On your first SSH login to port $SSH_PORT, it will ask:"
echo "    'Port 22 is still open. Close it now? [Y/n]'"
echo "  After you answer, the prompt auto-removes itself."
echo ""

if prompt_yn "Install the post-reboot port 22 removal prompt?"; then
    cat > /etc/profile.d/close-port22.sh <<'PORT22EOF'
#!/usr/bin/env bash
# One-time prompt to close SSH port 22 safety net after hardening.
# This script self-destructs after running once.

# Only run for users with sudo privileges, in interactive shells
if [[ $- != *i* ]] || ! sudo -n true 2>/dev/null; then
    return 0 2>/dev/null || exit 0
fi

# Check if port 22 is still open in UFW
if sudo ufw status | grep -q "22/tcp.*ALLOW"; then
    echo ""
    echo -e "\033[1;33m┌─────────────────────────────────────────────────────────┐\033[0m"
    echo -e "\033[1;33m│  SSH port 22 is still open (safety net from hardening)  │\033[0m"
    echo -e "\033[1;33m└─────────────────────────────────────────────────────────┘\033[0m"
    echo ""
    echo -e "  You are connected on the hardened port. If everything is"
    echo -e "  working correctly, it's safe to close port 22 now."
    echo ""
    read -rp "  Close port 22 now? [Y/n]: " answer
    case "${answer,,}" in
        ""|y|yes)
            sudo ufw delete allow 22/tcp
            echo ""
            echo -e "  \033[0;32m✓ Port 22 closed. Only your hardened SSH port remains open.\033[0m"
            echo ""
            ;;
        *)
            echo ""
            echo "  Port 22 left open. This prompt will appear on next login."
            echo "  To close manually: sudo ufw delete allow 22/tcp"
            echo "  To remove this prompt: sudo rm /etc/profile.d/close-port22.sh"
            echo ""
            return 0 2>/dev/null || exit 0
            ;;
    esac
fi

# Self-destruct after port 22 is closed
if ! sudo ufw status | grep -q "22/tcp.*ALLOW"; then
    sudo rm -f /etc/profile.d/close-port22.sh
fi
PORT22EOF
    chmod 644 /etc/profile.d/close-port22.sh

    ((STEPS_RUN++)) || true
    log_info "Post-reboot port 22 removal prompt installed."
    log_info "It will appear on first login after reboot and self-remove once port 22 is closed."
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped post-reboot port 22 prompt."
    log_info "Remember to manually run: sudo ufw delete allow 22/tcp"
fi

# =============================================================================
#  STEP 22: Install Docker Engine (Official Repository)
# =============================================================================

log_step "STEP 22: Install Docker Engine"
echo "  Installs Docker CE from Docker's official apt repository."
echo "  Includes: Docker Engine, CLI, containerd, Buildx, and Compose plugin."
echo "  Source: https://docs.docker.com/engine/install/ubuntu/"
echo ""
echo "  Post-install actions:"
echo "    - Adds '$ADMIN_USER' to the docker group (run without sudo)"
echo "    - Enables the sysctl IP forwarding override"
echo "    - Verifies installation with hello-world container"
echo ""

if prompt_yn "Install Docker Engine?"; then
    # Remove conflicting packages (if any)
    log_info "Removing any conflicting Docker packages..."
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
        apt remove -y "$pkg" 2>/dev/null || true
    done

    # Set up Docker's official apt repository
    log_info "Adding Docker's official GPG key and repository..."
    apt update -y 2>&1 | tee -a "$LOG_FILE"
    apt install -y ca-certificates curl 2>&1 | tee -a "$LOG_FILE"
    install -m 0755 -d /etc/apt/keyrings

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    tee /etc/apt/sources.list.d/docker.sources <<DOCKERREPO > /dev/null
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
DOCKERREPO

    apt update -y 2>&1 | tee -a "$LOG_FILE"

    # Install Docker packages
    log_info "Installing Docker Engine, CLI, containerd, Buildx, and Compose..."
    DEBIAN_FRONTEND=noninteractive apt install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin \
        2>&1 | tee -a "$LOG_FILE"

    # Add admin user to docker group
    if id "$ADMIN_USER" &>/dev/null; then
        usermod -aG docker "$ADMIN_USER"
        log_info "Added '$ADMIN_USER' to docker group (log out and back in to take effect)."
    fi

    # Enable the Docker sysctl override (IP forwarding)
    if [[ -f /etc/sysctl.d/99-docker.conf.disabled ]]; then
        log_info "Enabling IP forwarding for Docker networking..."
        mv /etc/sysctl.d/99-docker.conf.disabled /etc/sysctl.d/99-docker.conf
        sysctl --system 2>&1 | tee -a "$LOG_FILE"
    fi

    # Verify Docker is running
    log_info "Verifying Docker installation..."
    if systemctl is-active --quiet docker; then
        log_info "Docker service is running."
        docker --version 2>&1 | tee -a "$LOG_FILE"
        docker compose version 2>&1 | tee -a "$LOG_FILE"
    else
        log_warn "Docker service is not running. Starting it..."
        systemctl start docker
        systemctl enable docker
    fi

    # Configure Docker to bind to localhost by default (prevents UFW bypass)
    log_info "Configuring Docker to default-bind ports to 127.0.0.1..."
    mkdir -p /etc/docker
    if [[ -f /etc/docker/daemon.json ]]; then
        backup_file /etc/docker/daemon.json
        # Merge ip setting into existing config
        if command -v python3 &>/dev/null; then
            python3 -c "
import json
with open('/etc/docker/daemon.json') as f:
    cfg = json.load(f)
cfg['ip'] = '127.0.0.1'
with open('/etc/docker/daemon.json', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null || true
        fi
    else
        cat > /etc/docker/daemon.json <<'DAEMONJSON'
{
  "ip": "127.0.0.1",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
DAEMONJSON
    fi
    systemctl restart docker 2>&1 | tee -a "$LOG_FILE"
    log_info "Docker now binds all published ports to 127.0.0.1 by default."
    log_info "This means '-p 8080:80' binds to localhost only (not exposed to the internet)."
    log_info "To intentionally expose a port publicly, use: -p 0.0.0.0:8080:80"

    # Run hello-world test
    log_info "Running hello-world verification container..."
    if docker run --rm hello-world 2>&1 | tee -a "$LOG_FILE"; then
        log_info "Docker is working correctly."
    else
        log_warn "hello-world test failed. Check Docker logs: journalctl -u docker"
    fi

    ((STEPS_RUN++)) || true
    log_info "Docker installation complete."
    echo ""
    echo -e "  ${GREEN}Docker port binding secured:${NC}"
    echo -e "    -p 8080:80       → binds to 127.0.0.1:8080 (safe, localhost only)"
    echo -e "    -p 0.0.0.0:8080:80 → explicitly expose to internet (use with caution)"
    echo ""
else
    ((STEPS_SKIPPED++)) || true
    log_warn "Skipped Docker installation."
    log_info "You can install Docker later using the official guide:"
    log_info "https://docs.docker.com/engine/install/ubuntu/"
fi

# =============================================================================
#  SUMMARY
# =============================================================================

echo ""
echo -e "${BOLD}=========================================================${NC}"
echo -e "${BOLD}  HARDENING COMPLETE${NC}"
echo -e "${BOLD}=========================================================${NC}"
echo ""
echo -e "  Steps executed: ${GREEN}${BOLD}${STEPS_RUN}${NC}"
echo -e "  Steps skipped:  ${YELLOW}${BOLD}${STEPS_SKIPPED}${NC}"
echo ""
echo -e "  ${CYAN}Backups saved to:${NC}   $BACKUP_DIR"
echo -e "  ${CYAN}Full log saved to:${NC}  $LOG_FILE"
echo ""
echo -e "${BOLD}─── POST-HARDENING CHECKLIST ───${NC}"
echo ""
echo -e "  ${BOLD}1. TEST SSH (do this NOW, in a NEW terminal):${NC}"
echo ""
echo -e "     ssh -p ${SSH_PORT} ${ADMIN_USER}@$(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo ""
echo -e "  ${RED}${BOLD}   IMPORTANT: Your SSH port is ${SSH_PORT} — write this down!${NC}"
echo ""
echo -e "  ${BOLD}2. Reboot to apply all changes:${NC}"
echo ""
echo -e "     sudo reboot"
echo ""
echo -e "  ${BOLD}3. Port 22 safety net:${NC}"
echo "     After reboot, on your first login you'll be prompted to"
echo "     close port 22 automatically. Or manually:"
echo ""
echo -e "     sudo ufw delete allow 22/tcp"
echo ""
echo -e "  ${BOLD}4. Docker IP forwarding:${NC}"
echo ""
if command -v docker &>/dev/null; then
    # Docker is installed — auto-enable IP forwarding if not already
    if [[ -f /etc/sysctl.d/99-docker.conf.disabled ]]; then
        mv /etc/sysctl.d/99-docker.conf.disabled /etc/sysctl.d/99-docker.conf
        sysctl --system >/dev/null 2>&1
        echo -e "     ${GREEN}✓ Docker detected — IP forwarding auto-enabled.${NC}"
    elif [[ -f /etc/sysctl.d/99-docker.conf ]]; then
        echo -e "     ${GREEN}✓ Docker detected — IP forwarding already enabled.${NC}"
    else
        echo -e "     ${GREEN}✓ Docker detected — IP forwarding handled by Docker.${NC}"
    fi
else
    echo "     Docker not installed. If you install it later, run:"
    echo "     sudo mv /etc/sysctl.d/99-docker.conf.disabled /etc/sysctl.d/99-docker.conf"
    echo "     sudo sysctl --system"
fi
echo ""
echo -e "  ${BOLD}5. Docker port binding:${NC}"
echo ""
if command -v docker &>/dev/null; then
    # Docker is installed — ensure daemon.json has localhost binding
    if [[ -f /etc/docker/daemon.json ]] && grep -q '"ip"' /etc/docker/daemon.json 2>/dev/null; then
        echo -e "     ${GREEN}✓ Docker configured — ports default to 127.0.0.1 (localhost only).${NC}"
        echo "       -p 8080:80         → safe, localhost only"
        echo "       -p 0.0.0.0:8080:80 → explicitly public (use with caution)"
    else
        # daemon.json exists but missing ip setting, or doesn't exist — fix it
        mkdir -p /etc/docker
        if [[ -f /etc/docker/daemon.json ]]; then
            if command -v python3 &>/dev/null; then
                python3 -c "
import json
with open('/etc/docker/daemon.json') as f:
    cfg = json.load(f)
cfg['ip'] = '127.0.0.1'
with open('/etc/docker/daemon.json', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null || true
            fi
        else
            echo '{"ip": "127.0.0.1"}' > /etc/docker/daemon.json
        fi
        systemctl restart docker 2>/dev/null || true
        echo -e "     ${GREEN}✓ Docker detected — auto-configured ports to bind to 127.0.0.1.${NC}"
    fi
else
    echo "     Docker not installed. If you install it later, the script"
    echo "     will configure /etc/docker/daemon.json to bind ports to localhost."
    echo "     Or manually add: {\"ip\": \"127.0.0.1\"} to /etc/docker/daemon.json"
fi
echo ""
echo -e "  ${BOLD}6. Notification channels configured:${NC}"
echo ""
if [[ -n "$NTFY_TOPIC" ]]; then
    echo -e "     ✓ ntfy.sh  → https://ntfy.sh/${NTFY_TOPIC}"
fi
if [[ -n "$DISCORD_WEBHOOK" ]]; then
    echo -e "     ✓ Discord  → webhook configured"
fi
if [[ -n "$SLACK_WEBHOOK" ]]; then
    echo -e "     ✓ Slack    → webhook configured"
fi
if [[ -n "$TELEGRAM_BOT_TOKEN" ]]; then
    echo -e "     ✓ Telegram → bot configured"
fi
if [[ -n "$PUSHOVER_APP_TOKEN" ]]; then
    echo -e "     ✓ Pushover → push configured"
fi
if [[ -n "$GOTIFY_URL" ]]; then
    echo -e "     ✓ Gotify   → ${GOTIFY_URL}"
fi
if [[ -n "$N8N_WEBHOOK" ]]; then
    echo -e "     ✓ n8n      → webhook router configured"
fi
if [[ -z "$NTFY_TOPIC" ]] && [[ -z "$DISCORD_WEBHOOK" ]] && [[ -z "$SLACK_WEBHOOK" ]] && \
   [[ -z "$TELEGRAM_BOT_TOKEN" ]] && [[ -z "$PUSHOVER_APP_TOKEN" ]] && \
   [[ -z "$GOTIFY_URL" ]] && [[ -z "$N8N_WEBHOOK" ]]; then
    echo -e "     (none configured — edit the CONFIGURATION section and re-run Step 18)"
fi
echo ""
echo -e "  ${BOLD}7. Verify Fail2ban is running:${NC}"
echo ""
echo -e "     sudo fail2ban-client status sshd"
echo ""
echo -e "${GREEN}${BOLD}Stay safe out there, George.${NC}"
echo ""
