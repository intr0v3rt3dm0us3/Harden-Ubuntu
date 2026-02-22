# Ubuntu 24.04 LTS — Interactive Server Hardening Script

*** ALPHA VERSION. ***
*** TEST AND USE AT OWN RISK. ***
*** CREATED WITH CLAUDE AI ***

A single interactive bash script that hardens a fresh Ubuntu 24.04 LTS server. Every setting is configured through interactive prompts — **no manual file editing required**. Each step prompts you with **Y/n** before executing.

Designed for **DigitalOcean droplets** (512MB / 1 CPU / 10GB SSD) but works on any Ubuntu 24.04 VPS.

*** ONLY TESTED ON ABOVE DROPLET ***

## What It Does

| Step | Description |
|------|-------------|
| 1 | Full system update & upgrade |
| 2 | Install required packages (ufw, fail2ban, auditd, etc.) |
| 3 | Set timezone & enable NTP |
| 4 | Create non-root admin user with SSH keys |
| 5 | **SSH hardening** — random port (49152–65535), key-only auth, post-quantum algorithms, host key regeneration |
| 6 | **UFW firewall** — allow SSH/HTTP/HTTPS only, Docker/UFW conflict fix pre-installed |
| 7 | **Fail2ban** — brute-force protection with 2hr ban (escalating), 1wk recidive, multi-channel notifications |
| 8 | **Kernel/sysctl hardening** — SYN flood protection, ICMP hardening, ASLR, ptrace restriction |
| 9 | Disable unused kernel modules (cramfs, dccp, sctp, etc.) |
| 10 | CIS-aligned file permissions |
| 11 | Shared memory hardening (noexec on /dev/shm) |
| 12 | Disable core dumps |
| 13 | Legal login banners, disable Ubuntu MOTD news, random dad jokes on login |
| 14 | Password policy & umask 077 |
| 15 | **Unattended upgrades** — auto security updates, user-chosen reboot time, Docker packages blacklisted |
| 16 | Journald log limits (100MB cap for 512MB VPS) |
| 17 | **Auditd** — lightweight 20-rule set monitoring passwd, shadow, sudoers, SSH, cron, kernel modules |
| 18 | **Notifications** — interactive setup for ntfy, Discord, Slack, Telegram, Pushover, Gotify, n8n, Email |
| 19 | Disable unnecessary services (apport, motd-news) |
| 20 | AppArmor 4.0 verification |
| 21 | **Post-reboot port 22 prompt** — auto-asks to close safety-net port on first login, self-removes |
| 22 | **Docker Engine** — official apt repo install with Compose, Buildx, auto IP forwarding, user group setup |

## Ubuntu 24.04-Specific Handling

This script accounts for breaking changes in 24.04 that trip up older hardening guides:

- **SSH socket activation** — restarts `ssh.socket` (not `ssh.service`) and creates a systemd socket override for custom ports
- **AppArmor 4.0** — compiled into kernel, cannot be disabled via service
- **Fail2ban 1.1.0** — uses `systemd` backend (the `pyinotify` approach from 22.04 is broken on Python 3.12)
- **nftables** backend — UFW rules work through the iptables-nft compatibility shim

## Prerequisites

1. A fresh Ubuntu 24.04 LTS server
2. Root access (or sudo)
3. **Your SSH public key already added to the server** (the script disables password auth)

## Quick Start

```bash
# 1. SSH into your server as root
ssh root@your-server-ip

# 2. Download the script
curl -O https://raw.githubusercontent.com/intr0v3rt3dm0us3/Harden-Ubuntu/refs/heads/main/harden.sh

# 3. Make executable and run — everything is interactive, no editing required
chmod +x harden.sh
sudo ./harden.sh
```

## Configuration

Everything is configured interactively as you step through the script — no manual file editing required. Here's what each step will prompt you for:

| Setting | When prompted | Default |
|---------|-------------|---------|
| Admin username | Step 4 | `deploy` |
| Admin password | Step 4 | (you set it) |
| Timezone | Step 3 | `America/New_York` |
| SSH port | Auto-generated | Random (49152–65535) |
| Auto-reboot time | Step 15 | `03:00` |
| Notifications | Step 18 | (choose any/all of 8 channels) |

Every prompt accepts a default by pressing Enter, so you can blaze through the basics and only pause on the steps you want to customize.

## After Running

The script prints a checklist at the end. The critical steps:

```bash
# 1. TEST SSH in a NEW terminal (don't close your current session!)
# The script displays your randomized port — write it down!
ssh -p YOUR_PORT deploy@your-server-ip

# 2. Reboot to apply all changes
sudo reboot

# 3. On first login after reboot, you'll be prompted:
#    "Port 22 is still open. Close it now? [Y/n]"
#    Just press Enter to close it. The prompt self-removes.

# 4. Docker IP forwarding is auto-detected and enabled if Docker is installed.
#    If you install Docker later, run:
sudo mv /etc/sysctl.d/99-docker.conf.disabled /etc/sysctl.d/99-docker.conf
sudo sysctl --system

# 5. Docker port binding is auto-configured to default to 127.0.0.1 (localhost).
#    -p 8080:80         → safe, binds to localhost only
#    -p 0.0.0.0:8080:80 → explicitly expose to internet (use with caution)
```

## Docker + UFW Safety

Docker bypasses UFW by manipulating iptables directly. This script pre-installs the [chaifeng/ufw-docker](https://github.com/chaifeng/ufw-docker) fix in `/etc/ufw/after.rules`. Combined with binding containers to `127.0.0.1`, your firewall rules are respected.

## Notifications

Eight notification channels are supported — all configured interactively in Step 18. Enable any combination:

| Method | Type | What it covers | Cost |
|--------|------|---------------|------|
| **[ntfy.sh](https://ntfy.sh)** | Cloud push | Fail2ban bans/unbans → push to your phone | Free, no account needed |
| **[Discord](https://support.discord.com/hc/en-us/articles/228383668)** | Webhook | Fail2ban alerts → Discord channel | Free |
| **[Slack](https://api.slack.com/messaging/webhooks)** | Webhook | Fail2ban alerts → Slack channel | Free |
| **[Telegram](https://core.telegram.org/bots#botfather)** | Bot | Fail2ban alerts → Telegram chat | Free |
| **[Pushover](https://pushover.net)** | Mobile push | Fail2ban alerts with priority levels, quiet hours, emergency repeat | $4.99 one-time per platform |
| **[Gotify](https://gotify.net)** | Self-hosted push | Fail2ban alerts — you host it, you own the data | Free, open-source |
| **[n8n](https://n8n.io)** | Self-hosted router | Fail2ban → routes to SMS, Slack, PagerDuty, 500+ services | Free, open-source |
| **Email (msmtp)** | SMTP | Unattended-upgrade reports, cron failures | Free (with Gmail/SMTP) |

All webhook channels share a single notification script (`/usr/local/bin/fail2ban-notify.sh`). The script walks you through each channel with setup instructions, reference links, and input validation.

### Self-Hosting Highlights

**Gotify** and **n8n** can both run as Docker containers on this server or any other VPS. Quick start:

```bash
# Gotify — self-hosted push notifications
docker run -d --name gotify -p 8080:80 \
  -v /var/gotify/data:/app/data --restart unless-stopped gotify/server

# n8n — self-hosted IFTTT/Zapier alternative
docker run -d --name n8n -p 5678:5678 \
  -e WEBHOOK_URL=https://n8n.example.com/ \
  -v n8n_data:/home/node/.n8n --restart unless-stopped docker.n8n.io/n8nio/n8n
```

n8n is especially powerful — a single webhook from Fail2ban can trigger SMS via Twilio, post to Slack, create a PagerDuty incident, log to Google Sheets, and flash your smart lights, all from one visual workflow.

## Safety Features

- Every modified file is backed up to `/root/harden-backup-TIMESTAMP/`
- SSH config is validated with `sshd -t` before applying
- Port 22 remains open as a safety net until you reboot and approve its removal
- Post-reboot login prompt auto-asks to close port 22, then self-removes
- Full log saved to `/var/log/harden-TIMESTAMP.log`
- Each step is independently skippable — re-run the script anytime

## References

- [CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [SSH Audit Hardening Guides](https://www.sshaudit.com/hardening_guides.html)
- [Docker Packet Filtering & Firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Ubuntu 24.04 Security Features](https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts)

## License

MIT
