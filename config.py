#!/usr/bin/env python3

# Discord Configuration
DISCORD_WEBHOOK = ""

# Monitoring Configuration
CHECK_INTERVAL = 30  # seconds between security checks
MY_USERNAME = "root"  # VPS username

# File Monitoring Configuration
EXCLUDED_PATHS = [
    "/root/vps-monitor/lib/python3.11/",
    "/root/.cache",
    "/root/.ssh",
    "/root/.local",
    "/root/vps-monitor"
]

# Critical files to monitor for changes
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow", 
    "/etc/ssh/sshd_config"
]

# Log file paths for SSH monitoring
SSH_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure"
]

# Audit log configuration
AUDIT_LOG_FILE = "/var/log/audit/audit.log"

# Folder to monitor for file changes
MONITOR_FOLDER = "/root"

# Discord alert configuration
ALERT_COLORS = {
    "connection": 0x00ff00,
    "file_change": 0xff9900,
    "ssh_login": 0x00ff00,
    "ssh_failed": 0xff0000,
    "file_access": 0x00ffff,
    "error": 0x808080,
    "info": 0x808080
}

ALERT_TITLES = {
    "ssh_login": "🎮 SSH Login",
    "ssh_failed": "❌ SSH Login Failed",
    "file_access": "📂 File Access",
    "connection": "🔗 Connection",
    "file_change": "📝 File Changed",
    "info": "ℹ️ Information"
}

# Duplicate alert prevention (seconds)
DUPLICATE_ALERT_THRESHOLD = 2

# Network monitoring configuration
# Skip connections from these hosts
SKIP_HOSTS = [
    ".example.net"  # Contabo VPS connections
]

# Skip connections from these IP ranges
SKIP_IP_RANGES = [
    # eg : "162.159."  # Cloudflare IPs
]

# Request timeout settings
DISCORD_TIMEOUT = 10  # seconds
SS_COMMAND_TIMEOUT = 10  # seconds

