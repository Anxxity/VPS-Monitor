#!/usr/bin/env python3
import os

# --- Discord Settings ---
DISCORD_WEBHOOK = os.getenv(
    "DISCORD_WEBHOOK",
    "https://discord.com/api/webhooks/1552957510955040780/Qfb5dfnzNG1KtdCTqCGZzsWcxfaM0gMdpsoCatqXKtZrnJkHbLrqiPxhKdSajDPil-fB"
)

ALERT_COLORS = {
    "connection": 0x00ff00,   # Green
    "file_change": 0xff9900,  # Orange
    "ssh_login": 0x00ff00,    # Green
    "ssh_failed": 0xff0000,   # Red
    "file_access": 0x00ffff,  # Cyan
    "device": 0x9B59B6,       # Purple (Keyboard/Mouse/USB)
    "error": 0x808080,        # Gray
    "info": 0x808080          # Gray
}

ALERT_TITLES = {
    "ssh_login": "SSH Login Succeeded",
    "ssh_failed": "SSH Login Failed",
    "file_access": "Sensitive File Access",
    "connection": "New Network Connection",
    "file_change": "File System Event",
    "device": "Hardware / USB Peripheral",
    "error": "System Alert",
    "info": "VPS Monitor Status"
}

# --- Network & Port Exclusions ---
IGNORE_LOOPBACK = True          # Ignore localhost (127.0.0.1 / ::1)
EXCLUDED_PORTS = []             # Ports to ignore (e.g. [80, 443])
EXCLUDED_LOCAL_PORTS = []       # Ignore only if local port matches
EXCLUDED_REMOTE_PORTS = []      # Ignore only if remote port matches
SKIP_HOSTS = [".example.net"]   # Ignore connections ending in these hostnames
SKIP_IP_RANGES = [
    "192.168.11.1",
    "192.168.11.78"
]

# --- SSH Monitoring ---
MY_USERNAME = "jetson"
MONITOR_FAILED_SSH = True       # Alert on failed login attempts
FAILED_SSH_ALERT_THRESHOLD = 3  # Failed attempts before alerting
SSH_LOG_FILES = [
    "/var/log/auth.log",        # Debian / Ubuntu (rsyslog)
    "/var/log/secure"           # RHEL / CentOS
]
USE_JOURNALCTL = True           # Fallback for Ubuntu 22.04+ (systemd-journald)

# --- Hardware / Peripheral Monitoring ---
MONITOR_PERIPHERALS = True      # Alert when keyboard, mouse, or USB devices are plugged/unplugged

# --- File System Monitoring ---
MONITOR_FOLDERS = [
    "/home/jetson",
    "/etc/ssh",
    "/root"
]

CHECK_INTERVAL = 10             # Seconds between checks
DUPLICATE_ALERT_THRESHOLD = 2   # Suppress identical alerts within X seconds

# --- File & Folder Exclusions ---
# Exclude entire folders, specific files, or wildcard patterns
EXCLUDED_PATHS = [
    # Robot runtime files, databases, and logs
    "/home/jetson/.ros",
    "/home/jetson/.cache",
    "/home/jetson/.local",
    "/home/jetson/.robot/logs",
    "/home/jetson/.robot/src/tara_gen_one/db.sqlite3*",
    "/home/jetson/.robot/src/robot/api/*.json",
    "/home/jetson/.robot/src/robot/gpt/*.json",

    # Monitor script itself
    "/home/jetson/.robot/src/scripts/VPS-Monitor",
    "/root/vps-monitor",

    # Common temporary directories
    "/tmp",
    "/var/tmp"
]

# Exclude specific file extensions anywhere (e.g. .json, .log, .sqlite3, .sqlite3-journal)
EXCLUDED_EXTENSIONS = [
    ".json",
    ".sqlite3",
    ".sqlite3-journal",
    ".log",
    ".tmp",
    ".swp",
    ".pyc"
]

# Exclude specific filenames anywhere
EXCLUDED_FILENAMES = [
    ".bash_history",
    "db.sqlite3-journal",
    ".viminfo",
    ".DS_Store"
]

CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config"
]

AUDIT_LOG_FILE = "/var/log/audit/audit.log"

# --- Timeouts (seconds) ---
DISCORD_TIMEOUT = 10
SS_COMMAND_TIMEOUT = 10
DNS_TIMEOUT = 2.0