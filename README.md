# VPS Monitor

A comprehensive security monitoring solution for Linux VPS servers that sends alerts to Discord. It monitors file system changes, SSH logins, network connections, and sensitive file access.

## Features

- 🔐 Real-time file system monitoring
- 🔍 Audit log monitoring for sensitive file access
- 🌐 Network connection tracking
- 🔑 SSH login detection
- 📢 Discord webhook integration
- 🚫 Configurable exclusions and filters

## Requirements

- Python 3.6+
- Linux VPS with root access
- Discord webhook URL

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vps-monitor.git
cd vps-monitor
```

2. Install required packages:
```bash
pip install watchdog requests
```

3. Configure audit logging on your VPS:
```bash
auditctl -w /root -p wa -k root_write
```

4. Copy the example config and edit it:
```bash
cp config.example.py config.py
nano config.py
```

## Configuration

Edit `config.py` with your settings:

- `DISCORD_WEBHOOK`: Your Discord webhook URL
- `MONITOR_FOLDER`: Root folder to monitor for changes
- `EXCLUDED_PATHS`: List of paths to exclude from monitoring
- `CRITICAL_FILES`: List of sensitive files to monitor
- `SSH_LOG_FILES`: SSH log file locations
- `CHECK_INTERVAL`: How often to check for changes (in seconds)
- `SKIP_HOSTS`: Hostnames to ignore in connection monitoring
- `SKIP_IP_RANGES`: IP ranges to ignore

## Usage

Run the monitor:
```bash
python3 audit_to_discord.py
```

For permanent installation, create a systemd service:
```bash
sudo nano /etc/systemd/system/vps-monitor.service
```

Add the following content:
```ini
[Unit]
Description=VPS Monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/audit_to_discord.py
WorkingDirectory=/path/to/vps-monitor
User=root
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable vps-monitor
sudo systemctl start vps-monitor
```

## Alert Types

- 📁 File system changes (create/modify/delete)
- 📥 Sensitive file access attempts
- 🔗 New network connections
- 🎮 SSH login attempts
- ⚠️ System errors

## License

MIT License

## Security Considerations

- Keep your Discord webhook URL private
- Regularly review excluded paths and IP ranges
- Monitor the monitor's logs for any issues
- Ensure proper file permissions on config files
