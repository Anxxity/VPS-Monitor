
#!/usr/bin/env python3
import os
import time
import subprocess
import requests
import re
import hashlib
import threading
import queue
import glob
import socket
import pwd
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Import configuration
from config import (
    DISCORD_WEBHOOK, EXCLUDED_PATHS, CHECK_INTERVAL, MY_USERNAME,
    CRITICAL_FILES, SSH_LOG_FILES, AUDIT_LOG_FILE, MONITOR_FOLDER,
    ALERT_COLORS, ALERT_TITLES, DUPLICATE_ALERT_THRESHOLD,
    SKIP_HOSTS, SKIP_IP_RANGES, DISCORD_TIMEOUT, SS_COMMAND_TIMEOUT
)

# ==========================================

# Queue for async Discord alerts
alert_queue = queue.Queue()

# ----------------- Discord -----------------
# top of file
recent_alerts = {}

def send_to_discord(message: str, alert_type="info"):
    global recent_alerts
    now = time.time()

    # avoid duplicates within configured threshold
    if message in recent_alerts and now - recent_alerts[message] < DUPLICATE_ALERT_THRESHOLD:
        return  

    recent_alerts[message] = now

    embed = {
        "title": ALERT_TITLES.get(alert_type, "🔐 VPS Monitor"),
        "description": message,
        "color": ALERT_COLORS.get(alert_type, 0x808080),
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": f"VPS Monitor | {socket.gethostname()}"}
    }
    alert_queue.put({"embeds": [embed]})


def discord_worker():
    while True:
        try:
            payload = alert_queue.get(timeout=1)
            try:
                r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=DISCORD_TIMEOUT)
                if r.status_code not in (200, 204):
                    print(f"Discord error {r.status_code}: {r.text}")
            except Exception as e:
                print(f"Discord sender error: {e}")
                time.sleep(5)
        except queue.Empty:
            continue


# ----------------- File Access Monitor -----------------
def uid_to_user(uid: str) -> str:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except Exception:
        return f"UID:{uid}"




def is_excluded(path: str) -> bool:
    for excl in EXCLUDED_PATHS:
        excl = os.path.normpath(excl)
        norm_path = os.path.normpath(path)
        if norm_path == excl or norm_path.startswith(excl + os.sep):
            return True
    return False



def monitor_audit_logs():
    log_file = AUDIT_LOG_FILE
    print(f"🔎 Monitoring {log_file} for file reads in /root ...")
    last_sent = None
    current_uid = None

    with open(log_file, "r") as f:
        f.seek(0, 2)  # tail -f
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            if "type=SYSCALL" in line and "uid=" in line:
                parts = [p for p in line.split() if p.startswith("uid=")]
                if parts:
                    current_uid = parts[0].split("=")[1]

            if "/root/" in line and "type=PATH" in line:
                parts = [p for p in line.split() if p.startswith("name=")]
                filename = parts[0].split("=")[1].strip('"') if parts else "unknown"

                if is_excluded(filename):
                    continue

                username = uid_to_user(current_uid) if current_uid else "unknown"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                msg = f"**File:** `{filename}`\n**User:** `{username}`\n**Time:** {timestamp}"
                if msg != last_sent:
                    print("📥 File accessed:", msg)
                    send_to_discord(msg, alert_type="file_access")
                    last_sent = msg


# ----------------- Watchdog File Monitor -----------------
class ChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not is_excluded(event.src_path):
            send_to_discord(f"Created: `{event.src_path}`", "file_change")

    def on_deleted(self, event):
        if not is_excluded(event.src_path):
            send_to_discord(f"Deleted: `{event.src_path}`", "file_change")

    def on_modified(self, event):
        if not is_excluded(event.src_path):
            send_to_discord(f"Modified: `{event.src_path}`", "file_change")

    def on_moved(self, event):
        if not is_excluded(event.src_path) and not is_excluded(event.dest_path):
            send_to_discord(f"Moved: `{event.src_path}` → `{event.dest_path}`", "file_change")


def monitor_folder(path=MONITOR_FOLDER):
    observer = Observer()
    observer.schedule(ChangeHandler(), path, recursive=True)
    observer.start()
    print(f"📂 Monitoring folder: {path}")
    send_to_discord(f"✅ Folder monitoring started on `{path}`", "info")
    return observer


# ----------------- Security Monitor -----------------
class VPSSecurityMonitor:
    def __init__(self, check_interval=CHECK_INTERVAL):
        self.check_interval = check_interval
        self.known_connections = set()
        self.file_hashes = {}
        self.logged_ssh_sessions = set()
        self.critical_files = CRITICAL_FILES
        self.init_hashes()

    def init_hashes(self):
        for file_path in self.critical_files:
            if os.path.exists(file_path):
                self.file_hashes[file_path] = self.hash_file(file_path)

    def hash_file(self, file_path):
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def check_file_changes(self):
        for file_path in list(self.file_hashes.keys()):
            if os.path.exists(file_path):
                new_hash = self.hash_file(file_path)
                if new_hash and new_hash != self.file_hashes[file_path]:
                    msg = f"{file_path} modified at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    print("📝", msg)
                    send_to_discord(msg, "file_change")
                    self.file_hashes[file_path] = new_hash

    def check_connections(self):
        try:
            result = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=SS_COMMAND_TIMEOUT)
            hostname = socket.gethostname()
            for line in result.stdout.split("\n"):
                if "ESTAB" in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        local = parts[4]
                        remote = parts[5]

                        pid_info = parts[-1] if "pid=" in parts[-1] else None
                        username = "Unknown"

                        if pid_info and "pid=" in pid_info:
                            pid_match = re.search(r"pid=(\d+)", pid_info)
                            if pid_match:
                                pid = pid_match.group(1)
                                try:
                           
                                    with open(f"/proc/{pid}/status") as f:
                                        for l in f:
                                            if l.startswith("Uid:"):
                                                uid = int(l.split()[1])
                                                username = pwd.getpwuid(uid).pw_name
                                                break
                                except Exception:
                                    username = "Unknown"

                        conn_key = f"{local}->{remote}"
                        if conn_key not in self.known_connections:
                            self.known_connections.add(conn_key)

                            remote_ip = remote.split(":")[0]

                            try:
                                remote_host = socket.gethostbyaddr(remote_ip)[0]
                            except Exception:
                                remote_host = None

                            if remote_host and any(remote_host.endswith(host) for host in SKIP_HOSTS):
                                continue  

                            if any(remote_ip.startswith(ip_range) for ip_range in SKIP_IP_RANGES):
                                continue  

                            msg = (
                                f"New connection on **{hostname}**\n"
                                f"🔹 Local: `{local}`\n"
                                f"🔹 Remote IP: `{remote_ip}`\n"
                                f"🔹 Host: `{remote_host or 'N/A'}`\n"
                                f"🔹 User: `{username}`"
                            )
                            print("🔗", msg)
                            send_to_discord(msg, "connection")
        except Exception as e:
            send_to_discord(f"Error checking connections: {e}", "error")



    def check_ssh_logins(self):
        logs = SSH_LOG_FILES
        for log in logs:
            if os.path.exists(log):
                result = subprocess.run(["tail", "-100", log], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "sshd" in line and "Accepted" in line:
                        if line not in self.logged_ssh_sessions:
                            self.logged_ssh_sessions.add(line)

                            user_match = re.search(r"for (\w+)", line)
                            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

                            user = user_match.group(1) if user_match else "Unknown"
                            ip = ip_match.group(1) if ip_match else "Unknown"

                            try:
                             remote_host = socket.gethostbyaddr(ip)[0]
                            except Exception:
                                remote_host = None

                            msg = (
                                f"SSH login accepted\n"
                                f"🔹 VPS Host: **{socket.gethostname()}**\n"
                                f"🔹 User: `{user}`\n"
                                f"🔹 IP: `{ip}`\n"
                                f"🔹 Host: `{remote_host or 'N/A'}`"
                            )
                            print("🎮", msg)
                            send_to_discord(msg, "ssh_login")


    def run(self):
        while True:
            self.check_connections()
            self.check_file_changes()
            self.check_ssh_logins()
            time.sleep(self.check_interval)


# ----------------- Main -----------------
def main():
    if not DISCORD_WEBHOOK.startswith("http"):
        print("⚠️ Please set your Discord webhook in the script!")
        return

    threading.Thread(target=discord_worker, daemon=True).start()
    threading.Thread(target=monitor_audit_logs, daemon=True).start()

    observer = monitor_folder()

    monitor = VPSSecurityMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        observer.stop()
        print("🛑 Monitoring stopped.")
    observer.join()


if __name__ == "__main__":
    main()
