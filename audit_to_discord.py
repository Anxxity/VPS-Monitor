#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import requests
import re
import hashlib
import threading
import queue
import socket
import ipaddress
import signal
import glob
import fnmatch
from datetime import datetime
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import pwd
except ImportError:
    pwd = None

from config import (
    DISCORD_WEBHOOK, EXCLUDED_PATHS, CHECK_INTERVAL, CRITICAL_FILES,
    SSH_LOG_FILES, AUDIT_LOG_FILE, ALERT_COLORS, ALERT_TITLES,
    DUPLICATE_ALERT_THRESHOLD, SKIP_HOSTS, SKIP_IP_RANGES, DISCORD_TIMEOUT,
    SS_COMMAND_TIMEOUT, DNS_TIMEOUT, IGNORE_LOOPBACK, EXCLUDED_PORTS,
    EXCLUDED_LOCAL_PORTS, EXCLUDED_REMOTE_PORTS, MONITOR_FAILED_SSH,
    FAILED_SSH_ALERT_THRESHOLD, USE_JOURNALCTL, MONITOR_PERIPHERALS
)

try:
    from config import MONITOR_FOLDERS
except ImportError:
    from config import MONITOR_FOLDER
    MONITOR_FOLDERS = [MONITOR_FOLDER]

if isinstance(MONITOR_FOLDERS, str):
    MONITOR_FOLDERS = [MONITOR_FOLDERS]

try:
    from config import EXCLUDED_EXTENSIONS
except ImportError:
    EXCLUDED_EXTENSIONS = []

try:
    from config import EXCLUDED_FILENAMES
except ImportError:
    EXCLUDED_FILENAMES = []

shutdown_event = threading.Event()
alert_queue = queue.Queue(maxsize=1000)
recent_alerts = {}
recent_alerts_lock = threading.Lock()
dns_cache = {}
dns_cache_lock = threading.Lock()


# --- Structured Console Logger ---

class Style:
    USE_COLOR = sys.stdout.isatty() or os.environ.get("TERM") is not None
    RESET = "\033[0m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""
    CYAN = "\033[96m" if USE_COLOR else ""
    BLUE = "\033[94m" if USE_COLOR else ""
    GREEN = "\033[92m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    RED = "\033[91m" if USE_COLOR else ""
    MAGENTA = "\033[95m" if USE_COLOR else ""
    GRAY = "\033[90m" if USE_COLOR else ""

TAG_STYLES = {
    "SYS": Style.CYAN,
    "INFO": Style.CYAN,
    "NET": Style.BLUE,
    "SSH": Style.GREEN,
    "AUTH_FAIL": Style.RED,
    "FILE": Style.YELLOW,
    "AUDIT": Style.MAGENTA,
    "DEV": Style.MAGENTA,
    "WARN": Style.YELLOW,
    "ERROR": Style.RED,
}

def log(tag: str, text: str, detail: str = ""):
    """Prints a styled, timestamped log line."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag_upper = tag.upper()
    color = TAG_STYLES.get(tag_upper, Style.GRAY)
    tag_formatted = f"{color}[{tag_upper:<9}]{Style.RESET}"
    ts_formatted = f"{Style.GRAY}[{ts}]{Style.RESET}"
    if detail:
        print(f"{ts_formatted} {tag_formatted} {text} {Style.DIM}| {detail}{Style.RESET}")
    else:
        print(f"{ts_formatted} {tag_formatted} {text}")


# --- Helper Functions ---

def uid_to_user(uid: str) -> str:
    if not uid or not pwd:
        return f"UID:{uid}" if uid else "unknown"
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except Exception:
        return f"UID:{uid}"


def parse_endpoint(endpoint_str: str):
    """Extracts (ip, port) from IPv4, IPv6, or hostname strings."""
    endpoint_str = endpoint_str.strip()
    if not endpoint_str or endpoint_str == "*":
        return "", None

    # Bracketed IPv6 like [2001:db8::1]:443
    if endpoint_str.startswith("["):
        idx = endpoint_str.find("]")
        if idx != -1:
            ip = endpoint_str[1:idx]
            port = endpoint_str[idx + 1:].lstrip(":")
            return ip, (int(port) if port.isdigit() else None)

    # Standard IP:port
    if ":" in endpoint_str:
        parts = endpoint_str.rsplit(":", 1)
        return parts[0].strip("[]"), (int(parts[1]) if parts[1].isdigit() else None)

    return endpoint_str, None


def is_loopback(ip_str: str) -> bool:
    if not ip_str:
        return False
    clean = ip_str.lower().removeprefix("::ffff:")
    if clean in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::", "*"):
        return True
    try:
        return ipaddress.ip_address(clean).is_loopback
    except ValueError:
        return False


def is_ip_skipped(ip_str: str) -> bool:
    """Checks if an IP matches SKIP_IP_RANGES (CIDR or prefix)."""
    if not ip_str:
        return False
    clean = ip_str.lower().removeprefix("::ffff:")
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        ip_obj = None

    for item in SKIP_IP_RANGES:
        item = str(item).strip()
        if not item:
            continue
        if "/" in item and ip_obj:
            try:
                if ip_obj in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                pass
        if clean == item or clean.startswith(item):
            return True
    return False


def is_port_excluded(local_port: int, remote_port: int) -> bool:
    """Checks if local or remote port is in exclusion lists."""
    all_excl = set(int(p) for p in EXCLUDED_PORTS if str(p).isdigit())
    loc_excl = set(int(p) for p in EXCLUDED_LOCAL_PORTS if str(p).isdigit())
    rem_excl = set(int(p) for p in EXCLUDED_REMOTE_PORTS if str(p).isdigit())

    if local_port and (local_port in all_excl or local_port in loc_excl):
        return True
    if remote_port and (remote_port in all_excl or remote_port in rem_excl):
        return True
    return False


def resolve_hostname(ip_str: str) -> str:
    """Resolves IP to hostname with caching and fast timeout."""
    if not ip_str or is_loopback(ip_str):
        return "localhost"

    now = time.time()
    with dns_cache_lock:
        if ip_str in dns_cache:
            host, ts = dns_cache[ip_str]
            if now - ts < 3600:
                return host

    old_timeout = socket.getdefaulttimeout()
    host = None
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        clean = ip_str.lower().removeprefix("::ffff:")
        host = socket.gethostbyaddr(clean)[0]
    except Exception:
        host = None
    finally:
        socket.setdefaulttimeout(old_timeout)

    with dns_cache_lock:
        dns_cache[ip_str] = (host, now)
        if len(dns_cache) > 1000:
            dns_cache.clear()
    return host


def is_path_excluded(path: str) -> bool:
    """
    Checks if a path should be ignored based on:
    1. EXCLUDED_EXTENSIONS (e.g. .json, .sqlite3, .log)
    2. EXCLUDED_FILENAMES (e.g. .bash_history)
    3. EXCLUDED_PATHS (exact directory, specific file, or wildcard pattern)
    """
    if not path:
        return False
    norm_path = os.path.normpath(path)
    basename = os.path.basename(path)
    lower_name = basename.lower()

    # 1. Check file extensions
    for ext in EXCLUDED_EXTENSIONS:
        if not ext:
            continue
        ext_clean = ext.lower()
        if not ext_clean.startswith("."):
            ext_clean = "." + ext_clean
        if lower_name.endswith(ext_clean):
            return True

    # 2. Check exact file names
    if basename in EXCLUDED_FILENAMES:
        return True

    # 3. Check paths, directories, and wildcard glob patterns
    for excl in EXCLUDED_PATHS:
        if not excl:
            continue
        norm_excl = os.path.normpath(excl)

        # Exact path match or child of excluded directory
        if norm_path == norm_excl or norm_path.startswith(norm_excl + os.sep):
            return True

        # Wildcard pattern match (e.g. /path/to/*.json or temp_*)
        if fnmatch.fnmatch(norm_path, norm_excl) or fnmatch.fnmatch(basename, excl):
            return True

    return False


def decode_audit_path(raw: str) -> str:
    raw = raw.strip('"')
    if re.fullmatch(r"[0-9A-Fa-f]{4,}", raw):
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="replace")
        except Exception:
            pass
    return raw


# --- Discord Sender ---

def send_to_discord(message: str, alert_type: str = "info"):
    now = time.time()
    dedup_key = f"{alert_type}:{message}"

    with recent_alerts_lock:
        if dedup_key in recent_alerts and now - recent_alerts[dedup_key] < DUPLICATE_ALERT_THRESHOLD:
            return
        recent_alerts[dedup_key] = now
        if len(recent_alerts) > 500:
            recent_alerts.clear()

    embed = {
        "title": ALERT_TITLES.get(alert_type, "VPS Monitor"),
        "description": message,
        "color": ALERT_COLORS.get(alert_type, 0x95A5A6),
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": f"VPS Monitor | {socket.gethostname()}"}
    }

    try:
        alert_queue.put_nowait({"embeds": [embed]})
    except queue.Full:
        pass


def discord_worker():
    """Background queue worker for Discord webhooks."""
    session = requests.Session()
    while not shutdown_event.is_set():
        try:
            payload = alert_queue.get(timeout=1)
        except queue.Empty:
            continue

        if not DISCORD_WEBHOOK or not DISCORD_WEBHOOK.startswith("http"):
            alert_queue.task_done()
            continue

        for _ in range(3):
            try:
                res = session.post(DISCORD_WEBHOOK, json=payload, timeout=DISCORD_TIMEOUT)
                if res.status_code in (200, 204):
                    break
                if res.status_code == 429:
                    retry_after = float(res.json().get("retry_after", 5.0))
                    log("WARN", f"Discord rate limited (429), waiting {retry_after}s")
                    time.sleep(retry_after)
                else:
                    time.sleep(2)
            except Exception as e:
                log("ERROR", f"Discord network error: {e}")
                time.sleep(3)

        alert_queue.task_done()


# --- Hardware & USB Peripheral Monitor (Keyboard, Mouse, USB Drives) ---

class PeripheralMonitor:
    def __init__(self):
        self.known_inputs = set()
        self.known_usb = set()
        self.init_devices()

    def get_input_devices(self) -> set:
        """Parses /proc/bus/input/devices for keyboards, mice, and touch devices."""
        devices = set()
        if not os.path.exists("/proc/bus/input/devices"):
            return devices
        try:
            with open("/proc/bus/input/devices", "r") as f:
                content = f.read()
            for block in content.split("\n\n"):
                name_match = re.search(r'N:\s*Name="([^"]+)"', block)
                phys_match = re.search(r'P:\s*Phys=([^\n]+)', block)
                if name_match:
                    name = name_match.group(1)
                    phys = phys_match.group(1) if phys_match else ""
                    devices.add(f"{name} ({phys})")
        except Exception:
            pass
        return devices

    def get_usb_devices(self) -> set:
        """Scans /sys/bus/usb/devices/ for plugged USB hardware."""
        devices = set()
        for path in glob.glob("/sys/bus/usb/devices/*"):
            prod_path = os.path.join(path, "product")
            mfg_path = os.path.join(path, "manufacturer")
            if os.path.exists(prod_path):
                try:
                    with open(prod_path, "r") as f:
                        product = f.read().strip()
                    mfg = ""
                    if os.path.exists(mfg_path):
                        with open(mfg_path, "r") as f:
                            mfg = f.read().strip()
                    dev_name = f"{mfg} {product}".strip()
                    if dev_name:
                        devices.add(dev_name)
                except Exception:
                    pass
        return devices

    def init_devices(self):
        self.known_inputs = self.get_input_devices()
        self.known_usb = self.get_usb_devices()

    def check(self, hostname: str):
        # Check input devices (keyboard/mouse)
        current_inputs = self.get_input_devices()
        new_inputs = current_inputs - self.known_inputs
        removed_inputs = self.known_inputs - current_inputs

        for dev in new_inputs:
            log("DEV", f"Device connected: {dev}")
            send_to_discord(
                f"**Hardware Device Connected** on **{hostname}**\n"
                f"• **Device:** `{dev}`\n"
                f"• **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
                "device"
            )

        for dev in removed_inputs:
            log("DEV", f"Device disconnected: {dev}")
            send_to_discord(
                f"**Hardware Device Disconnected** on **{hostname}**\n"
                f"• **Device:** `{dev}`\n"
                f"• **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
                "device"
            )

        self.known_inputs = current_inputs

        # Check USB products
        current_usb = self.get_usb_devices()
        new_usb = current_usb - self.known_usb
        removed_usb = self.known_usb - current_usb

        for dev in new_usb:
            if not any(dev in inp for inp in new_inputs):
                log("DEV", f"USB Connected: {dev}")
                send_to_discord(
                    f"**USB Device Plugged In** on **{hostname}**\n"
                    f"• **Product:** `{dev}`\n"
                    f"• **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
                    "device"
                )

        for dev in removed_usb:
            if not any(dev in inp for inp in removed_inputs):
                log("DEV", f"USB Removed: {dev}")
                send_to_discord(
                    f"**USB Device Unplugged** on **{hostname}**\n"
                    f"• **Product:** `{dev}`\n"
                    f"• **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
                    "device"
                )

        self.known_usb = current_usb


# --- Audit Log Monitor (Kernel Syscall Open/Read/Write) ---

def monitor_audit_logs():
    """Monitors auditd logs for sensitive file access."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return

    last_sent = None
    current_uid = None

    try:
        with open(AUDIT_LOG_FILE, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            last_ino = os.fstat(f.fileno()).st_ino

            while not shutdown_event.is_set():
                try:
                    if os.stat(AUDIT_LOG_FILE).st_ino != last_ino:
                        f.close()
                        f = open(AUDIT_LOG_FILE, "r", errors="ignore")
                        last_ino = os.fstat(f.fileno()).st_ino
                except Exception:
                    pass

                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                if "type=SYSCALL" in line and "uid=" in line:
                    parts = [p for p in line.split() if p.startswith("uid=")]
                    if parts:
                        current_uid = parts[0].split("=")[1]

                if "type=PATH" in line:
                    parts = [p for p in line.split() if p.startswith("name=")]
                    if parts:
                        filename = decode_audit_path(parts[0].split("=")[1])
                        if is_path_excluded(filename):
                            continue

                        username = uid_to_user(current_uid)
                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        msg = f"**File Accessed:** `{filename}`\n• **User:** `{username}`\n• **Time:** `{ts}`"
                        if msg != last_sent:
                            log("AUDIT", f"File accessed: {filename}", f"user: {username}")
                            send_to_discord(msg, "file_access")
                            last_sent = msg
    except Exception as e:
        log("ERROR", f"Audit monitor error: {e}")


# --- Watchdog File Monitor (Create / Modify / Delete / Move) ---

class ChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and not is_path_excluded(event.src_path):
            log("FILE", f"Created/Copied: {event.src_path}")
            send_to_discord(f"**File Created / Copied:** `{event.src_path}`", "file_change")

    def on_deleted(self, event):
        if not event.is_directory and not is_path_excluded(event.src_path):
            log("FILE", f"Deleted: {event.src_path}")
            send_to_discord(f"**File Deleted:** `{event.src_path}`", "file_change")

    def on_modified(self, event):
        if not event.is_directory and not is_path_excluded(event.src_path):
            log("FILE", f"Modified: {event.src_path}")
            send_to_discord(f"**File Modified:** `{event.src_path}`", "file_change")

    def on_moved(self, event):
        if not event.is_directory:
            if not is_path_excluded(event.src_path) and not is_path_excluded(event.dest_path):
                log("FILE", f"Moved: {event.src_path} -> {event.dest_path}")
                send_to_discord(f"**File Moved / Renamed:**\n• **From:** `{event.src_path}`\n• **To:** `{event.dest_path}`", "file_change")


def start_file_monitors():
    observer = Observer()
    active_count = 0
    for folder in MONITOR_FOLDERS:
        if os.path.exists(folder):
            observer.schedule(ChangeHandler(), folder, recursive=True)
            log("SYS", f"Watching directory: {folder}")
            active_count += 1
        else:
            log("WARN", f"Monitor folder not found: {folder}")

    if active_count > 0:
        observer.start()
        send_to_discord(f"File monitoring active on: {', '.join(f'`{f}`' for f in MONITOR_FOLDERS if os.path.exists(f))}", "info")
        return observer
    return None


# --- Main Security Monitor ---

class VPSSecurityMonitor:
    def __init__(self, check_interval: int = CHECK_INTERVAL):
        self.check_interval = check_interval
        self.known_connections = set()
        self.file_hashes = {}
        self.ssh_log_positions = {}
        self.failed_ssh_attempts = defaultdict(list)
        self.processed_journal_lines = set()
        self.hostname = socket.gethostname()
        self.peripherals = PeripheralMonitor() if MONITOR_PERIPHERALS else None

        # Baseline hash for critical files (ignore unreadable files on init)
        for f in CRITICAL_FILES:
            if os.path.exists(f):
                h = self.hash_file(f)
                self.file_hashes[f] = h if h is not None else "UNREADABLE"

        # Prime journalctl with existing history so historical logins are NOT replayed on startup
        if USE_JOURNALCTL:
            try:
                res = subprocess.run(
                    ["journalctl", "-u", "ssh", "-u", "sshd", "-n", "100", "--no-pager", "-o", "cat"],
                    capture_output=True,
                    text=True,
                    timeout=4
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        line_str = line.strip()
                        if line_str:
                            self.processed_journal_lines.add(line_str)
            except Exception:
                pass

        # Set initial SSH log tail positions
        for log_path in SSH_LOG_FILES:
            if os.path.exists(log_path):
                try:
                    self.ssh_log_positions[log_path] = os.path.getsize(log_path)
                except Exception:
                    self.ssh_log_positions[log_path] = 0

    @staticmethod
    def hash_file(file_path: str):
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def check_file_changes(self):
        """Checks critical system files for modifications or deletions."""
        for file_path in CRITICAL_FILES:
            if os.path.exists(file_path):
                new_hash = self.hash_file(file_path)
                old_hash = self.file_hashes.get(file_path)

                # Skip unreadable files
                if new_hash is None:
                    continue

                if old_hash is None or old_hash == "UNREADABLE":
                    self.file_hashes[file_path] = new_hash
                elif new_hash != old_hash:
                    log("WARN", f"Critical file modified: {file_path}")
                    send_to_discord(f"**CRITICAL FILE MODIFIED**: `{file_path}`", "file_change")
                    self.file_hashes[file_path] = new_hash
            elif self.file_hashes.get(file_path) not in (None, "UNREADABLE"):
                log("WARN", f"Critical file deleted: {file_path}")
                send_to_discord(f"**CRITICAL FILE DELETED**: `{file_path}`", "file_change")
                self.file_hashes[file_path] = None

    def check_connections(self):
        """Monitors network connections with port, IP, and loopback filters."""
        try:
            res = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=SS_COMMAND_TIMEOUT)
            if res.returncode != 0:
                return

            current_conns = set()
            for line in res.stdout.splitlines():
                if "ESTAB" not in line:
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                local_raw, remote_raw = parts[4], parts[5]
                local_ip, local_port = parse_endpoint(local_raw)
                remote_ip, remote_port = parse_endpoint(remote_raw)

                if IGNORE_LOOPBACK and (is_loopback(local_ip) or is_loopback(remote_ip)):
                    continue
                if is_port_excluded(local_port, remote_port):
                    continue
                if is_ip_skipped(remote_ip) or is_ip_skipped(local_ip):
                    continue

                conn_key = f"{local_raw}->{remote_raw}"
                current_conns.add(conn_key)

                if conn_key not in self.known_connections:
                    self.known_connections.add(conn_key)

                    remote_host = resolve_hostname(remote_ip)
                    if remote_host and any(remote_host.endswith(h) for h in SKIP_HOSTS):
                        continue

                    proc_name = "Unknown"
                    if len(parts) >= 7 and '"' in parts[-1]:
                        m = re.search(r'"([^"]+)"', parts[-1])
                        if m:
                            proc_name = m.group(1)

                    log("NET", f"{local_raw} -> {remote_raw}", f"process: {proc_name}, host: {remote_host or 'N/A'}")

                    msg = (
                        f"**New Network Connection** on **{self.hostname}**\n"
                        f"• **Local:** `{local_raw}`\n"
                        f"• **Remote:** `{remote_raw}`\n"
                        f"• **Host:** `{remote_host or 'N/A'}`\n"
                        f"• **Process:** `{proc_name}`"
                    )
                    send_to_discord(msg, "connection")

            if len(self.known_connections) > 2000:
                self.known_connections = current_conns

        except Exception as e:
            log("ERROR", f"Connection check error: {e}")

    def process_ssh_line(self, line: str):
        """Extracts and alerts on SSH login and failed attempts from any log source."""
        if "sshd" not in line and "ssh" not in line:
            return

        # 1. Accepted Login
        if "Accepted" in line:
            user_m = re.search(r"for (?:invalid user )?([^\s]+)", line)
            ip_m = re.search(r"from ([^\s]+)", line)
            port_m = re.search(r"port (\d+)", line)

            user = user_m.group(1) if user_m else "Unknown"
            ip = ip_m.group(1) if ip_m else "Unknown"
            port = port_m.group(1) if port_m else "22"
            remote_host = resolve_hostname(ip)

            log("SSH", f"Accepted login: {user} from {ip}", f"host: {remote_host or 'N/A'}")
            msg = (
                f"**SSH Login Succeeded** on **{self.hostname}**\n"
                f"• **User:** `{user}`\n"
                f"• **Source IP:** `{ip}` (Port: `{port}`)\n"
                f"• **Host:** `{remote_host or 'N/A'}`\n"
                f"• **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
            )
            send_to_discord(msg, "ssh_login")

        # 2. Failed Login Attempt
        elif MONITOR_FAILED_SSH and ("Failed password" in line or "Invalid user" in line or "authentication failure" in line):
            user_m = re.search(r"(?:for|user|user=)([^\s]+)", line)
            ip_m = re.search(r"(?:from|rhost=)([^\s]+)", line)

            user = user_m.group(1) if user_m else "Unknown"
            ip = ip_m.group(1) if ip_m else "Unknown"

            if ip != "Unknown":
                now = time.time()
                self.failed_ssh_attempts[ip] = [t for t in self.failed_ssh_attempts[ip] if now - t < 600]
                self.failed_ssh_attempts[ip].append(now)

                attempts = len(self.failed_ssh_attempts[ip])
                if attempts == FAILED_SSH_ALERT_THRESHOLD or (attempts > FAILED_SSH_ALERT_THRESHOLD and attempts % 10 == 0):
                    remote_host = resolve_hostname(ip)
                    log("AUTH_FAIL", f"Failed SSH ({attempts} attempts): {user} from {ip}", f"host: {remote_host or 'N/A'}")
                    msg = (
                        f"**SSH Login Failed ({attempts} attempts)** on **{self.hostname}**\n"
                        f"• **Target User:** `{user}`\n"
                        f"• **Source IP:** `{ip}`\n"
                        f"• **Host:** `{remote_host or 'N/A'}`\n"
                        f"• **Time:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                    )
                    send_to_discord(msg, "ssh_failed")

    def check_ssh_logins(self):
        """Scans SSH auth logs (or journalctl on modern Ubuntu 22.04) for logins."""
        scanned_any_file = False

        # 1. Try file-based logs (/var/log/auth.log)
        for log_path in SSH_LOG_FILES:
            if not os.path.exists(log_path):
                continue

            try:
                curr_size = os.path.getsize(log_path)
                last_pos = self.ssh_log_positions.get(log_path, curr_size)

                if curr_size < last_pos:
                    last_pos = 0
                if curr_size == last_pos:
                    scanned_any_file = True
                    continue

                with open(log_path, "r", errors="ignore") as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    self.ssh_log_positions[log_path] = f.tell()

                for line in lines:
                    self.process_ssh_line(line)
                scanned_any_file = True
            except PermissionError:
                pass
            except Exception as e:
                log("ERROR", f"SSH log check error: {e}")

        # 2. If USE_JOURNALCTL enabled on Ubuntu 22.04+
        if USE_JOURNALCTL:
            try:
                res = subprocess.run(
                    ["journalctl", "-u", "ssh", "-u", "sshd", "-n", "30", "--no-pager", "-o", "cat"],
                    capture_output=True,
                    text=True,
                    timeout=4
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        line_str = line.strip()
                        if line_str and line_str not in self.processed_journal_lines:
                            self.processed_journal_lines.add(line_str)
                            self.process_ssh_line(line_str)

                    # Keep processed cache bounded
                    if len(self.processed_journal_lines) > 500:
                        self.processed_journal_lines = set(list(self.processed_journal_lines)[-200:])
            except Exception:
                pass

    def run(self):
        log("SYS", f"VPS Security Monitor active (polling interval: {self.check_interval}s)")
        send_to_discord(f"VPS Security Monitor started on **{self.hostname}**", "info")

        while not shutdown_event.is_set():
            self.check_connections()
            self.check_file_changes()
            self.check_ssh_logins()

            if self.peripherals:
                self.peripherals.check(self.hostname)

            for _ in range(int(self.check_interval * 2)):
                if shutdown_event.is_set():
                    break
                time.sleep(0.5)


def handle_signal(sig, frame):
    log("SYS", "Stopping VPS Monitor...")
    shutdown_event.set()


def main():
    if not DISCORD_WEBHOOK or not DISCORD_WEBHOOK.startswith("http"):
        log("WARN", "DISCORD_WEBHOOK not configured. Logging to console only.")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    threading.Thread(target=discord_worker, daemon=True).start()
    threading.Thread(target=monitor_audit_logs, daemon=True).start()

    observer = start_file_monitors()
    monitor = VPSSecurityMonitor()

    try:
        monitor.run()
    except Exception as e:
        log("ERROR", f"Fatal monitor exception: {e}")
    finally:
        shutdown_event.set()
        if observer:
            observer.stop()
            observer.join(timeout=3)
        log("SYS", "VPS Monitor stopped cleanly.")


if __name__ == "__main__":
    main()
