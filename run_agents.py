"""
Master Agent Runner
Runs all 4 monitoring agents (EMAIL, FILE, HTTP, USB) in parallel threads.

Bug fixes applied vs original agents:
  - agent_HTTP: Chrome timestamp was Unix microseconds — Chrome actually stores
    WebKit time (microseconds since 1601-01-01), off by factor of ~7.
    Fixed: adds 11644473600s offset before converting.
  - All agents: USER_ID was hardcoded "AUN001" — now uses your actual Windows
    username so events appear under the right account in the dashboard.
  - agent_USB: activity "COPY_TO_USB" not recognized by detection engine —
    mapped to "Connect" which IS in the feature schema.

Usage:
    1. Start Flask app:   python run.py
    2. Start agents:      python run_agents.py
    3. Open dashboard, filter by your username

Install dependencies first (once):
    pip install requests pywin32 watchdog wmi psutil
"""

import os
import sys
import time
import json
import hashlib
import shutil
import sqlite3
import threading
import requests
from datetime import datetime
from pathlib import Path
from collections import deque

# ── Config ────────────────────────────────────────────────────────────────────

API_URL       = "http://localhost:5000/api/ingest"
API_KEY       = os.environ.get("AGENT_API_KEY", "dev-agent-key-change-in-production")
USER_ID       = os.environ.get("USERNAME", "AUN001")   # real Windows username
PC_NAME       = os.environ.get("COMPUTERNAME", "PC-DEMO")
TARGET_EMAIL  = os.environ.get("MONITOR_TARGET_EMAIL", "you@example.com")  # your Outlook address, for the Sent-mail monitor
WATCH_FOLDERS = [
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
]
CHECK_INTERVAL = 5   # seconds between polls

recent_events = deque(maxlen=2000)

SYSTEM_FILES = {
    '.lnk', '.tmp', '.db', '.ini', '.sys', '.dat', '.log',
    '.etl', '.blf', 'desktop.ini', 'thumbs.db', 'autorun.inf'
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_event_id(user, ts, etype):
    return hashlib.md5(f"{user}{ts}{etype}{time.time()}".encode()).hexdigest()[:16]


def send(event_type, activity, details: dict, timestamp=None):
    ts = (timestamp or datetime.now()).isoformat()
    payload = {
        "event_id":   make_event_id(USER_ID, ts, event_type),
        "user":       USER_ID,
        "user_id":    USER_ID,
        "event_type": event_type,
        "activity":   activity,
        "timestamp":  ts,
        "details":    json.dumps(details),
    }
    try:
        r = requests.post(API_URL, json=payload, headers={"X-API-Key": API_KEY}, timeout=5)
        if r.status_code == 200:
            res = r.json()
            if res.get("alert_generated"):
                lvl   = res.get("risk_level", "?")
                score = res.get("risk_score", 0)
                print(f"  🚨 ALERT [{lvl}] {score:.2f}  {event_type}: {activity}")
            else:
                print(f"  ✓  {event_type}: {activity}")
    except Exception as e:
        print(f"  ✗  Send error: {e}")


def is_system_file(name):
    n = name.lower()
    return (n in SYSTEM_FILES or
            any(n.endswith(ext) for ext in SYSTEM_FILES) or
            n.startswith(('.', '~$', '$')))


# ── EMAIL agent (from agent_EMAIL.py) ────────────────────────────────────────

def run_email_monitor():
    try:
        import win32com.client
    except ImportError:
        print("[EMAIL] pywin32 not installed — skipping")
        return

    print(f"[EMAIL] Monitor started — watching {TARGET_EMAIL}")
    start_time = datetime.now()
    processed = set()

    outlook   = win32com.client.Dispatch("Outlook.Application")
    namespace = outlook.GetNamespace("MAPI")

    sent_folder = None
    for store in namespace.Stores:
        if TARGET_EMAIL.lower() in store.DisplayName.lower():
            root = store.GetRootFolder()
            for folder in root.Folders:
                if "sent" in folder.Name.lower():
                    sent_folder = folder
                    break

    if not sent_folder:
        print(f"[EMAIL] Sent folder not found for {TARGET_EMAIL}")
        return

    while True:
        try:
            messages = sent_folder.Items
            messages.Sort("[SentOn]", True)

            for i in range(1, min(10, messages.Count + 1)):
                msg = messages.Item(i)
                sent_time = msg.SentOn.replace(tzinfo=None)

                if sent_time <= start_time:
                    break
                if msg.EntryID in processed:
                    continue

                processed.add(msg.EntryID)
                attachments = [{"name": a.FileName, "size": a.Size}
                               for a in msg.Attachments]
                send("EMAIL", "Send", {
                    "pc":              PC_NAME,
                    "to":              str(msg.To),
                    "subject":         str(msg.Subject),
                    "size":            str(msg.Size),
                    "attachments":     json.dumps(attachments),
                    "attachment_count": len(attachments),
                    "content":         f"Email to {msg.To}: {msg.Subject}"
                }, timestamp=sent_time)

        except Exception:
            pass
        time.sleep(CHECK_INTERVAL)


# ── FILE agent (from agent_FILE.py) ──────────────────────────────────────────

def run_file_monitor():
    print(f"[FILE] Monitor started — watching {[str(f) for f in WATCH_FOLDERS]}")
    start_time = datetime.now()

    while True:
        cutoff = time.time() - 180   # last 3 min
        for folder in WATCH_FOLDERS:
            if not folder.exists():
                continue
            try:
                for fp in folder.iterdir():
                    try:
                        if not fp.is_file() or is_system_file(fp.name):
                            continue
                        stat = fp.stat()
                        recent = max(stat.st_atime, stat.st_mtime)
                        if recent <= cutoff:
                            continue
                        ts = datetime.fromtimestamp(recent)
                        if ts < start_time:
                            continue
                        key = f"file_{fp}_{int(recent)}"
                        if key in recent_events:
                            continue
                        recent_events.append(key)

                        activity = "FILE_WRITE" if abs(stat.st_mtime - recent) < 2 else "FILE_ACCESS"
                        send("FILE", activity, {
                            "pc":        PC_NAME,
                            "filename":  fp.name,
                            "file_size": stat.st_size,
                            "file_path": str(fp),
                            "folder":    folder.name.lower(),
                            "content":   f"{activity}: {fp.name}"
                        }, timestamp=ts)
                    except Exception:
                        continue
            except Exception:
                continue
        time.sleep(CHECK_INTERVAL)


# ── HTTP agent (from agent_HTTP.py — Chrome timestamp bug fixed) ──────────────

WEBKIT_EPOCH_OFFSET = 11644473600   # seconds between 1601-01-01 and 1970-01-01

def get_chrome_recent(limit=10):
    """Read recent URLs from Chrome — uses CORRECT WebKit timestamp conversion."""
    history = Path.home() / "AppData/Local/Google/Chrome/User Data/Default/History"
    if not history.exists():
        return []
    tmp = Path(os.environ.get("TEMP", ".")) / "chrome_tmp_agent.db"
    try:
        shutil.copy2(str(history), str(tmp))
        conn = sqlite3.connect(str(tmp))
        # FIX: Chrome stores microseconds since 1601-01-01 (WebKit epoch).
        # Original agent used Unix microseconds which is ~7x smaller,
        # so the WHERE clause never matched anything.
        five_min_webkit = int((time.time() - 300 + WEBKIT_EPOCH_OFFSET) * 1_000_000)
        rows = conn.execute(
            "SELECT url, title, last_visit_time FROM urls "
            "WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT ?",
            (five_min_webkit, limit)
        ).fetchall()
        conn.close()
        tmp.unlink(missing_ok=True)
        return rows
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return []


def get_edge_recent(limit=10):
    """Read recent URLs from Edge (same WebKit timestamp fix)."""
    history = Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/History"
    if not history.exists():
        return []
    tmp = Path(os.environ.get("TEMP", ".")) / "edge_tmp_agent.db"
    try:
        shutil.copy2(str(history), str(tmp))
        conn = sqlite3.connect(str(tmp))
        five_min_webkit = int((time.time() - 300 + WEBKIT_EPOCH_OFFSET) * 1_000_000)
        rows = conn.execute(
            "SELECT url, title, last_visit_time FROM urls "
            "WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT ?",
            (five_min_webkit, limit)
        ).fetchall()
        conn.close()
        tmp.unlink(missing_ok=True)
        return rows
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return []


def run_http_monitor():
    print("[HTTP] Browser monitor started (Chrome + Edge)")

    # Pre-seed to avoid flooding on startup
    for url, _, _ in get_chrome_recent(50) + get_edge_recent(50):
        recent_events.append(f"url_{url}")
    print(f"[HTTP] Pre-seeded existing URLs — won't re-send")

    while True:
        for url, title, _ in get_chrome_recent() + get_edge_recent():
            key = f"url_{url}"
            if key in recent_events:
                continue
            recent_events.append(key)
            send("HTTP", "WEB_ACCESS", {
                "pc":      PC_NAME,
                "url":     url[:500],
                "content": (title or "")[:200],
            })
        time.sleep(CHECK_INTERVAL)


# ── USB agent (from agent_USB.py — activity name fixed) ──────────────────────

usb_files_seen  = set()
known_usb_drives = set()


def scan_usb_files(drive, letter, start_ts):
    try:
        usb_path = Path(drive)
        lookback = time.time() - 60
        for item in usb_path.rglob("*"):
            try:
                if not item.is_file() or is_system_file(item.name):
                    continue
                stat = item.stat()
                file_ts = max(stat.st_mtime, stat.st_ctime)
                if file_ts < start_ts - 5:
                    continue
                key = f"{item}_{stat.st_size}_{int(file_ts)}"
                if key in usb_files_seen:
                    continue
                usb_files_seen.add(key)
                # FIX: was "COPY_TO_USB" which detection engine doesn't recognise.
                # "Connect" maps to the DEVICE feature schema correctly.
                send("DEVICE", "Connect", {
                    "pc":        PC_NAME,
                    "filename":  item.name,
                    "file_size": stat.st_size,
                    "full_path": str(item),
                    "drive":     letter,
                    "activity":  "Connect",
                    "file_tree": f"{letter}:\\"
                }, timestamp=datetime.fromtimestamp(file_ts))
            except (PermissionError, OSError):
                continue
    except Exception:
        pass


def run_usb_monitor():
    try:
        import win32api
        import win32file
    except ImportError:
        print("[USB] pywin32 not installed — skipping")
        return

    print("[USB] Monitor started")
    start_ts = time.time()

    while True:
        try:
            drives = win32api.GetLogicalDriveStrings().split("\000")
            current = set()
            for drive in drives:
                if not drive:
                    continue
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    letter = drive.replace(":\\", "")
                    current.add(letter)
                    if letter not in known_usb_drives:
                        known_usb_drives.add(letter)
                        print(f"[USB] New device: {letter}:\\")
                        send("DEVICE", "Connect", {
                            "pc": PC_NAME, "activity": "Connect",
                            "file_tree": f"{letter}:\\"
                        })
                    scan_usb_files(drive, letter, start_ts)

            for letter in (known_usb_drives - current):
                known_usb_drives.discard(letter)
                print(f"[USB] Removed: {letter}:\\")
                send("DEVICE", "Disconnect", {
                    "pc": PC_NAME, "activity": "Disconnect", "file_tree": ""
                })
        except Exception:
            pass
        time.sleep(2)


# ── Main ──────────────────────────────────────────────────────────────────────

def check_flask():
    try:
        return requests.get("http://localhost:5000/api/test", timeout=3).status_code == 200
    except Exception:
        return False


def main():
    print("=" * 60)
    print("  Insider Threat — Master Agent Runner")
    print(f"  User:    {USER_ID}")
    print(f"  PC:      {PC_NAME}")
    print(f"  API:     {API_URL}")
    print("=" * 60)

    if not check_flask():
        print("\n❌  Flask app is not running!")
        print("   Start it first:  python run.py")
        sys.exit(1)
    print("✅  Flask app detected\n")

    # Register user via a startup logon event
    send("LOGON", "Logon", {"pc": PC_NAME, "activity": "Logon"})

    threads = [
        threading.Thread(target=run_email_monitor, daemon=True, name="EMAIL"),
        threading.Thread(target=run_file_monitor,  daemon=True, name="FILE"),
        threading.Thread(target=run_http_monitor,  daemon=True, name="HTTP"),
        threading.Thread(target=run_usb_monitor,   daemon=True, name="USB"),
    ]

    for t in threads:
        t.start()
        time.sleep(0.5)

    print("\nAll monitors running. Open your dashboard and filter by:")
    print(f"  User: {USER_ID}")
    print("\nActions to trigger live events:")
    print("  • Open/save any file in Desktop, Documents, Downloads → FILE event")
    print("  • Visit a new URL in Chrome or Edge                   → HTTP event")
    print("  • Plug in a USB drive                                 → DEVICE event")
    print("  • Send an email from Outlook                          → EMAIL event")
    print("\nFor a live demo alert, visit a URL containing 'hack', 'exploit',")
    print("'malware', or 'wikileaks' — keyword detection will fire immediately.")
    print("\nPress Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nAll agents stopped.")


if __name__ == "__main__":
    main()
