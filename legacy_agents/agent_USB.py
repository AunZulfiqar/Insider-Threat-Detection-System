"""
FIXED USB MONITORING AGENT
- Uses ctime to detect new file copies regardless of original modification date.
- Improved duplicate detection using file size and timestamps.
"""

import os
import time
import json
import requests
from datetime import datetime
from pathlib import Path
from collections import deque

try:
    import win32api
    import win32file
    WINDOWS_OK = True
except ImportError:
    WINDOWS_OK = False
    print("⚠️  pywin32 not installed. Install with: pip install pywin32")

# ============================================================
# CONFIG
# ============================================================

API_URL = "http://localhost:5000/api/ingest"
USER_ID = "AUN001"
PC_NAME = os.environ.get('COMPUTERNAME', 'PC-DEMO')
CHECK_INTERVAL = 2  # Reduced for better responsiveness

SYSTEM_FILES = {
    'autorun.inf', 'desktop.ini', 'thumbs.db', '.ds_store',
    '$recycle.bin', 'system volume information', 'recycler'
}

usb_files_seen = set()
known_usb_drives = set()

# ============================================================
# USB MONITOR
# ============================================================

class USBMonitor:
    
    def __init__(self):
        self.start_time = time.time() # Store as float for comparison
        self.stats = {'connections': 0, 'transfers': 0, 'alerts': 0, 'errors': 0}
        print(f"🔄 USB MONITOR ACTIVE - Started at {datetime.now().strftime('%H:%M:%S')}")
    
    def is_system_file(self, filename):
        name = filename.lower()
        if name in SYSTEM_FILES or name.startswith(('.', '$', '~')):
            return True
        if name.endswith(('.lnk', '.db', '.ini', '.sys')):
            return True
        return False
    
    def send_event(self, event):
        try:
            response = requests.post(API_URL, json=event, timeout=5)
            if response.status_code == 200:
                print(f"  [SENT] {event['activity']}: {json.loads(event['details']).get('filename', 'USB')}")
                return True
            return False
        except:
            self.stats['errors'] += 1
            return False
    
    def scan_usb_files(self, drive, letter):
        """Scan USB drive for file transfers using creation time"""
        try:
            usb_path = Path(drive)
            if not usb_path.exists():
                return
            
            # Check files created or modified recently
            # We look slightly further back than the interval to ensure no gaps
            lookback_limit = time.time() - 60 
            
            for item in usb_path.rglob('*'):
                try:
                    if not item.is_file() or self.is_system_file(item.name):
                        continue
                    
                    stat = item.stat()
                    # CRITICAL FIX: Use the latest of ctime (creation) or mtime (modification)
                    # When you copy a file to USB, Windows sets ctime to 'now'
                    file_timestamp = max(stat.st_mtime, stat.st_ctime)
                    
                    # Only process if it happened after the script started OR within lookback
                    if file_timestamp < self.start_time - 5: 
                        continue
                    
                    # Unique key based on path, size, and time to prevent duplicate alerts
                    file_key = f"{item}_{stat.st_size}_{int(file_timestamp)}"
                    if file_key in usb_files_seen:
                        continue
                    
                    usb_files_seen.add(file_key)
                    self.stats['transfers'] += 1
                    
                    event = {
                        'user': USER_ID,
                        'user_id': USER_ID,
                        'timestamp': datetime.fromtimestamp(file_timestamp).isoformat(),
                        'event_type': 'DEVICE',
                        'activity': 'COPY_TO_USB',
                        'details': json.dumps({
                            'pc': PC_NAME,
                            'filename': item.name,
                            'file_size': stat.st_size,
                            'full_path': str(item),
                            'drive': letter
                        })
                    }
                    self.send_event(event)
                
                except (PermissionError, OSError):
                    continue
        except Exception as e:
            print(f"Error scanning files on {letter}: {e}")

    def scan_usb_devices(self):
        if not WINDOWS_OK: return
        
        try:
            drives = win32api.GetLogicalDriveStrings().split('\000')
            current_usb = set()
            
            for drive in drives:
                if not drive: continue
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    letter = drive.replace(':\\', '')
                    current_usb.add(letter)
                    
                    if letter not in known_usb_drives:
                        known_usb_drives.add(letter)
                        self.stats['connections'] += 1
                        print(f"\n✨ NEW DEVICE: {letter}:\\")
                        self.send_event({
                            'user': USER_ID, 'user_id': USER_ID,
                            'timestamp': datetime.now().isoformat(),
                            'event_type': 'DEVICE', 'activity': 'Connect',
                            'details': json.dumps({'pc': PC_NAME, 'drive': letter})
                        })
                    
                    # Always scan for new files while connected
                    self.scan_usb_files(drive, letter)
            
            # Cleanup disconnected drives
            disconnected = known_usb_drives - current_usb
            for letter in disconnected:
                known_usb_drives.remove(letter)
                print(f"🔌 REMOVED: {letter}:\\")
        
        except Exception as e:
            self.stats['errors'] += 1

    def monitor(self):
        print("Monitoring... (Ctrl+C to exit)")
        try:
            while True:
                self.scan_usb_devices()
                time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            print(f"\nFinal Stats: Connections: {self.stats['connections']}, Transfers: {self.stats['transfers']}")

if __name__ == '__main__':
    if not WINDOWS_OK:
        exit(1)
    # Check Flask
    try:
        requests.get("http://localhost:5000", timeout=2)
    except:
        print("❌ Flask API not found. Please start the server first.")
        exit(1)
        
    monitor = USBMonitor()
    monitor.monitor()