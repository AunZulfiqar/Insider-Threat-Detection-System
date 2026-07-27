"""
FILE MONITORING AGENT
Monitors file access in Desktop, Documents, Downloads
Sends events to Flask API
"""

import os
import time
import json
import requests
from datetime import datetime
from pathlib import Path
from collections import deque

# ============================================================
# CONFIG
# ============================================================

API_URL = "http://localhost:5000/api/ingest"
USER_ID = "AUN001"
PC_NAME = os.environ.get('COMPUTERNAME', 'PC-DEMO')
CHECK_INTERVAL = 3  # seconds

# Monitor these folders
MONITORED_FOLDERS = [
    Path.home() / 'Desktop',
    Path.home() / 'Documents',
    Path.home() / 'Downloads'
]

# System files to ignore
SYSTEM_FILES = {'.lnk', '.tmp', '.db', '.ini', '~', '.sys', '.dat', 
                '.log', '.etl', '.blf', 'desktop.ini', 'thumbs.db'}

# Cache to prevent duplicates
recent_events = deque(maxlen=1000)

# ============================================================
# FILE MONITOR
# ============================================================

class FileMonitor:
    
    def __init__(self):
        self.start_time = datetime.now()
        self.stats = {
            'total_files': 0,
            'alerts': 0,
            'errors': 0
        }
        print(f"🔄 FILE MONITOR started at {self.start_time.strftime('%H:%M:%S')}")
        print(f"📁 Monitoring folders:")
        for folder in MONITORED_FOLDERS:
            print(f"   • {folder}")
        print()
    
    def is_system_file(self, filename):
        """Check if file should be ignored"""
        name = filename.lower()
        
        # Check exact match
        if name in SYSTEM_FILES:
            return True
        
        # Check extensions
        if any(name.endswith(ext) for ext in SYSTEM_FILES):
            return True
        
        # Check patterns
        if name.startswith(('.', '~$', '$')):
            return True
        
        return False
    
    def send_event(self, event):
        """Send event to Flask API"""
        try:
            response = requests.post(API_URL, json=event, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                self.stats['total_files'] += 1
                
                if result.get('alert_generated'):
                    self.stats['alerts'] += 1
                    risk = result.get('risk_level', 'UNKNOWN')
                    score = result.get('risk_score', 0.0)
                    
                    if risk == "CRITICAL":
                        print(f"  🚨 CRITICAL ({score:.3f}) - {event['activity']}: {Path(event['details']).name if 'details' in event else 'file'}")
                    elif risk == "HIGH":
                        print(f"  ⚠️  HIGH ({score:.3f}) - {event['activity']}: {Path(event['details']).name if 'details' in event else 'file'}")
                    elif risk == "MEDIUM":
                        print(f"  📌 MEDIUM ({score:.3f}) - {event['activity']}: {Path(event['details']).name if 'details' in event else 'file'}")
                    else:
                        print(f"  ℹ️  LOW ({score:.3f}) - {event['activity']}: {Path(event['details']).name if 'details' in event else 'file'}")
                else:
                    print(f"  ✓ {event['activity']}: {Path(json.loads(event['details'])['file_path']).name}")
                
                return True
            else:
                self.stats['errors'] += 1
                return False
        
        except Exception as e:
            self.stats['errors'] += 1
            return False
    
    def scan_files(self):
        """Scan monitored folders for file access"""
        cutoff_time = time.time() - 180  # Last 3 minutes
        
        for folder in MONITORED_FOLDERS:
            if not folder.exists():
                continue
            
            try:
                for file_path in folder.iterdir():
                    try:
                        if not file_path.is_file():
                            continue
                        
                        if self.is_system_file(file_path.name):
                            continue
                        
                        # Check file times
                        stat = file_path.stat()
                        recent_time = max(stat.st_atime, stat.st_mtime)
                        
                        # Only recent files
                        if recent_time <= cutoff_time:
                            continue
                        
                        # Only files accessed after monitor started
                        timestamp = datetime.fromtimestamp(recent_time)
                        if timestamp < self.start_time:
                            continue
                        
                        # Check if already sent
                        event_key = f"file_{file_path}_{int(recent_time)}"
                        if event_key in recent_events:
                            continue
                        
                        recent_events.append(event_key)
                        
                        # Determine activity type
                        if abs(stat.st_mtime - recent_time) < 2:
                            activity = "FILE_WRITE"
                        else:
                            activity = "FILE_ACCESS"
                        
                        # Determine folder classification
                        path_str = str(file_path).lower()
                        if 'confidential' in path_str or 'classified' in path_str:
                            folder_type = "confidential"
                        elif 'test' in path_str:
                            folder_type = "test"
                        else:
                            folder_type = folder.name.lower()
                        
                        # Create event
                        event = {
                            'user': USER_ID,
                            'user_id': USER_ID,
                            'timestamp': timestamp.isoformat(),
                            'event_type': 'FILE',
                            'activity': activity,
                            'details': json.dumps({
                                'pc': PC_NAME,
                                'filename': file_path.name,
                                'file_size': stat.st_size,
                                'file_path': str(file_path),
                                'folder': folder_type,
                                'content': f'{activity}: {file_path.name}'
                            })
                        }
                        
                        # Send event
                        self.send_event(event)
                    
                    except Exception as e:
                        continue
            
            except Exception as e:
                continue
    
    def monitor(self):
        """Main monitoring loop"""
        print("=" * 70)
        print("FILE MONITOR ACTIVE")
        print("=" * 70)
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.scan_files()
                time.sleep(CHECK_INTERVAL)
        
        except KeyboardInterrupt:
            print("\n" + "=" * 70)
            print("FILE MONITOR STOPPED")
            print("=" * 70)
            print(f"Total Files: {self.stats['total_files']}")
            print(f"Alerts: {self.stats['alerts']}")
            print(f"Errors: {self.stats['errors']}")
            print("=" * 70)

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🔐 FILE MONITORING AGENT")
    print("=" * 70 + "\n")
    
    # Check Flask
    print("Checking Flask API...")
    try:
        requests.get("http://localhost:5000", timeout=2)
        print("✓ Flask is running\n")
    except:
        print("❌ Flask not running at localhost:5000!")
        print("Please start Flask server first.\n")
        input("Press Enter to exit...")
        exit(1)
    
    # Test API
    try:
        test_event = {
            'user': 'TEST',
            'user_id': 'TEST',
            'timestamp': datetime.now().isoformat(),
            'event_type': 'FILE',
            'activity': 'TEST',
            'details': json.dumps({'pc': 'TEST', 'filename': 'test.txt', 'content': 'test'})
        }
        r = requests.post(API_URL, json=test_event, timeout=3)
        if r.status_code == 200:
            print("✓ API endpoint working\n")
        else:
            print("❌ API endpoint error\n")
            exit(1)
    except:
        print("❌ Cannot connect to API\n")
        exit(1)
    
    print("=" * 70)
    input("Press Enter to start monitoring...")
    print()
    
    # Start monitoring
    monitor = FileMonitor()
    monitor.monitor()
