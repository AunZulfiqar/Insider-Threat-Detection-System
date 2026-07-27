"""
Real-Time Monitoring Agent for Insider Threat Detection System
Captures actual user activities on Windows and sends to Flask app

Run this script on your PC while the Flask app is running.
"""

import os
import time
import json
import hashlib
import requests
import sqlite3
from datetime import datetime , timedelta
from pathlib import Path
import threading
from collections import deque

# Configuration
FLASK_API_URL = "http://localhost:5000/api/ingest"  # Fixed: Use /api/ingest endpoint
USER_ID = "AUN001"  # Your user ID
PC_NAME = os.environ.get('COMPUTERNAME', 'PC-DEMO')
CHECK_INTERVAL = 5  # Check every 5 seconds

# Recent events cache (to avoid duplicates)
recent_events = deque(maxlen=1000)

class ActivityMonitor:
    """Monitor user activities on Windows"""
    
    def __init__(self, user_id, pc_name):
        self.user_id = user_id
        self.pc_name = pc_name
        self.running = True
        
    def generate_event_id(self, user, timestamp, event_type):
        """Generate unique event ID"""
        raw = f"{user}{timestamp}{event_type}{time.time()}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]
    
    def send_event_to_server(self, event):
        """Send event to Flask API"""
        try:
            response = requests.post(
                FLASK_API_URL,
                json=event,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Check if alert was generated
                if result.get('alert_generated'):
                    risk = result.get('risk_level', 'UNKNOWN')
                    print(f"ðŸš¨ ALERT: {risk} - {event['event_type']} - {event['activity']}")
                else:
                    print(f"âœ“  Normal: {event['event_type']} - {event['activity']}")
                
                return True
            else:
                print(f"âœ— Error {response.status_code}: {response.text[:100]}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"âœ— Connection error: {str(e)}")
            return False
    
    def check_browser_history(self):
        """Monitor Chrome browser history"""
        # Chrome history location
        chrome_history = Path.home() / 'AppData/Local/Google/Chrome/User Data/Default/History'
        
        if not chrome_history.exists():
            return []
        
        events = []
        
        try:
            # Create a copy to avoid locking issues
            temp_history = 'temp_history.db'
            if os.path.exists(temp_history):
                os.remove(temp_history)
            
            # Copy the database
            import shutil
            try:
                shutil.copy2(chrome_history, temp_history)
            except:
                return []
            
            # Connect to copied database
            conn = sqlite3.connect(temp_history)
            cursor = conn.cursor()
            
            # Get recent URLs (last 5 minutes)
            five_min_ago = int((time.time() - 300) * 1000000)  # Chrome uses microseconds
            
            query = """
                SELECT url, title, last_visit_time 
                FROM urls 
                WHERE last_visit_time > ? 
                ORDER BY last_visit_time DESC 
                LIMIT 20
            """
            
            cursor.execute(query, (five_min_ago,))
            rows = cursor.fetchall()
            
            for url, title, visit_time in rows:
                # FORCE CURRENT TIMESTAMP (not historical Chrome time)
                timestamp = datetime.now()
                
                # Check if already processed
                event_key = f"{url}_{visit_time}"
                if event_key in recent_events:
                    continue
                
                recent_events.append(event_key)
                
                event = {
                    'user': self.user_id,
                    'user_id': self.user_id,  # Added: for compatibility
                    'timestamp': timestamp.isoformat(),
                    'event_type': 'HTTP',
                    'activity': 'WEB_ACCESS',
                    'details': json.dumps({
                        'pc': self.pc_name,
                        'url': url,
                        'content': title or ''
                    })
                }
                
                events.append(event)
            
            conn.close()
            os.remove(temp_history)
            
        except Exception as e:
            print(f"Browser monitoring error: {str(e)}")
        
        return events
    
    def check_usb_devices(self):
        """Monitor USB device connections"""
        events = []
        
        try:
            import win32api
            import win32file
            
            # Get all drives
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            
            for drive in drives:
                try:
                    drive_type = win32file.GetDriveType(drive)
                    
                    # Check if removable (USB)
                    if drive_type == win32file.DRIVE_REMOVABLE:
                        event_key = f"usb_{drive}_{int(time.time()/60)}"  # Group by minute
                        
                        if event_key not in recent_events:
                            recent_events.append(event_key)
                            
                            timestamp = datetime.now()
                            
                            event = {
                                'user': self.user_id,
                                'user_id': self.user_id,  # Added: for compatibility
                                'timestamp': timestamp.isoformat(),
                                'event_type': 'DEVICE',
                                'activity': 'Connect',
                                'details': json.dumps({
                                    'pc': self.pc_name,
                                    'activity': 'Connect',
                                    'file_tree': f'{drive} (USB Device)'
                                })
                            }
                            
                            events.append(event)
                            
                except:
                    pass
                    
        except ImportError:
            pass  # pywin32 not installed
        except Exception as e:
            print(f"USB monitoring error: {str(e)}")
        
        return events
    
    def check_file_access(self):
        """Monitor recent file accesses (simplified)"""
        events = []
        
        try:
            # Monitor Downloads folder for recent files
            downloads = Path.home() / 'Downloads'
            
            if downloads.exists():
                # Get files modified in last 5 minutes
                five_min_ago = time.time() - 300
                
                for file_path in downloads.iterdir():
                    if file_path.is_file():
                        mtime = file_path.stat().st_mtime
                        
                        if mtime > five_min_ago:
                            event_key = f"file_{file_path}_{int(mtime)}"
                            
                            if event_key not in recent_events:
                                recent_events.append(event_key)
                                
                                # FORCE CURRENT TIMESTAMP
                                timestamp = datetime.now()
                                
                                event = {
                                    'user': self.user_id,
                                    'user_id': self.user_id,  # Added: for compatibility
                                    'timestamp': timestamp.isoformat(),
                                    'event_type': 'FILE',
                                    'activity': 'FILE_ACCESS',
                                    'details': json.dumps({
                                        'pc': self.pc_name,
                                        'filename': file_path.name,
                                        'content': f'Downloaded file: {file_path.name}'
                                    })
                                }
                                
                                events.append(event)
        
        except Exception as e:
            print(f"File monitoring error: {str(e)}")
        
        return events
    
    def monitor_loop(self):
        """Main monitoring loop"""
        print("=" * 60)
        print("Real-Time Activity Monitor Started")
        print("=" * 60)
        print(f"User ID: {self.user_id}")
        print(f"PC Name: {self.pc_name}")
        print(f"Flask API: {FLASK_API_URL}")
        print(f"Check Interval: {CHECK_INTERVAL} seconds")
        print("=" * 60)
        print("\nMonitoring:")
        print("  âœ“ Browser history (Chrome)")
        print("  âœ“ USB devices")
        print("  âœ“ File downloads")
        print("\nPress Ctrl+C to stop\n")
        print("=" * 60)
        
        # Statistics
        total_events = 0
        alerts_generated = 0
        
        while self.running:
            try:
                all_events = []
                
                # Check browser history
                browser_events = self.check_browser_history()
                all_events.extend(browser_events)
                
                # Check USB devices
                usb_events = self.check_usb_devices()
                all_events.extend(usb_events)
                
                # Check file access
                file_events = self.check_file_access()
                all_events.extend(file_events)
                
                # Send events to server
                for event in all_events:
                    success = self.send_event_to_server(event)
                    if success:
                        total_events += 1
                
                # Show stats every 10 checks (50 seconds)
                if total_events > 0 and total_events % 10 == 0:
                    print(f"\n--- Stats: {total_events} events sent ---\n")
                
                # Wait before next check
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                print("\n\nStopping monitor...")
                print(f"\nFinal Statistics:")
                print(f"  Total Events: {total_events}")
                self.running = False
                break
            except Exception as e:
                print(f"Monitor error: {str(e)}")
                time.sleep(CHECK_INTERVAL)

def check_flask_server():
    """Check if Flask server is running"""
    try:
        response = requests.get("http://127.0.0.1:5000", timeout=2)
        return True
    except:
        return False

def test_api_connection():
    """Test API endpoint with a sample event"""
    print("\nTesting API connection...")
    
    test_event = {
        'user': 'TEST_AGENT',
        'user_id': 'TEST_AGENT',
        'timestamp': datetime.now().isoformat(),
        'event_type': 'HTTP',
        'activity': 'CONNECTION_TEST',
        'details': json.dumps({
            'pc': 'TEST_PC',
            'url': 'http://test.com',
            'content': 'Connection test'
        })
    }
    
    try:
        response = requests.post(
            FLASK_API_URL,
            json=test_event,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"âœ“ API connection successful!")
            print(f"  Response: {result.get('status')}")
            if result.get('event_id'):
                print(f"  Event ID: {result.get('event_id')}")
            return True
        else:
            print(f"âœ— API returned error {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"âœ— API connection failed: {str(e)}")
        return False

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("Insider Threat Detection - Activity Monitor Agent")
    print("=" * 60 + "\n")
    
    # Check if Flask server is running
    print("Checking Flask server...")
    if not check_flask_server():
        print("âŒ Flask server is not running!")
        print("\nPlease start the Flask application first:")
        print("  python run.py")
        print("\nThen run this monitor again.")
        input("\nPress Enter to exit...")
        exit(1)
    
    print("âœ“ Flask server is running")
    
    # Test API connection
    if not test_api_connection():
        print("\nâŒ API endpoint test failed!")
        print("\nPlease ensure:")
        print("  1. Flask is running on http://localhost:5000")
        print("  2. API endpoint /api/ingest is available")
        print("  3. api_FIXED_v2.py is installed")
        input("\nPress Enter to exit...")
        exit(1)
    
    print("\n" + "=" * 60)
    
    # Get user confirmation
    print(f"This will monitor activities for user: {USER_ID}")
    print(f"PC Name: {PC_NAME}")
    print(f"API Endpoint: {FLASK_API_URL}")
    print("\nActivities monitored:")
    print("  - Web browsing (Chrome)")
    print("  - USB device connections")
    print("  - File downloads")
    
    response = input("\nStart monitoring? (yes/no): ")
    
    if response.lower() not in ['yes', 'y']:
        print("Monitoring cancelled.")
        exit(0)
    
    # Start monitoring
    monitor = ActivityMonitor(USER_ID, PC_NAME)
    
    try:
        monitor.monitor_loop()
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
    
    print("\n" + "=" * 60)
    print("Monitor Agent Stopped")
    print("=" * 60)