import os
import time
import json
import requests
from datetime import datetime

try:
    import win32com.client
    OUTLOOK_OK = True
except ImportError:
    OUTLOOK_OK = False

# --- CONFIGURATION ---
API_URL = "http://localhost:5000/api/ingest"
USER_ID = "AUN001"
PC_NAME = os.environ.get('COMPUTERNAME', 'PC-DEMO')
TARGET_EMAIL = os.environ.get("MONITOR_TARGET_EMAIL", "you@example.com")
CHECK_INTERVAL = 5 

class StrictTimeMonitor:
    def __init__(self):
        # Capture the exact moment the monitor starts
        self.monitor_start_time = datetime.now()
        self.processed_ids = set()
        
        print(f"🚀 MONITOR START: {self.monitor_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📧 Watching: {TARGET_EMAIL}")
        print("-" * 65)

    def print_ui_alert(self, data, payload_details, sent_time):
        """Displays the dashboard-style alert in the console"""
        print("\n" + "█" * 65)
        print(f" CRITICAL Risk Alert ".center(65, '█'))
        print("-" * 65)
        print(f" Forensics Alert ID: {data.get('alert_id', '74ca4b6262d933e7'):<22} User ID: {USER_ID}")
        print(f" Timestamp: {sent_time:<31} Alert Type: EMAIL")
        print(f" Risk Score: {data.get('risk_score', 0.950):<27.3f} Status: OPEN")
        print("-" * 65)
        print(f" Description:")
        
        size_mb = payload_details.get('size', 0) / (1024 * 1024)
        desc = (f"POTENTIAL DATA EXFILTRATION: Email ({size_mb:.2f}MB) "
                f"with subject '{payload_details.get('subject')}' "
                f"sent to {payload_details.get('to')}")
        print(f" {desc}")
        print("█" * 65 + "\n")

    def run(self):
        if not OUTLOOK_OK: return
        
        outlook = win32com.client.Dispatch("Outlook.Application")
        namespace = outlook.GetNamespace("MAPI")
        
        # Locate the specific account and Sent folder
        sent_folder = None
        for store in namespace.Stores:
            if TARGET_EMAIL.lower() in store.DisplayName.lower():
                root = store.GetRootFolder()
                for folder in root.Folders:
                    if 'sent' in folder.Name.lower():
                        sent_folder = folder
                        break
        
        if not sent_folder:
            print(f"❌ Error: Folder not found for {TARGET_EMAIL}")
            return

        while True:
            try:
                # Sort items to get the newest first
                messages = sent_folder.Items
                messages.Sort("[SentOn]", True)
                
                for i in range(1, min(10, messages.Count + 1)):
                    msg = messages.Item(i)
                    
                    # --- THE TIME COMPARISON ---
                    # We convert both to timestamps to ensure a strict mathematical 'ahead of' check
                    email_sent_time = msg.SentOn.replace(tzinfo=None) 
                    
                    if email_sent_time > self.monitor_start_time:
                        if msg.EntryID not in self.processed_ids:
                            
                            # Prepare Attachment Data
                            attachments = [{"name": a.FileName, "size": a.Size} for a in msg.Attachments]
                            
                            details_dict = {
                                'pc': PC_NAME,
                                'to': str(msg.To),
                                'subject': str(msg.Subject),
                                'size': msg.Size,
                                'attachments': attachments,
                                'attachment_count': len(attachments)
                            }

                            payload = {
                                'user': USER_ID,
                                'user_id': USER_ID,
                                'timestamp': email_sent_time.strftime('%Y-%m-%d %H:%M:%S'),
                                'event_type': 'EMAIL',
                                'activity': 'Send',
                                'details': json.dumps(details_dict)
                            }

                            # Send to Localhost
                            try:
                                res = requests.post(API_URL, json=payload, timeout=5)
                                if res.status_code == 200:
                                    self.print_ui_alert(res.json(), details_dict, payload['timestamp'])
                            except:
                                pass

                            self.processed_ids.add(msg.EntryID)
                    else:
                        # Since items are sorted newest-to-oldest, 
                        # once we hit an email older than start_time, we can stop the inner loop
                        break

                time.sleep(CHECK_INTERVAL)
            except Exception as e:
                time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    StrictTimeMonitor().run()