"""
Comprehensive Insider Threat Simulator
Tests all risk thresholds: LOW, MEDIUM, HIGH, CRITICAL
Plus normal benign activity
"""

import os
import requests
import random
import time
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List

# ============================================================
# CONFIG
# ============================================================

FLASK_URL = "http://localhost:5000/api/ingest"
API_KEY = os.environ.get("AGENT_API_KEY", "dev-agent-key-change-in-production")
USER_CSV = "user_profiles.csv"

# Risk thresholds (from settings.json)
THRESHOLDS = {
    'LOW': 0.2,
    'MEDIUM': 0.4,
    'HIGH': 0.7,
    'CRITICAL': 0.9
}

# ============================================================
# LOAD USERS
# ============================================================

try:
    users_df = pd.read_csv(USER_CSV)
    USERS = users_df.to_dict(orient="records")
    print(f"✅ Loaded {len(USERS)} users from {USER_CSV}")
except FileNotFoundError:
    # Fallback: Create sample users
    USERS = [
        {"user_id": "TEST001", "avg_logon_hour": 8, "avg_logoff_hour": 18},
        {"user_id": "TEST002", "avg_logon_hour": 7, "avg_logoff_hour": 19},
        {"user_id": "TEST003", "avg_logon_hour": 9, "avg_logoff_hour": 17},
    ]
    print(f"⚠️  {USER_CSV} not found, using {len(USERS)} sample users")

# ============================================================
# TIME HELPERS
# ============================================================

def force_weekday(dt):
    """Ensure timestamp is Mon–Fri"""
    while dt.weekday() >= 5:
        dt -= timedelta(days=1)
    return dt

def force_weekend(dt):
    """Ensure timestamp is Sat–Sun"""
    while dt.weekday() < 5:
        dt += timedelta(days=1)
    return dt

def normal_business_timestamp(base_date=None):
    """Normal activity: 08:00:00 → 17:59:59 (Mon-Fri)"""
    if base_date is None:
        base_date = datetime.now()
    
    base_date = force_weekday(base_date)
    
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    
    return base_date.replace(
        hour=hour, minute=minute, second=second, microsecond=0
    ).isoformat()

def after_hours_timestamp(base_date=None):
    """After-hours: 18:00–07:59 (Mon-Fri)"""
    if base_date is None:
        base_date = datetime.now()
    
    base_date = force_weekday(base_date)
    
    # Either early morning (2-7 AM) or late night (6 PM - 11 PM)
    if random.choice([True, False]):
        hour = random.randint(2, 7)  # Early morning
    else:
        hour = random.randint(18, 23)  # Late night
    
    return base_date.replace(
        hour=hour,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
        microsecond=0
    ).isoformat()

def weekend_timestamp(base_date=None):
    """Weekend activity (Sat-Sun)"""
    if base_date is None:
        base_date = datetime.now()
    
    base_date = force_weekend(base_date)
    
    hour = random.randint(9, 18)
    
    return base_date.replace(
        hour=hour,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
        microsecond=0
    ).isoformat()

# ============================================================
# SIMULATOR CLASS
# ============================================================

class ThreatSimulator:
    
    def __init__(self):
        self.session = requests.Session()
        self.stats = {
            'sent': 0,
            'alerts': 0,
            'benign': 0,
            'by_level': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        }
        
        self.sensitive_keywords = [
            "confidential", "password", "classified", "credentials",
            "proprietary", "secret", "malware", "hack", "exploit",
            "backdoor", "exfiltrate", "steal", "leak"
        ]
    
    def send(self, event: Dict, expected_level: str = None):
        """Send event to Flask API and track response"""
        try:
            r = self.session.post(FLASK_URL, json=event, headers={"X-API-Key": API_KEY}, timeout=5)
            self.stats['sent'] += 1
            
            if r.status_code == 200:
                res = r.json()
                
                if res.get("alert_generated"):
                    self.stats['alerts'] += 1
                    risk_level = res.get("risk_level", "UNKNOWN")
                    risk_score = res.get("risk_score", 0.0)
                    
                    if risk_level in self.stats['by_level']:
                        self.stats['by_level'][risk_level] += 1
                    
                    indicator = "🚨" if risk_level == "CRITICAL" else "⚠️" if risk_level == "HIGH" else "⚡" if risk_level == "MEDIUM" else "📌"
                    
                    print(f"{indicator} ALERT: {risk_level} ({risk_score:.3f}) - {event['user_id']} - {event['event_type']}")
                    
                    if expected_level:
                        match = "✅" if risk_level == expected_level else "❌"
                        print(f"   {match} Expected: {expected_level}, Got: {risk_level}")
                else:
                    self.stats['benign'] += 1
                    print(f"✓ Benign - {event['user_id']} - {event['event_type']}")
            else:
                print(f"❌ HTTP error {r.status_code}")
        
        except Exception as e:
            print(f"❌ Send failed: {e}")
    
    # ============================================================
    # NORMAL ACTIVITY (NO ALERTS)
    # ============================================================
    
    def normal_logon(self, user):
        """Normal business hours logon"""
        return {
            "user_id": user["user_id"],
            "event_type": "LOGON",
            "timestamp": normal_business_timestamp(),
            "activity": "LOGON",
            "details": json.dumps({
                "event_type": "LOGON",
                "pc": f"PC-{random.randint(1000,9999)}",
                "logon_type": "Interactive"
            })
        }
    
    def normal_http(self, user):
        """Normal web browsing"""
        return {
            "user_id": user["user_id"],
            "event_type": "HTTP",
            "timestamp": normal_business_timestamp(),
            "activity": "GET",
            "details": json.dumps({
                "event_type": "HTTP",
                "url": random.choice([
                    "https://portal.company.com",
                    "https://email.company.com",
                    "https://docs.company.com",
                    "https://wiki.company.com"
                ])
            })
        }
    
    def normal_file(self, user):
        """Normal file operations"""
        return {
            "user_id": user["user_id"],
            "event_type": "FILE",
            "timestamp": normal_business_timestamp(),
            "activity": random.choice(["Open", "Edit", "Save"]),
            "details": json.dumps({
                "event_type": "FILE",
                "filename": random.choice([
                    "report.xlsx", "notes.docx", "plan.pdf",
                    "meeting_notes.txt", "budget.xlsx"
                ])
            })
        }
    
    def normal_email(self, user):
        """Normal internal email"""
        return {
            "user_id": user["user_id"],
            "event_type": "EMAIL",
            "timestamp": normal_business_timestamp(),
            "activity": "Send",
            "details": json.dumps({
                "event_type": "EMAIL",
                "to": "team@company.com",
                "subject": "Meeting follow-up",
                "size": random.randint(2000, 60000)
            })
        }
    
    # ============================================================
    # LOW RISK (~0.2-0.3) - After-hours logon only
    # ============================================================
    
    def low_after_hours_logon(self, user):
        """After-hours logon: +0.25 = LOW"""
        return {
            "user_id": user["user_id"],
            "event_type": "LOGON",
            "timestamp": after_hours_timestamp(),
            "activity": "LOGON",
            "details": json.dumps({
                "event_type": "LOGON",
                "pc": f"PC-{random.randint(1000,9999)}",
                "logon_type": "Interactive"
            })
        }
    
    def low_weekend_logon(self, user):
        """Weekend logon: +0.10 = LOW"""
        return {
            "user_id": user["user_id"],
            "event_type": "LOGON",
            "timestamp": weekend_timestamp(),
            "activity": "LOGON",
            "details": json.dumps({
                "event_type": "LOGON",
                "pc": f"PC-{random.randint(1000,9999)}",
                "logon_type": "Interactive"
            })
        }
    
    # ============================================================
    # MEDIUM RISK (~0.4-0.6) - After-hours activity
    # ============================================================
    
    def medium_after_hours_file(self, user):
        """After-hours file access: +0.40 = MEDIUM"""
        return {
            "user_id": user["user_id"],
            "event_type": "FILE",
            "timestamp": after_hours_timestamp(),
            "activity": "Open",
            "details": json.dumps({
                "event_type": "FILE",
                "filename": "project_data.xlsx"
            })
        }
    
    def medium_after_hours_email(self, user):
        """After-hours email: +0.40 = MEDIUM"""
        return {
            "user_id": user["user_id"],
            "event_type": "EMAIL",
            "timestamp": after_hours_timestamp(),
            "activity": "Send",
            "details": json.dumps({
                "event_type": "EMAIL",
                "to": "colleague@company.com",
                "subject": "Update",
                "size": random.randint(50000, 100000)
            })
        }
    
    def medium_device_connect(self, user):
        """USB device during business hours: +0.25 = MEDIUM"""
        return {
            "user_id": user["user_id"],
            "event_type": "DEVICE",
            "timestamp": normal_business_timestamp(),
            "activity": "Connect",
            "details": json.dumps({
                "event_type": "DEVICE",
                "device": "USB"
            })
        }
    
    # ============================================================
    # HIGH RISK (~0.7-0.8) - Multiple risk factors
    # ============================================================
    
    def high_after_hours_device(self, user):
        """After-hours USB: +0.40 (after-hours) + 0.25 (USB) = 0.65 HIGH"""
        return {
            "user_id": user["user_id"],
            "event_type": "DEVICE",
            "timestamp": after_hours_timestamp(),
            "activity": "Connect",
            "details": json.dumps({
                "event_type": "DEVICE",
                "device": "USB"
            })
        }
    
    def high_keyword_after_hours(self, user):
        """Keyword + after-hours: 0.30 (keyword) + 0.40 (after-hours) = 0.70 HIGH"""
        return {
            "user_id": user["user_id"],
            "event_type": "EMAIL",
            "timestamp": after_hours_timestamp(),
            "activity": "Send",
            "details": json.dumps({
                "event_type": "EMAIL",
                "to": "external@gmail.com",
                "subject": "confidential information",
                "content": "sending confidential data",
                "size": random.randint(100000, 500000)
            })
        }
    
    def high_sensitive_file(self, user):
        """Sensitive file + after-hours: 0.40 + 0.30 = 0.70 HIGH"""
        return {
            "user_id": user["user_id"],
            "event_type": "FILE",
            "timestamp": after_hours_timestamp(),
            "activity": "Copy",
            "details": json.dumps({
                "event_type": "FILE",
                "filename": "confidential_report.xlsx"
            })
        }
    
    # ============================================================
    # CRITICAL RISK (~0.9+) - Severe threats
    # ============================================================
    
    def critical_data_exfiltration(self, user):
        """Large external email + keywords + after-hours = CRITICAL"""
        keyword = random.choice(self.sensitive_keywords)
        return {
            "user_id": user["user_id"],
            "event_type": "EMAIL",
            "timestamp": after_hours_timestamp(),
            "activity": "Send",
            "details": json.dumps({
                "event_type": "EMAIL",
                "to": "external@gmail.com",
                "subject": f"{keyword} documents",
                "content": f"Sending {keyword} data as requested",
                "size": random.randint(5_000_000, 10_000_000),  # 5-10 MB
                "total_email_size": 12_000_000
            })
        }
    
    def critical_malicious_url(self, user):
        """Malicious URL + keywords + after-hours = CRITICAL"""
        return {
            "user_id": user["user_id"],
            "event_type": "HTTP",
            "timestamp": after_hours_timestamp(),
            "activity": "GET",
            "details": json.dumps({
                "event_type": "HTTP",
                "url": "https://hacktools.com/crack/password-dump",
                "content": "downloading exploit tools"
            })
        }
    
    def critical_weekend_device_keyword(self, user):
        """Weekend + USB + sensitive file = CRITICAL"""
        return {
            "user_id": user["user_id"],
            "event_type": "DEVICE",
            "timestamp": weekend_timestamp(),
            "activity": "Connect",
            "details": json.dumps({
                "event_type": "DEVICE",
                "device": "USB",
                "filename": "classified_financial_data.xlsx"
            })
        }
    
    # ============================================================
    # STATISTICS
    # ============================================================
    
    def print_stats(self):
        """Print simulation statistics"""
        print("\n" + "="*60)
        print("📊 SIMULATION STATISTICS")
        print("="*60)
        print(f"Total Events Sent: {self.stats['sent']}")
        print(f"Alerts Generated: {self.stats['alerts']}")
        print(f"Benign Events: {self.stats['benign']}")
        print(f"\n🎯 Alerts by Risk Level:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = self.stats['by_level'][level]
            pct = (count / self.stats['alerts'] * 100) if self.stats['alerts'] > 0 else 0
            print(f"   {level:10s}: {count:3d} ({pct:5.1f}%)")
        print("="*60 + "\n")

# ============================================================
# TEST SCENARIOS
# ============================================================

def test_normal_activity(sim: ThreatSimulator, count: int = 10):
    """Test normal benign activity (should NOT generate alerts)"""
    print(f"\n🟢 Testing NORMAL Activity ({count} events)")
    print("-" * 60)
    
    user = random.choice(USERS)
    
    for _ in range(count):
        event_generator = random.choice([
            sim.normal_logon,
            sim.normal_http,
            sim.normal_file,
            sim.normal_email
        ])
        sim.send(event_generator(user))
        time.sleep(0.3)

def test_low_risk(sim: ThreatSimulator, count: int = 5):
    """Test LOW risk scenarios (0.2-0.39)"""
    print(f"\n📌 Testing LOW RISK Scenarios ({count} events)")
    print("-" * 60)
    
    user = random.choice(USERS)
    
    scenarios = [
        (sim.low_after_hours_logon, "After-hours logon"),
        (sim.low_weekend_logon, "Weekend logon"),
    ]
    
    for generator, desc in scenarios * (count // 2 + 1):
        print(f"Scenario: {desc}")
        sim.send(generator(user), expected_level="LOW")
        time.sleep(0.5)

def test_medium_risk(sim: ThreatSimulator, count: int = 5):
    """Test MEDIUM risk scenarios (0.4-0.69)"""
    print(f"\n⚡ Testing MEDIUM RISK Scenarios ({count} events)")
    print("-" * 60)
    
    user = random.choice(USERS)
    
    scenarios = [
        (sim.medium_after_hours_file, "After-hours file access"),
        (sim.medium_after_hours_email, "After-hours email"),
        (sim.medium_device_connect, "USB device connection"),
    ]
    
    for generator, desc in scenarios:
        print(f"Scenario: {desc}")
        sim.send(generator(user), expected_level="MEDIUM")
        time.sleep(0.5)

def test_high_risk(sim: ThreatSimulator, count: int = 5):
    """Test HIGH risk scenarios (0.7-0.89)"""
    print(f"\n⚠️  Testing HIGH RISK Scenarios ({count} events)")
    print("-" * 60)
    
    user = random.choice(USERS)
    
    scenarios = [
        (sim.high_after_hours_device, "After-hours USB device"),
        (sim.high_keyword_after_hours, "Keywords + after-hours email"),
        (sim.high_sensitive_file, "Sensitive file + after-hours"),
    ]
    
    for generator, desc in scenarios:
        print(f"Scenario: {desc}")
        sim.send(generator(user), expected_level="HIGH")
        time.sleep(0.5)

def test_critical_risk(sim: ThreatSimulator, count: int = 3):
    """Test CRITICAL risk scenarios (≥0.9)"""
    print(f"\n🚨 Testing CRITICAL RISK Scenarios ({count} events)")
    print("-" * 60)
    
    user = random.choice(USERS)
    
    scenarios = [
        (sim.critical_data_exfiltration, "Data exfiltration attempt"),
        (sim.critical_malicious_url, "Malicious URL access"),
        (sim.critical_weekend_device_keyword, "Weekend USB + sensitive data"),
    ]
    
    for generator, desc in scenarios:
        print(f"Scenario: {desc}")
        sim.send(generator(user), expected_level="CRITICAL")
        time.sleep(0.5)

def run_comprehensive_test(sim: ThreatSimulator):
    """Run all tests in sequence"""
    print("\n" + "="*60)
    print("🚀 COMPREHENSIVE THREAT DETECTION TEST")
    print("="*60)
    print(f"Flask API: {FLASK_URL}")
    print(f"Users: {len(USERS)}")
    print(f"Risk Thresholds: LOW≥{THRESHOLDS['LOW']}, MEDIUM≥{THRESHOLDS['MEDIUM']}, HIGH≥{THRESHOLDS['HIGH']}, CRITICAL≥{THRESHOLDS['CRITICAL']}")
    print("="*60)
    
    test_normal_activity(sim, count=10)
    test_low_risk(sim, count=4)
    test_medium_risk(sim, count=5)
    test_high_risk(sim, count=5)
    test_critical_risk(sim, count=3)
    
    sim.print_stats()

def insider_attack_scenario(sim: ThreatSimulator):
    """Simulate realistic insider attack progression"""
    user = random.choice(USERS)
    
    print(f"\n🎯 INSIDER ATTACK SCENARIO")
    print("="*60)
    print(f"Target User: {user['user_id']}")
    print("="*60)
    
    steps = [
        (sim.normal_logon, "1. Normal logon (establish baseline)"),
        (sim.normal_http, "2. Normal browsing"),
        (sim.low_after_hours_logon, "3. After-hours logon (reconnaissance)"),
        (sim.medium_after_hours_file, "4. After-hours file access"),
        (sim.high_sensitive_file, "5. Access sensitive files"),
        (sim.high_after_hours_device, "6. Connect USB device"),
        (sim.critical_data_exfiltration, "7. Exfiltrate data via email"),
    ]
    
    for generator, description in steps:
        print(f"\n{description}")
        sim.send(generator(user))
        time.sleep(1.5)
    
    print("\n" + "="*60)
    print("✅ Insider attack scenario complete")
    print("="*60)

# ============================================================
# MAIN MENU
# ============================================================

def main():
    sim = ThreatSimulator()
    
    while True:
        print("\n" + "="*60)
        print("🔐 INSIDER THREAT DETECTION - COMPREHENSIVE SIMULATOR")
        print("="*60)
        print("1. Test Normal Activity (No Alerts)")
        print("2. Test LOW Risk (0.2-0.39)")
        print("3. Test MEDIUM Risk (0.4-0.69)")
        print("4. Test HIGH Risk (0.7-0.89)")
        print("5. Test CRITICAL Risk (≥0.9)")
        print("6. Run Comprehensive Test (All Levels)")
        print("7. Insider Attack Scenario (Progressive)")
        print("8. View Statistics")
        print("9. Exit")
        print("="*60)
        
        choice = input("Select option: ").strip()
        
        if choice == "1":
            count = int(input("How many events? [10]: ") or "10")
            test_normal_activity(sim, count)
        
        elif choice == "2":
            count = int(input("How many events? [4]: ") or "4")
            test_low_risk(sim, count)
        
        elif choice == "3":
            count = int(input("How many events? [5]: ") or "5")
            test_medium_risk(sim, count)
        
        elif choice == "4":
            count = int(input("How many events? [5]: ") or "5")
            test_high_risk(sim, count)
        
        elif choice == "5":
            count = int(input("How many events? [3]: ") or "3")
            test_critical_risk(sim, count)
        
        elif choice == "6":
            run_comprehensive_test(sim)
        
        elif choice == "7":
            insider_attack_scenario(sim)
        
        elif choice == "8":
            sim.print_stats()
        
        elif choice == "9":
            sim.print_stats()
            print("\n👋 Exiting simulator...")
            break
        
        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    print("🚀 Starting Comprehensive Threat Simulator...")
    print(f"📡 Connecting to: {FLASK_URL}")
    main()