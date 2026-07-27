"""
Database Initialization - COMPLETE FIX
Handles ALL temporal fields: Time, Date, and DateTime conversions
"""

import sys
import os
from pathlib import Path
from datetime import time, date, datetime

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app, db
from app.models.database import User, UserProfile
import pandas as pd
from werkzeug.security import generate_password_hash

def init_database():
    app = create_app()
    
    with app.app_context():
        print("\n" + "=" * 70)
        print("🗄️  DATABASE INITIALIZATION - COMPLETE")
        print("=" * 70 + "\n")
        
        print("Step 1: Clear database?")
        response = input("⚠️  DELETE all data? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Cancelled.")
            return
        
        db.drop_all()
        db.create_all()
        print("✓ Tables ready\n")
        
        # Admin
        print("Step 2: Creating admin...")
        try:
            import secrets
            admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash(admin_password)
            )
            db.session.add(admin)
            db.session.commit()
            print(f"✓ Admin created — username: admin, password: {admin_password}")
            print("  ⚠️  Save this now — it will not be shown again.\n")
        except:
            db.session.rollback()
            print("✓ Admin exists\n")
        
        # Load CSV
        print("Step 3: Loading CSV...")
        csv_file = 'user_profiles.csv'
        
        if not os.path.exists(csv_file):
            print(f"❌ {csv_file} not found!")
            return
        
        df = pd.read_csv(csv_file)
        print(f"✓ Found {len(df)} users\n")
        print("Converting all temporal fields...\n")
        
        loaded = 0
        
        for idx, row in df.iterrows():
            try:
                profile = UserProfile(user_id=str(row['user_id']).strip())
                
                # === STRING FIELDS ===
                profile.full_name = str(row.get('full_name', row['user_id']))
                profile.department = str(row.get('department', ''))
                profile.role = str(row.get('role', ''))
                profile.supervisor = str(row.get('supervisor', ''))
                profile.typical_work_days = str(row.get('typical_work_days', '0,1,2,3,4'))
                profile.current_risk_level = str(row.get('current_risk_level', 'LOW'))
                
                # === NUMERIC FIELDS ===
                profile.avg_file_accesses_per_day = float(row.get('avg_file_accesses_per_day', 0))
                profile.avg_http_requests_per_day = float(row.get('avg_http_requests_per_day', 0))
                profile.avg_email_count_per_day = float(row.get('avg_email_count_per_day', 0))
                profile.usb_usage_frequency = float(row.get('usb_usage_frequency', 0))
                profile.total_alerts = int(row.get('total_alerts', 0))
                profile.high_risk_alerts = int(row.get('high_risk_alerts', 0))
                
                # === TIME FIELDS (hour:minute:second) ===
                if hasattr(profile, 'avg_logon_time') and 'avg_logon_hour' in row:
                    try:
                        hour = int(row['avg_logon_hour'])
                        profile.avg_logon_time = time(hour=hour, minute=0, second=0)
                    except:
                        profile.avg_logon_time = None
                
                if hasattr(profile, 'avg_logoff_time') and 'avg_logoff_hour' in row:
                    try:
                        hour = int(row['avg_logoff_hour'])
                        profile.avg_logoff_time = time(hour=hour, minute=0, second=0)
                    except:
                        profile.avg_logoff_time = None
                
                # === DATE FIELDS (year-month-day) ===
                # Convert "2010-01-02" string to date object
                if hasattr(profile, 'baseline_start'):
                    try:
                        if pd.notna(row.get('baseline_start')) and row.get('baseline_start'):
                            date_str = str(row['baseline_start'])
                            profile.baseline_start = datetime.strptime(date_str, '%Y-%m-%d').date()
                        else:
                            profile.baseline_start = None
                    except:
                        profile.baseline_start = None
                
                if hasattr(profile, 'baseline_end'):
                    try:
                        if pd.notna(row.get('baseline_end')) and row.get('baseline_end'):
                            date_str = str(row['baseline_end'])
                            profile.baseline_end = datetime.strptime(date_str, '%Y-%m-%d').date()
                        else:
                            profile.baseline_end = None
                    except:
                        profile.baseline_end = None
                
                # === DATETIME FIELDS (full timestamp) ===
                # Set to None - will be auto-populated by SQLAlchemy if needed
                if hasattr(profile, 'last_alert_date'):
                    profile.last_alert_date = None
                if hasattr(profile, 'last_activity'):
                    profile.last_activity = None
                if hasattr(profile, 'created_at'):
                    profile.created_at = None
                if hasattr(profile, 'updated_at'):
                    profile.updated_at = None
                
                db.session.add(profile)
                db.session.flush()
                db.session.commit()
                
                loaded += 1
                
                if loaded % 100 == 0:
                    print(f"  {loaded}/1000...")
                
            except Exception as e:
                db.session.rollback()
                print(f"  ✗ Row {idx} ({row.get('user_id', '?')}): {str(e)}")
                continue
        
        print(f"\n✓ Loaded {loaded} users\n")
        
        # AUN001
        print("Step 4: Adding AUN001...")
        existing = UserProfile.query.filter_by(user_id='AUN001').first()
        
        if not existing:
            try:
                aun = UserProfile(user_id='AUN001')
                aun.full_name = 'Aun - CS Student'
                aun.department = 'IT'
                aun.role = 'Student'
                aun.typical_work_days = '0,1,2,3,4'
                aun.current_risk_level = 'LOW'
                aun.avg_file_accesses_per_day = 15.0
                aun.avg_http_requests_per_day = 50.0
                aun.avg_email_count_per_day = 5.0
                aun.usb_usage_frequency = 0.5
                aun.total_alerts = 0
                aun.high_risk_alerts = 0
                
                # Time fields
                if hasattr(aun, 'avg_logon_time'):
                    aun.avg_logon_time = time(hour=9, minute=0)
                if hasattr(aun, 'avg_logoff_time'):
                    aun.avg_logoff_time = time(hour=18, minute=0)
                
                # Date fields
                if hasattr(aun, 'baseline_start'):
                    aun.baseline_start = date.today()
                if hasattr(aun, 'baseline_end'):
                    aun.baseline_end = date.today()
                
                # DateTime fields
                if hasattr(aun, 'last_alert_date'):
                    aun.last_alert_date = None
                if hasattr(aun, 'last_activity'):
                    aun.last_activity = None
                if hasattr(aun, 'created_at'):
                    aun.created_at = None
                if hasattr(aun, 'updated_at'):
                    aun.updated_at = None
                
                db.session.add(aun)
                db.session.commit()
                print("✓ Created\n")
            except Exception as e:
                print(f"✗ Error: {str(e)}\n")
                db.session.rollback()
        else:
            print("✓ Exists\n")
        
        # Verify
        print("Step 5: Verification...")
        total = UserProfile.query.count()
        admins = User.query.count()
        
        print(f"✓ Users: {total}")
        print(f"✓ Admins: {admins}\n")
        
        if total > 0:
            print("Sample users:")
            for u in UserProfile.query.limit(5).all():
                logon = u.avg_logon_time.strftime('%H:%M') if u.avg_logon_time else 'N/A'
                logoff = u.avg_logoff_time.strftime('%H:%M') if u.avg_logoff_time else 'N/A'
                baseline = f"{u.baseline_start} to {u.baseline_end}" if u.baseline_start else 'N/A'
                print(f"  {u.user_id}: {logon}-{logoff} | Baseline: {baseline}")
        
        print("\n" + "=" * 70)
        print("✅ SUCCESS!")
        print("=" * 70)
        print(f"\n📊 Total: {total} users")
        print(f"🔐 Login: admin / (password printed above when the admin account was created)")
        print(f"\n🚀 Next:")
        print(f"  python run.py")
        print(f"  python monitor_agent.py")
        print("=" * 70 + "\n")


if __name__ == '__main__':
    try:
        init_database()
    except KeyboardInterrupt:
        print("\n\nCancelled.")
    except Exception as e:
        print(f"\n\n❌ FATAL: {str(e)}")
        import traceback
        traceback.print_exc()
