"""
Demo data seeder.

Populates a small, entirely synthetic set of events and alerts so the
dashboard/alerts/user-detail pages have something to show right after a
fresh clone — no real monitoring agents, no personal data involved.

Run AFTER init_database.py (needs UserProfile rows already loaded from
user_profiles.csv, which is itself derived from the public CERT r4.2
research dataset — synthetic personas, not real people):

    python init_database.py
    python seed_demo_data.py
    python run.py
"""
import hashlib
import json
import random
from datetime import datetime, timedelta

from app import create_app
from app.models.database import db, Event, Alert, UserProfile
from app.routes.api import get_detection_engine

DEMO_USER_COUNT = 8
DAYS_OF_HISTORY = 14

NORMAL_EVENTS = [
    ("LOGON", "Logon", lambda: {"pc": "PC-DEMO-01", "activity": "Logon"}),
    ("HTTP", "GET", lambda: {
        "pc": "PC-DEMO-01",
        "url": random.choice([
            "https://portal.company.com", "https://docs.company.com", "https://wiki.company.com",
        ]),
        "content": "",
    }),
    ("FILE", "FILE_ACCESS", lambda: {
        "pc": "PC-DEMO-01",
        "filename": random.choice([
            "quarterly_report.xlsx", "meeting_notes.docx", "project_plan.pdf",
        ]),
        "content": "",
    }),
    ("EMAIL", "Send", lambda: {
        "pc": "PC-DEMO-01", "to": "colleague@company.com", "subject": "Weekly status update",
        "size": str(random.randint(2000, 60000)), "cc": "", "bcc": "", "attachments": "", "content": "",
    }),
]

SUSPICIOUS_EVENTS = [
    ("DEVICE", "Connect", lambda: {
        "pc": "PC-DEMO-01", "activity": "Connect", "file_tree": "E:\\", "filename": "customer_export.xlsx",
    }),
    ("EMAIL", "Send", lambda: {
        "pc": "PC-DEMO-01", "to": "external@gmail.com", "subject": "confidential financial data",
        "size": "8000000", "cc": "", "bcc": "", "attachments": "financials.xlsx",
        "content": "sending confidential quarterly financials",
    }),
    ("HTTP", "GET", lambda: {"pc": "PC-DEMO-01", "url": "https://pastebin.com/leaked-credentials", "content": ""}),
]


def make_event_id(user, ts, etype):
    return hashlib.md5(f"{user}{ts}{etype}{random.random()}".encode()).hexdigest()[:16]


def business_hours_ts(days_ago):
    ts = datetime.now() - timedelta(days=days_ago)
    return ts.replace(hour=random.randint(9, 17), minute=random.randint(0, 59), second=0, microsecond=0)


def after_hours_ts(days_ago):
    ts = datetime.now() - timedelta(days=days_ago)
    return ts.replace(hour=random.choice([2, 3, 22, 23]), minute=random.randint(0, 59), second=0, microsecond=0)


def build_event(user_id, event_type, activity, details, timestamp):
    return {
        "event_id": make_event_id(user_id, timestamp.isoformat(), event_type),
        "user": user_id,
        "user_id": user_id,
        "event_type": event_type,
        "activity": activity,
        "timestamp": timestamp.isoformat(),
        "details": json.dumps(details),
    }


def save_event(event_data, result):
    """Persist one event (and its alert, if the detection engine flagged it)."""
    is_anomalous = result is not None
    timestamp = datetime.fromisoformat(event_data["timestamp"])

    event = Event(
        event_id=event_data["event_id"],
        user_id=event_data["user_id"],
        timestamp=timestamp,
        event_type=event_data["event_type"],
        activity=event_data["activity"],
        details=event_data["details"],
        is_anomalous=is_anomalous,
        anomaly_score=result.get("anomaly_score") if result else None,
        risk_score=result.get("risk_score") if result else None,
    )
    db.session.add(event)
    db.session.flush()

    if result:
        alert_id = hashlib.md5(f"{event_data['user_id']}{timestamp.isoformat()}demo".encode()).hexdigest()[:16]
        db.session.add(Alert(
            alert_id=alert_id,
            user_id=event_data["user_id"],
            timestamp=timestamp,
            alert_type=event_data["event_type"],
            risk_level=result.get("risk_level", "LOW"),
            risk_score=result.get("risk_score", 0.0),
            anomaly_score=result.get("anomaly_score", 0.0),
            description=result.get("description", ""),
            event_details=event_data["details"],
            status="OPEN",
        ))

        profile = UserProfile.query.filter_by(user_id=event_data["user_id"]).first()
        if profile:
            profile.total_alerts = (profile.total_alerts or 0) + 1
            if result.get("risk_level") in ("HIGH", "CRITICAL"):
                profile.high_risk_alerts = (profile.high_risk_alerts or 0) + 1
            profile.current_risk_level = result.get("risk_level", "LOW")
            profile.last_alert_date = datetime.now()
            profile.last_activity = timestamp


def seed():
    app = create_app("development")
    with app.app_context():
        users = UserProfile.query.limit(DEMO_USER_COUNT).all()
        if not users:
            print("No user profiles found — run `python init_database.py` first.")
            return

        engine = get_detection_engine()
        if engine is None:
            print("Detection engine failed to load — check data/models/ has a trained model.")
            return

        events_created = 0
        alerts_created = 0

        # ~2 weeks of normal daily activity per demo user
        for user in users:
            for days_ago in range(DAYS_OF_HISTORY, 0, -1):
                for event_type, activity, details_fn in NORMAL_EVENTS:
                    if random.random() < 0.6:  # not every user does every activity every day
                        continue
                    ts = business_hours_ts(days_ago)
                    event_data = build_event(user.user_id, event_type, activity, details_fn(), ts)
                    result = engine.process_single_event(event_data)
                    save_event(event_data, result)
                    events_created += 1
                    if result:
                        alerts_created += 1

        # A few deliberately suspicious events so alerts/behavioral-analysis pages
        # have something to show.
        for user in users[:4]:
            event_type, activity, details_fn = random.choice(SUSPICIOUS_EVENTS)
            ts = after_hours_ts(random.randint(1, 5))
            event_data = build_event(user.user_id, event_type, activity, details_fn(), ts)
            result = engine.process_single_event(event_data)
            save_event(event_data, result)
            events_created += 1
            if result:
                alerts_created += 1

        db.session.commit()
        print(f"Seeded {events_created} events ({alerts_created} generated alerts) "
              f"across {len(users)} demo users: {', '.join(u.user_id for u in users)}")


if __name__ == "__main__":
    seed()
