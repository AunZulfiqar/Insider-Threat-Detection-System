"""
Optimized loader for CERT r4.2 malicious user activity.

Key optimizations vs previous version:
  - CSVs parsed ONCE into memory, then sliced per user (no re-reads)
  - Detection runs in BATCHES of 100 events (not one-at-a-time)
  - DB inserts committed in batches of 500
  - Rich terminal progress bar with ETA

Strategy:
  - Attack window: ALL events within labeled malicious period
  - Normal days: 3 days before attack window per user (for contrast)

Usage (run from project root):
    python load_malicious_users.py "C:\\path\\to\\cert_r4.2"
"""

import sys
import csv
import json
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

NORMAL_DAYS_PER_USER = 3
BATCH_SIZE = 100          # events processed per detection batch
DB_COMMIT_EVERY = 500     # rows between DB commits


# ── Progress bar ─────────────────────────────────────────────────────────────

class Progress:
    def __init__(self, total, width=40):
        self.total = total
        self.width = width
        self.start = time.time()
        self.current = 0

    def update(self, n=1):
        self.current += n

    def print(self, extra=''):
        done = self.current
        pct  = done / self.total if self.total else 0
        filled = int(self.width * pct)
        bar  = '█' * filled + '░' * (self.width - filled)
        elapsed = time.time() - self.start
        eta = (elapsed / pct - elapsed) if pct > 0 else 0
        eta_str = f"{int(eta//60)}m{int(eta%60):02d}s" if eta > 0 else "--:--"
        sys.stdout.write(
            f"\r  [{bar}] {pct*100:5.1f}%  {done}/{self.total}"
            f"  elapsed {int(elapsed//60)}m{int(elapsed%60):02d}s"
            f"  ETA {eta_str}  {extra}   "
        )
        sys.stdout.flush()

    def done(self):
        elapsed = time.time() - self.start
        sys.stdout.write(
            f"\r  [{'█'*self.width}] 100.0%  {self.total}/{self.total}"
            f"  elapsed {int(elapsed//60)}m{int(elapsed%60):02d}s  done!   \n"
        )
        sys.stdout.flush()


# ── Ground-truth loader ──────────────────────────────────────────────────────

def load_ground_truth(cert_path: Path):
    for candidate in [
        cert_path / 'answers' / 'insiders.csv',
        cert_path.parent / 'answers' / 'insiders.csv',
    ]:
        if candidate.exists():
            insiders_file = candidate
            break
    else:
        print("ERROR: answers/insiders.csv not found.")
        print(f"  Looked in: {cert_path / 'answers'} and {cert_path.parent / 'answers'}")
        sys.exit(1)

    rows = []
    with open(insiders_file, newline='') as f:
        for r in csv.DictReader(f):
            if r['dataset'].strip() == '4.2':
                rows.append({
                    'user':     r['user'].strip(),
                    'scenario': r['scenario'].strip(),
                    'start':    r['start'].strip(),
                    'end':      r['end'].strip(),
                })
    print(f"✔  Loaded {len(rows)} labeled malicious users (r4.2) from {insiders_file.name}")
    return rows


# ── CSV helpers ──────────────────────────────────────────────────────────────

def parse_ts(s):
    for fmt in ('%m/%d/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(str(s).strip(), fmt)
        except Exception:
            pass
    return None


def load_csv_filtered(cert_path: Path, filename: str, users: set) -> pd.DataFrame:
    fp = cert_path / filename
    if not fp.exists():
        print(f"  ⚠  {filename} not found — skipping")
        return pd.DataFrame()

    # Read in chunks for memory efficiency on large files (http.csv = 1.3M rows)
    chunks = []
    chunk_size = 50_000
    reader = pd.read_csv(fp, chunksize=chunk_size, low_memory=False)
    total_kept = 0
    for chunk in reader:
        chunk.columns = [c.strip().lower() for c in chunk.columns]
        user_col = next((c for c in chunk.columns if 'user' in c), None)
        if user_col and user_col != 'user':
            chunk = chunk.rename(columns={user_col: 'user'})
        chunk['user'] = chunk['user'].astype(str).str.strip()
        filtered = chunk[chunk['user'].isin(users)]
        if not filtered.empty:
            chunks.append(filtered)
            total_kept += len(filtered)

    df = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()
    print(f"  ✔  {filename:<12} → {total_kept:>7,} rows matched")
    return df


# ── Detail builders ──────────────────────────────────────────────────────────

def make_details(row, event_type):
    r = row
    if event_type == 'LOGON':
        return {'pc': str(r.get('pc', '')), 'activity': str(r.get('activity', ''))}
    if event_type == 'DEVICE':
        return {'pc': str(r.get('pc', '')), 'activity': str(r.get('activity', '')),
                'file_tree': str(r.get('file_tree', ''))[:400]}
    if event_type == 'HTTP':
        return {'pc': str(r.get('pc', '')), 'url': str(r.get('url', ''))[:400],
                'content': str(r.get('content', ''))[:150]}
    if event_type == 'FILE':
        return {'pc': str(r.get('pc', '')), 'filename': str(r.get('filename', '')),
                'content': str(r.get('content', ''))[:150]}
    if event_type == 'EMAIL':
        return {'pc': str(r.get('pc', '')), 'to': str(r.get('to', '')),
                'cc': str(r.get('cc', '')), 'bcc': str(r.get('bcc', '')),
                'size': str(r.get('size', '')),
                'attachments': str(r.get('attachments', '')),
                'content': str(r.get('content', ''))[:150]}
    return {}


# ── Event builder ────────────────────────────────────────────────────────────

ACTIVITY_DEFAULT = {
    'LOGON': 'Logon', 'DEVICE': 'Connect',
    'HTTP': 'WEB_ACCESS', 'FILE': 'FILE_ACCESS', 'EMAIL': 'EMAIL_SENT'
}

def build_events(cert_path: Path, label_rows: list) -> list:
    windows = {}
    for r in label_rows:
        s, e = parse_ts(r['start']), parse_ts(r['end'])
        if s and e:
            windows[r['user']] = (s, e, r['scenario'])

    users = set(windows.keys())
    print(f"\n{'─'*55}")
    print(f"  Loading & filtering CSVs for {len(users)} users ...")
    print(f"{'─'*55}")

    FILE_MAP = [
        ('logon.csv',  'LOGON'),
        ('device.csv', 'DEVICE'),
        ('http.csv',   'HTTP'),
        ('file.csv',   'FILE'),
        ('email.csv',  'EMAIL'),
    ]

    # Load all files once, filtered to malicious users only
    raw_dfs = {}
    for fname, etype in FILE_MAP:
        df = load_csv_filtered(cert_path, fname, users)
        if df.empty:
            continue
        df['_ts'] = df['date'].apply(parse_ts)
        df = df.dropna(subset=['_ts'])
        raw_dfs[etype] = df

    print(f"\n  Building trimmed event list ...")
    all_events = []

    for user, (win_start, win_end, scenario) in windows.items():
        for etype, df in raw_dfs.items():
            udf = df[df['user'] == user]
            if udf.empty:
                continue

            # All events inside attack window
            attack = udf[(udf['_ts'] >= win_start) & (udf['_ts'] <= win_end)]

            # Last N normal days before window
            before = udf[udf['_ts'] < win_start].copy()
            before['_date'] = before['_ts'].dt.date
            days = sorted(before['_date'].unique())
            sample_days = days[-NORMAL_DAYS_PER_USER:]
            normal = before[before['_date'].isin(sample_days)]

            for _, row in pd.concat([attack, normal], ignore_index=True).iterrows():
                all_events.append({
                    'user':       user,
                    'timestamp':  row['_ts'],
                    'event_type': etype,
                    'activity':   str(row.get('activity', ACTIVITY_DEFAULT[etype])),
                    'details':    json.dumps(make_details(row, etype)),
                })

    all_events.sort(key=lambda e: e['timestamp'])
    print(f"  ✔  {len(all_events):,} events ready to process")
    return all_events


def make_event_id(user, timestamp, event_type):
    return hashlib.md5(f"{user}{timestamp}{event_type}".encode()).hexdigest()[:16]


# ── Batch detection ──────────────────────────────────────────────────────────

def run_batch_detection(engine, batch: list) -> list:
    """
    Run a batch of events through detection. The engine's process_single_event
    is called per event (it needs individual context), but we group DB writes
    so commits happen far less often than before.
    Returns list of result dicts (None if normal).
    """
    results = []
    for e in batch:
        event_data = {
            'event_id':   make_event_id(e['user'], e['timestamp'], e['event_type']),
            'user':       e['user'],
            'user_id':    e['user'],
            'event_type': e['event_type'],
            'activity':   e['activity'],
            'timestamp':  e['timestamp'].isoformat(),
            'details':    e['details'],
        }
        try:
            result = engine.process_single_event(event_data)
        except Exception:
            result = None
        results.append((event_data, result))
    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python load_malicious_users.py \"C:\\path\\to\\cert_r4.2\"")
        sys.exit(1)

    cert_path = Path(sys.argv[1])
    if not cert_path.exists():
        print(f"Path not found: {cert_path}")
        sys.exit(1)

    sys.path.insert(0, str(Path(__file__).parent))
    from app import create_app
    from app.models.database import db, Event, Alert, UserProfile
    from app.routes.api import get_detection_engine

    print(f"\n{'='*55}")
    print(f"  CERT r4.2 Malicious User Loader")
    print(f"{'='*55}")

    label_rows = load_ground_truth(cert_path)

    # Save ground truth for Step 5 evaluation
    gt_out = Path('data') / 'ground_truth_labels.json'
    gt_out.parent.mkdir(parents=True, exist_ok=True)
    with open(gt_out, 'w') as f:
        json.dump(label_rows, f, indent=2)
    print(f"✔  Ground truth saved → {gt_out}")

    app = create_app('development')

    with app.app_context():
        print("\n  Initializing detection engine ...")
        engine = get_detection_engine()
        if engine is None:
            print("ERROR: Detection engine failed to initialize.")
            sys.exit(1)
        print("✔  Detection engine ready\n")

        # Ensure user_profiles exist
        created = 0
        for r in label_rows:
            if not UserProfile.query.filter_by(user_id=r['user']).first():
                db.session.add(UserProfile(
                    user_id=r['user'],
                    full_name=f"{r['user']} (CERT scenario {r['scenario']})",
                    department='Unknown', role='Unknown',
                    current_risk_level='LOW',
                    total_alerts=0, high_risk_alerts=0,
                ))
                created += 1
        db.session.commit()
        print(f"✔  User profiles: {created} created, "
              f"{len(label_rows)-created} already existed\n")

        events = build_events(cert_path, label_rows)
        if not events:
            print("No events built — check CSV paths.")
            sys.exit(1)

        existing_ids = set(r[0] for r in db.session.query(Event.event_id).all())

        # Filter out already-loaded events upfront so progress bar is accurate
        new_events = [
            e for e in events
            if make_event_id(e['user'], e['timestamp'], e['event_type']) not in existing_ids
        ]
        skipped = len(events) - len(new_events)

        print(f"\n{'─'*55}")
        print(f"  Processing {len(new_events):,} new events "
              f"({skipped:,} already in DB)")
        print(f"  Batch size: {BATCH_SIZE} events | "
              f"DB commit every {DB_COMMIT_EVERY} events")
        print(f"{'─'*55}")

        inserted_alert_ids = set(r[0] for r in db.session.query(Alert.alert_id).all())
        inserted = 0
        alerts_created = 0
        errors = 0
        progress = Progress(len(new_events))

        # Process in batches
        for batch_start in range(0, len(new_events), BATCH_SIZE):
            batch = new_events[batch_start: batch_start + BATCH_SIZE]
            batch_results = run_batch_detection(engine, batch)

            for e, (event_data, result) in zip(batch, batch_results):
                event_id     = event_data['event_id']
                is_anomalous = result is not None
                risk_score   = result.get('risk_score', 0.0)    if result else 0.0
                risk_level   = result.get('risk_level', 'LOW')  if result else 'NORMAL'
                description  = result.get('description', '')    if result else ''
                anomaly_sc   = result.get('anomaly_score', 0.0) if result else 0.0

                # skip if this ID already appeared earlier in THIS run
                if event_id in existing_ids:
                    skipped += 1
                    continue

                try:
                    ev = Event(
                        event_id=event_id,
                        user_id=e['user'],
                        timestamp=e['timestamp'],
                        event_type=e['event_type'],
                        activity=e['activity'],
                        details=e['details'],
                        is_anomalous=is_anomalous,
                        anomaly_score=anomaly_sc if is_anomalous else None,
                        risk_score=risk_score if is_anomalous else None,
                    )
                    db.session.add(ev)
                    existing_ids.add(event_id)
                    inserted += 1
                except Exception:
                    errors += 1
                    db.session.rollback()
                    continue

                if is_anomalous:
                    alert_id = hashlib.md5(
                        f"{e['user']}{e['timestamp'].isoformat()}cert".encode()
                    ).hexdigest()[:16]
                    if alert_id not in inserted_alert_ids:
                        try:
                            db.session.add(Alert(
                                alert_id=alert_id,
                                user_id=e['user'],
                                timestamp=e['timestamp'],
                                alert_type=e['event_type'],
                                risk_level=risk_level,
                                risk_score=risk_score,
                                anomaly_score=anomaly_sc,
                                description=description,
                                event_details=e['details'],
                                status='OPEN',
                            ))
                            inserted_alert_ids.add(alert_id)
                            alerts_created += 1
                        except Exception:
                            pass

                    with db.session.no_autoflush:
                        profile = UserProfile.query.filter_by(user_id=e['user']).first()
                        if profile:
                            profile.total_alerts = (profile.total_alerts or 0) + 1
                            if risk_level in ['HIGH', 'CRITICAL']:
                                profile.high_risk_alerts = (profile.high_risk_alerts or 0) + 1
                            profile.current_risk_level = risk_level
                            profile.last_alert_date    = datetime.now()
                            profile.last_activity      = e['timestamp']

            # Commit and update progress
            if inserted % DB_COMMIT_EVERY < BATCH_SIZE or batch_start + BATCH_SIZE >= len(new_events):
                db.session.commit()

            progress.update(len(batch))
            progress.print(f"alerts={alerts_created}")

        progress.done()
        db.session.commit()

        alert_rate = alerts_created / inserted * 100 if inserted else 0

        print(f"\n{'='*55}")
        print(f"  ✅ Complete!")
        print(f"{'─'*55}")
        print(f"  Events inserted  : {inserted:>8,}")
        print(f"  Alerts generated : {alerts_created:>8,}  ({alert_rate:.1f}%)")
        print(f"  Skipped (dupes)  : {skipped:>8,}")
        print(f"  Errors           : {errors:>8,}")
        print(f"{'─'*55}")
        print(f"\n  Sample users to check in your dashboard:")
        for r in label_rows[:6]:
            print(f"    {r['user']}  scenario {r['scenario']}  "
                  f"{r['start'][:10]} → {r['end'][:10]}")
        if len(label_rows) > 6:
            print(f"    ... and {len(label_rows)-6} more")
        print(f"{'='*55}\n")


if __name__ == '__main__':
    main()
