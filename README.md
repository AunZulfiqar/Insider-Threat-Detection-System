# Insider Threat Detection System

A machine-learning-driven User and Entity Behavior Analytics (UEBA) platform
that monitors employee activity (logons, web browsing, file access, USB
devices, email) and flags insider threats in real time — combining an
Isolation Forest anomaly detector, keyword-based fast-path detection, and
contextual risk scoring (after-hours, weekend, sensitive-file, external
recipient) into a single risk score per event.

Built as a final year project. Trained and evaluated against the **CERT r4.2
insider threat dataset** (Carnegie Mellon University Software Engineering
Institute CERT Division) — a public, synthetic dataset of corporate activity
logs with labeled malicious-insider scenarios. *(Link to your exact dataset
citation/DOI here.)*

## Features

- **Real-time detection pipeline** — every ingested event is checked against
  a suspicious-keyword list first (fast path), then scored by a trained
  Isolation Forest for behavioral anomalies, then adjusted for context
  (after-hours, weekend, USB/device use, sensitive filenames, external email
  recipients, unusual data volume).
- **Analyst dashboard** — alert triage queue, per-user risk profiles with
  baseline-vs-actual behavioral charts, full event history, and a live event
  simulator to test detection rules without waiting on real activity.
- **Feedback learning loop** — analysts mark alerts `FALSE_POSITIVE` or
  `CLOSED` (confirmed threat); a retraining job periodically uses that
  feedback to retrain a supervised classifier and adjust the anomaly
  detector.
- **Monitoring agents** — standalone Windows scripts (`run_agents.py`) that
  watch real browser history (Chrome/Edge), file access (Desktop/Documents/
  Downloads), USB device connects, and sent email (Outlook), and POST
  structured events to the detection API.
- **Role-based auth, CSRF protection, and API-key-gated ingest** — see
  [Security notes](#security-notes) below.

## Architecture

```
Monitoring agents (run_agents.py)
        │  POST /api/ingest  (X-API-Key header)
        ▼
Flask app (app/)
 ├─ routes/          — blueprints: auth, dashboard, api, admin, settings
 ├─ models/          — SQLAlchemy models (Event, Alert, UserProfile, User)
 │                      + ml_model.py (AnomalyDetector, KeywordDetector, RiskScorer)
 ├─ utils/           — detection_engine.py (orchestrates keyword+ML+context),
 │                      behavioral_analysis.py (baseline vs actual charts),
 │                      feature_engineering.py / data_preprocessing.py (offline training)
 ├─ ml/              — feedback_learning.py (retrain-from-analyst-feedback cycle)
 └─ templates/       — Bootstrap 5 + Chart.js dashboard UI
        │
        ▼
   SQLite (instance/insider_threat.db)
```

Detection settings (risk thresholds, business hours, suspicious keywords,
enable/disable keyword vs. ML detection) live in `app/config/settings.json`
and are edited from the **Settings** page in the dashboard — the same file
the detection engine reads at request time, so changes take effect
immediately without a restart.

## Tech stack

Flask 3 · Flask-SQLAlchemy · Flask-Login · Flask-WTF · SQLite · scikit-learn
(Isolation Forest + Random Forest) · pandas / numpy · APScheduler (weekly
auto-retraining) · Bootstrap 5 + Chart.js

## Getting started

```bash
git clone <this-repo-url>
cd insider_threat_system
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt

# Required for anything beyond local experimentation — see Security notes.
set SECRET_KEY=change-me
set AGENT_API_KEY=change-me

python init_database.py        # creates tables + loads user_profiles.csv
                                # (synthetic personas from the public CERT dataset)
                                # prints the randomly generated admin password — save it
python seed_demo_data.py        # synthetic events/alerts so the dashboard isn't empty

python run.py
# → http://localhost:5000, log in as admin with the password printed above
```

To monitor your **own** real activity instead of the seeded demo data, run
`python run_agents.py` in a separate terminal while `run.py` is running.
**Note:** this reads your actual browser history, filenames, and sent email —
it's meant for local experimentation, not for a shared/public machine, and
`instance/*.db` is gitignored for exactly this reason.

## Running tests

```bash
pytest
```

`tests/test_keyword_detector.py` and `tests/test_risk_scorer.py` cover the
core scoring logic directly (no Flask app needed). `tests/test_auth_and_security.py`
covers auth/CSRF/API-key behavior against a temporary in-memory-equivalent
test database.

## Security notes

- `SECRET_KEY` and `AGENT_API_KEY` ship with dev-only placeholder defaults —
  **set both via environment variables before deploying anywhere beyond
  localhost.**
- The default admin password is randomly generated on first run and printed
  once to the console (or set `ADMIN_PASSWORD` yourself before first run).
- `/api/ingest` and `/api/receive-log` require the `X-API-Key` header to
  match `AGENT_API_KEY` — this is what the agent scripts authenticate with.
- All dashboard forms are CSRF-protected (Flask-WTF).
- `instance/` (the real database) is gitignored — never commit it, since
  `run_agents.py` can populate it with real personal browsing/file/email
  data if you run it against your own machine.

## Known limitations / future work

- Detection settings load from `app/config/settings.json` via three separate
  loader functions (`detection_engine.py`, `ml_model.py`, `dashboard.py`) —
  works correctly today but should be consolidated into one shared module.
- No rate limiting or account lockout on the login form.
- The feedback-learning whitelist (auto-suppressing confirmed false
  positives) is scaffolded but not yet wired to real pattern matching.
- Dependency versions (Flask 3.0.0, Werkzeug 3.0.1, etc.) should be reviewed
  and bumped periodically.

## License

MIT — see [LICENSE](LICENSE).
