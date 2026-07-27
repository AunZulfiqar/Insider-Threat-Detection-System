"""
Regression tests for the security/consolidation fixes made in this session:
  - @login_required on /admin/retrain and /settings/ (previously open)
  - /settings/ and /admin/retrain now redirect to the real, wired-up routes
    instead of rendering their own dead/broken duplicate logic
  - X-API-Key required on /api/ingest
  - /auth/change-password renders (its template used to be missing -> 500)
"""
import json


def test_admin_retrain_requires_login(client):
    resp = client.get("/admin/retrain")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_settings_requires_login(client):
    resp = client.get("/settings/")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_settings_redirects_to_dashboard_settings_when_logged_in(logged_in_client):
    resp = logged_in_client.get("/settings/")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard/settings")


def test_admin_retrain_redirects_to_dashboard_retrain_when_logged_in(logged_in_client):
    resp = logged_in_client.get("/admin/retrain")
    assert resp.status_code == 302
    assert "/dashboard/admin/retrain" in resp.headers["Location"]


def test_change_password_page_renders(logged_in_client):
    """Regression test: this route used to render a template that didn't exist."""
    resp = logged_in_client.get("/auth/change-password")
    assert resp.status_code == 200
    assert b"Change Password" in resp.data


def test_login_wrong_password_stays_on_login_page(client):
    resp = client.post(
        "/auth/login",
        data={"username": "admin", "password": "definitely-wrong"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_api_ingest_rejects_missing_api_key(client):
    resp = client.post(
        "/api/ingest",
        json={
            "user_id": "TESTUSER",
            "event_type": "LOGON",
            "activity": "Logon",
            "timestamp": "2024-01-01T09:00:00",
            "details": json.dumps({"pc": "PC-TEST"}),
        },
    )
    assert resp.status_code == 401


def test_api_ingest_accepts_correct_api_key(client, app):
    resp = client.post(
        "/api/ingest",
        json={
            "user_id": "TESTUSER",
            "event_type": "LOGON",
            "activity": "Logon",
            "timestamp": "2024-01-01T09:00:00",
            "details": json.dumps({"pc": "PC-TEST"}),
        },
        headers={"X-API-Key": app.config["AGENT_API_KEY"]},
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "success"
