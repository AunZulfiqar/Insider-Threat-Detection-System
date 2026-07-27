"""
Shared pytest fixtures.

Run from the project root:
    pip install -r requirements.txt
    pytest

Tests must run with the project root as the working directory — the app
itself assumes this everywhere (e.g. 'data/models', 'app/config/settings.json'),
so this isn't a new constraint, just matching existing convention.
"""
import os
import tempfile

import pytest

TEST_ADMIN_PASSWORD = "test-admin-password-123"


@pytest.fixture
def app():
    # Known admin password + an isolated on-disk sqlite file for this test run,
    # set before create_app() so its internal db.create_all()/admin-creation
    # step uses them (TestingConfig hardcodes its own DB URI, so we point it
    # at a throwaway temp file instead of the real project database).
    os.environ["ADMIN_PASSWORD"] = TEST_ADMIN_PASSWORD

    from config.config import TestingConfig
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    TestingConfig.SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    from app import create_app, db as _db

    flask_app = create_app("testing")
    flask_app.config.update(
        WTF_CSRF_ENABLED=False,   # test client posts plain form data, no token dance
        SERVER_NAME="localhost",
    )

    yield flask_app

    with flask_app.app_context():
        _db.session.remove()
        _db.drop_all()
    os.remove(db_path)
    del os.environ["ADMIN_PASSWORD"]


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(client):
    """A test client with an authenticated session as the default admin user."""
    client.post(
        "/auth/login",
        data={"username": "admin", "password": TEST_ADMIN_PASSWORD},
        follow_redirects=True,
    )
    return client
