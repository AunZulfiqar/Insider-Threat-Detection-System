from flask import Flask
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from config.config import config
import os
import json

from app.models.database import db
from app.models.database import User

login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_name='default'):
    """Application factory"""
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    csrf.init_app(app)

    # ========================================
    # ADD CUSTOM JINJA2 FILTERS
    # ========================================
    @app.template_filter('from_json')
    def from_json_filter(value):
        """Parse JSON string to dict for template rendering"""
        try:
            return json.loads(value)
        except:
            return {}
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    with app.app_context():
        from app.routes import main, auth, dashboard, api, settings, admin
        
        app.register_blueprint(main.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(dashboard.bp)
        app.register_blueprint(api.bp)
        app.register_blueprint(settings.bp)
        app.register_blueprint(admin.bp)

        # api.bp is machine-to-machine (monitoring agents), authenticated via
        # the X-API-Key header instead of a browser session — CSRF tokens
        # don't apply to it, so it's exempted from CSRFProtect.
        csrf.exempt(api.bp)

        # Create database tables
        db.create_all()
        
        # Create default admin user if not exists
        create_default_admin()

    return app


def create_default_admin():
    """Create default admin user with a random password (printed once)."""
    from app.models.database import User
    import secrets

    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
        admin = User(
            username='admin',
            email='admin@insider-threat.local'
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print("=" * 70)
        print("✅ Default admin user created")
        print(f"   Username: admin")
        print(f"   Password: {admin_password}")
        print("   ⚠️  Save this now — it will not be shown again. Change it after login.")
        print("=" * 70)
