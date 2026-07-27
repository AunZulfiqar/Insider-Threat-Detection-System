from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """Admin user model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class SystemSettings(db.Model):
    """System settings configured by admin"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=False)
    setting_type = db.Column(db.String(50))  # 'string', 'integer', 'float', 'json', 'boolean'
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<SystemSettings {self.setting_name}>'
    
    # ========================================
    # ADDED: get_setting and set_setting methods
    # ========================================
    
    @staticmethod
    def get_setting(key, default=None):
        """Get a setting value by key"""
        setting = SystemSettings.query.filter_by(setting_name=key).first()
        if not setting:
            return default
        
        # Parse based on type
        if setting.setting_type == 'boolean':
            return setting.setting_value.lower() == 'true'
        elif setting.setting_type == 'int' or setting.setting_type == 'integer':
            return int(setting.setting_value)
        elif setting.setting_type == 'float':
            return float(setting.setting_value)
        elif setting.setting_type == 'json':
            import json
            return json.loads(setting.setting_value)
        else:
            return setting.setting_value
    
    @staticmethod
    def set_setting(key, value, setting_type='string', description='', updated_by=None):
        """Set a setting value"""
        import json
        
        setting = SystemSettings.query.filter_by(setting_name=key).first()
        
        # Convert value to string based on type
        if setting_type == 'boolean':
            str_value = 'true' if value else 'false'
        elif setting_type == 'json':
            str_value = json.dumps(value)
        else:
            str_value = str(value)
        
        if setting:
            # Update existing
            setting.setting_value = str_value
            setting.setting_type = setting_type
            setting.description = description
            setting.updated_at = datetime.utcnow()
            if updated_by:
                setting.updated_by = updated_by
        else:
            # Create new
            setting = SystemSettings(
                setting_name=key,
                setting_value=str_value,
                setting_type=setting_type,
                description=description,
                updated_by=updated_by
            )
            db.session.add(setting)
        
        db.session.commit()
        return setting

class Alert(db.Model):
    """Alert model for detected threats"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.String(100), nullable=False, index=True)  # CERT user ID
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    risk_level = db.Column(db.String(20), nullable=False, index=True)  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    risk_score = db.Column(db.Float, nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    alert_type = db.Column(db.String(100))  # Type of anomaly detected
    description = db.Column(db.Text)
    event_details = db.Column(db.Text)  # JSON string of event details
    status = db.Column(db.String(20), default='OPEN', index=True)  # 'OPEN', 'INVESTIGATING', 'CLOSED', 'FALSE_POSITIVE'
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolution_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assigned_user = db.relationship('User', backref='assigned_alerts', foreign_keys=[assigned_to])
    
    def __repr__(self):
        return f'<Alert {self.alert_id} - {self.risk_level}>'

class Event(db.Model):
    """Event log model for storing processed events"""
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.String(100), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)  # 'LOGON', 'DEVICE', 'HTTP', 'FILE', 'EMAIL'
    event_source = db.Column(db.String(100))
    activity = db.Column(db.String(255))
    details = db.Column(db.Text)  # JSON string
    is_anomalous = db.Column(db.Boolean, default=False, index=True)
    anomaly_score = db.Column(db.Float)
    risk_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Event {self.event_id} - {self.event_type}>'

class UserProfile(db.Model):
    """User behavioral profile"""
    __tablename__ = 'user_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(200))
    department = db.Column(db.String(100))
    role = db.Column(db.String(100))
    supervisor = db.Column(db.String(100))
    
    # Behavioral baseline statistics
    avg_logon_time = db.Column(db.Time)
    avg_logoff_time = db.Column(db.Time)
    typical_work_days = db.Column(db.String(50))  # Comma-separated days
    avg_file_accesses_per_day = db.Column(db.Float)
    avg_http_requests_per_day = db.Column(db.Float)
    avg_email_count_per_day = db.Column(db.Float)
    usb_usage_frequency = db.Column(db.Float)
    
    # Risk indicators
    total_alerts = db.Column(db.Integer, default=0, index=True)
    high_risk_alerts = db.Column(db.Integer, default=0)
    current_risk_level = db.Column(db.String(20), default='LOW', index=True)
    last_alert_date = db.Column(db.DateTime)
    
    # Metadata
    baseline_start = db.Column(db.DateTime)
    baseline_end = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<UserProfile {self.user_id}>'

class ModelMetadata(db.Model):
    """Metadata for trained ML models"""
    __tablename__ = 'model_metadata'
    
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(100), nullable=False)
    model_version = db.Column(db.String(50), nullable=False)
    model_type = db.Column(db.String(50), nullable=False)  # 'ISOLATION_FOREST'
    model_path = db.Column(db.String(255), nullable=False)
    
    # Training metadata
    training_start = db.Column(db.DateTime)
    training_end = db.Column(db.DateTime)
    training_samples = db.Column(db.Integer)
    training_features = db.Column(db.Text)  # JSON string of feature names
    
    # Performance metrics
    contamination_rate = db.Column(db.Float)
    avg_anomaly_score = db.Column(db.Float)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ModelMetadata {self.model_name} v{self.model_version}>'

class AuditLog(db.Model):
    """Audit log for system actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50))
    entity_id = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')
    
    def __repr__(self):
        return f'<AuditLog {self.action} by User {self.user_id}>'
