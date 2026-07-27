import os
from datetime import timedelta

class Config:
    """Main configuration class for the Insider Threat Detection System"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Shared secret the monitoring agents (run_agents.py) must send in the
    # X-API-Key header to POST to /api/ingest and /api/receive-log, and to
    # read /api/settings. Override via env var for anything beyond local use.
    AGENT_API_KEY = os.environ.get('AGENT_API_KEY') or 'dev-agent-key-change-in-production'

    # Session/cookie hardening (mitigates session hijacking and some CSRF vectors)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///insider_threat.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Upload Configuration
    UPLOAD_FOLDER = 'data/raw'
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    ALLOWED_EXTENSIONS = {'csv', 'log', 'txt'}
    
    # Model Configuration
    MODEL_PATH = 'data/models'
    BASELINE_WEEKS = 2  # Number of weeks for baseline training
    
    # Detection Configuration
    CHECK_INTERVAL = 300  # 5 minutes in seconds
    ALERT_RETENTION_DAYS = 90
    
    # ========================================
    # KEYWORD DETECTION CONFIGURATION
    # ========================================
    KEYWORD_DETECTION_ENABLED = True  # Can be toggled via settings
    ML_DETECTION_ENABLED = True  # Can be toggled via settings
    
    # ========================================
    # HIGH-CONFIDENCE KEYWORDS (Reduced False Positives)
    # ========================================
    # These keywords are highly specific to malicious activity
    # Common words like 'password', 'vpn', 'confidential' are removed
    # to prevent false positives on normal business activities
    DEFAULT_SUSPICIOUS_KEYWORDS = [
        # Malware types (high confidence)
        'malware', 'virus', 'trojan', 'ransomware', 'rootkit',
        'keylogger', 'spyware', 'botnet',
        
        # Attack techniques (high confidence)
        'exploit', 'backdoor', 'phishing', 'bypass', 'escalation',
        'exfiltrate', 'exfiltration',
        
        # Vulnerabilities
        'vulnerability', 'zero-day', 'zeroday',
        
        # Hacking activities
        'hack', 'hacking', 'hacked', 'cracking',
        
        # Security incidents
        'breach', 'ddos',
        
        # Suspicious networks
        'tor', 'darkweb', 'dark-web',
        
        # High-level classifications (rare in normal use)
        'classified'
    ]
    
    # Keyword detection weight (how much to boost risk score when keyword found)
    KEYWORD_DETECTION_WEIGHT = 0.7  # 70% risk score when keyword detected
    
    # ========================================
    # Risk Thresholds (4 levels: CRITICAL, HIGH, MEDIUM, LOW)
    # ========================================
    CRITICAL_THRESHOLD = 0.8  # Score >= 0.8 = CRITICAL
    HIGH_THRESHOLD = 0.6      # Score >= 0.6 = HIGH
    MEDIUM_THRESHOLD = 0.4    # Score >= 0.4 = MEDIUM
    LOW_THRESHOLD = 0.2       # Score >= 0.2 = LOW
    # Score < 0.2 = NORMAL (no alert)
    
    # Feature Configuration
    FEATURE_CONFIG = {
        'temporal_features': True,
        'behavioral_features': True,
        'network_features': True,
        'file_access_features': True,
        'usb_features': True
    }
    
    # Admin Default Settings
    DEFAULT_WORK_HOURS = {
        'start': '08:00',
        'end': '18:00'
    }
    
    DEFAULT_WORK_DAYS = [0, 1, 2, 3, 4]  # Monday to Friday (0=Monday)
    
    # Severity Weights for Risk Scoring
    SEVERITY_WEIGHTS = {
        'keyword_detected': 0.70,      # Keyword detection
        'time_deviation': 0.20,
        'sensitive_file_access': 0.30,
        'usb_external': 0.25,
        'malicious_domain': 0.40,
        'after_hours': 0.15,
        'unusual_data_volume': 0.25
    }
    
    # Isolation Forest Parameters
    ISOLATION_FOREST_PARAMS = {
        'n_estimators': 100,
        'contamination': 0.1,
        'random_state': 42,
        'max_samples': 256
    }
    
    # Session Configuration
    SESSION_WINDOW_MINUTES = 60  # Rolling 1-hour sessions
    REAL_TIME_BATCH_SIZE = 100  # Events to process in each batch
    
    # Logging Configuration
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = 'logs/application.log'
    
    # Dashboard Configuration
    RECENT_EVENTS_LIMIT = 50
    CHART_DATA_POINTS = 100
    
    # CERT Dataset Configuration
    CERT_LDAP_FILE = 'ldap.csv'
    CERT_LOGON_FILE = 'logon.csv'
    CERT_DEVICE_FILE = 'device.csv'
    CERT_HTTP_FILE = 'http.csv'
    CERT_FILE_FILE = 'file.csv'
    CERT_EMAIL_FILE = 'email.csv'
    
    # Known Malicious Users (from CERT r4.2 - to exclude from baseline)
    CERT_MALICIOUS_USERS = [
        'ACM2278', 'CMP2946', 'MBG3183', 'PLJ1771'
    ]

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    # Only send cookies over HTTPS — requires the app to actually be served over TLS
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    
class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_insider_threat.db'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
