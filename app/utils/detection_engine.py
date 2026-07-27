"""
Detection Engine with Integrated Keyword and ML Detection
- Checks keywords FIRST (fast path for obvious threats)
- Falls back to ML for behavioral anomalies
- Comprehensive risk scoring with all contextual factors
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from pathlib import Path
import hashlib
import joblib
import pickle
import os

from app.models.database import db, Alert, Event, UserProfile
from app.models.ml_model import AnomalyDetector, KeywordDetector, RiskScorer

# ============================================================
# SETTINGS LOADER
# ============================================================

def load_settings():
    """Load settings from JSON file with CONSISTENT defaults"""
    settings_file = os.path.join('app', 'config', 'settings.json')
    
    # CONSISTENT DEFAULTS (matching dashboard.py and ml_model.py)
    default_settings = {
        "keyword_detection_enabled": True,
        "ml_detection_enabled": True,
        "suspicious_keywords": [
            "malware", "virus", "hack", "exploit", "backdoor",
            "trojan", "ransomware", "phishing", "password",
            "credentials", "confidential", "secret", "classified",
            "sensitive", "breach", "leak", "dump", "exfiltrate",
            "proprietary", "insider", "steal", "competitor"
        ],
        "critical_threshold": 0.9,
        "high_threshold": 0.7,
        "medium_threshold": 0.4,
        "low_threshold": 0.2,
        "business_hours_start": 8,
        "business_hours_end": 18,
        "weekend_days": [5, 6]
    }
    
    # Create default settings if file doesn't exist
    if not os.path.exists(settings_file):
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)
        with open(settings_file, 'w') as f:
            json.dump(default_settings, f, indent=4)
        return default_settings
    
    # Load existing settings
    try:
        with open(settings_file, 'r') as f:
            settings = json.load(f)
        
        # Merge with defaults to ensure all keys exist
        for key, value in default_settings.items():
            if key not in settings:
                settings[key] = value
        
        return settings
    except Exception as e:
        print(f"⚠️ Error loading settings: {e}")
        return default_settings


# ============================================================
# THREAT DESCRIPTION GENERATOR
# ============================================================

class ThreatDescriptionGenerator:
    """Generate professional security threat descriptions"""
    
    def __init__(self):
        self._reload_settings()
    
    def _reload_settings(self):
        """Reload settings from settings.json"""
        settings = load_settings()
        self.suspicious_keywords = settings.get('suspicious_keywords', [])
        self.business_hours_start = settings.get('business_hours_start', 8)
        self.business_hours_end = settings.get('business_hours_end', 18)
        self.weekend_days = settings.get('weekend_days', [5, 6])
    
    def reload_settings(self):
        """Public method to reload settings"""
        self._reload_settings()
        print("✅ ThreatDescriptionGenerator settings reloaded")
    
    def generate_description(self, event_data, risk_result):
        """
        Generate intelligent threat description based on event context
        
        Args:
            event_data: Dict with event information
            risk_result: Dict from RiskScorer.calculate_risk_score()
        
        Returns:
            Professional security description string
        """
        event_type = event_data.get('event_type', 'UNKNOWN')
        activity = event_data.get('activity', '')
        risk_level = risk_result['level']
        keywords_found = risk_result.get('keywords_found', [])
        
        try:
            timestamp = datetime.fromisoformat(event_data.get('timestamp'))
        except:
            timestamp = datetime.now()
        
        try:
            details = json.loads(event_data.get('details', '{}'))
        except:
            details = {}
        
        # Analyze timing
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        is_after_hours = hour < self.business_hours_start or hour >= self.business_hours_end
        is_weekend = day_of_week in self.weekend_days
        
        # Generate contextual description
        if event_type == 'EMAIL':
            return self._describe_email_threat(activity, details, keywords_found, 
                                              is_after_hours, is_weekend, risk_level)
        elif event_type == 'DEVICE':
            return self._describe_device_threat(activity, details, keywords_found,
                                               is_after_hours, is_weekend, risk_level)
        elif event_type == 'FILE':
            return self._describe_file_threat(activity, details, keywords_found,
                                             is_after_hours, is_weekend, risk_level)
        elif event_type == 'HTTP':
            return self._describe_http_threat(activity, details, keywords_found,
                                             is_after_hours, is_weekend, risk_level)
        elif event_type == 'LOGON':
            return self._describe_logon_threat(activity, details, is_after_hours, 
                                              is_weekend, risk_level)
        else:
            return self._describe_generic_threat(event_type, activity, risk_level)
    
    def _describe_email_threat(self, activity, details, keywords, after_hours, weekend, risk_level):
        """Generate description for email threats"""
        to = details.get('to', '')
        subject = details.get('subject', '')
        size = details.get('size', 0)
        
        # Check for external recipients
        is_external = any(indicator in to.lower() for indicator in 
                         ['external', 'competitor', 'gmail', 'yahoo', 'hotmail', 'outlook'])
        
        # Build description
        if keywords and is_external:
            if 'confidential' in keywords or 'secret' in keywords or 'classified' in keywords:
                if after_hours:
                    return f"CRITICAL DATA EXFILTRATION: Email with confidential content '{subject}' sent to external recipient ({to}) during after-hours"
                else:
                    return f"DATA LEAKAGE ATTEMPT: Email containing sensitive keywords sent to external address ({to})"
        
        if is_external and size > 5000000:  # 5MB
            size_mb = size / 1000000
            return f"POTENTIAL DATA EXFILTRATION: Large email ({size_mb:.1f}MB) with subject '{subject}' sent to external recipient ({to})"
        
        if keywords:
            return f"SENSITIVE EMAIL DETECTED: Email with subject '{subject}' contains suspicious keywords: {', '.join(keywords)}"
        
        if after_hours and is_external:
            return f"SUSPICIOUS EMAIL ACTIVITY: External communication to {to} during after-hours"
        
        return f"ANOMALOUS EMAIL BEHAVIOR: Email to {to} deviates from normal patterns"
    
    def _describe_device_threat(self, activity, details, keywords, after_hours, weekend, risk_level):
        """Generate description for device threats"""
        if 'connect' in activity.lower():
            if after_hours:
                return "POTENTIAL DATA EXFILTRATION: USB device connected during after-hours"
            elif weekend:
                return "SUSPICIOUS REMOVABLE MEDIA ACCESS: USB device connected during weekend"
            else:
                return "ANOMALOUS DEVICE ACTIVITY: Unusual USB device connection pattern"
        elif 'disconnect' in activity.lower():
            if after_hours:
                return "DATA THEFT INDICATOR: Removable media disconnected after after-hours usage"
            else:
                return "POTENTIAL DATA EXFILTRATION: Suspicious USB device disconnection"
        else:
            return "UNUSUAL DEVICE ACTIVITY: Uncommon removable media behavior"
    
    def _describe_file_threat(self, activity, details, keywords, after_hours, weekend, risk_level):
        """Generate description for file threats"""
        filename = details.get('filename', '')
        
        if 'copy' in activity.lower():
            if keywords:
                if after_hours:
                    return f"CRITICAL DATA EXFILTRATION: File '{filename}' with sensitive content copied during after-hours"
                else:
                    return f"DATA EXFILTRATION ATTEMPT: Unauthorized copying of sensitive file '{filename}'"
            elif after_hours:
                return f"SUSPICIOUS FILE ACTIVITY: File '{filename}' copied during after-hours"
            else:
                return f"POTENTIAL INSIDER THREAT: Unusual file copying behavior detected for '{filename}'"
        
        if keywords:
            return f"SENSITIVE FILE ACCESS: File '{filename}' contains suspicious keywords: {', '.join(keywords)}"
        
        if after_hours or weekend:
            return f"AFTER-HOURS FILE ACCESS: File '{filename}' accessed outside normal working hours"
        
        return f"ANOMALOUS FILE BEHAVIOR: File access pattern for '{filename}' deviates from baseline"
    
    def _describe_http_threat(self, activity, details, keywords, after_hours, weekend, risk_level):
        """Generate description for HTTP threats"""
        url = details.get('url', '')
        
        # Check for file sharing services
        file_sharing = ['dropbox', 'drive.google', 'mediafire', 'mega.nz', 'wetransfer', 'pastebin']
        is_file_sharing = any(service in url.lower() for service in file_sharing)
        
        if 'upload' in activity.lower() or 'POST' in activity.upper():
            if is_file_sharing:
                return f"DATA EXFILTRATION ATTEMPT: Files uploaded to external cloud storage service: {url}"
            elif keywords:
                return f"INFORMATION DISCLOSURE: Sensitive data transmitted to external website: {url}"
            elif after_hours:
                return f"SUSPICIOUS UPLOAD ACTIVITY: Data transmission to {url} during after-hours"
            else:
                return f"ANOMALOUS WEB ACTIVITY: Unusual data upload to {url}"
        
        if 'download' in activity.lower():
            if keywords:
                return f"MALWARE DOWNLOAD ATTEMPT: Suspicious file downloaded from {url}"
            elif is_file_sharing:
                return f"UNAUTHORIZED DOWNLOAD: File retrieved from external file-sharing service: {url}"
            else:
                return f"SUSPICIOUS DOWNLOAD: Uncommon file download from {url}"
        
        if is_file_sharing:
            return f"UNAUTHORIZED CLOUD STORAGE ACCESS: Connection to external file-sharing service: {url}"
        
        if keywords:
            return f"SECURITY POLICY VIOLATION: Access to website with suspicious keywords: {url}"
        
        if after_hours or weekend:
            return f"AFTER-HOURS WEB ACTIVITY: Unusual internet usage at {url} outside normal working hours"
        
        return f"ANOMALOUS WEB BEHAVIOR: Internet activity to {url} deviates from typical pattern"
    
    def _describe_logon_threat(self, activity, details, after_hours, weekend, risk_level):
        """Generate description for logon threats"""
        pc = details.get('pc', '')
        
        if after_hours:
            return f"SUSPICIOUS LOGON: User authentication on {pc} during after-hours"
        elif weekend:
            return f"WEEKEND ACCESS DETECTED: User logon on {pc} during non-business days"
        else:
            return f"UNUSUAL LOGON ACTIVITY: Authentication on {pc} from unexpected location or time"
    
    def _describe_generic_threat(self, event_type, activity, risk_level):
        """Generic threat description"""
        if risk_level == 'CRITICAL':
            return f"HIGH-RISK ANOMALY: {event_type} activity strongly deviates from normal behavior"
        else:
            return f"SUSPICIOUS ACTIVITY: Unusual {event_type} behavior detected"


# ============================================================
# FEATURE ENGINEERING
# ============================================================

class FeatureEngineer:
    """Extract features from events"""
    
    def __init__(self):
        self.feature_names = [
            'first_logon_hour', 'first_logon_minute', 'last_event_hour',
            'work_duration_hours', 'day_of_week', 'is_weekend',
            'logon_count', 'logoff_count', 'logon_event_count',
            'device_event_count', 'http_event_count', 'file_event_count',
            'email_event_count', 'total_event_count',
            'avg_time_between_events', 'std_time_between_events',
            'max_time_between_events', 'unique_pc_count',
            'http_request_count', 'unique_domains_count',
            'file_access_count', 'unique_files_count',
            'usb_connect_count', 'usb_disconnect_count',
            'email_sent_count', 'total_email_size', 'email_with_attachments'
        ]
    
    def extract_single_event_features(self, event_data):
        """Extract features from a single event"""
        try:
            timestamp = datetime.fromisoformat(event_data.get('timestamp'))
        except:
            timestamp = datetime.now()
        
        try:
            details = json.loads(event_data.get('details', '{}'))
        except:
            details = {}
        
        features = {
            'first_logon_hour': timestamp.hour,
            'first_logon_minute': timestamp.minute,
            'last_event_hour': timestamp.hour,
            'work_duration_hours': 1.0,
            'day_of_week': timestamp.weekday(),
            'is_weekend': 1 if timestamp.weekday() >= 5 else 0,
            'logon_count': 1 if event_data.get('event_type') == 'LOGON' else 0,
            'logoff_count': 0,
            'logon_event_count': 1 if event_data.get('event_type') == 'LOGON' else 0,
            'device_event_count': 1 if event_data.get('event_type') == 'DEVICE' else 0,
            'http_event_count': 1 if event_data.get('event_type') == 'HTTP' else 0,
            'file_event_count': 1 if event_data.get('event_type') == 'FILE' else 0,
            'email_event_count': 1 if event_data.get('event_type') == 'EMAIL' else 0,
            'total_event_count': 1,
            'avg_time_between_events': 0,
            'std_time_between_events': 0,
            'max_time_between_events': 0,
            'unique_pc_count': 1,
            'http_request_count': 1 if event_data.get('event_type') == 'HTTP' else 0,
            'unique_domains_count': 1 if event_data.get('event_type') == 'HTTP' else 0,
            'file_access_count': 1 if event_data.get('event_type') == 'FILE' else 0,
            'unique_files_count': 1 if event_data.get('event_type') == 'FILE' else 0,
            'usb_connect_count': 1 if event_data.get('event_type') == 'DEVICE' and 'connect' in event_data.get('activity', '').lower() else 0,
            'usb_disconnect_count': 1 if event_data.get('event_type') == 'DEVICE' and 'disconnect' in event_data.get('activity', '').lower() else 0,
            'email_sent_count': 1 if event_data.get('event_type') == 'EMAIL' else 0,
            'total_email_size': details.get('size', 0) if event_data.get('event_type') == 'EMAIL' else 0,
            'email_with_attachments': 1 if int(details.get('size', 0) or 0) > 0 and event_data.get('event_type') == 'EMAIL' else 0
        }
        
        feature_array = np.array([features[name] for name in self.feature_names]).reshape(1, -1)
        return feature_array, features


# ============================================================
# FEEDBACK LEARNING COMPONENTS
# ============================================================

class FeedbackIntegrator:
    """Integrates feedback learning models into detection"""
    
    def __init__(self, model_dir='app/ml/models'):
        self.model_dir = model_dir
        self.supervised_model = None
        self.supervised_features = []
        self.whitelist = []
        self.load_feedback_models()
    
    def load_feedback_models(self):
        """Load retrained models if available"""
        supervised_path = os.path.join(self.model_dir, 'supervised_classifier.pkl')
        if os.path.exists(supervised_path):
            try:
                with open(supervised_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.supervised_model = model_data['model']
                    self.supervised_features = model_data['feature_cols']
                print("✅ Loaded retrained supervised classifier")
            except Exception as e:
                print(f"⚠️ Failed to load supervised classifier: {e}")
        
        whitelist_path = os.path.join(self.model_dir, 'whitelist.json')
        if os.path.exists(whitelist_path):
            try:
                with open(whitelist_path, 'r') as f:
                    self.whitelist = json.load(f)
                print(f"✅ Loaded whitelist with {len(self.whitelist)} patterns")
            except Exception as e:
                print(f"⚠️ Failed to load whitelist: {e}")
    
    def is_whitelisted(self, event_data):
        """Check if event matches whitelist patterns"""
        for pattern in self.whitelist:
            if pattern.get('user_id') and pattern['user_id'] != event_data.get('user_id'):
                continue
            
            if pattern.get('event_type') and pattern['event_type'] != event_data.get('event_type'):
                continue
            
            if pattern.get('activity_pattern'):
                if pattern['activity_pattern'] in (event_data.get('activity', '')):
                    return True, pattern.get('reason', 'Whitelisted pattern')
        
        return False, None


# ============================================================
# MAIN DETECTION ENGINE
# ============================================================

class DetectionEngine:
    """
    Comprehensive threat detection engine
    - Keyword detection (fast path for obvious threats)
    - ML anomaly detection (behavioral analysis)
    - Integrated risk scoring with all contextual factors
    """
    
    def __init__(self, model_path, config):
        self.model_path = Path(model_path)
        self.config = config
        self.ml_detector = None
        self.risk_scorer = None
        self.feature_engineer = FeatureEngineer()
        self.feedback_integrator = FeedbackIntegrator()
        self.threat_describer = ThreatDescriptionGenerator()
        
    def load_model(self):
        """Load trained ML model"""
        print(f"Looking for models in: {self.model_path}")
        
        # Check for retrained model first
        retrained_iso = Path('app/ml/models/isolation_forest_retrained.pkl')
        if retrained_iso.exists():
            print("✅ Found retrained Isolation Forest!")
            try:
                retrained_scaler = Path('app/ml/models/isolation_forest_retrained_scaler.pkl')
                retrained_meta = Path('app/ml/models/isolation_forest_retrained_metadata.json')
                
                if retrained_scaler.exists() and retrained_meta.exists():
                    self.ml_detector = AnomalyDetector(self.config.get('ISOLATION_FOREST_PARAMS', {}))
                    self.ml_detector.load_model(str(retrained_iso), str(retrained_scaler), str(retrained_meta))
                    print("✅ Using retrained Isolation Forest")
                    
                    self._initialize_risk_scorer()
                    return
            except Exception as e:
                print(f"⚠️ Failed to load retrained model: {e}")
                print("Falling back to original model...")
        
        # Load original model - find the latest timestamped model files
        # FIX: previously hardcoded timestamp = '20260110_201926'. If a new
        # model was ever trained and saved without also creating the
        # 'isolation_forest_retrained*' files above, the app would silently
        # keep loading this old hardcoded version forever.
        candidates = sorted(self.model_path.glob('isolation_forest_*.pkl'))
        # exclude scaler files which also match isolation_forest_*.pkl
        candidates = [c for c in candidates if 'scaler' not in c.name]
        if not candidates:
            raise FileNotFoundError(f"No isolation_forest_*.pkl model found in {self.model_path}")

        model_file = candidates[-1]  # lexicographic sort works since timestamp format is sortable
        timestamp = model_file.stem.replace('isolation_forest_', '')
        scaler_file = self.model_path / f"isolation_forest_scaler_{timestamp}.pkl"
        metadata_file = self.model_path / f"isolation_forest_metadata_{timestamp}.json"
        
        # Check if all files exist
        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found: {model_file}")
        if not scaler_file.exists():
            raise FileNotFoundError(f"Scaler file not found: {scaler_file}")
        if not metadata_file.exists():
            raise FileNotFoundError(f"Metadata file not found: {metadata_file}")
        
        print(f"📦 Loading ML model: {model_file.name}")
        
        self.ml_detector = AnomalyDetector(self.config.get('ISOLATION_FOREST_PARAMS', {}))
        self.ml_detector.load_model(str(model_file), str(scaler_file), str(metadata_file))
        
        print(f"✅ Model loaded successfully!")
        print(f"   Features: {len(self.ml_detector.feature_names)}")
        
        self._initialize_risk_scorer()
    
    def _initialize_risk_scorer(self):
        """Initialize comprehensive risk scorer with all settings"""
        settings = load_settings()
        
        # Get keywords for keyword detector
        keywords = settings.get('suspicious_keywords', [])
        
        # Get thresholds
        thresholds = {
            'critical': settings.get('critical_threshold', 0.9),
            'high': settings.get('high_threshold', 0.7),
            'medium': settings.get('medium_threshold', 0.4),
            'low': settings.get('low_threshold', 0.2)
        }
        
        # Get severity weights
        severity_weights = self.config.get('SEVERITY_WEIGHTS', {
            'HTTP': 1.0,
            'FILE': 1.2,
            'DEVICE': 1.5,
            'EMAIL': 1.0,
            'LOGON': 0.8,
            'keyword_detected': 0.76,
            'after_hours': 0.20,
            'usb_external': 0.30,
            'malicious_domain': 0.40,
            'sensitive_file_access': 0.30,
            'unusual_data_volume': 0.25
        })
        
        # Initialize RiskScorer with keyword detector
        self.risk_scorer = RiskScorer(severity_weights, thresholds, keywords)
        
        print("✅ Detection engine initialized!")
        print(f"  Keyword detection: {'ENABLED' if keywords else 'DISABLED'}")
        print(f"  ML detection: ENABLED")
        print(f"  Risk thresholds:")
        print(f"    CRITICAL ≥ {thresholds['critical']}")
        print(f"    HIGH     ≥ {thresholds['high']}")
        print(f"    MEDIUM   ≥ {thresholds['medium']}")
        print(f"    LOW      ≥ {thresholds['low']}")
    
    def reload_settings(self):
        """Reload all settings from settings.json"""
        print("🔄 Reloading detection engine settings...")
        
        if self.risk_scorer:
            self.risk_scorer.reload_settings()
        
        if self.threat_describer:
            self.threat_describer.reload_settings()
        
        print("✅ All detection engine settings reloaded")
    
    def process_single_event(self, event_data):
        """
        Process a single event with comprehensive detection
        
        Detection flow:
        1. Check whitelist
        2. Check keywords (FAST PATH - immediate alert for obvious threats)
        3. Extract ML features
        4. Check ML model (for behavioral anomalies)
        5. Calculate comprehensive risk score
        6. Generate professional description
        """
        try:
            settings = load_settings()
            keyword_detection_enabled = settings.get('keyword_detection_enabled', True)
            ml_detection_enabled = settings.get('ml_detection_enabled', True)
            
            # STEP 1: Check whitelist
            is_whitelisted, whitelist_reason = self.feedback_integrator.is_whitelisted(event_data)
            if is_whitelisted:
                print(f"✅ Event whitelisted: {whitelist_reason}")
                return None
            
            # STEP 2: Parse event details for full analysis
            try:
                details = json.loads(event_data.get('details', '{}'))
            except:
                details = {}
            
            # Enrich event_data with parsed details for comprehensive analysis
            full_event_details = {
                'event_type': event_data.get('event_type'),
                'activity': event_data.get('activity'),
                'timestamp': event_data.get('timestamp'),
                'user_id': event_data.get('user_id'),
                **details  # Include all parsed details
            }
            
            # STEP 3: KEYWORD DETECTION (Fast path - check first)
            keyword_triggered = False
            if keyword_detection_enabled and self.risk_scorer.keyword_detector:
                # Use RiskScorer's comprehensive keyword detection
                risk_result = self.risk_scorer.calculate_risk_score(
                    anomaly_score=0,  # No ML score yet
                    event_details=full_event_details,
                    keyword_detection_enabled=True,
                    ml_detection_enabled=False  # Only check keywords
                )
                
                if risk_result['keywords_found']:
                    keyword_triggered = True
                    print(f"🔍 KEYWORD MATCH: {risk_result['keywords_found']} in fields {risk_result['fields_matched']}")
                    print(f"   Risk score: {risk_result['score']:.3f} | Level: {risk_result['level']}")
                    
                    # Generate description
                    description = self.threat_describer.generate_description(event_data, risk_result)
                    
                    return {
                        'is_anomalous': True,
                        'anomaly_score': 0.0,
                        'risk_score': float(risk_result['score']),
                        'risk_level': risk_result['level'],
                        'description': description,
                        'keywords_found': risk_result['keywords_found'],
                        'fields_matched': risk_result['fields_matched'],
                        'detection_method': risk_result['detection_method']
                    }
            
            
            # STEP 4: ML DETECTION (Behavioral analysis)
            if not ml_detection_enabled:
                print("⚠️ ML detection disabled, skipping")
                return None
            
            # Extract features for ML
            features, feature_dict = self.feature_engineer.extract_single_event_features(event_data)
            
            # Get ML prediction
            predictions, anomaly_scores = self.ml_detector.predict(features)
            anomaly_score = anomaly_scores[0]
            
            # ML anomaly threshold
            is_ml_anomalous = anomaly_score > 0.20  # Normalized score, higher = more anomalous
            
            print(f"🤖 ML Score: {anomaly_score:.3f} | Anomalous: {is_ml_anomalous}")
            
            # ========================================
            # MODIFIED: Always check contextual factors
            # ========================================
            # Always calculate risk score to check contextual boosts
            risk_result = self.risk_scorer.calculate_risk_score(
                anomaly_score=anomaly_score,
                event_details=full_event_details,
                keyword_detection_enabled=keyword_detection_enabled,
                ml_detection_enabled=ml_detection_enabled
            )
            
            # Check if any detection method triggered or risk meets threshold
            has_keywords = risk_result.get('keywords_found', [])
            contextual_boost = risk_result.get('contextual_boost', 0)
            final_risk = risk_result['score']
            
            # FIX: previously `(contextual_boost > 0 and final_risk >= 0.2)`
            # alone could trigger an alert. Since contextual boosts for a
            # single weekend/after-hours/device event commonly land between
            # 0.25 and 0.80, almost ANY off-hours event cleared the 0.2 LOW
            # threshold with zero real ML or keyword signal behind it. That
            # was the main cause of the ~55-63% alert rate on real data.
            #
            # Context should AMPLIFY a real signal (ML or keyword), not
            # manufacture one on its own. Require ML or keyword detection
            # to have actually fired; let contextual_boost only raise the
            # final severity/level of an alert that already has a reason
            # to exist.
            should_alert = is_ml_anomalous or keyword_triggered or bool(has_keywords)
            
            if should_alert:
                print(f"📊 Final Risk: {risk_result['score']:.3f} | Level: {risk_result['level']}")
                print(f"   Detection: {risk_result['detection_method']}")
                
                # STEP 6: Generate professional description
                description = self.threat_describer.generate_description(event_data, risk_result)
                
                print(f"🚨 ALERT: {description[:100]}...")
                
                return {
                    'is_anomalous': True,
                    'anomaly_score': float(anomaly_score),
                    'risk_score': float(risk_result['score']),
                    'risk_level': risk_result['level'],
                    'description': description,
                    'keywords_found': risk_result.get('keywords_found', []),
                    'fields_matched': risk_result.get('fields_matched', []),
                    'detection_method': risk_result['detection_method'],
                    'ml_score': risk_result.get('ml_score', 0),
                    'keyword_score': risk_result.get('keyword_score', 0),
                    'contextual_boost': risk_result.get('contextual_boost', 0)
                }
            else:
                print(f"✅ Normal behavior (ML: {anomaly_score:.3f}, Risk: {final_risk:.3f})")
                return None
            
        except Exception as e:
            print(f"❌ Error in detection: {str(e)}")
            import traceback
            traceback.print_exc()
            return None


# Global instance (set by app initialization)
detection_engine_instance = None