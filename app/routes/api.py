"""
Fixed API - Uses Comprehensive Detection Engine
"""

from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from app.models.database import db, Event, Alert, UserProfile
from datetime import datetime
import json
import hashlib

bp = Blueprint('api', __name__)

# Global detection engine instance
_detection_engine = None


def require_api_key(f):
    """
    Requires the X-API-Key header to match AGENT_API_KEY (config/config.py).
    Protects endpoints that write data or disclose detection config from
    being reachable by anyone who can hit this Flask process on the network.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        expected = current_app.config.get('AGENT_API_KEY')
        provided = request.headers.get('X-API-Key')
        if not expected or provided != expected:
            return jsonify({'status': 'error', 'message': 'Unauthorized — missing or invalid X-API-Key header'}), 401
        return f(*args, **kwargs)
    return wrapper

def get_detection_engine():
    """Get or initialize the comprehensive detection engine"""
    global _detection_engine
    
    if _detection_engine is None:
        try:
            from app.utils.detection_engine import DetectionEngine
            from pathlib import Path
            
            model_path = Path('data/models')
            
            # Config for detection engine
            config = {
                'ISOLATION_FOREST_PARAMS': {
                    'n_estimators': 100,
                    'contamination': 0.1,
                    'random_state': 42,
                    'max_samples': 256
                },
                'SEVERITY_WEIGHTS': {
                    'HTTP': 1.0,
                    'FILE': 1.2,
                    'DEVICE': 1.5,
                    'EMAIL': 1.0,
                    'LOGON': 0.8,
                    'keyword_detected': 0.7,
                    'after_hours': 0.15,
                    'usb_external': 0.25,
                    'malicious_domain': 0.40,
                    'sensitive_file_access': 0.30,
                    'unusual_data_volume': 0.25
                }
            }
            
            _detection_engine = DetectionEngine(model_path, config)
            _detection_engine.load_model()
            print("✅ Detection Engine initialized successfully!")
            
        except Exception as e:
            print(f"❌ Failed to initialize detection engine: {e}")
            import traceback
            traceback.print_exc()
            _detection_engine = None
    
    return _detection_engine


@bp.route('/api/ingest', methods=['POST'])
@bp.route('/api/receive-log', methods=['POST'])
@require_api_key
def receive_log():
    """
    Receive and process events with comprehensive detection
    - Keyword detection (checks subjects, recipients, content)
    - ML anomaly detection
    - Contextual analysis (after-hours, external recipients, etc.)
    """
    try:
        event_data = request.get_json()
        
        if not event_data:
            return jsonify({'status': 'error', 'message': 'No data received'}), 400
        
        # Normalize field names
        if 'user' in event_data and 'user_id' not in event_data:
            event_data['user_id'] = event_data['user']
        if 'user_id' in event_data and 'user' not in event_data:
            event_data['user'] = event_data['user_id']
        
        print(f"\n{'='*70}")
        print(f"📥 RECEIVED EVENT:")
        print(f"   User: {event_data.get('user')}")
        print(f"   Type: {event_data.get('event_type')}")
        print(f"   Activity: {event_data.get('activity')}")
        
        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(event_data.get('timestamp'))
            print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            timestamp = datetime.now()
            print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')} (generated)")
        
        # Parse and display details
        try:
            details = json.loads(event_data.get('details', '{}'))
            if 'subject' in details:
                print(f"   Subject: {details['subject']}")
            if 'to' in details:
                print(f"   To: {details['to']}")
            if 'size' in details:
                print(f"   Size: {details['size']} bytes")
            if 'url' in details:
                print(f"   URL: {details['url'][:100]}")
        except:
            details = {}
        
        # === COMPREHENSIVE DETECTION ===
        print(f"\n🔍 RUNNING DETECTION:")
        
        engine = get_detection_engine()
        
        if engine is None:
            print("   ⚠️ Detection engine not available - saving event only")
            is_anomalous = False
            result = None
        else:
            # Process event through comprehensive detection engine
            result = engine.process_single_event(event_data)
            is_anomalous = result is not None
        
        # === PARSE DETECTION RESULT ===
        if result:
            risk_score = result.get('risk_score', 0.0)
            risk_level = result.get('risk_level', 'LOW')
            description = result.get('description', 'Anomalous behavior detected')
            keywords_found = result.get('keywords_found', [])
            detection_method = result.get('detection_method', 'unknown')
            anomaly_score = result.get('anomaly_score', 0.0)
            
            print(f"\n🚨 THREAT DETECTED!")
            print(f"   Risk Level: {risk_level}")
            print(f"   Risk Score: {risk_score:.3f}")
            print(f"   Detection Method: {detection_method}")
            if keywords_found:
                print(f"   Keywords Found: {keywords_found}")
            print(f"   Description: {description[:200]}...")
        else:
            risk_score = 0.0
            risk_level = 'NORMAL'
            description = 'Normal activity'
            keywords_found = []
            detection_method = 'none'
            anomaly_score = 0.0
            
            print(f"   ✅ Normal behavior - No threat detected")
        
        # === SAVE EVENT ===
        event_id = event_data.get('event_id')
        if not event_id:
            import uuid
            event_id = f"evt_{event_data.get('user')}_{int(timestamp.timestamp())}_{str(uuid.uuid4())[:8]}"
        
        event = Event(
            event_id=event_id,
            user_id=event_data.get('user'),
            timestamp=timestamp,
            event_type=event_data.get('event_type'),
            activity=event_data.get('activity'),
            details=event_data.get('details'),
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score if is_anomalous else None,
            risk_score=risk_score if is_anomalous else None
        )
        
        db.session.add(event)
        db.session.flush()
        print(f"\n💾 Event saved: {event_id}")
        
        # === CREATE ALERT IF THREAT DETECTED ===
        alert_id = None
        if is_anomalous:
            alert_id = hashlib.md5(
                f"{event_data.get('user')}{timestamp.isoformat()}{detection_method}".encode()
            ).hexdigest()[:16]
            
            alert = Alert(
                alert_id=alert_id,
                user_id=event_data.get('user'),
                timestamp=timestamp,
                alert_type=event_data.get('event_type'),
                risk_level=risk_level,
                risk_score=risk_score,
                anomaly_score=anomaly_score,
                description=description,
                event_details=event_data.get('details'),
                status='OPEN'
            )
            
            db.session.add(alert)
            print(f"🚨 Alert created: {alert_id}")
            print(f"   Level: {risk_level}")
            print(f"   Score: {risk_score:.3f}")
            
            # Update user profile
            user_profile = UserProfile.query.filter_by(user_id=event_data.get('user')).first()
            if user_profile:
                user_profile.total_alerts += 1
                if risk_level in ['HIGH', 'CRITICAL']:
                    user_profile.high_risk_alerts += 1
                user_profile.current_risk_level = risk_level
                user_profile.last_alert_date = datetime.now()
                user_profile.last_activity = timestamp
                print(f"   User profile updated: {event_data.get('user')}")
        
        # === COMMIT ===
        db.session.commit()
        print(f"✅ Transaction committed")
        print(f"{'='*70}\n")
        
        # === RETURN RESPONSE ===
        return jsonify({
            'status': 'success',
            'event_id': event_id,
            'alert_generated': is_anomalous,
            'alert_id': alert_id,
            'risk_level': risk_level if is_anomalous else None,
            'risk_score': risk_score if is_anomalous else 0.0,
            'description': description,
            'detection_method': detection_method,
            'keywords_found': keywords_found if is_anomalous else []
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"{'='*70}\n")
        
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp.route('/api/test', methods=['GET'])
def test_api():
    """Test endpoint to verify API is working"""
    from app.utils.detection_engine import load_settings
    
    settings = load_settings()
    
    return jsonify({
        'status': 'ok',
        'message': 'API is working',
        'detection_enabled': {
            'keywords': settings.get('keyword_detection_enabled', True),
            'ml': settings.get('ml_detection_enabled', True)
        },
        'keywords_count': len(settings.get('suspicious_keywords', [])),
        'endpoints': ['/api/ingest', '/api/receive-log']
    }), 200


@bp.route('/api/settings', methods=['GET'])
@require_api_key
def get_settings():
    """Get current detection settings"""
    from app.utils.detection_engine import load_settings
    
    settings = load_settings()
    
    return jsonify({
        'status': 'success',
        'settings': {
            'keyword_detection_enabled': settings.get('keyword_detection_enabled'),
            'ml_detection_enabled': settings.get('ml_detection_enabled'),
            'keywords_count': len(settings.get('suspicious_keywords', [])),
            'business_hours': {
                'start': settings.get('business_hours_start'),
                'end': settings.get('business_hours_end')
            },
            'weekend_days': settings.get('weekend_days'),
            'thresholds': {
                'critical': settings.get('critical_threshold'),
                'high': settings.get('high_threshold'),
                'medium': settings.get('medium_threshold'),
                'low': settings.get('low_threshold')
            }
        }
    }), 200