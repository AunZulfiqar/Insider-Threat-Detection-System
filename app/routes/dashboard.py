from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models.database import db, Alert, Event, UserProfile
from sqlalchemy import desc, func
from datetime import datetime, timedelta
import json
import os

# Feedback learning integration
try:
    from app.ml.feedback_learning import FeedbackLearner
    FEEDBACK_LEARNING_AVAILABLE = True
except ImportError:
    FEEDBACK_LEARNING_AVAILABLE = False
    print("⚠️ Feedback learning module not available")

bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@bp.route('/')
@login_required
def index():
    """Main dashboard view with statistics"""
    from app.models.database import Alert, UserProfile, Event
    from sqlalchemy import func, desc
    from datetime import datetime
    
    # Count total alerts
    total_alerts = Alert.query.count()
    
    # Count CRITICAL alerts specifically
    critical_alerts = Alert.query.filter_by(risk_level='CRITICAL').count()
    
    # Count HIGH risk alerts (excluding CRITICAL)
    high_risk_alerts = Alert.query.filter_by(risk_level='HIGH').count()
    
    # Count open alerts (all unresolved)
    open_alerts = Alert.query.filter(
        Alert.status.in_(['OPEN', 'INVESTIGATING', None])
    ).count()
    
    # Count total users
    total_users = UserProfile.query.count()
    
    # Get recent alerts (last 10)
    recent_alerts = Alert.query.order_by(desc(Alert.timestamp)).limit(10).all()
    
    # Get top risky users (by total_alerts)
    top_users = UserProfile.query.filter(
        UserProfile.total_alerts > 0
    ).order_by(desc(UserProfile.total_alerts)).limit(5).all()
    
    # Get recent events (last 10)
    recent_events = Event.query.order_by(desc(Event.timestamp)).limit(10).all()
    
    return render_template('dashboard.html',
                          now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                          total_alerts=total_alerts,
                          critical_alerts=critical_alerts,
                          high_risk_alerts=high_risk_alerts,
                          open_alerts=open_alerts,
                          total_users=total_users,
                          recent_alerts=recent_alerts,
                          top_users=top_users,
                          recent_events=recent_events)

@bp.route('/alerts')
@login_required
def alerts():
    """Alerts page"""
    status_filter = request.args.get('status', 'all')
    risk_filter = request.args.get('risk', 'all')
    
    query = Alert.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter.upper())
    
    if risk_filter != 'all':
        query = query.filter_by(risk_level=risk_filter.upper())
    
    alerts = query.order_by(desc(Alert.timestamp)).all()
    
    return render_template('alerts.html', alerts=alerts)


# ========================================
# ALERT DETAIL - USES HASH ALERT_ID (FORENSICS)
# ========================================

@bp.route('/alerts/<alert_id>')
@login_required
def alert_detail(alert_id):
    """
    Show detailed view of a single alert with related event
    Uses hash alert_id for forensics tracking (not integer database ID)
    """
    
    # Get the alert by hash alert_id (forensics ID)
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    
    # Find the related event by matching user_id and timestamp (within 1 second)
    related_event = Event.query.filter(
        Event.user_id == alert.user_id,
        Event.timestamp >= alert.timestamp - timedelta(seconds=1),
        Event.timestamp <= alert.timestamp + timedelta(seconds=1)
    ).first()
    
    # If no event found by timestamp, try to find by event_id in alert.event_details
    if not related_event and alert.event_details:
        try:
            details = json.loads(alert.event_details)
            event_id = details.get('event_id')
            
            if event_id:
                related_event = Event.query.filter_by(event_id=event_id).first()
        except:
            pass
    
    # Get user profile
    user_profile = UserProfile.query.filter_by(user_id=alert.user_id).first()
    
    return render_template('alert_detail.html',
                         alert=alert,
                         related_event=related_event,
                         user_profile=user_profile)


@bp.route('/alerts/<alert_id>/update', methods=['POST'])
@login_required
def update_alert(alert_id):
    """
    Update alert status and resolution notes
    Uses hash alert_id for forensics tracking
    """
    
    # Get alert by hash alert_id
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    
    # Update status
    new_status = request.form.get('status')
    if new_status in ['OPEN', 'INVESTIGATING', 'CLOSED', 'FALSE_POSITIVE']:
        alert.status = new_status
    
    # Update resolution notes
    notes = request.form.get('resolution_notes', '').strip()
    if notes:
        alert.resolution_notes = notes
    
    # Update timestamp
    alert.updated_at = datetime.now()
    
    # Commit changes
    db.session.commit()
    
    flash(f'Alert {alert.alert_id} updated successfully!', 'success')
    
    return redirect(url_for('dashboard.alert_detail', alert_id=alert_id))


@bp.route('/users')
@login_required
def users():
    """Users listing with search and filters"""
    from app.models.database import UserProfile
    from sqlalchemy import or_, func, desc
    
    # Get filter parameters
    search = request.args.get('search', '').strip()
    department = request.args.get('department', '').strip()
    role = request.args.get('role', '').strip()
    risk_level = request.args.get('risk_level', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Build query
    query = UserProfile.query
    
    # Apply search filter (user ID or name)
    if search:
        query = query.filter(
            or_(
                UserProfile.user_id.ilike(f'%{search}%'),
                UserProfile.full_name.ilike(f'%{search}%')
            )
        )
    
    # Apply department filter
    if department:
        query = query.filter(UserProfile.department.ilike(f'%{department}%'))
    
    # Apply role filter
    if role:
        query = query.filter(UserProfile.role.ilike(f'%{role}%'))
    
    # Apply risk level filter
    if risk_level:
        query = query.filter(UserProfile.current_risk_level == risk_level)
    
    # Order by total alerts (descending)
    query = query.order_by(desc(UserProfile.total_alerts))
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    
    # Calculate statistics
    total_users = UserProfile.query.count()
    critical_users = UserProfile.query.filter_by(current_risk_level='CRITICAL').count()
    high_risk_users = UserProfile.query.filter_by(current_risk_level='HIGH').count()
    medium_risk_users = UserProfile.query.filter_by(current_risk_level='MEDIUM').count()
    
    return render_template('users.html',
                          users=users,
                          pagination=pagination,
                          total_users=total_users,
                          critical_users=critical_users,
                          high_risk_users=high_risk_users,
                          medium_risk_users=medium_risk_users,
                          current_filters={
                              'search': search,
                              'department': department,
                              'role': role,
                              'risk_level': risk_level
                          })

@bp.route('/users/<user_id>')
@login_required
def user_detail(user_id):
    """User detail page with behavioral analysis"""
    from app.models.database import UserProfile, Alert, Event
    from app.utils.behavioral_analysis import get_behavioral_summary
    from sqlalchemy import desc

    # Get user
    user = UserProfile.query.filter_by(user_id=user_id).first()
    if not user:
        flash(f'User {user_id} not found', 'warning')
        return redirect(url_for('dashboard.users'))

    # Get recent alerts (last 10)
    recent_alerts = Alert.query.filter_by(user_id=user_id)\
        .order_by(desc(Alert.timestamp)).limit(10).all()

    # Get recent events (last 10)
    recent_events = Event.query.filter_by(user_id=user_id)\
        .order_by(desc(Event.timestamp)).limit(10).all()

    # Real behavioral analysis data (drives the charts on the page)
    behavioral = get_behavioral_summary(user_id)

    return render_template('user_detail.html',
                          user=user,
                          recent_alerts=recent_alerts,
                          recent_events=recent_events,
                          behavioral=behavioral)

@bp.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    """Event simulator page — lets you manually trigger a test event
    through the SAME detection pipeline used for real ingested events
    (app/routes/api.py:/api/ingest), so you can verify detection live
    without waiting for the background event simulator agent."""
    users = UserProfile.query.limit(20).all()

    if request.method == 'GET':
        return render_template('simulate.html', users=users)

    # --- POST: build a synthetic event and run it through real detection ---
    import uuid
    import hashlib
    from app.routes.api import get_detection_engine

    user_id = request.form.get('user_id')
    event_type = request.form.get('event_type', 'LOGON')

    if not user_id:
        flash('Please select a user.', 'danger')
        return redirect(url_for('dashboard.simulate'))

    timestamp = datetime.now()

    # Minimal, plausible details per event type so feature extraction
    # and keyword scanning have something real to work with.
    details_by_type = {
        'LOGON':  {'pc': 'PC-TEST-01', 'activity': 'Logon'},
        'DEVICE': {'pc': 'PC-TEST-01', 'activity': 'Connect', 'file_tree': 'D:\\'},
        'HTTP':   {'pc': 'PC-TEST-01', 'url': 'http://example-test-site.com/page', 'content': ''},
        'FILE':   {'pc': 'PC-TEST-01', 'filename': 'test_document.docx', 'content': ''},
        'EMAIL':  {'pc': 'PC-TEST-01', 'to': 'external@example.com', 'cc': '', 'bcc': '',
                   'size': '50000', 'attachments': '', 'content': ''},
    }
    activity_by_type = {
        'LOGON': 'Logon', 'DEVICE': 'Connect', 'HTTP': 'GET',
        'FILE': 'FILE_ACCESS', 'EMAIL': 'EMAIL_SENT'
    }

    details = details_by_type.get(event_type, {})
    event_id = f"evt_{user_id}_{int(timestamp.timestamp())}_{str(uuid.uuid4())[:8]}"

    event_data = {
        'event_id': event_id,
        'user': user_id,
        'user_id': user_id,
        'event_type': event_type,
        'activity': activity_by_type.get(event_type, event_type),
        'timestamp': timestamp.isoformat(),
        'details': json.dumps(details)
    }

    engine = get_detection_engine()
    result = engine.process_single_event(event_data) if engine else None
    is_anomalous = result is not None

    if result:
        risk_score = result.get('risk_score', 0.0)
        risk_level = result.get('risk_level', 'LOW')
        description = result.get('description', 'Anomalous behavior detected')
        anomaly_score = result.get('anomaly_score', 0.0)
    else:
        risk_score = 0.0
        risk_level = 'NORMAL'
        description = 'Normal activity'
        anomaly_score = 0.0

    event = Event(
        event_id=event_id,
        user_id=user_id,
        timestamp=timestamp,
        event_type=event_type,
        activity=event_data['activity'],
        details=event_data['details'],
        is_anomalous=is_anomalous,
        anomaly_score=anomaly_score if is_anomalous else None,
        risk_score=risk_score if is_anomalous else None
    )
    db.session.add(event)
    db.session.flush()

    if is_anomalous:
        alert_id = hashlib.md5(
            f"{user_id}{timestamp.isoformat()}simulate".encode()
        ).hexdigest()[:16]

        alert = Alert(
            alert_id=alert_id,
            user_id=user_id,
            timestamp=timestamp,
            alert_type=event_type,
            risk_level=risk_level,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            description=description,
            event_details=event_data['details'],
            status='OPEN'
        )
        db.session.add(alert)

        user_profile = UserProfile.query.filter_by(user_id=user_id).first()
        if user_profile:
            user_profile.total_alerts += 1
            if risk_level in ['HIGH', 'CRITICAL']:
                user_profile.high_risk_alerts += 1
            user_profile.current_risk_level = risk_level
            user_profile.last_alert_date = datetime.now()
            user_profile.last_activity = timestamp

        db.session.commit()
        flash(f'Event triggered — ALERT generated ({risk_level}, score {risk_score:.2f}).', 'warning')
    else:
        db.session.commit()
        flash('Event triggered — no alert generated (normal activity).', 'success')

    return redirect(url_for('dashboard.simulate'))

from flask import render_template, request
from flask_login import login_required
from app.models.database import Event, UserProfile
from sqlalchemy import desc

@bp.route('/events')
@login_required
def events():
    """Display all events with filtering"""
    
    # Get filter parameters
    event_type = request.args.get('event_type', '')
    user_id = request.args.get('user_id', '')
    is_anomalous = request.args.get('is_anomalous', '')
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Build query
    query = Event.query
    
    # Apply filters
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if is_anomalous == 'true':
        query = query.filter_by(is_anomalous=True)
    elif is_anomalous == 'false':
        query = query.filter_by(is_anomalous=False)
    
    # Order by most recent
    query = query.order_by(desc(Event.timestamp))
    
    # Paginate
    events_paginated = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get statistics
    total_events = Event.query.count()
    anomalous_events = Event.query.filter_by(is_anomalous=True).count()
    
    # Get event types for filter dropdown
    event_types = Event.query.with_entities(Event.event_type).distinct().all()
    event_types = [et[0] for et in event_types if et[0]]
    
    # Get top active users
    from sqlalchemy import func
    top_users = Event.query.with_entities(
        Event.user_id,
        func.count(Event.id).label('event_count')
    ).group_by(Event.user_id).order_by(desc('event_count')).limit(10).all()
    
    return render_template('events.html',
                          events=events_paginated.items,
                          pagination=events_paginated,
                          total_events=total_events,
                          anomalous_events=anomalous_events,
                          event_types=event_types,
                          top_users=top_users,
                          current_filters={
                              'event_type': event_type,
                              'user_id': user_id,
                              'is_anomalous': is_anomalous
                          })


@bp.route('/events/<event_id>')
@login_required
def event_detail(event_id):
    """Display detailed view of a specific event"""
    from app.models.database import Alert, UserProfile
    
    event = Event.query.filter_by(event_id=event_id).first_or_404()
    
    # Get user profile
    user = UserProfile.query.filter_by(user_id=event.user_id).first()
    
    # Get related alerts - Find by user_id and similar timestamp
    # Since Alert doesn't have event_id field, we find alerts around the same time
    related_alerts = []
    if event.timestamp:
        from datetime import timedelta
        
        # Find alerts from same user within 5 minutes of event
        time_start = event.timestamp - timedelta(minutes=5)
        time_end = event.timestamp + timedelta(minutes=5)
        
        related_alerts = Alert.query.filter(
            Alert.user_id == event.user_id,
            Alert.timestamp >= time_start,
            Alert.timestamp <= time_end
        ).all()
    
    return render_template('event_detail.html',
                          event=event,
                          user=user,
                          related_alerts=related_alerts)

# Helper functions for settings management
def load_settings():
    """Load settings from JSON file"""
    settings_file = os.path.join('app', 'config', 'settings.json')
    
    # Create default settings if file doesn't exist
    if not os.path.exists(settings_file):
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)
        default_settings = {
            "keyword_detection_enabled": True,
            "ml_detection_enabled": True,
            "suspicious_keywords": [
                "malware", "virus", "hack", "exploit", "backdoor",
                "trojan", "ransomware", "phishing", "password",
                "credentials", "confidential", "secret", "classified",
                "sensitive", "breach", "leak", "dump", "exfiltrate"
            ],
            "critical_threshold": 0.9,
            "high_threshold": 0.7,
            "medium_threshold": 0.4,
            "low_threshold": 0.2,
            "business_hours_start": 8,
            "business_hours_end": 18,
            "weekend_days": [5, 6]
        }
        save_settings(default_settings)
        return default_settings
    
    with open(settings_file, 'r') as f:
        return json.load(f)

def save_settings(settings):
    """Save settings to JSON file"""
    settings_file = os.path.join('app', 'config', 'settings.json')
    os.makedirs(os.path.dirname(settings_file), exist_ok=True)
    
    with open(settings_file, 'w') as f:
        json.dump(settings, f, indent=4)

def is_keyword_detection_enabled():
    """Quick check if keyword detection is enabled"""
    settings = load_settings()
    return settings.get('keyword_detection_enabled', True)

def get_suspicious_keywords():
    """Get list of suspicious keywords"""
    settings = load_settings()
    return settings.get('suspicious_keywords', [])


# Settings route - Updated to handle business hours and weekend days
@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """System settings page"""
    if request.method == 'POST':
        # Get form data
        keyword_detection = 'keyword_detection_enabled' in request.form
        ml_detection = 'ml_detection_enabled' in request.form
        
        # Get keywords from textarea (one per line)
        keywords_text = request.form.get('suspicious_keywords', '')
        keywords = [k.strip() for k in keywords_text.split('\n') if k.strip()]
        
        # Get thresholds
        critical = float(request.form.get('critical_threshold', 0.9))
        high = float(request.form.get('high_threshold', 0.7))
        medium = float(request.form.get('medium_threshold', 0.4))
        low = float(request.form.get('low_threshold', 0.2))
        
        # Get business hours
        business_hours_start = int(request.form.get('business_hours_start', 8))
        business_hours_end = int(request.form.get('business_hours_end', 18))
        
        # Get weekend days from checkboxes
        weekend_days = []
        if 'monday_weekend' in request.form:
            weekend_days.append(0)
        if 'tuesday_weekend' in request.form:
            weekend_days.append(1)
        if 'wednesday_weekend' in request.form:
            weekend_days.append(2)
        if 'thursday_weekend' in request.form:
            weekend_days.append(3)
        if 'friday_weekend' in request.form:
            weekend_days.append(4)
        if 'saturday_weekend' in request.form:
            weekend_days.append(5)
        if 'sunday_weekend' in request.form:
            weekend_days.append(6)
        
        # Default to Saturday-Sunday if nothing selected
        if not weekend_days:
            weekend_days = [5, 6]
            flash('No weekend days selected. Defaulting to Saturday-Sunday.', 'info')
        
        # Save settings
        new_settings = {
            'keyword_detection_enabled': keyword_detection,
            'ml_detection_enabled': ml_detection,
            'suspicious_keywords': keywords,
            'critical_threshold': critical,
            'high_threshold': high,
            'medium_threshold': medium,
            'low_threshold': low,
            'business_hours_start': business_hours_start,
            'business_hours_end': business_hours_end,
            'weekend_days': weekend_days
        }
        
        save_settings(new_settings)
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('dashboard.settings'))
    
    # GET request - load current settings
    current_settings = load_settings()
    
    # Add weekend day flags for template
    weekend_days_list = current_settings.get('weekend_days', [5, 6])
    current_settings['is_monday_weekend'] = 0 in weekend_days_list
    current_settings['is_tuesday_weekend'] = 1 in weekend_days_list
    current_settings['is_wednesday_weekend'] = 2 in weekend_days_list
    current_settings['is_thursday_weekend'] = 3 in weekend_days_list
    current_settings['is_friday_weekend'] = 4 in weekend_days_list
    current_settings['is_saturday_weekend'] = 5 in weekend_days_list
    current_settings['is_sunday_weekend'] = 6 in weekend_days_list
    
    # Add business hours with defaults
    if 'business_hours_start' not in current_settings:
        current_settings['business_hours_start'] = 8
    if 'business_hours_end' not in current_settings:
        current_settings['business_hours_end'] = 18
    
    # Add feedback statistics
    total_alerts = Alert.query.count()
    false_positives = Alert.query.filter_by(status='FALSE_POSITIVE').count()
    closed_threats = Alert.query.filter_by(status='CLOSED').count()
    
    return render_template('settings.html', 
                          settings=current_settings,
                          total_alerts=total_alerts,
                          false_positives=false_positives,
                          closed_threats=closed_threats,
                          feedback_learning_available=FEEDBACK_LEARNING_AVAILABLE)


# ========================================
# FEEDBACK LEARNING ROUTES
# ========================================

@bp.route('/admin/retrain', methods=['GET', 'POST'])
@login_required
def retrain_models():
    """Admin page to manually retrain models from feedback"""
    
    if not FEEDBACK_LEARNING_AVAILABLE:
        flash('❌ Feedback learning module not available. Please install it first.', 'danger')
        return redirect(url_for('dashboard.settings'))
    
    if request.method == 'POST':
        days_back = int(request.form.get('days_back', 30))
        
        try:
            learner = FeedbackLearner()
            success = learner.full_feedback_learning_cycle(days_back=days_back)
            
            if success:
                flash('✅ Models retrained successfully! Check console for details.', 'success')
            else:
                flash('⚠️ No feedback data available. Mark more alerts as TRUE/FALSE POSITIVE.', 'warning')
        except Exception as e:
            flash(f'❌ Error during retraining: {str(e)}', 'danger')
            import traceback
            print(traceback.format_exc())
        
        return redirect(url_for('dashboard.retrain_models'))
    
    # GET - Show retraining page with statistics
    total_alerts = Alert.query.count()
    false_positives = Alert.query.filter_by(status='FALSE_POSITIVE').count()
    closed_threats = Alert.query.filter_by(status='CLOSED').count()
    open_alerts = Alert.query.filter(
        Alert.status.in_(['OPEN', 'INVESTIGATING', None])
    ).count()
    
    return render_template('admin_retrain.html',
                         total_alerts=total_alerts,
                         false_positives=false_positives,
                         closed_threats=closed_threats,
                         open_alerts=open_alerts)