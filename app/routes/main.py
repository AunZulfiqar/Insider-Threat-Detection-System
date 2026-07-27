from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Home page - redirect to login"""
    return redirect(url_for('auth.login'))

@bp.route('/about')
def about():
    return render_template('about.html')

@bp.route('/user/<user_id>')
@login_required
def user_details(user_id):
    from app.models.database import UserProfile, Alert, Event

    user = UserProfile.query.filter_by(user_id=user_id).first_or_404()

    recent_alerts = (
        Alert.query.filter_by(user_id=user_id)
        .order_by(Alert.timestamp.desc())
        .limit(20)
        .all()
    )

    recent_events = (
        Event.query.filter_by(user_id=user_id)
        .order_by(Event.timestamp.desc())
        .limit(50)
        .all()
    )

    return render_template(
        'user_details.html',
        user=user,
        recent_alerts=recent_alerts,
        recent_events=recent_events
    )
