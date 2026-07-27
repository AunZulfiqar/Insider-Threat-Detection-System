from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models.database import db, User, AuditLog
from datetime import datetime

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log audit
            audit = AuditLog(
                user_id=user.id,
                action='LOGIN',
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    """Logout"""
    # Log audit
    audit = AuditLog(
        user_id=current_user.id,
        action='LOGOUT',
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.login'))

@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            
            # Log audit
            audit = AuditLog(
                user_id=current_user.id,
                action='PASSWORD_CHANGE',
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            db.session.commit()
            
            flash('Password changed successfully', 'success')
            return redirect(url_for('dashboard.index'))
    
    return render_template('change_password.html')
