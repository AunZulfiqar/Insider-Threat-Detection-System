"""
Behavioral Analysis Helper Functions - Normal vs Suspicious Behavior
Calculates patterns for normal events vs suspicious/alert-triggering events
Place in: app/utils/behavioral_analysis.py

FIXED: Works without Alert.event_id field
"""

from datetime import datetime, timedelta
from collections import defaultdict
from app.models.database import Event, UserProfile, Alert, db
from sqlalchemy import func


def calculate_activity_by_type(user_id, days=7, suspicious_only=False):
    """
    Calculate activity metrics for normal or suspicious events
    
    Args:
        user_id: User ID
        days: Number of days to analyze
        suspicious_only: If True, only count events around alert times
        
    Returns:
        dict: Activity counts by event type
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    if suspicious_only:
        # Get alert timestamps (events that caused alerts)
        alerts = Alert.query.filter(
            Alert.user_id == user_id,
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).all()
        
        # Get events within ±2 minutes of each alert
        suspicious_events = []
        for alert in alerts:
            related_events = Event.query.filter(
                Event.user_id == user_id,
                Event.timestamp >= alert.timestamp - timedelta(minutes=2),
                Event.timestamp <= alert.timestamp + timedelta(minutes=2)
            ).all()
            suspicious_events.extend(related_events)
        
        # Remove duplicates
        events = list({e.id: e for e in suspicious_events}.values())
    else:
        # Get all events
        events = Event.query.filter(
            Event.user_id == user_id,
            Event.timestamp >= start_date,
            Event.timestamp <= end_date
        ).all()
    
    if days == 0:
        days = 1
    
    # Count by event type
    http_count = sum(1 for e in events if e.event_type == 'HTTP')
    file_count = sum(1 for e in events if e.event_type == 'FILE')
    email_count = sum(1 for e in events if e.event_type == 'EMAIL')
    device_count = sum(1 for e in events if e.event_type == 'DEVICE')
    
    return {
        'http_per_day': round(http_count / days, 2),
        'file_per_day': round(file_count / days, 2),
        'email_per_day': round(email_count / days, 2),
        'usb_per_day': round(device_count / days, 2),
        'total_events': len(events)
    }


def calculate_hourly_patterns_by_behavior(user_id, days=30, suspicious_only=False):
    """
    Calculate hourly patterns for normal or suspicious behavior
    
    Args:
        user_id: User ID
        days: Number of days to analyze
        suspicious_only: If True, only events around alert times
        
    Returns:
        list: [count_hour_0, count_hour_1, ..., count_hour_23]
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    if suspicious_only:
        # Get alert timestamps
        alerts = Alert.query.filter(
            Alert.user_id == user_id,
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).all()
        
        # Get events around alert times
        suspicious_events = []
        for alert in alerts:
            related_events = Event.query.filter(
                Event.user_id == user_id,
                Event.timestamp >= alert.timestamp - timedelta(minutes=2),
                Event.timestamp <= alert.timestamp + timedelta(minutes=2)
            ).all()
            suspicious_events.extend(related_events)
        
        # Remove duplicates
        events = list({e.id: e for e in suspicious_events}.values())
    else:
        # Get all normal events
        events = Event.query.filter(
            Event.user_id == user_id,
            Event.timestamp >= start_date,
            Event.timestamp <= end_date
        ).all()
    
    # Count events by hour
    hourly_counts = [0] * 24
    for event in events:
        hour = event.timestamp.hour
        hourly_counts[hour] += 1
    
    # Convert to average per day
    total_days = days if days > 0 else 1
    hourly_avg = [round(count / total_days, 2) for count in hourly_counts]
    
    return hourly_avg


def calculate_alert_distribution(user_id, weeks=12):
    """
    Calculate alert distribution over time (by week)
    
    Args:
        user_id: User ID
        weeks: Number of weeks (default: 12 weeks = ~3 months)
        
    Returns:
        dict: Weekly alert counts by risk level
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(weeks=weeks)
    
    # Get all alerts in period
    alerts = Alert.query.filter(
        Alert.user_id == user_id,
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).all()
    
    # Group by week and risk level
    weekly_alerts = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})
    
    for alert in alerts:
        # Get the Monday of the week this alert occurred
        alert_date = alert.timestamp.date()
        week_start = alert_date - timedelta(days=alert_date.weekday())
        week_str = week_start.strftime('%Y-%m-%d')
        
        risk_level = alert.risk_level or 'LOW'
        if risk_level in weekly_alerts[week_str]:
            weekly_alerts[week_str][risk_level] += 1
        weekly_alerts[week_str]['total'] += 1
    
    # Create sorted lists for each week
    dates = []
    critical_counts = []
    high_counts = []
    medium_counts = []
    low_counts = []
    total_counts = []
    
    # Generate week labels
    current_week_start = (start_date.date() - timedelta(days=start_date.date().weekday()))
    
    for i in range(weeks):
        week_str = current_week_start.strftime('%Y-%m-%d')
        week_label = f"Week of {current_week_start.strftime('%b %d')}"
        dates.append(week_label)
        
        data = weekly_alerts.get(week_str, {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})
        critical_counts.append(data['CRITICAL'])
        high_counts.append(data['HIGH'])
        medium_counts.append(data['MEDIUM'])
        low_counts.append(data['LOW'])
        total_counts.append(data['total'])
        
        current_week_start += timedelta(weeks=1)
    
    return {
        'dates': dates,
        'critical_counts': critical_counts,
        'high_counts': high_counts,
        'medium_counts': medium_counts,
        'low_counts': low_counts,
        'total_counts': total_counts
    }


def calculate_current_week_daily_alerts(user_id):
    """
    Calculate alert distribution for current week (Monday-Sunday) by day
    
    Args:
        user_id: User ID
        
    Returns:
        dict: Daily alert counts for current week
    """
    today = datetime.now()
    # Get Monday of current week
    week_start = today - timedelta(days=today.weekday())
    week_start = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Get Sunday of current week
    week_end = week_start + timedelta(days=7)
    
    # Get all alerts in current week
    alerts = Alert.query.filter(
        Alert.user_id == user_id,
        Alert.timestamp >= week_start,
        Alert.timestamp < week_end
    ).all()
    
    # Group by day and risk level
    daily_alerts = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})
    
    for alert in alerts:
        day_name = alert.timestamp.strftime('%A')  # Monday, Tuesday, etc.
        risk_level = alert.risk_level or 'LOW'
        if risk_level in daily_alerts[day_name]:
            daily_alerts[day_name][risk_level] += 1
        daily_alerts[day_name]['total'] += 1
    
    # Create ordered lists (Monday to Sunday)
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    critical_counts = []
    high_counts = []
    medium_counts = []
    low_counts = []
    total_counts = []
    
    for day in days:
        data = daily_alerts.get(day, {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})
        critical_counts.append(data['CRITICAL'])
        high_counts.append(data['HIGH'])
        medium_counts.append(data['MEDIUM'])
        low_counts.append(data['LOW'])
        total_counts.append(data['total'])
    
    return {
        'days': days,
        'critical_counts': critical_counts,
        'high_counts': high_counts,
        'medium_counts': medium_counts,
        'low_counts': low_counts,
        'total_counts': total_counts,
        'week_start': week_start.strftime('%Y-%m-%d'),
        'week_end': (week_end - timedelta(days=1)).strftime('%Y-%m-%d')
    }


def calculate_hourly_alert_distribution(user_id, days=7):
    """
    Calculate hourly alert distribution (24-hour view)
    
    Args:
        user_id: User ID
        days: Number of days to analyze (default: 7)
        
    Returns:
        dict: Hourly alert counts
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Get all alerts in period
    alerts = Alert.query.filter(
        Alert.user_id == user_id,
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).all()
    
    # Group by hour and risk level
    hourly_alerts = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})
    
    for alert in alerts:
        hour = alert.timestamp.hour
        risk_level = alert.risk_level or 'LOW'
        if risk_level in hourly_alerts[hour]:
            hourly_alerts[hour][risk_level] += 1
        hourly_alerts[hour]['total'] += 1
    
    # Create lists for all 24 hours
    hours = [f"{h:02d}:00" for h in range(24)]
    critical_counts = []
    high_counts = []
    medium_counts = []
    low_counts = []
    total_counts = []
    
    for h in range(24):
        data = hourly_alerts.get(h, {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0})
        critical_counts.append(data['CRITICAL'])
        high_counts.append(data['HIGH'])
        medium_counts.append(data['MEDIUM'])
        low_counts.append(data['LOW'])
        total_counts.append(data['total'])
    
    return {
        'hours': hours,
        'critical_counts': critical_counts,
        'high_counts': high_counts,
        'medium_counts': medium_counts,
        'low_counts': low_counts,
        'total_counts': total_counts
    }


def calculate_behavior_comparison(user_id, days=30):
    """
    Compare normal vs suspicious behavior patterns
    
    Returns:
        dict: Comparison metrics
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    # Get all events
    all_events = Event.query.filter(
        Event.user_id == user_id,
        Event.timestamp >= start_date,
        Event.timestamp <= end_date
    ).all()
    
    # Get alert timestamps to identify suspicious periods
    alerts = Alert.query.filter(
        Alert.user_id == user_id,
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).all()
    
    # Create set of suspicious time windows (±2 minutes from alerts)
    suspicious_periods = set()
    for alert in alerts:
        # Round to minute
        alert_minute = alert.timestamp.replace(second=0, microsecond=0)
        for offset in range(-2, 3):  # -2 to +2 minutes
            suspicious_periods.add(alert_minute + timedelta(minutes=offset))
    
    # Separate normal vs suspicious events
    normal_events = []
    suspicious_events = []
    
    for event in all_events:
        event_minute = event.timestamp.replace(second=0, microsecond=0)
        if event_minute in suspicious_periods:
            suspicious_events.append(event)
        else:
            normal_events.append(event)
    
    # Count after-hours activity
    normal_after_hours = sum(1 for e in normal_events if e.timestamp.hour < 8 or e.timestamp.hour >= 18)
    suspicious_after_hours = sum(1 for e in suspicious_events if e.timestamp.hour < 8 or e.timestamp.hour >= 18)
    
    # Count weekend activity
    normal_weekend = sum(1 for e in normal_events if e.timestamp.weekday() >= 5)
    suspicious_weekend = sum(1 for e in suspicious_events if e.timestamp.weekday() >= 5)
    
    return {
        'total_events': len(all_events),
        'normal_events': len(normal_events),
        'suspicious_events': len(suspicious_events),
        'normal_after_hours': normal_after_hours,
        'suspicious_after_hours': suspicious_after_hours,
        'normal_weekend': normal_weekend,
        'suspicious_weekend': suspicious_weekend,
        'suspicion_rate': round(len(suspicious_events) / len(all_events) * 100, 2) if all_events else 0
    }


def calculate_daily_pattern_7days(user_id, suspicious_only=False):
    """
    Calculate pattern for last 7 days (one data point per day)
    
    Returns:
        list: [count_day1, count_day2, ..., count_day7] and labels
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    # Get events or suspicious events
    if suspicious_only:
        alerts = Alert.query.filter(
            Alert.user_id == user_id,
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).all()
        
        events = []
        for alert in alerts:
            related = Event.query.filter(
                Event.user_id == user_id,
                Event.timestamp >= alert.timestamp - timedelta(minutes=2),
                Event.timestamp <= alert.timestamp + timedelta(minutes=2)
            ).all()
            events.extend(related)
        events = list({e.id: e for e in events}.values())
    else:
        events = Event.query.filter(
            Event.user_id == user_id,
            Event.timestamp >= start_date,
            Event.timestamp <= end_date
        ).all()
    
    # Count by day
    daily_counts = defaultdict(int)
    for event in events:
        day_str = event.timestamp.strftime('%Y-%m-%d')
        daily_counts[day_str] += 1
    
    # Create lists for last 7 days
    labels = []
    counts = []
    current = start_date.date()
    
    for i in range(7):
        day_str = current.strftime('%Y-%m-%d')
        day_label = current.strftime('%a')  # Mon, Tue, etc.
        labels.append(day_label)
        counts.append(daily_counts.get(day_str, 0))
        current += timedelta(days=1)
    
    return {'labels': labels, 'counts': counts}


def calculate_weekly_pattern_4weeks(user_id, suspicious_only=False):
    """
    Calculate pattern for last 4 weeks (one data point per week)
    
    Returns:
        dict: labels and counts for 4 weeks
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(weeks=4)
    
    # Get events or suspicious events
    if suspicious_only:
        alerts = Alert.query.filter(
            Alert.user_id == user_id,
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).all()
        
        events = []
        for alert in alerts:
            related = Event.query.filter(
                Event.user_id == user_id,
                Event.timestamp >= alert.timestamp - timedelta(minutes=2),
                Event.timestamp <= alert.timestamp + timedelta(minutes=2)
            ).all()
            events.extend(related)
        events = list({e.id: e for e in events}.values())
    else:
        events = Event.query.filter(
            Event.user_id == user_id,
            Event.timestamp >= start_date,
            Event.timestamp <= end_date
        ).all()
    
    # Count by week
    weekly_counts = defaultdict(int)
    for event in events:
        # Get week start (Monday)
        event_date = event.timestamp.date()
        week_start = event_date - timedelta(days=event_date.weekday())
        week_str = week_start.strftime('%Y-%m-%d')
        weekly_counts[week_str] += 1
    
    # Create lists for last 4 weeks
    labels = []
    counts = []
    
    # Start from 4 weeks ago (Monday)
    current = start_date.date()
    current = current - timedelta(days=current.weekday())  # Get to Monday
    
    for i in range(4):
        week_str = current.strftime('%Y-%m-%d')
        week_label = f"Week {i+1}"
        labels.append(week_label)
        counts.append(weekly_counts.get(week_str, 0))
        current += timedelta(weeks=1)
    
    return {'labels': labels, 'counts': counts}


def calculate_monthly_pattern_6months(user_id, suspicious_only=False):
    """
    Calculate pattern for last 6 months (one data point per month)
    
    Returns:
        dict: labels and counts for 6 months
    """
    end_date = datetime.now()
    start_date = end_date - timedelta(days=180)  # ~6 months
    
    # Get events or suspicious events
    if suspicious_only:
        alerts = Alert.query.filter(
            Alert.user_id == user_id,
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).all()
        
        events = []
        for alert in alerts:
            related = Event.query.filter(
                Event.user_id == user_id,
                Event.timestamp >= alert.timestamp - timedelta(minutes=2),
                Event.timestamp <= alert.timestamp + timedelta(minutes=2)
            ).all()
            events.extend(related)
        events = list({e.id: e for e in events}.values())
    else:
        events = Event.query.filter(
            Event.user_id == user_id,
            Event.timestamp >= start_date,
            Event.timestamp <= end_date
        ).all()
    
    # Count by month
    monthly_counts = defaultdict(int)
    for event in events:
        month_str = event.timestamp.strftime('%Y-%m')
        monthly_counts[month_str] += 1
    
    # Create lists for last 6 months
    labels = []
    counts = []
    
    for i in range(6):
        month_date = end_date - timedelta(days=30 * (5 - i))
        month_str = month_date.strftime('%Y-%m')
        month_label = month_date.strftime('%b %Y')  # Jan 2025, etc.
        labels.append(month_label)
        counts.append(monthly_counts.get(month_str, 0))
    
    return {'labels': labels, 'counts': counts}


def get_behavioral_summary(user_id):
    """
    Get complete behavioral analysis: Normal vs Suspicious
    
    Args:
        user_id: User ID
    
    Returns:
        dict: Complete behavioral data showing normal vs suspicious patterns
        None: If user not found
    """
    user = UserProfile.query.filter_by(user_id=user_id).first()
    
    if not user:
        return None
    
    try:
        # Chart 1: Hourly patterns (last 24 hours) vs 30-day baseline
        hourly_24h_normal = calculate_hourly_patterns_by_behavior(user_id, days=1, suspicious_only=False)
        hourly_24h_suspicious = calculate_hourly_patterns_by_behavior(user_id, days=1, suspicious_only=True)
        hourly_baseline_30d = calculate_hourly_patterns_by_behavior(user_id, days=30, suspicious_only=False)
        
        # Chart 2: Daily patterns (last 7 days) - 7 data points
        daily_7d = calculate_daily_pattern_7days(user_id, suspicious_only=False)
        daily_7d_suspicious = calculate_daily_pattern_7days(user_id, suspicious_only=True)
        
        # Chart 3: Weekly patterns (last 4 weeks) - 4 data points
        weekly_4w = calculate_weekly_pattern_4weeks(user_id, suspicious_only=False)
        weekly_4w_suspicious = calculate_weekly_pattern_4weeks(user_id, suspicious_only=True)
        
        # Chart 4: Monthly patterns (last 6 months) - 6 data points
        monthly_6m = calculate_monthly_pattern_6months(user_id, suspicious_only=False)
        monthly_6m_suspicious = calculate_monthly_pattern_6months(user_id, suspicious_only=True)
        
        # Activity summary for backward compatibility
        normal_activity = calculate_activity_by_type(user_id, days=7, suspicious_only=False)
        suspicious_activity = calculate_activity_by_type(user_id, days=7, suspicious_only=True)
        
        # Behavior comparison metrics
        comparison = calculate_behavior_comparison(user_id, days=30)
        
        return {
            'normal': normal_activity,
            'suspicious': suspicious_activity,
            
            # Chart 1: Hourly (24 hours) vs 30-day baseline
            'hourly_24h_normal': hourly_24h_normal,
            'hourly_24h_suspicious': hourly_24h_suspicious,
            'hourly_baseline_30d': hourly_baseline_30d,
            
            # Chart 2: Daily (7 days)
            'daily_7d': daily_7d,
            'daily_7d_suspicious': daily_7d_suspicious,
            
            # Chart 3: Weekly (4 weeks)
            'weekly_4w': weekly_4w,
            'weekly_4w_suspicious': weekly_4w_suspicious,
            
            # Chart 4: Monthly (6 months)
            'monthly_6m': monthly_6m,
            'monthly_6m_suspicious': monthly_6m_suspicious,
            
            'comparison': comparison,
            
            # Keep baseline for backward compatibility
            'baseline': {
                'http_per_day': round(user.avg_http_requests_per_day or 0, 2),
                'file_per_day': round(user.avg_file_accesses_per_day or 0, 2),
                'email_per_day': round(user.avg_email_count_per_day or 0, 2),
                'usb_per_day': round((user.usb_usage_frequency or 0) * 100, 2)
            },
            'current': normal_activity
        }
    except Exception as e:
        print(f"❌ Error in get_behavioral_summary: {e}")
        # Return safe defaults
        return {
            'normal': {'http_per_day': 0, 'file_per_day': 0, 'email_per_day': 0, 'usb_per_day': 0, 'total_events': 0},
            'suspicious': {'http_per_day': 0, 'file_per_day': 0, 'email_per_day': 0, 'usb_per_day': 0, 'total_events': 0},
            'hourly_normal': [0] * 24,
            'hourly_suspicious': [0] * 24,
            'hourly_24h_normal': [0] * 24,
            'hourly_24h_suspicious': [0] * 24,
            'hourly_baseline_30d': [0] * 24,
            'daily_7d': {'labels': [], 'counts': []},
            'daily_7d_suspicious': {'labels': [], 'counts': []},
            'alert_trends': {
                'dates': [],
                'critical_counts': [],
                'high_counts': [],
                'medium_counts': [],
                'low_counts': [],
                'total_counts': []
            },
            'comparison': {
                'total_events': 0,
                'normal_events': 0,
                'suspicious_events': 0,
                'suspicion_rate': 0
            },
            'baseline': {'http_per_day': 0, 'file_per_day': 0, 'email_per_day': 0, 'usb_per_day': 0},
            'current': {'http_per_day': 0, 'file_per_day': 0, 'email_per_day': 0, 'usb_per_day': 0}
        }
