"""
Unit tests for RiskScorer (app/models/ml_model.py) — the core scoring logic
that turns an ML anomaly score + keyword hits + context into a risk level.

No Flask app/DB needed. Business-hours/weekend settings are pinned on the
instance after construction so tests don't depend on whatever happens to be
in app/config/settings.json.

Fixed reference dates (verified, not relative to "today"):
  2024-01-01 = Monday
  2024-01-06 = Saturday
"""
import pytest

from app.models.ml_model import RiskScorer

SEVERITY_WEIGHTS = {
    'keyword_detected': 0.70,
    'malicious_domain': 0.40,
    'sensitive_file_access': 0.30,
    'unusual_data_volume': 0.25,
}
THRESHOLDS = {'critical': 0.9, 'high': 0.7, 'medium': 0.4, 'low': 0.2}


def make_scorer(keywords=None):
    scorer = RiskScorer(SEVERITY_WEIGHTS, THRESHOLDS, keywords)
    scorer.business_hours_start = 8
    scorer.business_hours_end = 18
    scorer.weekend_days = [5, 6]
    return scorer


def test_get_risk_level_boundaries():
    scorer = make_scorer()
    assert scorer.get_risk_level(0.95) == 'CRITICAL'
    assert scorer.get_risk_level(0.9) == 'CRITICAL'
    assert scorer.get_risk_level(0.75) == 'HIGH'
    assert scorer.get_risk_level(0.5) == 'MEDIUM'
    assert scorer.get_risk_level(0.25) == 'LOW'
    assert scorer.get_risk_level(0.1) == 'NORMAL'


def test_pure_ml_score_no_keywords_no_context():
    scorer = make_scorer()
    result = scorer.calculate_risk_score(
        anomaly_score=0.5,
        event_details={'timestamp': '2024-01-01T12:00:00', 'event_type': 'HTTP'},
    )
    assert result['score'] == pytest.approx(0.5)
    assert result['keywords_found'] == []
    assert 'ml' in result['detection_method']


def test_keyword_detection_triggers_score():
    scorer = make_scorer(keywords=['confidential'])
    result = scorer.calculate_risk_score(
        anomaly_score=0.0,
        event_details={
            'timestamp': '2024-01-01T12:00:00',
            'event_type': 'EMAIL',
            'subject': 'confidential data',
        },
    )
    assert 'confidential' in result['keywords_found']
    assert result['score'] == pytest.approx(0.70)
    assert 'keyword' in result['detection_method']


def test_after_hours_boosts_score():
    scorer = make_scorer()
    result = scorer.calculate_risk_score(
        anomaly_score=0.0,
        event_details={'timestamp': '2024-01-01T02:00:00', 'event_type': 'FILE'},  # Monday, 2 AM
    )
    assert result['contextual_boost'] > 0
    assert result['score'] > 0


def test_weekend_boosts_more_than_weekday_after_hours():
    scorer = make_scorer()
    weekend_result = scorer.calculate_risk_score(
        anomaly_score=0.0,
        event_details={'timestamp': '2024-01-06T12:00:00', 'event_type': 'FILE'},  # Saturday
    )
    weekday_after_hours_result = scorer.calculate_risk_score(
        anomaly_score=0.0,
        event_details={'timestamp': '2024-01-01T02:00:00', 'event_type': 'FILE'},  # Monday, 2 AM
    )
    assert weekend_result['contextual_boost'] > weekday_after_hours_result['contextual_boost']


def test_sensitive_filename_boosts_score():
    scorer = make_scorer()
    result = scorer.calculate_risk_score(
        anomaly_score=0.0,
        event_details={
            'timestamp': '2024-01-01T12:00:00',
            'event_type': 'FILE',
            'filename': 'salary_report_confidential.xlsx',
        },
    )
    assert result['contextual_boost'] >= 0.30


def test_score_capped_at_one():
    scorer = make_scorer(keywords=['leak'])
    result = scorer.calculate_risk_score(
        anomaly_score=1.0,
        event_details={
            'timestamp': '2024-01-06T02:00:00',  # Saturday
            'event_type': 'DEVICE',
            'filename': 'confidential_leak_data.xlsx',
            'total_email_size': 20_000_000,
        },
    )
    assert result['score'] == 1.0


def test_keyword_detection_disabled_flag_respected():
    scorer = make_scorer(keywords=['confidential'])
    result = scorer.calculate_risk_score(
        anomaly_score=0.0,
        event_details={'timestamp': '2024-01-01T12:00:00', 'event_type': 'EMAIL', 'subject': 'confidential'},
        keyword_detection_enabled=False,
    )
    assert result['keywords_found'] == []
    assert result['score'] == 0.0
