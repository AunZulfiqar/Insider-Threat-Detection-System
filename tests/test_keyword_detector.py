"""
Unit tests for KeywordDetector (app/models/ml_model.py).

Pure logic, no Flask app or database needed — these run the detector
directly against the keyword list.
"""
from app.models.ml_model import KeywordDetector


def test_detects_whole_word_match():
    detector = KeywordDetector(["hack", "malware"])
    has_kw, found = detector.detect("trying to hack the server")
    assert has_kw is True
    assert found == ["hack"]


def test_ignores_substring_false_positive():
    """'tor' must not match inside 'tutorial' or 'actor' — word-boundary matching."""
    detector = KeywordDetector(["tor"])
    has_kw, found = detector.detect("please read the tutorial before you start")
    assert has_kw is False
    assert found == []


def test_no_match_returns_empty():
    detector = KeywordDetector(["malware", "exploit"])
    has_kw, found = detector.detect("just a normal status update email")
    assert has_kw is False
    assert found == []


def test_empty_text_returns_false():
    detector = KeywordDetector(["malware"])
    has_kw, found = detector.detect("")
    assert has_kw is False
    assert found == []


def test_case_insensitive_match():
    detector = KeywordDetector(["confidential"])
    has_kw, found = detector.detect("Subject: CONFIDENTIAL quarterly results")
    assert has_kw is True
    assert found == ["confidential"]


def test_detect_in_event_searches_multiple_fields_and_dedupes():
    detector = KeywordDetector(["confidential", "secret"])
    event_details = {
        "subject": "confidential report",
        "content": "this is confidential and secret",
        "to": "colleague@company.com",
    }
    has_kw, found, fields = detector.detect_in_event(event_details)
    assert has_kw is True
    assert set(found) == {"confidential", "secret"}
    assert set(fields) == {"subject", "content"}


def test_detect_in_event_handles_invalid_json_string():
    detector = KeywordDetector(["malware"])
    has_kw, found, fields = detector.detect_in_event("not valid json {")
    assert has_kw is False
    assert found == []
    assert fields == []
