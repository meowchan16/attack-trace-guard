"""
Unit tests for GenAI editorial report generation.
"""

from unittest.mock import MagicMock, patch
import pytest
from genai import write_report, build_fallback_report


def test_no_api_key_returns_fallback():
    """When no API key is provided, write_report returns fallback template and generated_by='fallback'."""
    incident = {
        "id": 1,
        "attack_type": "DDoS",
        "src_ip": "203.0.113.99",
        "ts": "2026-10-18T14:00:00Z"
    }
    plan = {"steps": [{"description": "Add a firewall rule to block 203.0.113.99"}]}
    probability = 0.95

    text, generated_by = write_report(incident, plan, probability, api_key="")

    assert generated_by == "fallback"
    assert isinstance(text, str)
    assert len(text) > 50


def test_fallback_contains_required_facts():
    """Fallback text must contain the attack type, the source IP, and the probability."""
    incident = {
        "id": 42,
        "attack_type": "DDoS",
        "src_ip": "203.0.113.99",
        "ts": "2026-10-18T14:00:00Z"
    }
    plan = {"steps": [{"description": "Add a firewall rule to block 203.0.113.99"}]}
    probability = 0.95

    text = build_fallback_report(incident, plan, probability)

    # Attack type, src_ip, and probability
    assert "DDoS" in text
    assert "203.0.113.99" in text
    assert "95%" in text


def test_mocked_gemini_client_success():
    """When Gemini client successfully generates content, return its text and generated_by='gemini'."""
    incident = {
        "id": 1,
        "attack_type": "DDoS",
        "src_ip": "203.0.113.99",
        "ts": "2026-10-18T14:00:00Z"
    }
    mock_text = "At 2:00 PM, a DDoS attack was detected from 203.0.113.99. The perimeter firewall was engaged and the incident is resolved."

    with patch("genai._call_gemini_api", return_value=mock_text):
        text, generated_by = write_report(incident, None, 0.95, api_key="test-key-fake")

    assert generated_by == "gemini"
    assert "DDoS" in text
    assert "203.0.113.99" in text


def test_mocked_gemini_client_error_falls_back():
    """When Gemini client raises an exception, write_report must catch it and return fallback without raising."""
    incident = {
        "id": 1,
        "attack_type": "DDoS",
        "src_ip": "203.0.113.99",
        "ts": "2026-10-18T14:00:00Z"
    }

    with patch("genai._call_gemini_api", side_effect=RuntimeError("Google GenAI API connection failed")):
        text, generated_by = write_report(incident, None, 0.95, api_key="test-key-fake")

    assert generated_by == "fallback"
    assert "DDoS" in text
    assert "203.0.113.99" in text
    assert "95%" in text
