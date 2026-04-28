"""Shared pytest fixtures for all Sorabbyngo tests."""
import pytest
from sorabbyngo.api.app import create_app
from sorabbyngo.core.models import RawSignal, SecurityEvent, Severity, EventCategory


@pytest.fixture
def app():
    """Flask test app in dry-run + testing mode."""
    return create_app(dry_run=True, testing=True)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def critical_payload() -> dict:
    return {
        "source": "falco",
        "payload": {
            "severity": "CRITICAL",
            "category": "INTRUSION",
            "title": "SSH brute-force detected",
            "description": "Multiple failed SSH login attempts from external IP",
            "host": "prod-server-01",
            "process": "sshd",
            "user": "root",
            "mitre_technique": "T1110 – Brute Force",
        },
    }


@pytest.fixture
def low_payload() -> dict:
    return {
        "source": "osquery",
        "payload": {
            "severity": "LOW",
            "category": "POLICY_VIOLATION",
            "title": "USB device connected",
            "description": "Unknown USB device plugged into workstation",
            "host": "ws-dev-07",
        },
    }


@pytest.fixture
def medium_payload() -> dict:
    return {
        "source": "custom",
        "payload": {
            "severity": "MEDIUM",
            "category": "ANOMALY",
            "title": "Unusual outbound traffic",
            "description": "High volume outbound traffic detected on port 443",
            "host": "app-server-03",
            "process": "python3",
            "user": "deploy",
        },
    }
