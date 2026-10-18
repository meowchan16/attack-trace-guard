"""
Tests for db.py in the Boutique Cybersecurity Agency Dashboard.

Validates:
1. All three tables exist (users, incidents, reports).
2. Seeded user 'agent001' is created on first run with correct display name.
3. Correct password verifies against stored hash.
4. Wrong password verification fails cleanly.
"""

import sqlite3
import pytest
import os
import tempfile

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from db import init_db, get_user, verify_password, hash_password, create_incident, update_incident
except ImportError:
    from agency.db import init_db, get_user, verify_password, hash_password, create_incident, update_incident


@pytest.fixture
def temp_db_path(tmp_path):
    """Fixture providing an isolated temporary database path for each test."""
    db_file = tmp_path / "test_agency.db"
    return str(db_file)


def test_tables_created(temp_db_path):
    """Verify that users, incidents, and reports tables are all created."""
    init_db(temp_db_path)

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name IN ('users', 'incidents', 'reports')
        ORDER BY name;
    """)
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()

    assert "users" in tables, "users table was not created"
    assert "incidents" in tables, "incidents table was not created"
    assert "reports" in tables, "reports table was not created"
    assert len(tables) == 3


def test_seeded_user_exists(temp_db_path):
    """Verify that agent001 is seeded on initial database creation."""
    init_db(temp_db_path)

    user = get_user("agent001", db_path=temp_db_path)
    assert user is not None, "Seeded user 'agent001' not found in database"
    assert user["username"] == "agent001"
    assert user["display_name"] == "Agent 001"
    assert "password_hash" in user
    assert user["password_hash"].startswith("$2b$") or user["password_hash"].startswith("$2a$")


def test_correct_password_verifies(temp_db_path):
    """Verify that the default password 'olive-and-cream' passes verification."""
    init_db(temp_db_path)

    user = get_user("agent001", db_path=temp_db_path)
    assert user is not None
    is_valid = verify_password("olive-and-cream", user["password_hash"])
    assert is_valid is True, "Expected correct password to verify successfully"


def test_wrong_password_fails(temp_db_path):
    """Verify that an incorrect password fails verification."""
    init_db(temp_db_path)

    user = get_user("agent001", db_path=temp_db_path)
    assert user is not None
    is_valid = verify_password("wrong-password", user["password_hash"])
    assert is_valid is False, "Expected incorrect password to fail verification"

    # Also test empty and random strings
    assert verify_password("", user["password_hash"]) is False
    assert verify_password("Olive-and-cream", user["password_hash"]) is False


def test_init_db_idempotent(temp_db_path):
    """Verify calling init_db multiple times does not duplicate seed user or error."""
    init_db(temp_db_path)
    init_db(temp_db_path)

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'agent001'")
    count = cursor.fetchone()[0]
    conn.close()

    assert count == 1, "Seed user should only exist once after multiple init_db calls"


def test_create_and_update_incident(temp_db_path):
    """Verify create_incident inserts a record and update_incident updates fields properly."""
    init_db(temp_db_path)

    incident_id = create_incident(
        attack_type="DDoS",
        src_ip="203.0.113.99",
        status="detected",
        db_path=temp_db_path
    )
    assert incident_id > 0

    # Verify inserted record
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT attack_type, src_ip, status FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "DDoS"
    assert row[1] == "203.0.113.99"
    assert row[2] == "detected"

    # Update status to 'ended'
    updated = update_incident(incident_id, status="ended", db_path=temp_db_path)
    assert updated is True

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,))
    updated_status = cursor.fetchone()[0]
    conn.close()

    assert updated_status == "ended"

