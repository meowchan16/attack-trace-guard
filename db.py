"""
Database management for the Boutique Cybersecurity Agency Dashboard.

Uses the Python standard library's sqlite3 module with parameterized queries,
bcrypt password hashing, and automatic schema initialization and seeding.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import bcrypt

# Default database filename (can be overridden via environment or parameter)
DEFAULT_DB_PATH = os.getenv("AGENCY_DB_PATH", "agency.db")


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Open a connection to SQLite database with Row factory enabled
    for convenient dictionary-style field access.
    """
    path = db_path or os.getenv("AGENCY_DB_PATH", "agency.db")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password using bcrypt with a generated salt.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a bcrypt-hashed string.
    Returns False safely on any mismatch or malformed hash.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize all database tables automatically on first run and
    seed the initial default user ('agent001') if not already present.
    Prints credentials to the console on first run only.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()

            # 1. users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

            # 2. incidents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    probability REAL NOT NULL,
                    status TEXT NOT NULL,
                    plan_json TEXT
                );
            """)

            # 3. reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER REFERENCES incidents(id),
                    ts TEXT NOT NULL,
                    body TEXT NOT NULL,
                    generated_by TEXT NOT NULL
                );
            """)

            # Seed user check: 'agent001'
            cursor.execute("SELECT id FROM users WHERE username = ?", ("agent001",))
            existing_user = cursor.fetchone()

            if not existing_user:
                initial_username = "agent001"
                initial_display_name = "Agent 001"
                initial_password = "olive-and-cream"
                created_at = datetime.now(timezone.utc).isoformat()
                password_hash = hash_password(initial_password)

                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, display_name, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (initial_username, password_hash, initial_display_name, created_at)
                )

                # Console notification on first run only
                print("==================================================================")
                print("[The Agency] Initial agent seeded (first run):")
                print(f"  Username:     {initial_username}")
                print(f"  Password:     {initial_password}")
                print(f"  Display Name: {initial_display_name}")
                print("==================================================================")
    finally:
        conn.close()


def get_user(username: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch a user record by username using a parameterized query.
    Returns a dict representation of the user row, or None if not found.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, password_hash, display_name, created_at
            FROM users
            WHERE username = ?
            """,
            (username,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        conn.close()


def create_incident(
    attack_type: str,
    src_ip: str,
    ts: Optional[str] = None,
    status: str = "detected",
    probability: float = 1.0,
    plan_json: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """
    Create a new incident row in the incidents table using parameterized queries.
    Returns the newly inserted incident ID.
    """
    now_ts = ts or datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO incidents (ts, attack_type, src_ip, probability, status, plan_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now_ts, attack_type, src_ip, probability, status, plan_json)
            )
            return cursor.lastrowid
    finally:
        conn.close()


def update_incident(
    incident_id: int,
    status: Optional[str] = None,
    probability: Optional[float] = None,
    plan_json: Optional[str] = None,
    db_path: Optional[str] = None
) -> bool:
    """
    Update status, probability, or plan_json of an existing incident using parameterized queries.
    Returns True if an incident row was modified, False otherwise.
    """
    updates = []
    params = []

    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if probability is not None:
        updates.append("probability = ?")
        params.append(probability)
    if plan_json is not None:
        updates.append("plan_json = ?")
        params.append(plan_json)

    if not updates:
        return False

    params.append(incident_id)
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?",
                tuple(params)
            )
            return cursor.rowcount > 0
    finally:
        conn.close()


def save_report(
    incident_id: int,
    body: str,
    generated_by: str,
    ts: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """
    Save an incident report to the reports table using parameterized queries.
    Stores timestamp automatically if not provided.
    Returns the newly inserted report ID.
    """
    now_ts = ts or datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO reports (incident_id, ts, body, generated_by)
                VALUES (?, ?, ?, ?)
                """,
                (incident_id, now_ts, body, generated_by)
            )
            return cursor.lastrowid
    finally:
        conn.close()


def list_incidents_with_reports(
    limit: int = 20,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List newest incidents with associated reports (limit default 20), newest first.
    Returns list of dicts:
    {
        "id": int,
        "ts": str,
        "attack_type": str,
        "src_ip": str,
        "probability": float,
        "status": str,
        "plan": dict or None (parsed from plan_json),
        "report": {"body": str, "generated_by": str, "ts": str} or None
    }
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, ts, attack_type, src_ip, probability, status, plan_json
            FROM incidents
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        incident_rows = cursor.fetchall()

        results = []
        for inc in incident_rows:
            inc_dict = dict(inc)
            inc_id = inc_dict["id"]

            plan_obj = None
            if inc_dict.get("plan_json"):
                try:
                    plan_obj = json.loads(inc_dict["plan_json"])
                except Exception:
                    plan_obj = None

            cursor.execute(
                """
                SELECT id, ts, body, generated_by
                FROM reports
                WHERE incident_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (inc_id,)
            )
            report_row = cursor.fetchone()
            report_dict = None
            if report_row:
                report_dict = {
                    "id": report_row["id"],
                    "body": report_row["body"],
                    "generated_by": report_row["generated_by"],
                    "ts": report_row["ts"]
                }

            results.append({
                "id": inc_dict["id"],
                "ts": inc_dict["ts"],
                "attack_type": inc_dict["attack_type"],
                "src_ip": inc_dict["src_ip"],
                "probability": inc_dict["probability"],
                "status": inc_dict["status"],
                "plan": plan_obj,
                "report": report_dict
            })

        return results
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()


