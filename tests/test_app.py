"""
Tests for app.py endpoints, session authentication, rate limiting, and editorial rendering.
"""

import sys
from pathlib import Path
import pytest
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import app, FAILED_ATTEMPTS, RATE_LIMIT_WINDOW, MAX_FAILED_ATTEMPTS
from db import init_db

@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Ensure clean database and rate limiter for each test."""
    test_db = tmp_path / "app_test.db"
    monkeypatch.setenv("AGENCY_DB_PATH", str(test_db))
    init_db(str(test_db))
    FAILED_ATTEMPTS.clear()


def test_root_redirect_unauthenticated():
    """Unauthenticated GET / redirects to /login."""
    client = TestClient(app, follow_redirects=False)
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_page_renders_styled_html():
    """GET /login serves the login page HTML containing the editorial headline and botanical leaf."""
    client = TestClient(app)
    response = client.get("/login")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Welcome back" in response.text
    assert "Private Security Concierge" in response.text


def test_dashboard_requires_auth():
    """Unauthenticated GET /dashboard redirects to /login."""
    client = TestClient(app, follow_redirects=False)
    response = client.get("/dashboard")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_api_me_unauthenticated():
    """Unauthenticated GET /api/me returns 401."""
    client = TestClient(app)
    response = client.get("/api/me")
    assert response.status_code == 401


def test_login_wrong_credentials_shows_error():
    """POST /login with invalid credentials re-shows login with terracotta error."""
    client = TestClient(app)
    response = client.post("/login", data={"username": "agent001", "password": "wrong-password"})
    assert response.status_code == 200
    assert "Those credentials don't match our records. Please try again." in response.text


def test_successful_login_and_flow():
    """POST /login with valid credentials redirects to /dashboard, establishes session, and provides /api/me."""
    client = TestClient(app, follow_redirects=False)
    response = client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert "agency_session" in response.cookies

    # Now request /dashboard with the active session
    dash_response = client.get("/dashboard")
    assert dash_response.status_code == 200
    assert "Calm. Secure." in dash_response.text

    # Request /api/me
    me_response = client.get("/api/me")
    assert me_response.status_code == 200
    data = me_response.json()
    assert data["display_name"] == "Agent 001"
    assert data["username"] == "agent001"

    # Now test /logout
    logout_response = client.post("/logout")
    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/login"

    # Verify session is cleared
    after_logout = client.get("/dashboard")
    assert after_logout.status_code == 303
    assert after_logout.headers["location"] == "/login"


def test_rate_limiting_after_five_failed_attempts():
    """After 5 failed attempts from one IP, shows rate limit error."""
    client = TestClient(app)
    
    # Trigger 5 failed attempts
    for _ in range(5):
        res = client.post("/login", data={"username": "agent001", "password": "bad"})
    
    # 6th attempt should be blocked with rate limit message
    blocked_res = client.post("/login", data={"username": "agent001", "password": "bad"})
    assert blocked_res.status_code == 429
    assert "Please wait a few minutes before trying again." in blocked_res.text


def test_ws_unauthenticated_rejected():
    """Unauthenticated WebSocket connection is closed with policy violation code 1008."""
    from starlette.websockets import WebSocketDisconnect

    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws"):
            pass
    assert exc_info.value.code == 1008


def test_ws_authenticated_receives_data():
    """Authenticated client connects to /ws and receives telemetry replay data."""
    from app import summary_history

    client = TestClient(app, follow_redirects=False)
    # Log in first to establish signed session cookie
    login_res = client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})
    assert login_res.status_code == 303

    # Seed at least one summary into replay deque
    test_summary = {
        "type": "traffic",
        "ts": "2026-10-18T18:30:00Z",
        "packets": 5,
        "blocked": 0,
        "avg_size": 482.0
    }
    summary_history.append(test_summary)

    with client.websocket_connect("/ws") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "traffic"
        assert "packets" in data
        assert "avg_size" in data


def test_api_attack_requires_auth():
    """Unauthenticated POST /api/attack returns 401."""
    client = TestClient(app)
    response = client.post("/api/attack")
    assert response.status_code == 401


def test_api_attack_lifecycle():
    """Authenticated POST /api/attack initiates attack; concurrent trigger returns 409."""
    from app import simulator

    # Ensure clean simulator attack state
    simulator.stop_attack()

    client = TestClient(app, follow_redirects=False)
    # Login
    login_res = client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})
    assert login_res.status_code == 303

    # Trigger attack
    res = client.post("/api/attack")
    assert res.status_code == 200
    assert res.json()["status"] == "attack_started"
    assert simulator.attack_active is True

    # Immediate second trigger should return 409 Conflict
    conflict_res = client.post("/api/attack")
    assert conflict_res.status_code == 409
    assert "already underway" in conflict_res.json()["detail"]

    # Clean up
    simulator.stop_attack()


@pytest.mark.anyio
async def test_run_planner_analysis_persists_and_broadcasts():
    """Verify run_planner_analysis writes plan_json to SQLite incident row."""
    from app import run_planner_analysis
    from db import create_incident, get_connection
    import json

    incident_id = create_incident("DDoS", "203.0.113.99")
    await run_planner_analysis(incident_id, "203.0.113.99")

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT plan_json FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["plan_json"] is not None
        plan = json.loads(row["plan_json"])
        assert len(plan["steps"]) == 3
        assert plan["steps"][0]["action"] == "identify_source_ip"
        assert plan["steps"][1]["action"] == "add_firewall_rule"
        assert plan["steps"][2]["action"] == "verify_block"
    finally:
        conn.close()


def test_ws_replays_cached_plan():
    """Verify newly connected WebSocket receives cached last_plan."""
    import app as app_module

    app_module.last_plan = {
        "type": "plan",
        "incident_id": 999,
        "goal": ["block_verified", "threat_blocked"],
        "steps": [{"n": 1, "action": "identify_source_ip", "description": "Identify and confirm the attacking IP"}],
        "states_explored": 8
    }

    client = TestClient(app, follow_redirects=False)
    client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})

    with client.websocket_connect("/ws") as websocket:
        received = []
        for _ in range(5):
            msg = websocket.receive_json()
            received.append(msg)
            if msg.get("type") == "plan":
                break

        types = [m.get("type") for m in received]
        assert "plan" in types


def test_api_incidents_auth():
    """Unauthenticated GET /api/incidents returns 401; authenticated returns 200 list."""
    client = TestClient(app, follow_redirects=False)

    # 1. Unauthenticated
    unauth_res = client.get("/api/incidents")
    assert unauth_res.status_code == 401

    # 2. Authenticated
    client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})
    auth_res = client.get("/api/incidents")
    assert auth_res.status_code == 200
    assert isinstance(auth_res.json(), list)


def test_api_reset_auth():
    """POST /api/reset clears blocklist and resets active replay state."""
    from app import simulator
    import app as app_module

    client = TestClient(app, follow_redirects=False)

    # 1. Unauthenticated
    unauth_res = client.post("/api/reset")
    assert unauth_res.status_code == 401

    # 2. Authenticated
    client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})

    # Set some state to verify reset clears it
    simulator.block_ip("203.0.113.99")
    app_module.last_plan = {"type": "plan"}

    res = client.post("/api/reset")
    assert res.status_code == 200
    assert res.json()["status"] == "reset"
    assert "203.0.113.99" not in simulator.blocklist
    assert app_module.last_plan is None


@pytest.mark.anyio
async def test_run_report_and_resolve_pipeline_execution():
    """Verify run_report_and_resolve_pipeline saves report and marks incident blocked."""
    from app import run_report_and_resolve_pipeline, simulator
    from db import create_incident, get_connection

    incident_id = create_incident("DDoS", "203.0.113.99")
    plan = {"steps": [{"description": "Add a firewall rule to block 203.0.113.99"}]}

    await run_report_and_resolve_pipeline(incident_id, "203.0.113.99", plan)

    # Attacker IP must be blocked
    assert "203.0.113.99" in simulator.blocklist

    # Incident status must be 'blocked' and report must exist
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        assert inc_row is not None
        assert inc_row["status"] == "blocked"

        cursor.execute("SELECT body, generated_by FROM reports WHERE incident_id = ?", (incident_id,))
        rep_row = cursor.fetchone()
        assert rep_row is not None
        assert rep_row["generated_by"] in ["gemini", "fallback"]
    finally:
        conn.close()
        simulator.unblock_all()


def test_security_headers():
    """Verify security headers are attached to responses."""
    client = TestClient(app)
    res = client.get("/login")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_custom_404_error_page_html_and_json():
    """Verify custom 404 renders forest-and-cream HTML or JSON depending on Accept header."""
    client = TestClient(app)

    # 1. HTML request
    html_res = client.get("/unaccounted-estate-corridor", headers={"Accept": "text/html"})
    assert html_res.status_code == 404
    assert "A Room Unaccounted For" in html_res.text
    assert "Return to the Agency" in html_res.text

    # 2. JSON request
    json_res = client.get("/unaccounted-estate-corridor", headers={"Accept": "application/json"})
    assert json_res.status_code == 404
    assert "detail" in json_res.json()


@pytest.mark.anyio
async def test_full_story_e2e_lifecycle():
    """
    End-to-end integration test that simulates the full story:
    1. Authenticate agent ->
    2. Trigger attack ->
    3. Detect attack via logic ->
    4. Bayes posterior calculation & persistence ->
    5. STRIPS defense plan synthesis & persistence ->
    6. GenAI incident report generation & persistence ->
    7. Defense applied: attacker IP blocked and marked resolved ->
    8. Back Issues retrieval verifies full historical incident.
    """
    import json
    from app import simulator, run_bayes_analysis, run_planner_analysis, run_report_and_resolve_pipeline
    from db import get_connection, create_incident, list_incidents_with_reports
    from modules.logic import detect
    from simulator import attack_packet

    client = TestClient(app, follow_redirects=False)

    # 1. Login
    login_res = client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})
    assert login_res.status_code == 303

    # 2. Trigger attack
    attack_res = client.post("/api/attack")
    assert attack_res.status_code == 200
    assert simulator.attack_active is True

    # Populate simulator window with attack packets to trigger Module 4 detection
    attacker_ip = "203.0.113.99"
    for _ in range(25):
        simulator.window.append(attack_packet(attacker_ip=attacker_ip))

    # 3. Detection via Module 4 Logic
    detection = detect(simulator.window)
    assert detection is not None
    assert detection["attack_type"] == "DDoS"
    assert detection["src_ip"] == attacker_ip

    incident_id = create_incident(
        attack_type=detection["attack_type"],
        src_ip=detection["src_ip"],
        status="detected"
    )
    assert incident_id > 0

    # 4. Module 5 Bayes Analysis
    await run_bayes_analysis(incident_id, attacker_ip)

    # 5. Module 6 STRIPS Planner
    await run_planner_analysis(incident_id, attacker_ip)

    # 6. Stage 6 Report & Defense Resolution
    plan_data = {"steps": [{"description": f"Add a firewall rule to block {attacker_ip}"}]}
    await run_report_and_resolve_pipeline(incident_id, attacker_ip, plan_data)

    # Verify Attacker is blocked in simulator
    assert attacker_ip in simulator.blocklist

    # Verify Database state
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT status, probability, plan_json FROM incidents WHERE id = ?", (incident_id,))
        inc_row = cursor.fetchone()
        assert inc_row is not None
        assert inc_row["status"] == "blocked"
        assert inc_row["probability"] >= 0.8
        assert inc_row["plan_json"] is not None

        parsed_plan = json.loads(inc_row["plan_json"])
        assert "steps" in parsed_plan
        assert len(parsed_plan["steps"]) >= 3

        cursor.execute("SELECT body, generated_by FROM reports WHERE incident_id = ?", (incident_id,))
        rep_row = cursor.fetchone()
        assert rep_row is not None
        assert rep_row["generated_by"] in ["gemini", "fallback"]
        assert len(rep_row["body"]) > 50
    finally:
        conn.close()

    # 7. Check Back Issues API
    incidents_res = client.get("/api/incidents")
    assert incidents_res.status_code == 200
    incidents_list = incidents_res.json()
    assert len(incidents_list) >= 1
    newest = incidents_list[0]
    assert newest["src_ip"] == attacker_ip
    assert newest["status"] == "blocked"
    assert newest["report"] is not None
    assert newest["plan"] is not None

    # 8. Reset demo
    reset_res = client.post("/api/reset")
    assert reset_res.status_code == 200
    assert attacker_ip not in simulator.blocklist




