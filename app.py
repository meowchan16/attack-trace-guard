"""
FastAPI application for the Boutique Cybersecurity Agency Dashboard.

Handles:
- Authentication & signed session cookie via Starlette SessionMiddleware
- Rate limiting for login attempts (in-memory, 5 attempts per 5 minutes per IP)
- Elegant editorial dashboard and login rendering
- User profile retrieval via /api/me
"""

import asyncio
import html
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from collections import deque
import logging
from typing import Dict, List, Optional, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

try:
    from db import get_user, init_db, verify_password, create_incident, update_incident
except ImportError:
    from agency.db import get_user, init_db, verify_password, create_incident, update_incident

try:
    from simulator import Simulator
except ImportError:
    from agency.simulator import Simulator

try:
    from modules.logic import detect
except ImportError:
    from agency.modules.logic import detect

try:
    from modules.bayes import explain as bayes_explain, most_suspicious as bayes_most_suspicious
except ImportError:
    from agency.modules.bayes import explain as bayes_explain, most_suspicious as bayes_most_suspicious

try:
    from modules.planner import make_plan
except ImportError:
    from agency.modules.planner import make_plan

from datetime import datetime, timezone

logger = logging.getLogger("agency")

# Load environment configuration (.env)
load_dotenv()
SESSION_SECRET = os.getenv("SESSION_SECRET", "the-agency-boutique-retreat-default-secret-key-32b")

# Directory paths
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# ============================================================================
# Simulator & WebSocket Connection Manager
# ============================================================================
simulator = Simulator()
summary_history: deque = deque(maxlen=60)
current_incident_id: Optional[int] = None
last_detection: Optional[Dict[str, Any]] = None
last_bayes: Optional[Dict[str, Any]] = None
last_plan: Optional[Dict[str, Any]] = None
prev_attack_active: bool = False


class ConnectionManager:
    """
    Tracks active authenticated WebSocket connections, broadcasts telemetry,
    and cleanly handles disconnections.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        """Broadcast message to all connected clients; drop dead sockets silently."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


async def simulator_loop():
    """
    Background worker:
    - Calls simulator.tick() once per second
    - Broadcasts traffic summary
    - Runs logic.detect() on the packet window (only once per attack)
    - Persists detected incidents in database & broadcasts {type: "detection"}
    - Detects attack termination, updates incident status to 'ended', and broadcasts {type: "attack_ended"}
    """
    global current_incident_id, last_detection, prev_attack_active

    while True:
        try:
            summary = simulator.tick()
            summary_history.append(summary)
            await manager.broadcast(summary)

            # 1. Detection check on packet window (only once per attack cycle)
            if simulator.attack_active and current_incident_id is None:
                detection = detect(simulator.window)
                if detection:
                    incident_ts = datetime.now(timezone.utc).isoformat()
                    incident_id = create_incident(
                        attack_type=detection["attack_type"],
                        src_ip=detection["src_ip"],
                        ts=incident_ts,
                        status="detected"
                    )
                    current_incident_id = incident_id
                    detection_payload = {
                        "type": "detection",
                        "incident_id": incident_id,
                        "attack_type": detection["attack_type"],
                        "src_ip": detection["src_ip"],
                        "rule_fired": detection["rule_fired"],
                        "proof_trace": detection["proof_trace"],
                        "ts": incident_ts
                    }
                    last_detection = detection_payload
                    await manager.broadcast(detection_payload)

                    # Trigger Module 5 Bayes reasoning engine after ~1 second without blocking loop
                    asyncio.create_task(run_bayes_analysis(incident_id, detection["src_ip"]))

            # 2. Check if an active attack concluded during this tick
            if prev_attack_active and not simulator.attack_active:
                await manager.broadcast({"type": "attack_ended"})
                if current_incident_id is not None:
                    update_incident(current_incident_id, status="ended")
                    current_incident_id = None

            prev_attack_active = simulator.attack_active

        except Exception as exc:
            logger.exception(f"Error in simulator background loop: {exc}")

        await asyncio.sleep(1.0)


async def run_bayes_analysis(incident_id: int, src_ip: str):
    """
    Module 5: Bayes probability engine runner.
    Waits 1 second after detection, computes source rate, picks most suspicious packet,
    computes posterior probability and step-by-step reasoning, persists probability
    to incident in SQLite, and broadcasts {type: 'bayes'}.
    """
    global last_bayes
    await asyncio.sleep(1.0)
    try:
        now = time.time()
        # 1. Compute source rate (packets from that IP in the last second)
        pkts_1s = [
            p for p in simulator.window
            if p.get("src_ip") == src_ip and (now - 1.0) <= p.get("_time", 0) <= now
        ]
        src_rate = float(len(pkts_1s)) if pkts_1s else 40.0

        # 2. Pick most suspicious packet from attacker in window
        suspicious_pkt = bayes_most_suspicious(simulator.window, src_ip, src_rate=src_rate)
        if not suspicious_pkt:
            suspicious_pkt = {"size": 40, "flags": "SYN", "src_ip": src_ip, "_time": now}

        # 3. Call bayes.explain()
        explanation = bayes_explain(suspicious_pkt, src_rate=src_rate)

        # 4. Save probability to incident row in SQLite
        update_incident(incident_id, probability=explanation["posterior"])

        # 5. Broadcast {type: "bayes", incident_id, prior, steps, posterior}
        bayes_payload = {
            "type": "bayes",
            "incident_id": incident_id,
            "prior": explanation["prior"],
            "steps": explanation["steps"],
            "posterior": explanation["posterior"]
        }
        last_bayes = bayes_payload
        await manager.broadcast(bayes_payload)

        # Trigger Module 6 STRIPS Planner engine ~1 second after Bayes finishes
        asyncio.create_task(run_planner_analysis(incident_id, src_ip))

    except Exception as exc:
        logger.exception(f"Error in Bayes analysis: {exc}")


async def run_planner_analysis(incident_id: int, src_ip: str):
    """
    Module 6: STRIPS-style Automated Defense Planner runner.
    Waits 1 second after Bayes finishes, synthesizes a minimal-action containment plan,
    saves the plan as JSON in the incident's plan_json column in SQLite,
    and broadcasts {type: 'plan', incident_id, goal, steps, states_explored}.
    """
    global last_plan
    await asyncio.sleep(1.0)
    try:
        incident_metadata = {
            "id": incident_id,
            "src_ip": src_ip,
            "dst_port": 80,
            "attack_type": "DDoS"
        }
        plan_result = make_plan(incident_metadata)

        # Save plan JSON string to incident record in SQLite
        plan_json_str = json.dumps(plan_result)
        update_incident(incident_id, plan_json=plan_json_str)

        # Broadcast {type: "plan", incident_id, goal, steps, states_explored}
        plan_payload = {
            "type": "plan",
            "incident_id": incident_id,
            "goal": plan_result["goal"],
            "steps": plan_result["steps"],
            "states_explored": plan_result["states_explored"]
        }
        last_plan = plan_payload
        await manager.broadcast(plan_payload)

    except Exception as exc:
        logger.exception(f"Error in Planner analysis: {exc}")


# ============================================================================
# In-Memory Rate Limiter Configuration
# 5 failed attempts from one IP in 5 minutes (300 seconds)
# ============================================================================
FAILED_ATTEMPTS: Dict[str, List[float]] = {}
RATE_LIMIT_WINDOW = 300.0  # 5 minutes in seconds
MAX_FAILED_ATTEMPTS = 5


def get_client_ip(request: Request) -> str:
    """Extract client IP address, respecting X-Forwarded-For if present."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def is_rate_limited(ip: str) -> bool:
    """Check if the client IP has exceeded failed login attempts within the window."""
    now = time.time()
    attempts = FAILED_ATTEMPTS.get(ip, [])
    # Prune attempts outside the active window
    active_attempts = [ts for ts in attempts if now - ts < RATE_LIMIT_WINDOW]
    FAILED_ATTEMPTS[ip] = active_attempts
    return len(active_attempts) >= MAX_FAILED_ATTEMPTS


def record_failed_attempt(ip: str) -> None:
    """Record a failed login attempt for the client IP."""
    now = time.time()
    attempts = FAILED_ATTEMPTS.get(ip, [])
    active_attempts = [ts for ts in attempts if now - ts < RATE_LIMIT_WINDOW]
    active_attempts.append(now)
    FAILED_ATTEMPTS[ip] = active_attempts


def clear_failed_attempts(ip: str) -> None:
    """Clear recorded failed attempts upon successful authentication."""
    if ip in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[ip]


# ============================================================================
# HTML Template Rendering Helper
# ============================================================================
def render_login_html(error: str = "", username: str = "", status_code: int = 200) -> HTMLResponse:
    """
    Render login.html with dynamic error banner and preserved username field.
    """
    login_path = STATIC_DIR / "login.html"
    with open(login_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Inject terracotta error banner if present
    if error:
        safe_error = html.escape(error, quote=False)
        error_markup = (
            f'<div id="login-error" class="error-message" role="alert">'
            f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            f'<circle cx="12" cy="12" r="10"></circle>'
            f'<line x1="12" y1="8" x2="12" y2="12"></line>'
            f'<line x1="12" y1="16" x2="12.01" y2="16"></line>'
            f'</svg>'
            f'<span>{safe_error}</span>'
            f'</div>'
        )
        content = content.replace("<!--ERROR_PLACEHOLDER-->", error_markup)
    else:
        content = content.replace("<!--ERROR_PLACEHOLDER-->", "")

    # Inject existing username value
    content = content.replace("<!--USERNAME_VALUE-->", html.escape(username))

    return HTMLResponse(content=content, status_code=status_code)


# ============================================================================
# FastAPI App Lifecycle & Setup
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database tables and seed agent exist on first run
    init_db()
    # Start background simulator worker task
    sim_task = asyncio.create_task(simulator_loop())
    try:
        yield
    finally:
        sim_task.cancel()
        try:
            await sim_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="The Agency — Boutique Cybersecurity Concierge",
    lifespan=lifespan
)

# Mount static directory for CSS, JS, and botanical assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Signed cookie session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="agency_session",
    max_age=14 * 24 * 3600,  # 14 days
    same_site="lax",
    https_only=False,  # Set to False for local dev convenience
)


# ============================================================================
# Routes
# ============================================================================

@app.get("/")
async def root(request: Request):
    """
    GET / -> redirect to /dashboard if logged in, else /login
    """
    if request.session.get("username"):
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/login")
async def login_get(request: Request):
    """
    GET /login -> serves login.html
    Redirects to /dashboard if agent is already authenticated.
    """
    if request.session.get("username"):
        return RedirectResponse(url="/dashboard", status_code=303)
    return render_login_html()


@app.post("/login")
async def login_post(request: Request):
    """
    POST /login -> checks credentials;
    On success: sets session and redirects to /dashboard (303);
    On failure: re-shows login with a friendly error ("Those credentials don't match our records. Please try again.");
    Rate limit: after 5 failed attempts from one IP in 5 minutes, shows "Please wait a few minutes before trying again."
    """
    ip = get_client_ip(request)

    # 1. Check rate limit
    if is_rate_limited(ip):
        rate_error = "Please wait a few minutes before trying again."
        # Support JSON API requests if sent
        if "application/json" in request.headers.get("content-type", ""):
            return JSONResponse({"detail": rate_error}, status_code=429)
        return render_login_html(error=rate_error, status_code=429)

    # 2. Parse credentials from form or JSON
    content_type = request.headers.get("content-type", "")
    is_json = "application/json" in content_type

    if is_json:
        try:
            body = await request.json()
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
        except Exception:
            username, password = "", ""
    else:
        form = await request.form()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))

    # 3. Authenticate against database
    user = get_user(username)
    authenticated = False
    if user and verify_password(password, user["password_hash"]):
        authenticated = True

    # 4. Handle failed credentials
    if not authenticated:
        record_failed_attempt(ip)

        # Check if this failure triggered the rate limit threshold
        if is_rate_limited(ip):
            error_msg = "Please wait a few minutes before trying again."
            status = 429
        else:
            error_msg = "Those credentials don't match our records. Please try again."
            status = 200

        if is_json:
            return JSONResponse({"detail": error_msg}, status_code=status)
        return render_login_html(error=error_msg, username=username, status_code=status)

    # 5. Success: clear rate limiting and set session cookie
    clear_failed_attempts(ip)
    request.session["username"] = user["username"]

    if is_json:
        return JSONResponse({"success": True, "redirect": "/dashboard"})
    return RedirectResponse(url="/dashboard", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    """
    POST /logout -> clears session, redirects to /login
    """
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/dashboard")
async def dashboard_get(request: Request):
    """
    GET /dashboard -> serves dashboard.html (auth required, else redirects to /login)
    """
    username = request.session.get("username")
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    dashboard_file = STATIC_DIR / "dashboard.html"
    return FileResponse(dashboard_file)


@app.get("/api/me")
async def api_me(request: Request):
    """
    GET /api/me -> returns {"display_name": "..."} for the logged-in user
    (401 if not logged in); app.js uses it to fill in the name on the dashboard
    """
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user = get_user(username)
    if not user:
        # Session references non-existent user
        request.session.clear()
        raise HTTPException(status_code=401, detail="User not found")

    return {
        "display_name": user["display_name"],
        "username": user["username"]
    }


@app.post("/api/attack")
async def trigger_attack(request: Request):
    """
    POST /api/attack -> starts a simulated DDoS attack for 8 seconds.
    Requires authenticated session.
    Returns 409 Conflict if an attack is already in progress.
    """
    username = request.session.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if simulator.attack_active:
        return JSONResponse(
            {"detail": "An attack simulation is already underway. Please wait for it to conclude."},
            status_code=409
        )

    global last_bayes, last_plan
    last_bayes = None
    last_plan = None

    simulator.start_attack(duration=8.0)
    await manager.broadcast({"type": "attack_started"})
    return {"status": "attack_started", "duration": 8.0}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WS /ws -> Real-time telemetry stream.
    - Requires authenticated session cookie; closed with code 1008 if unauthenticated.
    - On connect: replays the last 30 seconds of telemetry summaries.
    - Replays active attack state, last detection, last Bayes explanation, and last plan if available.
    - Broadcasts live 1-second summary updates from simulator.
    """
    username = websocket.session.get("username")
    if not username:
        # 1008 Policy Violation for unauthenticated WebSocket requests
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        # 1. Replay up to the last 30 seconds of historical summaries so chart is pre-populated
        recent_summaries = list(summary_history)[-30:]
        for summary in recent_summaries:
            await websocket.send_json(summary)

        # 2. If an attack is actively running, inform client immediately
        if simulator.attack_active:
            await websocket.send_json({"type": "attack_started"})

        # 3. If there is a cached detection, send it so page refresh mid-attack still shows it
        if last_detection:
            await websocket.send_json(last_detection)

        # 4. If there is a cached Bayes event, send it so page refresh mid-attack still shows it
        if last_bayes:
            await websocket.send_json(last_bayes)

        # 5. If there is a cached Plan event, send it so page refresh mid-attack still shows it
        if last_plan:
            await websocket.send_json(last_plan)

        # Keep connection open and await any client frames
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        manager.disconnect(websocket)


