"""
Comprehensive Stage 8 verification test suite:
- Multi-attacker pool (RFC 5737 compliance and geolocation metadata)
- Simulator pre-attack unblocking & attack types (ddos, botnet, port_scan, brute_force)
- Logic detection for multi-attack vectors and detect_all()
- Planner variations for different attack types
- AI trace-back BFS vs A* exploration metrics and speedup
- API endpoints: POST /api/attack with vector payloads and GET /api/watchlist
- Database schema migration and persistence of Stage 8 fields
"""

import sys
import time
from pathlib import Path
import pytest
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attackers import ATTACKER_POOL, get_attacker, get_random_attacker, get_botnet_attackers
from simulator import Simulator
from modules.logic import detect, detect_all, SYN_RATE_THRESHOLD, DISTINCT_PORTS_THRESHOLD, SSH_ATTEMPTS_THRESHOLD
from modules.planner import make_plan, Action
from modules.search import ESTATE_GRAPH, bfs, astar, euclidean_heuristic, find_attack_route
from db import init_db, create_incident, update_incident, get_incident
from app import app, FAILED_ATTEMPTS


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Ensure clean database for each test."""
    test_db = tmp_path / "stage8_test.db"
    monkeypatch.setenv("AGENCY_DB_PATH", str(test_db))
    init_db(str(test_db))
    FAILED_ATTEMPTS.clear()


def test_attacker_profiles_pool():
    """Verify 8 profiles exist, all RFC 5737 compliant, with valid lat/lon and labels."""
    assert len(ATTACKER_POOL) == 8
    valid_prefixes = ("203.0.113.", "198.51.100.", "192.0.2.")
    
    for att in ATTACKER_POOL:
        assert any(att["ip"].startswith(pfx) for pfx in valid_prefixes), f"IP {att['ip']} not in RFC 5737 range"
        assert att["country"] != ""
        assert att["city"] != ""
        assert -90 <= att["lat"] <= 90
        assert -180 <= att["lon"] <= 180
        assert att["label"] != ""

    botnet_group = get_botnet_attackers()
    assert len(botnet_group) == 5

    random_att = get_random_attacker()
    assert random_att in ATTACKER_POOL


def test_simulator_unblocks_before_attack():
    """Verify Launch Attack / start_attack unblocks chosen attacker IP before traffic starts."""
    sim = Simulator()
    att = ATTACKER_POOL[0]
    sim.block_ip(att["ip"])
    assert att["ip"] in sim.blocklist

    sim.start_attack(attack_type="ddos", attack_ips=[att["ip"]])
    assert att["ip"] not in sim.blocklist, "Attacker IP must be removed from blocklist before starting"
    assert sim.attack_active is True
    assert sim.attack_type == "ddos"


def test_simulator_attack_types_generation():
    """Verify simulator generates appropriate traffic patterns for all 4 attack types."""
    # 1. DDoS
    sim = Simulator()
    sim.start_attack(attack_type="ddos")
    sim.tick()
    pkts = [p for p in sim.window if p.get("is_attack")]
    assert len(pkts) >= 30
    assert all(p["dst_port"] == 80 for p in pkts)
    assert all(p["flags"] == "SYN" for p in pkts)

    # 2. Botnet (5 attackers)
    sim = Simulator()
    sim.start_attack(attack_type="botnet")
    sim.tick()
    botnet_ips = {p["src_ip"] for p in sim.window if p.get("is_attack") and p["dst_port"] == 80 and p["flags"] == "SYN"}
    assert len(botnet_ips) == 5

    # 3. Port scan (touches 10+ ports)
    sim = Simulator()
    sim.start_attack(attack_type="port_scan")
    sim.tick()
    scan_ports = {p["dst_port"] for p in sim.window if p.get("is_attack")}
    assert len(scan_ports) >= 10

    # 4. Brute force (SSH port 22)
    sim = Simulator()
    sim.start_attack(attack_type="brute_force")
    sim.tick()
    ssh_pkts = [p for p in sim.window if p.get("is_attack") and p["dst_port"] == 22]
    assert len(ssh_pkts) >= 12


def test_logic_detection_all_types():
    """Verify logic rules detect each attack type in sliding window."""
    # Brute force
    sim_brute = Simulator()
    sim_brute.start_attack(attack_type="brute_force")
    sim_brute.tick()
    detections = detect_all(list(sim_brute.window))
    assert len(detections) >= 1
    assert detections[0]["attack_type"] == "brute_force"
    assert "brute force" in detections[0]["rule_fired"].lower()

    # Port scan
    sim_scan = Simulator()
    sim_scan.start_attack(attack_type="port_scan")
    sim_scan.tick()
    detections = detect_all(list(sim_scan.window))
    assert len(detections) >= 1
    assert detections[0]["attack_type"] == "port_scan"
    assert "port scan" in detections[0]["rule_fired"].lower()

    # Botnet
    sim_bot = Simulator()
    sim_bot.start_attack(attack_type="botnet")
    sim_bot.tick()
    detections = detect_all(list(sim_bot.window))
    assert len(detections) == 5
    assert all(d["attack_type"] == "botnet" for d in detections)


def test_planner_custom_action_descriptions():
    """Verify planner descriptions adapt based on attack type."""
    # Port scan
    plan_port_scan = make_plan({"src_ip": "198.51.100.23", "attack_type": "port_scan", "dst_port": 8080})
    assert plan_port_scan is not None
    assert any("Lock port 8080" in step["description"] for step in plan_port_scan["steps"])

    # Brute force
    plan_brute = make_plan({"src_ip": "192.0.2.77", "attack_type": "brute_force", "dst_port": 22})
    assert plan_brute is not None
    assert any("Block SSH attempts from 192.0.2.77" in step["description"] for step in plan_brute["steps"])

    # Standard DDoS
    plan_ddos = make_plan({"src_ip": "203.0.113.99", "attack_type": "ddos", "dst_port": 80})
    assert plan_ddos is not None
    assert any("Add a firewall rule to block 203.0.113.99" in step["description"] for step in plan_ddos["steps"])


def test_search_bfs_vs_astar_speedup():
    """Verify A* search explores fewer nodes than BFS for estate topology."""
    route_info = find_attack_route(attack_type="DDoS", dst_port=80)
    assert route_info["target"] == "Web Server"
    assert route_info["bfs"]["explored_count"] == 9
    assert route_info["astar"]["explored_count"] == 4
    # Speedup is (9 - 4) / 9 = 55.6% ~ 56%
    assert route_info["speedup_percent"] >= 50
    assert route_info["astar"]["path"] == [
        "Gateway Router",
        "External Firewall",
        "Core Switch",
        "Web Server",
    ]


def test_api_attack_types_and_watchlist():
    """Verify POST /api/attack accepts vector types and GET /api/watchlist returns items."""
    client = TestClient(app)
    
    # Authenticate as agent001
    login_resp = client.post("/login", data={"username": "agent001", "password": "olive-and-cream"})
    assert login_resp.status_code == 200

    # Test attack with botnet
    attack_resp = client.post("/api/attack", json={"type": "botnet"})
    assert attack_resp.status_code == 200
    data = attack_resp.json()
    assert data["attack_type"] == "botnet"
    assert len(data["attack_ips"]) == 5

    # Test watchlist endpoint
    wl_resp = client.get("/api/watchlist")
    assert wl_resp.status_code == 200
    wl_data = wl_resp.json()
    assert isinstance(wl_data, list)

    # Reset
    reset_resp = client.post("/api/reset")
    assert reset_resp.status_code == 200


def test_db_migration_stage8_fields(tmp_path):
    """Verify database persists origin_city, origin_country, detected_at, blocked_at, route_json."""
    db_file = str(tmp_path / "stage8_db_check.db")
    init_db(db_file)

    inc_id = create_incident(
        src_ip="203.0.113.99",
        attack_type="ddos",
        origin_city="Lagos",
        origin_country="Nigeria",
        route_json='{"path": ["Gateway Router", "Web Server"]}',
        db_path=db_file
    )
    assert inc_id > 0

    inc = get_incident(inc_id, db_path=db_file)
    assert inc["origin_city"] == "Lagos"
    assert inc["origin_country"] == "Nigeria"
    assert inc["detected_at"] is not None
    assert 'Gateway Router' in inc["route_json"]

    # Update incident to blocked
    now_ts = "2026-10-18T16:00:00"
    update_incident(inc_id, status="blocked", blocked_at=now_ts, db_path=db_file)
    updated = get_incident(inc_id, db_path=db_file)
    assert updated["status"] == "blocked"
    assert updated["blocked_at"] == now_ts
