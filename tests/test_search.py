"""
Unit tests for Module 7: AI Search & Route Tracing (modules/search.py)
"""

import pytest
from modules.search import ESTATE_GRAPH, bfs, astar, euclidean_heuristic, find_attack_route


def test_bfs_shortest_path():
    """BFS finds the unweighted shortest path from Gateway Router to Web Server."""
    result = bfs(ESTATE_GRAPH, "Gateway Router", "Web Server")
    assert result["path"] == ["Gateway Router", "External Firewall", "Core Switch", "Web Server"]
    assert result["explored_count"] > len(result["path"])
    assert "Gateway Router" in result["explored"]
    assert "Web Server" in result["explored"]


def test_astar_finds_optimal_path_exploring_fewer_nodes():
    """A* finds the optimal path while exploring fewer nodes than BFS."""
    bfs_res = bfs(ESTATE_GRAPH, "Gateway Router", "Web Server")
    astar_res = astar(ESTATE_GRAPH, "Gateway Router", "Web Server")

    assert astar_res["path"] == ["Gateway Router", "External Firewall", "Core Switch", "Web Server"]
    assert astar_res["cost"] == 6.0  # 2.0 + 2.0 + 2.0
    assert astar_res["explored_count"] < bfs_res["explored_count"]
    assert astar_res["explored_count"] == 4
    assert bfs_res["explored_count"] == 9


def test_speedup_calculation():
    """Verify find_attack_route produces expected speedup comparison."""
    route = find_attack_route(attack_type="DDoS", dst_port=80)
    assert route["start"] == "Gateway Router"
    assert route["target"] == "Web Server"
    assert route["bfs"]["explored_count"] == 9
    assert route["astar"]["explored_count"] == 4
    assert route["speedup_percent"] >= 50
    assert "faster" in route["comparison_text"]
    assert "A* found the path exploring 4 nodes vs 9 for BFS" in route["comparison_text"]


def test_brute_force_route_target():
    """Brute force routes to SSH Bastion."""
    route = find_attack_route(attack_type="brute_force", dst_port=22)
    assert route["target"] == "SSH Bastion"
    assert "SSH Bastion" in route["astar"]["path"]


def test_unreachable_node_returns_empty():
    """Searching for a non-existent or unreachable node returns empty path."""
    res = bfs(ESTATE_GRAPH, "Gateway Router", "Unknown Node")
    assert res["path"] == []
    assert res["explored_count"] == 0

    res_a = astar(ESTATE_GRAPH, "Gateway Router", "Unknown Node")
    assert res_a["path"] == []
    assert res_a["explored_count"] == 0
