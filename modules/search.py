"""
Module 7: AI Search & Route Tracing (modules/search.py)
Pure functions, zero I/O.

Implements graph-based Breadth-First Search (BFS) and A* Search over
the Agency's network topology to trace attack ingress routes and
demonstrate AI search efficiency speedups.
"""

import heapq
import math
from typing import Any, Dict, List, Optional, Set, Tuple


# Network topology graph of the Agency estate
# Nodes have a 2D coordinate pos (x, y) and weighted directed edges to neighbors.
ESTATE_GRAPH: Dict[str, Dict[str, Any]] = {
    "Gateway Router": {
        "pos": (60, 150),
        "neighbors": [
            ("External Firewall", 2.0),
            ("Backup Gateway", 6.0),
            ("Perimeter IDS", 4.0),
        ]
    },
    "Backup Gateway": {
        "pos": (60, 270),
        "neighbors": [
            ("Gateway Router", 6.0),
            ("Out-of-band Switch", 5.0),
        ]
    },
    "Out-of-band Switch": {
        "pos": (200, 270),
        "neighbors": [
            ("Backup Gateway", 5.0),
            ("Core Switch", 6.0),
        ]
    },
    "Perimeter IDS": {
        "pos": (200, 50),
        "neighbors": [
            ("Gateway Router", 4.0),
            ("External Firewall", 3.0),
            ("Security Operations Hub", 4.0),
        ]
    },
    "Security Operations Hub": {
        "pos": (340, 50),
        "neighbors": [
            ("Perimeter IDS", 4.0),
            ("Core Switch", 5.0),
        ]
    },
    "External Firewall": {
        "pos": (200, 150),
        "neighbors": [
            ("Gateway Router", 2.0),
            ("Core Switch", 2.0),
            ("Perimeter IDS", 3.0),
            ("DMZ Honeypot", 5.0),
        ]
    },
    "DMZ Honeypot": {
        "pos": (200, 210),
        "neighbors": [
            ("External Firewall", 5.0),
            ("Sandbox Isolation", 4.0),
        ]
    },
    "Sandbox Isolation": {
        "pos": (340, 210),
        "neighbors": [
            ("DMZ Honeypot", 4.0),
        ]
    },
    "Core Switch": {
        "pos": (340, 150),
        "neighbors": [
            ("External Firewall", 2.0),
            ("Security Operations Hub", 5.0),
            ("Out-of-band Switch", 6.0),
            ("Web Server", 2.0),
            ("SSH Bastion", 2.0),
            ("Database Server", 4.0),
        ]
    },
    "Web Server": {
        "pos": (480, 80),
        "port": 80,
        "neighbors": [
            ("Core Switch", 2.0),
            ("Database Server", 3.0),
        ]
    },
    "SSH Bastion": {
        "pos": (480, 150),
        "port": 22,
        "neighbors": [
            ("Core Switch", 2.0),
        ]
    },
    "Database Server": {
        "pos": (480, 220),
        "neighbors": [
            ("Core Switch", 4.0),
            ("Web Server", 3.0),
        ]
    },
}


def euclidean_heuristic(node_a: str, node_b: str, graph: Optional[Dict[str, Any]] = None) -> float:
    """
    Admissible and consistent Euclidean distance heuristic scaled to match graph edge weights.
    """
    g = graph or ESTATE_GRAPH
    pos_a = g.get(node_a, {}).get("pos", (0, 0))
    pos_b = g.get(node_b, {}).get("pos", (0, 0))
    dx = pos_a[0] - pos_b[0]
    dy = pos_a[1] - pos_b[1]
    # Scale Euclidean pixels to graph edge cost scale (~100px per 2.0 cost)
    return math.hypot(dx, dy) / 60.0


def bfs(
    graph: Dict[str, Any],
    start: str,
    goal: str
) -> Dict[str, Any]:
    """
    Breadth-First Search from start to goal.
    Returns:
    {
        "path": List[str],
        "explored": List[str],
        "explored_count": int,
    }
    """
    if start not in graph or goal not in graph:
        return {"path": [], "explored": [], "explored_count": 0}

    from collections import deque
    queue = deque([(start, [start])])
    visited: Set[str] = {start}
    explored: List[str] = []

    while queue:
        current, path = queue.popleft()
        explored.append(current)

        if current == goal:
            return {
                "path": path,
                "explored": explored,
                "explored_count": len(explored),
            }

        neighbors = graph[current].get("neighbors", [])
        for neighbor_entry in neighbors:
            nxt = neighbor_entry[0] if isinstance(neighbor_entry, (list, tuple)) else neighbor_entry
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))

    return {
        "path": [],
        "explored": explored,
        "explored_count": len(explored),
    }


def astar(
    graph: Dict[str, Any],
    start: str,
    goal: str,
    heuristic=None
) -> Dict[str, Any]:
    """
    A* Search from start to goal using f(n) = g(n) + h(n).
    Returns:
    {
        "path": List[str],
        "explored": List[str],
        "explored_count": int,
        "cost": float,
    }
    """
    if start not in graph or goal not in graph:
        return {"path": [], "explored": [], "explored_count": 0, "cost": 0.0}

    h_fn = heuristic or (lambda a, b: euclidean_heuristic(a, b, graph))

    counter = 0
    # Priority queue entries: (f_score, counter, current_node, current_g, path)
    initial_h = h_fn(start, goal)
    open_heap = [(initial_h, counter, start, 0.0, [start])]
    closed_set: Set[str] = set()
    best_g: Dict[str, float] = {start: 0.0}
    explored: List[str] = []

    while open_heap:
        f_score, _, current, g_score, path = heapq.heappop(open_heap)

        if current in closed_set:
            continue
        closed_set.add(current)
        explored.append(current)

        if current == goal:
            return {
                "path": path,
                "explored": explored,
                "explored_count": len(explored),
                "cost": round(g_score, 2),
            }

        neighbors = graph[current].get("neighbors", [])
        for neighbor_entry in neighbors:
            if isinstance(neighbor_entry, (list, tuple)):
                nxt, weight = neighbor_entry[0], float(neighbor_entry[1])
            else:
                nxt, weight = neighbor_entry, 1.0

            if nxt in closed_set:
                continue

            tentative_g = g_score + weight
            if nxt not in best_g or tentative_g < best_g[nxt]:
                best_g[nxt] = tentative_g
                counter += 1
                f = tentative_g + h_fn(nxt, goal)
                heapq.heappush(open_heap, (f, counter, nxt, tentative_g, path + [nxt]))

    return {
        "path": [],
        "explored": explored,
        "explored_count": len(explored),
        "cost": 0.0,
    }


def find_attack_route(
    attack_type: str = "DDoS",
    dst_port: int = 80,
    graph: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Determine target node based on attack type and destination port,
    run both BFS and A* from 'Gateway Router' to target node,
    and compute search speedup comparison metrics.
    """
    g = graph or ESTATE_GRAPH
    at_lower = str(attack_type).lower()

    if "brute" in at_lower or dst_port == 22:
        target = "SSH Bastion"
    elif "scan" in at_lower:
        target = "Core Switch"
    else:
        target = "Web Server"

    start = "Gateway Router"

    bfs_res = bfs(g, start, target)
    astar_res = astar(g, start, target)

    bfs_count = bfs_res["explored_count"]
    astar_count = astar_res["explored_count"]

    if bfs_count > astar_count and bfs_count > 0:
        speedup_pct = round(((bfs_count - astar_count) / bfs_count) * 100)
    else:
        speedup_pct = 0

    comparison_text = (
        f"A* found the path exploring {astar_count} nodes vs {bfs_count} for BFS ({speedup_pct}% faster)"
    )

    return {
        "start": start,
        "target": target,
        "bfs": bfs_res,
        "astar": astar_res,
        "speedup_percent": speedup_pct,
        "comparison_text": comparison_text,
    }
