"""
Module 6: Planning (STRIPS-style Automated Defense Planning)

Pure functions with zero I/O.
Performs breadth-first forward search over discrete state spaces defined by
fact assertions to synthesize the minimal-length containment sequence.
"""

from typing import Dict, List, Set, FrozenSet, Any, Optional
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Action:
    """A STRIPS action with preconditions, add/delete effects, and a human-readable description template."""
    name: str
    preconditions: FrozenSet[str]
    add_effects: FrozenSet[str]
    delete_effects: FrozenSet[str]
    description_template: str

    def is_applicable(self, state: FrozenSet[str]) -> bool:
        """Check if action preconditions are fully satisfied by current state."""
        return self.preconditions.issubset(state)

    def apply(self, state: FrozenSet[str]) -> FrozenSet[str]:
        """Apply action effects to produce new state."""
        return (state - self.delete_effects) | self.add_effects

    def format_description(self, src_ip: str, dst_port: int = 80) -> str:
        """Format the plain-English description with incident parameters."""
        return self.description_template.format(src_ip=src_ip, dst_port=dst_port)


# Domain Actions (stored as data)
# Notice rate_limit_port and notify_admin serve as distractor actions
ACTIONS: List[Action] = [
    Action(
        name="identify_source_ip",
        preconditions=frozenset({"attack_detected"}),
        add_effects=frozenset({"ip_identified"}),
        delete_effects=frozenset(),
        description_template="Identify and confirm the attacking IP ({src_ip})"
    ),
    Action(
        name="add_firewall_rule",
        preconditions=frozenset({"ip_identified"}),
        add_effects=frozenset({"threat_blocked"}),
        delete_effects=frozenset(),
        description_template="Add a firewall rule to block {src_ip}"
    ),
    Action(
        name="verify_block",
        preconditions=frozenset({"threat_blocked"}),
        add_effects=frozenset({"block_verified"}),
        delete_effects=frozenset(),
        description_template="Verify that malicious traffic has stopped"
    ),
    Action(
        name="rate_limit_port",
        preconditions=frozenset({"attack_detected"}),
        add_effects=frozenset({"port_limited"}),
        delete_effects=frozenset(),
        description_template="Apply rate limiting to port {dst_port}"
    ),
    Action(
        name="notify_admin",
        preconditions=frozenset({"attack_detected"}),
        add_effects=frozenset({"admin_notified"}),
        delete_effects=frozenset(),
        description_template="Notify network administrator of suspicious activity"
    ),
]

DEFAULT_INITIAL_STATE: FrozenSet[str] = frozenset({"attack_detected"})
DEFAULT_GOAL: FrozenSet[str] = frozenset({"threat_blocked", "block_verified"})


def bfs_search(
    initial_state: FrozenSet[str],
    goal: FrozenSet[str],
    actions: List[Action]
) -> tuple[List[Action], int]:
    """
    Breadth-first forward search over discrete STRIPS state graph.
    BFS guarantees returning the minimal-action path to satisfy goal.
    Returns (plan_actions, states_explored).
    """
    if goal.issubset(initial_state):
        return [], 1

    queue: deque[tuple[FrozenSet[str], List[Action]]] = deque([(initial_state, [])])
    visited: Set[FrozenSet[str]] = {initial_state}
    states_explored = 0

    while queue:
        current_state, path = queue.popleft()
        states_explored += 1

        if goal.issubset(current_state):
            return path, states_explored

        for action in actions:
            if action.is_applicable(current_state):
                next_state = action.apply(current_state)
                if next_state not in visited:
                    visited.add(next_state)
                    queue.append((next_state, path + [action]))

    return [], states_explored


def make_plan(
    incident: Optional[Dict[str, Any]] = None,
    initial: Optional[Set[str] | FrozenSet[str]] = None,
    goal: Optional[Set[str] | FrozenSet[str]] = None,
    actions: Optional[List[Action]] = None
) -> Dict[str, Any]:
    """
    Synthesize an automated containment plan for an incident using STRIPS planning.

    Parameters:
    - incident: metadata dict containing at least 'src_ip' (and optionally 'dst_port')
    - initial: initial state facts (defaults to {"attack_detected"})
    - goal: goal state facts (defaults to {"threat_blocked", "block_verified"})
    - actions: available domain actions (defaults to ACTIONS)

    Returns:
    {
        "goal": [...],
        "steps": [
            {"n": 1, "action": "...", "description": "..."},
            ...
        ],
        "states_explored": N
    }
    """
    incident = incident or {}
    src_ip = incident.get("src_ip", "203.0.113.99")
    dst_port = incident.get("dst_port", 80)

    initial_state = frozenset(initial) if initial is not None else DEFAULT_INITIAL_STATE
    goal_state = frozenset(goal) if goal is not None else DEFAULT_GOAL
    domain_actions = actions if actions is not None else ACTIONS

    action_path, states_explored = bfs_search(initial_state, goal_state, domain_actions)

    steps = [
        {
            "n": idx + 1,
            "action": action.name,
            "description": action.format_description(src_ip=src_ip, dst_port=dst_port)
        }
        for idx, action in enumerate(action_path)
    ]

    return {
        "goal": sorted(list(goal_state)),
        "steps": steps,
        "states_explored": states_explored
    }
