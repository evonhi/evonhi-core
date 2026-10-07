"""Compiled, integer-indexed view of an attack graph and of remediation effects.

The planner never mutates the ``nx.DiGraph``. It compiles the part of the graph that matters —
edges lying on some entry -> crown-jewel route — into flat arrays, and compiles every
:class:`RemediationAction` into the set of edge modifications it causes. Everything downstream
(risk evaluation, search, decomposition) works on these integer ids.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Sequence

import networkx as nx

from evonhi_core.graph.contract import Capability, CapabilityKind, Guard, GuardStatus
from evonhi_core.models import RemediationAction
from evonhi_core.planning.model import RiskModel, requirement_effort


@dataclass(frozen=True, slots=True)
class ActionEffect:
    """What one action does to the compiled surface."""

    index: int
    action_id: str
    cost: int
    impact: float
    removed: frozenset[int]
    added_required: tuple[tuple[int, Capability], ...]
    added_effort: tuple[tuple[int, float], ...]

    @property
    def edges(self) -> frozenset[int]:
        return self.removed | {e for e, _ in self.added_required} | {e for e, _ in self.added_effort}

    def covers(self, other: "ActionEffect") -> bool:
        """True if applying ``self`` changes the surface at least as much as ``other``."""
        if not other.removed <= self.removed:
            return False
        mine_req = set(self.added_required)
        if any(item not in mine_req and item[0] not in self.removed for item in other.added_required):
            return False
        mine_effort: dict[int, float] = {}
        for e, x in self.added_effort:
            mine_effort[e] = mine_effort.get(e, 0.0) + x
        other_effort: dict[int, float] = {}
        for e, x in other.added_effort:
            other_effort[e] = other_effort.get(e, 0.0) + x
        return all(e in self.removed or mine_effort.get(e, 0.0) >= x for e, x in other_effort.items())


class AttackSurface:
    """Relevant sub-graph (edges on some entry -> jewel route) compiled to arrays."""

    def __init__(self, graph: nx.DiGraph, entry_kinds: Sequence[str], risk_model: RiskModel) -> None:
        self.graph = graph
        self.risk_model = risk_model
        kinds = set(entry_kinds)
        entries = sorted(n for n, a in graph.nodes(data=True) if a.get("kind") in kinds and a.get("public"))
        jewels = sorted(n for n, a in graph.nodes(data=True) if a.get("crown_jewel"))

        def traversable(u: str, v: str) -> bool:
            guard = graph.edges[u, v].get("guard")
            return not (isinstance(guard, Guard) and guard.static_status == GuardStatus.BLOCKED.value)

        forward = _bfs(entries, lambda n: (v for v in graph.successors(n) if traversable(n, v)))
        backward = _bfs(jewels, lambda n: (u for u in graph.predecessors(n) if traversable(u, n)))
        edge_keys = sorted(
            (u, v) for u, v in graph.edges() if u in forward and v in backward and traversable(u, v)
        )
        node_names = sorted({u for u, _ in edge_keys} | {v for _, v in edge_keys})
        self.node_names: list[str] = node_names
        self.node_index: dict[str, int] = {n: i for i, n in enumerate(node_names)}

        n_nodes = len(node_names)
        self.out_adj: list[list[tuple[int, int]]] = [[] for _ in range(n_nodes)]
        self.in_adj: list[list[tuple[int, int]]] = [[] for _ in range(n_nodes)]
        self.edge_src: list[int] = []
        self.edge_dst: list[int] = []
        self.edge_relation: list[str] = []
        self.edge_base: list[float] = []
        self.edge_required: list[frozenset[Capability]] = []
        self.edge_grants: list[frozenset[Capability]] = []
        self.edge_index: dict[tuple[str, str], int] = {}
        for eid, (u, v) in enumerate(edge_keys):
            attrs = graph.edges[u, v]
            relation = str(attrs.get("relation", ""))
            guard = attrs.get("guard")
            required = frozenset(guard.required) if isinstance(guard, Guard) else frozenset()
            grants = frozenset(guard.grants) if isinstance(guard, Guard) else frozenset()
            effort = attrs.get("effort")
            base = float(effort) if effort is not None else float(risk_model.relation_effort.get(relation, risk_model.default_effort))
            ui, vi = self.node_index[u], self.node_index[v]
            self.edge_src.append(ui)
            self.edge_dst.append(vi)
            self.edge_relation.append(relation)
            self.edge_base.append(base)
            self.edge_required.append(required)
            self.edge_grants.append(grants)
            self.edge_index[(u, v)] = eid
            self.out_adj[ui].append((vi, eid))
            self.in_adj[vi].append((ui, eid))

        self.entries: list[int] = [self.node_index[n] for n in entries if n in self.node_index]
        self.entry_weight: dict[int, float] = {
            i: float(graph.nodes[node_names[i]].get("compromise_likelihood", risk_model.entry_compromise_likelihood))
            for i in self.entries
        }
        self.jewels: list[int] = [self.node_index[n] for n in jewels if n in self.node_index]
        #: Every declared crown jewel (also those no entry reaches), for reporting.
        self.all_jewels: list[str] = jewels
        self.jewel_criticality: dict[int, float] = {
            i: float(graph.nodes[node_names[i]].get("criticality", risk_model.default_criticality)) for i in self.jewels
        }
        #: Grants make edge costs depend on the attacker's accumulated capabilities, which forces a
        #: forward label-setting search. Without grants every edge cost is static.
        self.stateful: bool = any(self.edge_grants)
        self.baseline_effort: list[float] = [
            base + requirement_effort(risk_model, req) for base, req in zip(self.edge_base, self.edge_required)
        ]

    @property
    def edge_count(self) -> int:
        return len(self.edge_src)

    def incident_edges(self, node: str) -> list[int]:
        i = self.node_index.get(node)
        if i is None:
            return []
        return [e for _, e in self.out_adj[i]] + [e for _, e in self.in_adj[i]]

    def components(self) -> list[int]:
        """Weakly-connected component id of every node (union-find over relevant edges)."""
        parent = list(range(len(self.node_names)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for u, v in zip(self.edge_src, self.edge_dst):
            ru, rv = find(u), find(v)
            if ru != rv:
                parent[max(ru, rv)] = min(ru, rv)
        return [find(i) for i in range(len(parent))]

    def compile_actions(self, actions: Sequence[RemediationAction]) -> list[ActionEffect]:
        effects: list[ActionEffect] = []
        for index, action in enumerate(actions):
            removed: set[int] = set()
            added_required: list[tuple[int, Capability]] = []
            added_effort: list[tuple[int, float]] = []
            targeted = [self.edge_index[tuple(edge)] for edge in action.target_edges if tuple(edge) in self.edge_index]  # type: ignore[arg-type]
            if action.effect_kind == "modify_guard":
                delta = action.guard_delta or {}
                capability = _capability_from_delta(delta)
                extra = float(delta.get("add_effort", 0.0) or 0.0)
                for eid in targeted:
                    if capability is not None:
                        added_required.append((eid, capability))
                    elif not extra:
                        extra = self.risk_model.unmet_requirement_effort
                    if extra:
                        added_effort.append((eid, extra))
            elif action.effect_kind == "weaken":
                extra = float((action.guard_delta or {}).get("add_effort", self.risk_model.default_weaken_effort))
                added_effort.extend((eid, extra) for eid in targeted)
            else:  # remove_edge | remove_node (and legacy actions that only list targets)
                removed.update(targeted)
                for node in action.target_nodes:
                    removed.update(self.incident_edges(node))
            effects.append(
                ActionEffect(
                    index=index,
                    action_id=action.action_id,
                    cost=int(action.cost),
                    impact=float(action.impact),
                    removed=frozenset(removed),
                    added_required=tuple(added_required),
                    added_effort=tuple(added_effort),
                )
            )
        return effects


def _bfs(starts: Sequence[str], neighbours) -> set[str]:
    seen = set(starts)
    queue = deque(starts)
    while queue:
        node = queue.popleft()
        for nxt in neighbours(node):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _capability_from_delta(delta: dict) -> Capability | None:
    kind = delta.get("add_required")
    if kind is None:
        return None
    try:
        return Capability(CapabilityKind(kind), str(delta.get("value", "")))
    except ValueError:
        return None
