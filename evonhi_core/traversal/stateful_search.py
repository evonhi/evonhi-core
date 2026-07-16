"""Capability-aware traversal (Fase 2, multi-cloud refactor).

This module holds three related things:

1. ``find_attack_paths`` — path enumeration for reporting and path counting. It is now
   capability-aware (it reads each edge's ``Guard`` and accumulates capabilities), but
   with an empty capability domain and open guards it reduces EXACTLY to the previous
   Kubernetes behavior, so the golden tests are unchanged. This is the enumeration
   primitive; it does NOT dominance-prune (that would drop distinct simple paths).

2. ``reachable_states`` — capability-aware reachability with DOMINANCE PRUNING and a
   CLOSED capability domain. This is the scalable primitive (used at scale, e.g. AWS):
   the visited key is the dominance relation over ``(node, frozenset[Capability])``, not
   the node alone, which keeps the frontier bounded to O(k·nodes) instead of O(2^k·nodes).

3. ``ReachabilityIndex`` — precomputes the baseline paths once and indexes which edges/
   nodes each path crosses, so ``apply_and_recount`` answers "how many paths remain after
   removing these edges/nodes" by filtering the precomputed set instead of re-searching.

``path_analysis`` is kept as a thin shim re-exporting the public names from here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

import networkx as nx

from evonhi_core.graph.contract import Capability, CapabilityKind, Guard, GuardStatus, open_guard
from evonhi_core.models import AttackPath

DEFAULT_MAX_PATH_DEPTH = 8

#: Default per-relation risk weights (Kubernetes). Moves to providers/kubernetes in Fase 4.
EDGE_RISK: dict[str, float] = {
    "uses_token": 2.0,
    "mounted_secret": 6.0,
    "granted_permission": 3.0,
    "read_secret": 8.0,
    "spawn_workload_as": 7.0,
}
EDGE_LABELS: dict[str, str] = {
    "uses_token": "uses service account token",
    "mounted_secret": "reads mounted secret",
    "granted_permission": "is granted permission",
    "read_secret": "can read secret",
    "spawn_workload_as": "can pivot into another service account",
}

#: Upper bound on the capability domain size; keeps the 2^k term of the stateful search
#: tractable by design (Fase 2.3). Raising it is a deliberate architectural decision.
CAPABILITY_DOMAIN_LIMIT = 8


# --------------------------------------------------------------------------- #
# Guard / capability helpers
# --------------------------------------------------------------------------- #


def _edge_guard(graph: nx.DiGraph, left: str, right: str) -> Guard:
    """The edge's Guard, or an open guard when none is present (e.g. today's K8s graph)."""
    guard = graph.edges[left, right].get("guard")
    return guard if isinstance(guard, Guard) else open_guard()


def _guard_is_traversable(guard: Guard, capabilities: frozenset[Capability], *, conservative: bool) -> bool:
    """An edge is traversable if its required capabilities are already held, or it is
    open, or (in conservative mode) it is conditional."""
    if set(guard.required) <= capabilities:
        return True
    if guard.static_status == GuardStatus.OPEN.value:
        return True
    if conservative and guard.static_status == GuardStatus.CONDITIONAL.value:
        return True
    return False


def validate_capability_domain(domain: Sequence[CapabilityKind], *, limit: int = CAPABILITY_DOMAIN_LIMIT) -> frozenset[CapabilityKind]:
    """Enforce the closed, small capability domain (Fase 2.3). Raises if it exceeds the
    limit or contains non-CapabilityKind members."""
    domain_set = frozenset(domain)
    for kind in domain_set:
        if not isinstance(kind, CapabilityKind):
            raise ValueError(f"capability domain contains a non-CapabilityKind member: {kind!r}")
    if len(domain_set) > limit:
        raise ValueError(f"capability domain exceeds the closed-domain limit ({len(domain_set)} > {limit})")
    return domain_set


def _assert_guard_within_domain(guard: Guard, domain: frozenset[CapabilityKind]) -> None:
    """A builder must not emit a Guard carrying a capability outside the declared domain."""
    for cap in (*guard.required, *guard.grants):
        if cap.kind not in domain:
            raise ValueError(
                f"guard uses capability {cap.kind!r} outside the declared closed domain {sorted(k.value for k in domain)}"
            )


# --------------------------------------------------------------------------- #
# Dominance-pruned reachability (the scalable primitive)
# --------------------------------------------------------------------------- #


def reachable_states(
    graph: nx.DiGraph,
    entry_nodes: Iterable[str],
    capability_domain: Sequence[CapabilityKind],
    *,
    conservative: bool = True,
    limit: int = CAPABILITY_DOMAIN_LIMIT,
) -> dict[str, list[frozenset[Capability]]]:
    """Capability-aware reachability with dominance pruning.

    Returns ``memo``: for each reached node, the list of MAXIMAL capability sets it was
    reached with. Justification (monotonicity): if a node was already reached with a set
    ``E`` that contains ``S``, any edge ``S`` enables is also enabled by ``E``, so the
    ``S`` route discovers nothing new and is pruned. This bounds ``|memo|`` to a small
    multiple of the node count rather than ``nodes · 2^k``.
    """
    domain = validate_capability_domain(capability_domain, limit=limit)
    memo: dict[str, list[frozenset[Capability]]] = {}
    stack: list[tuple[str, frozenset[Capability]]] = [(node, frozenset()) for node in entry_nodes]

    while stack:
        node, caps = stack.pop()
        existing = memo.get(node)
        if existing is None:
            memo[node] = [caps]
        elif any(caps <= seen for seen in existing):
            continue  # dominated -> prune, do not expand
        else:
            memo[node] = [seen for seen in existing if not (seen <= caps)] + [caps]

        for succ in graph.successors(node):
            guard = _edge_guard(graph, node, succ)
            _assert_guard_within_domain(guard, domain)
            if _guard_is_traversable(guard, caps, conservative=conservative):
                new_caps = caps | frozenset(guard.grants)
                stack.append((succ, new_caps))

    return memo


# --------------------------------------------------------------------------- #
# Path enumeration (golden-preserving) + scoring/labels
# --------------------------------------------------------------------------- #


def entry_nodes(graph: nx.DiGraph, kinds: Sequence[str] = ("workload",)) -> list[str]:
    kind_set = set(kinds)
    return [n for n, a in graph.nodes(data=True) if a.get("kind") in kind_set and a.get("public")]


def crown_jewel_nodes(graph: nx.DiGraph) -> list[str]:
    return [node for node, attrs in graph.nodes(data=True) if attrs.get("crown_jewel")]


def _node_label(graph: nx.DiGraph, node: str) -> str:
    attrs = graph.nodes[node]
    kind = attrs.get("kind", "object")
    name = attrs.get("name", node)
    namespace = attrs.get("namespace")
    if kind == "permission":
        api_group = attrs.get("api_group") or "core"
        resource = attrs.get("resource", "*")
        verb = attrs.get("verb", "*")
        return f"{verb} {resource} ({api_group})"
    if namespace:
        return f"{kind}:{namespace}/{name}"
    return f"{kind}:{name}"


def _edge_priority(graph: nx.DiGraph, left: str, right: str, edge_risk: Mapping[str, float]) -> tuple[float, str]:
    attrs = graph.edges[left, right]
    relation = attrs.get("relation", "")
    target = graph.nodes[right]
    target_bonus = float(target.get("criticality", 0))
    return (edge_risk.get(relation, 1.0) + target_bonus, right)


def _score_path(graph: nx.DiGraph, nodes: list[str], edge_risk: Mapping[str, float]) -> float:
    edge_score = sum(edge_risk.get(graph.edges[left, right].get("relation", ""), 1.0) for left, right in zip(nodes, nodes[1:]))
    criticality = float(graph.nodes[nodes[-1]].get("criticality", 5))
    public_bonus = 2.0 if graph.nodes[nodes[0]].get("public") else 0.0
    return edge_score + criticality + public_bonus


def _headline(graph: nx.DiGraph, nodes: list[str]) -> str:
    source = graph.nodes[nodes[0]]
    target = graph.nodes[nodes[-1]]
    return (
        f"Public workload {source.get('name', nodes[0])} can reach "
        f"{target.get('kind', 'asset')} {target.get('name', nodes[-1])}"
    )


def explain_path(graph: nx.DiGraph, path: AttackPath) -> dict:
    evidence = []
    for left, right in zip(path.nodes, path.nodes[1:]):
        edge = graph.edges[left, right]
        evidence.append(
            {
                "from": _node_label(graph, left),
                "to": _node_label(graph, right),
                "relation": edge.get("relation", "connected_to"),
                "label": EDGE_LABELS.get(edge.get("relation", ""), edge.get("relation", "connected to")),
                "why": edge.get("rationale", ""),
            }
        )
    return {
        "headline": path.headline or _headline(graph, path.nodes),
        "score": round(path.score, 2),
        "steps": evidence,
        "path": path.nodes,
    }


def find_attack_paths(
    graph: nx.DiGraph,
    max_paths: int = 50,
    max_depth: int | None = None,
    *,
    entry_kinds: Sequence[str] = ("workload",),
    capability_domain: Sequence[CapabilityKind] | None = None,
    conservative: bool = True,
    edge_risk: Mapping[str, float] | None = None,
) -> list[AttackPath]:
    """Enumerate distinct simple attack paths from entry nodes to crown jewels.

    Capability-aware: each partial path carries the capabilities accumulated so far, and
    an edge is only descended if its Guard is traversable given those capabilities. With
    ``capability_domain=None`` and open/absent guards (Kubernetes today) every edge is
    traversable and no capabilities accumulate, so the result is identical to the previous
    implementation — the golden tests are the proof of that equivalence.
    """
    if max_paths <= 0:
        return []

    max_depth = max_depth or DEFAULT_MAX_PATH_DEPTH
    edge_risk = edge_risk if edge_risk is not None else EDGE_RISK
    domain = None if capability_domain is None else validate_capability_domain(capability_domain)

    targets = set(crown_jewel_nodes(graph))
    if not targets:
        return []

    discovered: list[AttackPath] = []
    seen_paths: set[tuple[str, ...]] = set()

    for source in sorted(entry_nodes(graph, entry_kinds)):
        # each stack item is (path, accumulated capabilities)
        stack: list[tuple[list[str], frozenset[Capability]]] = [([source], frozenset())]
        while stack and len(discovered) < max_paths:
            current_path, caps = stack.pop()
            current = current_path[-1]
            if len(current_path) - 1 >= max_depth:
                continue

            successors = sorted(
                graph.successors(current),
                key=lambda node: _edge_priority(graph, current, node, edge_risk),
                reverse=True,
            )
            for successor in successors:
                if successor in current_path:
                    continue
                guard = _edge_guard(graph, current, successor)
                if domain is not None:
                    _assert_guard_within_domain(guard, domain)
                if not _guard_is_traversable(guard, caps, conservative=conservative):
                    continue
                next_caps = caps | frozenset(guard.grants)
                next_path = current_path + [successor]
                path_key = tuple(next_path)
                if successor in targets:
                    if path_key in seen_paths:
                        continue
                    score = _score_path(graph, next_path, edge_risk)
                    discovered.append(
                        AttackPath(
                            nodes=next_path,
                            score=score,
                            relations=[graph.edges[left, right].get("relation", "") for left, right in zip(next_path, next_path[1:])],
                            headline=_headline(graph, next_path),
                        )
                    )
                    seen_paths.add(path_key)
                    if len(discovered) >= max_paths:
                        break
                    continue
                if len(next_path) - 1 < max_depth:
                    stack.append((next_path, next_caps))

    discovered.sort(key=lambda item: (-item.score, len(item.nodes), item.nodes))
    return discovered[:max_paths]


def path_summary(paths: Iterable[AttackPath]) -> list[str]:
    return [path.headline or " -> ".join(path.nodes) for path in paths]


# --------------------------------------------------------------------------- #
# Incremental reachability index
# --------------------------------------------------------------------------- #


class ReachabilityIndex:
    """Precomputes the baseline attack paths once and indexes the edges/nodes each path
    crosses, so ``apply_and_recount`` counts survivors by filtering the precomputed set
    instead of re-searching the graph.

    Correctness: removing edges or nodes can only DESTROY paths, never create new ones, so
    the survivors after a removal are exactly the precomputed paths that avoid every
    removed edge/node — provided the baseline enumeration was complete (i.e. the path cap
    did not bind). The optimizer builds the index with the same ``max_paths`` it uses for
    baselining, so it stays consistent with ``find_attack_paths``.
    """

    __slots__ = ("_graph", "_paths", "_path_edges", "_path_nodes", "_max_paths", "_max_depth")

    def __init__(
        self,
        graph: nx.DiGraph,
        *,
        max_paths: int = 50,
        max_depth: int | None = None,
        entry_kinds: Sequence[str] = ("workload",),
    ) -> None:
        # Sanctioned deviation (Fase 5): entry_kinds is plumbed through to find_attack_paths so
        # non-Kubernetes providers (e.g. AWS entries are "compute") can be baselined. Default
        # ("workload",) preserves Kubernetes behavior and the golden. The search LOGIC below
        # (find_attack_paths, dominance, apply_and_recount) is unchanged.
        self._graph = graph
        self._max_paths = max_paths
        self._max_depth = max_depth
        self._paths = find_attack_paths(graph, max_paths=max_paths, max_depth=max_depth, entry_kinds=entry_kinds)
        self._path_edges = [frozenset(zip(p.nodes, p.nodes[1:])) for p in self._paths]
        self._path_nodes = [frozenset(p.nodes) for p in self._paths]

    def paths(self) -> list[AttackPath]:
        return list(self._paths)

    def baseline_count(self) -> int:
        return len(self._paths)

    def incident_edges(self, node: str) -> list[tuple[str, str]]:
        if not self._graph.has_node(node):
            return []
        return [(node, s) for s in self._graph.successors(node)] + [(p, node) for p in self._graph.predecessors(node)]

    def apply_and_recount(
        self,
        removed_edges: Iterable[tuple[str, str]] = (),
        modified_guards: Iterable[tuple[tuple[str, str], Guard]] = (),
        *,
        removed_nodes: Iterable[str] = (),
    ) -> int:
        """Remaining attack-path count after removing edges/nodes (and, for guard-based
        remediation, tightening guards). Only the precomputed paths touched by the change
        are re-evaluated."""
        removed_edge_set = set(removed_edges)
        removed_node_set = set(removed_nodes)
        for node in removed_node_set:
            removed_edge_set.update(self.incident_edges(node))
        guard_overrides = dict(modified_guards)

        remaining = 0
        for idx, _path in enumerate(self._paths):
            if self._path_nodes[idx] & removed_node_set:
                continue
            if self._path_edges[idx] & removed_edge_set:
                continue
            if guard_overrides and not self._path_survives_guards(idx, guard_overrides):
                continue
            remaining += 1
        return remaining

    def _path_survives_guards(self, idx: int, guard_overrides: dict[tuple[str, str], Guard]) -> bool:
        """Re-evaluate capability feasibility along one path with tightened guards. For the
        Kubernetes case (no capabilities) there are no overrides, so this is never reached;
        AWS guard-based remediation (Fase 5) exercises it."""
        nodes = self._paths[idx].nodes
        caps: frozenset[Capability] = frozenset()
        for left, right in zip(nodes, nodes[1:]):
            guard = guard_overrides.get((left, right)) or _edge_guard(self._graph, left, right)
            if not _guard_is_traversable(guard, caps, conservative=True):
                return False
            caps = caps | frozenset(guard.grants)
        return True
