from __future__ import annotations

from typing import Iterable

import networkx as nx

from app.config import settings
from app.domain.analysis_models import AttackPath

EDGE_RISK = {
    "uses_token": 2.0,
    "mounted_secret": 6.0,
    "granted_permission": 3.0,
    "read_secret": 8.0,
    "spawn_workload_as": 7.0,
}
EDGE_LABELS = {
    "uses_token": "uses service account token",
    "mounted_secret": "reads mounted secret",
    "granted_permission": "is granted permission",
    "read_secret": "can read secret",
    "spawn_workload_as": "can pivot into another service account",
}


def entry_nodes(graph: nx.DiGraph) -> list[str]:
    return [node for node, attrs in graph.nodes(data=True) if attrs.get("kind") == "workload" and attrs.get("public")]


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


def _edge_priority(graph: nx.DiGraph, left: str, right: str) -> tuple[float, str]:
    attrs = graph.edges[left, right]
    relation = attrs.get("relation", "")
    target = graph.nodes[right]
    target_bonus = float(target.get("criticality", 0))
    return (EDGE_RISK.get(relation, 1.0) + target_bonus, right)


def _score_path(graph: nx.DiGraph, nodes: list[str]) -> float:
    edge_score = sum(EDGE_RISK.get(graph.edges[left, right].get("relation", ""), 1.0) for left, right in zip(nodes, nodes[1:]))
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


def find_attack_paths(graph: nx.DiGraph, max_paths: int = 50, max_depth: int | None = None) -> list[AttackPath]:
    if max_paths <= 0:
        return []

    max_depth = max_depth or settings.max_path_depth
    targets = set(crown_jewel_nodes(graph))
    if not targets:
        return []

    discovered: list[AttackPath] = []
    seen_paths: set[tuple[str, ...]] = set()

    for source in sorted(entry_nodes(graph)):
        stack: list[list[str]] = [[source]]
        while stack and len(discovered) < max_paths:
            current_path = stack.pop()
            current = current_path[-1]
            if len(current_path) - 1 >= max_depth:
                continue

            successors = sorted(graph.successors(current), key=lambda node: _edge_priority(graph, current, node), reverse=True)
            for successor in successors:
                if successor in current_path:
                    continue
                next_path = current_path + [successor]
                path_key = tuple(next_path)
                if successor in targets:
                    if path_key in seen_paths:
                        continue
                    score = _score_path(graph, next_path)
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
                    stack.append(next_path)

    discovered.sort(key=lambda item: (-item.score, len(item.nodes), item.nodes))
    return discovered[:max_paths]


def path_summary(paths: Iterable[AttackPath]) -> list[str]:
    return [path.headline or " -> ".join(path.nodes) for path in paths]
