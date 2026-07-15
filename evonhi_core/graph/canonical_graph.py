"""CanonicalGraph — thin wrapper over ``nx.DiGraph`` (Fase 1, multi-cloud refactor).

Internally it is still an ``nx.DiGraph`` (exposed via :meth:`to_digraph`), so the
traversal and optimization layers keep operating on plain networkx. Its job is to make
the effective-permission invariant structural: :meth:`add_permission_edge` only accepts
permissions coming from a resolved ``EffectivePermissionSet``, so a builder cannot
create a permission edge that skipped effective-policy resolution.

Structural relations (USES_TOKEN, MOUNTED_SECRET, CONTAINS) are inherent and are added
through :meth:`add_structural_edge` / :meth:`add_containment` without resolution.
"""

from __future__ import annotations

from typing import Iterator

import networkx as nx

from evonhi_core.graph.contract import (
    PERMISSION_RELATIONS,
    STRUCTURAL_RELATIONS,
    EdgeRelation,
    Guard,
    NodeKind,
    UnresolvedPermissionError,
    open_guard,
)
from evonhi_core.resolution.base import EffectivePermission, EffectivePermissionSet


class CanonicalGraph:
    __slots__ = ("_g",)

    def __init__(self) -> None:
        self._g = nx.DiGraph()

    # -- nodes ---------------------------------------------------------------

    def add_node(self, node_id: str, kind: NodeKind, **attrs) -> str:
        self._g.add_node(node_id, kind=kind.value, **attrs)
        return node_id

    def add_identity(self, node_id: str, **attrs) -> str:
        return self.add_node(node_id, NodeKind.IDENTITY, **attrs)

    def add_scope(self, node_id: str, **attrs) -> str:
        return self.add_node(node_id, NodeKind.SCOPE, **attrs)

    def mark_crown_jewel(self, node_id: str, *, criticality: int = 10, rationale: str = "") -> None:
        if not self._g.has_node(node_id):
            raise KeyError(f"cannot mark unknown node as crown jewel: {node_id}")
        self._g.nodes[node_id]["crown_jewel"] = True
        self._g.nodes[node_id]["criticality"] = criticality
        self._g.nodes[node_id]["rationale"] = rationale

    # -- structural edges (no resolution) ------------------------------------

    def add_structural_edge(
        self,
        source: str,
        target: str,
        relation: EdgeRelation,
        *,
        guard: Guard | None = None,
        weight: float = 1.0,
        rationale: str = "",
        **attrs,
    ) -> None:
        if relation not in STRUCTURAL_RELATIONS:
            raise ValueError(
                f"{relation} is a permission relation; use add_permission_edge with a resolved permission"
            )
        self._g.add_edge(
            source,
            target,
            relation=relation.value,
            guard=guard or open_guard(),
            weight=weight,
            rationale=rationale,
            **attrs,
        )

    def add_containment(self, scope: str, child: str, *, rationale: str = "") -> None:
        """A CONTAINS edge propagating hierarchy (namespace->child, account->OU, ...).

        Inheritance along CONTAINS is resolved by the provider resolver, never by the
        traversal."""
        self.add_structural_edge(scope, child, EdgeRelation.CONTAINS, rationale=rationale)

    # -- permission edges (require resolution) -------------------------------

    def add_permission_edge(self, permission: EffectivePermission, **attrs) -> None:
        """Add an effective-permission edge. Rejects anything that did not come from a
        resolved EffectivePermissionSet, making it impossible to bypass resolution."""
        if not isinstance(permission, EffectivePermission):
            raise UnresolvedPermissionError(
                f"add_permission_edge requires an EffectivePermission, got {type(permission)!r}"
            )
        if not permission._resolved:
            raise UnresolvedPermissionError(
                "refusing to add an unresolved permission edge: the permission did not come "
                "from a resolved EffectivePermissionSet (effective-policy resolution was skipped)"
            )
        if permission.relation not in PERMISSION_RELATIONS:
            raise ValueError(
                f"{permission.relation} is not a permission relation; use add_structural_edge"
            )
        self._g.add_edge(
            permission.source,
            permission.target,
            relation=permission.relation.value,
            guard=permission.guard,
            weight=permission.weight,
            rationale=permission.rationale,
            **attrs,
        )

    def add_permissions(self, permission_set: EffectivePermissionSet, **attrs) -> None:
        """Add every effective permission in a resolved set."""
        if not isinstance(permission_set, EffectivePermissionSet):
            raise UnresolvedPermissionError(
                f"add_permissions requires an EffectivePermissionSet, got {type(permission_set)!r}"
            )
        for permission in permission_set:
            self.add_permission_edge(permission, **attrs)

    # -- typed accessors -----------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        return self._g.has_node(node_id)

    def nodes_of_kind(self, kind: NodeKind) -> list[str]:
        return [n for n, a in self._g.nodes(data=True) if a.get("kind") == kind.value]

    def identities(self) -> list[str]:
        return self.nodes_of_kind(NodeKind.IDENTITY)

    def crown_jewels(self) -> list[str]:
        return [n for n, a in self._g.nodes(data=True) if a.get("crown_jewel")]

    def permission_edges(self) -> Iterator[tuple[str, str, dict]]:
        for u, v, a in self._g.edges(data=True):
            if a.get("relation") in {r.value for r in PERMISSION_RELATIONS}:
                yield u, v, a

    def number_of_nodes(self) -> int:
        return self._g.number_of_nodes()

    def number_of_edges(self) -> int:
        return self._g.number_of_edges()

    def to_digraph(self) -> nx.DiGraph:
        """The underlying ``nx.DiGraph`` (the traversal/optimization layers use this)."""
        return self._g
