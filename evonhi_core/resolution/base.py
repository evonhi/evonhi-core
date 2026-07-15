"""Effective-policy resolution interface (Fase 1, multi-cloud refactor).

Every provider resolves its own policy precedence BEFORE any canonical edge is built.
The resolver applies the provider's evaluation order and returns only the permissions
that survive, wrapped in an :class:`EffectivePermissionSet`. The canonical graph only
accepts permission edges that come from such a resolved set (see
``graph.canonical_graph.CanonicalGraph.add_permission_edge``), which makes it
structurally impossible to skip resolution and inject a raw (unresolved) permission.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from evonhi_core.graph.contract import EdgeRelation, Guard


@dataclass(slots=True)
class EffectivePermission:
    """A single effective permission = one prospective canonical permission edge.

    Produced only by a resolver (via :class:`EffectivePermissionSet`). The private
    ``_resolved`` flag is set when the permission passes through an
    ``EffectivePermissionSet``; the canonical graph checks it before creating an edge.
    """

    source: str                                   # source node id (e.g. an identity)
    target: str                                   # target node id (resource / permission / identity)
    relation: EdgeRelation                        # must be one of contract.PERMISSION_RELATIONS
    guard: Guard                                  # traversability contract for the edge
    weight: float = 1.0                           # scalar, for path scoring only
    rationale: str = ""
    _resolved: bool = field(default=False, repr=False, compare=False)


class EffectivePermissionSet:
    """An immutable, resolved collection of effective permissions.

    Constructing a set stamps every member as resolved. Only resolvers should build
    one; passing a hand-made ``EffectivePermission`` (or anything else) to the canonical
    graph is rejected because it never went through here.
    """

    __slots__ = ("_permissions",)

    def __init__(self, permissions: Iterable[EffectivePermission]) -> None:
        resolved: list[EffectivePermission] = []
        for perm in permissions:
            if not isinstance(perm, EffectivePermission):
                raise TypeError(
                    f"EffectivePermissionSet accepts EffectivePermission instances, got {type(perm)!r}"
                )
            perm._resolved = True
            resolved.append(perm)
        self._permissions = tuple(resolved)

    def __iter__(self) -> Iterator[EffectivePermission]:
        return iter(self._permissions)

    def __len__(self) -> int:
        return len(self._permissions)


class EffectivePolicyResolver(ABC):
    """Resolves effective permissions before edges are built. One per provider."""

    @abstractmethod
    def resolve(self, provider_model) -> EffectivePermissionSet:
        """Apply the provider's evaluation order and return the surviving permissions:

        1. Gather direct Allow plus Allow inherited through the scope hierarchy (CONTAINS).
        2. Subtract explicit Deny.
        3. Apply hierarchical ceilings (AWS SCP / Azure Deny Assignment / GCP Org Policy).

        Returns only the ``(source, target, relation, guard)`` tuples that survive, as an
        :class:`EffectivePermissionSet`. Kubernetes RBAC has no explicit Deny nor
        hierarchical ceilings, so its resolver is trivial and returns what the current
        builder produces.
        """
        raise NotImplementedError
