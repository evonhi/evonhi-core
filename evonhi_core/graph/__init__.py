"""Canonical attack-graph contract and container."""

from __future__ import annotations

from evonhi_core.graph.canonical_graph import CanonicalGraph
from evonhi_core.graph.contract import (
    PERMISSION_RELATIONS,
    STRUCTURAL_RELATIONS,
    Capability,
    CapabilityKind,
    EdgeRelation,
    Guard,
    GuardStatus,
    NodeKind,
    UnresolvedPermissionError,
    open_guard,
)

__all__ = [
    "CanonicalGraph",
    "NodeKind",
    "EdgeRelation",
    "CapabilityKind",
    "Capability",
    "Guard",
    "GuardStatus",
    "open_guard",
    "PERMISSION_RELATIONS",
    "STRUCTURAL_RELATIONS",
    "UnresolvedPermissionError",
]
