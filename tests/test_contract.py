"""Isolation tests for the canonical contract (Fase 1, multi-cloud refactor).

Covers the contract types, the CanonicalGraph container, and the central invariant:
add_permission_edge rejects any permission that did not come from a resolved
EffectivePermissionSet (i.e. effective-policy resolution cannot be bypassed).
"""

from __future__ import annotations

import pytest

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
from evonhi_core.resolution.base import (
    EffectivePermission,
    EffectivePermissionSet,
    EffectivePolicyResolver,
)

# --------------------------------------------------------------------------- #
# Contract types
# --------------------------------------------------------------------------- #


def test_spawn_workload_as_string_is_frozen():
    # golden tests depend on this exact relation string
    assert EdgeRelation.SPAWN_WORKLOAD_AS.value == "spawn_workload_as"


def test_permission_and_structural_relations_partition_the_enum():
    assert PERMISSION_RELATIONS.isdisjoint(STRUCTURAL_RELATIONS)
    assert PERMISSION_RELATIONS | STRUCTURAL_RELATIONS == set(EdgeRelation)


def test_capability_is_hashable_and_frozen():
    cap = Capability(CapabilityKind.NETWORK_POSITION, "10.0.0.0/8")
    # usable inside the frozenset[Capability] the stateful traversal accumulates
    assert cap in {cap}
    with pytest.raises(Exception):
        cap.value = "changed"  # frozen


def test_capability_domain_is_closed_and_small():
    # Fase 2 asserts len <= 8 at runtime; document the current closed domain here.
    assert len(CapabilityKind) <= 8


def test_open_guard_reproduces_default_open_behavior():
    g = open_guard("k8s has no conditions")
    assert g.is_open
    assert not g.is_conditional
    assert g.required == [] and g.grants == []
    assert Guard().static_status == GuardStatus.OPEN.value


# --------------------------------------------------------------------------- #
# CanonicalGraph — nodes and structural edges
# --------------------------------------------------------------------------- #


def test_add_identity_and_crown_jewel():
    cg = CanonicalGraph()
    cg.add_identity("identity:web-sa")
    cg.add_node("secret:db", NodeKind.SECRET, name="db")
    cg.mark_crown_jewel("secret:db", criticality=10, rationale="prod db")
    assert cg.identities() == ["identity:web-sa"]
    assert cg.crown_jewels() == ["secret:db"]


def test_mark_crown_jewel_on_unknown_node_raises():
    cg = CanonicalGraph()
    with pytest.raises(KeyError):
        cg.mark_crown_jewel("nope")


def test_add_containment_creates_contains_edge():
    cg = CanonicalGraph()
    cg.add_scope("scope:ns")
    cg.add_identity("identity:sa")
    cg.add_containment("scope:ns", "identity:sa")
    g = cg.to_digraph()
    assert g.edges["scope:ns", "identity:sa"]["relation"] == EdgeRelation.CONTAINS.value


def test_add_structural_edge_rejects_permission_relation():
    cg = CanonicalGraph()
    cg.add_identity("a")
    cg.add_node("b", NodeKind.SECRET)
    with pytest.raises(ValueError):
        cg.add_structural_edge("a", "b", EdgeRelation.READ_SECRET)


# --------------------------------------------------------------------------- #
# The invariant: permission edges must come from a resolved set
# --------------------------------------------------------------------------- #


def _perm(relation=EdgeRelation.READ_SECRET) -> EffectivePermission:
    return EffectivePermission(
        source="permission:p",
        target="secret:db",
        relation=relation,
        guard=open_guard(),
        weight=8.0,
        rationale="can read secret",
    )


def test_add_permission_edge_rejects_raw_object():
    cg = CanonicalGraph()
    with pytest.raises(UnresolvedPermissionError):
        cg.add_permission_edge({"source": "a", "target": "b", "relation": "read_secret"})


def test_add_permission_edge_rejects_unresolved_permission():
    cg = CanonicalGraph()
    raw = _perm()  # constructed directly, never went through EffectivePermissionSet
    assert raw._resolved is False
    with pytest.raises(UnresolvedPermissionError):
        cg.add_permission_edge(raw)


def test_add_permission_edge_accepts_resolved_permission():
    cg = CanonicalGraph()
    cg.add_node("permission:p", NodeKind.PERMISSION)
    cg.add_node("secret:db", NodeKind.SECRET)
    perm_set = EffectivePermissionSet([_perm()])
    (perm,) = list(perm_set)
    assert perm._resolved is True
    cg.add_permission_edge(perm)
    edge = cg.to_digraph().edges["permission:p", "secret:db"]
    assert edge["relation"] == EdgeRelation.READ_SECRET.value
    assert edge["weight"] == 8.0
    assert isinstance(edge["guard"], Guard)


def test_add_permission_edge_rejects_structural_relation_even_if_resolved():
    cg = CanonicalGraph()
    perm_set = EffectivePermissionSet([_perm(relation=EdgeRelation.USES_TOKEN)])
    (perm,) = list(perm_set)
    with pytest.raises(ValueError):
        cg.add_permission_edge(perm)


def test_add_permissions_iterates_resolved_set():
    cg = CanonicalGraph()
    cg.add_node("permission:p", NodeKind.PERMISSION)
    cg.add_node("secret:db", NodeKind.SECRET)
    cg.add_identity("identity:priv")
    perm_set = EffectivePermissionSet(
        [
            _perm(),
            EffectivePermission("permission:p", "identity:priv", EdgeRelation.PIVOT_IDENTITY, open_guard()),
        ]
    )
    cg.add_permissions(perm_set)
    assert cg.number_of_edges() == 2
    assert list(cg.permission_edges())  # both are permission edges


def test_effective_permission_set_rejects_non_permissions():
    with pytest.raises(TypeError):
        EffectivePermissionSet([{"not": "a permission"}])


# --------------------------------------------------------------------------- #
# End-to-end through a trivial concrete resolver
# --------------------------------------------------------------------------- #


class _StubResolver(EffectivePolicyResolver):
    """Trivial resolver: passes model tuples straight through (no Deny/ceilings)."""

    def resolve(self, provider_model) -> EffectivePermissionSet:
        return EffectivePermissionSet(
            EffectivePermission(src, dst, EdgeRelation.GRANTED_PERMISSION, open_guard())
            for (src, dst) in provider_model
        )


def test_resolver_output_feeds_canonical_graph():
    cg = CanonicalGraph()
    cg.add_identity("identity:sa")
    cg.add_node("permission:p", NodeKind.PERMISSION)
    resolved = _StubResolver().resolve([("identity:sa", "permission:p")])
    assert len(resolved) == 1
    cg.add_permissions(resolved)
    assert cg.number_of_edges() == 1
