"""Mandatory traversal acceptance tests (Fase 2, multi-cloud refactor).

Covers three of the four mandatory criteria:
  (a) dominance keeps only the non-dominated capability set at a shared node,
  (b) a 50k-node synthetic graph keeps |memo| a small multiple of nodes (no 2^k blow-up),
  (c) the closed capability domain structurally rejects an out-of-domain capability.

The fourth (apply_and_recount == recompute-from-scratch on S4, and faster) needs the S4
manifests and lives in evo_saas/tests/test_incremental_recount.py.
"""

from __future__ import annotations

import networkx as nx
import pytest

from evonhi_core.graph.contract import Capability, CapabilityKind, Guard, GuardStatus, open_guard
from evonhi_core.traversal.stateful_search import reachable_states, validate_capability_domain


def _grant_guard(*caps: Capability) -> Guard:
    return Guard(required=[], grants=list(caps), static_status=GuardStatus.OPEN.value)


# --------------------------------------------------------------------------- #
# (a) dominance retains only the non-dominated set
# --------------------------------------------------------------------------- #


def test_a_dominance_retains_only_non_dominated_set():
    np_cap = Capability(CapabilityKind.NETWORK_POSITION, "10.0.0.0/8")
    g = nx.DiGraph()
    # A reaches X granting NETWORK_POSITION; B reaches X with nothing.
    g.add_edge("A", "X", guard=_grant_guard(np_cap))
    g.add_edge("B", "X", guard=open_guard())

    memo = reachable_states(g, entry_nodes=["A", "B"], capability_domain=[CapabilityKind.NETWORK_POSITION])

    # X was reached with {} (via B) and with {NETWORK_POSITION} (via A). {} is dominated by
    # {NETWORK_POSITION}, so only the maximal set survives.
    assert len(memo["X"]) == 1
    assert memo["X"][0] == frozenset({np_cap})
    # sanity: the empty set never lingers at X
    assert frozenset() not in memo["X"]


def test_a_incomparable_sets_are_both_retained():
    np_cap = Capability(CapabilityKind.NETWORK_POSITION, "x")
    mfa_cap = Capability(CapabilityKind.MFA, "y")
    g = nx.DiGraph()
    g.add_edge("A", "X", guard=_grant_guard(np_cap))
    g.add_edge("B", "X", guard=_grant_guard(mfa_cap))

    memo = reachable_states(
        g, entry_nodes=["A", "B"], capability_domain=[CapabilityKind.NETWORK_POSITION, CapabilityKind.MFA]
    )
    # {NP} and {MFA} are incomparable -> both retained (neither dominates the other).
    assert {frozenset({np_cap}), frozenset({mfa_cap})} == set(memo["X"])


# --------------------------------------------------------------------------- #
# (b) 50k-node graph: |memo| stays a small multiple of nodes, far from nodes*2^k
# --------------------------------------------------------------------------- #


def test_b_fifty_thousand_nodes_memo_stays_bounded():
    k = 5
    domain = [
        CapabilityKind.NETWORK_POSITION,
        CapabilityKind.PRINCIPAL_TAG,
        CapabilityKind.ORG_MEMBERSHIP,
        CapabilityKind.REGION,
        CapabilityKind.MFA,
    ]
    caps = [Capability(kind, "v") for kind in domain]

    g = nx.DiGraph()
    # k entry nodes, each granting one distinct capability into a shared spine head.
    entries = [f"entry:{i}" for i in range(k)]
    for i, cap in enumerate(caps):
        g.add_edge(entries[i], "spine:0", guard=_grant_guard(cap))

    # A long shared spine. Each spine node is reachable with up to k incomparable singleton
    # sets; without dominance the frontier would explode toward nodes * 2^k.
    spine_len = 50_000
    for j in range(spine_len - 1):
        g.add_edge(f"spine:{j}", f"spine:{j + 1}", guard=open_guard())

    total_nodes = g.number_of_nodes()
    assert total_nodes >= 50_000

    memo = reachable_states(g, entry_nodes=entries, capability_domain=domain)
    total_states = sum(len(v) for v in memo.values())

    # O(k * nodes), NOT O(2^k * nodes).
    assert total_states <= (k + 1) * total_nodes, "memo grew beyond a small multiple of nodes"
    explosion = total_nodes * (2 ** k)
    assert total_states < explosion / 4, "memo is approaching the nodes * 2^k blow-up"
    # each spine node holds at most k distinct maximal sets
    assert max(len(v) for v in memo.values()) <= k


# --------------------------------------------------------------------------- #
# (c) closed domain structurally rejects an out-of-domain capability
# --------------------------------------------------------------------------- #


def test_c_guard_with_out_of_domain_capability_is_rejected():
    region_cap = Capability(CapabilityKind.REGION, "us-east-1")
    g = nx.DiGraph()
    # The declared domain is {NETWORK_POSITION}, but this edge's guard grants REGION.
    g.add_edge("A", "X", guard=_grant_guard(region_cap))

    with pytest.raises(ValueError, match="outside the declared closed domain"):
        reachable_states(g, entry_nodes=["A"], capability_domain=[CapabilityKind.NETWORK_POSITION])


def test_c_domain_larger_than_limit_is_rejected():
    with pytest.raises(ValueError, match="closed-domain limit"):
        validate_capability_domain(list(CapabilityKind), limit=3)


def test_c_required_capability_out_of_domain_is_rejected():
    org_cap = Capability(CapabilityKind.ORG_MEMBERSHIP, "o-123")
    g = nx.DiGraph()
    g.add_edge("A", "X", guard=Guard(required=[org_cap], grants=[], static_status=GuardStatus.CONDITIONAL.value))
    with pytest.raises(ValueError, match="outside the declared closed domain"):
        reachable_states(g, entry_nodes=["A"], capability_domain=[CapabilityKind.NETWORK_POSITION])
