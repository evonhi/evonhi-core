"""KubernetesProvider + resolver tests (Fase 4, multi-cloud refactor)."""

from __future__ import annotations

import networkx as nx
import pytest

from evonhi_core.graph_builder import build_attack_graph
from evonhi_core.providers.base import GraphProvider
from evonhi_core.providers.kubernetes.provider import KubernetesProvider
from evonhi_core.resolution.base import EffectivePermissionSet, EffectivePolicyResolver
from tests.scenarios import ALL_SCENARIOS


def test_provider_conforms_to_graph_provider_protocol():
    provider = KubernetesProvider()
    assert isinstance(provider, GraphProvider)  # runtime_checkable structural check
    assert provider.name == "kubernetes"
    assert provider.entry_node_kinds == ("workload",)
    assert provider.capability_domain == ()
    assert isinstance(provider.resolver(), EffectivePolicyResolver)


@pytest.mark.parametrize("name", sorted(ALL_SCENARIOS))
def test_build_graph_matches_shim(name: str):
    model, scenario = ALL_SCENARIOS[name]()
    provider = KubernetesProvider()
    via_provider = provider.build_graph(model, scenario)
    via_shim = build_attack_graph(model, scenario)
    assert isinstance(via_provider, nx.DiGraph)
    assert set(via_provider.nodes) == set(via_shim.nodes)
    assert set(via_provider.edges) == set(via_shim.edges)


@pytest.mark.parametrize("name", sorted(ALL_SCENARIOS))
def test_resolver_grants_match_granted_permission_edges(name: str):
    model, scenario = ALL_SCENARIOS[name]()
    provider = KubernetesProvider()
    resolved = provider.resolver().resolve(model)
    assert isinstance(resolved, EffectivePermissionSet)

    graph = build_attack_graph(model, scenario)
    granted_edges = [(u, v) for u, v, a in graph.edges(data=True) if a.get("relation") == "granted_permission"]
    # One effective permission per granted_permission edge (RBAC has no Deny/ceilings).
    assert len(list(resolved)) == len(granted_edges)
    resolved_pairs = {(p.source, p.target) for p in resolved}
    assert resolved_pairs == set(granted_edges)
