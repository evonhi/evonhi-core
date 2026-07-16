"""KubernetesProvider (Fase 4, multi-cloud refactor).

Isolates Kubernetes behind the GraphProvider Protocol. build_graph delegates to the indexed
builder and returns the same byte-identical nx.DiGraph the pipeline already consumes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import networkx as nx

from evonhi_core.graph.contract import CapabilityKind
from evonhi_core.providers.kubernetes.builder import build_attack_graph
from evonhi_core.providers.kubernetes.resolver import KubernetesEffectivePolicyResolver

if TYPE_CHECKING:
    from evonhi_core.models import ScenarioConfig
    from evonhi_core.providers.kubernetes.model import ClusterModel
    from evonhi_core.resolution.base import EffectivePolicyResolver


class KubernetesProvider:
    """Graph-side Kubernetes provider. Structurally conforms to GraphProvider.

    TODO (tech debt, multi-cloud refactor): migrate build_graph to construct through
    CanonicalGraph.add_permission_edge like AwsProvider does (Fase 5), so effective-permission
    resolution is structurally enforced here too. It currently emits a byte-identical raw
    nx.DiGraph to protect the S1-S4 golden; the migration must move together with the
    downstream consumers (path_analysis/reporting/remediation) that read K8s edge attrs, and
    re-baseline the golden if edge attrs (guard/weight) change.
    """

    name: str = "kubernetes"
    entry_node_kinds: tuple[str, ...] = ("workload",)
    capability_domain: tuple[CapabilityKind, ...] = ()  # RBAC carries no capability conditions

    def __init__(self) -> None:
        self._resolver = KubernetesEffectivePolicyResolver()

    def resolver(self) -> "EffectivePolicyResolver":
        return self._resolver

    def build_graph(self, model: "ClusterModel", scenario: "ScenarioConfig") -> nx.DiGraph:
        return build_attack_graph(model, scenario)
