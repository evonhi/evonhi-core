"""Back-compat shim (Fase 4, multi-cloud refactor).

The Kubernetes graph builder moved to ``evonhi_core.providers.kubernetes`` when the
KubernetesProvider was extracted and the edge construction was indexed. This keeps the
public import path frozen: ``from evonhi_core.graph_builder import build_attack_graph``.
"""

from __future__ import annotations

from evonhi_core.providers.kubernetes.builder import (  # noqa: F401  (re-export shim)
    build_attack_graph,
    node_id,
    permission_id,
)
from evonhi_core.providers.kubernetes.semantics import (  # noqa: F401  (re-export shim)
    SECRET_READ_VERBS,
    WORKLOAD_API_GROUPS,
    WORKLOAD_MUTATION_VERBS,
)

__all__ = [
    "build_attack_graph",
    "node_id",
    "permission_id",
    "SECRET_READ_VERBS",
    "WORKLOAD_MUTATION_VERBS",
    "WORKLOAD_API_GROUPS",
]
