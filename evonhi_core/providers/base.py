"""Graph-provider interface (Fase 4, multi-cloud refactor).

For architectural symmetry with the remediation interfaces (Fase 3), GraphProvider is a
``typing.Protocol`` decorated with ``@runtime_checkable`` — providers conform structurally
(no inheritance) and can be validated with ``isinstance``.

``build_graph`` returns a plain ``nx.DiGraph`` (what the traversal/optimization/reporting
layers consume). CanonicalGraph remains an internal construction aid a provider may use;
the Kubernetes provider emits a byte-identical nx.DiGraph directly to keep the golden intact.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import networkx as nx

if TYPE_CHECKING:
    from evonhi_core.graph.contract import CapabilityKind
    from evonhi_core.resolution.base import EffectivePolicyResolver


@runtime_checkable
class GraphProvider(Protocol):
    """Builds the attack graph for one cloud/platform from its own rich model."""

    name: str
    entry_node_kinds: tuple[str, ...]
    capability_domain: tuple["CapabilityKind", ...]

    def resolver(self) -> "EffectivePolicyResolver": ...

    def build_graph(self, model: Any, scenario: Any) -> nx.DiGraph: ...
