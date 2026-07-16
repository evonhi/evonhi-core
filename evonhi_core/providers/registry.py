"""Graph-provider registry (Fase 5/6, multi-cloud refactor)."""

from __future__ import annotations

from evonhi_core.providers.aws.provider import AwsProvider
from evonhi_core.providers.base import GraphProvider
from evonhi_core.providers.kubernetes.provider import KubernetesProvider

_GRAPH_PROVIDERS: dict[str, GraphProvider] = {p.name: p for p in (KubernetesProvider(), AwsProvider())}


def get_graph_provider(name: str) -> GraphProvider:
    if name not in _GRAPH_PROVIDERS:
        raise ValueError(f"Unknown graph provider: {name!r} (registered: {sorted(_GRAPH_PROVIDERS)})")
    return _GRAPH_PROVIDERS[name]


def registered_graph_providers() -> tuple[str, ...]:
    return tuple(_GRAPH_PROVIDERS)
