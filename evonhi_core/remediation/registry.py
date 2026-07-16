"""Runtime registry for provider remediation implementations (Fase 3).

evo-core ships the interfaces; evo_saas registers its concrete (moat) providers at import
time. The graph-side provider registry lives separately under ``providers/`` (Fase 4/6)."""

from __future__ import annotations

from evonhi_core.remediation.base import RemediationProvider

_REGISTRY: dict[str, RemediationProvider] = {}


def register_remediation_provider(name: str, provider: RemediationProvider) -> None:
    _REGISTRY[name] = provider


def get_remediation_provider(name: str) -> RemediationProvider:
    if name not in _REGISTRY:
        raise ValueError(f"Unknown remediation provider: {name!r} (registered: {sorted(_REGISTRY)})")
    return _REGISTRY[name]


def registered_remediation_providers() -> tuple[str, ...]:
    return tuple(_REGISTRY)
