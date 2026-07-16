"""Remediation and impact interfaces (Fase 3, multi-cloud refactor).

These are the *interfaces* only; the concrete, telemetry-driven implementations live in
evo_saas (the private moat) and are registered at runtime. Per the multi-cloud plan the
open-core package publishes the contract, not the moat.

They are declared as ``typing.Protocol`` (structural typing) decorated with
``@runtime_checkable`` so a provider conforms by shape — no inheritance required — and can
be validated at runtime with ``isinstance``. Note ``runtime_checkable`` only verifies
method *presence*, not signatures; the contract test additionally checks signatures with
``inspect.signature``.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

import networkx as nx

from evonhi_core.models import RemediationAction
from evonhi_core.traversal.stateful_search import ReachabilityIndex


@runtime_checkable
class RemediationGenerator(Protocol):
    """Produces candidate remediation actions from a graph and the provider's model."""

    def generate(self, graph: nx.DiGraph, provider_model: Any) -> list[RemediationAction]: ...


@runtime_checkable
class RemediationApplicator(Protocol):
    """Applies selected actions against a ReachabilityIndex and returns remaining paths.

    ``remove_edge``/``remove_node`` cut edges and recount; ``modify_guard`` does not cut the
    edge — it tightens the guard (adds ``required=[...]``) and lets the stateful traversal
    decide efficacy. Returns the remaining attack-path count via ``apply_and_recount``."""

    def apply(self, reach_index: ReachabilityIndex, selected_ids: list[str]) -> int: ...


@runtime_checkable
class ImpactEstimator(Protocol):
    """Computes the operational impact of an action from runtime/telemetry context.

    With telemetry, impact reflects real usage (a permission used 10k/day -> high; unused for
    90 days -> near zero). Without telemetry (confidence == 0) it falls back to the
    conservative table value, reproducing pre-telemetry behavior."""

    def estimate(self, action: RemediationAction, runtime_context: Mapping[str, Any]) -> float: ...


@runtime_checkable
class RemediationProvider(RemediationGenerator, RemediationApplicator, ImpactEstimator, Protocol):
    """A provider that satisfies all three remediation Protocols (generate/apply/estimate)."""


# Aliases used by the evo_saas contract test for explicit structural isinstance checks.
RemediationGeneratorProtocol = RemediationGenerator
RemediationApplicatorProtocol = RemediationApplicator
ImpactEstimatorProtocol = ImpactEstimator
RemediationProviderProtocol = RemediationProvider
