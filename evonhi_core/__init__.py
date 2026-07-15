"""EvoNHI Open Core — pure attack-graph and optimization engine.

This module re-exports the stable public API so downstream consumers (e.g. evo_saas)
can import from ``evonhi_core`` directly. The individual submodules
(``evonhi_core.graph_builder``, ``evonhi_core.path_analysis``, ``evonhi_core.optimizer``,
``evonhi_core.models``) remain importable and are the current integration surface; the
multi-cloud refactor keeps them as thin shims so this surface stays frozen.
"""

from __future__ import annotations

from evonhi_core.graph_builder import build_attack_graph, node_id, permission_id
from evonhi_core.models import (
    AttackPath,
    ClusterModel,
    CrownJewelSpec,
    Metadata,
    NetworkPolicy,
    PlanEvaluation,
    PolicyRule,
    RemediationAction,
    Role,
    RoleBinding,
    ScenarioConfig,
    Secret,
    ServiceAccount,
    SubjectRef,
    Workload,
)
from evonhi_core.optimizer import optimize_actions
from evonhi_core.path_analysis import explain_path, find_attack_paths, path_summary

__all__ = [
    # graph construction
    "build_attack_graph",
    "node_id",
    "permission_id",
    # path analysis
    "find_attack_paths",
    "explain_path",
    "path_summary",
    # optimization
    "optimize_actions",
    # generic + kubernetes model types
    "AttackPath",
    "ClusterModel",
    "CrownJewelSpec",
    "Metadata",
    "NetworkPolicy",
    "PlanEvaluation",
    "PolicyRule",
    "RemediationAction",
    "Role",
    "RoleBinding",
    "ScenarioConfig",
    "Secret",
    "ServiceAccount",
    "SubjectRef",
    "Workload",
]
