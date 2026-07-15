"""Back-compat shim (Fase 2, multi-cloud refactor).

The path-analysis implementation moved to ``evonhi_core.traversal.stateful_search`` when
the DFS was replaced by capability-aware traversal. This module keeps the public import
path frozen so consumers (e.g. evo_saas) do not change: ``from evonhi_core.path_analysis
import find_attack_paths, explain_path, path_summary``.
"""

from __future__ import annotations

from evonhi_core.traversal.stateful_search import (  # noqa: F401  (re-export shim)
    DEFAULT_MAX_PATH_DEPTH,
    EDGE_LABELS,
    EDGE_RISK,
    ReachabilityIndex,
    crown_jewel_nodes,
    entry_nodes,
    explain_path,
    find_attack_paths,
    path_summary,
)

__all__ = [
    "find_attack_paths",
    "explain_path",
    "path_summary",
    "entry_nodes",
    "crown_jewel_nodes",
    "ReachabilityIndex",
    "EDGE_RISK",
    "EDGE_LABELS",
    "DEFAULT_MAX_PATH_DEPTH",
]
