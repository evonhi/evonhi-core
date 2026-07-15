"""Back-compat shim (Fase 2, multi-cloud refactor).

The optimizer moved to ``evonhi_core.optimization.optimizer``. This keeps the public
import path frozen so consumers (e.g. evo_saas) do not change: ``from evonhi_core.optimizer
import optimize_actions``.

Note the ApplyActions contract changed in Fase 2 (returns int via ReachabilityIndex.
apply_and_recount, no longer an nx.DiGraph) — see optimization/optimizer.py.
"""

from __future__ import annotations

from evonhi_core.optimization.optimizer import (  # noqa: F401  (re-export shim)
    ApplyActions,
    optimize_actions,
)

__all__ = ["optimize_actions", "ApplyActions"]
