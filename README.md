<div align="center">
  <h1>EvoNHI Core</h1>
  <p><b>Attack-graph, risk and remediation-planning engine for non-human identities</b></p>

  [![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

<br/>

**EvoNHI Core** is the open-source mathematical engine behind the EvoNHI platform. It models Non-Human Identities (NHIs) — Kubernetes service accounts and RBAC, AWS IAM roles and policies — as attack graphs, measures the residual risk to your crown jewels exactly, and computes budget-aware remediation plans with a decomposed, memetic multi-objective optimizer (NSGA-II at its core, exact wherever the problem allows it).

Unlike static YAML linters, this engine reasons about **privilege transitivity** (e.g., how a `create pods` permission acts as a pivot to assume any ServiceAccount in a namespace) and evaluates remediations based on their implementation cost and operational impact.

---

## What it does

Given a cloud-native environment (Kubernetes RBAC today, AWS IAM in preview) and the assets you care
about most ("crown jewels"), EvoNHI Core:

1. **Builds an attack graph** of non-human identities: workloads, service accounts / IAM roles, effective
   permissions and secrets — including privilege transitivity such as `create pods` → act as any service
   account in the namespace, or `sts:AssumeRole` chains that survive SCPs and explicit Denies.
2. **Measures residual risk exactly.** For every (entry point, crown jewel) pair it computes the cheapest
   attacker effort; likelihoods are aggregated per jewel with a noisy-OR and weighted by criticality. No path
   enumeration, no path cap, no ordering bias — and partial credit for changes that make an attack *harder*
   (e.g. adding an `aws:SourceIp` condition) rather than impossible.
3. **Plans remediation under a budget.** It searches the combinations of candidate changes that minimize
   residual risk, cost and operational impact at the same time, and returns a few distinct plans
   (max reduction, balanced, low disruption, quick win), each as an ordered implementation sequence, plus
   the full budget/risk curve.

### How the planner works (v2)

| Stage | Technique | Why |
|---|---|---|
| Relevance pruning | forward ∩ backward reachability | only edges on some entry → jewel route matter |
| Action reduction | effect-dominance filtering | an action covered by a cheaper, less disruptive one never helps |
| Decomposition | weakly-connected components | risk is additive over jewels; independent parts are solved separately |
| Small components | exact enumeration with budget pruning | provably optimal Pareto front |
| Large components | memetic NSGA-II: greedy-ladder, min-cut and per-jewel-cut seeding, budget repair, elitist archive, redundancy elimination | high-quality fronts where exhaustive search is impossible |
| Global plan | multi-choice knapsack DP over component fronts | exact combination; reports `optimality: exact` when every part was exact |
| Evaluation | per-jewel reverse Dijkstra with shortest-path-DAG skipping and per-region caching; label-setting search when guards grant capabilities | thousands of evaluations per second in pure Python |

`tests/test_planner.py` checks the risk evaluator against a naive networkx reference and the search
against brute force (including the evolutionary path).

### v1 vs v2 (`python benchmarks/planner_v1_vs_v2.py`)

| scenario | budget | actions | baseline exposures | v1 exposures left | v2 exposures left | v1 risk left | v2 risk left | v2 optimality |
|---|---|---|---|---|---|---|---|---|
| 50 namespaces | 20 | 600 | 50 | 49 | **40** | 90.1 | **73.6** | exact |
| 200 namespaces | 20 | 2400 | 200 | 199 | **190** | 366.0 | **349.5** | exact |
| 200 ns + cluster-wide operator | 20 | 2401 | 399 | 199 | **190** | 366.0 | **349.5** | heuristic |
| 200 namespaces | ∞ | 2400 | 200 | 63 | **0** | 115.9 | **0.0** | exact |

v1 counted at most 50 paths, enumerated in alphabetical order of entry points (the rest of the cluster was
invisible) and initialized its population densely, so almost every genome exceeded the budget.

## Quick usage

```bash
pip install "evonhi-core @ git+https://github.com/gnazinu/evonhi-core.git@v0.2.0"
```

```python
from evonhi_core import build_attack_graph, plan_remediation
from evonhi_core.models import CrownJewelSpec, RemediationAction, ScenarioConfig

graph = build_attack_graph(cluster_model, ScenarioConfig(crown_jewels=[CrownJewelSpec("secret", "db-creds", "payments")]))

# Candidate changes come from your own catalog (the hosted platform generates them with runtime telemetry).
actions = [
    RemediationAction("disable-token::web", "Disable automounted token on web", "", cost=2, impact=1.0,
                      action_type="edge_removal", target_edges=[("workload:payments:web", "serviceaccount:payments:web")]),
]

result = plan_remediation(graph, actions, budget=10)
print(result.baseline_risk, result.baseline_exposures)
for plan in result.plans:
    print(plan.strategy, plan.cost, f"{plan.risk_reduction_ratio:.0%}", [step.action_id for step in plan.steps])
```

`optimize_actions` (v1) is still importable for backward compatibility, emits a `DeprecationWarning` and will be
removed in 0.3.

---

## Relationship with EvoNHI Enterprise

This core library provides graph construction, risk evaluation and remediation planning. It performs no I/O.

The commercial control plane (EvoNHI Enterprise) imports this engine and surrounds it with:

- Multi-tenant PostgreSQL architecture.
- Asynchronous distributed workers.
- Runtime telemetry ingestion to dynamically adjust the operational impact weights ($\delta\_{runtime}$).
- Multi-cloud ingestion and continuous re-analysis.

By keeping the core algorithms open-source, security teams can fully audit the mathematical models generating their remediation plans.

---

## Contributing

Contributions focused on performance optimizations (especially parallelization of the graph traversal) and the formalization of new cloud-native edge semantics are welcome. Please open an issue before submitting major structural pull requests.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.