<div align="center">
  <h1>EvoNHI Core</h1>
  <p><b>Evolutionary Optimization Engine for Kubernetes Attack Paths</b></p>

  [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

<br/>

**EvoNHI Core** is the open-source mathematical engine behind the EvoNHI platform. It provides the foundational algorithms to model Kubernetes Non-Human Identities (NHIs) and RBAC configurations as directed attack graphs, computing optimal remediation strategies using Multi-Objective Evolutionary Optimization (NSGA-II).

Unlike static YAML linters, this engine reasons about **privilege transitivity** (e.g., how a `create pods` permission acts as a pivot to assume any ServiceAccount in a namespace) and evaluates remediations based on their implementation cost and operational impact.

---

## Core Modules

This repository isolates the pure computational logic from the SaaS infrastructure. It consists of three primary modules:

1. **`graph_builder.py`** — Translates Kubernetes resources (ServiceAccounts, Roles, RoleBindings, Secrets, Workloads) into a semantically weighted directed graph $G=(V,E,W)$. It maps specific attack primitives, including the critical `spawn_workload_as` vector.
2. **`path_analysis.py`** — Executes a bounded Depth-First Search (DFS) to discover all possible attack chains from public-facing workloads to defined cluster "crown jewels".
3. **`optimizer.py`** — Implements a tailored **NSGA-II** (Non-dominated Sorting Genetic Algorithm) to solve the NP-hard combinatorial problem of selecting which RBAC permissions to revoke or modify. It produces a Pareto front of plans balancing attack-surface reduction, operational impact, and cost.

---

## Quick Usage

EvoNHI Core is designed to be imported as a Python library into your own security pipelines or used as the backend for the EvoNHI SaaS.

### Installation

> **Note:** Currently, clone the repository to use the engine locally. PyPI package release pending.

```bash
git clone https://github.com/your-username/evonhi-core.git
cd evonhi-core
```

### Basic Example

```python
from evonhi_core.graph_builder import build_attack_graph
from evonhi_core.path_analysis import find_attack_paths
from evonhi_core.optimizer import optimize_actions

# 1. Build the semantic graph from your parsed cluster state
graph, actions = build_attack_graph(parsed_k8s_manifests, crown_jewels)

# 2. Discover existing transitive attack paths
initial_paths = find_attack_paths(graph, max_paths=100)
print(f"Discovered {len(initial_paths)} attack paths.")

# 3. Compute Pareto-optimal remediation plans
# Finds the best combinations of actions to reduce paths with minimal operational impact
pareto_front = optimize_actions(
    graph=graph,
    actions=actions,
    max_paths=100,
    population_size=40,
    generations=25
)

for plan in pareto_front:
    print(f"Cost: {plan.cost} | Impact: {plan.operational_impact} | Paths Remaining: {plan.remaining_paths}")
```

---

## Relationship with EvoNHI Enterprise

This core library provides static graph analysis and optimization.

The commercial control plane (EvoNHI Enterprise) imports this engine and surrounds it with:

- Multi-tenant PostgreSQL architecture.
- Asynchronous distributed workers.
- Runtime telemetry ingestion to dynamically adjust the operational impact weights ($\delta\_{runtime}$).
- Automated GitOps remediation workflows.

By keeping the core algorithms open-source, security teams can fully audit the mathematical models generating their remediation plans.

---

## Contributing

Contributions focused on performance optimizations (especially parallelization of the graph traversal) and the formalization of new cloud-native edge semantics are welcome. Please open an issue before submitting major structural pull requests.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.