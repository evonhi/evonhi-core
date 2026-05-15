<div align="center">
  <h1>EvoNHI Core</h1>
  <p><b>Evolutionary Optimization Engine for Kubernetes Attack Paths</b></p>
  
  [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

<br/>

**EvoNHI Core** is the open-source mathematical engine behind the EvoNHI platform. It provides the foundational algorithms to model Kubernetes Non-Human Identities (NHIs) and RBAC configurations as directed attack graphs, computing optimal remediation strategies using Multi-Objective Evolutionary Optimization (NSGA-II).

Unlike static YAML linters, this engine reasons about **privilege transitivity** (e.g., how a `create pods` permission acts as a pivot to assume any ServiceAccount in a namespace) and evaluates remediations based on their implementation cost and operational impact.

## Core Modules

This repository isolates the pure computational logic from the SaaS infrastructure. It consists of three primary modules:

1. **`graph_builder.py`**: Translates Kubernetes resources (ServiceAccounts, Roles, RoleBindings, Secrets, Workloads) into a semantically weighted directed graph $G=(V,E,W)$. It maps specific attack primitives, including the critical `spawn_workload_as` vector.
2. **`path_analysis.py`**: Executes a bounded Depth-First Search (DFS) to discover all possible attack chains from public-facing workloads to defined cluster "crown jewels".
3. **`optimizer.py`**: Implements a tailored **NSGA-II** (Non-dominated Sorting Genetic Algorithm) to solve the NP-hard combinatorial problem of selecting which RBAC permissions to revoke or modify. It produces a Pareto front of plans balancing attack-surface reduction, operational impact, and cost.

## Quick Usage

EvoNHI Core is designed to be imported as a Python library into your own security pipelines or used as the backend for the EvoNHI SaaS.

### Installation

*(Note: Currently, clone the repository to use the engine locally. PyPI package release pending).*
```bash
git clone [https://github.com/your-username/evonhi-core.git](https://github.com/your-username/evonhi-core.git)
cd evonhi-core