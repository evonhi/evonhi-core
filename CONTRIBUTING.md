# Contributing to evonhi-core

## Workflow

- Work on a short-lived branch (`feat/...`, `fix/...`, `chore/...`) and open a pull request against `main`.
- A pull request needs a green CI run before it is merged.
- Keep pull requests small: one theme, ideally under ~400 changed lines.

## Commits

- One logical change per commit; every commit builds and passes the tests.
- One-line message in [Conventional Commits](https://www.conventionalcommits.org) style, in the imperative,
  under 72 characters: `fix(ingest): reject snapshots that violate the contract`.
- Add a body only when the reason for the change is not obvious from the diff.

## Checks

```bash
python -m venv .venv && .venv/bin/pip install -e . pytest ruff jsonschema
.venv/bin/ruff check evonhi_core tests benchmarks
.venv/bin/pytest -q
```

The engine performs no I/O and depends only on `networkx` and `pydantic`. New attack semantics come with one scenario per primitive, and anything that changes risk numbers is checked against the reference evaluator in `tests/test_planner.py`.
