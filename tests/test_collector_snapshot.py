"""Collector snapshot contract and its translation into the attack graph."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from evonhi_core.graph_builder import build_attack_graph
from evonhi_core.models import CrownJewelSpec, ScenarioConfig
from evonhi_core.planning import assess_risk
from evonhi_core.providers.kubernetes.snapshot import SnapshotError, cluster_model_from_snapshot

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SCHEMA = json.loads((ROOT / "contracts" / "cluster-snapshot.v1.schema.json").read_text())


def _load(version: str) -> dict:
    return json.loads((FIXTURES / f"collector_snapshot_v{version}.json").read_text())


@pytest.mark.parametrize("version", ["1_0", "1_1"])
def test_fixtures_follow_the_contract(version):
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(_load(version), SCHEMA)


@pytest.mark.parametrize("version", ["1_0", "1_1"])
def test_snapshot_builds_the_expected_attack_path(version):
    model = cluster_model_from_snapshot(_load(version))
    scenario = ScenarioConfig(crown_jewels=[CrownJewelSpec("secret", "db-creds", "shop")])
    graph = build_attack_graph(model, scenario)
    result = assess_risk(graph)
    assert result.baseline_exposures == 1
    assert result.baseline_paths[0].relations == [
        "uses_token",
        "granted_permission",
        "spawn_workload_as",
        "granted_permission",
        "read_secret",
    ]
    assert result.baseline_paths[0].nodes[0] == "workload:shop:web"


def test_image_pull_secrets_are_not_readable_from_the_container():
    model = cluster_model_from_snapshot(_load("1_0"))
    web = next(w for w in model.workloads if w.metadata.name == "web")
    worker = next(w for w in model.workloads if w.metadata.name == "worker")
    assert web.mounted_secrets == []
    assert worker.mounted_secrets == ["db-creds"]


def test_non_resource_url_rules_grant_nothing_on_objects():
    """A /healthz rule has no resources; treating it as '*' would invent a cluster-wide secret read."""
    model = cluster_model_from_snapshot(_load("1_0"))
    health = next(r for r in model.roles if r.metadata.name == "health")
    assert health.rules == []


def test_service_account_automount_is_inherited_unless_the_pod_overrides_it():
    payload = _load("1_0")
    payload["service_accounts"][0]["automount_token"] = False
    model = cluster_model_from_snapshot(payload)
    assert next(w for w in model.workloads if w.metadata.name == "web").automount_token is False

    explicit = _load("1_1")  # SA says False, pod says True -> pod wins
    model = cluster_model_from_snapshot(explicit)
    assert next(w for w in model.workloads if w.metadata.name == "web").automount_token is True


def test_public_exposure_comes_from_collector_or_marker():
    v11 = cluster_model_from_snapshot(_load("1_1"))
    assert {w.metadata.name: w.public for w in v11.workloads} == {"web": True, "worker": False}
    v10 = cluster_model_from_snapshot(_load("1_0"))
    assert {w.metadata.name: w.public for w in v10.workloads} == {"web": True, "worker": False}


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda p: p.update(schema_version="2.0"), "schema_version"),
        (lambda p: p["role_bindings"][0]["role_ref"].update(kind="Group"), "role_ref"),
        (lambda p: p["workloads"][0].pop("namespace"), "namespace"),
        (lambda p: p.update(secrets={"not": "a list"}), "secrets"),
    ],
)
def test_contract_violations_are_rejected(mutate, message):
    payload = copy.deepcopy(_load("1_0"))
    mutate(payload)
    with pytest.raises(SnapshotError, match=message):
        cluster_model_from_snapshot(payload)
