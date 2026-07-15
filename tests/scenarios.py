"""Self-contained ClusterModel factories for evo-core tests.

These build small, deterministic Kubernetes models programmatically so the pure
engine can be exercised in the public repo without depending on evo_saas data or
its manifest loader. Each factory returns ``(ClusterModel, ScenarioConfig)`` and
exercises one core semantic of the graph builder.
"""

from __future__ import annotations

from evonhi_core.models import (
    ClusterModel,
    CrownJewelSpec,
    Metadata,
    PolicyRule,
    Role,
    RoleBinding,
    ScenarioConfig,
    Secret,
    ServiceAccount,
    SubjectRef,
    Workload,
)


def secret_read_scenario() -> tuple[ClusterModel, ScenarioConfig]:
    """Public workload -> SA -> RBAC `get secrets` -> crown-jewel secret.

    Exercises: uses_token, granted_permission, read_secret.
    """
    ns = "prod"
    model = ClusterModel(
        service_accounts=[ServiceAccount(metadata=Metadata(name="web-sa", namespace=ns))],
        roles=[
            Role(
                metadata=Metadata(name="web-role", namespace=ns),
                rules=[PolicyRule(resources=["secrets"], verbs=["get"], api_groups=[""])],
            )
        ],
        role_bindings=[
            RoleBinding(
                metadata=Metadata(name="web-binding", namespace=ns),
                role_ref_kind="Role",
                role_ref_name="web-role",
                subjects=[SubjectRef(kind="ServiceAccount", name="web-sa", namespace=ns)],
            )
        ],
        secrets=[Secret(metadata=Metadata(name="db-secret", namespace=ns))],
        workloads=[
            Workload(
                metadata=Metadata(name="web", namespace=ns),
                workload_kind="Deployment",
                service_account_name="web-sa",
                public=True,
            )
        ],
    )
    scenario = ScenarioConfig(
        crown_jewels=[CrownJewelSpec(kind="secret", name="db-secret", namespace=ns)],
        entry_workloads=[],
        max_paths=50,
    )
    return model, scenario


def mounted_secret_scenario() -> tuple[ClusterModel, ScenarioConfig]:
    """Public workload with a directly mounted crown-jewel secret.

    Exercises: mounted_secret (direct exposure).
    """
    ns = "prod"
    model = ClusterModel(
        service_accounts=[ServiceAccount(metadata=Metadata(name="api-sa", namespace=ns))],
        secrets=[Secret(metadata=Metadata(name="api-key", namespace=ns))],
        workloads=[
            Workload(
                metadata=Metadata(name="api", namespace=ns),
                workload_kind="Deployment",
                service_account_name="api-sa",
                public=True,
                mounted_secrets=["api-key"],
            )
        ],
    )
    scenario = ScenarioConfig(
        crown_jewels=[CrownJewelSpec(kind="secret", name="api-key", namespace=ns)],
        entry_workloads=[],
        max_paths=50,
    )
    return model, scenario


def pivot_scenario() -> tuple[ClusterModel, ScenarioConfig]:
    """Public workload -> SA -> workload-mutation -> pivot into privileged SA -> secret.

    Exercises: spawn_workload_as pivot followed by a secret read.
    """
    ns = "ci"
    model = ClusterModel(
        service_accounts=[
            ServiceAccount(metadata=Metadata(name="ci-sa", namespace=ns)),
            ServiceAccount(metadata=Metadata(name="priv-sa", namespace=ns)),
        ],
        roles=[
            Role(
                metadata=Metadata(name="ci-role", namespace=ns),
                rules=[PolicyRule(resources=["deployments"], verbs=["create"], api_groups=["apps"])],
            ),
            Role(
                metadata=Metadata(name="priv-role", namespace=ns),
                rules=[PolicyRule(resources=["secrets"], verbs=["get"], api_groups=[""])],
            ),
        ],
        role_bindings=[
            RoleBinding(
                metadata=Metadata(name="ci-binding", namespace=ns),
                role_ref_kind="Role",
                role_ref_name="ci-role",
                subjects=[SubjectRef(kind="ServiceAccount", name="ci-sa", namespace=ns)],
            ),
            RoleBinding(
                metadata=Metadata(name="priv-binding", namespace=ns),
                role_ref_kind="Role",
                role_ref_name="priv-role",
                subjects=[SubjectRef(kind="ServiceAccount", name="priv-sa", namespace=ns)],
            ),
        ],
        secrets=[Secret(metadata=Metadata(name="ci-secret", namespace=ns))],
        workloads=[
            Workload(
                metadata=Metadata(name="ci-runner", namespace=ns),
                workload_kind="Deployment",
                service_account_name="ci-sa",
                public=True,
            )
        ],
    )
    scenario = ScenarioConfig(
        crown_jewels=[CrownJewelSpec(kind="secret", name="ci-secret", namespace=ns)],
        entry_workloads=[],
        max_paths=50,
    )
    return model, scenario


ALL_SCENARIOS = {
    "secret_read": secret_read_scenario,
    "mounted_secret": mounted_secret_scenario,
    "pivot": pivot_scenario,
}
