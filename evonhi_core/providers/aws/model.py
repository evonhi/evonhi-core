"""AWS provider model (Fase 5, multi-cloud refactor).

A rich, AWS-specific model — deliberately NOT reusing ClusterModel. The provider translates
it into the canonical graph; boto3 ingestion that populates it lives in evo_saas, never here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class IamPolicyStatement:
    effect: str  # "Allow" | "Deny"
    actions: list[str]
    resources: list[str]
    # Condition keys the traversal cares about, e.g. {"aws:PrincipalOrgID": "o-abc"}.
    condition: dict[str, str] = field(default_factory=dict)
    # For trust statements: the principals allowed to assume (ARNs or "*").
    principals: list[str] = field(default_factory=list)


@dataclass(slots=True)
class IamRole:
    arn: str
    name: str
    account_id: str
    identity_statements: list[IamPolicyStatement] = field(default_factory=list)  # what this role can do
    trust_statements: list[IamPolicyStatement] = field(default_factory=list)      # who can assume it (+ conditions)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AwsCompute:
    """A compute entry point (Lambda / EC2) running with an execution role."""

    arn: str
    name: str
    account_id: str
    execution_role_arn: str
    public: bool = False


@dataclass(slots=True)
class AwsResource:
    arn: str
    service: str            # "s3", "secretsmanager", "kms", ...
    resource_type: str = ""


@dataclass(slots=True)
class OrganizationalUnit:
    ou_id: str
    parent_ou_id: str | None = None
    scps: list[IamPolicyStatement] = field(default_factory=list)  # Service Control Policies (Deny ceilings)


@dataclass(slots=True)
class AwsAccount:
    account_id: str
    ou_id: str | None = None


@dataclass(slots=True)
class AwsOrganization:
    accounts: list[AwsAccount] = field(default_factory=list)
    organizational_units: list[OrganizationalUnit] = field(default_factory=list)
    roles: list[IamRole] = field(default_factory=list)
    computes: list[AwsCompute] = field(default_factory=list)
    resources: list[AwsResource] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
