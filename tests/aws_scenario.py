"""Synthetic AWS organization for provider tests (Fase 5).

Chain: public lambda -> assume-role (gated by org membership) -> privileged role -> secret
(crown jewel). An SCP on the data OU denies s3:*, cutting the privileged role's apparent
access to a prod bucket crown jewel. An orphan role has no path to any crown jewel.
"""

from __future__ import annotations

from evonhi_core.models import CrownJewelSpec, ScenarioConfig
from evonhi_core.providers.aws.model import (
    AwsAccount,
    AwsCompute,
    AwsOrganization,
    AwsResource,
    IamPolicyStatement,
    IamRole,
    OrganizationalUnit,
)

DB = "arn:aws:secretsmanager:us-east-1:222:secret:db-master"
S3 = "arn:aws:s3:::prod-secrets"
GATEWAY = "arn:aws:iam::111:role/gateway"
PRIV = "arn:aws:iam::222:role/priv"
ORPHAN = "arn:aws:iam::111:role/orphan"
LAMBDA = "arn:aws:lambda:us-east-1:111:function:public-api"


def make_org() -> AwsOrganization:
    return AwsOrganization(
        accounts=[AwsAccount("111", "app-ou"), AwsAccount("222", "data-ou")],
        organizational_units=[
            OrganizationalUnit("root-ou", None, []),
            OrganizationalUnit("app-ou", "root-ou", []),
            OrganizationalUnit("data-ou", "root-ou", [IamPolicyStatement("Deny", ["s3:*"], ["*"])]),
        ],
        roles=[
            IamRole(GATEWAY, "gateway", "111", identity_statements=[IamPolicyStatement("Allow", ["sts:AssumeRole"], [PRIV])]),
            IamRole(
                PRIV,
                "priv",
                "222",
                identity_statements=[
                    IamPolicyStatement("Allow", ["secretsmanager:GetSecretValue"], [DB]),
                    IamPolicyStatement("Allow", ["s3:*"], [S3]),  # apparent access, killed by the SCP
                ],
                trust_statements=[IamPolicyStatement("Allow", [], [], condition={"aws:PrincipalOrgID": "o-123"}, principals=[GATEWAY])],
            ),
            IamRole(ORPHAN, "orphan", "111", identity_statements=[IamPolicyStatement("Allow", ["s3:GetObject"], ["arn:aws:s3:::unrelated"])]),
        ],
        computes=[AwsCompute(LAMBDA, "public-api", "111", execution_role_arn=GATEWAY, public=True)],
        resources=[AwsResource(DB, "secretsmanager"), AwsResource(S3, "s3")],
    )


def make_scenario() -> ScenarioConfig:
    return ScenarioConfig(
        crown_jewels=[
            CrownJewelSpec(kind="resource", name=DB, criticality=10, rationale="Master DB secret"),
            CrownJewelSpec(kind="resource", name=S3, criticality=9, rationale="Prod bucket"),
        ]
    )
