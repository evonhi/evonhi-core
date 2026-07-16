"""AwsProvider tests (Fase 5): index wildcards, SCP resolution, backward-reachability,
construction through CanonicalGraph, and a capability-aware traversal over the AWS graph."""

from __future__ import annotations

import networkx as nx

from evonhi_core.graph.contract import CapabilityKind
from evonhi_core.path_analysis import find_attack_paths
from evonhi_core.providers.aws.index import ActionResourceIndex
from evonhi_core.providers.aws.model import IamPolicyStatement, IamRole
from evonhi_core.providers.aws.provider import AwsProvider
from evonhi_core.providers.aws.resolver import AwsEffectivePolicyResolver
from evonhi_core.providers.base import GraphProvider
from evonhi_core.providers.registry import get_graph_provider
from tests.aws_scenario import DB, GATEWAY, LAMBDA, ORPHAN, PRIV, S3, make_org, make_scenario

# --------------------------------------------------------------------------- #
# (a) inverted index handles Action/Resource wildcards
# --------------------------------------------------------------------------- #


def test_index_resource_wildcard_matching():
    roles = [
        IamRole("r:star", "star", "1", identity_statements=[IamPolicyStatement("Allow", ["s3:*"], ["*"])]),
        IamRole("r:prod", "prod", "1", identity_statements=[IamPolicyStatement("Allow", ["s3:GetObject"], ["arn:aws:s3:::prod-*"])]),
        IamRole("r:dev", "dev", "1", identity_statements=[IamPolicyStatement("Allow", ["s3:GetObject"], ["arn:aws:s3:::dev-*"])]),
    ]
    index = ActionResourceIndex(roles)
    hits = {arn for arn, _, _ in index.principals_with_access("arn:aws:s3:::prod-secrets")}
    assert hits == {"r:star", "r:prod"}  # "*" and prod-* match; dev-* does not


# --------------------------------------------------------------------------- #
# (b) SCP resolution removes the blocked route — the key test
# --------------------------------------------------------------------------- #


def test_scp_denies_s3_and_cuts_the_edge():
    org, scenario = make_org(), make_scenario()

    # resolver: the priv role's s3:* Allow to the prod bucket does not survive the OU's SCP Deny.
    resolver = AwsEffectivePolicyResolver(org)
    assert resolver.denies(PRIV, ["s3:*"], S3) is True
    assert resolver.denies(PRIV, ["secretsmanager:GetSecretValue"], DB) is False
    resolved_targets = {p.target for p in resolver.resolve(org)}
    assert DB in resolved_targets
    assert S3 not in resolved_targets  # SCP-blocked access never becomes an effective permission

    # end-to-end: the S3 crown jewel has no node/edge in the built graph
    graph = AwsProvider().build_graph(org, scenario)
    assert S3 not in graph.nodes
    assert DB in graph.nodes


# --------------------------------------------------------------------------- #
# (c) backward-reachability keeps the working graph small
# --------------------------------------------------------------------------- #


def test_backward_reachability_prunes_unreachable_roles():
    graph = AwsProvider().build_graph(make_org(), make_scenario())
    # only roles on a backward path to a crown jewel are present
    assert set(graph.nodes) == {LAMBDA, GATEWAY, PRIV, DB}
    assert ORPHAN not in graph.nodes


# --------------------------------------------------------------------------- #
# (d) built through CanonicalGraph -> edges carry resolved guards
# --------------------------------------------------------------------------- #


def test_build_goes_through_canonical_graph_with_guards():
    graph = AwsProvider().build_graph(make_org(), make_scenario())
    pivot = graph.edges[GATEWAY, PRIV]
    assert pivot["relation"] == "pivot_identity"
    guard = pivot["guard"]  # present only because it was added via CanonicalGraph.add_permission_edge
    assert guard.required[0].kind == CapabilityKind.ORG_MEMBERSHIP
    assert "weight" in pivot


# --------------------------------------------------------------------------- #
# provider conformance + capability-aware traversal over the AWS graph
# --------------------------------------------------------------------------- #


def test_provider_conforms_and_path_is_found_conservatively():
    provider = get_graph_provider("aws")
    assert isinstance(provider, GraphProvider)
    graph = provider.build_graph(make_org(), make_scenario())
    assert isinstance(graph, nx.DiGraph)

    # the org-membership guard is handled in conservative mode (path is found, not blocked)
    paths = find_attack_paths(graph, entry_kinds=provider.entry_node_kinds, capability_domain=provider.capability_domain)
    assert len(paths) == 1
    assert paths[0].relations == ["uses_token", "pivot_identity", "read_secret"]
    assert paths[0].nodes == [LAMBDA, GATEWAY, PRIV, DB]
