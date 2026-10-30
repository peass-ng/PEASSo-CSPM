"""The optional main catalog is resolved once and replayed by immutable digest."""

from __future__ import annotations

import io
import json

import pytest

from peaso.attack_detection import catalog, github_source
from peaso.attack_detection.rules import RuleSourceError


SAMPLE = """id: sample-aws-rule
title: Synthetic action
level: low
description: Test-only event.
x_hacktricks_technique_id: synthetic
logsource: {product: aws, service: cloudtrail}
detection:
  selection: {event.name: SyntheticAction}
  condition: selection
"""




def test_latest_catalog_rejects_changed_or_invalid_pack(monkeypatch):
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, commit, digest: {
        "aws/iam/sample.yml": SAMPLE})
    with pytest.raises(RuleSourceError, match="invalid_rule_catalog_commit"):
        catalog.select_catalog("latest", commit="main")
    with pytest.raises(RuleSourceError, match="rule_catalog_changed"):
        catalog.select_catalog("latest", commit="a" * 40, digest="0" * 64)
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, commit, digest: {
        "aws/iam/sample.yml": "id: malformed\n"})
    with pytest.raises(RuleSourceError, match="rule_source_unavailable"):
        catalog.select_catalog("latest", commit="b" * 40)


def test_each_new_analysis_resolves_and_downloads_current_main(monkeypatch):
    first, second = "a" * 40, "b" * 40
    resolved = iter((first, second))
    fetched = []
    monkeypatch.setenv("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "untrusted/repository")
    monkeypatch.setenv("HACKTRICKS_CSPM_RULES_GITHUB_REF", "c" * 40)
    def resolve(repo):
        assert repo == catalog.DEFAULT_RULE_REPO
        return next(resolved)

    monkeypatch.setattr(catalog, "resolve_main_commit", resolve)
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, commit, digest: (
        fetched.append((repo, commit, digest)) or {"aws/iam/sample.yml": SAMPLE}))
    assert catalog.select_catalog().commit == first
    assert catalog.select_catalog().commit == second
    assert fetched == [(catalog.DEFAULT_RULE_REPO, first, None),
                       (catalog.DEFAULT_RULE_REPO, second, None)]


def test_latest_failure_never_reuses_prior_pack_or_pinned_fallback(monkeypatch):
    commit = "a" * 40
    monkeypatch.setattr(catalog, "resolve_main_commit", lambda repo: commit)
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, sha, digest: {
        "aws/iam/sample.yml": SAMPLE})
    selected = catalog.select_catalog("latest")
    assert selected.commit == commit

    def unavailable(repo, sha, digest):
        raise RuntimeError("private upstream response")

    monkeypatch.setattr(catalog, "fetch_rules", unavailable)
    with pytest.raises(RuleSourceError) as error:
        catalog.select_catalog("latest")
    assert str(error.value) == "rule_source_unavailable"
    assert "private upstream response" not in str(error.value)


def test_main_ref_resolution_is_bounded_and_validated(monkeypatch):
    class Response(io.BytesIO):
        status = 200

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.github.com/repos/peass-ng/peasso-cspm-detections/branches/main"
            assert timeout == 15
            assert request.get_header("Authorization") is None
            return Response(json.dumps({"commit": {"sha": "A" * 40}}).encode())

    monkeypatch.setattr(github_source, "build_opener", lambda *args: Opener())
    assert github_source.resolve_main_commit("peass-ng/peasso-cspm-detections") == "a" * 40
    with pytest.raises(github_source.RuleSourceError, match="invalid_repo"):
        github_source.resolve_main_commit("https://other.example/rules")


def test_main_ref_rejects_oversized_or_malformed_responses(monkeypatch):
    class Response(io.BytesIO):
        status = 200

    class Opener:
        def __init__(self, body):
            self.body = body

        def open(self, request, timeout):
            return Response(self.body)

    monkeypatch.setattr(github_source, "build_opener", lambda *args: Opener(b"x" * (github_source.MAX_REF_BYTES + 1)))
    with pytest.raises(github_source.RuleSourceError, match="rule_ref_too_large"):
        github_source.resolve_main_commit(catalog.DEFAULT_RULE_REPO)
    monkeypatch.setattr(github_source, "build_opener", lambda *args: Opener(b'{"commit":{"sha":"main"}}'))
    with pytest.raises(github_source.RuleSourceError, match="invalid_rule_ref"):
        github_source.resolve_main_commit(catalog.DEFAULT_RULE_REPO)
