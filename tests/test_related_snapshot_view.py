"""A related view may omit only kinds that the privesc join cannot read."""
import ast
import re
from pathlib import Path

import pytest

from peaso.engine import evaluate_snapshot
from peaso.related_snapshots import UNREAD_KINDS, related_view
from peaso.snapshot import make_snapshot
from tests.test_peaso_related_snapshots import gke_pair

ROOT = Path(__file__).resolve().parents[1] / "peaso" / "privesc"


def test_unread_kinds_are_absent_from_privesc_sources_and_catalogs():
    # A new join that names one of these kinds must first remove it from
    # UNREAD_KINDS. Include f-string patterns and catalog tokens, not just
    # literal equality, since collection lookups can be constructed.
    literals, patterns = set(), []
    for path in ROOT.rglob("*"):
        if path.suffix == ".py":
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    literals.add(node.value)
                elif isinstance(node, ast.JoinedStr):
                    pattern = "".join(re.escape(part.value) if isinstance(part, ast.Constant)
                                      else ".*" for part in node.values)
                    patterns.append(re.compile("^" + pattern + "$"))
        elif path.suffix in {".json", ".yaml", ".yml"}:
            literals.update(re.findall(r"[A-Za-z0-9_]+", path.read_text()))
    for provider, kinds in UNREAD_KINDS.items():
        for kind in kinds:
            assert kind not in literals, (provider, kind)
            assert not any(pattern.fullmatch(kind) for pattern in patterns), (provider, kind)


def test_k8s_privesc_report_is_identical_with_validated_related_view():
    cloud, cluster = gke_pair()
    cloud = make_snapshot("gcp", cloud["scopes"], cloud["collections"] + [
        {"type": "cloud_asset", "scope": cloud["scopes"][0], "status": "collected",
         "items": [{"name": "large-unread-asset", "payload": "x" * 4096}]},
    ], created_at=cloud["created_at"], metadata=cloud["metadata"])
    view = related_view(cloud)
    assert view["snapshot_id"] == cloud["snapshot_id"]
    assert "cloud_asset" not in {part["type"] for part in view["collections"]}
    assert evaluate_snapshot(cluster, categories=["privesc"], related_snapshots=[cloud]) == \
        evaluate_snapshot(cluster, categories=["privesc"], related_snapshots=[view])
    assert related_view(view) is view


def test_related_view_validates_before_dropping_kinds():
    cloud, cluster = gke_pair()
    tampered = dict(cloud)
    tampered["collections"] = [*cloud["collections"],
                               {"type": "cloud_asset", "scope": cloud["scopes"][0],
                                "status": "collected", "items": [{"name": "changed"}]}]
    with pytest.raises(ValueError, match="digest mismatch"):
        related_view(tampered)
    assert related_view(cluster)["collections"] == cluster["collections"]
