"""Reproduce the exact pre-bulk admission view, without changing runtime state.

Historical conservation tests describe the 3,434-check release. The successor
adds precisely the 552 signed entries in bulk_pending.json. Recompile that
ancestor from its retained signed inputs instead of rewriting old hashes or
pretending the new checks remain unregistered. Current compiler/materializer
tests still verify the complete successor artifacts.
"""
import copy
import base64
from dataclasses import replace
from functools import lru_cache
import hashlib
import gzip
import json
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BULK = json.loads((ROOT / "peaso/checks/bulk_pending.json").read_text())
BULK_IDS = frozenset(BULK["checks"])
ANCESTOR_MANIFEST = "db02091367b0067b5c4db3439d9fa13805877bb933e7e2dfab37113c1ffcaac8"
VIEWS_SHA256 = "149b54a78e6811c1ec4d639e5912d5c7f4fe6a7aba16a2e6e2ee3550d995d41e"
PUBLISHED_SPRINT_ARCHIVE = ROOT / "infra/aws/build/peaso-source-414e037b411d4e5abd0a214fc67b4b8bd96aede52dc843cf23748054f4dfbe6d.zip"
SOURCE414_VERSION = "414e037b411d4e5abd0a214fc67b4b8bd96aede52dc843cf23748054f4dfbe6d"
SOURCE414_NATIVE_MEMBER = "peaso/rulepacks/native_catalog.json"
SOURCE414_NATIVE_DELTA = "tests/fixtures/post_dfaf_integration/source414-native-catalog-delta.json.gz"
SOURCE414_NATIVE_DELTA_SHA256 = "eb8e5f44af26d656cabed2aa8420f45c03fd906189f5b31dfa22f8ca7a33788b"
SOURCE414_NATIVE_BASELINE = "tests/fixtures/post_dfaf_integration/source414-native-catalog-baseline.json.gz"
SOURCE414_NATIVE_BASELINE_PACKED_SHA256 = "69eae1edceb1b8a5cf689a88289d0861361a7cb1675d07e8e7926618e83318fd"
SOURCE414_NATIVE_BASE_SHA256 = "53e49812f0afd4fd9a1d30ca7ceb6c5ea27bf575d269233c691a3a84173a270b"
SOURCE414_NATIVE_SHA256 = "9007b31199e3cbe2f9866057d6ac46c04c62e7c83a3ee78c61a70ffb30c1fbba"
PRE_REVIEW_LEDGER_BUNDLE = "tests/fixtures/post_dfaf_integration/pre_review_ledger_inputs.json.gz"
PRE_REVIEW_LEDGER_BUNDLE_SHA256 = "0a5dd6f4b192da6c2c0b5a9c2bbd92e982f6ce33b99282ea2aeeff4188011108"
PRE_REVIEW_MANIFEST_SHA256 = "ffb564cedbf575c3d1f94a158c4565f198c14919f93236207e02177855de5879"
REVIEWED_SUCCESSOR_MANIFEST_SHA256 = "2b6e09aa867063ec82de2df146ac085e08b09bc8e7bc8b6b9fdd3ae18325e399"
REVIEWED_CLOUDSQL_FIXTURE_SHA256 = "d03f19c384786999ded6a9a9a462cf52c72a098bf0de697a57f506ceaad274d6"
# Exact signed predecessor from commit 15842280dfb336f356497451d94ec46b2ba5d4ee.
# The current ledger includes four accepted Workbench mapping rejections.
PRE_REVIEW_GCP_PCI = 'tests/fixtures/post_dfaf_integration/pre_review_gcp_pci.json.gz'
PRE_REVIEW_GCP_PCI_PACKED_SHA256 = '5f28c8335a2d008497ce1090960f9660684312d3caab70ca636d20d390a8068e'
PRE_REVIEW_GCP_PCI_SHA256 = "8ebb75fdd0950e3689d3b531509140b020e4f9fdecca4114ccd8a50f48a686c2"


def assert_reviewed_central_fixture_successor(cases, original):
    """Keep the 203 original cases exact and admit one reviewed GCP fixture."""
    assert set(cases) == set(original)
    changed = {cid for cid in original if cases[cid] != original[cid]}
    assert changed == {"gcp_cloudsql_backup_failure_alert"}
    successor = cases["gcp_cloudsql_backup_failure_alert"]
    digest = hashlib.sha256(json.dumps(successor, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert digest == REVIEWED_CLOUDSQL_FIXTURE_SHA256


def retained_ledger_inputs():
    """Read exact public pre-review ledger bytes from a whole-bundle pin."""
    packed = (ROOT / PRE_REVIEW_LEDGER_BUNDLE).read_bytes()
    if hashlib.sha256(packed).hexdigest() != PRE_REVIEW_LEDGER_BUNDLE_SHA256:
        raise ValueError("Historical ledger input bundle digest differs")
    payload = json.loads(gzip.decompress(packed))
    expected = {"manifest.json", "aws-cis.json", "aws-fsbp-wellarch-ftr.json",
                "aws-kisa-ens-secnum-nis2.json", "aws-nist-ffiec-nydfs.json",
                "aws-other.json", "aws-pci.json",
                "descriptions/implemented-new-checks.json"}
    if payload.get("schema") != "pre-review-ledger-inputs-v1" or set(payload.get("files", {})) != expected:
        raise ValueError("Historical ledger input bundle shape differs")
    result = {}
    for name, entry in payload["files"].items():
        raw = base64.b64decode(entry["content_b64"], validate=True)
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("Historical ledger input member digest differs")
        result[name] = raw
    if hashlib.sha256(result["manifest.json"]).hexdigest() != PRE_REVIEW_MANIFEST_SHA256:
        raise ValueError("Historical ledger manifest digest differs")
    manifest = json.loads(result["manifest.json"])
    if hashlib.sha256(result["descriptions/implemented-new-checks.json"]).hexdigest() != manifest["new_descriptions"]["sha256"]:
        raise ValueError("Historical supplemental descriptions digest differs")
    for entry in manifest["slices"].values():
        if entry["path"] in result and hashlib.sha256(result[entry["path"]]).hexdigest() != entry["sha256"]:
            raise ValueError("Historical ledger slice digest differs")
    packed_gcp = (ROOT / PRE_REVIEW_GCP_PCI).read_bytes()
    if hashlib.sha256(packed_gcp).hexdigest() != PRE_REVIEW_GCP_PCI_PACKED_SHA256:
        raise ValueError("Historical GCP PCI packed digest differs")
    raw_gcp = gzip.decompress(packed_gcp)
    if hashlib.sha256(raw_gcp).hexdigest() != PRE_REVIEW_GCP_PCI_SHA256:
        raise ValueError("Historical GCP PCI source digest differs")
    expected_gcp = next(entry for entry in manifest["slices"].values() if entry["path"] == "gcp-pci.json")
    if expected_gcp["sha256"] != PRE_REVIEW_GCP_PCI_SHA256:
        raise ValueError("Historical GCP PCI manifest binding differs")
    result["gcp-pci.json"] = raw_gcp
    return result


def _historical_alias_not_runnable(item, index):
    # One shared callable keeps repeated historical projections equal.
    raise AssertionError('Historical alias metadata is not a runnable current predicate')


def registered_before_bulk(checks):
    from scripts.peaso_compliance_compile import REVIEWED_NATIVE_ALIASES_20261021
    from peaso.checks import CHECK_ALIASES

    ids = [check.id for check in checks]
    assert len(ids) == len(set(ids))
    assert BULK_IDS <= set(ids) and len(BULK_IDS) == 552
    # Bind the cohort to the retained, digest-verified historical catalog.
    # Later native admissions must not silently enter the old conservation view.
    signed = json.loads(historical_bytes(PUBLISHED_SPRINT_ARCHIVE, SOURCE414_NATIVE_MEMBER))
    prior = {row["id"]: row for row in signed["checks"] if row["id"] not in BULK_IDS}
    expected = set(prior)
    assert len(expected) == BULK["baseline_native_checks"] == 3434
    current = {check.id: check for check in checks}
    missing = expected - set(current)
    assert missing <= set(REVIEWED_NATIVE_ALIASES_20261021), 'Unreviewed historical registry removal'
    assert missing == set(REVIEWED_NATIVE_ALIASES_20261021), 'Historical retired alias set changed'
    for ident in missing:
        survivor = REVIEWED_NATIVE_ALIASES_20261021[ident]
        assert CHECK_ALIASES.get(ident) == survivor and survivor in current
        metadata = prior[ident]
        current[ident] = replace(current[survivor], id=ident, provider=metadata['provider'],
            category=metadata['category'], kind=metadata['type'], title=metadata['title'],
            severity=metadata['severity'], target=metadata['target'], remediation=metadata['remediation'],
            declared_dependencies=tuple(metadata.get('dependencies', [])), evaluate=_historical_alias_not_runnable)
    # Preserve the digest-verified ancestor order; never insert aliases into live CHECKS.
    old = [current[ident] for ident in prior]
    assert len(old) == 3434
    assert {check.id for check in old} == expected
    return old


def registry_source_before_bulk():
    source = (ROOT / "tests/fixtures/post_dfaf_integration/registry_pre_bulk.py.txt").read_bytes()
    delta = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/sprint_source_changes.json").read_text())
    assert hashlib.sha256(source).hexdigest() == delta["changes"]["peaso/checks/__init__.py"]["baseline_sha256"]
    return source.decode()


def encoded(value, *, compact=False):
    options = {"separators": (",", ":")} if compact else {"indent": 2}
    return (json.dumps(value, ensure_ascii=False, **options) + "\n").encode()


@lru_cache(maxsize=1)
def _history():
    from scripts.peaso_compliance_compile import compile_verified, matrix_from, lookup_index

    ledger = ROOT / "docs/compliance-ledgers"
    retained = retained_ledger_inputs()
    manifest = json.loads(retained["manifest.json"])
    supplemental = json.loads(retained["descriptions/implemented-new-checks.json"])
    assert BULK_IDS <= supplemental.keys()
    supplemental = {key: row for key, row in supplemental.items() if key not in BULK_IDS}
    assert len(supplemental) == 329
    manifest["new_descriptions"].update(checks=329, sha256=hashlib.sha256(encoded(supplemental)).hexdigest())
    assert hashlib.sha256(encoded(manifest)).hexdigest() == ANCESTOR_MANIFEST
    # Bind historical membership to the retained Source414e release, not the
    # mutable successor catalog that may have changed after native admission.
    native = json.loads(historical_bytes(PUBLISHED_SPRINT_ARCHIVE, "peaso/rulepacks/native_catalog.json"))
    # These two long-standing predicates were corrected after the published
    # historical cohort. Reconstruct their old descriptions from the exact
    # Source414e archive; current runtime retains the corrected descriptions.
    legacy = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/legacy_native_records.json").read_text())
    assert legacy["source_version"] == "414e037b411d4e5abd0a214fc67b4b8bd96aede52dc843cf23748054f4dfbe6d"
    baseline = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/conservation.json").read_text())
    for index, row in enumerate(native["checks"]):
        if row["id"] in legacy["records"]:
            historical = legacy["records"][row["id"]]
            masked = copy.deepcopy(historical)
            masked.get("proposal_provenance", {}).pop("source_manifest_sha256", None)
            digest = hashlib.sha256(json.dumps(masked, sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=False).encode()).hexdigest()
            assert digest == baseline["old_native_masked_sha256"][row["id"]]
            native["checks"][index] = historical
    native["checks"] = [row for row in native["checks"] if row["id"] not in BULK_IDS]
    assert len(native["checks"]) == 3434
    with tempfile.TemporaryDirectory(prefix="peaso-admission-history-") as folder:
        target = Path(folder)
        # Use only original manifest members. Today's extra ledgers and
        # successor revisions cannot enter the historical compiler view.
        entries = list(manifest["slices"].values()) + list(manifest["descriptions"].values())
        for entry in entries:
            rel = entry["path"]
            source = retained[rel] if rel in retained else (ledger / rel).read_bytes()
            if hashlib.sha256(source).hexdigest() != entry["sha256"]:
                raise ValueError("Historical ledger source digest differs")
            output = target / rel
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(source)
        index = ledger / "inputs/check-index.json"
        if hashlib.sha256(index.read_bytes()).hexdigest() != manifest["check_index_sha256"]:
            raise ValueError("Historical check index digest differs")
        # The signed input snapshots are unchanged; the compiler validates
        # their individual hashes against the original manifest.
        shutil.copytree(ledger / "inputs", target / "inputs")
        (target / "manifest.json").write_bytes(encoded(manifest))
        (target / "descriptions/implemented-new-checks.json").write_bytes(encoded(supplemental))
        requirements, descriptions = compile_verified(target, matrix_from(ROOT / "docs/compliance-ledgers/inputs/compliance-requirements-matrix.json.gz"), native)
    # Rebind the only derived mapping fields that registration of a new proposal can alter.
    native["compliance_source_manifest_sha256"] = ANCESTOR_MANIFEST
    for row in native["checks"]:
        tags = requirements["by_check"].get(row["id"], [])
        row["requirement_controls"] = copy.deepcopy(tags)
        if isinstance(row.get("proposal_provenance"), dict):
            row["proposal_provenance"]["source_manifest_sha256"] = ANCESTOR_MANIFEST
        lookup = {(tag["framework_id"], tag["requirement_id"]): tag for tag in tags}
        for mapping in row.get("mapping", {}).values():
            for control in mapping.get("controls", []):
                tag = lookup.get((control["framework_id"], control["control_id"]))
                if tag:
                    control.update(decision=tag["decision"], runtime_status=tag["runtime_status"])
    result = {
        "docs/compliance-ledgers/manifest.json": manifest,
        "docs/compliance-ledgers/descriptions/implemented-new-checks.json": supplemental,
        "peaso/rulepacks/native_catalog.json": native,
        "peaso/rulepacks/compliance_requirements.json": requirements,
        "peaso/rulepacks/check_descriptions.json": descriptions,
        "peaso/rulepacks/compliance_lookup.json": lookup_index(requirements, hashlib.sha256(encoded(requirements, compact=True)).hexdigest()),
    }
    archived = ROOT / "tests/fixtures/post_dfaf_integration/pre_bulk_views.json.gz"
    assert hashlib.sha256(archived.read_bytes()).hexdigest() == VIEWS_SHA256
    views = json.loads(gzip.decompress(archived.read_bytes()))
    pins = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/two_hour_native_cohort.json").read_text())["source_changes"]
    for path, text in views.items():
        assert hashlib.sha256(text.encode()).hexdigest() == pins[path]["sha256"]
        result[path] = json.loads(text)
    return result


def ancestor_json(path):
    relative = str(Path(path).resolve().relative_to(ROOT))
    return copy.deepcopy(_history().get(relative, json.loads(Path(path).read_text())))


def ancestor_bytes(path):
    relative = str(Path(path).resolve().relative_to(ROOT))
    if relative in _history():
        compact = Path(relative).name in ("native_catalog.json", "runtime_metadata.json", "compliance_requirements.json",
                                         "compliance_lookup.json", "check_descriptions.json", "frameworkCatalog.json")
        return encoded(_history()[relative], compact=compact)
    if relative == "peaso/checks/__init__.py":
        return registry_source_before_bulk().encode()
    return Path(path).read_bytes()


def ancestor_sha(path):
    path = Path(path)
    relative = str(path.resolve().relative_to(ROOT))
    delta_path = ROOT / "tests/fixtures/post_dfaf_integration/sprint_source_changes.json"
    delta = json.loads(delta_path.read_text()) if delta_path.exists() else {"changes": {}}
    published = _published_sprint()
    if relative in delta["changes"]:
        change = delta["changes"][relative]
        assert published["files"].get(relative) == change["sha256"], relative
        if change["baseline_sha256"] is not None:
            return change["baseline_sha256"]
    if relative in published["files"]:
        return published["files"][relative]
    return hashlib.sha256(ancestor_bytes(path)).hexdigest()


@lru_cache(maxsize=1)
def _published_sprint():
    return historical_release(PUBLISHED_SPRINT_ARCHIVE)


def historical_release(path):
    """Read an authentic release manifest; source archives need not be nested."""
    import re
    import zipfile
    path = Path(path)
    match = re.fullmatch(r"peaso-source-([0-9a-f]{64})\.zip", path.name)
    if match is None:
        raise ValueError("Unexpected historical source archive name")
    version = match.group(1)
    if path.is_file():
        with zipfile.ZipFile(path) as archive:
            result = json.loads(archive.read("release.json"))
    else:
        payload = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/historical-release-manifests.json").read_text())
        if payload.get("schema") != 1:
            raise ValueError("Historical release manifest schema differs")
        visiting = set()
        def reconstruct(wanted):
            if wanted in visiting:
                raise ValueError("Historical release manifest cycle")
            visiting.add(wanted)
            row = payload["releases"][wanted]
            manifest = reconstruct(row["base"])["files"].copy() if row["base"] else {}
            for name, digest in row["files_delta"].items():
                if digest is None:
                    manifest.pop(name, None)
                else:
                    manifest[name] = digest
            value = {key: item for key, item in row.items() if key not in {"base", "files_delta"}}
            value["files"] = manifest
            if value.get("source_version") != wanted or hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != wanted:
                raise ValueError("Historical release manifest binding differs")
            visiting.remove(wanted)
            return value
        result = reconstruct(version)
    if result.get("source_version") != version or hashlib.sha256(json.dumps(result["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest() != version:
        raise ValueError("Historical release manifest binding differs")
    return result


# Exact evidence-only IAM successor: four literal reversals recover the original
# frozen baseline byte-for-byte. This is not a current-source repin.
_IAM_HISTORICAL_BASELINE_SHA256 = "2002c02d63715d2b878d6405ca2bd7df87d02d7832e424b5bd1964c113a96423"
_IAM_EVIDENCE_SUCCESSOR_SHA256 = "d94768357e6b0681e0b438490bfdec1383f0228636d32c0d79ca54504631ccf4"
_IAM_SECURITY_SUCCESSOR_SHA256 = "671b51dad0a630377080f1f74a41eb6b0afa481fae9bd29c4c7da5c6d9dc8eaf"
_IAM_UNUSED_ACCESS_SUCCESSOR_SHA256 = "5a1f81ead33c02f957be1d1ee2461afaa7a07b2cb62ec8997dcbc377f3c5c687"
_IAM_UNUSED_ACCESS_PREDECESSOR = "tests/fixtures/post_dfaf_integration/iam_unused_access_pre_successor.py.gz"
_IAM_UNUSED_ACCESS_PREDECESSOR_PACKED_SHA256 = "0c3be6674ed6a37b2cf0979c01303e765b1a2494f359791f3c63ca96b97278e6"
_IAM_RETAINED_PREDECESSOR = "tests/fixtures/post_dfaf_integration/iam_evidence_pre_security_review.py.gz"
_IAM_RETAINED_PREDECESSOR_PACKED_SHA256 = "3e3d598692b530113b37c90a795d86a866da82c728e8a1677a715d06d8f60c37"
_IAM_EVIDENCE_ONLY_REVERSE_HUNKS = (('        matched = set()\n'
  '        def count_and_describe(rows):\n'
  '            hits = count_rows(rows, matcher, resource_ok)\n'
  '            if hits:\n'
  '                for statement in rows:\n'
  '                    if statement["Effect"] == "Allow" and any(resource_ok(r) for r in '
  'statement.get("Resource", [])):\n'
  '                        matched.update(a for a in statement.get("Action", []) if matcher(a))\n'
  '            return hits\n'
  '        return result_rows(_identity_policy_hits(item, count_and_describe), '
  'matching_actions=sorted(matched))\n',
  '        return result_rows(_identity_policy_hits(item, lambda rows: count_rows(rows, matcher, '
  'resource_ok)))\n'),
 ('        attached = arn in role_attached_arns(index)\n'
  '        return result(not attached, policy_arn=arn, role_attachment_found=attached)\n',
  '        return result(arn not in role_attached_arns(index), policy_arn=arn)\n'),
 ('        attached = arn in in_use_arns(index)\n'
  '        return result(not attached, policy_arn=arn, attached_to_active_identity=attached)\n',
  '        return result(arn not in in_use_arns(index), policy_arn=arn)\n'),
 ('    return result(bool(other) and bool(keys), access_keys=len(keys), other_services=len(other), '
  'non_iam_sts_services=other)\n',
  '    return result(bool(other) and bool(keys), access_keys=len(keys), '
  'other_services=len(other))\n'))


def _source414_reviewed_baseline(member, baseline, expected_sha256):
    if (member != "peaso/checks/claude_aws_a_iam.py" or
            expected_sha256 != _IAM_HISTORICAL_BASELINE_SHA256):
        raise ValueError("Historical source baseline digest differs")
    current_sha = hashlib.sha256(baseline).hexdigest()
    if current_sha == _IAM_UNUSED_ACCESS_SUCCESSOR_SHA256:
        # The current Access Analyzer finding logic follows the security review.
        # Keep that logic live while reconstructing its exact predecessor.
        packed = (ROOT / _IAM_UNUSED_ACCESS_PREDECESSOR).read_bytes()
        if hashlib.sha256(packed).hexdigest() != _IAM_UNUSED_ACCESS_PREDECESSOR_PACKED_SHA256:
            raise ValueError("Historical IAM unused-access predecessor digest differs")
        baseline = gzip.decompress(packed)
        current_sha = hashlib.sha256(baseline).hexdigest()
    if current_sha == _IAM_SECURITY_SUCCESSOR_SHA256:
        # This reviewed semantic fix follows the evidence-only successor.
        # Recover the exact pinned predecessor rather than reverting live code.
        packed = (ROOT / _IAM_RETAINED_PREDECESSOR).read_bytes()
        if hashlib.sha256(packed).hexdigest() != _IAM_RETAINED_PREDECESSOR_PACKED_SHA256:
            raise ValueError("Historical IAM retained predecessor digest differs")
        baseline = gzip.decompress(packed)
        current_sha = hashlib.sha256(baseline).hexdigest()
    if current_sha != _IAM_EVIDENCE_SUCCESSOR_SHA256:
        raise ValueError("Historical source baseline digest differs")
    source = baseline.decode()
    for enriched, original in _IAM_EVIDENCE_ONLY_REVERSE_HUNKS:
        if source.count(enriched) != 1:
            raise ValueError("Historical IAM evidence successor hunk differs")
        source = source.replace(enriched, original)
    restored = source.encode()
    if hashlib.sha256(restored).hexdigest() != expected_sha256:
        raise ValueError("Historical IAM baseline reconstruction digest differs")
    return restored


def historical_bytes(path, member):
    """Return retained historical bytes bound to the original release roster."""
    import zipfile
    from pathlib import PurePosixPath
    relative = PurePosixPath(member)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unexpected historical source member")
    release = historical_release(path)
    if Path(path).is_file():
        with zipfile.ZipFile(path) as archive:
            raw = archive.read(member)
    elif release["source_version"] == SOURCE414_VERSION and member == SOURCE414_NATIVE_MEMBER:
        raw = _source414_native_catalog(release)
    else:
        payload = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/historical-release-manifests.json").read_text())
        patch = payload["member_patches"][release["source_version"]][member]
        baseline = (ROOT / member).read_bytes()
        if hashlib.sha256(baseline).hexdigest() != patch["baseline_sha256"]:
            if (member == "docs/compliance-ledgers/manifest.json" and
                    patch["baseline_sha256"] == PRE_REVIEW_MANIFEST_SHA256 and
                    hashlib.sha256(baseline).hexdigest() == REVIEWED_SUCCESSOR_MANIFEST_SHA256):
                baseline = retained_ledger_inputs()["manifest.json"]
            elif release["source_version"] == SOURCE414_VERSION:
                baseline = _source414_reviewed_baseline(member, baseline, patch["baseline_sha256"])
            else:
                raise ValueError("Historical source baseline digest differs")
        if "select_keys" in patch:
            value = json.loads(baseline)
            raw = (json.dumps({key: value[key] for key in patch["select_keys"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        else:
            lines = baseline.decode().splitlines(keepends=True)
            parts = []
            for operation in patch["operations"]:
                if set(operation) == {"copy"}:
                    start, end = operation["copy"]
                    if not 0 <= start <= end <= len(lines):
                        raise ValueError("Historical source copy range differs")
                    parts.append("".join(lines[start:end]))
                elif set(operation) == {"text"}:
                    parts.append(operation["text"])
                else:
                    raise ValueError("Historical source operation differs")
            raw = "".join(parts).encode()
    if hashlib.sha256(raw).hexdigest() != release["files"][member]:
        raise ValueError("Historical source member digest differs")
    return raw


def _source414_native_catalog(release):
    """Reassemble the published member from an immutable baseline and pinned delta."""
    if release["files"].get(SOURCE414_NATIVE_MEMBER) != SOURCE414_NATIVE_SHA256:
        raise ValueError("Historical native catalog release binding differs")
    packed = (ROOT / SOURCE414_NATIVE_DELTA).read_bytes()
    if hashlib.sha256(packed).hexdigest() != SOURCE414_NATIVE_DELTA_SHA256:
        raise ValueError("Historical native catalog delta digest differs")
    patch = json.loads(gzip.decompress(packed))
    if (patch.get("schema") != "source414-native-catalog-index-delta-v1" or
            patch.get("source_version") != SOURCE414_VERSION or
            patch.get("source_member") != SOURCE414_NATIVE_MEMBER or
            patch.get("base_member_sha256") != SOURCE414_NATIVE_BASE_SHA256 or
            patch.get("release_member_sha256") != SOURCE414_NATIVE_SHA256):
        raise ValueError("Historical native catalog delta binding differs")
    baseline_packed = (ROOT / SOURCE414_NATIVE_BASELINE).read_bytes()
    if hashlib.sha256(baseline_packed).hexdigest() != SOURCE414_NATIVE_BASELINE_PACKED_SHA256:
        raise ValueError("Historical native catalog baseline archive digest differs")
    baseline = gzip.decompress(baseline_packed)
    if hashlib.sha256(baseline).hexdigest() != SOURCE414_NATIVE_BASE_SHA256:
        raise ValueError("Historical native catalog baseline digest differs")
    current = json.loads(baseline)
    rows = current["checks"] + current["archived_checks"]
    order = patch.get("order")
    replacements = patch.get("replacements")
    if (len(rows) != 3986 or len({row["id"] for row in rows}) != len(rows) or
            not isinstance(order, list) or len(order) != 3986 or
            any(type(index) is not int or not 0 <= index < len(rows) for index in order) or
            len(set(order)) != len(rows) or
            not isinstance(replacements, dict) or len(replacements) != 46 or
            any(not key.isdecimal() or str(int(key)) != key or int(key) >= len(order)
                for key in replacements)):
        raise ValueError("Historical native catalog delta shape differs")
    historical = patch["top_level"].copy()
    historical["checks"] = [replacements.get(str(index), rows[item])
                            for index, item in enumerate(order)]
    raw = encoded(historical, compact=True)
    if hashlib.sha256(raw).hexdigest() != SOURCE414_NATIVE_SHA256:
        raise ValueError("Historical native catalog reconstruction digest differs")
    return raw


def historical_catalog_ids(path):
    """Read a hash-pinned ID projection, not a fabricated historical catalog."""
    release = historical_release(path)
    version = release["source_version"]
    payload = json.loads((ROOT / "tests/fixtures/post_dfaf_integration/historical-release-manifests.json").read_text())
    projection = payload["catalog_id_projections"][version]
    if projection["source_member_sha256"] != release["files"][projection["source_member"]]:
        raise ValueError("Historical catalog projection source differs")
    ids = projection["ids"]
    expected = {"e022caf8ffd81b18571939a12313dfd9afa60c8f2095239cf3ad25e3002a31b7": "30bc3897a0e8a0b37ac28235f17d5f2a6a5e7deffa8e002daf55ac26bf355007"}
    if len(ids) != len(set(ids)) or hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest() != expected[version]:
        raise ValueError("Historical catalog ID projection digest differs")
    return set(ids)
