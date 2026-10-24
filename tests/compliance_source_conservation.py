"""Conserve upstream source references without treating them as reviewed coverage."""

from functools import lru_cache
import json
from pathlib import Path

from peaso.checks.catalog import requirement_tags_for


@lru_cache(maxsize=1)
def _requirements():
    path = Path(__file__).resolve().parents[1] / "peaso/rulepacks/compliance_requirements.json"
    pack = json.loads(path.read_text())
    return {(framework["id"], row["requirement_id"]): row
            for framework in pack["frameworks"] for row in framework["requirements"]}


def assert_source_frameworks_conserved(source_row, native):
    """Each source tag is explicitly mapped or rejected for this native in the signed row."""
    from peaso.checks import resolve_check_id
    native = resolve_check_id(native)
    reviewed = _requirements()
    runtime_tags = {(tag["framework_id"], tag["requirement_id"])
                    for tag in requirement_tags_for(native)}
    for source_tag in source_row["frameworks"]:
        key = source_tag["framework_id"], source_tag["control_id"]
        assert key in reviewed, (source_row["check_id"], native, key)
        row = reviewed[key]
        if native in {resolve_check_id(cid) for cid in row["native_checks"]}:
            assert key in runtime_tags, (source_row["check_id"], native, key)
        else:
            assert native in {resolve_check_id(cid) for cid in row["removed_checks"]} and len(row["reason"].strip()) >= 15, (
                source_row["check_id"], native, key, row["decision"])
            assert key not in runtime_tags, (source_row["check_id"], native, key)
