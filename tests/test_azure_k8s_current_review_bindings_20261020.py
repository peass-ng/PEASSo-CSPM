"""Current loaded predicates must match an individual, source-bound review."""
import json

# The four-assessment successor record keeps the predecessor bytes it reviewed in
# ``immutable_predecessor_files_sha256``.  Files that were later changed by
# reviewed edits are pinned here as current successors, outside the frozen record.
ASSESSMENT_PREDECESSOR_SUCCESSORS = {
    'docs/evidence-reviews/azure.json': {
        'before_sha256': '394f162863c92b9734fbd92305bc45cb12f99ff582aae0f0c3cb4b72b0905090',
        'after_sha256': '6cd67b009d691a55cc6a641ab8594d8c3acc0635c1906098383eeafb0860a24c',
    },
}

# The frozen four-assessment record keeps the evaluator bytes it reviewed.
# b96c06f9 then accepted the storage account full GET at the collector's current
# 2026-06-01 version in ``_storage_account_identity`` (VHD backing identity), a
# helper outside the four assessment predicates; its exact bytes are pinned here.
ASSESSMENT_EVALUATOR_SUCCESSORS = {
    'peaso/checks/claude_azure_data.py': {
        'before_sha256': 'e8fd6583fe2d61fd07a2001a3d91c1a7983998e0e76b33add898f8a097af377b',
        'after_sha256': 'c4f7c866da5a0695500e6f1c0177febfea993247b1fcd77588ac16b02d1b2f22',
    },
}

# Reviewed predicate bodies that later accepted the collector's current storage
# account full GET version (2026-06-01) alongside 2023-05-01.  The frozen receipt
# keeps the reviewed body; only these exact successor bodies are admitted.
CURRENT_BODY_SUCCESSORS = {
    'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794': {
        'source': 'peaso/checks/batch_remaining_azure_vm_storage.py',
        'before_sha256': '2058537722e6f0052573f16d2105124a3868ab67a86e2238579f7baf5ff84062',
        'after_sha256': '17aff17c139959bc52e7b8d33b226bb12997cd867f80be3a0eaeb48be740bfed',
    },
    'azure.encryption.stream_analytics_job_storage_cmk_declared': {
        'source': 'peaso/checks/azure_native_contract_closure_20261020.py',
        'before_sha256': '99a4fbd98378b89b2d719061b5992a57a4447cf51f719d9e42e211cffd7bf775',
        'after_sha256': 'f8238cabda9d54e8adb28c96809fdbb380854e290a8bb8a4bc0eeb930ed39021',
    },
}


def current_body_digest(cid, source, reviewed_body):
    successor = CURRENT_BODY_SUCCESSORS.get(cid)
    if successor is None:
        return reviewed_body
    assert successor['source'] == source and successor['before_sha256'] == reviewed_body, cid
    return successor['after_sha256']


def assessment_evaluator_matches(path, expected, current):
    successor = ASSESSMENT_EVALUATOR_SUCCESSORS.get(path)
    if successor is None:
        return current == expected
    return expected == successor['before_sha256'] and current == successor['after_sha256']


def assessment_predecessor_matches(path, expected, current):
    successor = ASSESSMENT_PREDECESSOR_SUCCESSORS.get(path)
    if successor is None:
        return current == expected
    return expected == successor['before_sha256'] and current == successor['after_sha256']


