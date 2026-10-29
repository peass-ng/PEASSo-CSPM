"""AI stage progress for a scan whose native results are already published.

Native sections (findings, leaks, image CVEs, graphs, least privilege and the
privilege-escalation map) are served from the latest durable publication while
the scan runs. Only the model stages (Network and Priorities) may still be in
progress. This projection names those stages so a reader can tell "still
running" apart from "not requested" without waiting for the final report.
"""
import json

from peaso.storage.sqlite import TERMINAL


def _selectors(row):
    data = row.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return {}
    return data if isinstance(data, dict) else {}


def with_pending_stages(row, value):
    """Return ``value`` plus ``pending_stages`` while selected AI stages run.

    Only the API placeholder (no AI document yet) and the progressive stage
    overlay are annotated. A stored AI document is never changed, and terminal
    scans keep their stored state exactly.
    """
    if not isinstance(value, dict) or row.get("status") in TERMINAL:
        return value
    overlay = isinstance(value.get("completed_stages"), list)
    placeholder = value.get("status") == "not_requested" and "version" not in value
    if not overlay and not placeholder:
        return value
    selectors = _selectors(row)
    if selectors.get("ai_enabled", True) is False:
        return value
    from peaso.ai.pipeline import selected_stages
    pending = set(selected_stages(selectors)) - set(value.get("completed_stages") or ())
    if not pending:
        return value
    result = dict(value, pending_stages=sorted(pending))
    if placeholder:
        result["status"] = "in_progress"
    return result
