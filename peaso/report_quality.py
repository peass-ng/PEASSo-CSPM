"""Output-only reasons for UNKNOWN findings; no security evaluation or status changes."""


def _labels(value):
    if not isinstance(value, (list, tuple)):
        return []
    labels = []
    for entry in value:
        if isinstance(entry, str) and entry.strip():
            labels.append(entry)
        elif isinstance(entry, dict):
            label = next((entry[key] for key in ("field", "path", "fact", "name")
                          if isinstance(entry.get(key), str) and entry[key].strip()), None)
            if label:
                labels.append(label)
    return sorted(set(labels))


def normalize_unknown_reasons(findings):
    """Fill absent evidence.reason using existing evidence, without mutating input.

    A retained UNKNOWN can name an inventory gap, unavailable fact or unresolved
    condition. The fallback says only that the producer supplied no explanation;
    it does not invent a missing fact, permission denial or security conclusion.
    """
    output = []
    for finding in findings:
        evidence = finding.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        reason = evidence.get("reason")
        if finding.get("status") != "UNKNOWN" or (isinstance(reason, str) and reason.strip()):
            output.append(finding)
            continue
        supplied = finding.get("reason")
        facts = _labels(evidence.get("missing_facts")) + _labels(evidence.get("missing_fields"))
        gaps = []
        for key in ("gaps", "dependencies"):
            for gap in evidence.get(key, []) if isinstance(evidence.get(key), (list, tuple)) else []:
                if isinstance(gap, dict) and isinstance(gap.get("type"), str):
                    state = gap.get("status")
                    gaps.append(gap["type"] + ("(" + state + ")" if isinstance(state, str) else ""))
        conditions = _labels(evidence.get("conditions"))
        unresolved = sorted({(entry["layer"] + ": " if isinstance(entry.get("layer"), str) and entry["layer"].strip() else "") + entry["reason"]
                             for entry in (evidence.get("unresolved") if isinstance(evidence.get("unresolved"), (list, tuple)) else [])
                             if isinstance(entry, dict) and isinstance(entry.get("reason"), str) and entry["reason"].strip()})
        if isinstance(supplied, str) and supplied.strip():
            reason = supplied
        elif facts:
            reason = "missing_facts: " + ", ".join(sorted(set(facts)))
        elif gaps:
            reason = "incomplete_inventory: " + ", ".join(sorted(set(gaps)))
        elif conditions:
            reason = "unresolved_conditions: " + ", ".join(conditions)
        elif unresolved:
            reason = "unresolved: " + "; ".join(unresolved)
        else:
            reason = "unknown_reason_not_supplied"
        output.append(dict(finding, evidence=dict(evidence, reason=reason)))
    return output
