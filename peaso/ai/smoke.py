"""Explicit paid/live deployment smoke, invoked by the release owner only."""
import json
import uuid


def main():
    # Use only an offline native snapshot; no customer cloud credentials or
    # tenant artifacts are supplied. Exercise the shipped Network/Priorities
    # orchestration and verify native Hardening/Exposure findings stay final.
    from peaso.demo import demo_snapshot
    from peaso.engine import evaluate_snapshot, hydrate_finding
    from .pipeline import review_scan

    snapshot = demo_snapshot('aws')
    report = evaluate_snapshot(snapshot, categories=['hardening', 'exposure', 'network'])
    findings = [hydrate_finding(row, report.get('check_frameworks'), report.get('check_meta'),
        report.get('check_meta_encoding'), report.get('remediation_templates')) for row in report['findings']]
    report['findings'] = [next(row for row in findings if row['category'] == category and row['status'] == 'FAIL')
                          for category in ('hardening', 'exposure')]
    result = review_scan(report, snapshot, {'ai_enabled': True},
                         tenant='release-smoke-' + uuid.uuid4().hex, artifacts=None)
    native = result.get('native_final', {})
    reviews = result.get('reviews', {})
    if (result.get('status') != 'completed' or result.get('network', {}).get('status') != 'completed'
            or not isinstance(result.get('actions'), list)
            or len(native.get('hardening', [])) != 1 or len(native.get('exposure', [])) != 1
            or len(reviews.get('hardening', [])) != 1 or len(reviews.get('exposure', [])) != 1
            or result.get('stage_inputs') != {'hardening': [], 'exposure': []}
            or result.get('coverage', {}).get('total') != 2):
        raise RuntimeError('isolated_live_pipeline_smoke_failed')
    print(json.dumps({'status': 'passed', 'model_stages': ['network', 'priorities'],
                      'native_final_categories': ['hardening', 'exposure']}))


if __name__ == '__main__':
    main()
