"""Compare the entire native GCP privilege stage before/after shared work reuse.

python -m tests.synthetic.benchmark_peaso_gcp_permissions --projects 200

The baseline retains the prior target loop and linear inventory lookup. Both
paths load the same model and evaluate all currently admitted GCP techniques.
This performs no cloud calls. It excludes collection, final principal exposure
annotation and report publication; simulated inventory is not a cloud SLA.
"""
import argparse
import json
import statistics
from unittest.mock import patch

from tests.synthetic.benchmark_peaso_permission_prefilter import benchmark
from peaso.privesc import effective_permissions
from peaso.privesc.effective_permissions import ANY, AllTargets, downgrade
from peaso.privesc.effective_permissions.gcp import GcpModel


class ReferenceGcpModel(GcpModel):
    # Original implementation: resolve and check every scope for every source.
    def check_targets(self, principal, req, template, candidates, localized=False):
        perm = self.requirement_key(req)
        if perm == "cloudidentity.groups.memberships.create":
            return super().check_targets(principal, req, template, candidates, localized)
        held = self.holders(principal, perm)
        if not held:
            return {}
        # When the permission is not granted on individual resources, a target's own-resource requirement
        # depends only on its parent scope: evaluate once per scope (not when a binding condition names resources).
        own = not self._resdep.get((principal.perm_key, perm)) and (localized or template in ("{target.email}", "{target.id}", "{target.resource}"))
        resource_grants = {n for n in held if "/serviceAccounts/" in n or n.startswith("//")} if own else None
        result, memo, single, total = {}, {}, None, 0
        for target in candidates:
            total += 1
            key = None
            if own and target.attrs.get("resource") not in resource_grants:
                key = target.scope
                if key in memo:
                    if memo[key] is not None:
                        result[target.id] = memo[key]
                    continue
            refs, floor = self.resolve(template, principal, target) if not localized else ([self.localize(req, target)], None)
            if refs == [ANY]:
                key = ("any", floor)  # resolution did not depend on this target
                if key in memo:
                    if memo[key] is not None:
                        result[target.id] = memo[key]
                    continue
            grant = None
            for ref in refs:
                got = self.cached_check(principal, req, ref)
                if got is not None and (grant is None or got.confidence == "derived"):
                    grant = got
            if grant is not None:
                grant = downgrade(grant, floor[0], floor[1]) if floor else grant
                result[target.id] = grant
            if key is not None:
                memo[key] = grant
        grants = {id(g) for g in result.values()}
        if result and len(result) == total and len(grants) == 1:
            return AllTargets(next(iter(result.values())))
        return result


def linear_collections(snapshot, kind):
    return [c for c in snapshot.get('collections', []) if c.get('type') == kind]


def compare(projects=200):
    with patch.object(effective_permissions, 'collections', linear_collections):
        before = benchmark('gcp', projects, model_class=ReferenceGcpModel)
    after = benchmark('gcp', projects)
    assert before['output_digest'] == after['output_digest'], 'analysis output changed'
    return {'baseline': before, 'optimized': after,
            'speedup': round(statistics.median(before['seconds']) / statistics.median(after['seconds']), 2),
            'identical_output': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--projects', type=int, default=200)
    args = parser.parse_args()
    print(json.dumps(compare(args.projects), indent=2))
