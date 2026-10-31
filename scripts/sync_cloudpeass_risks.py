#!/usr/bin/env python3
"""Vendor the audited provider and Kubernetes classifiers without running scanners."""
from __future__ import annotations

import argparse
from pathlib import Path


def sync(source: Path, target: Path, *, check: bool = False) -> None:
    files = {}
    for provider in ('aws', 'gcp', 'azure', 'k8s'):
        files[target / 'risk_rules' / f'{provider}.yaml'] = (source / 'src/CloudPEASS/risk_rules' / f'{provider}.yaml').read_text()
    classifier = (source / 'src/CloudPEASS/permission_risk_classifier.py').read_text()
    classifier = classifier.replace('Path(__file__).resolve().parent / "risk_rules"', 'Path(__file__).resolve().parent.parent / "risk_rules"')
    files[target / 'scripts/cloud_permission_risks.py'] = classifier
    models = (source / 'src/k8s/models.py').read_text()
    key = models[models.index('@dataclass(frozen=True)\nclass PermissionKey:'):models.index('\n\n@dataclass\nclass PermissionFinding:')]
    k8s = (source / 'src/k8s/risks.py').read_text()
    k8s = k8s.replace('Path(__file__).resolve().parent.parent / \"CloudPEASS\" / \"risk_rules\" / \"k8s.yaml\"', 'Path(__file__).resolve().parent.parent / \"risk_rules\" / \"k8s.yaml\"')
    k8s = k8s.replace('from .models import PermissionKey', 'from dataclasses import dataclass\n\n\n' + key)
    files[target / 'bluepeass/k8s_risks.py'] = k8s
    stale = []
    for path, contents in files.items():
        if check:
            if not path.exists() or path.read_text() != contents:
                stale.append(str(path.relative_to(target)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
    if stale:
        raise SystemExit('Stale CloudPEASS risk files: ' + ', '.join(stale))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cloudpeass-root', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    sync(args.cloudpeass_root.resolve(), Path(__file__).resolve().parent.parent, check=args.check)


if __name__ == '__main__':
    main()
