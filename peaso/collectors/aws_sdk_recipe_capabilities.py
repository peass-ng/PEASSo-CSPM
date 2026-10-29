"""Installed-SDK support for the finite AWS resource-policy recipes, without loading every model at import.

aws_resource_policy_families checks each recipe's operations against the installed botocore service
models. Loading those ~85 models costs about half a second of CPU at import, and every scan process
(including GCP, Azure and Kubernetes scans, through the collector registry) pays it. For a recorded
botocore release the answer is fixed by the models that release bundles, so it is reused when, and
only when, all of these hold:

* the installed botocore is that release,
* the recipe set (ids, services, operations) is the one the answer was recorded for,
* every recipe service resolves to the same latest API version from botocore's bundled data, and
* no other model search path (~/.aws/models, AWS_DATA_PATH or a configured data_path) and no
  botocore plugin can override or extend any recipe service's model.

Otherwise every model is loaded and checked exactly as before. No cloud call is made either way.
"""
from __future__ import annotations

import hashlib
import json
import os

# botocore version -> recipe fingerprint, bundled latest API version per service, and the
# unsupported recipes (id -> missing operations, in recipe order) computed from those models.
RECORDED = {
    "1.43.38": {
        "recipes": "cf01ebe8556bc2134dc16fc9de054224d6a0a41a5c5f78a0d9935a9bd5629a7d",
        "unsupported": [],
        "api_versions": {
            "acm-pca": "2017-08-22",
            "aiops": "2018-05-10",
            "amp": "2020-08-01",
            "apigateway": "2015-07-09",
            "apigatewayv2": "2018-11-29",
            "backup": "2018-11-15",
            "bcm-dashboards": "2025-08-18",
            "bedrock": "2023-04-20",
            "bedrock-agent": "2023-06-05",
            "bedrock-agentcore-control": "2023-06-05",
            "billing": "2023-09-07",
            "cleanroomsml": "2023-09-06",
            "cloudfront": "2020-05-31",
            "cloudhsmv2": "2017-04-28",
            "cloudsearch": "2013-01-01",
            "cloudtrail": "2013-11-01",
            "codeartifact": "2018-09-22",
            "codebuild": "2016-10-06",
            "codeguruprofiler": "2019-07-18",
            "comprehend": "2017-11-27",
            "dsql": "2018-05-10",
            "dynamodb": "2012-08-10",
            "ec2": "2016-11-15",
            "ecr": "2015-09-21",
            "ecr-public": "2020-10-30",
            "efs": "2015-02-01",
            "elbv2": "2015-12-01",
            "entityresolution": "2018-05-10",
            "events": "2015-10-07",
            "glacier": "2012-06-01",
            "glue": "2017-03-31",
            "iam": "2010-05-08",
            "imagebuilder": "2019-12-02",
            "kafka": "2018-11-14",
            "kinesis": "2013-12-02",
            "kms": "2014-11-01",
            "lambda": "2015-03-31",
            "lexv2-models": "2020-08-07",
            "logs": "2014-03-28",
            "lookoutequipment": "2020-12-15",
            "marketplace-catalog": "2018-09-17",
            "mediapackagev2": "2022-12-25",
            "mediastore": "2017-09-01",
            "mediatailor": "2018-04-23",
            "migration-hub-refactor-spaces": "2021-10-26",
            "mpa": "2022-07-26",
            "network-firewall": "2020-11-12",
            "networkmanager": "2019-07-05",
            "oam": "2022-06-10",
            "omics": "2022-11-28",
            "opensearch": "2021-01-01",
            "organizations": "2016-11-28",
            "osis": "2022-01-01",
            "payment-cryptography": "2021-09-14",
            "pinpoint-sms-voice-v2": "2022-03-31",
            "qbusiness": "2023-11-27",
            "ram": "2018-01-04",
            "redshift": "2012-12-01",
            "redshift-serverless": "2021-04-21",
            "rekognition": "2016-06-27",
            "route53-recovery-control-config": "2020-11-02",
            "route53resolver": "2018-04-01",
            "rum": "2018-05-10",
            "s3": "2006-03-01",
            "s3control": "2018-08-20",
            "s3files": "2025-05-05",
            "s3tables": "2018-05-10",
            "s3vectors": "2025-07-15",
            "sagemaker": "2017-07-24",
            "schemas": "2019-12-02",
            "secretsmanager": "2017-10-17",
            "serverlessrepo": "2017-09-08",
            "sesv2": "2019-09-27",
            "signer": "2017-08-25",
            "signin": "2023-01-01",
            "ssm": "2014-11-06",
            "ssm-contacts": "2021-05-03",
            "ssm-incidents": "2018-05-10",
            "ssm-sap": "2018-05-10",
            "vpc-lattice": "2022-11-30",
            "waf": "2015-08-24",
            "waf-regional": "2016-11-28",
            "wafv2": "2019-07-29",
            "xray": "2016-04-12",
        },
    },
}


def fingerprint(recipes, operations):
    rows = [[r.id, r.service, sorted(operations(r))] for r in recipes]
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def recorded(recipes, operations, session):
    """The recorded unsupported-recipe map when it provably applies to this SDK install, else None."""
    import botocore
    entry = RECORDED.get(botocore.__version__)
    if entry is None or fingerprint(recipes, operations) != entry["recipes"]:
        return None
    if os.environ.get("BOTOCORE_EXPERIMENTAL__PLUGINS"):
        return None  # Plugins may rewrite loaded service data.
    try:
        loader = session.get_component("data_loader")
        builtin = os.path.realpath(loader.BUILTIN_DATA_PATH)
        services = {r.service for r in recipes}
        if set(entry["api_versions"]) != services:
            return None
        for path in loader.search_paths:
            if os.path.realpath(path) == builtin or not os.path.isdir(path):
                continue
            if any(os.path.exists(os.path.join(path, service)) for service in services):
                return None
        if os.path.realpath(loader.BUILTIN_DATA_PATH) not in {os.path.realpath(p) for p in loader.search_paths}:
            return None
        for service, version in entry["api_versions"].items():
            if loader.determine_latest_version(service, "service-2") != version:
                return None
    except Exception:
        return None
    return {recipe_id: list(missing) for recipe_id, missing in entry["unsupported"]}


def unsupported_recipes(recipes, operations, check, session):
    """Recipe id -> missing operations for the installed SDK (recorded when provably valid, else live)."""
    known = recorded(recipes, operations, session)
    if known is not None:
        return known
    return {r.id: missing for r in recipes if (missing := check(r, session))}
