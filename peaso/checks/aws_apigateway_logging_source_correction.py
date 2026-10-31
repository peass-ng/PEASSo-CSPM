"""Protocol-aware derived execution-logging criterion; signed history is preserved."""
from copy import deepcopy
import hashlib
import json

CHECK_ID = "aws_nist_apigateway_stage_logging_enabled"
PRIOR_FROZEN_SPEC_SHA256 = "2570d6bf4c95aa10190a974eb062b11da753c74de006169fffd525ae023e9463"
FROZEN_SPEC = {'id': 'aws_nist_apigateway_stage_logging_enabled',
 'provider': 'aws',
 'resource_kind': 'http_api_stage',
 'data_source': 'apigateway:GetStages methodSettings and accessLogSettings for every REST/HTTP '
                'stage',
 'predicate': 'For every in-scope stage and every effective method setting after wildcard and '
              'method overrides, PASS only if loggingLevel is INFO or ERROR; FAIL if any effective '
              'method is OFF or missing logging, and UNKNOWN on incomplete stage/method inventory.',
 'severity': 'medium',
 'category': 'compliance',
 'title': 'API Gateway stage logging should be enabled',
 'description': 'Method overrides with logging disabled remain untested.',
 'remediation_hint': 'Configure the resource to satisfy the stated predicate and review missing '
                     'inventory or policy inputs.'}
SOURCE_URL = "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/803dda1f7555ed5cea959aef30cfa0719b030d8c/conformance_pack/apigateway.pp"
SOURCE_SHA256 = "2ee8e6ce867f2b85c49dd00f498ef0328812576bd5a7eee1f63685044a6de90d"
CONTROL_SHA256 = "16ed56584964d6af4f112ed6843fd91e8eb38102d79d2ed4029fe4c68a2e5785"
QUERY_SHA256 = "3f60ce58b1f093493c12348e588f1ca5bbd21039875de184f0b0572dc8c06855"
OFFICIAL_REFERENCES = [
 "https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-stages-stagename.html",
 "https://docs.aws.amazon.com/apigateway/latest/api/API_GetDeployment.html",
 "https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-execution-logging.html",
 "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html",
 "https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html",
 "https://docs.aws.amazon.com/config/latest/developerguide/api-gw-execution-logging-enabled.html",
]

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

TITLE = "Applicable API Gateway stages configure execution logging"
DESCRIPTION_TEXT = ("Evaluates deployed REST method execution-logging settings and configured WebSocket stage defaults and overrides. "
 "AWS does not support execution LoggingLevel on HTTP APIs, which are explicitly not applicable here; HTTP access logging is a separate control. "
 "This is configuration evidence, not proof of log delivery or application traffic.")
DATA_SOURCE = ("Read-only native REST GetStages and stage-bound GetDeployment(embed=apisummary) method inventory; "
 "v2 GetApis ProtocolType joined to GetStages DefaultRouteSettings and RouteSettings. Complete regional source inventories required.")
PREDICATE = ("For applicable stages, PASS requires every bound deployed REST method to resolve to INFO or ERROR after exact override and wildcard field inheritance, "
 "and every WebSocket stage to have a complete INFO/ERROR all-route default with every readable override good or inheriting. "
 "FAIL for a proved OFF deployed REST method with complete required inventories. HTTP stages are excluded as unsupported for execution LoggingLevel; "
 "HTTP-only or no-applicable-stage scope is NOT_APPLICABLE. Unknown protocol, unreadable sources, unresolved REST settings, canaries, "
 "or WebSocket OFF without a deployed route universe remain UNKNOWN. Mixed proven HTTP exclusions do not negate applicable-stage evidence.")
REMEDIATION = ("Configure INFO or ERROR execution logging for applicable REST methods or WebSocket stages and review overrides; "
 "verify actual log delivery separately. Configure HTTP API access logs through its separate control.")
CORRECTED_SPEC = {**FROZEN_SPEC, "title": TITLE, "description": DESCRIPTION_TEXT,
                  "data_source": DATA_SOURCE, "predicate": PREDICATE, "remediation_hint": REMEDIATION}
CORRECTED_SPEC_SHA256 = _digest(CORRECTED_SPEC)
# The v1 derived criterion is hash-pinned before this narrow absence correction.
PRIOR_CORRECTED_SPEC_SHA256 = "c74f15bcc791e99335fc2500820b5e40f960073aac81a1d7fa6a775e6d2d05e7"
PREDICATE = PREDICATE.replace(
 "FAIL for a proved OFF deployed REST method with complete required inventories.",
 "FAIL for a deployed REST method with proved OFF or missing effective INFO/ERROR logging under a complete native GetStages methodSettings map and complete required inventories.")
CORRECTED_SPEC = {**CORRECTED_SPEC, "predicate": PREDICATE}
CORRECTED_SPEC_SHA256 = _digest(CORRECTED_SPEC)
SOURCE_CORRECTION = {
 "version": "peaso-apigateway-logging-source-correction-v2", "status": "source_erratum_successor",
 "prior_frozen_signed_spec_sha256": PRIOR_FROZEN_SPEC_SHA256, "prior_frozen_status": "historical_superseded_for_this_check",
 "current_canonical_spec_sha256": CORRECTED_SPEC_SHA256,
 "prior_current_canonical_spec_sha256": PRIOR_CORRECTED_SPEC_SHA256, "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
 "source_control_lines": "53-80", "source_control_sha256": CONTROL_SHA256,
 "source_query_lines": "206-248", "source_query_sha256": QUERY_SHA256,
 "source_relationship": "Derived protocol-aware configuration rule, stronger than the pinned wildcard/default-only SQL; not a literal SQL port",
 "official_references": OFFICIAL_REFERENCES,
}
DESCRIPTION = {"title": TITLE, "description": DESCRIPTION_TEXT,
 "evaluated": [DATA_SOURCE, "REST exact method and wildcard loggingLevel inheritance", "WebSocket LoggingLevel defaults and sparse route overrides", "v2 parent ProtocolType binding"],
 "pass_when": "All applicable REST methods and WebSocket stage configurations meet the bounded criterion; known HTTP exclusions do not establish a security PASS.",
 "fail_when": "A complete bound deployed REST method has effective loggingLevel OFF or no enabled INFO/ERROR level in a complete native settings map; denied, incomplete, unsupported or malformed evidence is UNKNOWN or DENIED.",
 "not_applicable_when": "No applicable REST or WebSocket stages; HTTP execution LoggingLevel is unsupported by AWS.",
 "unknown_when": "Unresolved method or route coverage, active canary, unknown protocol, incomplete or foreign native evidence.",
 "remediation": REMEDIATION, "source_correction": SOURCE_CORRECTION}

def description():
    return deepcopy(DESCRIPTION)

def correction_provenance():
    return deepcopy(SOURCE_CORRECTION)
