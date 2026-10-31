"""Source-bound, family-reviewed prose for native GCP configuration findings.

No cloud operations or evaluator changes. Configuration is not runtime proof.
"""
from copy import deepcopy
import json

VERSION = "gcp-remaining-clarity-v1"
ROWS = json.loads(r'''
{
  "gcp.apikeys.active_service_restrictions": {
    "description_fields": {
      "description": "Joins explicit API-key targets to Service Usage and flags targets whose API is disabled."
    },
    "remediation_fields": {
      "caveats": [
        "Enabled APIs do not establish active key use and remain UNKNOWN; no key string or request is collected."
      ],
      "cli": [],
      "references": [
        {
          "title": "Restrict API targets",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unused disabled API targets; keep only the APIs the key’s clients require."
      ],
      "summary": "Remove unused disabled API targets; keep only the APIs the key’s clients require."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "evaluator": {
          "callable": "_load_08.<locals>._api_key_services"
        }
      },
      "kind": "api_key",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_08.<locals>._inventory"
        },
        "_rows": {
          "callable": "_load_08.<locals>._rows"
        },
        "canonical_service": {
          "callable": "canonical_service"
        },
        "canonical_target": {
          "callable": "canonical_target"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_08.<locals>._api_key_services",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key declares an API target that is disabled in the project."
  },
  "gcp.appengine.version_https_only": {
    "description_fields": {
      "description": "Checks every full serving App Engine handler for SECURE_ALWAYS."
    },
    "remediation_fields": {
      "caveats": [
        "Stopped versions are excluded; no endpoint requests or redirect behavior are tested."
      ],
      "cli": [],
      "references": [
        {
          "title": "App Engine handler HTTPS configuration",
          "url": "https://cloud.google.com/appengine/docs/standard/reference/app-yaml#handlers_element"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require HTTPS on handlers that should not accept HTTP, after checking application behavior."
      ],
      "summary": "Require HTTPS on handlers that should not accept HTTP, after checking application behavior."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_scope": {
          "callable": "_load_09.<locals>._scope"
        },
        "full_representation": {
          "callable": "full_representation"
        },
        "get": {
          "callable": "get"
        },
        "list_of_objects": {
          "callable": "list_of_objects"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "app_engine_version",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_scope": {
          "callable": "_load_09.<locals>._scope"
        },
        "full_representation": {
          "callable": "full_representation"
        },
        "get": {
          "callable": "get"
        },
        "list_of_objects": {
          "callable": "list_of_objects"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_09.<locals>.appengine_https_only",
      "source_qualname": "_load_09.<locals>.appengine_https_only"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A serving App Engine handler does not declare SECURE_ALWAYS."
  },
  "gcp.claude.backend_bucket.bucket_exists": {
    "description_fields": {
      "description": "Joins the backend bucket name to the complete project bucket inventory."
    },
    "remediation_fields": {
      "caveats": [
        "An absent project-local match is MANUAL; the bucket may exist in another project."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bucket.name",
          "bucketName"
        ],
        "kind": "backend_bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Backend buckets",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/backendBuckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the referenced bucket exists under the intended owner before changing or removing the backend."
      ],
      "summary": "Confirm the referenced bucket exists under the intended owner before changing or removing the backend."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "backend_bucket_exists"
        }
      },
      "kind": "backend_bucket",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "backend_bucket_exists",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The referenced bucket is absent from the project-local inventory."
  },
  "gcp.claude.backend_service.external_iap": {
    "description_fields": {
      "description": "Checks external backend services for an enabled IAP declaration."
    },
    "remediation_fields": {
      "caveats": [
        "Public websites may be intentional; IAP configuration does not prove every ingress path is protected."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iap.enabled",
          "loadBalancingScheme"
        ],
        "kind": "backend_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Backend services",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/backendServices"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable IAP if this backend should require an approved identity."
      ],
      "summary": "Enable IAP if this backend should require an approved identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "backend_iap"
        }
      },
      "kind": "backend_service",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "backend_iap",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The external backend service does not enable IAP."
  },
  "gcp.claude.bigquery_dataset.no_gmail_access": {
    "description_fields": {
      "description": "Checks dataset userByEmail ACL entries for the gmail.com suffix."
    },
    "remediation_fields": {
      "caveats": [
        "The predicate uses a string suffix; group expansion and effective permissions are not evaluated."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "access[].userByEmail"
        ],
        "kind": "bigquery_dataset",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery dataset resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review whether the listed consumer identities need dataset access and remove unnecessary entries."
      ],
      "summary": "Review whether the listed consumer identities need dataset access and remove unnecessary entries."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "dataset_domain.<locals>.evaluate"
        }
      },
      "kind": "bigquery_dataset",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "suffix": "gmail.com"
      },
      "predicate_qualname": "dataset_domain.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A dataset user ACL entry ends in gmail.com."
  },
  "gcp.claude.bigquery_dataset.no_googlegroups_access": {
    "description_fields": {
      "description": "Checks dataset userByEmail ACL entries for the googlegroups.com suffix."
    },
    "remediation_fields": {
      "caveats": [
        "The predicate uses a string suffix; group membership and effective permissions are not evaluated."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "access[].userByEmail"
        ],
        "kind": "bigquery_dataset",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery dataset resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review whether the listed identities need dataset access and remove unnecessary entries."
      ],
      "summary": "Review whether the listed identities need dataset access and remove unnecessary entries."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "dataset_domain.<locals>.evaluate"
        }
      },
      "kind": "bigquery_dataset",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "suffix": "googlegroups.com"
      },
      "predicate_qualname": "dataset_domain.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A dataset user ACL entry ends in googlegroups.com."
  },
  "gcp.claude.bucket.log_sink_not_public": {
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks public IAM bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "log_sink.destination",
          "name"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public IAM grants from the log destination."
      ],
      "summary": "Remove unnecessary public IAM grants from the log destination."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "log_bucket.<locals>.evaluate"
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "evaluate_bucket": {
          "callable": "_log_public"
        }
      },
      "predicate_qualname": "log_bucket.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The log destination IAM policy declares a public principal."
  },
  "gcp.claude.bucket.log_sink_retention_locked": {
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks retentionPolicy.isLocked."
    },
    "remediation_fields": {
      "caveats": [
        "Same-scope sink destinations only; locking does not prove log export or retained volume."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "log_sink.destination",
          "name",
          "retentionPolicy.isLocked"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Choose suitable retention and lock it only after reviewing the irreversible retention commitment."
      ],
      "summary": "Choose suitable retention and lock it only after reviewing the irreversible retention commitment."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "log_bucket.<locals>.evaluate"
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "evaluate_bucket": {
          "callable": "_locked"
        }
      },
      "predicate_qualname": "log_bucket.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log-sink destination bucket has no locked retention policy."
  },
  "gcp.claude.bucket.log_sink_retention_policy": {
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks for a retention policy."
    },
    "remediation_fields": {
      "caveats": [
        "Policy presence alone does not establish an adequate duration or successful exports."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "log_sink.destination",
          "name",
          "retentionPolicy.retentionPeriod"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable retention for this log destination."
      ],
      "summary": "Configure suitable retention for this log destination."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "log_bucket.<locals>.evaluate"
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "evaluate_bucket": {
          "callable": "_retention"
        }
      },
      "predicate_qualname": "log_bucket.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log-sink destination bucket has no retention policy."
  },
  "gcp.claude.bucket.log_sink_versioning": {
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks object versioning."
    },
    "remediation_fields": {
      "caveats": [
        "Versioning configuration does not establish successful exports or restoration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "log_sink.destination",
          "name",
          "versioning.enabled"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable versioning if recovery of replaced or deleted log objects is required."
      ],
      "summary": "Enable versioning if recovery of replaced or deleted log objects is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "log_bucket.<locals>.evaluate"
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "evaluate_bucket": {
          "callable": "_log_versioning"
        }
      },
      "predicate_qualname": "log_bucket.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Object versioning is disabled on the log destination."
  },
  "gcp.claude.bucket.retention_90_days": {
    "description_fields": {
      "description": "Checks bucket retention duration for at least 90 whole days."
    },
    "remediation_fields": {
      "caveats": [
        "The duration is a profile requirement; it does not prove log coverage or require locking."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "retentionPolicy.retentionPeriod"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set at least 90 days of retention if this data must meet that retention profile."
      ],
      "summary": "Set at least 90 days of retention if this data must meet that retention profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "bucket_retention"
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_retention",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket has no retention policy of at least 90 days."
  },
  "gcp.claude.dns_zone.dnssec_enabled": {
    "description_fields": {
      "description": "Checks public-zone DNSSEC state for exactly on."
    },
    "remediation_fields": {
      "caveats": [
        "Transfer state does not pass this profile; configuration does not prove a valid signing chain."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "dnssecConfig.state",
          "visibility"
        ],
        "kind": "dns_managed_zone",
        "target": "resource"
      },
      "references": [
        {
          "title": "DNSSEC",
          "url": "https://cloud.google.com/dns/docs/dnssec"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable DNSSEC with a coordinated parent DS-record rollout."
      ],
      "summary": "Enable DNSSEC with a coordinated parent DS-record rollout."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "zone_dnssec"
        }
      },
      "kind": "dns_managed_zone",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "zone_dnssec",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The public zone does not declare DNSSEC on."
  },
  "gcp.claude.dns_zone.ksk_not_rsasha1": {
    "description_fields": {
      "description": "Checks enabled or transferring public-zone key-signing specifications for RSASHA1."
    },
    "remediation_fields": {
      "caveats": [
        "Private zones and DNSSEC-off zones are not applicable; no DNS answers are probed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "dnssecConfig.defaultKeySpecs[].algorithm",
          "dnssecConfig.defaultKeySpecs[].keyType",
          "dnssecConfig.state",
          "visibility"
        ],
        "kind": "dns_managed_zone",
        "target": "resource"
      },
      "references": [
        {
          "title": "DNSSEC",
          "url": "https://cloud.google.com/dns/docs/dnssec"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Plan a supported key-signing rollover and coordinate parent DS records."
      ],
      "summary": "Plan a supported key-signing rollover and coordinate parent DS records."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "rsasha1.<locals>.evaluate"
        }
      },
      "kind": "dns_managed_zone",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "key_type": "keySigning"
      },
      "predicate_qualname": "rsasha1.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key-signing specification uses RSASHA1."
  },
  "gcp.claude.dns_zone.zsk_not_rsasha1": {
    "description_fields": {
      "description": "Checks enabled or transferring public-zone zone-signing specifications for RSASHA1."
    },
    "remediation_fields": {
      "caveats": [
        "Private zones and DNSSEC-off zones are not applicable; no DNS answers are probed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "dnssecConfig.defaultKeySpecs[].algorithm",
          "dnssecConfig.defaultKeySpecs[].keyType",
          "dnssecConfig.state",
          "visibility"
        ],
        "kind": "dns_managed_zone",
        "target": "resource"
      },
      "references": [
        {
          "title": "DNSSEC",
          "url": "https://cloud.google.com/dns/docs/dnssec"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Plan a supported zone-signing rollover and verify DNS resolution."
      ],
      "summary": "Plan a supported zone-signing rollover and verify DNS resolution."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "rsasha1.<locals>.evaluate"
        }
      },
      "kind": "dns_managed_zone",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "key_type": "zoneSigning"
      },
      "predicate_qualname": "rsasha1.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The zone-signing specification uses RSASHA1."
  },
  "gcp.claude.firewall.default_rules_not_open": {
    "description_fields": {
      "description": "Checks the four listed default-network rules for Internet-wide source ranges; HTTP and HTTPS names are exceptions."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "direction",
          "name",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict unnecessary default-rule sources and preserve intended administration paths."
      ],
      "summary": "Restrict unnecessary default-rule sources and preserve intended administration paths."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "firewall_default_rules"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "firewall_default_rules",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A listed default-network rule declares Internet-wide sources."
  },
  "gcp.claude.firewall.logging_enabled": {
    "description_fields": {
      "description": "Checks the firewall rule logConfig.enable flag."
    },
    "remediation_fields": {
      "caveats": [
        "The flag does not prove successful log delivery or complete connection capture."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logConfig.enable"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable rule logging where connection audit records are needed."
      ],
      "summary": "Enable rule logging where connection audit records are needed."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "firewall_logging"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "firewall_logging",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Firewall rule logging is disabled."
  },
  "gcp.claude.firewall.public_ingress_all_protocols": {
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide sources with an all-protocol allow declaration."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "name",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace all-protocol ingress with the specific protocols, ports and sources that are required."
      ],
      "summary": "Replace all-protocol ingress with the specific protocols, ports and sources that are required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "firewall_all_protocols"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "firewall_all_protocols",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress over all protocols."
  },
  "gcp.claude.firewall.public_ingress_common_ports": {
    "description_fields": {
      "description": "Checks active public ingress rules for the listed administrative and database ports over TCP, UDP or SCTP."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "name",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the affected administrative or database ports to required clients."
      ],
      "summary": "Restrict the affected administrative or database ports to required clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "firewall_common_ports"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "firewall_common_ports",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress to a listed administrative or database port."
  },
  "gcp.claude.firewall.public_ingress_tcp_udp": {
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide TCP, UDP or all-protocol allowances."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "name",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Keep public service ports only where needed; restrict unnecessary sources and ports."
      ],
      "summary": "Keep public service ports only where needed; restrict unnecessary sources and ports."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "firewall_tcp_udp"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "firewall_tcp_udp",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide TCP or UDP ingress."
  },
  "gcp.claude.firewall.public_ingress_without_target": {
    "description_fields": {
      "description": "Checks public ingress allow rules for absence of target tags and target service accounts."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "name",
          "sourceRanges[]",
          "targetTags[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Limit this rule to the workload targets that need public traffic."
      ],
      "summary": "Limit this rule to the workload targets that need public traffic."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "firewall_without_target"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "firewall_without_target",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The public ingress rule has no target tag or service-account restriction."
  },
  "gcp.claude.gke.binary_authorization": {
    "description_fields": {
      "description": "Checks documented Binary Authorization modes for a non-disabled configuration.",
      "description_correction": {
        "base_row_sha256": "99bf7141236eede310f5ba1f1f91ed2de3b69cdde44ddead595c43f7b406edb4",
        "change": "Accept only documented evaluation modes; unknown modes remain UNKNOWN. Continuous-validation-only mode does not prove admission enforcement.",
        "prior_predicate_sha256": "413fafcdfd584b6c25dedecf97c9e357fd1f47637fa4ba3ed54bff0e9bd1cb09",
        "reference": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/projects.locations.clusters#EvaluationMode",
        "version": "gcp-clarity-input-validation-v1"
      },
      "fail_when": "FAIL when configuration is absent or the resolved mode is DISABLED or EVALUATION_MODE_UNSPECIFIED; unknown mode strings are UNKNOWN.",
      "pass_when": "PASS for PROJECT_SINGLETON_POLICY_ENFORCE, POLICY_BINDINGS or POLICY_BINDINGS_AND_PROJECT_SINGLETON_POLICY_ENFORCE; a legacy enabled=true fallback counts when no mode is supplied."
    },
    "remediation_fields": {
      "caveats": [
        "POLICY_BINDINGS is continuous validation, not admission enforcement; the configured mode does not establish policy strength or observed decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "binaryAuthorization.evaluationMode",
          "enabled"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable a supported enforcing Binary Authorization mode and define the intended image policy."
      ],
      "summary": "Enable a supported enforcing Binary Authorization mode and define the intended image policy."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_binauthz"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_binauthz",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Binary Authorization is missing, disabled or unspecified."
  },
  "gcp.claude.gke.dashboard_disabled": {
    "description_fields": {
      "description": "Checks the legacy Kubernetes Dashboard add-on disabled setting."
    },
    "remediation_fields": {
      "caveats": [
        "The add-on setting does not establish Dashboard exposure or effective permissions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "addonsConfig.kubernetesDashboard.disabled",
          "disabled"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable the legacy Dashboard add-on if present."
      ],
      "summary": "Disable the legacy Dashboard add-on if present."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_dashboard"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_dashboard",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The legacy Dashboard add-on is enabled."
  },
  "gcp.claude.gke.http_load_balancing": {
    "description_fields": {
      "description": "Checks whether the HTTP load-balancing add-on is explicitly disabled."
    },
    "remediation_fields": {
      "caveats": [
        "An alternative ingress controller may be intentional; add-on presence does not prove safe ingress configuration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "addonsConfig.httpLoadBalancing.disabled",
          "disabled"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the add-on only if workloads use GKE Ingress."
      ],
      "summary": "Enable the add-on only if workloads use GKE Ingress."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_http_lb"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_http_lb",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The HTTP load-balancing add-on is disabled."
  },
  "gcp.claude.gke.logging_enabled": {
    "description_fields": {
      "description": "Checks loggingService for an empty string or none."
    },
    "remediation_fields": {
      "caveats": [
        "A nonempty service name passes this comparison; actual log coverage and retention are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "loggingService"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the intended cluster logging service and verify delivered logs."
      ],
      "summary": "Enable the intended cluster logging service and verify delivered logs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "telemetry.<locals>.evaluate"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "field": "loggingService"
      },
      "predicate_qualname": "telemetry.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster logging service is empty or none."
  },
  "gcp.claude.gke.master_authorized_networks_restricted": {
    "description_fields": {
      "description": "Checks master authorized networks enablement and rejects exact Internet-wide CIDR entries."
    },
    "remediation_fields": {
      "caveats": [
        "This checks declared restrictions, not public endpoint status or actual connectivity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "enabled",
          "masterAuthorizedNetworksConfig.cidrBlocks[].cidrBlock",
          "masterAuthorizedNetworksConfig.enabled"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable authorized networks with the administrator ranges that need control-plane access."
      ],
      "summary": "Enable authorized networks with the administrator ranges that need control-plane access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_man"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_man",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Authorized networks are disabled or include an Internet-wide CIDR."
  },
  "gcp.claude.gke.monitoring_enabled": {
    "description_fields": {
      "description": "Checks monitoringService for an empty string or none."
    },
    "remediation_fields": {
      "caveats": [
        "A nonempty service name passes this comparison; actual telemetry and notification delivery are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "monitoringService"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the intended monitoring service and verify its metrics and alerts."
      ],
      "summary": "Enable the intended monitoring service and verify its metrics and alerts."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "telemetry.<locals>.evaluate"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "field": "monitoringService"
      },
      "predicate_qualname": "telemetry.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster monitoring service is empty or none."
  },
  "gcp.claude.gke.network_no_untargeted_public_ingress": {
    "description_fields": {
      "description": "Joins the cluster network to active Internet-wide ingress rules without target selectors."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. Targeted-only rules require separate node matching."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed",
          "name",
          "networkConfig.network"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict unnecessary public sources or scope rules to the workloads that need them."
      ],
      "summary": "Restrict unnecessary public sources or scope rules to the workloads that need them."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_open_network"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_open_network",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster network has an untargeted public ingress rule."
  },
  "gcp.claude.gke.no_client_certificate": {
    "description_fields": {
      "description": "Checks for a legacy client certificate or issueClientCertificate=true declaration."
    },
    "remediation_fields": {
      "caveats": [
        "Certificate presence does not establish valid credentials or effective privileges; private key contents are not shown."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "masterAuth.clientCertificate",
          "masterAuth.clientCertificateConfig.issueClientCertificate"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Migrate required clients to supported identity authentication before replacing legacy certificate access."
      ],
      "summary": "Migrate required clients to supported identity authentication before replacing legacy certificate access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_client_cert"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_client_cert",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster declares legacy client-certificate issuance."
  },
  "gcp.claude.gke.no_default_network": {
    "description_fields": {
      "description": "Checks whether the cluster network string equals default."
    },
    "remediation_fields": {
      "caveats": [
        "This exact-name comparison does not evaluate network topology or full resource-name aliases."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "network"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated network if workload isolation requires one."
      ],
      "summary": "Use a dedicated network if workload isolation requires one."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_default_network"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_default_network",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster network is named default."
  },
  "gcp.claude.gke.no_kubernetes_alpha": {
    "description_fields": {
      "description": "Checks the cluster enableKubernetesAlpha flag."
    },
    "remediation_fields": {
      "caveats": [
        "The setting does not identify a specific vulnerability or test workload availability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "enableKubernetesAlpha"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a supported non-alpha cluster for workloads requiring production stability."
      ],
      "summary": "Use a supported non-alpha cluster for workloads requiring production stability."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_alpha"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_alpha",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Kubernetes alpha features are enabled."
  },
  "gcp.claude.gke.nodes_no_default_service_account": {
    "description_fields": {
      "description": "Checks every node pool, or fallback nodeConfig, for default Compute Engine identity selection."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Node identity declarations do not establish actual workload identity permissions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "nodePools[].name",
          "nodePools[].config.serviceAccount",
          "nodeConfig.serviceAccount"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use dedicated node identities with the permissions the nodes need."
      ],
      "summary": "Use dedicated node identities with the permissions the nodes need."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_default_sa"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_default_sa",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A node pool selects the default Compute Engine identity."
  },
  "gcp.claude.gke.private_nodes": {
    "description_fields": {
      "description": "Checks legacy or current cluster defaults for private-node enablement."
    },
    "remediation_fields": {
      "caveats": [
        "Cluster defaults do not inspect node-pool overrides or prove effective network isolation."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "networkConfig.defaultEnablePrivateNodes",
          "privateClusterConfig.enablePrivateNodes"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use private nodes where node external addresses are unnecessary."
      ],
      "summary": "Use private nodes where node external addresses are unnecessary."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_private_nodes"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_private_nodes",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster does not declare private-node enablement."
  },
  "gcp.claude.gke.release_channel": {
    "description_fields": {
      "description": "Checks for a supported RAPID, REGULAR, STABLE or EXTENDED release channel.",
      "description_correction": {
        "base_row_sha256": "598a491b59797c2c77a8f806093d5dda10b3ca0ba3810639bad415256d4d9121",
        "change": "Accept only RAPID, REGULAR, STABLE, EXTENDED or UNSPECIFIED; unknown channel strings remain UNKNOWN.",
        "prior_predicate_sha256": "d1c05b49ae79b5d27db223c142359874c25f58be8aaa3cdf31339679ed1f5ae2",
        "reference": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#ReleaseChannel",
        "version": "gcp-clarity-input-validation-v1"
      },
      "fail_when": "FAIL when channel is absent or UNSPECIFIED; unknown channel strings are UNKNOWN.",
      "pass_when": "PASS when channel is RAPID, REGULAR, STABLE or EXTENDED."
    },
    "remediation_fields": {
      "caveats": [
        "Channel selection does not prove nodes are patched; unknown strings remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "releaseChannel.channel"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Choose a supported release channel compatible with the cluster’s maintenance requirements."
      ],
      "summary": "Choose a supported release channel compatible with the cluster’s maintenance requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_channel"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_channel",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster does not select a release channel."
  },
  "gcp.claude.gke.subnetwork_private_google_access": {
    "description_fields": {
      "description": "Joins the cluster subnet reference to its Private Google Access declaration."
    },
    "remediation_fields": {
      "caveats": [
        "The setting is not Internet exposure protection or a connection test."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "networkConfig.subnetwork"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable Private Google Access if private nodes need supported Google APIs."
      ],
      "summary": "Enable Private Google Access if private nodes need supported Google APIs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_subnet_pga"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_subnet_pga",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Private Google Access is disabled on the cluster subnet."
  },
  "gcp.claude.gke.zone_redundant": {
    "description_fields": {
      "description": "Checks zonal clusters for at least three distinct node locations in the same region."
    },
    "remediation_fields": {
      "caveats": [
        "Regional clusters are not applicable; configured locations do not prove healthy node or workload placement."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "location",
          "locations[]"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use suitable multi-zone placement where a zonal failure must be tolerated."
      ],
      "summary": "Use suitable multi-zone placement where a zonal failure must be tolerated."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "gke_zones"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "gke_zones",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The zonal cluster declares fewer than three node zones."
  },
  "gcp.claude.iam_policy.no_all_users": {
    "description_fields": {
      "description": "Checks project, folder or organization IAM bindings for allUsers."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings[].members[]",
          "bindings[].role",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary allUsers root-policy grants and preserve intended access."
      ],
      "summary": "Remove unnecessary allUsers root-policy grants and preserve intended access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "no_all_users"
        }
      },
      "kind": "iam_policy",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "no_all_users",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "The root IAM policy declares an allUsers grant."
  },
  "gcp.claude.iam_policy.no_project_sa_user_or_token_creator": {
    "description_fields": {
      "description": "Checks project-root IAM bindings for unconditional Service Account User or Token Creator grants."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Conditional-only matches require review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings[].members[]",
          "bindings[].role",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Grant identity use or token creation at individual service-account scope where required."
      ],
      "summary": "Grant identity use or token creation at individual service-account scope where required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "project_sa_roles"
        }
      },
      "kind": "iam_policy",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "project_sa_roles",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The project declares an unconditional identity-use or token-creator grant."
  },
  "gcp.claude.image.not_public": {
    "description_fields": {
      "description": "Checks custom-image IAM bindings for allUsers or allAuthenticatedUsers principals."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings",
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role"
        ],
        "kind": "image",
        "target": "resource"
      },
      "references": [
        {
          "title": "Custom image access",
          "url": "https://cloud.google.com/compute/docs/images/sharing-images-across-projects"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public image grants and preserve intended users."
      ],
      "summary": "Remove unnecessary public image grants and preserve intended users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "image_public"
        }
      },
      "kind": "image",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "image_public",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The custom-image IAM policy declares a public principal."
  },
  "gcp.claude.instance.disks_csek": {
    "description_fields": {
      "description": "Checks every attached disk for a customer-supplied encryption-key digest."
    },
    "remediation_fields": {
      "caveats": [
        "Missing CSEK metadata does not mean plaintext; Google-managed or customer-managed KMS encryption may be used."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "disks[]",
          "disks[].deviceName",
          "disks[].diskEncryptionKey.sha256"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use customer-supplied keys only if required and maintain recoverable key management."
      ],
      "summary": "Use customer-supplied keys only if required and maintain recoverable key management."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_csek"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "instance_csek",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "An attached disk has no customer-supplied key digest."
  },
  "gcp.claude.instance.not_preemptible": {
    "description_fields": {
      "description": "Checks the VM scheduling.preemptible flag."
    },
    "remediation_fields": {
      "caveats": [
        "Preemptible workloads may be intentional; this profile evaluates availability preference."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "scheduling.preemptible"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use standard provisioning if the workload must tolerate no preemption."
      ],
      "summary": "Use standard provisioning if the workload must tolerate no preemption."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_not_preemptible"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "instance_not_preemptible",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The VM is preemptible."
  },
  "gcp.claude.instance.not_preemptible_or_spot": {
    "description_fields": {
      "description": "Checks whether the VM is preemptible or uses the SPOT provisioning model."
    },
    "remediation_fields": {
      "caveats": [
        "Spot workloads may be intentional; this does not predict an actual interruption."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "scheduling.preemptible",
          "scheduling.provisioningModel"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use suitable non-Spot provisioning where interruption is unacceptable."
      ],
      "summary": "Use suitable non-Spot provisioning where interruption is unacceptable."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_not_spot"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "instance_not_spot",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM is preemptible or uses Spot provisioning."
  },
  "gcp.claude.instance.sa_no_basic_role": {
    "description_fields": {
      "description": "Checks attached VM identities for project-root Owner or Editor declarations, excluding labeled GKE nodes."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace unnecessary Owner or Editor grants with the VM’s required permissions."
      ],
      "summary": "Replace unnecessary Owner or Editor grants with the VM’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [],
        "predefined": [
          "roles/owner",
          "roles/editor"
        ],
        "skip_gke": true
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has an Owner or Editor role declaration."
  },
  "gcp.claude.instance.sa_no_data_destruction_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role data destruction permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary data destruction grants from the VM identity."
      ],
      "summary": "Remove unnecessary data destruction grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "compute.instances.delete",
          "compute.disks.delete",
          "compute.snapshots.delete",
          "compute.images.delete",
          "storage.buckets.delete",
          "cloudsql.databases.delete",
          "cloudsql.instances.delete",
          "file.instances.delete"
        ],
        "predefined": [
          "roles/cloudsql.admin",
          "roles/cloudsql.instanceUser",
          "roles/compute.admin",
          "roles/compute.instanceAdmin.v1"
        ],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching data destruction grant declaration."
  },
  "gcp.claude.instance.sa_no_database_write_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role database write permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary database write grants from the VM identity."
      ],
      "summary": "Remove unnecessary database write grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "cloudsql.databases.update",
          "cloudsql.instances.update",
          "datastore.databases.update",
          "datastore.entities.update",
          "datastore.indexes.update",
          "spanner.databases.update",
          "spanner.databases.write",
          "spanner.instances.update",
          "bigtable.clusters.update",
          "bigtable.instances.update",
          "bigtable.tables.update",
          "redis.instances.update",
          "memcache.instances.update",
          "datamigration.migrationjobs.update",
          "datamigration.connectionprofiles.update",
          "datamigration.conversionworkspaces.update",
          "alloydb.clusters.update",
          "alloydb.instances.update"
        ],
        "predefined": [
          "roles/cloudsql.admin",
          "roles/cloudsql.instanceUser",
          "roles/datastore.indexAdmin",
          "roles/datastore.owner",
          "roles/datastore.user",
          "roles/alloydb.admin",
          "roles/bigtable.admin",
          "roles/datamigration.admin",
          "roles/datamigration.serviceAgent",
          "roles/memcache.admin",
          "roles/redis.admin",
          "roles/redisenterprisecloud.admin",
          "roles/spanner.admin",
          "roles/spanner.databaseAdmin"
        ],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching database write grant declaration."
  },
  "gcp.claude.instance.sa_no_deny_policy_write_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role deny policy write permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary deny policy write grants from the VM identity."
      ],
      "summary": "Remove unnecessary deny policy write grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "iam.denypolicies.delete",
          "iam.denypolicies.update"
        ],
        "predefined": [],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching deny policy write grant declaration."
  },
  "gcp.claude.instance.sa_no_deployments_manager_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role deployments manager permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary deployments manager grants from the VM identity."
      ],
      "summary": "Remove unnecessary deployments manager grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "deploymentmanager.deployments.create",
          "deploymentmanager.deployments.update"
        ],
        "predefined": [
          "roles/deploymentmanager.editor"
        ],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching deployments manager grant declaration."
  },
  "gcp.claude.instance.sa_no_disrupt_logging_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role disrupt logging permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary disrupt logging grants from the VM identity."
      ],
      "summary": "Remove unnecessary disrupt logging grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "logging.buckets.delete",
          "logging.buckets.update",
          "logging.logMetrics.delete",
          "logging.logMetrics.update",
          "logging.logs.delete",
          "logging.sinks.delete",
          "logging.sinks.update"
        ],
        "predefined": [
          "roles/logging.bucketWriter",
          "roles/logging.configWriter",
          "roles/logging.admin"
        ],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching disrupt logging grant declaration."
  },
  "gcp.claude.instance.sa_no_iam_write_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role iam write permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary iam write grants from the VM identity."
      ],
      "summary": "Remove unnecessary iam write grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "accessapproval.requests.approve",
          "accessapproval.requests.dismiss",
          "accessapproval.settings.delete",
          "accessapproval.settings.update",
          "accesscontextmanager.accessLevels.create",
          "accesscontextmanager.accessLevels.delete",
          "accesscontextmanager.accessLevels.replaceAll",
          "accesscontextmanager.accessLevels.update",
          "accesscontextmanager.accessPolicies.create",
          "accesscontextmanager.accessPolicies.delete",
          "accesscontextmanager.accessPolicies.setIamPolicy",
          "accesscontextmanager.accessPolicies.update",
          "accesscontextmanager.gcpUserAccessBindings.create",
          "accesscontextmanager.gcpUserAccessBindings.delete",
          "accesscontextmanager.gcpUserAccessBindings.update",
          "accesscontextmanager.policies.create",
          "accesscontextmanager.policies.delete",
          "accesscontextmanager.policies.setIamPolicy",
          "accesscontextmanager.policies.update",
          "iam.roles.create",
          "iam.roles.delete",
          "iam.roles.undelete",
          "iam.roles.update",
          "iam.serviceAccounts.getAccessToken",
          "iam.serviceAccountKeys.create",
          "iam.serviceAccountKeys.delete",
          "iam.serviceAccounts.create",
          "iam.serviceAccounts.delete",
          "iam.serviceAccounts.disable",
          "iam.serviceAccounts.enable",
          "iam.serviceAccounts.setIamPolicy",
          "iam.serviceAccounts.undelete",
          "iam.serviceAccounts.update",
          "iam.serviceAccounts.implicitDelegation",
          "iam.serviceAccounts.signBlob",
          "iam.serviceAccounts.signJwt",
          "iam.serviceAccounts.actAs",
          "compute.backendServices.setIamPolicy",
          "compute.disks.removeResourcePolicies",
          "compute.disks.setIamPolicy",
          "compute.firewallPolicies.setIamPolicy",
          "compute.globalOperations.setIamPolicy",
          "compute.images.setIamPolicy",
          "compute.instanceTemplates.setIamPolicy",
          "compute.instances.removeResourcePolicies",
          "compute.instances.setIamPolicy",
          "compute.instances.setServiceAccount",
          "compute.machineImages.setIamPolicy",
          "compute.maintenancePolicies.setIamPolicy",
          "compute.snapshots.setIamPolicy"
        ],
        "predefined": [],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching iam write grant declaration."
  },
  "gcp.claude.instance.sa_no_service_account_impersonate_permission": {
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role service account impersonate permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Only project-root declarations are assessed; predefined-role matches use the profile table, custom roles use collected definitions, and conditional-only matches need review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "name",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary service account impersonate grants from the VM identity."
      ],
      "summary": "Remove unnecessary service account impersonate grants from the VM identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_grant.<locals>.evaluate"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "permissions": [
          "iam.serviceAccounts.getAccessToken",
          "iam.serviceAccounts.signBlob",
          "iam.serviceAccounts.signJwt",
          "iam.serviceAccounts.implicitDelegation",
          "iam.serviceAccounts.getOpenIdToken",
          "iam.serviceAccounts.actAs"
        ],
        "predefined": [
          "roles/iam.securityAdmin"
        ],
        "skip_gke": false
      },
      "predicate_qualname": "instance_grant.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching service account impersonate grant declaration."
  },
  "gcp.claude.instance.suspended_without_disks": {
    "description_fields": {
      "description": "Checks SUSPENDED or SUSPENDING VMs for any attached disks."
    },
    "remediation_fields": {
      "caveats": [
        "The predicate counts all attached disk declarations; it does not establish data sensitivity or recoverability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "disks",
          "disks[].deviceName",
          "status"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review whether the suspended VM and its disks are still needed before detaching or deleting anything."
      ],
      "summary": "Review whether the suspended VM and its disks are still needed before detaching or deleting anything."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "instance_suspended"
        }
      },
      "kind": "instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "instance_suspended",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The suspended VM still has attached disks."
  },
  "gcp.claude.instance_group_manager.autohealing": {
    "description_fields": {
      "description": "Checks managed instance-group policies for a nonempty autohealing health-check reference."
    },
    "remediation_fields": {
      "caveats": [
        "A reference does not prove health-check correctness or successful recovery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "autoHealingPolicies[].healthCheck"
        ],
        "kind": "instance_group_manager",
        "target": "resource"
      },
      "references": [
        {
          "title": "Managed instance groups",
          "url": "https://cloud.google.com/compute/docs/instance-groups"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable autohealing check if automatic recovery is required."
      ],
      "summary": "Configure a suitable autohealing check if automatic recovery is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "mig_autohealing"
        }
      },
      "kind": "instance_group_manager",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "mig_autohealing",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance group has no autohealing health-check reference."
  },
  "gcp.claude.instance_group_manager.load_balancer_attached": {
    "description_fields": {
      "description": "Joins the managed instance group to backend-service group references."
    },
    "remediation_fields": {
      "caveats": [
        "No matching project-local backend produces MANUAL, not a proven dangling or insecure group."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "backend_service.backends[].group",
          "instanceGroup"
        ],
        "kind": "instance_group_manager",
        "target": "resource"
      },
      "references": [
        {
          "title": "Managed instance groups",
          "url": "https://cloud.google.com/compute/docs/instance-groups"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the group intentionally serves no load-balanced traffic or attach the required backend."
      ],
      "summary": "Confirm the group intentionally serves no load-balanced traffic or attach the required backend."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "mig_backend"
        }
      },
      "kind": "instance_group_manager",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "mig_backend",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "No project-local backend reference is confirmed."
  },
  "gcp.claude.instance_group_manager.multiple_zones": {
    "description_fields": {
      "description": "Checks that a managed instance group declares at least two distinct zones."
    },
    "remediation_fields": {
      "caveats": [
        "Declared placement does not establish healthy capacity in each zone."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "distributionPolicy.zones",
          "distributionPolicy.zones[].zone",
          "region",
          "zone"
        ],
        "kind": "instance_group_manager",
        "target": "resource"
      },
      "references": [
        {
          "title": "Managed instance groups",
          "url": "https://cloud.google.com/compute/docs/instance-groups"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a multi-zone regional group where zonal-failure tolerance is required."
      ],
      "summary": "Use a multi-zone regional group where zonal-failure tolerance is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "mig_zones"
        }
      },
      "kind": "instance_group_manager",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "mig_zones",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The managed instance group declares fewer than two zones."
  },
  "gcp.claude.instance_template.no_ip_forwarding": {
    "description_fields": {
      "description": "Checks the instance template properties.canIpForward flag."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "properties.canIpForward"
        ],
        "kind": "instance_template",
        "target": "resource"
      },
      "references": [
        {
          "title": "Instance templates",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instanceTemplates"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Create a template revision with forwarding disabled unless routing is intended."
      ],
      "summary": "Create a template revision with forwarding disabled unless routing is intended."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "template_ip_forwarding"
        }
      },
      "kind": "instance_template",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "template_ip_forwarding",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance template enables IP forwarding."
  },
  "gcp.claude.kms_key.rotation_100_days": {
    "description_fields": {
      "description": "Checks a positive encryption-key rotation period no longer than 100 days.",
      "description_correction": {
        "base_row_sha256": "7dc447cd6ebabdcae8097eeef5fe9fa09bc806a52dbd145b4745eff6a28633d0",
        "change": "Reject nonpositive automatic rotation durations as UNKNOWN rather than PASS.",
        "prior_predicate_sha256": "783a12da1f81d72cd4fd59868518005033fa2cfec454fe93ab5f81d50b19cebb",
        "reference": "https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys",
        "version": "gcp-clarity-input-validation-v1"
      },
      "fail_when": "FAIL when no automatic rotation period is declared or the positive interval exceeds 100 days.",
      "pass_when": "PASS when the applicable key declares a positive automatic rotation interval no longer than 100 days."
    },
    "remediation_fields": {
      "caveats": [
        "Nonpositive intervals remain UNKNOWN; the schedule does not establish the last rotation or re-encrypt existing data."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "primary.state",
          "purpose",
          "rotationPeriod"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable automatic rotation within 100 days where required."
      ],
      "summary": "Configure suitable automatic rotation within 100 days where required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "kms_rotation_100"
        }
      },
      "kind": "kms_key",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "kms_rotation_100",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The key omits an automatic rotation period or declares more than 100 days."
  },
  "gcp.claude.kms_key.users_limited_to_3": {
    "description_fields": {
      "description": "Checks for public key-policy bindings or more than three members in an individual binding."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. The three-member limit applies per binding, not to effective users or group membership."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unintended public grants and review whether broader member lists are necessary."
      ],
      "summary": "Remove unintended public grants and review whether broader member lists are necessary."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "kms_users"
        }
      },
      "kind": "kms_key",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "kms_users",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key policy declares a public principal or a binding with more than three members."
  },
  "gcp.claude.logging.metric_alert_audit_configuration_changes": {
    "description_fields": {
      "description": "Matches the audit configuration changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for audit configuration changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for audit configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "audit_configuration_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_bucket_iam_changes": {
    "description_fields": {
      "description": "Matches the bucket iam changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for bucket iam changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for bucket iam changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "bucket_iam_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_compute_configuration_changes": {
    "description_fields": {
      "description": "Matches the compute configuration changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for compute configuration changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for compute configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "compute_configuration_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_custom_role_changes": {
    "description_fields": {
      "description": "Matches the custom role changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for custom role changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for custom role changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "custom_role_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_custom_role_changes_with_undelete": {
    "description_fields": {
      "description": "Matches the custom role changes with undelete filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for custom role changes with undelete."
      ],
      "summary": "Configure a suitable log metric and enabled alert for custom role changes with undelete."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "custom_role_changes_with_undelete"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_firewall_rule_changes": {
    "description_fields": {
      "description": "Matches the firewall rule changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for firewall rule changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for firewall rule changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "firewall_rule_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_network_changes": {
    "description_fields": {
      "description": "Matches the network changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for network changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for network changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "network_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_network_changes_beta_methods": {
    "description_fields": {
      "description": "Matches the network changes beta methods filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for network changes beta methods."
      ],
      "summary": "Configure a suitable log metric and enabled alert for network changes beta methods."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "network_changes_beta_methods"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_project_ownership_changes": {
    "description_fields": {
      "description": "Matches the project ownership changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for project ownership changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for project ownership changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "project_ownership_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_route_changes": {
    "description_fields": {
      "description": "Matches the route changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for route changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for route changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "route_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.metric_alert_sql_instance_configuration_changes": {
    "description_fields": {
      "description": "Matches the sql instance configuration changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Pattern matching does not establish equivalent filters, alert thresholds, cross-project coverage or successful notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionAbsent.filter",
          "monitoring_alert_policy.conditions[].conditionMonitoringQueryLanguage.query",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable log metric and enabled alert for sql instance configuration changes."
      ],
      "summary": "Configure a suitable log metric and enabled alert for sql instance configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "name": "sql_instance_configuration_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py"
    }
  },
  "gcp.claude.logging.project_sink_all_entries": {
    "description_fields": {
      "description": "Checks project and source-bound ancestor sink routes for an enabled unfiltered path without active exclusions."
    },
    "remediation_fields": {
      "caveats": [
        "Incomplete or shadowed routes remain unresolved; a valid route does not prove destination delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "projectId and project ancestry",
          "project log_sink inventory",
          "_inherited_sinks and its complete ancestor/source-request coverage",
          "sink.name, destination, filter, disabled, exclusions, includeChildren, interceptChildren"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable all-entry sink and account for inherited intercepting routes."
      ],
      "summary": "Configure a suitable all-entry sink and account for inherited intercepting routes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sink_all_entries"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "sink_all_entries",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Complete project and ancestor routes contain no qualifying all-entry sink."
  },
  "gcp.claude.network.dns_logging": {
    "description_fields": {
      "description": "Joins the network to a DNS policy and checks its logging flag."
    },
    "remediation_fields": {
      "caveats": [
        "A logging flag does not prove complete query capture or delivered logs."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "selfLink"
        ],
        "kind": "network",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine network resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable DNS query logging on the intended policy and verify delivery."
      ],
      "summary": "Enable DNS query logging on the intended policy and verify delivery."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "network_dns_logging"
        }
      },
      "kind": "network",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "network_dns_logging",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The network has no attached DNS policy with logging enabled."
  },
  "gcp.claude.organization.essential_contacts_any": {
    "description_fields": {
      "description": "Counts Essential Contacts belonging to the observed organization."
    },
    "remediation_fields": {
      "caveats": [
        "Contact existence does not establish category completeness, validation or delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name"
        ],
        "kind": "organization",
        "target": "resource"
      },
      "references": [
        {
          "title": "Essential Contacts",
          "url": "https://cloud.google.com/resource-manager/docs/managing-notification-contacts"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Assign maintained organizational contacts for required operational and security notices."
      ],
      "summary": "Assign maintained organizational contacts for required operational and security notices."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "any_contact"
        }
      },
      "kind": "organization",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "any_contact",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The organization has no Essential Contact."
  },
  "gcp.claude.project.audit_logs_configured": {
    "description_fields": {
      "description": "Checks whether project or source-bound ancestor IAM policies declare any auditConfig service."
    },
    "remediation_fields": {
      "caveats": [
        "Any auditConfig entry passes this existence check; it does not establish category completeness or delivered logs."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "direct project auditConfigs[].service",
          "effectiveAuditConfigs project/ancestor union",
          "ordered ancestor scopes and complete getAncestry/getIamPolicy source-request coverage"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure data-access audit categories for the services that need them."
      ],
      "summary": "Configure data-access audit categories for the services that need them."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "audit_any"
        }
      },
      "kind": "iam_policy",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "audit_any",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The complete project and ancestor policies declare no auditConfig service."
  },
  "gcp.claude.project.container_scanning_api_enabled": {
    "description_fields": {
      "description": "Joins the project to the Container Scanning API state and requires ENABLED."
    },
    "remediation_fields": {
      "caveats": [
        "API enablement does not prove scan coverage, completed scans or clean images."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "projectId",
          "service_usage.name",
          "service_usage.state"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the scanning API where container vulnerability analysis is required."
      ],
      "summary": "Enable the scanning API where container vulnerability analysis is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "service_state.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "service_name": "containerscanning.googleapis.com",
        "want": "ENABLED"
      },
      "predicate_qualname": "service_state.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Container Scanning API is disabled."
  },
  "gcp.claude.project.gemini_api_disabled": {
    "description_fields": {
      "description": "Joins the project to the Gemini API state and flags ENABLED."
    },
    "remediation_fields": {
      "caveats": [
        "An enabled API can be intentional and does not alone establish public access or compromise."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "projectId",
          "service_usage.name",
          "service_usage.state"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable Gemini only if unused; otherwise restrict the required credentials and clients."
      ],
      "summary": "Disable Gemini only if unused; otherwise restrict the required credentials and clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "service_state.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "service_name": "generativelanguage.googleapis.com",
        "want": "DISABLED"
      },
      "predicate_qualname": "service_state.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Gemini API is enabled."
  },
  "gcp.claude.project.no_api_keys": {
    "description_fields": {
      "description": "Checks the complete project API-key inventory for keys without a deleteTime."
    },
    "remediation_fields": {
      "caveats": [
        "An active key declaration is not evidence of compromise or activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "api_key.name",
          "name"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unused keys after migrating clients to suitable credentials."
      ],
      "summary": "Remove unused keys after migrating clients to suitable credentials."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "project_api_keys"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "project_api_keys",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project contains an API key that is not marked deleted."
  },
  "gcp.claude.project.oslogin_enabled": {
    "description_fields": {
      "description": "Resolves project OS Login metadata and the effective requireOsLogin policy when metadata is unset."
    },
    "remediation_fields": {
      "caveats": [
        "The project setting does not prove an effective SSH login on every instance."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "commonInstanceMetadata.fingerprint",
          "commonInstanceMetadata.items[].key",
          "commonInstanceMetadata.items[].value"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable OS Login at project or organization scope where required and verify instance overrides."
      ],
      "summary": "Enable OS Login at project or organization scope where required and verify instance overrides."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "project_oslogin"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "project_oslogin",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Project OS Login is disabled and not required by effective policy."
  },
  "gcp.claude.project.storage_data_access_audit_logs": {
    "description_fields": {
      "description": "Checks project and collected ancestor audit policies for Cloud Storage DATA_READ and DATA_WRITE categories."
    },
    "remediation_fields": {
      "caveats": [
        "Incomplete ancestry or exemptions remain unresolved; configuration does not prove log delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "direct and effectiveAuditConfigs[].service",
          "effectiveAuditConfigs[].auditLogConfigs[].logType and exemptedMembers",
          "ordered project/ancestor scopes and complete getAncestry/getIamPolicy source-request coverage"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable required Cloud Storage data-access categories and review exemptions."
      ],
      "summary": "Enable required Cloud Storage data-access categories and review exemptions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "audit_logs.<locals>.evaluate"
        }
      },
      "kind": "iam_policy",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {
        "log_types": {
          "type": "set"
        },
        "services": {
          "type": "set"
        }
      },
      "predicate_qualname": "audit_logs.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Cloud Storage data-access audit category is missing."
  },
  "gcp.claude.project.storage_vpc_service_controls": {
    "description_fields": {
      "description": "Checks enforced service-perimeter status for the project number and storage.googleapis.com."
    },
    "remediation_fields": {
      "caveats": [
        "Dry-run configurations do not count; ingress, egress exceptions and actual request decisions remain separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "status"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Add the project to an appropriate Cloud Storage perimeter if that boundary is required."
      ],
      "summary": "Add the project to an appropriate Cloud Storage perimeter if that boundary is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "storage_perimeter"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "storage_perimeter",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No enforced perimeter declares this project and Cloud Storage."
  },
  "gcp.claude.pubsub_snapshot.not_public": {
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role"
        ],
        "kind": "pubsub_snapshot",
        "target": "resource"
      },
      "references": [
        {
          "title": "Pub/Sub access control",
          "url": "https://cloud.google.com/pubsub/docs/access-control"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public-principal grants and preserve intended users."
      ],
      "summary": "Remove unnecessary public-principal grants and preserve intended users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "public_policy.<locals>.evaluate"
        }
      },
      "kind": "pubsub_snapshot",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "public_policy.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.pubsub_subscription.not_public": {
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role"
        ],
        "kind": "pubsub_subscription",
        "target": "resource"
      },
      "references": [
        {
          "title": "Pub/Sub access control",
          "url": "https://cloud.google.com/pubsub/docs/access-control"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public-principal grants and preserve intended users."
      ],
      "summary": "Remove unnecessary public-principal grants and preserve intended users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "public_policy.<locals>.evaluate"
        }
      },
      "kind": "pubsub_subscription",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "public_policy.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.pubsub_topic.not_public": {
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role"
        ],
        "kind": "pubsub_topic",
        "target": "resource"
      },
      "references": [
        {
          "title": "Pub/Sub access control",
          "url": "https://cloud.google.com/pubsub/docs/access-control"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public-principal grants and preserve intended users."
      ],
      "summary": "Remove unnecessary public-principal grants and preserve intended users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "public_policy.<locals>.evaluate"
        }
      },
      "kind": "pubsub_topic",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "public_policy.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.secret.not_public": {
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role"
        ],
        "kind": "secret",
        "target": "resource"
      },
      "references": [
        {
          "title": "Secret rotation",
          "url": "https://cloud.google.com/secret-manager/docs/rotation/rotation-recommendations"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public-principal grants and preserve intended users."
      ],
      "summary": "Remove unnecessary public-principal grants and preserve intended users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "public_policy.<locals>.evaluate"
        }
      },
      "kind": "secret",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "public_policy.<locals>.evaluate",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.secret.rotation_90_days": {
    "description_fields": {
      "description": "Checks the secret’s declared rotation notification period and whether nextRotationTime is overdue."
    },
    "remediation_fields": {
      "caveats": [
        "Rotation notifications do not rotate the secret by themselves; an unreadable input-only period remains UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.collected_at",
          "rotation.nextRotationTime",
          "rotation.rotationPeriod"
        ],
        "kind": "secret",
        "target": "resource"
      },
      "references": [
        {
          "title": "Secret rotation",
          "url": "https://cloud.google.com/secret-manager/docs/rotation/rotation-recommendations"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure an appropriate rotation notification schedule and a handler that actually updates credentials."
      ],
      "summary": "Configure an appropriate rotation notification schedule and a handler that actually updates credentials."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "secret_rotation"
        }
      },
      "kind": "secret",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "secret_rotation",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The secret has no rotation schedule, exceeds 90 days or is overdue."
  },
  "gcp.claude.service_account.recently_used": {
    "description_fields": {
      "description": "Checks Policy Analyzer’s last authentication observation for an enabled service account against 180 elapsed days."
    },
    "remediation_fields": {
      "caveats": [
        "No observation means no authentication was seen in the supplied observation window, not proof the account was never used."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_activity.lastAuthenticatedTime",
          "_activity.observationEndTime",
          "disabled",
          "email"
        ],
        "kind": "service_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the account is unused before disabling it and preserve infrequent required workloads."
      ],
      "summary": "Confirm the account is unused before disabling it and preserve infrequent required workloads."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "account_unused"
        }
      },
      "kind": "service_account",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "account_unused",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "No service-account authentication was observed recently enough."
  },
  "gcp.claude.service_account_key.age_100_days": {
    "description_fields": {
      "description": "Compares user-managed key creation time with midnight UTC 100 days before collection."
    },
    "remediation_fields": {
      "caveats": [
        "Provider-managed keys are excluded; key age does not establish compromise or activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.collected_at",
          "keyType",
          "validAfterTime"
        ],
        "kind": "service_account_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Prefer keyless authentication; otherwise rotate old keys after migrating clients."
      ],
      "summary": "Prefer keyless authentication; otherwise rotate old keys after migrating clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "key_age_100"
        }
      },
      "kind": "service_account_key",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "key_age_100",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user-managed key predates the 100-day UTC-date cutoff."
  },
  "gcp.claude.service_account_key.recently_used": {
    "description_fields": {
      "description": "Checks user-managed enabled keys’ last authentication observation against 180 elapsed days."
    },
    "remediation_fields": {
      "caveats": [
        "Provider-managed and disabled keys are excluded; observation coverage does not prove lifetime nonuse."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_activity.lastAuthenticatedTime",
          "_activity.observationEndTime",
          "disabled",
          "keyType"
        ],
        "kind": "service_account_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the key is unused before retiring it and migrate any remaining clients."
      ],
      "summary": "Confirm the key is unused before retiring it and migrate any remaining clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "key_unused"
        }
      },
      "kind": "service_account_key",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "key_unused",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "No key authentication was observed recently enough."
  },
  "gcp.claude.snapshot.not_outdated": {
    "description_fields": {
      "description": "Compares snapshot creation time with the captured clock and flags more than 90 whole days."
    },
    "remediation_fields": {
      "caveats": [
        "An old snapshot may be intentional retention; this is not a restore test."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.collected_at",
          "creationTimestamp"
        ],
        "kind": "snapshot",
        "target": "resource"
      },
      "references": [
        {
          "title": "Disk snapshots",
          "url": "https://cloud.google.com/compute/docs/disks/snapshots"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review whether older snapshots must be retained; refresh recovery copies without deleting required archives."
      ],
      "summary": "Review whether older snapshots must be retained; refresh recovery copies without deleting required archives."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "snapshot_age"
        }
      },
      "kind": "snapshot",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "snapshot_age",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The snapshot is more than 90 elapsed whole days old."
  },
  "gcp.claude.sql_instance.private_ip_only": {
    "description_fields": {
      "description": "Checks for a PRIVATE address and private-network reference without a PRIMARY incoming address."
    },
    "remediation_fields": {
      "caveats": [
        "OUTGOING is outbound-only; this does not test database connectivity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ipAddresses[].type",
          "settings.ipConfiguration",
          "settings.ipConfiguration.privateNetwork"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure required private connectivity and disable unnecessary public incoming addressing."
      ],
      "summary": "Configure required private connectivity and disable unnecessary public incoming addressing."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sql_private_only"
        }
      },
      "kind": "sql_instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "sql_private_only",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance lacks the required private configuration or declares a PRIMARY incoming address."
  },
  "gcp.claude.sql_instance.second_gen_no_public_ip": {
    "description_fields": {
      "description": "Checks SECOND_GEN Cloud SQL instances for a PRIMARY incoming address assignment."
    },
    "remediation_fields": {
      "caveats": [
        "OUTGOING is outbound-only; address metadata does not establish database reachability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "backendType",
          "ipAddresses[].type"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable unnecessary public incoming addressing after confirming private client connectivity."
      ],
      "summary": "Disable unnecessary public incoming addressing after confirming private client connectivity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sql_public_ip"
        }
      },
      "kind": "sql_instance",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "sql_public_ip",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SECOND_GEN instance declares a PRIMARY incoming address."
  },
  "gcp.claude.target_proxy.https_custom_ssl_policy": {
    "description_fields": {
      "description": "Checks HTTPS proxies for a nonempty SSL policy reference."
    },
    "remediation_fields": {
      "caveats": [
        "A reference alone does not establish the policy contents or negotiated TLS version."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "kind",
          "sslPolicy"
        ],
        "kind": "target_proxy",
        "target": "resource"
      },
      "references": [
        {
          "title": "SSL policies",
          "url": "https://cloud.google.com/load-balancing/docs/ssl-policies-concepts"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Attach a compatible SSL policy where explicit TLS policy control is required."
      ],
      "summary": "Attach a compatible SSL policy where explicit TLS policy control is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "proxy_has_policy"
        }
      },
      "kind": "target_proxy",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "proxy_has_policy",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The HTTPS proxy has no explicit SSL policy reference."
  },
  "gcp.claude.target_proxy.https_min_tls_1_2": {
    "description_fields": {
      "description": "Joins HTTPS proxies to SSL policies and checks minimum TLS 1.2 or 1.3."
    },
    "remediation_fields": {
      "caveats": [
        "This checks configuration; no TLS connection is attempted."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "kind",
          "sslPolicy"
        ],
        "kind": "target_proxy",
        "target": "resource"
      },
      "references": [
        {
          "title": "SSL policies",
          "url": "https://cloud.google.com/load-balancing/docs/ssl-policies-concepts"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require TLS 1.2 or later after checking client compatibility."
      ],
      "summary": "Require TLS 1.2 or later after checking client compatibility."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "proxy_min_tls"
        }
      },
      "kind": "target_proxy",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "proxy_min_tls",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The HTTPS proxy permits a minimum TLS version below 1.2."
  },
  "gcp.claude.workload_identity_provider.multi_tenant_condition": {
    "description_fields": {
      "description": "Checks active OIDC providers using listed shared issuers for a nonempty attributeCondition."
    },
    "remediation_fields": {
      "caveats": [
        "Condition presence alone does not prove that its expression excludes untrusted tenants."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "attributeCondition",
          "disabled",
          "oidc.issuerUri",
          "state"
        ],
        "kind": "workload_identity_provider",
        "target": "resource"
      },
      "references": [
        {
          "title": "Workload identity federation conditions",
          "url": "https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the provider to the intended tenant, repository or namespace claims."
      ],
      "summary": "Restrict the provider to the intended tenant, repository or namespace claims."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "wif_condition"
        }
      },
      "kind": "workload_identity_provider",
      "module": "peaso.checks.claude_gcp_k8s_common",
      "predicate_bindings": {},
      "predicate_qualname": "wif_condition",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The active provider trusts a listed shared issuer without an attribute condition."
  },
  "gcp.claude2.api_key.created_within_90_days": {
    "description_fields": {
      "description": "Checks undeleted API keys for more than 90 elapsed whole days since creation."
    },
    "remediation_fields": {
      "caveats": [
        "Uses the captured collection clock; key age does not establish compromise."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.collected_at",
          "createTime"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace old keys after migrating clients, then revoke the old key."
      ],
      "summary": "Replace old keys after migrating clients, then revoke the old key."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "api_key_age"
        }
      },
      "kind": "api_key",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "api_key_age",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key is more than 90 elapsed whole days old."
  },
  "gcp.claude2.bigquery_dataset.default_cmek": {
    "description_fields": {
      "description": "Checks full dataset details for a nonempty default customer-managed key reference."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate. A dataset default applies to new tables."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_coverage.datasetDetails.status",
          "datasetReference.datasetId",
          "defaultEncryptionConfiguration.kmsKeyName"
        ],
        "kind": "bigquery_dataset",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery dataset resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set a default customer-managed key if required and separately review existing tables."
      ],
      "summary": "Set a default customer-managed key if required and separately review existing tables."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "dataset_cmek"
        }
      },
      "kind": "bigquery_dataset",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "dataset_cmek",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The dataset has no default customer-managed key reference."
  },
  "gcp.claude2.cloudrun_service.invoker_not_public": {
    "description_fields": {
      "description": "Checks disabled invoker IAM checks or unconditional public invoker-role bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Ingress and endpoint reachability are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].condition",
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "invokerIamDisabled",
          "name"
        ],
        "kind": "cloudrun_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run ingress",
          "url": "https://cloud.google.com/run/docs/securing/ingress"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public invoker grants and keep IAM checks enabled unless public invocation is intended."
      ],
      "summary": "Remove unnecessary public invoker grants and keep IAM checks enabled unless public invocation is intended."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "run_public"
        }
      },
      "kind": "cloudrun_service",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "run_public",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service declares public invocation or disables invoker IAM checks."
  },
  "gcp.claude2.function.ingress_not_allow_all": {
    "description_fields": {
      "description": "Checks non-deleting functions for ALLOW_ALL ingress."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. Invocation IAM is separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "serviceConfig.ingressSettings"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict ingress where only internal or load-balanced requests are needed."
      ],
      "summary": "Restrict ingress where only internal or load-balanced requests are needed."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "function_ingress"
        }
      },
      "kind": "function",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "function_ingress",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function declares ALLOW_ALL ingress."
  },
  "gcp.claude2.function.not_publicly_accessible": {
    "description_fields": {
      "description": "Checks function public IAM declarations and, for second-generation functions, backing Cloud Run invoker settings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. A public declaration does not prove Internet reachability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "cloudrun_service.iamPolicy.bindings[].members[]",
          "cloudrun_service.iamPolicy.bindings[].role",
          "cloudrun_service.invokerIamDisabled",
          "cloudrun_service.name",
          "environment",
          "iamPolicy.bindings",
          "iamPolicy.bindings[].condition",
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "serviceConfig.service",
          "state"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public grants and keep backing-service invoker IAM checks enabled."
      ],
      "summary": "Remove unnecessary public grants and keep backing-service invoker IAM checks enabled."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "function_public"
        }
      },
      "kind": "function",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "function_public",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The function or its backing service declares public access or disabled invoker IAM checks."
  },
  "gcp.claude2.function.vpc_connector_configured": {
    "description_fields": {
      "description": "Checks non-deleting functions for a connector, referring direct or backing-service VPC access for review."
    },
    "remediation_fields": {
      "caveats": [
        "A connector controls outbound connectivity; it does not protect incoming invocation."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "environment",
          "serviceConfig.service",
          "serviceConfig.vpcConnector"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the outbound VPC path the function needs, using a connector or supported direct access."
      ],
      "summary": "Configure the outbound VPC path the function needs, using a connector or supported direct access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "function_vpc"
        }
      },
      "kind": "function",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "function_vpc",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No function connector or alternate VPC access declaration was found."
  },
  "gcp.claude2.logging.metric_alert_audit_configuration_changes": {
    "description_fields": {
      "description": "Evaluates the audit configuration changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for audit configuration changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for audit configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "audit_configuration_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_bucket_iam_changes": {
    "description_fields": {
      "description": "Evaluates the bucket iam changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for bucket iam changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for bucket iam changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "bucket_iam_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_custom_role_changes": {
    "description_fields": {
      "description": "Evaluates the custom role changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for custom role changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for custom role changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "custom_role_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_custom_role_changes_with_undelete": {
    "description_fields": {
      "description": "Evaluates the custom role changes with undelete filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for custom role changes with undelete."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for custom role changes with undelete."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "custom_role_changes_with_undelete"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_firewall_rule_changes": {
    "description_fields": {
      "description": "Evaluates the firewall rule changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for firewall rule changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for firewall rule changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "firewall_rule_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_network_changes": {
    "description_fields": {
      "description": "Evaluates the network changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for network changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for network changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "network_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_project_ownership_changes": {
    "description_fields": {
      "description": "Evaluates the project ownership changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for project ownership changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for project ownership changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "project_ownership_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_route_changes": {
    "description_fields": {
      "description": "Evaluates the route changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for route changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for route changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "route_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_sql_instance_configuration_changes": {
    "description_fields": {
      "description": "Evaluates the sql instance configuration changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_fields": {
      "caveats": [
        "Synthetic filter coverage and configured channels do not prove real event detection or message delivery; remote routes remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId",
          "log_sink.destination",
          "log_sink.includeChildren",
          "log_sink.name",
          "logging_metric.bucketName",
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "monitoring_alert_policy.notificationChannels[]",
          "monitoring_notification_channel.enabled",
          "monitoring_notification_channel.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a covering metric filter, enabled threshold alert and enabled notification channel for sql instance configuration changes."
      ],
      "summary": "Configure a covering metric filter, enabled threshold alert and enabled notification channel for sql instance configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "metric_alert.<locals>.evaluate"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {
        "name": "sql_instance_configuration_changes"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.sink_all_log_entries": {
    "description_fields": {
      "description": "Checks local or inherited aggregated sinks for an enabled unfiltered route without active exclusions."
    },
    "remediation_fields": {
      "caveats": [
        "Unresolved ancestry or exclusions need review; configuration does not prove destination writes."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_ancestry[].resourceId.id",
          "_ancestry[].resourceId.type",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure an appropriate all-entry sink and review inherited routes and exclusions."
      ],
      "summary": "Configure an appropriate all-entry sink and review inherited routes and exclusions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sink_all_log_entries"
        }
      },
      "kind": "project",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "sink_all_log_entries",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No qualifying all-entry sink was found."
  },
  "gcp.claude2.sql_instance.only_private_ip_addresses": {
    "description_fields": {
      "description": "Checks address types for any declaration other than PRIVATE; external primaries are excluded."
    },
    "remediation_fields": {
      "caveats": [
        "OUTGOING is outbound-only and also fails this all-address-types profile; failure does not establish public incoming access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "backendType",
          "ipAddresses[].type"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review the address types and remove unnecessary incoming public addressing while preserving required outbound service traffic."
      ],
      "summary": "Review the address types and remove unnecessary incoming public addressing while preserving required outbound service traffic."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sql_private_only"
        }
      },
      "kind": "sql_instance",
      "module": "peaso.checks.claude2_gcp_common",
      "predicate_bindings": {},
      "predicate_qualname": "sql_private_only",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Cloud SQL declares an address type other than PRIVATE."
  },
  "gcp.compute.no_external_ip": {
    "description_fields": {
      "description": "Checks all VM interfaces for valid external IPv4 or IPv6 address declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "networkInterfaces[].accessConfigs[].natIP",
          "networkInterfaces[].ipv6AccessConfigs[].externalIpv6"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove external addresses that are unnecessary and preserve required outbound connectivity."
      ],
      "summary": "Remove external addresses that are unnecessary and preserve required outbound connectivity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks",
      "predicate_bindings": {},
      "predicate_qualname": "gcp_ip",
      "source_qualname": "gcp_ip"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM declares an external IP address."
  },
  "gcp.compute.restrict_internet_ingress": {
    "description_fields": {
      "description": "Checks active ingress allow rules for Internet-wide source ranges, including documented omitted-source defaults."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed",
          "allowed[].IPProtocol",
          "denied",
          "direction",
          "disabled",
          "sourceRanges",
          "sourceServiceAccounts",
          "sourceTags"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Keep public service ports only where required; restrict unnecessary sources or ports."
      ],
      "summary": "Keep public service ports only where required; restrict unnecessary sources or ports."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "firewall",
      "module": "peaso.checks",
      "predicate_bindings": {},
      "predicate_qualname": "gcp_ingress",
      "source_qualname": "gcp_ingress"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress."
  },
  "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only": {
    "description_fields": {
      "description": "Compares active TCP ingress sources with the three listed IPv4 IAP and health-check ranges."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. This profile rejects extra source selectors and IPv6 sources even when intentional."
      ],
      "steps": [
        "Apply the listed proxy ranges only where this rule is intended for IAP or load-balancer traffic."
      ],
      "summary": "Apply the listed proxy ranges only where this rule is intended for IAP or load-balancer traffic."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "firewall",
      "module": "peaso.checks.gcp_gap_cis",
      "predicate_bindings": {},
      "predicate_qualname": "iap_lb_sources_only",
      "source_qualname": "iap_lb_sources_only"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The TCP ingress sources are outside the profile’s IAP and health-check list."
  },
  "gcp.gap.iam_user_managed_sa_no_admin_roles": {
    "description_fields": {
      "description": "Checks user-managed service-account bindings for Owner, Editor or role-name suffix Admin or admin."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Role-name matching does not resolve every role’s permissions."
      ],
      "steps": [
        "Replace unnecessary administrative role declarations with the workload’s required permissions."
      ],
      "summary": "Replace unnecessary administrative role declarations with the workload’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "service_account",
      "module": "peaso.checks.gcp_gap_cis",
      "predicate_bindings": {},
      "predicate_qualname": "user_managed_sa_admin_roles",
      "source_qualname": "user_managed_sa_admin_roles"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service account has an Owner, Editor or admin-named role declaration."
  },
  "gcp.gap.sql_3625_trace_flag_off_cis_v1": {
    "description_fields": {
      "description": "Checks SQL Server trace flag 3625 for explicit off under legacy CIS GCP v1.2 or v1.3."
    },
    "remediation_fields": {
      "caveats": [
        "Legacy compliance preference conflicts with newer CIS guidance; disabling masking can expose error parameters."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the required benchmark version before changing 3625; current security guidance prefers on."
      ],
      "summary": "Confirm the required benchmark version before changing 3625; current security guidance prefers on."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_gap_cis",
      "predicate_bindings": {},
      "predicate_qualname": "sql_3625_off_cis_v1",
      "source_qualname": "sql_3625_off_cis_v1"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Trace flag 3625 does not meet the legacy explicit-off profile."
  },
  "gcp.gke.authorized_networks": {
    "description_fields": {
      "description": "Checks the declared master-authorized-networks enablement flag."
    },
    "remediation_fields": {
      "caveats": [
        "Enablement does not establish a narrow CIDR list or endpoint reachability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "controlPlaneEndpointsConfig.ipEndpointsConfig.authorizedNetworksConfig.enabled",
          "name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable control-plane authorized networks with the administrator ranges that need access."
      ],
      "summary": "Enable control-plane authorized networks with the administrator ranges that need access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_authorized_networks_native",
      "source_qualname": "gke_authorized_networks_native"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Control-plane authorized networks are disabled."
  },
  "gcp.gke.control_plane_restricted": {
    "description_fields": {
      "description": "Checks IP control-plane endpoint settings and authorized networks for Internet-wide CIDRs."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. IAM and RBAC authentication still apply; DNS-only endpoints need separate review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "enabled",
          "masterAuthorizedNetworksConfig.cidrBlocks[].cidrBlock",
          "masterAuthorizedNetworksConfig.enabled",
          "name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a private endpoint or limit public control-plane sources to required administrator networks."
      ],
      "summary": "Use a private endpoint or limit public control-plane sources to required administrator networks."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.exposure_endpoints",
      "predicate_bindings": {},
      "predicate_qualname": "gke_control_plane",
      "source_qualname": "gke_control_plane"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The IP control plane is public without a qualifying source restriction."
  },
  "gcp.gke.network_policy": {
    "description_fields": {
      "description": "Checks NetworkPolicy enforcement settings, accepting Dataplane V2 and Autopilot."
    },
    "remediation_fields": {
      "caveats": [
        "Enforcement enablement alone does not establish complete namespace policy coverage."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "networkConfig.datapathProvider",
          "autopilot.enabled",
          "networkPolicy.enabled",
          "addonsConfig.networkPolicyConfig.disabled"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable a supported NetworkPolicy enforcement mode and define workload-appropriate policies."
      ],
      "summary": "Enable a supported NetworkPolicy enforcement mode and define workload-appropriate policies."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "network_policy",
      "source_qualname": "network_policy"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "NetworkPolicy enforcement is explicitly disabled."
  },
  "gcp.gke.no_legacy_abac": {
    "description_fields": {
      "description": "Checks whether the cluster declares legacy ABAC authorization enabled."
    },
    "remediation_fields": {
      "caveats": [
        "The declaration does not evaluate every RBAC grant or effective authorization."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "legacyAbac.enabled",
          "name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable legacy ABAC after migrating required access to RBAC."
      ],
      "summary": "Disable legacy ABAC after migrating required access to RBAC."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_legacy_abac",
      "source_qualname": "gke_legacy_abac"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Legacy ABAC authorization is enabled."
  },
  "gcp.gke.node_pools_gke_metadata": {
    "description_fields": {
      "description": "Checks every node pool for GKE_METADATA or a decisively unsupported metadata mode."
    },
    "remediation_fields": {
      "caveats": [
        "Unknown node modes remain unresolved; configured metadata mode does not prove effective workload permissions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].config.workloadMetadataConfig.mode",
          "nodePools[].name",
          "workloadIdentityConfig.workloadPool"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use GKE_METADATA for affected node pools and verify workload identity bindings."
      ],
      "summary": "Use GKE_METADATA for affected node pools and verify workload identity bindings."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_pools_metadata",
      "source_qualname": "gke_pools_metadata"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A node pool declares an incompatible workload metadata mode."
  },
  "gcp.gke.private_endpoint": {
    "description_fields": {
      "description": "Checks current and legacy GKE control-plane public/private endpoint settings."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. Current and legacy endpoint declarations are interpreted by this profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "privateClusterConfig.enablePrivateEndpoint",
          "controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable the public control-plane endpoint where administrators can use a private access path."
      ],
      "summary": "Disable the public control-plane endpoint where administrators can use a private access path."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_private_endpoint",
      "source_qualname": "gke_private_endpoint"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GKE control plane declares a public endpoint."
  },
  "gcp.gke.private_nodes": {
    "description_fields": {
      "description": "Checks cluster defaults for private nodes in legacy and current network configuration."
    },
    "remediation_fields": {
      "caveats": [
        "Cluster defaults do not inspect node-pool overrides or prove effective network isolation."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "privateClusterConfig.enablePrivateNodes",
          "networkConfig.defaultEnablePrivateNodes"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use private nodes where workloads do not need node external addresses."
      ],
      "summary": "Use private nodes where workloads do not need node external addresses."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_private_nodes_native",
      "source_qualname": "gke_private_nodes_native"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster does not declare private nodes."
  },
  "gcp.gke.shielded_nodes": {
    "description_fields": {
      "description": "Checks whether Shielded GKE Nodes are enabled in cluster metadata."
    },
    "remediation_fields": {
      "caveats": [
        "A cluster setting does not prove measured integrity on every running node."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "shieldedNodes.enabled"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable Shielded GKE Nodes where supported and verify node rollout."
      ],
      "summary": "Enable Shielded GKE Nodes where supported and verify node rollout."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_shielded_nodes",
      "source_qualname": "gke_shielded_nodes"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Shielded GKE Nodes are disabled."
  },
  "gcp.gke.workload_identity": {
    "description_fields": {
      "description": "Checks for a Workload Identity pool; Autopilot clusters are accepted."
    },
    "remediation_fields": {
      "caveats": [
        "Cluster enablement does not prove node-pool metadata modes or workload IAM bindings."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "workloadIdentityConfig.workloadPool"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable Workload Identity Federation for GKE and migrate required workload identities."
      ],
      "summary": "Enable Workload Identity Federation for GKE and migrate required workload identities."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "gke_workload_identity",
      "source_qualname": "gke_workload_identity"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster has no Workload Identity pool."
  },
  "gcp.htbp.appengine.no_default_service_account": {
    "description_fields": {
      "description": "Checks the App Engine application serviceAccount against its default identity."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Application defaults do not determine every deployed version’s identity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "id",
          "name",
          "serviceAccount"
        ],
        "kind": "app_engine_application",
        "target": "resource"
      },
      "references": [
        {
          "title": "App Engine IAP",
          "url": "https://cloud.google.com/iap/docs/enabling-app-engine"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Choose a dedicated application identity and review version-level overrides."
      ],
      "summary": "Choose a dedicated application identity and review version-level overrides."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "appengine_identity"
        }
      },
      "kind": "app_engine_application",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "appengine_identity",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application selects its default App Engine service account."
  },
  "gcp.htbp.artifactregistry.virtual_repo_private_precedence": {
    "description_fields": {
      "description": "Compares the highest remote upstream priority with the highest standard upstream priority."
    },
    "remediation_fields": {
      "caveats": [
        "This comparison uses the highest priority in each group, not every private upstream; no packages are requested."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "mode",
          "name",
          "virtualRepositoryConfig.upstreamPolicies",
          "virtualRepositoryConfig.upstreamPolicies[].id",
          "virtualRepositoryConfig.upstreamPolicies[].priority",
          "virtualRepositoryConfig.upstreamPolicies[].repository"
        ],
        "kind": "artifact_repository",
        "target": "resource"
      },
      "references": [
        {
          "title": "Artifact Registry virtual repositories",
          "url": "https://cloud.google.com/artifact-registry/docs/repositories/virtual-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Give intended private package sources precedence over remote sources and verify package resolution."
      ],
      "summary": "Give intended private package sources precedence over remote sources and verify package resolution."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "virtual_precedence"
        }
      },
      "kind": "artifact_repository",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "virtual_precedence",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A remote upstream priority meets or exceeds the highest standard upstream priority."
  },
  "gcp.htbp.cloudbuild.pr_trigger_gated": {
    "description_fields": {
      "description": "Checks enabled pull-request triggers for required comments or approvalRequired=true."
    },
    "remediation_fields": {
      "caveats": [
        "The gate declaration does not prove reviewers, repository trust or build identity permissions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.representation",
          "github.name",
          "github.owner",
          "github.pullRequest.branch",
          "github.pullRequest.commentControl",
          "id",
          "name",
          "resourceName"
        ],
        "kind": "cloudbuild_trigger",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Build triggers",
          "url": "https://cloud.google.com/build/docs/triggers"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require an appropriate pull-request comment gate or build approval before untrusted changes can build."
      ],
      "summary": "Require an appropriate pull-request comment gate or build approval before untrusted changes can build."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "cloudbuild_pr"
        }
      },
      "kind": "cloudbuild_trigger",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "cloudbuild_pr",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The pull-request trigger requires neither a comment gate nor build approval."
  },
  "gcp.htbp.cloudbuild.trigger_no_default_sa": {
    "description_fields": {
      "description": "Checks enabled build triggers for an omitted or default Compute Engine or legacy Cloud Build identity."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.representation",
          "id",
          "name",
          "resourceName",
          "serviceAccount"
        ],
        "kind": "cloudbuild_trigger",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Build triggers",
          "url": "https://cloud.google.com/build/docs/triggers"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated build identity with the permissions its builds need."
      ],
      "summary": "Use a dedicated build identity with the permissions its builds need."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "cloudbuild_sa"
        }
      },
      "kind": "cloudbuild_trigger",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "cloudbuild_sa",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The build trigger selects a default build identity."
  },
  "gcp.htbp.cloudrun.job_no_default_compute_sa": {
    "description_fields": {
      "description": "Checks the Cloud Run job template.template.serviceAccount for default Compute Engine identity selection."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Cloud Functions-managed services are excluded."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "template.template.serviceAccount"
        ],
        "kind": "cloudrun_job",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run job resource",
          "url": "https://cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated service account with only the workload’s required permissions."
      ],
      "summary": "Use a dedicated service account with only the workload’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "_run_identity.<locals>.evaluate"
        }
      },
      "kind": "cloudrun_job",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {
        "path": "template.template"
      },
      "predicate_qualname": "_run_identity.<locals>.evaluate",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The workload selects the default Compute Engine service account."
  },
  "gcp.htbp.cloudrun.job_secret_env_from_secret_manager": {
    "description_fields": {
      "description": "Checks credential-like environment variable names under template.template without valueFrom references."
    },
    "remediation_fields": {
      "caveats": [
        "Names are a heuristic; values are not collected or displayed, and a valueFrom object alone does not validate a secret reference."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "template.template.containers[].env[].name",
          "template.template.containers[].env[].valueFrom.secretKeyRef.secret",
          "template.template.containers[].env[].valueFrom.secretKeyRef.version",
          "template.template.containers[].image",
          "template.template.containers[].name"
        ],
        "kind": "cloudrun_job",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run job resource",
          "url": "https://cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm whether the named variables contain credentials; move actual credentials to Secret Manager references."
      ],
      "summary": "Confirm whether the named variables contain credentials; move actual credentials to Secret Manager references."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "_run_env.<locals>.evaluate"
        }
      },
      "kind": "cloudrun_job",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {
        "path": "template.template"
      },
      "predicate_qualname": "_run_env.<locals>.evaluate",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A credential-like environment variable has no valueFrom reference."
  },
  "gcp.htbp.cloudrun.service_no_default_compute_sa": {
    "description_fields": {
      "description": "Checks the Cloud Run service template.serviceAccount for default Compute Engine identity selection."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Cloud Functions-managed services are excluded."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "template.serviceAccount"
        ],
        "kind": "cloudrun_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run ingress",
          "url": "https://cloud.google.com/run/docs/securing/ingress"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated service account with only the workload’s required permissions."
      ],
      "summary": "Use a dedicated service account with only the workload’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "_run_identity.<locals>.evaluate"
        }
      },
      "kind": "cloudrun_service",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {
        "path": "template"
      },
      "predicate_qualname": "_run_identity.<locals>.evaluate",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The workload selects the default Compute Engine service account."
  },
  "gcp.htbp.cloudrun.service_secret_env_from_secret_manager": {
    "description_fields": {
      "description": "Checks credential-like environment variable names under template without valueFrom references."
    },
    "remediation_fields": {
      "caveats": [
        "Names are a heuristic; values are not collected or displayed, and a valueFrom object alone does not validate a secret reference."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "template.containers[].env[].name",
          "template.containers[].env[].valueFrom.secretKeyRef.secret",
          "template.containers[].env[].valueFrom.secretKeyRef.version",
          "template.containers[].image",
          "template.containers[].name"
        ],
        "kind": "cloudrun_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run ingress",
          "url": "https://cloud.google.com/run/docs/securing/ingress"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm whether the named variables contain credentials; move actual credentials to Secret Manager references."
      ],
      "summary": "Confirm whether the named variables contain credentials; move actual credentials to Secret Manager references."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "_run_env.<locals>.evaluate"
        }
      },
      "kind": "cloudrun_service",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {
        "path": "template"
      },
      "predicate_qualname": "_run_env.<locals>.evaluate",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A credential-like environment variable has no valueFrom reference."
  },
  "gcp.htbp.composer.no_default_compute_sa": {
    "description_fields": {
      "description": "Checks Composer nodeConfig.serviceAccount for an omitted or default Compute Engine identity."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "config.nodeConfig.serviceAccount",
          "name"
        ],
        "kind": "composer_environment",
        "target": "resource"
      },
      "references": [
        {
          "title": "Composer service accounts",
          "url": "https://cloud.google.com/composer/docs/composer-3/access-control"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated Composer identity with only the environment’s required permissions."
      ],
      "summary": "Use a dedicated Composer identity with only the environment’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "composer_identity"
        }
      },
      "kind": "composer_environment",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "composer_identity",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Composer environment selects the default Compute Engine identity."
  },
  "gcp.htbp.function.runtime_no_default_sa": {
    "description_fields": {
      "description": "Checks function runtime identity for omitted, Compute Engine default or App Engine default accounts."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "environment",
          "name",
          "serviceConfig.serviceAccountEmail"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated runtime service account with only the function’s required permissions."
      ],
      "summary": "Use a dedicated runtime service account with only the function’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "function_identity"
        }
      },
      "kind": "function",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "function_identity",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function selects a default runtime service account."
  },
  "gcp.htbp.function.secret_env_from_secret_manager": {
    "description_fields": {
      "description": "Checks collected inline environment variable names for credential-like names."
    },
    "remediation_fields": {
      "caveats": [
        "Variable names are a heuristic; values are not collected or displayed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "environment",
          "name",
          "serviceConfig.environmentVariableNames[]",
          "serviceConfig.secretEnvironmentVariables[].key",
          "serviceConfig.secretEnvironmentVariables[].secret",
          "serviceConfig.secretEnvironmentVariables[].version"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm whether the named variables contain credentials; move actual credentials to Secret Manager references."
      ],
      "summary": "Confirm whether the named variables contain credentials; move actual credentials to Secret Manager references."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "function_env"
        }
      },
      "kind": "function",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "function_env",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An inline function environment variable has a credential-like name."
  },
  "gcp.htbp.gke.kubelet_readonly_port_disabled": {
    "description_fields": {
      "description": "Resolves node-pool and cluster-default insecureKubeletReadonlyPortEnabled declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Undeclared version-dependent defaults require review; no node listener is probed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].config.kubeletConfig.insecureKubeletReadonlyPortEnabled",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable the read-only kubelet port in affected node pools and relevant cluster defaults."
      ],
      "summary": "Disable the read-only kubelet port in affected node pools and relevant cluster defaults."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "kubelet_readonly"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "kubelet_readonly",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool or cluster default explicitly enables the read-only kubelet port."
  },
  "gcp.htbp.iam.policy_no_pool_wide_workload_principal_set": {
    "description_fields": {
      "description": "Checks IAM members for a workload identity pool-wide principalSet wildcard."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Pool admission and binding conditions still affect eligible identities."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings[].members[]",
          "bindings[].role",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace pool-wide grants with the intended subject or attribute-based principal sets."
      ],
      "summary": "Replace pool-wide grants with the intended subject or attribute-based principal sets."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "policy_pool_wide"
        }
      },
      "kind": "iam_policy",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "policy_pool_wide",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The IAM policy grants a role to a whole workload identity pool."
  },
  "gcp.htbp.iam.sa_no_pool_wide_workload_principal_set": {
    "description_fields": {
      "description": "Checks service-account IAM members for a workload identity pool-wide principalSet wildcard."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Pool admission and binding conditions still affect eligible identities."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "email",
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "name"
        ],
        "kind": "service_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace pool-wide grants with the intended subject or attribute-based principal sets."
      ],
      "summary": "Replace pool-wide grants with the intended subject or attribute-based principal sets."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "sa_pool_wide"
        }
      },
      "kind": "service_account",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "sa_pool_wide",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service-account policy grants a role to a whole workload identity pool."
  },
  "gcp.htbp.instance_template.no_default_sa_full_scope": {
    "description_fields": {
      "description": "Checks template service accounts for the Compute Engine default identity with cloud-platform OAuth scope."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Existing instances are not changed by a template update."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.representation",
          "name",
          "properties.serviceAccounts[].email",
          "properties.serviceAccounts[].scopes[]"
        ],
        "kind": "instance_template",
        "target": "resource"
      },
      "references": [
        {
          "title": "Instance templates",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instanceTemplates"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Create a template revision with a dedicated least-privilege identity and roll out required instances."
      ],
      "summary": "Create a template revision with a dedicated least-privilege identity and roll out required instances."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "template_identity"
        }
      },
      "kind": "instance_template",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "template_identity",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The template attaches the default identity with cloud-platform OAuth scope."
  },
  "gcp.htbp.kms.destroy_window_not_shortened": {
    "description_fields": {
      "description": "Checks the key destruction grace period for at least seven days, applying the full-read omission default."
    },
    "remediation_fields": {
      "caveats": [
        "The window does not prove destruction monitoring or recoverability; preserve key access while migrating encrypted data."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.representation",
          "destroyScheduledDuration",
          "name",
          "purpose"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a suitable destruction recovery window; changing an immutable key setting may require planned key replacement."
      ],
      "summary": "Use a suitable destruction recovery window; changing an immutable key setting may require planned key replacement."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "destroy_window"
        }
      },
      "kind": "kms_key",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "destroy_window",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key destruction grace period is shorter than seven days."
  },
  "gcp.htbp.logging.default_sink_not_disabled": {
    "description_fields": {
      "description": "Checks the project _Default sink disabled flag."
    },
    "remediation_fields": {
      "caveats": [
        "This does not assess alternative sink coverage or prove successful log delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "disabled"
        ],
        "kind": "log_sink",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Logging sinks",
          "url": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the default sink unless a verified alternative routing design replaces it."
      ],
      "summary": "Enable the default sink unless a verified alternative routing design replaces it."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "default_sink"
        }
      },
      "kind": "log_sink",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "default_sink",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project _Default log sink is disabled."
  },
  "gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled": {
    "description_fields": {
      "description": "Checks effective iam.disableCrossProjectServiceAccountUsage for an explicit enforce=true rule."
    },
    "remediation_fields": {
      "caveats": [
        "Unset policy remains UNKNOWN; this does not enumerate existing identity attachments."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Keep cross-project attachment blocked unless a narrowly scoped workload requires it."
      ],
      "summary": "Keep cross-project attachment blocked unless a narrowly scoped workload requires it."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "orgpolicy_cross_project"
        }
      },
      "kind": "project",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "orgpolicy_cross_project",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The effective policy explicitly permits cross-project service-account attachment."
  },
  "gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled": {
    "description_fields": {
      "description": "Checks the effective managed or legacy constraint blocking privileged default-service-account grants."
    },
    "remediation_fields": {
      "caveats": [
        "The guardrail does not remove existing Owner or Editor assignments."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "org_policy_effective.constraint",
          "org_policy_effective.spec.rules[].enforce"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Prevent automatic broad grants to new default accounts and separately review existing grants."
      ],
      "summary": "Prevent automatic broad grants to new default accounts and separately review existing grants."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "orgpolicy_default_sa"
        }
      },
      "kind": "project",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "orgpolicy_default_sa",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The effective default-account automatic-grant guardrail is not enforced."
  },
  "gcp.htbp.orgpolicy.domain_restricted_sharing": {
    "description_fields": {
      "description": "Checks effective managed enforcement or legacy allowed-domain restriction presence."
    },
    "remediation_fields": {
      "caveats": [
        "Restriction presence does not validate every allowed member, existing grant or conditional exception."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict new IAM policy members to the intended organizations or principal sets."
      ],
      "summary": "Restrict new IAM policy members to the intended organizations or principal sets."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "orgpolicy_drs"
        }
      },
      "kind": "project",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "orgpolicy_drs",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The effective domain-restricted-sharing guardrail is not enforced."
  },
  "gcp.htbp.orgpolicy.essential_contacts_domain_restricted": {
    "description_fields": {
      "description": "Checks effective managed enforcement or legacy contact-domain restriction presence."
    },
    "remediation_fields": {
      "caveats": [
        "Restriction presence does not prove existing contact ownership or notification delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict contact registration to suitable organizational domains where required."
      ],
      "summary": "Restrict contact registration to suitable organizational domains where required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "orgpolicy_contacts"
        }
      },
      "kind": "project",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "orgpolicy_contacts",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The effective contact-domain restriction is not enforced."
  },
  "gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked": {
    "description_fields": {
      "description": "Checks effective managed or legacy constraints for blocking both service-account key creation and upload."
    },
    "remediation_fields": {
      "caveats": [
        "Managed constraints with explicit rules take precedence; existing keys and conditional policies require separate review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Block new key creation and upload where required, after migrating legitimate key-based workflows."
      ],
      "summary": "Block new key creation and upload where required, after migrating legitimate key-based workflows."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "orgpolicy_sa_keys"
        }
      },
      "kind": "project",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "orgpolicy_sa_keys",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Key creation or upload is not blocked by the applicable effective constraint."
  },
  "gcp.htbp.pubsub.push_endpoint_not_tunnel": {
    "description_fields": {
      "description": "Checks the push endpoint host for an IP literal or a listed tunnel or request-capture service."
    },
    "remediation_fields": {
      "caveats": [
        "A matching host is a review signal, not proof of exfiltration; other hosts are not ownership-verified."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "pushConfig.pushEndpoint"
        ],
        "kind": "pubsub_subscription",
        "target": "resource"
      },
      "references": [
        {
          "title": "Pub/Sub access control",
          "url": "https://cloud.google.com/pubsub/docs/access-control"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Verify the endpoint owner and replace unintended destinations with the approved receiving service."
      ],
      "summary": "Verify the endpoint owner and replace unintended destinations with the approved receiving service."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "push_endpoint"
        }
      },
      "kind": "pubsub_subscription",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "push_endpoint",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The push endpoint uses an IP literal or listed tunnel or request-capture host."
  },
  "gcp.htbp.scheduler.no_recurring_access_regrant": {
    "description_fields": {
      "description": "Matches enabled OAuth HTTP jobs against listed Google API write paths for access-granting configuration."
    },
    "remediation_fields": {
      "caveats": [
        "A URI and method pattern do not prove that requests succeed, grant access or are malicious."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "httpTarget.httpMethod",
          "httpTarget.oauthToken.serviceAccountEmail",
          "httpTarget.uri",
          "name",
          "state"
        ],
        "kind": "scheduler_job",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Scheduler HTTP targets",
          "url": "https://cloud.google.com/scheduler/docs/http-target-auth"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review the scheduled access-changing operation and disable it if it has no approved operational purpose."
      ],
      "summary": "Review the scheduled access-changing operation and disable it if it has no approved operational purpose."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "scheduler_replay"
        }
      },
      "kind": "scheduler_job",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "scheduler_replay",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The scheduled OAuth job declares a listed access-changing API write pattern."
  },
  "gcp.htbp.storage.default_object_acl_not_public": {
    "description_fields": {
      "description": "Checks default object ACL public entities when uniform bucket-level access is disabled."
    },
    "remediation_fields": {
      "caveats": [
        "This declaration applies to future objects; public access prevention and existing object permissions are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.representation",
          "defaultObjectAcl[].entity",
          "defaultObjectAcl[].role",
          "iamConfiguration.uniformBucketLevelAccess.enabled",
          "name"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public default-object grants or migrate ACL-dependent access before enabling uniform access."
      ],
      "summary": "Remove unnecessary public default-object grants or migrate ACL-dependent access before enabling uniform access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "default_object_acl"
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "default_object_acl",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The default object ACL declares a public principal."
  },
  "gcp.htbp.storage.hmac_key_not_stale_or_default_sa": {
    "description_fields": {
      "description": "Checks active HMAC key age against 90 elapsed days and its identity for default service accounts."
    },
    "remediation_fields": {
      "caveats": [
        "Only metadata is read; key age or identity does not prove compromise."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "accessId",
          "state",
          "serviceAccountEmail",
          "timeCreated",
          "_provenance.collected_at",
          "context.created_at"
        ],
        "kind": "storage_hmac_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage HMAC keys",
          "url": "https://cloud.google.com/storage/docs/authentication/hmackeys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm client dependencies, then replace stale keys and migrate default identities to suitable dedicated accounts."
      ],
      "summary": "Confirm client dependencies, then replace stale keys and migrate default identities to suitable dedicated accounts."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "hmac_key"
        }
      },
      "kind": "storage_hmac_key",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "hmac_key",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active HMAC key is older than 90 days or uses a default service account."
  },
  "gcp.htbp.storage.notification_topic_in_bucket_project": {
    "description_fields": {
      "description": "Compares the notification topic project ID with the bucket project ID."
    },
    "remediation_fields": {
      "caveats": [
        "Centralized pipelines may be legitimate; a cross-project reference does not prove data exfiltration."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bucket",
          "bucketProject",
          "name",
          "topic"
        ],
        "kind": "bucket_notification",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage Pub/Sub notifications",
          "url": "https://cloud.google.com/storage/docs/pubsub-notifications"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the cross-project topic is an intended event pipeline and remove unknown notification configurations."
      ],
      "summary": "Confirm the cross-project topic is an intended event pipeline and remove unknown notification configurations."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "bucket_notification_topic"
        }
      },
      "kind": "bucket_notification",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_notification_topic",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket notification targets a topic in a different project."
  },
  "gcp.htbp.workbench.no_default_compute_sa": {
    "description_fields": {
      "description": "Checks Workbench gceSetup service accounts for omission or a default Compute Engine identity."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "gceSetup.serviceAccounts[].email",
          "name"
        ],
        "kind": "workbench_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Workbench service accounts",
          "url": "https://cloud.google.com/vertex-ai/docs/workbench/instances/manage-access"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Attach dedicated identities with only the notebook workload’s required permissions."
      ],
      "summary": "Attach dedicated identities with only the notebook workload’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "function": {
          "callable": "workbench_identity"
        }
      },
      "kind": "workbench_instance",
      "module": "peaso.checks.hacktricks_bp_common",
      "predicate_bindings": {},
      "predicate_qualname": "workbench_identity",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Workbench selects the default Compute Engine identity."
  },
  "gcp.iam.avoid_basic_roles": {
    "description_fields": {
      "description": "Checks project IAM bindings for Owner or Editor roles, retaining their conditions."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace unnecessary Owner or Editor grants with the roles each identity needs."
      ],
      "summary": "Replace unnecessary Owner or Editor grants with the roles each identity needs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "iam_policy",
      "module": "peaso.checks",
      "predicate_bindings": {},
      "predicate_qualname": "gcp_basic",
      "source_qualname": "gcp_basic"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The project IAM policy declares an Owner or Editor grant."
  },
  "gcp.iam.data_access_audit": {
    "description_fields": {
      "description": "Checks complete inherited allServices audit configuration for DATA_READ and DATA_WRITE categories."
    },
    "remediation_fields": {
      "caveats": [
        "Exemptions trigger review; configured categories do not prove log delivery or retention."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_coverage.effectiveAuditConfigs.missing_scopes",
          "_coverage.effectiveAuditConfigs.status",
          "effectiveAuditConfigs[].auditConfigs",
          "effectiveAuditConfigs[].auditConfigs[].auditLogConfigs[].logType",
          "effectiveAuditConfigs[].auditConfigs[].service",
          "effectiveAuditConfigs[].scope",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the missing all-service data-access audit categories and review exemptions."
      ],
      "summary": "Enable the missing all-service data-access audit categories and review exemptions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "iam_policy",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "audit",
      "source_qualname": "audit"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An all-service data-access audit category is missing."
  },
  "gcp.iam.no_user_managed_sa_keys": {
    "description_fields": {
      "description": "Checks service-account keyType for USER_MANAGED rather than SYSTEM_MANAGED."
    },
    "remediation_fields": {
      "caveats": [
        "Key type does not establish key activity or compromise; disabled keys still match this profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "keyType"
        ],
        "kind": "service_account_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Prefer keyless identity; retire user-managed keys after migrating dependent clients."
      ],
      "summary": "Prefer keyless identity; retire user-managed keys after migrating dependent clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "service_account_key",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "sa_keys",
      "source_qualname": "sa_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service-account key is user-managed."
  },
  "gcp.iam.restrict_public_members": {
    "description_fields": {
      "description": "Checks project IAM bindings for unconditional allUsers or allAuthenticatedUsers grants."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings",
          "members"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove public-principal grants that are not required; review conditional grants separately."
      ],
      "summary": "Remove public-principal grants that are not required; review conditional grants separately."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "iam_policy",
      "module": "peaso.checks",
      "predicate_bindings": {},
      "predicate_qualname": "gcp_public",
      "source_qualname": "gcp_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The project IAM policy declares an unconditional public-principal grant."
  },
  "gcp.identity.non_service_account_mfa": {
    "description_fields": {
      "description": "Checks native two-step verification enrollment and enforcement for active, customer-bound Directory users directly declared in Cloud IAM."
    },
    "remediation_fields": {
      "caveats": [
        "Enrollment and enforcement are Directory configuration; sign-in behavior and indirect IAM access remain separate."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Enroll the affected human identity in two-step verification and require enforcement in the Admin console."
      ],
      "summary": "Enroll the affected human identity in two-step verification and require enforcement in the Admin console."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_bindings": {
          "callable": "_load_52.<locals>._bindings"
        },
        "_directory_user": {
          "callable": "_load_52.<locals>._directory_user"
        },
        "_iam_members": {
          "callable": "_load_52.<locals>._iam_members"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "kind": "workspace_user",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_bindings": {
          "callable": "_load_52.<locals>._bindings"
        },
        "_directory_user": {
          "callable": "_load_52.<locals>._directory_user"
        },
        "_iam_members": {
          "callable": "_load_52.<locals>._iam_members"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_52.<locals>.non_service_account_mfa",
      "source_qualname": "_load_52.<locals>.non_service_account_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The directly observed IAM user lacks two-step verification enrollment or enforcement."
  },
  "gcp.identity.super_admin_recovery_group": {
    "description_fields": {
      "description": "Joins assigned super administrators to same-customer recovery groups and counts distinct direct members matched to active Directory users."
    },
    "remediation_fields": {
      "caveats": [
        "Group membership is configuration evidence, not proof of recovery delivery or a successful recovery."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Use a maintained recovery group with at least two suitable active members where this recovery profile is required."
      ],
      "summary": "Use a maintained recovery group with at least two suitable active members where this recovery profile is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_directory_user": {
          "callable": "_load_52.<locals>._directory_user"
        },
        "_list": {
          "callable": "_load_52.<locals>._list"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "_super_admin_ids": {
          "callable": "_load_52.<locals>._super_admin_ids"
        },
        "datetime": {
          "callable": "datetime"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "workspace_user",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_directory_user": {
          "callable": "_load_52.<locals>._directory_user"
        },
        "_list": {
          "callable": "_load_52.<locals>._list"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "_super_admin_ids": {
          "callable": "_load_52.<locals>._super_admin_ids"
        },
        "datetime": {
          "callable": "datetime"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_52.<locals>.super_admin_recovery_group",
      "source_qualname": "_load_52.<locals>.super_admin_recovery_group"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The super-admin recovery address is not a group with at least two active members."
  },
  "gcp.identity.super_admin_separation": {
    "description_fields": {
      "description": "Joins source-bound Directory super-admin assignments and project-to-organization IAM roots for direct broad-role conflicts."
    },
    "remediation_fields": {
      "caveats": [
        "Conditional or indirect grants remain unresolved; role-name matching does not compute all effective permissions."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Separate Workspace super-admin identities from unnecessary Cloud Owner, Editor or admin-named role grants."
      ],
      "summary": "Separate Workspace super-admin identities from unnecessary Cloud Owner, Editor or admin-named role grants."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "unknown": {
          "callable": "unknown"
        }
      },
      "kind": "workspace_role_assignment",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_52.<locals>.super_admin_separation",
      "source_qualname": "_load_52.<locals>.super_admin_separation"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Workspace super-admin has a direct broad Cloud IAM role declaration."
  },
  "gcp.logging.access_transparency_entries": {
    "description_fields": {
      "description": "Counts project-bound Access Transparency entries within 30 days of collection."
    },
    "remediation_fields": {
      "caveats": [
        "No recent entries remains UNKNOWN because provider access may not have occurred; absence is not a failure."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Review any available provider-access records and preserve appropriate log access."
      ],
      "summary": "Review any available provider-access records and preserve appropriate log access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "EVALUATORS": {
          "gcp.compute.os_patch_compliance": {
            "callable": "_load_53.<locals>.<lambda>"
          },
          "gcp.logging.access_transparency_entries": {
            "callable": "_load_53.<locals>._transparency"
          },
          "gcp_c5_backup_remote_location": {
            "callable": "_load_53.<locals>._remote"
          },
          "gcp_c5_iam_change_timeliness": {
            "callable": "_load_53.<locals>._timeliness"
          },
          "gcp_c5_iam_conditions": {
            "callable": "_load_53.<locals>._conditions"
          },
          "gcp_c5_iam_expiry": {
            "callable": "_load_53.<locals>._expiry"
          },
          "gcp_c5_malware_telemetry": {
            "callable": "_load_53.<locals>._malware"
          },
          "gcp_c5_patch_deployment": {
            "callable": "_load_53.<locals>._patch_deployment"
          },
          "gcp_c5_restore_destination": {
            "callable": "_load_53.<locals>._restore_destination"
          },
          "gcp_c5_restore_test": {
            "callable": "_load_53.<locals>._restore_test"
          },
          "gcp_c5_software_inventory": {
            "callable": "_load_53.<locals>._software"
          },
          "gcp_c5_sql_backup_run": {
            "callable": "_load_53.<locals>._backup_run"
          },
          "gcp_cloudsql_backup_failure_alert": {
            "callable": "_load_53.<locals>._backup_alert"
          },
          "gcp_compute_approved_packages": {
            "callable": "_load_53.<locals>._approved_packages"
          },
          "gcp_compute_os_patch_compliance": {
            "callable": "_load_53.<locals>.<lambda>"
          }
        }
      },
      "kind": "project",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_base": {
          "callable": "_load_53.<locals>._base"
        },
        "_ctx": {
          "callable": "_load_53.<locals>._ctx"
        },
        "_now": {
          "callable": "_load_53.<locals>._now"
        },
        "_rows": {
          "callable": "_load_53.<locals>._rows"
        },
        "_time": {
          "callable": "_load_53.<locals>._time"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        },
        "timedelta": {
          "callable": "timedelta"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_53.<locals>._transparency",
      "source_qualname": "_load_53.<locals>._evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No recent Access Transparency entry is confirmed."
  },
  "gcp.ports.access_approval_explicit_enrollment": {
    "description_fields": {
      "description": "Checks Access Approval settings for an explicitly BLOCK_ALL-enrolled product."
    },
    "remediation_fields": {
      "caveats": [
        "Notification emails alone are not enrollment; inherited enrollment without parent evidence remains UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "enrolledServices[].cloudProduct",
          "enrolledServices[].enrollmentLevel",
          "enrolledAncestor"
        ],
        "kind": "access_approval_settings",
        "target": "resource"
      },
      "references": [
        {
          "title": "Access Approval settings",
          "url": "https://cloud.google.com/assured-workloads/access-approval/docs/reference/rest/v1/AccessApprovalSettings"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enroll the required products in Access Approval and verify the intended approval process."
      ],
      "summary": "Enroll the required products in Access Approval and verify the intended approval process."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "access_approval_settings",
      "module": "peaso.checks.gcp_ports_relationships",
      "predicate_bindings": {},
      "predicate_qualname": "approval",
      "source_qualname": "approval"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No product is explicitly enrolled with BLOCK_ALL."
  },
  "gcp.ports.alloydb_cluster_encrypted_with_cmk": {
    "description_fields": {
      "description": "Checks whether AlloyDB declares customer-managed rather than Google-default encryption."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "encryptionInfo.encryptionType"
        ],
        "kind": "alloydb_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "AlloyDB encryption",
          "url": "https://cloud.google.com/alloydb/docs/secure-data-cmek"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a customer-managed key if required and verify service permissions and recovery access."
      ],
      "summary": "Use a customer-managed key if required and verify service permissions and recovery access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "alloydb_cluster",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {},
      "predicate_qualname": "alloy_encryption",
      "source_qualname": "alloy_encryption"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB cluster declares Google-managed encryption."
  },
  "gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter": {
    "description_fields": {
      "description": "Checks the AlloyDB log_error_verbosity declaration for default or verbose."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. No inherited PostgreSQL default is inferred."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseFlags.log_error_verbosity"
        ],
        "kind": "alloydb_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "AlloyDB database flags",
          "url": "https://cloud.google.com/alloydb/docs/reference/database-flags"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure log_error_verbosity for the database’s logging requirements."
      ],
      "summary": "Configure log_error_verbosity for the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "default",
          "verbose"
        ],
        "flag": "log_error_verbosity",
        "presence": false
      },
      "kind": "alloydb_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "default",
          "verbose"
        ],
        "flag": "log_error_verbosity",
        "presence": false
      },
      "predicate_qualname": "alloy_flag.<locals>.evaluate",
      "source_qualname": "alloy_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB log_error_verbosity flag is absent or outside the accepted values."
  },
  "gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured": {
    "description_fields": {
      "description": "Checks the AlloyDB log_min_error_statement declaration for an explicit value."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. No inherited PostgreSQL default is inferred."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseFlags.log_min_error_statement"
        ],
        "kind": "alloydb_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "AlloyDB database flags",
          "url": "https://cloud.google.com/alloydb/docs/reference/database-flags"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure log_min_error_statement for the database’s logging requirements."
      ],
      "summary": "Configure log_min_error_statement for the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": null,
        "flag": "log_min_error_statement",
        "presence": true
      },
      "kind": "alloydb_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": null,
        "flag": "log_min_error_statement",
        "presence": true
      },
      "predicate_qualname": "alloy_flag.<locals>.evaluate",
      "source_qualname": "alloy_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB log_min_error_statement flag is absent or outside the accepted values."
  },
  "gcp.ports.alloydb_instance_log_min_messages_database_flag_error": {
    "description_fields": {
      "description": "Checks the AlloyDB log_min_messages declaration for error or warning."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. No inherited PostgreSQL default is inferred."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseFlags.log_min_messages"
        ],
        "kind": "alloydb_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "AlloyDB database flags",
          "url": "https://cloud.google.com/alloydb/docs/reference/database-flags"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure log_min_messages for the database’s logging requirements."
      ],
      "summary": "Configure log_min_messages for the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "error",
          "warning"
        ],
        "flag": "log_min_messages",
        "presence": false
      },
      "kind": "alloydb_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "error",
          "warning"
        ],
        "flag": "log_min_messages",
        "presence": false
      },
      "predicate_qualname": "alloy_flag.<locals>.evaluate",
      "source_qualname": "alloy_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB log_min_messages flag is absent or outside the accepted values."
  },
  "gcp.ports.api_key_elapsed_age_gt90": {
    "description_fields": {
      "description": "Compares API-key creation time with the captured clock and flags more than 90 elapsed whole days."
    },
    "remediation_fields": {
      "caveats": [
        "Uses elapsed whole days rather than a UTC-date cutoff; age is not evidence of compromise."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.collected_at",
          "createTime"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace stale keys after migrating clients, then revoke the old keys."
      ],
      "summary": "Replace stale keys after migrating clients, then revoke the old keys."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "api_key",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {},
      "predicate_qualname": "elapsed_age",
      "source_qualname": "elapsed_age"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key is more than 90 elapsed whole days old."
  },
  "gcp.ports.api_key_meaningful_restrictions": {
    "description_fields": {
      "description": "Checks for a specific API target or a narrow caller-restriction declaration."
    },
    "remediation_fields": {
      "caveats": [
        "Either restriction category can pass this profile; both may be appropriate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "restrictions.apiTargets[].service",
          "restrictions.serverKeyRestrictions.allowedIps[]"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the API key to the required APIs and intended clients."
      ],
      "summary": "Restrict the API key to the required APIs and intended clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "api_key",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {},
      "predicate_qualname": "meaningful_restrictions",
      "source_qualname": "meaningful_restrictions"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key has neither a specific API target nor a narrow caller restriction."
  },
  "gcp.ports.apikeys_api_restricted_with_gemini_api": {
    "description_fields": {
      "description": "Checks API-key target restrictions when the project’s Gemini API is enabled."
    },
    "remediation_fields": {
      "caveats": [
        "A disabled Gemini API passes this scoped profile; caller restrictions and effective permissions are separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "restrictions.apiTargets",
          "restrictions.apiTargets[].service",
          "state"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the key to required APIs; use a separate Gemini key when separation is needed."
      ],
      "summary": "Restrict the key to required APIs; use a separate Gemini key when separation is needed."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "api_key",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {},
      "predicate_qualname": "gemini",
      "source_qualname": "gemini"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The enabled-Gemini project key has unrestricted or mixed Gemini API targets."
  },
  "gcp.ports.app_engine_application_iap_enabled": {
    "description_fields": {
      "description": "Checks the identified App Engine application’s IAP enabled setting."
    },
    "remediation_fields": {
      "caveats": [
        "Application IAP configuration does not prove protection of every service or alternative ingress path."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "id",
          "name",
          "iap.enabled"
        ],
        "kind": "app_engine_application",
        "target": "resource"
      },
      "references": [
        {
          "title": "App Engine IAP",
          "url": "https://cloud.google.com/iap/docs/enabling-app-engine"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable IAP if application access should require an approved identity."
      ],
      "summary": "Enable IAP if application access should require an approved identity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "app_engine_application",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {},
      "predicate_qualname": "app_engine_iap",
      "source_qualname": "app_engine_iap"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "IAP is disabled for the application."
  },
  "gcp.ports.artifacts_container_analysis_enabled": {
    "description_fields": {
      "description": "Joins the project to its Container Analysis API service state and requires ENABLED."
    },
    "remediation_fields": {
      "caveats": [
        "API enablement alone does not establish scanning coverage or clean images."
      ],
      "steps": [
        "Enable Container Analysis where artifact analysis is required."
      ],
      "summary": "Enable Container Analysis where artifact analysis is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "service_name": "containeranalysis.googleapis.com"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "service_name": "containeranalysis.googleapis.com"
      },
      "predicate_qualname": "service.<locals>.evaluate",
      "source_qualname": "service.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Container Analysis API is disabled."
  },
  "gcp.ports.audit_logging_configured_for_all_service": {
    "description_fields": {
      "description": "Checks all-service ADMIN_READ, DATA_READ and DATA_WRITE configuration and flags exemptions."
    },
    "remediation_fields": {
      "caveats": [
        "Collected inherited configurations count where available; configuration does not prove log delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy._coverage.effectiveAuditConfigs",
          "iam_policy.auditConfigs[].auditLogConfigs[].exemptedMembers[]",
          "iam_policy.auditConfigs[].auditLogConfigs[].logType",
          "iam_policy.auditConfigs[].service",
          "iam_policy.effectiveAuditConfigs",
          "iam_policy.name",
          "scope"
        ],
        "kind": "inventory",
        "target": "scope"
      },
      "references": [
        {
          "title": "Cloud Audit Logs configuration",
          "url": "https://cloud.google.com/logging/docs/audit/configure-data-access"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the required all-service audit categories and remove unintended exemptions."
      ],
      "summary": "Enable the required all-service audit categories and remove unintended exemptions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "inventory",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "audit_scope",
      "source_qualname": "audit_scope"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "All-service audit categories are missing or include exemptions."
  },
  "gcp.ports.bigquery_dataset_not_publicly_accessible": {
    "description_fields": {
      "description": "Checks dataset ACLs for allAuthenticatedUsers specialGroup or allUsers iamMember entries."
    },
    "remediation_fields": {
      "caveats": [
        "This exact ACL profile does not cover every public-principal encoding, inherited grant or view."
      ],
      "steps": [
        "Remove unnecessary public dataset ACL entries and retain intended readers."
      ],
      "summary": "Remove unnecessary public dataset ACL entries and retain intended readers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bigquery_dataset",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {},
      "predicate_qualname": "dataset_public",
      "source_qualname": "dataset_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset ACL contains a public-group or public-IAM entry."
  },
  "gcp.ports.bigquery_table_encrypted_with_cmk": {
    "description_fields": {
      "description": "Checks stored BigQuery tables for a nonempty customer-managed key reference; logical views are excluded."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "encryptionConfiguration.kmsKeyName",
          "type"
        ],
        "kind": "bigquery_table",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery table resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/tables"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a customer-managed key if required and verify table migration and key access."
      ],
      "summary": "Configure a customer-managed key if required and verify table migration and key access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "path": "encryptionConfiguration.kmsKeyName",
        "view": true
      },
      "kind": "bigquery_table",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {
        "path": "encryptionConfiguration.kmsKeyName",
        "view": true
      },
      "predicate_qualname": "encryption.<locals>.evaluate",
      "source_qualname": "encryption.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The table has an empty customer-managed key reference."
  },
  "gcp.ports.cloud_run_not_publicly_accessible": {
    "description_fields": {
      "description": "Checks Cloud Run’s ingress boundary for INGRESS_TRAFFIC_ALL."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. Ingress scope alone does not grant unauthenticated invocation."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ingress"
        ],
        "kind": "cloudrun_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run ingress",
          "url": "https://cloud.google.com/run/docs/securing/ingress"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Keep unrestricted ingress only where required; otherwise select the intended internal boundary."
      ],
      "summary": "Keep unrestricted ingress only where required; otherwise select the intended internal boundary."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_service",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {},
      "predicate_qualname": "run_ingress",
      "source_qualname": "run_ingress"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud Run declares unrestricted ingress."
  },
  "gcp.ports.cloud_run_service_policy_prohibit_public_access": {
    "description_fields": {
      "description": "Checks Cloud Run IAM bindings for any role assigned to allUsers or allAuthenticatedUsers."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings",
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "members"
        ],
        "kind": "cloudrun_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Run ingress",
          "url": "https://cloud.google.com/run/docs/securing/ingress"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public-principal bindings and review their role and conditions."
      ],
      "summary": "Remove unnecessary public-principal bindings and review their role and conditions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_service",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {},
      "predicate_qualname": "cloudrun_public",
      "source_qualname": "cloudrun_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cloud Run IAM policy declares a public principal."
  },
  "gcp.ports.cloudfunction_function_no_ingress_settings_allow_all": {
    "description_fields": {
      "description": "Checks function ingress for ALLOW_ALL, including the explicit unspecified enum’s default.",
      "description_correction": {
        "base_row_sha256": "12c1adaa534a7925612f8b369adbd9c544114b1535f4314e56df338cd0346677",
        "change": "Unknown ingress strings remain UNKNOWN; explicit INGRESS_SETTINGS_UNSPECIFIED uses the documented ALLOW_ALL default.",
        "prior_predicate_sha256": "7474fed431b7b6c8212bc074b8e05e185d68f88cb01920f72b1d0c3182923c86",
        "reference": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#IngressSettings",
        "version": "gcp-clarity-input-validation-v1"
      },
      "fail_when": "FAIL when ingressSettings is ALLOW_ALL or explicitly INGRESS_SETTINGS_UNSPECIFIED; absent or unrecognized values are UNKNOWN.",
      "pass_when": "PASS when ingressSettings is ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB."
    },
    "remediation_fields": {
      "caveats": [
        "Missing or unknown settings remain UNKNOWN; ingress configuration does not prove invocation permission or endpoint reachability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "serviceConfig.ingressSettings",
          "state"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict ingress where the function should receive only internal or load-balanced requests."
      ],
      "summary": "Restrict ingress where the function should receive only internal or load-balanced requests."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": false,
        "field": "ingressSettings"
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": false,
        "field": "ingressSettings"
      },
      "predicate_qualname": "function_setting.<locals>.evaluate",
      "source_qualname": "function_setting.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function declares ALLOW_ALL ingress."
  },
  "gcp.ports.cloudfunction_function_restrict_public_access": {
    "description_fields": {
      "description": "Checks function IAM bindings for public principals."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "steps": [
        "Remove unnecessary public-principal bindings and preserve intended callers."
      ],
      "summary": "Remove unnecessary public-principal bindings and preserve intended callers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": false,
        "invoker_only": false
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": false,
        "invoker_only": false
      },
      "predicate_qualname": "policy_public.<locals>.evaluate",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function IAM policy declares a public principal."
  },
  "gcp.ports.cloudfunction_function_vpc_connector_enabled": {
    "description_fields": {
      "description": "Checks for a nonempty function VPC connector reference."
    },
    "remediation_fields": {
      "caveats": [
        "A connector controls outbound networking; it is not inbound access protection."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "serviceConfig.vpcConnector",
          "state"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a connector only if this function needs that outbound VPC path."
      ],
      "summary": "Configure a connector only if this function needs that outbound VPC path."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": false,
        "field": "vpcConnector"
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": false,
        "field": "vpcConnector"
      },
      "predicate_qualname": "function_setting.<locals>.evaluate",
      "source_qualname": "function_setting.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function has no VPC connector reference."
  },
  "gcp.ports.cloudrun_service_restrict_public_access": {
    "description_fields": {
      "description": "Checks Cloud Run run.invoker bindings for public principals."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Other roles and disabled invoker checks are outside this predicate."
      ],
      "steps": [
        "Remove unnecessary public invoker grants and preserve intended callers."
      ],
      "summary": "Remove unnecessary public invoker grants and preserve intended callers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": false,
        "invoker_only": true
      },
      "kind": "cloudrun_service",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": false,
        "invoker_only": true
      },
      "predicate_qualname": "policy_public.<locals>.evaluate",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The service declares a public run.invoker binding."
  },
  "gcp.ports.compute_disk_encrypted_with_csk": {
    "description_fields": {
      "description": "Checks for a customer-supplied encryption-key digest in disk metadata."
    },
    "remediation_fields": {
      "caveats": [
        "A missing digest does not mean plaintext; no raw key is collected."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "diskEncryptionKey.sha256",
          "name"
        ],
        "kind": "disk",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine disk encryption",
          "url": "https://cloud.google.com/compute/docs/disks/customer-supplied-encryption"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use customer-supplied keys only if required and maintain a recoverable key-management process."
      ],
      "summary": "Use customer-supplied keys only if required and maintain a recoverable key-management process."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "disk",
      "module": "peaso.checks.gcp_ports_relationships",
      "predicate_bindings": {},
      "predicate_qualname": "csek",
      "source_qualname": "csek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The disk has no customer-supplied key digest."
  },
  "gcp.ports.compute_firewall_rule_rdp_access_restricted": {
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide TCP 3389 allowance."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed",
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "disabled",
          "sourceRanges",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict RDP sources to the administrator networks or access proxy that need access."
      ],
      "summary": "Restrict RDP sources to the administrator networks or access proxy that need access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "port": 3389
      },
      "kind": "firewall",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {
        "port": 3389
      },
      "predicate_qualname": "firewall_port.<locals>.evaluate",
      "source_qualname": "firewall_port.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The firewall rule declares Internet-wide TCP 3389 ingress."
  },
  "gcp.ports.compute_firewall_rule_ssh_access_restricted": {
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide TCP 22 allowance."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed",
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "disabled",
          "sourceRanges",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict SSH sources to the administrator networks or access proxy that need access."
      ],
      "summary": "Restrict SSH sources to the administrator networks or access proxy that need access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "port": 22
      },
      "kind": "firewall",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {
        "port": 22
      },
      "predicate_qualname": "firewall_port.<locals>.evaluate",
      "source_qualname": "firewall_port.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The firewall rule declares Internet-wide TCP 22 ingress."
  },
  "gcp.ports.compute_instance_block_project_wide_ssh_enabled": {
    "description_fields": {
      "description": "Checks explicit project-SSH-key blocking outside the labeled GKE-node scope."
    },
    "remediation_fields": {
      "caveats": [
        "Missing or duplicate metadata remains UNKNOWN; effective SSH authorization is separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "metadata.items[].key",
          "metadata.items[].value",
          "name"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Block project-wide SSH keys where instance-level access or OS Login is intended."
      ],
      "summary": "Block project-wide SSH keys where instance-level access or OS Login is intended."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "block_project_keys",
      "source_qualname": "block_project_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM explicitly allows project-wide SSH keys."
  },
  "gcp.ports.compute_instance_ip_forwarding_disabled": {
    "description_fields": {
      "description": "Checks canIpForward outside the explicitly labeled GKE-node scope."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "canIpForward",
          "name"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable forwarding unless the VM is an intended network appliance."
      ],
      "summary": "Disable forwarding unless the VM is an intended network appliance."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "no_forward",
      "source_qualname": "no_forward"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM allows IP forwarding."
  },
  "gcp.ports.compute_instance_shielded_vm_enabled": {
    "description_fields": {
      "description": "Checks that both vTPM and integrity monitoring are explicitly enabled."
    },
    "remediation_fields": {
      "caveats": [
        "These declarations do not prove measured boot integrity or alert delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "shieldedInstanceConfig.enableIntegrityMonitoring",
          "shieldedInstanceConfig.enableVtpm"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable vTPM and integrity monitoring where supported by the VM and image."
      ],
      "summary": "Enable vTPM and integrity monitoring where supported by the VM and image."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "shielding",
      "source_qualname": "shielding"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM disables vTPM or integrity monitoring."
  },
  "gcp.ports.compute_instance_with_no_default_service_account": {
    "description_fields": {
      "description": "Checks non-GKE-scoped VMs for an attached default Compute Engine service account."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "labels.goog-gke-node",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated service account with the permissions the VM requires."
      ],
      "summary": "Use a dedicated service account with the permissions the VM requires."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "require_full_scope": false
      },
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {
        "require_full_scope": false
      },
      "predicate_qualname": "account_rule.<locals>.evaluate",
      "source_qualname": "account_rule.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM attaches the default Compute Engine service account."
  },
  "gcp.ports.compute_instance_with_no_default_service_account_with_full_access": {
    "description_fields": {
      "description": "Checks non-GKE-scoped VMs for the default service account with cloud-platform OAuth scope."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "serviceAccounts",
          "serviceAccounts[].email",
          "serviceAccounts[].scopes[]"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated least-privilege service account and review required OAuth scopes."
      ],
      "summary": "Use a dedicated least-privilege service account and review required OAuth scopes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "require_full_scope": true
      },
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {
        "require_full_scope": true
      },
      "predicate_qualname": "account_rule.<locals>.evaluate",
      "source_qualname": "account_rule.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The default service account has the cloud-platform OAuth scope."
  },
  "gcp.ports.compute_instance_with_no_public_ip_addresses": {
    "description_fields": {
      "description": "Checks every observed interface for declared external IPv4 or IPv6 addresses."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "networkInterfaces[].accessConfigs[].natIP",
          "networkInterfaces[].ipv6AccessConfigs[].externalIpv6"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove external addresses that are unnecessary and preserve required outbound access."
      ],
      "summary": "Remove external addresses that are unnecessary and preserve required outbound access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "public_interfaces",
      "source_qualname": "public_interfaces"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM declares an external IP address."
  },
  "gcp.ports.compute_network_contains_no_legacy_network": {
    "description_fields": {
      "description": "Checks for the legacy-network IPv4Range property."
    },
    "remediation_fields": {
      "caveats": [
        "Legacy networking and automatic subnet creation are different properties."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "IPv4Range",
          "name"
        ],
        "kind": "network",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine network resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Plan migration from a legacy network to a suitable VPC."
      ],
      "summary": "Plan migration from a legacy network to a suitable VPC."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "network",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "no_legacy",
      "source_qualname": "no_legacy"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The network declares the legacy IPv4Range model."
  },
  "gcp.ports.compute_network_dns_logging_scoped": {
    "description_fields": {
      "description": "Joins the exact network reference to one DNS policy and checks enableLogging."
    },
    "remediation_fields": {
      "caveats": [
        "The policy setting does not prove DNS log delivery or completeness."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "dns_policy.enableLogging",
          "dns_policy.networks[].networkUrl",
          "selfLink"
        ],
        "kind": "network",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine network resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable DNS query logging on the network’s intended DNS policy."
      ],
      "summary": "Enable DNS query logging on the network’s intended DNS policy."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "network",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {},
      "predicate_qualname": "dns_network_logging",
      "source_qualname": "dns_network_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The network has no attached DNS policy with logging enabled."
  },
  "gcp.ports.compute_oslogin_metadata_precedence": {
    "description_fields": {
      "description": "Resolves OS Login through instance metadata, project metadata and applicable effective organization policy."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration precedence does not prove a successful SSH login or complete IAM authorization."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "metadata.items[].key",
          "metadata.items[].value"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable OS Login at the appropriate scope and remove an overriding instance opt-out."
      ],
      "summary": "Enable OS Login at the appropriate scope and remove an overriding instance opt-out."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_ports_relationships",
      "predicate_bindings": {},
      "predicate_qualname": "oslogin",
      "source_qualname": "oslogin"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The resolved OS Login setting is disabled."
  },
  "gcp.ports.compute_ssl_policy_strict_declaration": {
    "description_fields": {
      "description": "Joins HTTPS or SSL proxies to their SSL policy and compares its profile, minimum TLS version and custom ciphers."
    },
    "remediation_fields": {
      "caveats": [
        "This is a policy comparison, not a TLS connection test; RESTRICTED is accepted by the profile without a separate minimum-version requirement."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "kind",
          "sslPolicy",
          "ssl_policy.enabledFeatures[]",
          "ssl_policy.minTlsVersion",
          "ssl_policy.profile",
          "ssl_policy.selfLink"
        ],
        "kind": "target_proxy",
        "target": "resource"
      },
      "references": [
        {
          "title": "SSL policies",
          "url": "https://cloud.google.com/load-balancing/docs/ssl-policies-concepts"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Attach a compatible strict SSL policy, normally TLS 1.2 or later without the listed weak ciphers."
      ],
      "summary": "Attach a compatible strict SSL policy, normally TLS 1.2 or later without the listed weak ciphers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "target_proxy",
      "module": "peaso.checks.gcp_ports_relationships",
      "predicate_bindings": {},
      "predicate_qualname": "ssl_policy",
      "source_qualname": "ssl_policy"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The proxy lacks a qualifying strict SSL policy."
  },
  "gcp.ports.compute_url_map_backend_logging": {
    "description_fields": {
      "description": "Follows URL-map routes to each backend service and checks its logging flag."
    },
    "remediation_fields": {
      "caveats": [
        "Redirect-only maps and backend buckets are excluded; an enabled flag does not prove complete request capture."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nested defaultService/service/backendService references",
          "defaultUrlRedirect",
          "backend_service.selfLink",
          "backend_service.logConfig.enable",
          "backend_bucket.selfLink"
        ],
        "kind": "url_map",
        "target": "resource"
      },
      "references": [
        {
          "title": "Load balancer logging",
          "url": "https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable request logging on the affected backend services and verify delivery."
      ],
      "summary": "Enable request logging on the affected backend services and verify delivery."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "url_map",
      "module": "peaso.checks.gcp_ports_relationships",
      "predicate_bindings": {},
      "predicate_qualname": "map_logging",
      "source_qualname": "map_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A routed backend service has logging disabled."
  },
  "gcp.ports.dataproc_cluster_encryption_with_cmek": {
    "description_fields": {
      "description": "Checks Dataproc’s declared persistent-disk customer-managed key reference."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "config.encryptionConfig.gcePdKmsKeyName"
        ],
        "kind": "dataproc_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "Dataproc encryption",
          "url": "https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/customer-managed-encryption"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the cluster’s disk encryption key if required, after reviewing replacement and access requirements."
      ],
      "summary": "Configure the cluster’s disk encryption key if required, after reviewing replacement and access requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "path": "config.encryptionConfig.gcePdKmsKeyName",
        "view": false
      },
      "kind": "dataproc_cluster",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {
        "path": "config.encryptionConfig.gcePdKmsKeyName",
        "view": false
      },
      "predicate_qualname": "encryption.<locals>.evaluate",
      "source_qualname": "encryption.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Dataproc cluster has an empty customer-managed disk key reference."
  },
  "gcp.ports.dns_managed_zone_dnssec_enabled": {
    "description_fields": {
      "description": "Checks public-zone DNSSEC state for on or transfer."
    },
    "remediation_fields": {
      "caveats": [
        "This profile accepts transfer as well as on; it does not prove active DNS signing or a valid parent chain."
      ],
      "steps": [
        "Enable DNSSEC where appropriate and coordinate parent DS records for a safe rollout."
      ],
      "summary": "Enable DNSSEC where appropriate and coordinate parent DS records for a safe rollout."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "key_type": null
      },
      "kind": "dns_managed_zone",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "key_type": null
      },
      "predicate_qualname": "dns.<locals>.evaluate",
      "source_qualname": "dns.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "DNSSEC is not configured for the public zone."
  },
  "gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1": {
    "description_fields": {
      "description": "Checks public-zone key-signing specifications for RSASHA1."
    },
    "remediation_fields": {
      "caveats": [
        "This algorithm profile can pass with DNSSEC disabled; it does not establish active signing."
      ],
      "steps": [
        "Plan a supported key-signing algorithm rollover and coordinate parent DS records."
      ],
      "summary": "Plan a supported key-signing algorithm rollover and coordinate parent DS records."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "key_type": "keySigning"
      },
      "kind": "dns_managed_zone",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "key_type": "keySigning"
      },
      "predicate_qualname": "dns.<locals>.evaluate",
      "source_qualname": "dns.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key-signing specification uses RSASHA1."
  },
  "gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1": {
    "description_fields": {
      "description": "Checks public-zone zone-signing specifications for RSASHA1."
    },
    "remediation_fields": {
      "caveats": [
        "This algorithm profile can pass with DNSSEC disabled; it does not establish active signing."
      ],
      "steps": [
        "Plan a supported zone-signing algorithm rollover and verify DNS resolution throughout."
      ],
      "summary": "Plan a supported zone-signing algorithm rollover and verify DNS resolution throughout."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "key_type": "zoneSigning"
      },
      "kind": "dns_managed_zone",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "key_type": "zoneSigning"
      },
      "predicate_qualname": "dns.<locals>.evaluate",
      "source_qualname": "dns.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The zone-signing specification uses RSASHA1."
  },
  "gcp.ports.firewall_http_lb_proxy_source_restriction": {
    "description_fields": {
      "description": "Compares active TCP ingress source ranges with the documented Google HTTP load-balancer proxy ranges."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. This profile does not establish that the rule serves a load-balancer backend."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed",
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "disabled",
          "sourceRanges",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "If this rule protects a proxy-only backend, restrict its sources to the required proxy ranges."
      ],
      "summary": "If this rule protects a proxy-only backend, restrict its sources to the required proxy ranges."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed_ranges": [
          "130.211.0.0/22",
          "35.191.0.0/16"
        ]
      },
      "kind": "firewall",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {
        "allowed_ranges": [
          "130.211.0.0/22",
          "35.191.0.0/16"
        ]
      },
      "predicate_qualname": "iap_sources.<locals>.evaluate",
      "source_qualname": "iap_sources.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The TCP ingress rule includes sources outside the HTTP load-balancer proxy ranges."
  },
  "gcp.ports.firewall_iap_tcp_proxy_source_restriction": {
    "description_fields": {
      "description": "Compares active TCP ingress source ranges with the documented IPv4 and IPv6 IAP TCP proxy ranges."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. This profile applies its proxy-range preference to any active TCP ingress rule."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "allowed",
          "allowed[].IPProtocol",
          "allowed[].ports[]",
          "direction",
          "disabled",
          "sourceRanges",
          "sourceRanges[]"
        ],
        "kind": "firewall",
        "target": "resource"
      },
      "references": [
        {
          "title": "VPC firewall rules",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "If this rule is for IAP TCP forwarding, restrict its sources to the IAP proxy ranges."
      ],
      "summary": "If this rule is for IAP TCP forwarding, restrict its sources to the IAP proxy ranges."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed_ranges": [
          "35.235.240.0/20",
          "2600:2d00:1:7::/64"
        ]
      },
      "kind": "firewall",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {
        "allowed_ranges": [
          "35.235.240.0/20",
          "2600:2d00:1:7::/64"
        ]
      },
      "predicate_qualname": "iap_sources.<locals>.evaluate",
      "source_qualname": "iap_sources.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The TCP ingress rule includes sources outside the IAP proxy ranges."
  },
  "gcp.ports.function_active_public_binding": {
    "description_fields": {
      "description": "Checks IAM bindings on ACTIVE functions for public principals."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "steps": [
        "Remove unnecessary public-principal bindings from the active function."
      ],
      "summary": "Remove unnecessary public-principal bindings from the active function."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": true,
        "invoker_only": false
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": true,
        "invoker_only": false
      },
      "predicate_qualname": "policy_public.<locals>.evaluate",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active function IAM policy declares a public principal."
  },
  "gcp.ports.function_active_vpc_connector": {
    "description_fields": {
      "description": "Checks ACTIVE functions for a nonempty VPC connector reference."
    },
    "remediation_fields": {
      "caveats": [
        "A connector controls outbound networking; it is not inbound access protection."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "serviceConfig.vpcConnector",
          "state"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a connector only if this function needs that outbound VPC path."
      ],
      "summary": "Configure a connector only if this function needs that outbound VPC path."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": true,
        "field": "vpcConnector"
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": true,
        "field": "vpcConnector"
      },
      "predicate_qualname": "function_setting.<locals>.evaluate",
      "source_qualname": "function_setting.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active function has no VPC connector reference."
  },
  "gcp.ports.function_basic_role_declarations": {
    "description_fields": {
      "description": "Joins the function identity to project and ancestor Owner or Editor role declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "iam_role.includedPermissions[]",
          "serviceConfig.serviceAccountEmail"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace broad Owner or Editor grants with the function’s required permissions."
      ],
      "summary": "Replace broad Owner or Editor grants with the function’s required permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "mode": "basic"
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {
        "mode": "basic"
      },
      "predicate_qualname": "function_roles.<locals>.evaluate",
      "source_qualname": "function_roles.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function identity has an Owner or Editor role declaration."
  },
  "gcp.ports.function_internal_ingress_declaration": {
    "description_fields": {
      "description": "Checks the function ingress setting for ALLOW_INTERNAL_ONLY."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. A VPC connector controls outbound traffic, not inbound authorization."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "serviceConfig.ingressSettings"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use internal-only ingress if the function should receive only internal requests."
      ],
      "summary": "Use internal-only ingress if the function should receive only internal requests."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "function",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {},
      "predicate_qualname": "function_internal",
      "source_qualname": "function_internal"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function does not declare internal-only ingress."
  },
  "gcp.ports.function_legacy_deployment_role_declarations": {
    "description_fields": {
      "description": "Joins function identity roles to Deployment Manager create or update permission declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "iam_role.includedPermissions[]",
          "serviceConfig.serviceAccountEmail"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove legacy deployment permissions the function does not need."
      ],
      "summary": "Remove legacy deployment permissions the function does not need."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "mode": "deployment"
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {
        "mode": "deployment"
      },
      "predicate_qualname": "function_roles.<locals>.evaluate",
      "source_qualname": "function_roles.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function identity has a Deployment Manager mutation permission declaration."
  },
  "gcp.ports.function_logging_mutation_declarations": {
    "description_fields": {
      "description": "Joins function identity roles to logging update or delete permission declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam_policy.bindings[].members[]",
          "iam_policy.bindings[].role",
          "iam_role.includedPermissions[]",
          "serviceConfig.serviceAccountEmail"
        ],
        "kind": "function",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Functions service configuration",
          "url": "https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove logging mutation permissions the function does not need."
      ],
      "summary": "Remove logging mutation permissions the function does not need."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "mode": "logging"
      },
      "kind": "function",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {
        "mode": "logging"
      },
      "predicate_qualname": "function_roles.<locals>.evaluate",
      "source_qualname": "function_roles.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function identity has a logging mutation permission declaration."
  },
  "gcp.ports.iam_api_key_age_90": {
    "description_fields": {
      "description": "Compares API-key creation time with midnight UTC 90 days before the collection date."
    },
    "remediation_fields": {
      "caveats": [
        "Key age is metadata, not evidence of compromise or recent use."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "createTime",
          "_provenance.collected_at",
          "context.created_at"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace stale keys after migrating clients, then revoke the old key."
      ],
      "summary": "Replace stale keys after migrating clients, then revoke the old key."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "field": "createTime",
        "user_managed": false
      },
      "kind": "api_key",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {
        "field": "createTime",
        "user_managed": false
      },
      "predicate_qualname": "age.<locals>.evaluate",
      "source_qualname": "age.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key was created on or before the 90-day UTC-date cutoff."
  },
  "gcp.ports.iam_api_key_restricts_apis": {
    "description_fields": {
      "description": "Checks for nonempty API targets without the unrestricted cloudapis.googleapis.com target."
    },
    "remediation_fields": {
      "caveats": [
        "API target declarations do not restrict callers or prove requests are authorized."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "restrictions.apiTargets",
          "restrictions.apiTargets[].service"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the key to the APIs its clients actually use."
      ],
      "summary": "Restrict the key to the APIs its clients actually use."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "api_key",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {},
      "predicate_qualname": "api_targets",
      "source_qualname": "api_targets"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key has no specific API restriction."
  },
  "gcp.ports.iam_api_key_restricts_websites_hosts_apps": {
    "description_fields": {
      "description": "Checks one caller-restriction mode for a nonempty list without recognized universal entries."
    },
    "remediation_fields": {
      "caveats": [
        "This checks declared lists, not caller requests or possession of the key."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "restrictions.serverKeyRestrictions.allowedIps[]"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the key to its intended IP addresses, websites or applications."
      ],
      "summary": "Restrict the key to its intended IP addresses, websites or applications."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "api_key",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {},
      "predicate_qualname": "caller_restrictions",
      "source_qualname": "caller_restrictions"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key has no narrow caller restriction."
  },
  "gcp.ports.iam_service_account_gcp_managed_key": {
    "description_fields": {
      "description": "Joins a service account to collected key metadata and flags user-managed keys."
    },
    "remediation_fields": {
      "caveats": [
        "The key inventory does not establish activity, key contents or compromise."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "email",
          "name",
          "service_account_key.keyType",
          "service_account_key.serviceAccount"
        ],
        "kind": "service_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Prefer attached identities or federation and remove unused user-managed keys after migrating clients."
      ],
      "summary": "Prefer attached identities or federation and remove unused user-managed keys after migrating clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "service_account",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {},
      "predicate_qualname": "account_keys",
      "source_qualname": "account_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The service account has a user-managed key."
  },
  "gcp.ports.iam_service_account_key_age_90": {
    "description_fields": {
      "description": "Compares user-managed key creation time with midnight UTC 90 days before collection."
    },
    "remediation_fields": {
      "caveats": [
        "Provider-managed keys are excluded; creation time does not establish key use or compromise."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "keyType",
          "validAfterTime",
          "_provenance.collected_at",
          "context.created_at"
        ],
        "kind": "service_account_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Prefer keyless authentication; otherwise rotate the key after migrating its clients."
      ],
      "summary": "Prefer keyless authentication; otherwise rotate the key after migrating its clients."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "field": "validAfterTime",
        "user_managed": true
      },
      "kind": "service_account_key",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {
        "field": "validAfterTime",
        "user_managed": true
      },
      "predicate_qualname": "age.<locals>.evaluate",
      "source_qualname": "age.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user-managed service-account key predates the 90-day UTC-date cutoff."
  },
  "gcp.ports.iam_user_not_assigned_service_account_user_role_project_level": {
    "description_fields": {
      "description": "Checks project-root Service Account User or Token Creator bindings for non-service-account-suffix principals."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings",
          "bindings[].members[]",
          "bindings[].role",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Grant identity use or token creation only at the service-account scope where required."
      ],
      "summary": "Grant identity use or token creation only at the service-account scope where required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "iam_policy",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {},
      "predicate_qualname": "project_identity_roles",
      "source_qualname": "project_identity_roles"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A project-root identity-use or token-creator role is assigned to a non-service-account principal."
  },
  "gcp.ports.iam_user_separation_of_duty_scoped": {
    "description_fields": {
      "description": "Checks project-root user bindings for both Service Account Admin and Service Account User roles."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings[].members[]",
          "bindings[].role",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Separate service-account administration and use where duties must be separated."
      ],
      "summary": "Separate service-account administration and use where duties must be separated."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "admin_role": "roles/iam.serviceAccountAdmin",
        "use_roles": [
          "roles/iam.serviceAccountUser"
        ]
      },
      "kind": "iam_policy",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {
        "admin_role": "roles/iam.serviceAccountAdmin",
        "use_roles": [
          "roles/iam.serviceAccountUser"
        ]
      },
      "predicate_qualname": "duty.<locals>.evaluate",
      "source_qualname": "duty.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A user has both service-account administrator and user role declarations."
  },
  "gcp.ports.kms_key_rotated_within_90_day": {
    "description_fields": {
      "description": "Checks an applicable active encryption key for an automatic period above zero and at most 90 days."
    },
    "remediation_fields": {
      "caveats": [
        "This checks the scheduled interval, not the last rotation or re-encryption of existing data."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "purpose",
          "primary.state",
          "primary.protectionLevel",
          "rotationPeriod"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a supported automatic rotation period of at most 90 days."
      ],
      "summary": "Configure a supported automatic rotation period of at most 90 days."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "kms_key",
      "module": "peaso.checks.gcp_ports_keys",
      "predicate_bindings": {},
      "predicate_qualname": "kms_period",
      "source_qualname": "kms_period"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The automatic rotation period is disabled or exceeds 90 days."
  },
  "gcp.ports.kms_key_separation_of_duties_enforced": {
    "description_fields": {
      "description": "Checks project-root user bindings for both KMS administration and a cryptographic-use role."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings[].members[]",
          "bindings[].role",
          "name"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "IAM policy resource",
          "url": "https://cloud.google.com/iam/docs/reference/rest/v1/Policy"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Separate key administration and cryptographic-use roles where duties must be separated."
      ],
      "summary": "Separate key administration and cryptographic-use roles where duties must be separated."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "admin_role": "roles/cloudkms.admin",
        "use_roles": [
          "roles/cloudkms.cryptoKeyEncrypterDecrypter",
          "roles/cloudkms.cryptoKeyEncrypter",
          "roles/cloudkms.cryptoKeyDecrypter"
        ]
      },
      "kind": "iam_policy",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {
        "admin_role": "roles/cloudkms.admin",
        "use_roles": [
          "roles/cloudkms.cryptoKeyEncrypterDecrypter",
          "roles/cloudkms.cryptoKeyEncrypter",
          "roles/cloudkms.cryptoKeyDecrypter"
        ]
      },
      "predicate_qualname": "duty.<locals>.evaluate",
      "source_qualname": "duty.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A user has both KMS administrator and cryptographic-use role declarations."
  },
  "gcp.ports.kubernetes_cluster_auto_repair_enabled": {
    "description_fields": {
      "description": "Checks each node pool’s autoRepair management setting."
    },
    "remediation_fields": {
      "caveats": [
        "A node-pool setting does not establish a successful repair."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].management.autoRepair",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable node auto-repair where compatible with maintenance and availability requirements."
      ],
      "summary": "Enable node auto-repair where compatible with maintenance and availability requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "field": "autoRepair"
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "field": "autoRepair"
      },
      "predicate_qualname": "node_pool.<locals>.evaluate",
      "source_qualname": "node_pool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool disables automatic repair."
  },
  "gcp.ports.kubernetes_cluster_auto_upgrade_enabled": {
    "description_fields": {
      "description": "Checks each node pool’s autoUpgrade management setting."
    },
    "remediation_fields": {
      "caveats": [
        "The setting does not prove nodes are already patched."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].management.autoUpgrade",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable automatic node upgrades with suitable maintenance windows and disruption controls."
      ],
      "summary": "Enable automatic node upgrades with suitable maintenance windows and disruption controls."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "field": "autoUpgrade"
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "field": "autoUpgrade"
      },
      "predicate_qualname": "node_pool.<locals>.evaluate",
      "source_qualname": "node_pool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool disables automatic upgrades."
  },
  "gcp.ports.kubernetes_cluster_intra_node_visibility_enabled": {
    "description_fields": {
      "description": "Checks the cluster’s intra-node visibility flag, including known false omission."
    },
    "remediation_fields": {
      "caveats": [
        "The flag does not establish flow-log enablement, sampling or delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "networkConfig.enableIntraNodeVisibility",
          "networkConfig.network"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable intra-node visibility if required for node traffic visibility."
      ],
      "summary": "Enable intra-node visibility if required for node traffic visibility."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {},
      "predicate_qualname": "intra_node_visibility",
      "source_qualname": "intra_node_visibility"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Intra-node visibility is disabled."
  },
  "gcp.ports.kubernetes_cluster_legacy_endpoints_disabled": {
    "description_fields": {
      "description": "Checks each node pool for disable-legacy-endpoints=true metadata."
    },
    "remediation_fields": {
      "caveats": [
        "Node-pool declarations do not prove endpoint behavior on running nodes."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].config.metadata.disable-legacy-endpoints",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable legacy metadata endpoints in affected node pools."
      ],
      "summary": "Disable legacy metadata endpoints in affected node pools."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "absent": null,
        "bad": "false",
        "expected": {
          "callable": "str"
        },
        "good": "true",
        "path": "metadata.disable-legacy-endpoints"
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "absent": null,
        "bad": "false",
        "expected": {
          "callable": "str"
        },
        "good": "true",
        "path": "metadata.disable-legacy-endpoints"
      },
      "predicate_qualname": "pool_scalar.<locals>.evaluate",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool explicitly enables legacy metadata endpoints."
  },
  "gcp.ports.kubernetes_cluster_node_config_image_cos_containerd": {
    "description_fields": {
      "description": "Checks each node pool imageType for COS_CONTAINERD rather than UBUNTU_CONTAINERD."
    },
    "remediation_fields": {
      "caveats": [
        "This profile compares two declared image types; it does not establish that Ubuntu is vulnerable."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].config.imageType",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use COS_CONTAINERD where this operating-system preference fits the workload."
      ],
      "summary": "Use COS_CONTAINERD where this operating-system preference fits the workload."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "absent": null,
        "bad": "UBUNTU_CONTAINERD",
        "expected": {
          "callable": "str"
        },
        "good": "COS_CONTAINERD",
        "path": "imageType"
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "absent": null,
        "bad": "UBUNTU_CONTAINERD",
        "expected": {
          "callable": "str"
        },
        "good": "COS_CONTAINERD",
        "path": "imageType"
      },
      "predicate_qualname": "pool_scalar.<locals>.evaluate",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool declares UBUNTU_CONTAINERD."
  },
  "gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled": {
    "description_fields": {
      "description": "Checks each node pool’s integrity-monitoring setting, including its true omission default."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration does not prove alert delivery or node integrity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].config.shieldedInstanceConfig.enableIntegrityMonitoring",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable integrity monitoring in the affected node pools."
      ],
      "summary": "Enable integrity monitoring in the affected node pools."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "absent": true,
        "bad": false,
        "expected": {
          "callable": "bool"
        },
        "good": true,
        "path": "shieldedInstanceConfig.enableIntegrityMonitoring"
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "absent": true,
        "bad": false,
        "expected": {
          "callable": "bool"
        },
        "good": true,
        "path": "shieldedInstanceConfig.enableIntegrityMonitoring"
      },
      "predicate_qualname": "pool_scalar.<locals>.evaluate",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool disables integrity monitoring."
  },
  "gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled": {
    "description_fields": {
      "description": "Checks each node pool’s Secure Boot setting, treating known omission as false."
    },
    "remediation_fields": {
      "caveats": [
        "A node-pool declaration does not prove the state of every running node."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "nodePools[].config.shieldedInstanceConfig.enableSecureBoot",
          "nodePools[].name"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable Secure Boot after verifying required node drivers and images are compatible."
      ],
      "summary": "Enable Secure Boot after verifying required node drivers and images are compatible."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "absent": false,
        "bad": false,
        "expected": {
          "callable": "bool"
        },
        "good": true,
        "path": "shieldedInstanceConfig.enableSecureBoot"
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "absent": false,
        "bad": false,
        "expected": {
          "callable": "bool"
        },
        "good": true,
        "path": "shieldedInstanceConfig.enableSecureBoot"
      },
      "predicate_qualname": "pool_scalar.<locals>.evaluate",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool does not enable Secure Boot."
  },
  "gcp.ports.kubernetes_cluster_use_ip_aliases": {
    "description_fields": {
      "description": "Checks whether the cluster explicitly selects alias IP ranges rather than route-based networking."
    },
    "remediation_fields": {
      "caveats": [
        "Unspecified or contradictory network modes remain UNKNOWN; migration may require a replacement cluster."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "ipAllocationPolicy.useIpAliases",
          "ipAllocationPolicy.useRoutes"
        ],
        "kind": "gke_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "GKE cluster resource",
          "url": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use VPC-native alias IP networking when creating or migrating a suitable cluster."
      ],
      "summary": "Use VPC-native alias IP networking when creating or migrating a suitable cluster."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_cluster",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {},
      "predicate_qualname": "use_ip_aliases",
      "source_qualname": "use_ip_aliases"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster explicitly selects route-based networking."
  },
  "gcp.ports.logging_bucket_retention_policy_enabled": {
    "description_fields": {
      "description": "Joins a Cloud Storage log-sink destination to its bucket and checks retentionPolicy.isLocked."
    },
    "remediation_fields": {
      "caveats": [
        "This applies only to Cloud Storage destinations; locking does not prove exported log volume."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bucket.name",
          "bucket.retentionPolicy.isLocked",
          "destination"
        ],
        "kind": "log_sink",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Logging sinks",
          "url": "https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set suitable retention and lock it only after reviewing the irreversible retention commitment."
      ],
      "summary": "Set suitable retention and lock it only after reviewing the irreversible retention commitment."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "log_sink",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {},
      "predicate_qualname": "retained_destination",
      "source_qualname": "retained_destination"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log destination bucket has no locked retention policy."
  },
  "gcp.ports.logging_metric_alert_audit_configuration_changes_scoped": {
    "description_fields": {
      "description": "Matches the audit configuration changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for audit configuration changes."
      ],
      "summary": "Configure a matching metric and enabled alert for audit configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*protoPayload.methodName\\s*=\\s*\"SetIamPolicy\"\\s*AND\\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:\\*\\s*"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*protoPayload.methodName\\s*=\\s*\"SetIamPolicy\"\\s*AND\\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:\\*\\s*"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_custom_role_changes_scoped": {
    "description_fields": {
      "description": "Matches the custom role changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for custom role changes."
      ],
      "summary": "Configure a matching metric and enabled alert for custom role changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"iam_role\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.CreateRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.DeleteRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.UpdateRole\"\\s*\\)"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"iam_role\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.CreateRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.DeleteRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.UpdateRole\"\\s*\\)"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role_scoped": {
    "description_fields": {
      "description": "Matches the custom role changes with iam admin undelete role filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for custom role changes with iam admin undelete role."
      ],
      "summary": "Configure a matching metric and enabled alert for custom role changes with iam admin undelete role."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"iam_role\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.CreateRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.DeleteRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.UpdateRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.UndeleteRole\"\\s*\\)"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"iam_role\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.CreateRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.DeleteRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.UpdateRole\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"google\\.iam\\.admin\\.v1\\.UndeleteRole\"\\s*\\)"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_firewall_rule_changes_scoped": {
    "description_fields": {
      "description": "Matches the firewall rule changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for firewall rule changes."
      ],
      "summary": "Configure a matching metric and enabled alert for firewall rule changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"gce_firewall_rule\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.firewalls\\.patch\"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.firewalls\\.insert\"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.firewalls\\.delete\"\\s*\\)"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"gce_firewall_rule\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.firewalls\\.patch\"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.firewalls\\.insert\"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.firewalls\\.delete\"\\s*\\)"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_network_changes_scoped": {
    "description_fields": {
      "description": "Matches the network changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for network changes."
      ],
      "summary": "Configure a matching metric and enabled alert for network changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*resource\\.type\\s*=\\s*gce_network\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*\"beta\\.compute\\.networks\\.insert\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"beta\\.compute\\.networks\\.patch\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"v1\\.compute\\.networks\\.delete\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"v1\\.compute\\.networks\\.removePeering\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"v1\\.compute\\.networks\\.addPeering\"\\s*\\)"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*resource\\.type\\s*=\\s*gce_network\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*=\\s*\"beta\\.compute\\.networks\\.insert\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"beta\\.compute\\.networks\\.patch\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"v1\\.compute\\.networks\\.delete\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"v1\\.compute\\.networks\\.removePeering\"\\s*OR\\s*protoPayload\\.methodName\\s*=\\s*\"v1\\.compute\\.networks\\.addPeering\"\\s*\\)"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_network_route_changes_scoped": {
    "description_fields": {
      "description": "Matches the network route changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for network route changes."
      ],
      "summary": "Configure a matching metric and enabled alert for network route changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"gce_route\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.routes\\.delete\"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.routes\\.insert\"\\s*\\)"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"gce_route\"\\s*AND\\s*\\(\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.routes\\.delete\"\\s*OR\\s*protoPayload\\.methodName\\s*:\\s*\"compute\\.routes\\.insert\"\\s*\\)"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_project_ownership_assignment_scoped": {
    "description_fields": {
      "description": "Matches the project ownership assignment filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for project ownership assignment."
      ],
      "summary": "Configure a matching metric and enabled alert for project ownership assignment."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*\\(protoPayload.serviceName\\s*=\\s*\"cloudresourcemanager.googleapis.com\"\\s*\\)\\s*AND\\s*\\(\\s*ProjectOwnership\\s*OR\\s*projectOwnerInvitee\\s*\\)\\s*OR\\s*\\(\\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\\s*=\\s*\"REMOVE\"\\s*AND\\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\\s*=\\s*\"roles/owner\"\\s*\\)\\s*OR\\s*\\(\\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\\s*=\\s*\"ADD\"\\s*AND\\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\\s*=\\s*\"roles/owner\"\\s*\\)\\s*"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*\\(protoPayload.serviceName\\s*=\\s*\"cloudresourcemanager.googleapis.com\"\\s*\\)\\s*AND\\s*\\(\\s*ProjectOwnership\\s*OR\\s*projectOwnerInvitee\\s*\\)\\s*OR\\s*\\(\\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\\s*=\\s*\"REMOVE\"\\s*AND\\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\\s*=\\s*\"roles/owner\"\\s*\\)\\s*OR\\s*\\(\\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\\s*=\\s*\"ADD\"\\s*AND\\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\\s*=\\s*\"roles/owner\"\\s*\\)\\s*"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_sql_instance_configuration_changes_scoped": {
    "description_fields": {
      "description": "Matches the sql instance configuration changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for sql instance configuration changes."
      ],
      "summary": "Configure a matching metric and enabled alert for sql instance configuration changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*protoPayload.methodName\\s*=\\s*\"cloudsql.instances.update\"\\s*"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*protoPayload.methodName\\s*=\\s*\"cloudsql.instances.update\"\\s*"
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_storage_iam_permission_changes_scoped": {
    "description_fields": {
      "description": "Matches the storage iam permission changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_fields": {
      "caveats": [
        "Template matching does not establish equivalent filters, cross-project coverage, thresholds, enabled notification channels or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "logging_metric.disabled",
          "logging_metric.filter",
          "logging_metric.metricDescriptor.type",
          "logging_metric.name",
          "monitoring_alert_policy.conditions[].conditionThreshold.filter",
          "monitoring_alert_policy.enabled",
          "monitoring_alert_policy.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a matching metric and enabled alert for storage iam permission changes."
      ],
      "summary": "Configure a matching metric and enabled alert for storage iam permission changes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"gcs_bucket\"\\s*AND\\s*protoPayload\\.methodName\\s*=\\s*\"storage\\.setIamPermissions\""
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {
        "pattern": "\\s*resource\\.type\\s*=\\s*\"gcs_bucket\"\\s*AND\\s*protoPayload\\.methodName\\s*=\\s*\"storage\\.setIamPermissions\""
      },
      "predicate_qualname": "metric_alert.<locals>.evaluate",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_sink_all_entries_enabled": {
    "description_fields": {
      "description": "Checks for an enabled project sink with no filter or active exclusions and a nonempty destination."
    },
    "remediation_fields": {
      "caveats": [
        "A sink declaration does not prove destination writes or retention."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "disabled",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a suitable unfiltered sink if every project log entry must be routed."
      ],
      "summary": "Configure a suitable unfiltered sink if every project log entry must be routed."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "project",
      "module": "peaso.checks.gcp_ports_logging",
      "predicate_bindings": {},
      "predicate_qualname": "all_entries",
      "source_qualname": "all_entries"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No qualifying all-entries project sink was found."
  },
  "gcp.ports.organization_essential_contacts_complete": {
    "description_fields": {
      "description": "Combines organization contact subscriptions and checks ALL or the five required categories."
    },
    "remediation_fields": {
      "caveats": [
        "Subscriptions do not establish contact validation or message delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "essential_contact.name",
          "essential_contact.notificationCategorySubscriptions[]",
          "name"
        ],
        "kind": "organization",
        "target": "resource"
      },
      "references": [
        {
          "title": "Essential Contacts",
          "url": "https://cloud.google.com/resource-manager/docs/managing-notification-contacts"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Assign maintained contacts for legal, security, suspension, technical and technical-incident notifications."
      ],
      "summary": "Assign maintained contacts for legal, security, suspension, technical and technical-incident notifications."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "organization",
      "module": "peaso.checks.gcp_ports_relationships",
      "predicate_bindings": {},
      "predicate_qualname": "contacts",
      "source_qualname": "contacts"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Organization contacts do not cover every required notification category."
  },
  "gcp.ports.project_no_api_key": {
    "description_fields": {
      "description": "Joins project identifiers to collected API-key metadata and checks for keys."
    },
    "remediation_fields": {
      "caveats": [
        "Key existence does not establish compromise, permissions or recent use."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "api_key.name",
          "name",
          "projectId"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unused API keys after migrating clients to suitable credentials."
      ],
      "summary": "Remove unused API keys after migrating clients to suitable credentials."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "project",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {},
      "predicate_qualname": "project_no_keys",
      "source_qualname": "project_no_keys"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project has an API key."
  },
  "gcp.ports.project_service_cloudasset_api_enabled": {
    "description_fields": {
      "description": "Joins the project to its Cloud Asset API service state and requires ENABLED."
    },
    "remediation_fields": {
      "caveats": [
        "API enablement does not establish inventory completeness or freshness."
      ],
      "steps": [
        "Enable Cloud Asset Inventory if asset inventory collection is required."
      ],
      "summary": "Enable Cloud Asset Inventory if asset inventory collection is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "service_name": "cloudasset.googleapis.com"
      },
      "kind": "project",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "service_name": "cloudasset.googleapis.com"
      },
      "predicate_qualname": "service.<locals>.evaluate",
      "source_qualname": "service.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cloud Asset API is disabled."
  },
  "gcp.ports.reference_sql_pg_min_duration": {
    "description_fields": {
      "description": "Compares POSTGRES flag log_min_duration_statement with '-1', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value '-1'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review log_min_duration_statement and set a compatible value required by this profile."
      ],
      "summary": "Review log_min_duration_statement and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "-1"
        ],
        "default": "-1",
        "engine": "POSTGRES",
        "flag": "log_min_duration_statement"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "-1"
        ],
        "default": "-1",
        "engine": "POSTGRES",
        "flag": "log_min_duration_statement"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_duration_statement declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sql_pg_min_error": {
    "description_fields": {
      "description": "Compares POSTGRES flag log_min_error_statement with 'error', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'error'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review log_min_error_statement and set a compatible value required by this profile."
      ],
      "summary": "Review log_min_error_statement and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "error"
        ],
        "default": "error",
        "engine": "POSTGRES",
        "flag": "log_min_error_statement"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "error"
        ],
        "default": "error",
        "engine": "POSTGRES",
        "flag": "log_min_error_statement"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_error_statement declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sql_pg_min_messages": {
    "description_fields": {
      "description": "Compares POSTGRES flag log_min_messages with 'WARNING' or 'ERROR' or 'LOG' or 'FATAL' or 'PANIC' or 'warning' or 'error' or 'log' or 'fatal' or 'panic', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'missing'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review log_min_messages and set a compatible value required by this profile."
      ],
      "summary": "Review log_min_messages and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "WARNING",
          "ERROR",
          "LOG",
          "FATAL",
          "PANIC",
          "warning",
          "error",
          "log",
          "fatal",
          "panic"
        ],
        "default": "missing",
        "engine": "POSTGRES",
        "flag": "log_min_messages"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "WARNING",
          "ERROR",
          "LOG",
          "FATAL",
          "PANIC",
          "warning",
          "error",
          "log",
          "fatal",
          "panic"
        ],
        "default": "missing",
        "engine": "POSTGRES",
        "flag": "log_min_messages"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_messages declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sql_ssl_connections": {
    "description_fields": {
      "description": "Checks native Cloud SQL encryption enforcement, including engine-specific SSL modes and the observed legacy fallback.",
      "pass_when": "PASS for supported native encryption-enforcing SSL modes or an explicit legacy requireSsl=true when the mode is absent or unspecified.",
      "fail_when": "FAIL for a supported allow-unencrypted mode or explicit legacy requireSsl=false; missing, conflicting or unsupported observations remain UNKNOWN.",
      "description_correction": {
        "base_row_sha256": "1431994006a4607531997f5eb29f1f96fabc62f5477b3b2af94f6c96de483d37",
        "change": "Validate engine/mode applicability and compatible native flag pairs; preserve explicit legacy encryption enforcement and keep missing or conflicting observations UNKNOWN.",
        "prior_predicate_sha256": "3a5f3e585d7924c7028fb65f2cc39d1ed04c55243e99a6fbe20972002dfb256b",
        "reference": "https://cloud.google.com/sql/docs/postgres/admin-api/rest/v1/instances#IpConfiguration",
        "version": "gcp-native-sql-transport-review-v1"
      }
    },
    "remediation_fields": {
      "caveats": [
        "Unsupported engine/mode pairs or conflicting flags remain UNKNOWN; runtime TLS and client authentication are outside this check."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.ipConfiguration.sslMode",
          "settings.ipConfiguration.requireSsl"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require encrypted database connections after migrating clients to TLS."
      ],
      "summary": "Require encrypted database connections after migrating clients to TLS."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {},
      "predicate_qualname": "sql_ssl",
      "source_qualname": "sql_ssl"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL permits unencrypted client connections.",
    "native_semantic_followup": {
      "report": "sql-transport-semantic-followup.json",
      "helper": "peaso/checks/gcp_sql_transport_native.py"
    }
  },
  "gcp.ports.reference_sqlserver_contained_database_authentication": {
    "description_fields": {
      "description": "Compares SQLSERVER flag contained database authentication with 'off', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'off'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review contained database authentication and set a compatible value required by this profile."
      ],
      "summary": "Review contained database authentication and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "contained database authentication"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "contained database authentication"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The contained database authentication declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_cross_db_ownership_chaining": {
    "description_fields": {
      "description": "Compares SQLSERVER flag cross db ownership chaining with 'off', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'off'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review cross db ownership chaining and set a compatible value required by this profile."
      ],
      "summary": "Review cross db ownership chaining and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "cross db ownership chaining"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "cross db ownership chaining"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cross db ownership chaining declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_external_scripts_enabled": {
    "description_fields": {
      "description": "Compares SQLSERVER flag external scripts enabled with 'off', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'off'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review external scripts enabled and set a compatible value required by this profile."
      ],
      "summary": "Review external scripts enabled and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "external scripts enabled"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "external scripts enabled"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The external scripts enabled declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_remote_access": {
    "description_fields": {
      "description": "Compares SQLSERVER flag remote access with 'off', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'on'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review remote access and set a compatible value required by this profile."
      ],
      "summary": "Review remote access and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "default": "on",
        "engine": "SQLSERVER",
        "flag": "remote access"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "default": "on",
        "engine": "SQLSERVER",
        "flag": "remote access"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The remote access declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_trace3625": {
    "description_fields": {
      "description": "Compares SQLSERVER flag 3625 with 'on', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value 'off'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review 3625 and set a compatible value required by this profile."
      ],
      "summary": "Review 3625 and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "on"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "3625"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "on"
        ],
        "default": "off",
        "engine": "SQLSERVER",
        "flag": "3625"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The 3625 declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_user_connections": {
    "description_fields": {
      "description": "Compares SQLSERVER flag user connections with '0', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value '0'; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review user connections and set a compatible value required by this profile."
      ],
      "summary": "Review user connections and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "0"
        ],
        "default": "0",
        "engine": "SQLSERVER",
        "flag": "user connections"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          "0"
        ],
        "default": "0",
        "engine": "SQLSERVER",
        "flag": "user connections"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user connections declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_user_options": {
    "description_fields": {
      "description": "Compares SQLSERVER flag user options with '', applying this profile’s omission rule."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. An omitted flag uses the profile value ''; this is not a measured database runtime value."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review user options and set a compatible value required by this profile."
      ],
      "summary": "Review user options and set a compatible value required by this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          ""
        ],
        "default": "",
        "engine": "SQLSERVER",
        "flag": "user options"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_configuration",
      "predicate_bindings": {
        "allowed": [
          ""
        ],
        "default": "",
        "engine": "SQLSERVER",
        "flag": "user options"
      },
      "predicate_qualname": "sql.<locals>.evaluate",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user options declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.service_account_mutating_role_declarations": {
    "description_fields": {
      "description": "Joins service-account bindings and role definitions for create, update, delete or setIamPolicy permissions."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "email"
        ],
        "kind": "service_account",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service account keys",
          "url": "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove mutation permissions the service account does not need and retain required workload operations."
      ],
      "summary": "Remove mutation permissions the service account does not need and retain required workload operations."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "service_account",
      "module": "peaso.checks.gcp_ports_iam",
      "predicate_bindings": {},
      "predicate_qualname": "account_mutations",
      "source_qualname": "account_mutations"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An assigned role declares resource mutation permissions."
  },
  "gcp.ports.sql_instance_mysql_binary_log_enabled": {
    "description_fields": {
      "description": "Checks the Cloud SQL binaryLogEnabled backup setting."
    },
    "remediation_fields": {
      "caveats": [
        "Binary-log configuration does not establish a successful backup or recovery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "settings.backupConfiguration.binaryLogEnabled"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable binary logging where MySQL recovery or replication requires it."
      ],
      "summary": "Enable binary logging where MySQL recovery or replication requires it."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": false,
        "expected": {
          "callable": "bool"
        },
        "good": true,
        "path": "settings.backupConfiguration.binaryLogEnabled"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "bad": false,
        "expected": {
          "callable": "bool"
        },
        "good": true,
        "path": "settings.backupConfiguration.binaryLogEnabled"
      },
      "predicate_qualname": "scalar.<locals>.evaluate",
      "source_qualname": "scalar.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "MySQL binary logging is disabled."
  },
  "gcp.ports.sql_instance_not_open_to_internet": {
    "description_fields": {
      "description": "Checks Cloud SQL authorized network entries for 0.0.0.0/0 or ::/0."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "settings.ipConfiguration",
          "settings.ipConfiguration.authorizedNetworks",
          "settings.ipConfiguration.authorizedNetworks[].value",
          "value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict authorized networks to the client ranges that require database access."
      ],
      "summary": "Restrict authorized networks to the client ranges that require database access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_perimeter",
      "predicate_bindings": {},
      "predicate_qualname": "sql_authorized",
      "source_qualname": "sql_authorized"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL authorizes an Internet-wide network range."
  },
  "gcp.ports.sql_instance_not_publicly_accessible": {
    "description_fields": {
      "description": "Checks for a PRIVATE address and private-network reference, and rejects PRIMARY incoming addresses."
    },
    "remediation_fields": {
      "caveats": [
        "OUTGOING is outbound-only; this is address metadata, not a live database connection test."
      ],
      "steps": [
        "Configure required private connectivity and disable unnecessary public incoming addressing."
      ],
      "summary": "Configure required private connectivity and disable unnecessary public incoming addressing."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "criterion": "private_network"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "criterion": "private_network"
      },
      "predicate_qualname": "sql_address.<locals>.evaluate",
      "source_qualname": "sql_address.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance lacks the required private configuration or declares a PRIMARY public incoming address."
  },
  "gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_checkpoints for on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_checkpoints to on after checking engine and workload requirements."
      ],
      "summary": "Set log_checkpoints to on after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_checkpoints",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_checkpoints",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_checkpoints flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_duration_database_flag_on": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_duration for on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_duration to on after checking engine and workload requirements."
      ],
      "summary": "Set log_duration to on after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_duration",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_duration",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_duration flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_error_verbosity for default or verbose."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_error_verbosity to default or verbose after checking engine and workload requirements."
      ],
      "summary": "Set log_error_verbosity to default or verbose after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "default",
          "verbose"
        ],
        "engine": "POSTGRES",
        "flag": "log_error_verbosity",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "default",
          "verbose"
        ],
        "engine": "POSTGRES",
        "flag": "log_error_verbosity",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_error_verbosity flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_executor_stats for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_executor_stats to off after checking engine and workload requirements."
      ],
      "summary": "Set log_executor_stats to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_executor_stats",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_executor_stats",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_executor_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_hostname for on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set log_hostname to on after checking engine and workload requirements."
      ],
      "summary": "Set log_hostname to on after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_hostname",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_hostname",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_hostname flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_lock_waits for on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_lock_waits to on after checking engine and workload requirements."
      ],
      "summary": "Set log_lock_waits to on after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_lock_waits",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "on"
        ],
        "engine": "POSTGRES",
        "flag": "log_lock_waits",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_lock_waits flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_min_duration_statement for -1."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set log_min_duration_statement to -1 after checking engine and workload requirements."
      ],
      "summary": "Set log_min_duration_statement to -1 after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "-1"
        ],
        "engine": "POSTGRES",
        "flag": "log_min_duration_statement",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "-1"
        ],
        "engine": "POSTGRES",
        "flag": "log_min_duration_statement",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_duration_statement flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_min_error_statement for an explicit value."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure log_min_error_statement explicitly for the database’s logging requirements."
      ],
      "summary": "Configure log_min_error_statement explicitly for the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [],
        "engine": "POSTGRES",
        "flag": "log_min_error_statement",
        "forbidden": false,
        "presence": true
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [],
        "engine": "POSTGRES",
        "flag": "log_min_error_statement",
        "forbidden": false,
        "presence": true
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_error_statement flag is not explicitly configured."
  },
  "gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_min_messages for error or warning."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_min_messages to error or warning after checking engine and workload requirements."
      ],
      "summary": "Set log_min_messages to error or warning after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "error",
          "warning"
        ],
        "engine": "POSTGRES",
        "flag": "log_min_messages",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "error",
          "warning"
        ],
        "engine": "POSTGRES",
        "flag": "log_min_messages",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_messages flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_parser_stats for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_parser_stats to off after checking engine and workload requirements."
      ],
      "summary": "Set log_parser_stats to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_parser_stats",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_parser_stats",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_parser_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_planner_stats for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_planner_stats to off after checking engine and workload requirements."
      ],
      "summary": "Set log_planner_stats to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_planner_stats",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_planner_stats",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_planner_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_statement_stats for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_statement_stats to off after checking engine and workload requirements."
      ],
      "summary": "Set log_statement_stats to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_statement_stats",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "POSTGRES",
        "flag": "log_statement_stats",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_statement_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0": {
    "description_fields": {
      "description": "Checks POSTGRES flag log_temp_files for 0."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set log_temp_files to 0 after checking engine and workload requirements."
      ],
      "summary": "Set log_temp_files to 0 after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "0"
        ],
        "engine": "POSTGRES",
        "flag": "log_temp_files",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "0"
        ],
        "engine": "POSTGRES",
        "flag": "log_temp_files",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_temp_files flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_require_ssl_enabled": {
    "description_fields": {
      "description": "Checks native Cloud SQL encryption enforcement, including engine-specific SSL modes and the observed legacy fallback.",
      "pass_when": "PASS for supported native encryption-enforcing SSL modes or an explicit legacy requireSsl=true when the mode is absent or unspecified.",
      "fail_when": "FAIL for a supported allow-unencrypted mode or explicit legacy requireSsl=false; missing, conflicting or unsupported observations remain UNKNOWN.",
      "description_correction": {
        "base_row_sha256": "970ae57f5331c919bed0ef1390a2cd04582c2fe8cb36333190d5bb3f58b455f7",
        "change": "Validate engine/mode applicability and compatible native flag pairs; preserve explicit legacy encryption enforcement and keep missing or conflicting observations UNKNOWN.",
        "prior_predicate_sha256": "9762e3d59a15eeba148639267033ae2d6d6cefae54502589fa3655e16faf46f3",
        "reference": "https://cloud.google.com/sql/docs/postgres/admin-api/rest/v1/instances#IpConfiguration",
        "version": "gcp-native-sql-transport-review-v1"
      }
    },
    "remediation_fields": {
      "caveats": [
        "Unsupported engine/mode pairs or conflicting flags remain UNKNOWN; runtime TLS and client authentication are outside this check."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.ipConfiguration.sslMode",
          "settings.ipConfiguration.requireSsl"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require encrypted database connections after verifying client TLS compatibility."
      ],
      "summary": "Require encrypted database connections after verifying client TLS compatibility."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_compute",
      "predicate_bindings": {},
      "predicate_qualname": "sql_ssl",
      "source_qualname": "sql_ssl"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL permits unencrypted client connections.",
    "native_semantic_followup": {
      "report": "sql-transport-semantic-followup.json",
      "helper": "peaso/checks/gcp_sql_transport_native.py"
    }
  },
  "gcp.ports.sql_instance_sql_3625_trace_database_flag_on": {
    "description_fields": {
      "description": "Checks SQLSERVER flag 3625 for on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set 3625 to on after checking engine and workload requirements."
      ],
      "summary": "Set 3625 to on after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "on"
        ],
        "engine": "SQLSERVER",
        "flag": "3625",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "on"
        ],
        "engine": "SQLSERVER",
        "flag": "3625",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The 3625 flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off": {
    "description_fields": {
      "description": "Checks SQLSERVER flag contained database authentication for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set contained database authentication to off after checking engine and workload requirements."
      ],
      "summary": "Set contained database authentication to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "contained database authentication",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "contained database authentication",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The contained database authentication flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off": {
    "description_fields": {
      "description": "Checks SQLSERVER flag cross db ownership chaining for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set cross db ownership chaining to off after checking engine and workload requirements."
      ],
      "summary": "Set cross db ownership chaining to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "cross db ownership chaining",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "cross db ownership chaining",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cross db ownership chaining flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off": {
    "description_fields": {
      "description": "Checks SQLSERVER flag external scripts enabled for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set external scripts enabled to off after checking engine and workload requirements."
      ],
      "summary": "Set external scripts enabled to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "external scripts enabled",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "external scripts enabled",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The external scripts enabled flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_remote_access_database_flag_off": {
    "description_fields": {
      "description": "Checks SQLSERVER flag remote access for off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity. Updating database flags replaces every existing flag; preserve the full current flag set in the reviewed update file."
      ],
      "steps": [
        "Set remote access to off after checking engine and workload requirements."
      ],
      "summary": "Set remote access to off after checking engine and workload requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "remote access",
        "forbidden": false,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [
          "off"
        ],
        "engine": "SQLSERVER",
        "flag": "remote access",
        "forbidden": false,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The remote access flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_user_connections_database_flag_configured": {
    "description_fields": {
      "description": "Checks SQLSERVER flag user connections for an explicit value."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure user connections explicitly for the database’s logging requirements."
      ],
      "summary": "Configure user connections explicitly for the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [],
        "engine": "SQLSERVER",
        "flag": "user connections",
        "forbidden": false,
        "presence": true
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [],
        "engine": "SQLSERVER",
        "flag": "user connections",
        "forbidden": false,
        "presence": true
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user connections flag is not explicitly configured."
  },
  "gcp.ports.sql_instance_sql_user_options_database_flag_not_configured": {
    "description_fields": {
      "description": "Checks SQLSERVER flag user options for absence."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. This is a flag declaration, not an observation of database activity."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove the explicit user options flag if it is unnecessary under this profile."
      ],
      "summary": "Remove the explicit user options flag if it is unnecessary under this profile."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "allowed": [],
        "engine": "SQLSERVER",
        "flag": "user options",
        "forbidden": true,
        "presence": false
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_services",
      "predicate_bindings": {
        "allowed": [],
        "engine": "SQLSERVER",
        "flag": "user options",
        "forbidden": true,
        "presence": false
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user options flag is explicitly configured."
  },
  "gcp.ports.sql_instance_with_no_public_ips": {
    "description_fields": {
      "description": "Checks SECOND_GEN Cloud SQL address metadata for a PRIMARY public incoming assignment."
    },
    "remediation_fields": {
      "caveats": [
        "OUTGOING is outbound-only; legacy incoming assignments outside this predicate remain unresolved."
      ],
      "steps": [
        "Disable unnecessary public incoming addressing after verifying private client connectivity."
      ],
      "summary": "Disable unnecessary public incoming addressing after verifying private client connectivity."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "criterion": "source_second_gen"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "criterion": "source_second_gen"
      },
      "predicate_qualname": "sql_address.<locals>.evaluate",
      "source_qualname": "sql_address.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SECOND_GEN instance declares a PRIMARY public incoming address."
  },
  "gcp.ports.sql_no_primary_address": {
    "description_fields": {
      "description": "Checks Cloud SQL address metadata for a PRIMARY incoming address."
    },
    "remediation_fields": {
      "caveats": [
        "OUTGOING is outbound-only; legacy MIGRATED_1ST_GEN addressing is not the same type."
      ],
      "steps": [
        "Disable public incoming addressing if clients can use private connectivity instead."
      ],
      "summary": "Disable public incoming addressing if clients can use private connectivity instead."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "criterion": "primary"
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "criterion": "primary"
      },
      "predicate_qualname": "sql_address.<locals>.evaluate",
      "source_qualname": "sql_address.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance declares a PRIMARY public incoming address."
  },
  "gcp.ports.storage_bucket_not_publicly_accessible": {
    "description_fields": {
      "description": "Checks bucket IAM bindings for public principals, retaining role and condition metadata."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "steps": [
        "Remove unnecessary public-principal bindings and preserve intended readers."
      ],
      "summary": "Remove unnecessary public-principal bindings and preserve intended readers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "active_only": false,
        "invoker_only": false
      },
      "kind": "bucket",
      "module": "peaso.checks.gcp_ports_metadata",
      "predicate_bindings": {
        "active_only": false,
        "invoker_only": false
      },
      "predicate_qualname": "policy_public.<locals>.evaluate",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket IAM policy declares a public principal."
  },
  "gcp.reviewed.bigquery.cmek": {
    "description_fields": {
      "description": "Checks non-anonymous datasets for a default customer-managed key reference."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate. A dataset default applies to new tables."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "defaultEncryptionConfiguration.kmsKeyName"
        ],
        "kind": "bigquery_dataset",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery dataset resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set a default customer-managed key if required and separately review existing tables."
      ],
      "summary": "Set a default customer-managed key if required and separately review existing tables."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bigquery_dataset",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "bigquery_cmek",
      "source_qualname": "bigquery_cmek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset has no default customer-managed key."
  },
  "gcp.reviewed.bigquery.no_public_acl": {
    "description_fields": {
      "description": "Checks dataset ACL entries for public IAM or legacy public-group declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Views, inherited permissions and conditions require separate review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "access",
          "access[].role",
          "access[].specialGroup"
        ],
        "kind": "bigquery_dataset",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery dataset resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public dataset access and retain the intended readers."
      ],
      "summary": "Remove unnecessary public dataset access and retain the intended readers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bigquery_dataset",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "bigquery_public",
      "source_qualname": "bigquery_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset ACL declares public access."
  },
  "gcp.reviewed.compute.block_project_ssh_keys": {
    "description_fields": {
      "description": "Checks for one explicit block-project-ssh-keys=true VM metadata entry."
    },
    "remediation_fields": {
      "caveats": [
        "Missing or duplicate metadata stays UNKNOWN; this does not prove effective SSH authorization."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "metadata.items[].key",
          "metadata.items[].value"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Block project-wide SSH keys where instance-specific access or OS Login should control SSH."
      ],
      "summary": "Block project-wide SSH keys where instance-specific access or OS Login should control SSH."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "block_project_keys",
      "source_qualname": "block_project_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM explicitly allows project-wide SSH keys."
  },
  "gcp.reviewed.compute.disk_auto_delete": {
    "description_fields": {
      "description": "Checks whether persistent VM disks are configured for deletion with the VM."
    },
    "remediation_fields": {
      "caveats": [
        "Scratch disks are excluded; retaining a disk does not establish a backup."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "disks[].autoDelete"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable automatic deletion for persistent disks that must survive VM removal."
      ],
      "summary": "Disable automatic deletion for persistent disks that must survive VM removal."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "disk_auto_delete",
      "source_qualname": "disk_auto_delete"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A persistent disk is configured to delete with the VM."
  },
  "gcp.reviewed.compute.ip_forwarding": {
    "description_fields": {
      "description": "Checks the VM canIpForward declaration; GKE-named nodes are referred for review."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "canIpForward",
          "name"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable IP forwarding unless this VM is an intended network appliance."
      ],
      "summary": "Disable IP forwarding unless this VM is an intended network appliance."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "ip_forwarding",
      "source_qualname": "ip_forwarding"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM allows IP forwarding."
  },
  "gcp.reviewed.compute.no_default_full_api": {
    "description_fields": {
      "description": "Checks for the default Compute Engine identity with the cloud-platform OAuth scope."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "serviceAccounts",
          "serviceAccounts[].email",
          "serviceAccounts[].scopes[]"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use a dedicated least-privilege service account and review required OAuth scopes."
      ],
      "summary": "Use a dedicated least-privilege service account and review required OAuth scopes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "no_default_full_api",
      "source_qualname": "no_default_full_api"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The default Compute Engine service account has the cloud-platform OAuth scope."
  },
  "gcp.reviewed.compute.no_default_service_account": {
    "description_fields": {
      "description": "Checks attached identities for the default Compute Engine service account."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "serviceAccounts",
          "serviceAccounts[].email"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Attach a dedicated service account with only the permissions the VM needs."
      ],
      "summary": "Attach a dedicated service account with only the permissions the VM needs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "no_default_account",
      "source_qualname": "no_default_account"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM attaches the default Compute Engine service account."
  },
  "gcp.reviewed.compute.no_serial_console": {
    "description_fields": {
      "description": "Checks for one explicit serial-port-enable=false VM metadata entry."
    },
    "remediation_fields": {
      "caveats": [
        "Metadata is assessed; an active serial-console session is not observed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "metadata.items[].key",
          "metadata.items[].value"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable interactive serial-console access unless operational recovery requires it."
      ],
      "summary": "Disable interactive serial-console access unless operational recovery requires it."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "serial_console",
      "source_qualname": "serial_console"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Interactive serial-console access is explicitly enabled."
  },
  "gcp.reviewed.compute.single_interface": {
    "description_fields": {
      "description": "Counts declared VM network interfaces; GKE-named nodes are referred for review."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name",
          "networkInterfaces[].name"
        ],
        "kind": "instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine instance resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary interfaces after checking application routes and network-appliance requirements."
      ],
      "summary": "Remove unnecessary interfaces after checking application routes and network-appliance requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "single_interface",
      "source_qualname": "single_interface"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM declares more than one network interface."
  },
  "gcp.reviewed.kms.no_public_iam": {
    "description_fields": {
      "description": "Checks the key IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bindings",
          "iamPolicy.bindings",
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "members"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove public-principal bindings that are not required and review their conditions."
      ],
      "summary": "Remove public-principal bindings that are not required and review their conditions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "kms_key",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "kms_public",
      "source_qualname": "kms_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key IAM policy declares a public principal."
  },
  "gcp.reviewed.kms.rotation_90_days": {
    "description_fields": {
      "description": "Checks a positive rotation period and next scheduled rotation within 90 days of collection."
    },
    "remediation_fields": {
      "caveats": [
        "Uses the captured collection clock; rotation does not re-encrypt existing data."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "_provenance.collected_at",
          "nextRotationTime",
          "primary.state",
          "purpose",
          "rotationPeriod"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set a rotation period of at most 90 days and correct an overdue or distant next rotation."
      ],
      "summary": "Set a rotation period of at most 90 days and correct an overdue or distant next rotation."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "kms_key",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "kms_rotation_90",
      "source_qualname": "kms_rotation_90"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The rotation period or next scheduled rotation is outside the 90-day window."
  },
  "gcp.reviewed.kms.rotation_enabled": {
    "description_fields": {
      "description": "Checks automatic rotation for applicable encryption keys with an active primary version."
    },
    "remediation_fields": {
      "caveats": [
        "External, inactive and non-encryption keys are excluded; automatic rotation does not re-encrypt existing data."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "primary.state",
          "purpose",
          "rotationPeriod"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure automatic rotation for keys that require it, preserving application key-version access."
      ],
      "summary": "Configure automatic rotation for keys that require it, preserving application key-version access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "kms_key",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "kms_rotation",
      "source_qualname": "kms_rotation"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Automatic key rotation is not configured."
  },
  "gcp.reviewed.network.flow_logs": {
    "description_fields": {
      "description": "Checks applicable subnet flow-log settings and matching Network Management configurations."
    },
    "remediation_fields": {
      "caveats": [
        "Filtered configurations need separate review; enabled logging does not prove every flow was recorded."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "enableFlowLogs",
          "logConfig.enable",
          "purpose",
          "vpc_flow_logs_config.filter"
        ],
        "kind": "subnetwork",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine subnet resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable suitable flow logging for the subnet and verify its destination and sampling."
      ],
      "summary": "Enable suitable flow logging for the subnet and verify its destination and sampling."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "subnetwork",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "flow_logs",
      "source_qualname": "flow_logs"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No applicable enabled flow-log configuration was found."
  },
  "gcp.reviewed.network.no_default_vpc": {
    "description_fields": {
      "description": "Checks whether the observed network is named default."
    },
    "remediation_fields": {
      "caveats": [
        "The check evaluates this network name, not every project network or its firewall rules."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "name"
        ],
        "kind": "network",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine network resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Migrate required workloads before removing an unused default VPC."
      ],
      "summary": "Migrate required workloads before removing an unused default VPC."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "network",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "no_default_vpc",
      "source_qualname": "no_default_vpc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The observed network is named default."
  },
  "gcp.reviewed.project.os_login_2fa": {
    "description_fields": {
      "description": "Checks the project enable-oslogin-2fa metadata flag when Compute Engine is enabled."
    },
    "remediation_fields": {
      "caveats": [
        "This flag alone does not enable OS Login or prove an MFA-protected login."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "commonInstanceMetadata.fingerprint",
          "commonInstanceMetadata.items[].key",
          "commonInstanceMetadata.items[].value",
          "value"
        ],
        "kind": "project",
        "target": "resource"
      },
      "references": [
        {
          "title": "Service Usage service resource",
          "url": "https://cloud.google.com/service-usage/docs/reference/rest/v1/services"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable OS Login two-step verification where compatible, and separately verify OS Login is used."
      ],
      "summary": "Enable OS Login two-step verification where compatible, and separately verify OS Login is used."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "project",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "project_os_login_2fa",
      "source_qualname": "project_os_login_2fa"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project does not declare OS Login two-step verification."
  },
  "gcp.reviewed.sql.cmek": {
    "description_fields": {
      "description": "Checks primary Cloud SQL instances for a customer-managed KMS key reference."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "diskEncryptionConfiguration.kmsKeyName",
          "instanceType"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a customer-managed key if required, after checking service permissions and migration constraints."
      ],
      "summary": "Configure a customer-managed key if required, after checking service permissions and migration constraints."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "sql_cmek",
      "source_qualname": "sql_cmek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The primary Cloud SQL instance has no customer-managed key reference."
  },
  "gcp.reviewed.sql.high_availability": {
    "description_fields": {
      "description": "Checks primary Cloud SQL instances for REGIONAL rather than ZONAL availability."
    },
    "remediation_fields": {
      "caveats": [
        "Replicas and external instances are excluded; this does not test failover."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "instanceType",
          "settings.availabilityType"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use regional high availability where the database needs protection from a zonal failure."
      ],
      "summary": "Use regional high availability where the database needs protection from a zonal failure."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "sql_ha",
      "source_qualname": "sql_ha"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The primary Cloud SQL instance uses zonal availability."
  },
  "gcp.reviewed.sql.mysql_local_infile": {
    "description_fields": {
      "description": "Checks the explicit MYSQL flag local_infile for exactly off."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set local_infile to off if this profile matches the database’s logging requirements."
      ],
      "summary": "Set local_infile to off if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "on",
        "engine": "MYSQL",
        "flag": "local_infile",
        "good": "off",
        "values": null
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "on",
        "engine": "MYSQL",
        "flag": "local_infile",
        "good": "off",
        "values": null
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared local_infile value differs from off."
  },
  "gcp.reviewed.sql.mysql_skip_show_database": {
    "description_fields": {
      "description": "Checks the explicit MYSQL flag skip_show_database for exactly on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set skip_show_database to on if this profile matches the database’s logging requirements."
      ],
      "summary": "Set skip_show_database to on if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "off",
        "engine": "MYSQL",
        "flag": "skip_show_database",
        "good": "on",
        "values": null
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "off",
        "engine": "MYSQL",
        "flag": "skip_show_database",
        "good": "on",
        "values": null
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared skip_show_database value differs from on."
  },
  "gcp.reviewed.sql.postgres_log_connections": {
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_connections for exactly on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set log_connections to on if this profile matches the database’s logging requirements."
      ],
      "summary": "Set log_connections to on if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "off",
        "engine": "POSTGRES",
        "flag": "log_connections",
        "good": "on",
        "values": null
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "off",
        "engine": "POSTGRES",
        "flag": "log_connections",
        "good": "on",
        "values": null
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_connections value differs from on."
  },
  "gcp.reviewed.sql.postgres_log_disconnections": {
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_disconnections for exactly on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set log_disconnections to on if this profile matches the database’s logging requirements."
      ],
      "summary": "Set log_disconnections to on if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "off",
        "engine": "POSTGRES",
        "flag": "log_disconnections",
        "good": "on",
        "values": null
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "off",
        "engine": "POSTGRES",
        "flag": "log_disconnections",
        "good": "on",
        "values": null
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_disconnections value differs from on."
  },
  "gcp.reviewed.sql.postgres_log_error_verbosity": {
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_error_verbosity for exactly default."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set log_error_verbosity to default if this profile matches the database’s logging requirements."
      ],
      "summary": "Set log_error_verbosity to default if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "terse",
        "engine": "POSTGRES",
        "flag": "log_error_verbosity",
        "good": "default",
        "values": [
          "terse",
          "default",
          "verbose"
        ]
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "terse",
        "engine": "POSTGRES",
        "flag": "log_error_verbosity",
        "good": "default",
        "values": [
          "terse",
          "default",
          "verbose"
        ]
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_error_verbosity value differs from default."
  },
  "gcp.reviewed.sql.postgres_log_statement": {
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_statement for exactly ddl."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set log_statement to ddl if this profile matches the database’s logging requirements."
      ],
      "summary": "Set log_statement to ddl if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "none",
        "engine": "POSTGRES",
        "flag": "log_statement",
        "good": "ddl",
        "values": [
          "none",
          "ddl",
          "mod",
          "all"
        ]
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "none",
        "engine": "POSTGRES",
        "flag": "log_statement",
        "good": "ddl",
        "values": [
          "none",
          "ddl",
          "mod",
          "all"
        ]
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_statement value differs from ddl."
  },
  "gcp.reviewed.sql.postgres_pgaudit": {
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag cloudsql.enable_pgaudit for exactly on."
    },
    "remediation_fields": {
      "caveats": [
        "Change only this flag while preserving other database flags; check engine support and any restart or logging-volume impact. Missing values stay UNKNOWN; other logging levels may be valid for another profile."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "databaseVersion",
          "settings.databaseFlags",
          "settings.databaseFlags[].name",
          "settings.databaseFlags[].value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Set cloudsql.enable_pgaudit to on if this profile matches the database’s logging requirements."
      ],
      "summary": "Set cloudsql.enable_pgaudit to on if this profile matches the database’s logging requirements."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "bad": "off",
        "engine": "POSTGRES",
        "flag": "cloudsql.enable_pgaudit",
        "good": "on",
        "values": null
      },
      "kind": "sql_instance",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {
        "bad": "off",
        "engine": "POSTGRES",
        "flag": "cloudsql.enable_pgaudit",
        "good": "on",
        "values": null
      },
      "predicate_qualname": "sql_flag.<locals>.evaluate",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared cloudsql.enable_pgaudit value differs from on."
  },
  "gcp.reviewed.storage.access_logging": {
    "description_fields": {
      "description": "Checks for a nonempty bucket access-log destination."
    },
    "remediation_fields": {
      "caveats": [
        "A destination reference does not prove delivery, retention or destination permissions."
      ],
      "steps": [
        "Configure an appropriate access-log bucket and verify logs arrive."
      ],
      "summary": "Configure an appropriate access-log bucket and verify logs arrive."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_logging",
      "source_qualname": "bucket_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket has no access-log destination."
  },
  "gcp.reviewed.storage.lifecycle": {
    "description_fields": {
      "description": "Checks for lifecycle rules with recognized actions and nonempty conditions."
    },
    "remediation_fields": {
      "caveats": [
        "Rule presence does not prove retention adequacy; deletion rules can remove required data."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "action.storageClass",
          "action.type",
          "lifecycle.rule",
          "lifecycle.rule[].action.type",
          "lifecycle.rule[].condition.age"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Add lifecycle rules appropriate to the objects’ retention and storage-class needs."
      ],
      "summary": "Add lifecycle rules appropriate to the objects’ retention and storage-class needs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "lifecycle",
      "source_qualname": "lifecycle"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket lacks a qualifying lifecycle rule."
  },
  "gcp.reviewed.storage.soft_delete": {
    "description_fields": {
      "description": "Checks whether the bucket declares a positive soft-delete retention duration."
    },
    "remediation_fields": {
      "caveats": [
        "A positive duration does not establish adequate retention or a successful restoration."
      ],
      "steps": [
        "Enable an appropriate soft-delete window after reviewing recovery needs and storage costs."
      ],
      "summary": "Enable an appropriate soft-delete window after reviewing recovery needs and storage costs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "soft_delete",
      "source_qualname": "soft_delete"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket declares a zero soft-delete retention duration."
  },
  "gcp.reviewed.storage.versioning": {
    "description_fields": {
      "description": "Checks the bucket versioning declaration, including known omitted-field defaults."
    },
    "remediation_fields": {
      "caveats": [
        "Versioning configuration does not prove backup or restoration success."
      ],
      "steps": [
        "Enable object versioning where recovery from replacement or deletion is required."
      ],
      "summary": "Enable object versioning where recovery from replacement or deletion is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.gcp_extended",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_versioning",
      "source_qualname": "bucket_versioning"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Object versioning is disabled."
  },
  "gcp.sql.deletion_protection": {
    "description_fields": {
      "description": "Checks explicit settings.deletionProtectionEnabled on instances from a complete scoped inventory."
    },
    "remediation_fields": {
      "caveats": [
        "Deletion protection is not a backup or restore test."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "sql_instance collection status",
          "sql_instance.name",
          "sql_instance.settings.deletionProtectionEnabled"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable deletion protection where the database must resist accidental removal."
      ],
      "summary": "Enable deletion protection where the database must resist accidental removal."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.compliance_new_gcp_sql",
      "predicate_bindings": {},
      "predicate_qualname": "sql_deletion_protection",
      "source_qualname": "sql_deletion_protection"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL deletion protection is disabled."
  },
  "gcp.sql.iam_database_authentication": {
    "description_fields": {
      "description": "Checks complete instance-bound MySQL or PostgreSQL user lists for CLOUD_IAM_USER or CLOUD_IAM_SERVICE_ACCOUNT entries."
    },
    "remediation_fields": {
      "caveats": [
        "Group-based IAM user types do not satisfy this exact predicate; user presence does not prove the authentication flag is enabled."
      ],
      "cli": [],
      "references": [
        {
          "title": "Cloud SQL IAM database authentication",
          "url": "https://cloud.google.com/sql/docs/mysql/iam-authentication"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use appropriate IAM database users where keyless database authentication is required."
      ],
      "summary": "Use appropriate IAM database users where keyless database authentication is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_scope": {
          "callable": "_load_09.<locals>._scope"
        },
        "_sql_engine": {
          "callable": "_load_09.<locals>._sql_engine"
        },
        "get": {
          "callable": "get"
        },
        "list_of_objects": {
          "callable": "list_of_objects"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "sql_instance",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_scope": {
          "callable": "_load_09.<locals>._scope"
        },
        "_sql_engine": {
          "callable": "_load_09.<locals>._sql_engine"
        },
        "get": {
          "callable": "get"
        },
        "list_of_objects": {
          "callable": "list_of_objects"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_09.<locals>.sql_iam_database_user",
      "source_qualname": "_load_09.<locals>.sql_iam_database_user"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance has no direct IAM database user or service-account entry."
  },
  "gcp.sql.mysql_admin_account_posture": {
    "description_fields": {
      "description": "Joins MySQL user metadata to its instance and flags root or built-in accounts with percent or Internet-wide host patterns."
    },
    "remediation_fields": {
      "caveats": [
        "This is account metadata, not a connection attempt or proof of public database reachability."
      ],
      "cli": [],
      "references": [
        {
          "title": "MySQL built-in users and root account",
          "url": "https://cloud.google.com/sql/docs/mysql/users"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict built-in account host patterns where supported and prefer suitable IAM database identities."
      ],
      "summary": "Restrict built-in account host patterns where supported and prefer suitable IAM database identities."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "evaluator": {
          "callable": "_load_08.<locals>._mysql_admin"
        }
      },
      "kind": "sql_user",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_08.<locals>._inventory"
        },
        "_rows": {
          "callable": "_load_08.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "quote": {
          "callable": "quote"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_08.<locals>._mysql_admin",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A MySQL root or built-in account declares an unrestricted host pattern."
  },
  "gcp.sql.restrict_authorized_networks": {
    "description_fields": {
      "description": "Checks Cloud SQL authorized networks for 0.0.0.0/0 or ::/0."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "settings.ipConfiguration",
          "settings.ipConfiguration.authorizedNetworks",
          "settings.ipConfiguration.authorizedNetworks[].value",
          "value"
        ],
        "kind": "sql_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud SQL instance settings",
          "url": "https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/instances"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict database authorized networks to the clients that need access."
      ],
      "summary": "Restrict database authorized networks to the clients that need access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "sql_instance",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "sql_networks",
      "source_qualname": "sql_networks"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Cloud SQL authorizes an Internet-wide client range."
  },
  "gcp.storage.no_public_iam": {
    "description_fields": {
      "description": "Checks bucket IAM bindings for unconditional public principals, considering public-access-prevention configuration."
    },
    "remediation_fields": {
      "caveats": [
        "Bindings and conditions are reported as declarations; inherited permissions, deny policies and principal access boundaries can change effective access. Enforced public access prevention sends conflicting grants for review."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamPolicy.bindings[].members[]",
          "iamPolicy.bindings[].role",
          "iamPolicy.bindings[].condition",
          "iamConfiguration.publicAccessPrevention"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public IAM grants; preserve intended readers before changing access."
      ],
      "summary": "Remove unnecessary public IAM grants; preserve intended readers before changing access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_public",
      "source_qualname": "bucket_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The bucket IAM policy declares an unconditional public-principal grant."
  },
  "gcp.storage.public_access_prevention": {
    "description_fields": {
      "description": "Checks public access prevention, resolving inherited settings through the project’s effective organization policy."
    },
    "remediation_fields": {
      "caveats": [
        "The preventative setting does not inventory every object ACL or establish successful authorized reads."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamConfiguration.publicAccessPrevention"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enforce public access prevention if this bucket should not permit public readers."
      ],
      "summary": "Enforce public access prevention if this bucket should not permit public readers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks",
      "predicate_bindings": {},
      "predicate_qualname": "gcp_prevention",
      "source_qualname": "gcp_prevention"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The inherited public-access-prevention policy is not enforced."
  },
  "gcp.storage.uniform_access": {
    "description_fields": {
      "description": "Checks the bucket’s uniformBucketLevelAccess.enabled declaration."
    },
    "remediation_fields": {
      "caveats": [
        "This setting removes ACL-based authorization; it does not itself make bucket IAM private."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iamConfiguration.uniformBucketLevelAccess.enabled"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable uniform bucket-level access after migrating required object ACL permissions."
      ],
      "summary": "Enable uniform bucket-level access after migrating required object ACL permissions."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks",
      "predicate_bindings": {},
      "predicate_qualname": "gcp_uniform",
      "source_qualname": "gcp_uniform"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Uniform bucket-level access is disabled."
  },
  "gcp.subnetwork.private_google_access": {
    "description_fields": {
      "description": "Checks the Private Google Access flag on applicable VM subnets."
    },
    "remediation_fields": {
      "caveats": [
        "Proxy-only, NAT and other non-VM subnet purposes are excluded; this is not an Internet exposure check."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "privateIpGoogleAccess"
        ],
        "kind": "subnetwork",
        "target": "resource"
      },
      "references": [
        {
          "title": "Compute Engine subnet resource",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable Private Google Access where VMs without external IPs need supported Google APIs."
      ],
      "summary": "Enable Private Google Access where VMs without external IPs need supported Google APIs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "subnetwork",
      "module": "peaso.checks.gcp",
      "predicate_bindings": {},
      "predicate_qualname": "private_google_access",
      "source_qualname": "private_google_access"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Private Google Access is disabled."
  },
  "gcp_api_keys_active_services_only": {
    "description_fields": {
      "description": "Checks undeleted keys from a source-bound inventory for specific API target declarations."
    },
    "remediation_fields": {
      "caveats": [
        "This does not establish service enablement or active use; broad cloudapis targets remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "complete project-scoped api_key inventory from paginated keys.list",
          "api_key.name, deleteTime and _provenance.scope/source_requests",
          "api_key.restrictions.apiTargets[].service"
        ],
        "kind": "api_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "API key restrictions",
          "url": "https://cloud.google.com/api-keys/docs/add-restrictions-api-keys"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict the key to the APIs its clients need."
      ],
      "summary": "Restrict the key to the APIs its clients need."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "api_key",
      "module": "peaso.checks.compliance_new_gcp_api_keys",
      "predicate_bindings": {},
      "predicate_qualname": "active_api_key_targets",
      "source_qualname": "active_api_key_targets"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active API key has no API target restriction."
  },
  "gcp_autoscaler_capacity_target": {
    "description_fields": {
      "description": "Joins the autoscaler to its group and checks CPU target above 80% or no capacity above targetSize."
    },
    "remediation_fields": {
      "caveats": [
        "Declared targets do not prove resource exhaustion or autoscaling failure."
      ],
      "cli": [],
      "references": [
        {
          "title": "CPU utilization autoscaling targets",
          "url": "https://cloud.google.com/compute/docs/autoscaler/scaling-cpu"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Choose suitable CPU targets and maximum replicas with enough capacity for expected load."
      ],
      "summary": "Choose suitable CPU targets and maximum replicas with enough capacity for expected load."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "autoscaler",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_09.<locals>.autoscaler_capacity",
      "source_qualname": "_load_09.<locals>.autoscaler_capacity"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The autoscaler CPU target exceeds 80% or its maximum leaves no declared growth capacity."
  },
  "gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3": {
    "description_fields": {
      "description": "Checks attached Cloud Armor policies for a nondefault-priority rule with a nonempty match."
    },
    "remediation_fields": {
      "caveats": [
        "Any matching action can satisfy this existence check; it does not prove blocking or WAF enforcement."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Add the intended protective rule if the attached policy should do more than its default rule."
      ],
      "summary": "Add the intended protective rule if the attached policy should do more than its default rule."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_policy_backends": {
          "callable": "_load_51.<locals>._policy_backends"
        },
        "_rules": {
          "callable": "_load_51.<locals>._rules"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "security_policy",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_policy_backends": {
          "callable": "_load_51.<locals>._policy_backends"
        },
        "_rules": {
          "callable": "_load_51.<locals>._rules"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_51.<locals>.armor_nondefault_rule",
      "source_qualname": "_load_51.<locals>.armor_nondefault_rule"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The attached Cloud Armor policy has no qualifying nondefault rule."
  },
  "gcp_bucket_logging_enabled_fb7cc594582a": {
    "description_fields": {
      "description": "Checks the full bucket configuration for a nonblank usage-log destination."
    },
    "remediation_fields": {
      "caveats": [
        "A destination reference does not prove delivery, retention or access-log completeness."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bucket.name",
          "bucket._provenance.representation=full",
          "bucket.logging.logBucket (documented omission means unset in FULL projection)"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required usage-log destination and verify logs arrive."
      ],
      "summary": "Configure the required usage-log destination and verify logs arrive."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.compliance_new_gcp_storage",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_usage_log_destination",
      "source_qualname": "bucket_usage_log_destination"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket has no usage-log destination."
  },
  "gcp_c5_log_event_fields": {
    "description_fields": {
      "description": "Checks classified authenticated audit events for a timezone-aware timestamp and nonblank principal email."
    },
    "remediation_fields": {
      "caveats": [
        "This does not establish event authenticity or coverage of other event classes; action method absence remains UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Cloud Logging entries.list: timestamp, resource.type, protoPayload.authenticationInfo.principalEmail and protoPayload.methodName.",
          "Complete inventories: log_entry"
        ],
        "kind": "log_entry",
        "target": "resource"
      },
      "references": [
        {
          "title": "Audit log resource",
          "url": "https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Correct audit metadata collection or routing so timestamp and authenticated principal are retained."
      ],
      "summary": "Correct audit metadata collection or routing so timestamp and authenticated principal are retained."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "log_entry",
      "module": "peaso.checks._bulk_pending_compliance_new_sw52",
      "predicate_bindings": {},
      "predicate_qualname": "c5_log_event_fields",
      "source_qualname": "c5_log_event_fields"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The authenticated audit event has an invalid timestamp or missing principal email."
  },
  "gcp_c5_sbom": {
    "description_fields": {
      "description": "Joins deployed image digests to repository images and SBOM_REFERENCE occurrences with note names."
    },
    "remediation_fields": {
      "caveats": [
        "Reference existence does not validate SBOM contents, dependency completeness or vulnerability status."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Artifact Registry dockerImages.list: uri, tags; Artifact Analysis occurrences.list: resourceUri, kind=SBOM_REFERENCE, noteName; approved deployed image digest inventory.",
          "Complete inventories: artifact_repository, artifact_image, sbom_occurrence, deployed_image"
        ],
        "kind": "artifact_repository",
        "target": "resource"
      },
      "references": [
        {
          "title": "Artifact Registry virtual repositories",
          "url": "https://cloud.google.com/artifact-registry/docs/repositories/virtual-overview"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Publish an SBOM reference for each required deployed image digest and verify its contents separately."
      ],
      "summary": "Publish an SBOM reference for each required deployed image digest and verify its contents separately."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "artifact_repository",
      "module": "peaso.checks._bulk_pending_compliance_new_sw52",
      "predicate_bindings": {},
      "predicate_qualname": "c5_sbom",
      "source_qualname": "c5_sbom"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A deployed image digest has no matching SBOM reference."
  },
  "gcp_certificate_renewal_30_days": {
    "description_fields": {
      "description": "Checks deployed managed certificate replacements against the 30-day-before-expiry threshold with a 24-hour grace window."
    },
    "remediation_fields": {
      "caveats": [
        "The association is metadata, not a TLS probe; complete replacement inventory is required."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Deploy an ACTIVE replacement covering the required domains before the renewal window closes."
      ],
      "summary": "Deploy an ACTIVE replacement covering the required domains before the renewal window closes."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_cert": {
          "callable": "_load_54.<locals>._cert"
        }
      },
      "kind": "certificate",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_cert": {
          "callable": "_load_54.<locals>._cert"
        }
      },
      "predicate_qualname": "_load_54.<locals>.certificate_renewal",
      "source_qualname": "_load_54.<locals>.certificate_renewal"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No timely ACTIVE replacement covers the deployed certificate’s domains."
  },
  "gcp_certificate_rotation_180_days": {
    "description_fields": {
      "description": "Checks deployed ACTIVE managed certificate creation age against 180 days."
    },
    "remediation_fields": {
      "caveats": [
        "Certificate resource creation time is not leaf issuance time or proof of the certificate currently served."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Replace certificates if the 180-day creation-age profile is required."
      ],
      "summary": "Replace certificates if the 180-day creation-age profile is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_cert": {
          "callable": "_load_54.<locals>._cert"
        }
      },
      "kind": "certificate",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_cert": {
          "callable": "_load_54.<locals>._cert"
        }
      },
      "predicate_qualname": "_load_54.<locals>.certificate_rotation_180",
      "source_qualname": "_load_54.<locals>.certificate_rotation_180"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The deployed ACTIVE managed certificate resource is more than 180 days old."
  },
  "gcp_certificate_rotation_90_days": {
    "description_fields": {
      "description": "Parses the leaf certificate issuance time and compares deployed certificate age with 90 days."
    },
    "remediation_fields": {
      "caveats": [
        "Deployment metadata does not independently prove which leaf certificate an endpoint serves."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Replace certificates if the 90-day issuance-age profile is required."
      ],
      "summary": "Replace certificates if the 90-day issuance-age profile is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_cert": {
          "callable": "_load_54.<locals>._cert"
        }
      },
      "kind": "certificate",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_cert": {
          "callable": "_load_54.<locals>._cert"
        }
      },
      "predicate_qualname": "_load_54.<locals>.certificate_rotation_90",
      "source_qualname": "_load_54.<locals>.certificate_rotation_90"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The associated deployed leaf certificate was issued more than 90 days ago."
  },
  "gcp_certificate_validity": {
    "description_fields": {
      "description": "Checks certificate expiry against collection time and requires ACTIVE managed certificates."
    },
    "remediation_fields": {
      "caveats": [
        "Certificate Manager metadata does not prove which certificate an endpoint serves."
      ],
      "cli": [],
      "references": [
        {
          "title": "Manage Certificate Manager certificates",
          "url": "https://cloud.google.com/certificate-manager/docs/certificates"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Renew expired certificates or resolve managed provisioning failures before relying on them."
      ],
      "summary": "Renew expired certificates or resolve managed provisioning failures before relying on them."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_time": {
          "callable": "_load_09.<locals>._time"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "certificate",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_time": {
          "callable": "_load_09.<locals>._time"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_09.<locals>.certificate_validity",
      "source_qualname": "_load_09.<locals>.certificate_validity"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The certificate is expired or its managed state is not ACTIVE."
  },
  "gcp_cloud_armor_waf_enabled": {
    "description_fields": {
      "description": "Checks the attached external-backend policy for an enforced preconfigured WAF deny rule and an earlier bypass. It evaluates declared configuration, not public reachability or blocked traffic."
    },
    "remediation_fields": {
      "caveats": [
        "Expression text and action do not prove rule enforcement, coverage or actual attack blocking."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Configure suitable blocking WAF rules and review priorities and preview settings."
      ],
      "summary": "Configure suitable blocking WAF rules and review priorities and preview settings."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_list": {
          "callable": "_load_52.<locals>._list"
        },
        "_member": {
          "callable": "_load_52.<locals>._member"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "security_policy",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_list": {
          "callable": "_load_52.<locals>._list"
        },
        "_member": {
          "callable": "_load_52.<locals>._member"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_52.<locals>.cloud_armor_waf_enabled",
      "source_qualname": "_load_52.<locals>.cloud_armor_waf_enabled"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached external-backend policy lacks a supported enforced preconfigured WAF deny rule."
  },
  "gcp_cloudcdn_cookie_ttl": {
    "description_fields": {
      "description": "Checks GENERATED_COOKIE or HTTP_COOKIE affinityCookieTtlSec for at most 1800 seconds."
    },
    "remediation_fields": {
      "caveats": [
        "Load-balancer affinity is not application authentication, inactivity timeout or the consistentHash cookie override."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "backend_service.name",
          "backend_service._provenance.representation=full",
          "backend_service.sessionAffinity (must be observed)",
          "backend_service.affinityCookieTtlSec"
        ],
        "kind": "backend_service",
        "target": "resource"
      },
      "references": [
        {
          "title": "Backend services",
          "url": "https://cloud.google.com/compute/docs/reference/rest/v1/backendServices"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Choose an appropriate affinity cookie duration; reduce it if the 30-minute profile applies."
      ],
      "summary": "Choose an appropriate affinity cookie duration; reduce it if the 30-minute profile applies."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "backend_service",
      "module": "peaso.checks.compliance_new_gcp_backend",
      "predicate_bindings": {},
      "predicate_qualname": "backend_cookie_affinity_ttl",
      "source_qualname": "backend_cookie_affinity_ttl"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The backend affinity cookie duration exceeds 30 minutes."
  },
  "gcp_cloudsql_backup_failure_alert": {
    "description_fields": {
      "description": "Checks native local alert declarations for failed Cloud SQL automated-backup windows; unsupported filters or thresholds remain unknown."
    },
    "remediation_fields": {
      "caveats": [
        "This checks alert configuration, not notification channels, successful delivery or restored backups."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Configure an enabled alert for failed automated-backup windows, then test its notification delivery."
      ],
      "summary": "Configure an enabled alert for failed automated-backup windows, then test its notification delivery."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "EVALUATORS": {
          "gcp.compute.os_patch_compliance": {
            "callable": "_load_53.<locals>.<lambda>"
          },
          "gcp.logging.access_transparency_entries": {
            "callable": "_load_53.<locals>._transparency"
          },
          "gcp_c5_backup_remote_location": {
            "callable": "_load_53.<locals>._remote"
          },
          "gcp_c5_iam_change_timeliness": {
            "callable": "_load_53.<locals>._timeliness"
          },
          "gcp_c5_iam_conditions": {
            "callable": "_load_53.<locals>._conditions"
          },
          "gcp_c5_iam_expiry": {
            "callable": "_load_53.<locals>._expiry"
          },
          "gcp_c5_malware_telemetry": {
            "callable": "_load_53.<locals>._malware"
          },
          "gcp_c5_patch_deployment": {
            "callable": "_load_53.<locals>._patch_deployment"
          },
          "gcp_c5_restore_destination": {
            "callable": "_load_53.<locals>._restore_destination"
          },
          "gcp_c5_restore_test": {
            "callable": "_load_53.<locals>._restore_test"
          },
          "gcp_c5_software_inventory": {
            "callable": "_load_53.<locals>._software"
          },
          "gcp_c5_sql_backup_run": {
            "callable": "_load_53.<locals>._backup_run"
          },
          "gcp_cloudsql_backup_failure_alert": {
            "callable": "_load_53.<locals>._backup_alert"
          },
          "gcp_compute_approved_packages": {
            "callable": "_load_53.<locals>._approved_packages"
          },
          "gcp_compute_os_patch_compliance": {
            "callable": "_load_53.<locals>.<lambda>"
          }
        }
      },
      "kind": "project",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_base": {
          "callable": "_load_53.<locals>._base"
        },
        "_ctx": {
          "callable": "_load_53.<locals>._ctx"
        },
        "_rows": {
          "callable": "_load_53.<locals>._rows"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_53.<locals>._backup_alert",
      "source_qualname": "_load_53.<locals>._evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No enabled local alert for failed automated-backup windows was found."
  },
  "gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d": {
    "description_fields": {
      "description": "Checks every cluster in the complete scoped inventory for explicit public IP endpoint enablement."
    },
    "remediation_fields": {
      "caveats": [
        "DNS endpoint exposure, authorized networks and IAM authorization are separate."
      ],
      "cli": [],
      "references": [
        {
          "title": "GKE control-plane network isolation",
          "url": "https://cloud.google.com/kubernetes-engine/docs/how-to/latest/network-isolation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Disable unnecessary public IP control-plane endpoints after preparing an alternative administrator path."
      ],
      "summary": "Disable unnecessary public IP control-plane endpoints after preparing an alternative administrator path."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "complete_items": {
          "callable": "complete_items"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "complete_items": {
          "callable": "complete_items"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_ke.<locals>.gke_public_ip_endpoint_disabled",
      "source_qualname": "_load_ke.<locals>.gke_public_ip_endpoint_disabled"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A cluster explicitly enables its public IP control-plane endpoint."
  },
  "gcp_gke_small_cluster_auto_upgrade": {
    "description_fields": {
      "description": "Joins node-pool instance groups and flags disabled auto-upgrade only below three target nodes."
    },
    "remediation_fields": {
      "caveats": [
        "Target node counts are configuration, not actual healthy capacity; larger clusters pass this scoped profile."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Enable suitable node auto-upgrades in the small cluster with appropriate maintenance controls."
      ],
      "summary": "Enable suitable node auto-upgrades in the small cluster with appropriate maintenance controls."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_gke": {
          "callable": "_load_54.<locals>._gke"
        }
      },
      "kind": "gke_cluster",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_gke": {
          "callable": "_load_54.<locals>._gke"
        }
      },
      "predicate_qualname": "_load_54.<locals>.gke_small_cluster_auto_upgrade",
      "source_qualname": "_load_54.<locals>.gke_small_cluster_auto_upgrade"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster targets fewer than three nodes and a pool disables auto-upgrade."
  },
  "gcp_https_proxy_mtls_required": {
    "description_fields": {
      "description": "Joins the HTTPS proxy to its server TLS policy and requires REJECT_INVALID client validation."
    },
    "remediation_fields": {
      "caveats": [
        "Mutual TLS is a profile requirement; ordinary public HTTPS endpoints may intentionally use other authentication."
      ],
      "cli": [],
      "references": [
        {
          "title": "Load balancer mutual TLS",
          "url": "https://cloud.google.com/load-balancing/docs/mtls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Require valid client certificates only where this endpoint is intended to use mutual TLS."
      ],
      "summary": "Require valid client certificates only where this endpoint is intended to use mutual TLS."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "full_representation": {
          "callable": "full_representation"
        },
        "get": {
          "callable": "get"
        },
        "omitted": {
          "callable": "omitted"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "target_https_proxy",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "full_representation": {
          "callable": "full_representation"
        },
        "get": {
          "callable": "get"
        },
        "omitted": {
          "callable": "omitted"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_09.<locals>.https_proxy_mtls",
      "source_qualname": "_load_09.<locals>.https_proxy_mtls"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The HTTPS proxy lacks a strict client-certificate validation policy."
  },
  "gcp_kms_key_destroy_alert": {
    "description_fields": {
      "description": "Matches the native DestroyCryptoKeyVersion audit event to an enabled, valid positive-count metric alert in the selected project."
    },
    "remediation_fields": {
      "caveats": [
        "This predicate does not require a notification channel or prove delivered alerts."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Configure an enabled positive-count alert for Cloud KMS key-version destruction events."
      ],
      "summary": "Configure an enabled positive-count alert for Cloud KMS key-version destruction events."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_alerts": {
          "callable": "_load_54.<locals>._alerts"
        }
      },
      "kind": "project",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_alerts": {
          "callable": "_load_54.<locals>._alerts"
        }
      },
      "predicate_qualname": "_load_54.<locals>.kms_key_destroy_alert",
      "source_qualname": "_load_54.<locals>.kms_key_destroy_alert"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No qualifying local alert for Cloud KMS key-version destruction was found."
  },
  "gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650": {
    "description_fields": {
      "description": "Joins the key to its versions and checks for DESTROY_SCHEDULED states with valid destruction times."
    },
    "remediation_fields": {
      "caveats": [
        "Scheduled destruction can be intentional; this does not prove dependent data is recoverable."
      ],
      "cli": [],
      "references": [
        {
          "title": "Destroy and restore KMS key versions",
          "url": "https://cloud.google.com/kms/docs/destroy-restore"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm scheduled versions are no longer needed; restore unintended schedules before their deadlines."
      ],
      "summary": "Confirm scheduled versions are no longer needed; restore unintended schedules before their deadlines."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "evaluator": {
          "callable": "_load_08.<locals>._versions"
        }
      },
      "kind": "kms_key",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_08.<locals>._inventory"
        },
        "_rows": {
          "callable": "_load_08.<locals>._rows"
        },
        "datetime": {
          "callable": "datetime"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_08.<locals>._versions",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A key version is scheduled for destruction."
  },
  "gcp_lb_server_header_rewrite": {
    "description_fields": {
      "description": "Checks complete effective routes of public URL maps for a replacing Server header set to lb."
    },
    "remediation_fields": {
      "caveats": [
        "This exact header preference does not establish a vulnerability or test response headers."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary server-identifying headers or apply the profile’s intended replacement."
      ],
      "summary": "Remove unnecessary server-identifying headers or apply the profile’s intended replacement."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_identity": {
          "callable": "_load_52.<locals>._identity"
        },
        "_list": {
          "callable": "_load_52.<locals>._list"
        },
        "_member": {
          "callable": "_load_52.<locals>._member"
        },
        "_server_rewrite": {
          "callable": "_load_52.<locals>._server_rewrite"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "kind": "url_map",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_identity": {
          "callable": "_load_52.<locals>._identity"
        },
        "_list": {
          "callable": "_load_52.<locals>._list"
        },
        "_member": {
          "callable": "_load_52.<locals>._member"
        },
        "_server_rewrite": {
          "callable": "_load_52.<locals>._server_rewrite"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_52.<locals>.lb_server_header_rewrite",
      "source_qualname": "_load_52.<locals>.lb_server_header_rewrite"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A public URL-map route lacks the profile’s Server: lb replacement."
  },
  "gcp_logging_detect_t1110": {
    "description_fields": {
      "description": "Looks for more than nine failed classified authentication events from the same principal and caller IP within five minutes."
    },
    "remediation_fields": {
      "caveats": [
        "A burst is a detection heuristic, not proof of credential compromise; complete classified audit-window evidence is required."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only Cloud Logging entries.list for the project audit log with timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code,protoPayload.requestMetadata.callerIp",
          "Complete inventories: audit_log"
        ],
        "kind": "audit_log",
        "target": "resource"
      },
      "references": [
        {
          "title": "Audit logging",
          "url": "https://cloud.google.com/logging/docs/audit"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Investigate the repeated authentication failures and restrict or recover affected identities if needed."
      ],
      "summary": "Investigate the repeated authentication failures and restrict or recover affected identities if needed."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "audit_log",
      "module": "peaso.checks._bulk_pending_compliance_new_sw50",
      "predicate_bindings": {},
      "predicate_qualname": "_evaluate",
      "source_qualname": "_evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Repeated failed authentication events exceed the five-minute burst threshold."
  },
  "gcp_logging_enumeration_alert": {
    "description_fields": {
      "description": "Checks the exact list/get metric filter, principal extractor and a five-minute threshold alert at ten or fewer events."
    },
    "remediation_fields": {
      "caveats": [
        "Channel references do not prove channel enablement or delivery; high read volume can be legitimate."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Configure an appropriate enumeration alert with principal grouping and a notification channel."
      ],
      "summary": "Configure an appropriate enumeration alert with principal grouping and a notification channel."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_alerts": {
          "callable": "_load_54.<locals>._alerts"
        }
      },
      "kind": "project",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_alerts": {
          "callable": "_load_54.<locals>._alerts"
        }
      },
      "predicate_qualname": "_load_54.<locals>.logging_enumeration_alert",
      "source_qualname": "_load_54.<locals>.logging_enumeration_alert"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No qualifying principal-grouped enumeration alert was found."
  },
  "gcp_pci_asset_6ee2fef37d98": {
    "description_fields": {
      "description": "Checks the Logging bucket retentionDays against the configured threshold, defaulting to 365 days."
    },
    "remediation_fields": {
      "caveats": [
        "The retention setting does not prove event coverage, delivered logs or retained historical volume."
      ],
      "cli": [],
      "references": [
        {
          "title": "Log bucket retention",
          "url": "https://cloud.google.com/logging/docs/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Increase log retention if the default 365-day or selected profile is required."
      ],
      "summary": "Increase log retention if the default 365-day or selected profile is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "evaluator": {
          "callable": "_load_08.<locals>._logging_retention"
        }
      },
      "kind": "logging_bucket",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_08.<locals>._inventory"
        },
        "get": {
          "callable": "get"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_08.<locals>._logging_retention",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Logging bucket retention is shorter than the profile threshold."
  },
  "gcp_pci_backend_service_2ce96d36d0bf": {
    "description_fields": {
      "description": "Follows CDN backend URL maps to HTTPS proxies and checks minimum TLS 1.2 or 1.3."
    },
    "remediation_fields": {
      "caveats": [
        "The joined configuration does not prove a live negotiated TLS version or cover every HTTP frontend."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Raise weak attached SSL policy minimums after checking client compatibility."
      ],
      "summary": "Raise weak attached SSL policy minimums after checking client compatibility."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_backend": {
          "callable": "_load_51.<locals>._backend"
        },
        "_by": {
          "callable": "_load_51.<locals>._by"
        },
        "_rows": {
          "callable": "_load_51.<locals>._rows"
        },
        "_url_backend_refs": {
          "callable": "_load_51.<locals>._url_backend_refs"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "backend_service",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_backend": {
          "callable": "_load_51.<locals>._backend"
        },
        "_by": {
          "callable": "_load_51.<locals>._by"
        },
        "_rows": {
          "callable": "_load_51.<locals>._rows"
        },
        "_url_backend_refs": {
          "callable": "_load_51.<locals>._url_backend_refs"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_51.<locals>.cdn_viewer_tls",
      "source_qualname": "_load_51.<locals>.cdn_viewer_tls"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An HTTPS proxy serving the CDN backend permits TLS below 1.2."
  },
  "gcp_pci_bigquery_dataset_6017267cdf32": {
    "description_fields": {
      "description": "Checks full dataset ACLs for public READER or WRITER role entries."
    },
    "remediation_fields": {
      "caveats": [
        "OWNER and predefined IAM role entries are outside this exact profile; other checks cover broader public grants."
      ],
      "steps": [
        "Remove unnecessary public reader or writer ACLs and preserve intended users."
      ],
      "summary": "Remove unnecessary public reader or writer ACLs and preserve intended users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bigquery_dataset",
      "module": "peaso.checks.compliance_new_gcp",
      "predicate_bindings": {},
      "predicate_qualname": "dataset_no_public_read_write",
      "source_qualname": "dataset_no_public_read_write"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset declares a public READER or WRITER ACL entry."
  },
  "gcp_pci_bigquery_dataset_a4e25dbf9640": {
    "description_fields": {
      "description": "Checks full dataset ACLs for the exact specialGroup=allUsers and role=READER pair."
    },
    "remediation_fields": {
      "caveats": [
        "Other public principal encodings and roles are outside this narrow predicate."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "bigquery_dataset.name",
          "bigquery_dataset._provenance.representation=full",
          "bigquery_dataset.access[].specialGroup",
          "bigquery_dataset.access[].role"
        ],
        "kind": "bigquery_dataset",
        "target": "resource"
      },
      "references": [
        {
          "title": "BigQuery dataset resource",
          "url": "https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove an unnecessary allUsers READER ACL and grant the intended readers instead."
      ],
      "summary": "Remove an unnecessary allUsers READER ACL and grant the intended readers instead."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bigquery_dataset",
      "module": "peaso.checks.compliance_new_gcp_bigquery",
      "predicate_bindings": {},
      "predicate_qualname": "no_anonymous_reader",
      "source_qualname": "no_anonymous_reader"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset declares an allUsers READER special-group ACL."
  },
  "gcp_pci_bigquery_dataset_fb9fcc01d5b7": {
    "description_fields": {
      "description": "Checks full dataset ACLs for any role assigned to allUsers."
    },
    "remediation_fields": {
      "caveats": [
        "This exact principal profile does not cover allAuthenticatedUsers or inherited permissions."
      ],
      "steps": [
        "Remove unnecessary allUsers dataset ACL entries and retain intended readers."
      ],
      "summary": "Remove unnecessary allUsers dataset ACL entries and retain intended readers."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bigquery_dataset",
      "module": "peaso.checks.compliance_new_gcp",
      "predicate_bindings": {},
      "predicate_qualname": "dataset_no_all_users",
      "source_qualname": "dataset_no_all_users"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset ACL assigns a role to allUsers."
  },
  "gcp_pci_bucket_0742bd5dc32c": {
    "description_fields": {
      "description": "Checks versioned buckets for at least one supported lifecycle rule with a nonempty condition."
    },
    "remediation_fields": {
      "caveats": [
        "Unversioned buckets pass this conditional profile; a rule does not prove retention adequacy."
      ],
      "steps": [
        "Add suitable lifecycle rules without deleting required recovery versions or retained records."
      ],
      "summary": "Add suitable lifecycle rules without deleting required recovery versions or retained records."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.compliance_new_gcp",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_versioning_lifecycle",
      "source_qualname": "bucket_versioning_lifecycle"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The versioned bucket has no supported lifecycle rule."
  },
  "gcp_pci_bucket_157fb0c69361": {
    "description_fields": {
      "description": "Checks known local and ancestor public read IAM roles and complete active bucket or object ACL read grants."
    },
    "remediation_fields": {
      "caveats": [
        "Conditional or unknown-role permissions remain unresolved; public access prevention and actual requests are separate."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public read grants and migrate intended readers before changing IAM or ACLs."
      ],
      "summary": "Remove unnecessary public read grants and migrate intended readers before changing IAM or ACLs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_EVALUATORS": {
          "gcp_c5_deletion_recoverability": {
            "callable": "_load_50.<locals>._deletion"
          },
          "gcp_c5_log_retention": {
            "callable": "_load_50.<locals>._log_retention"
          },
          "gcp_gcs_replication_status": {
            "callable": "_load_50.<locals>._replication"
          },
          "gcp_pci_bucket_157fb0c69361": {
            "callable": "_load_50.<locals>._pci"
          }
        }
      },
      "kind": "bucket",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_PUBLIC": {
          "type": "set"
        },
        "_READ_ROLES": {
          "type": "set"
        },
        "_bucket": {
          "callable": "_load_50.<locals>._bucket"
        },
        "_strings": {
          "callable": "_load_50.<locals>._strings"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_50.<locals>._pci",
      "source_qualname": "_load_50.<locals>._evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The bucket declares a known public read grant."
  },
  "gcp_pci_bucket_3d76b0b0701e": {
    "description_fields": {
      "description": "Checks versioned buckets for a positive retention duration."
    },
    "remediation_fields": {
      "caveats": [
        "Unversioned buckets pass this conditional profile; positive retention is not necessarily adequate."
      ],
      "steps": [
        "Set suitable retention if versioned objects must be protected against deletion."
      ],
      "summary": "Set suitable retention if versioned objects must be protected against deletion."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks.compliance_new_gcp",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_versioning_retention",
      "source_qualname": "bucket_versioning_retention"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The versioned bucket has no positive retention duration."
  },
  "gcp_pci_bucket_56c6b1b7f813": {
    "description_fields": {
      "description": "Checks known public write IAM roles, effective-use projections and active ACLs for object-write grants."
    },
    "remediation_fields": {
      "caveats": [
        "Missing effective-use or ACL inventories remain unresolved unless a known write grant proves failure."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Cloud Storage buckets.getIamPolicy (existing), bucketAccessControls.list and objectAccessControls.list (new reads); inspect iamPolicy.bindings, iamConfiguration.uniformBucketLevelAccess.enabled, bucket/object ACL; UNKNOWN on denied, incomplete or malformed reads",
          "Complete inventories: bucket, bucket_acl, object_acl, bucket_effective_iam"
        ],
        "kind": "bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Storage bucket resource",
          "url": "https://cloud.google.com/storage/docs/json_api/v1/buckets"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public write grants while preserving intended upload workflows."
      ],
      "summary": "Remove unnecessary public write grants while preserving intended upload workflows."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "bucket",
      "module": "peaso.checks._bulk_pending_compliance_new_sw51",
      "predicate_bindings": {},
      "predicate_qualname": "bucket_public_write",
      "source_qualname": "bucket_public_write"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The bucket has a known public object-write grant."
  },
  "gcp_pci_cloudbuild_trigger_3302edf7cb18": {
    "description_fields": {
      "description": "Checks enabled inline triggers for logging=NONE, using LEGACY for proven omitted settings."
    },
    "remediation_fields": {
      "caveats": [
        "File-backed build settings remain UNKNOWN; declared logging does not prove execution or delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "cloudbuild_trigger.id or resourceName",
          "cloudbuild_trigger.disabled",
          "cloudbuild_trigger.inlineBuild.logging_field_state and logging",
          "cloudbuild_trigger._provenance.representation=full"
        ],
        "kind": "cloudbuild_trigger",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud Build triggers",
          "url": "https://cloud.google.com/build/docs/triggers"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Select a suitable stored-log mode for the inline build and verify a later build’s logs."
      ],
      "summary": "Select a suitable stored-log mode for the inline build and verify a later build’s logs."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_trigger",
      "module": "peaso.checks.compliance_new_gcp_cloudbuild",
      "predicate_bindings": {},
      "predicate_qualname": "trigger_logging",
      "source_qualname": "trigger_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The enabled inline build trigger declares logging=NONE."
  },
  "gcp_pci_firewall_2080b14f1361": {
    "description_fields": {
      "description": "Checks full active ingress allow rules for Internet-wide sources and any declared allowed protocol."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions."
      ],
      "cli": [],
      "references": [
        {
          "title": "VPC firewall rule declarations",
          "url": "https://cloud.google.com/firewall/docs/firewalls"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Keep public service traffic only where required; restrict unnecessary sources and protocols."
      ],
      "summary": "Keep public service traffic only where required; restrict unnecessary sources and protocols."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_strings": {
          "callable": "_load_09.<locals>._strings"
        },
        "full_representation": {
          "callable": "full_representation"
        },
        "get": {
          "callable": "get"
        },
        "ip_network": {
          "callable": "ip_network"
        },
        "list_of_objects": {
          "callable": "list_of_objects"
        },
        "omitted": {
          "callable": "omitted"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "kind": "firewall",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "Unavailable": {
          "callable": "Unavailable"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_strings": {
          "callable": "_load_09.<locals>._strings"
        },
        "full_representation": {
          "callable": "full_representation"
        },
        "get": {
          "callable": "get"
        },
        "ip_network": {
          "callable": "ip_network"
        },
        "list_of_objects": {
          "callable": "list_of_objects"
        },
        "omitted": {
          "callable": "omitted"
        },
        "re": {
          "type": "module"
        },
        "result": {
          "callable": "result"
        }
      },
      "predicate_qualname": "_load_09.<locals>.public_ingress_firewall",
      "source_qualname": "_load_09.<locals>.public_ingress_firewall"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress."
  },
  "gcp_pci_instance_template_2e26bed500fc": {
    "description_fields": {
      "description": "Checks template network interfaces for nonempty IPv4 accessConfigs declarations."
    },
    "remediation_fields": {
      "caveats": [
        "Configuration declarations do not establish endpoint reachability or effective firewall decisions. Existing VM state and IPv6 access configurations are separate."
      ],
      "steps": [
        "Remove unnecessary external IPv4 configurations in a new template revision and migrate consumers safely."
      ],
      "summary": "Remove unnecessary external IPv4 configurations in a new template revision and migrate consumers safely."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "instance_template",
      "module": "peaso.checks.compliance_new_gcp",
      "predicate_bindings": {},
      "predicate_qualname": "instance_template_no_public_ip",
      "source_qualname": "instance_template_no_public_ip"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The template declares an external IPv4 access configuration."
  },
  "gcp_pci_kms_key_a3927a5f3b84": {
    "description_fields": {
      "description": "Checks complete effective KMS-use projections for public principals or more than three listed principals."
    },
    "remediation_fields": {
      "caveats": [
        "The three-principal limit is a profile threshold; the collected effective-use projection must be complete."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Complete CryptoKey.getIamPolicy plus complete ancestor IAM policies, role permission resolution, group memberships and IAM condition evaluation for effective cryptographic-use principals.",
          "Complete inventories: kms_key, kms_effective_use"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "Cloud KMS key rotation",
          "url": "https://cloud.google.com/kms/docs/key-rotation"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unintended public key use and review whether each listed principal needs cryptographic access."
      ],
      "summary": "Remove unintended public key use and review whether each listed principal needs cryptographic access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "kms_key",
      "module": "peaso.checks._bulk_pending_compliance_new_sw51",
      "predicate_bindings": {},
      "predicate_qualname": "kms_effective_users",
      "source_qualname": "kms_effective_users"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The KMS-use projection lists a public principal or more than three principals."
  },
  "gcp_pci_url_map_9ed56c323a05": {
    "description_fields": {
      "description": "Joins active HTTP frontends to URL maps and checks enumerated default and path redirects for httpsRedirect=true."
    },
    "remediation_fields": {
      "caveats": [
        "This checks route declarations, not live redirects; incomplete route coverage remains UNKNOWN."
      ],
      "cli": [],
      "review_status": "approved",
      "steps": [
        "Redirect HTTP routes to HTTPS where encrypted access is required."
      ],
      "summary": "Redirect HTTP routes to HTTPS where encrypted access is required."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_member": {
          "callable": "_load_52.<locals>._member"
        },
        "_optional_object": {
          "callable": "_load_52.<locals>._optional_object"
        },
        "_optional_objects": {
          "callable": "_load_52.<locals>._optional_objects"
        },
        "_redirect": {
          "callable": "_load_52.<locals>._redirect"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "kind": "url_map",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_member": {
          "callable": "_load_52.<locals>._member"
        },
        "_optional_object": {
          "callable": "_load_52.<locals>._optional_object"
        },
        "_optional_objects": {
          "callable": "_load_52.<locals>._optional_objects"
        },
        "_redirect": {
          "callable": "_load_52.<locals>._redirect"
        },
        "_rows": {
          "callable": "_load_52.<locals>._rows"
        },
        "get": {
          "callable": "get"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_52.<locals>.pci_url_map_redirect",
      "source_qualname": "_load_52.<locals>.pci_url_map_redirect"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An attached HTTP URL-map route does not declare HTTPS redirection."
  },
  "gcp_pubsub_topic_cmek": {
    "description_fields": {
      "description": "Checks the full Pub/Sub topic for a nonempty customer-managed KMS key reference."
    },
    "remediation_fields": {
      "caveats": [
        "Customer-managed key configuration is assessed; Google-managed encryption is not plaintext, and key accessibility is separate."
      ],
      "steps": [
        "Configure a customer-managed key if required and verify service-agent access."
      ],
      "summary": "Configure a customer-managed key if required and verify service-agent access."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {},
      "kind": "pubsub_topic",
      "module": "peaso.checks.compliance_new_gcp",
      "predicate_bindings": {},
      "predicate_qualname": "pubsub_topic_cmek",
      "source_qualname": "pubsub_topic_cmek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The topic has no customer-managed key reference."
  },
  "gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6": {
    "description_fields": {
      "description": "Checks the engine-specific MySQL or PostgreSQL IAM authentication flag for on."
    },
    "remediation_fields": {
      "caveats": [
        "Flag enablement does not prove successful logins or complete user coverage."
      ],
      "cli": [],
      "references": [
        {
          "title": "Cloud SQL IAM authentication flag",
          "url": "https://cloud.google.com/sql/docs/mysql/iam-authentication"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable the supported IAM database authentication flag and configure required database users."
      ],
      "summary": "Enable the supported IAM database authentication flag and configure required database users."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_flags": {
          "callable": "_load_09.<locals>._flags"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_sql_engine": {
          "callable": "_load_09.<locals>._sql_engine"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "kind": "sql_instance",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_flags": {
          "callable": "_load_09.<locals>._flags"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_sql_engine": {
          "callable": "_load_09.<locals>._sql_engine"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_09.<locals>.sql_iam_flag",
      "source_qualname": "_load_09.<locals>.sql_iam_flag"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The instance does not declare its IAM authentication flag on."
  },
  "gcp_sql_trace3625_off": {
    "description_fields": {
      "description": "Checks SQL Server trace flag 3625 and flags on under the legacy off profile."
    },
    "remediation_fields": {
      "caveats": [
        "This legacy preference conflicts with newer guidance; disabling masking can expose error parameters."
      ],
      "cli": [],
      "references": [
        {
          "title": "SQL Server database flags",
          "url": "https://cloud.google.com/sql/docs/sqlserver/flags"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the benchmark version before changing 3625; current security guidance prefers on."
      ],
      "summary": "Confirm the benchmark version before changing 3625; current security guidance prefers on."
    },
    "review_batch": "native-families-1",
    "reviewed_binding": {
      "closure": {
        "_flags": {
          "callable": "_load_09.<locals>._flags"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_sql_engine": {
          "callable": "_load_09.<locals>._sql_engine"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "kind": "sql_instance",
      "module": "peaso.checks.batch_remaining_gcp",
      "predicate_bindings": {
        "_flags": {
          "callable": "_load_09.<locals>._flags"
        },
        "_inventory": {
          "callable": "_load_09.<locals>._inventory"
        },
        "_sql_engine": {
          "callable": "_load_09.<locals>._sql_engine"
        },
        "result": {
          "callable": "result"
        },
        "unknown": {
          "callable": "unknown"
        }
      },
      "predicate_qualname": "_load_09.<locals>.sql_trace3625",
      "source_qualname": "_load_09.<locals>.sql_trace3625"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Trace flag 3625 is on, contrary to this legacy off profile."
  }
}
''')


_CURRENT_BASE_DESCRIPTIONS = frozenset({"gcp.claude.service_account.recently_used",
                                        "gcp.claude.service_account_key.recently_used"})


def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    if kind == "description" and check_id in _CURRENT_BASE_DESCRIPTIONS:
        # The compiled base already carries the later reviewed criteria.
        return deepcopy(original)
    updated = deepcopy(original) if isinstance(original, dict) else {}
    updated.update(deepcopy(row[kind + "_fields"]))
    return updated


def description(check_id, original):
    return _apply(check_id, original, "description")


def remediation(check_id, original):
    return _apply(check_id, original, "remediation")


REVIEWED_RISKS = {cid: (row["reviewed_source_severity"], row["reviewed_severity"]) for cid, row in ROWS.items()}


def severity_review(check_id, source_severity):
    review = REVIEWED_RISKS.get(check_id)
    if review is None:
        return None
    return review[1]


# Exact admitted extension cohort; independently owned copy and native fixtures.
NATIVE_EXTENSION_REVIEWS = json.loads(r'''
{
  "gcp.compute.os_config_fixable_vulnerabilities": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_os_security_update_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_os_security_update_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_os_security_update_review_20261019.py"
  },
  "gcp.review.app_engine_version.literal_environment_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_additional_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "app_engine_version_secret",
      "module": "peaso.checks.gcp_additional_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "appengine",
      "source_qualname": "appengine"
    },
    "source": "peaso/checks/gcp_additional_literal_secret_review_20261019.py"
  },
  "gcp.review.artifact_image.content_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_image_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "artifact_image",
      "module": "peaso.checks.gcp_image_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_image_secret_review_20261019.py"
  },
  "gcp.review.artifactregistry.selected_file_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_artifact_file_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "artifact_selected_file",
      "module": "peaso.checks.gcp_artifact_file_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_artifact_file_secret_review_20261019.py"
  },
  "gcp.review.batch_job.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "batch_job",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py"
  },
  "gcp.review.cloudbuild_build.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_build",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudbuild_build",
      "source_qualname": "cloudbuild_build"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.cloudbuild_trigger.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_trigger",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudbuild_trigger",
      "source_qualname": "cloudbuild_trigger"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.cloudrun_job.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_job",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudrun_job",
      "source_qualname": "cloudrun_job"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.cloudrun_service.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_service",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudrun_service",
      "source_qualname": "cloudrun_service"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.composer.dag_source_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_composer_source_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "composer_dag_source",
      "module": "peaso.checks.gcp_composer_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_composer_source_secret_review_20261019.py"
  },
  "gcp.review.composer_environment.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_notebook_airflow_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "composer_environment",
      "module": "peaso.checks.gcp_notebook_airflow_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_notebook_airflow_secret_review_20261019.py"
  },
  "gcp.review.dataflow_job.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataflow_job",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py"
  },
  "gcp.review.dataform.selected_file_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_dataform_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataform_selected_file",
      "module": "peaso.checks.gcp_dataform_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_dataform_secret_review_20261019.py"
  },
  "gcp.review.dataproc_cluster.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataproc_cluster",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py"
  },
  "gcp.review.dataproc_job.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataproc_job",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py"
  },
  "gcp.review.function.literal_environment_secret_indicators": {
    "fixture_sources": [
      {
        "note": "install() constructs the native-shaped fixture locally",
        "path": "peaso/checks/gcp_function_secret_review_20261019.py"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "function",
      "module": "peaso.checks.gcp_function_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_function_secret_review_20261019.py"
  },
  "gcp.review.function.resolved_source_archive_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_function_source_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "function_source_archive",
      "module": "peaso.checks.gcp_function_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_function_source_secret_review_20261019.py"
  },
  "gcp.review.gke_workload.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_gke_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_workload_literal",
      "module": "peaso.checks.gcp_gke_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_gke_literal_secret_review_20261019.py"
  },
  "gcp.review.instance.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "instance",
      "source_qualname": "instance"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.instance_template.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "instance_template",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "instance_template",
      "source_qualname": "instance_template"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.logging.application_log_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_log_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "log_secret_sample",
      "module": "peaso.checks.gcp_log_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_log_secret_review_20261019.py"
  },
  "gcp.review.project.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "project",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "project",
      "source_qualname": "project"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py"
  },
  "gcp.review.scheduler_job.literal_target_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_additional_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "scheduler_job",
      "module": "peaso.checks.gcp_additional_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "scheduler",
      "source_qualname": "scheduler"
    },
    "source": "peaso/checks/gcp_additional_literal_secret_review_20261019.py"
  },
  "gcp.review.storage.selected_archive_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_selected_archive_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "gcs_selected_archive",
      "module": "peaso.checks.gcp_selected_archive_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_selected_archive_secret_review_20261019.py"
  },
  "gcp.review.storage.selected_object_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_selected_object_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "gcs_selected_object",
      "module": "peaso.checks.gcp_selected_object_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_selected_object_secret_review_20261019.py"
  },
  "gcp.review.workbench.public_ip_disabled": {
    "fixture_sources": [
      {
        "note": "install() constructs the native-shaped fixture locally",
        "path": "peaso/checks/gcp_workbench_review_20261019.py"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "public_ip",
      "source_qualname": "public_ip"
    },
    "source": "peaso/checks/gcp_workbench_review_20261019.py"
  },
  "gcp.review.workbench.root_access_disabled": {
    "fixture_sources": [
      {
        "note": "install() constructs the native-shaped fixture locally",
        "path": "peaso/checks/gcp_workbench_review_20261019.py"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "root_access",
      "source_qualname": "root_access"
    },
    "source": "peaso/checks/gcp_workbench_review_20261019.py"
  },
  "gcp.review.workbench_instance.literal_configuration_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_notebook_airflow_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_notebook_airflow_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_notebook_airflow_secret_review_20261019.py"
  },
  "gcp.review.workflow.deployed_source_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_additional_literal_secret_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workflow_source",
      "module": "peaso.checks.gcp_additional_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "workflow",
      "source_qualname": "workflow"
    },
    "source": "peaso/checks/gcp_additional_literal_secret_review_20261019.py"
  },
  "gcp.review.cloudbuild.stored_log_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_cloudbuild_log_secret_review_20261019_fixtures.json.gz"
      }
    ],
    "source": "peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_log_source",
      "module": "peaso.checks.gcp_cloudbuild_log_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.appengine.deployment_source_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_appengine_source_secret_review_20261019_fixtures.json.gz"
      }
    ],
    "source": "peaso/checks/gcp_appengine_source_secret_review_20261019.py",
    "reviewed_binding": {
      "closure": {},
      "kind": "appengine_deployment_source",
      "module": "peaso.checks.gcp_appengine_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.cloudbuild.artifact_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_cloudbuild_artifact_secret_review_20261019_fixtures.json.gz"
      }
    ],
    "source": "peaso/checks/gcp_cloudbuild_artifact_secret_review_20261019.py",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_artifact_source",
      "module": "peaso.checks.gcp_cloudbuild_artifact_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.clouddeploy.release_source_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_clouddeploy_source_secret_review_20261019_fixtures.json.gz"
      }
    ],
    "source": "peaso/checks/gcp_clouddeploy_source_secret_review_20261019.py",
    "reviewed_binding": {
      "closure": {},
      "kind": "clouddeploy_release_source",
      "module": "peaso.checks.gcp_clouddeploy_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.sourcerepo.selected_file_secret_indicators": {
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_sourcerepo_secret_review_20261019_fixtures.json.gz"
      }
    ],
    "source": "peaso/checks/gcp_sourcerepo_secret_review_20261019.py",
    "reviewed_binding": {
      "closure": {},
      "kind": "source_repository_file",
      "module": "peaso.checks.gcp_sourcerepo_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "source_qualname": "evaluate"
    }
  }
}
''')

# Explicitly reviewed selected-content successors; older entries remain unchanged.
NATIVE_EXTENSION_REVIEWS.update(json.loads(r'''
{
  "gcp.review.cloudtasks.selected_payload_secret_indicators": {
    "source": "peaso/checks/gcp_task_routine_secret_review_20261020.py",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_task_routine_secret_review_20261020_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "kind": "cloudtasks_selected_task",
      "module": "peaso.checks.gcp_task_routine_secret_review_20261020",
      "source_qualname": "task_payload",
      "predicate_qualname": "task_payload",
      "closure": {},
      "predicate_bindings": {}
    }
  },
  "gcp.review.bigquery.selected_routine_secret_indicators": {
    "source": "peaso/checks/gcp_task_routine_secret_review_20261020.py",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_task_routine_secret_review_20261020_fixtures.json.gz"
      }
    ],
    "reviewed_binding": {
      "kind": "bigquery_selected_routine",
      "module": "peaso.checks.gcp_task_routine_secret_review_20261020",
      "source_qualname": "routine_definition",
      "predicate_qualname": "routine_definition",
      "closure": {},
      "predicate_bindings": {}
    }
  }
}
'''))
