"""Source-bound, family-reviewed prose for native GCP configuration findings.

No cloud operations or evaluator changes. Configuration is not runtime proof.
"""
from copy import deepcopy
import hashlib
import json

VERSION = "gcp-remaining-clarity-v1"
ROWS = json.loads(r'''
{
  "gcp.apikeys.active_service_restrictions": {
    "description_base_sha256": "7a62335206acf6ddaa63059b06556101d207d069ce3addb47d361d2cf34b377a",
    "description_fields": {
      "description": "Joins explicit API-key targets to Service Usage and flags targets whose API is disabled."
    },
    "remediation_base_sha256": "af759e9151a34798487c5bb5b1286d2d1212deab37eef1a128c7bbfb995fae97",
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
      "predicate_source_sha256": "24f79b57ec2b59d8e4a61c1ebe49bccbcf84804234dd9620043f8628e3937556",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key declares an API target that is disabled in the project."
  },
  "gcp.appengine.version_https_only": {
    "description_base_sha256": "371d216bea11e6f8e90942776ab219432ba2153011904c56563a378010576647",
    "description_fields": {
      "description": "Checks every full serving App Engine handler for SECURE_ALWAYS."
    },
    "remediation_base_sha256": "bdd99bd4a1fad995ec085858c921cf4d3bdd3e9a685939f3161fac53319db92b",
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
      "predicate_source_sha256": "1425915389925ac6cdac8b255ab512e2ea9b381ec4697351c50ecaee509e9ef8",
      "source_qualname": "_load_09.<locals>.appengine_https_only"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A serving App Engine handler does not declare SECURE_ALWAYS."
  },
  "gcp.claude.backend_bucket.bucket_exists": {
    "description_base_sha256": "ca55b11bbb9e43ba61f549dab499621bed977ceaf5b1157d6fafe4721e080826",
    "description_fields": {
      "description": "Joins the backend bucket name to the complete project bucket inventory."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8520aaa038305afaecabe0974cfd037c56a2f9f51361ebccc6705eb59b9376e2",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The referenced bucket is absent from the project-local inventory."
  },
  "gcp.claude.backend_service.external_iap": {
    "description_base_sha256": "5332c497a73fe02a007c1e06d06e86e60daff9d992fec8bb311e29f59a066674",
    "description_fields": {
      "description": "Checks external backend services for an enabled IAP declaration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "815ebafaa1d0479e3bd67bdef73205233bde38cd883f5aa1d6268f194713a7d7",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The external backend service does not enable IAP."
  },
  "gcp.claude.bigquery_dataset.no_gmail_access": {
    "description_base_sha256": "8ad76b558a02ca54cb16d36e6f10d55265be5aee8b6514cd0d725d9a74c85f32",
    "description_fields": {
      "description": "Checks dataset userByEmail ACL entries for the gmail.com suffix."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "76e3ddcda7cec46c074e11195238405e3dfb9efc38b4e809dae71cc8b21c52c0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A dataset user ACL entry ends in gmail.com."
  },
  "gcp.claude.bigquery_dataset.no_googlegroups_access": {
    "description_base_sha256": "0667ca3ced4650126fbc34a417ae195b25aeda68b410b095317bf549abb075e4",
    "description_fields": {
      "description": "Checks dataset userByEmail ACL entries for the googlegroups.com suffix."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "76e3ddcda7cec46c074e11195238405e3dfb9efc38b4e809dae71cc8b21c52c0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A dataset user ACL entry ends in googlegroups.com."
  },
  "gcp.claude.bucket.log_sink_not_public": {
    "description_base_sha256": "8d2a78fa9520fcdf9833c78bc65fceff0e0062aa32c440dc41b6c5de1f3d2a61",
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks public IAM bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b0aa2dd2c481d00c96cb3b0d20f9692c2ddcc93bd210f2a51d7c7dac7b7035e0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The log destination IAM policy declares a public principal."
  },
  "gcp.claude.bucket.log_sink_retention_locked": {
    "description_base_sha256": "87a3355896e286cf3444751eea5f6f52f7fabf22373b265f70c6db8a53dfcec2",
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks retentionPolicy.isLocked."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b0aa2dd2c481d00c96cb3b0d20f9692c2ddcc93bd210f2a51d7c7dac7b7035e0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log-sink destination bucket has no locked retention policy."
  },
  "gcp.claude.bucket.log_sink_retention_policy": {
    "description_base_sha256": "f225b49cae9948fc0434655852fe9b2b41eff3b9054c8b4db5d9ebc4e185da04",
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks for a retention policy."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b0aa2dd2c481d00c96cb3b0d20f9692c2ddcc93bd210f2a51d7c7dac7b7035e0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log-sink destination bucket has no retention policy."
  },
  "gcp.claude.bucket.log_sink_versioning": {
    "description_base_sha256": "9121ab7767b06fbb9215c4dee185f3eb739434f13c5ee00fc26d983976d8d211",
    "description_fields": {
      "description": "Joins the bucket to same-scope log sinks and checks object versioning."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b0aa2dd2c481d00c96cb3b0d20f9692c2ddcc93bd210f2a51d7c7dac7b7035e0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Object versioning is disabled on the log destination."
  },
  "gcp.claude.bucket.retention_90_days": {
    "description_base_sha256": "768b5e8dbf656fb04e9da2db80c836a8d48835d9687ad37d73f707fc71bec351",
    "description_fields": {
      "description": "Checks bucket retention duration for at least 90 whole days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1932e78b3cc3a5046ba20197482f15032dc16a0875912c921695e2843aac57c0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket has no retention policy of at least 90 days."
  },
  "gcp.claude.dns_zone.dnssec_enabled": {
    "description_base_sha256": "d91aedc9bb9d931a6524f3d457bfd5e5c0030026687c45bd3a9ced658fae8845",
    "description_fields": {
      "description": "Checks public-zone DNSSEC state for exactly on."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63f4c109bee375c02dfb78c0b38ac351224414cde94076c014ad6a92e3b0fc1c",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The public zone does not declare DNSSEC on."
  },
  "gcp.claude.dns_zone.ksk_not_rsasha1": {
    "description_base_sha256": "26e223e4bb65a6c8315d533701a0b01a4905a08786caff9239f929aae8431e3e",
    "description_fields": {
      "description": "Checks enabled or transferring public-zone key-signing specifications for RSASHA1."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c6c6c9a5143858a56a961f8cb46d406ef789925a3d2455922a52789812e4a37b",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key-signing specification uses RSASHA1."
  },
  "gcp.claude.dns_zone.zsk_not_rsasha1": {
    "description_base_sha256": "85aeba3ddffe8c10fa8502a30d41ecbde075807351fb32d3c355bf95cdecce82",
    "description_fields": {
      "description": "Checks enabled or transferring public-zone zone-signing specifications for RSASHA1."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c6c6c9a5143858a56a961f8cb46d406ef789925a3d2455922a52789812e4a37b",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The zone-signing specification uses RSASHA1."
  },
  "gcp.claude.firewall.default_rules_not_open": {
    "description_base_sha256": "a21f9d775ae90455613dadbcc6e2b80e7d2319f98ec7c4ca8cabb19c19b60f75",
    "description_fields": {
      "description": "Checks the four listed default-network rules for Internet-wide source ranges; HTTP and HTTPS names are exceptions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "287c4ac2e5bd1694880de75983c366842d36d03de0d6ba3de1d31fd99669a9f7",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A listed default-network rule declares Internet-wide sources."
  },
  "gcp.claude.firewall.logging_enabled": {
    "description_base_sha256": "665f307341cbb7e9c358b302cceea33c17320dd28671e8d711f351a909a5bba0",
    "description_fields": {
      "description": "Checks the firewall rule logConfig.enable flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6925389ec6ffe5b749053d34602eab9230c4065e559cc9aeea299ee987460e66",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Firewall rule logging is disabled."
  },
  "gcp.claude.firewall.public_ingress_all_protocols": {
    "description_base_sha256": "f70e8b932ba9bf0c6722dfe71ac59a34c0aa7bbcad0d7c9f5f3325531146d290",
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide sources with an all-protocol allow declaration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "eecf82033dc281547b5b48aafa41f886968db18b3e6414ecdce86fa09444d7c3",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress over all protocols."
  },
  "gcp.claude.firewall.public_ingress_common_ports": {
    "description_base_sha256": "7feb915a9e6bea926ebedff48ae73757b793248384c17b76f18700ca46de8b93",
    "description_fields": {
      "description": "Checks active public ingress rules for the listed administrative and database ports over TCP, UDP or SCTP."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "d354eed05a7a77f86ae3fd868e3530c024cc29c6fe793c3f8a03145dec01312a",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress to a listed administrative or database port."
  },
  "gcp.claude.firewall.public_ingress_tcp_udp": {
    "description_base_sha256": "0d89dd50227a495f088f974376320309ae3e51ad86d34e40e997c390c0c87ef4",
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide TCP, UDP or all-protocol allowances."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0e64860815c835d228687771f6df34c8d62e8cca596075825be498486619b0e0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide TCP or UDP ingress."
  },
  "gcp.claude.firewall.public_ingress_without_target": {
    "description_base_sha256": "4c71c685677167e40e659fb0a37aabcfc37826f49704770ec57331ad4229e956",
    "description_fields": {
      "description": "Checks public ingress allow rules for absence of target tags and target service accounts."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b9f79ff26dd6e844a9c403180c77b559fb17d2ff4fb6a0b7d86305015484b899",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The public ingress rule has no target tag or service-account restriction."
  },
  "gcp.claude.gke.binary_authorization": {
    "description_base_sha256": "99bf7141236eede310f5ba1f1f91ed2de3b69cdde44ddead595c43f7b406edb4",
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
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "f815eada5959cc1f11efa51331c262842c883a12e5f17c671064cd79aff1b205",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Binary Authorization is missing, disabled or unspecified."
  },
  "gcp.claude.gke.dashboard_disabled": {
    "description_base_sha256": "80d02c0832fa078acb11047704932b1e8670948584bb94db8ab4af318daf23aa",
    "description_fields": {
      "description": "Checks the legacy Kubernetes Dashboard add-on disabled setting."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "98ace828c19424404804f750286b22e0118e16fff74b92156a96dbfb425ca4cf",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The legacy Dashboard add-on is enabled."
  },
  "gcp.claude.gke.http_load_balancing": {
    "description_base_sha256": "20245a88f30ffbccc665f6b9034883b19fd0d39e4abe22e7a754b224c0add1b6",
    "description_fields": {
      "description": "Checks whether the HTTP load-balancing add-on is explicitly disabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5d3a83e116ff6ed09eae465f0d2d2e6d6bec307bab4286ed8c5731f1fe05e9ea",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The HTTP load-balancing add-on is disabled."
  },
  "gcp.claude.gke.logging_enabled": {
    "description_base_sha256": "e097cef70caa3dbebb510fb8d9e3bf7273cc041a0400d36f5c88546bca9dffb2",
    "description_fields": {
      "description": "Checks loggingService for an empty string or none."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "bf94bae2c72a34c91859051240f008723cc917937a050888a293b5f478fbf2f0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster logging service is empty or none."
  },
  "gcp.claude.gke.master_authorized_networks_restricted": {
    "description_base_sha256": "c74f8db23fb497fde94b5c9053fc3b72bd7d7e3af36a190c3b5b45b29e79cfb0",
    "description_fields": {
      "description": "Checks master authorized networks enablement and rejects exact Internet-wide CIDR entries."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "dfbc2917db37263eacbeb990471040991f85acad1015ffcff170f4f396a17fb6",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Authorized networks are disabled or include an Internet-wide CIDR."
  },
  "gcp.claude.gke.monitoring_enabled": {
    "description_base_sha256": "8718912ffdb5e6c98b04b0e2603d2f10d2d56c7e11f393e9428d00780e21e7c2",
    "description_fields": {
      "description": "Checks monitoringService for an empty string or none."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "bf94bae2c72a34c91859051240f008723cc917937a050888a293b5f478fbf2f0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster monitoring service is empty or none."
  },
  "gcp.claude.gke.network_no_untargeted_public_ingress": {
    "description_base_sha256": "a81c4b83f51880cb0fbb8beeadd0572a636a2018e289f6c0cd5d162b5391668e",
    "description_fields": {
      "description": "Joins the cluster network to active Internet-wide ingress rules without target selectors."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5ee849e8cdc363f63d6a07e94d4616e457def865504d5729c1b1c182719e3655",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster network has an untargeted public ingress rule."
  },
  "gcp.claude.gke.no_client_certificate": {
    "description_base_sha256": "a1ecfe4b03a9012440e0b9c3cf94d5c77546a226503c7b67d42e89b34f0a0d5c",
    "description_fields": {
      "description": "Checks for a legacy client certificate or issueClientCertificate=true declaration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0452da5b16df3aa2728cbf2e6203ff36b46de6b374cf3f8334e9d163fc4a3de6",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster declares legacy client-certificate issuance."
  },
  "gcp.claude.gke.no_default_network": {
    "description_base_sha256": "3e63d5dd5679c3c78518cad49038bc7240ea6dc592b32de33017532fb07fb852",
    "description_fields": {
      "description": "Checks whether the cluster network string equals default."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "61979b1bf6c4991d90ec064284727c92ce96cec356e641fec28ab0de770b7900",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster network is named default."
  },
  "gcp.claude.gke.no_kubernetes_alpha": {
    "description_base_sha256": "bfcbcf16ad957bfca9cba5bd2f18df61acac153bb965a11bb69776f36c9e83a4",
    "description_fields": {
      "description": "Checks the cluster enableKubernetesAlpha flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "d08b19356cf04915894c7b82139544c1e4f35fecf4d4b12290e400b16b8e6769",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Kubernetes alpha features are enabled."
  },
  "gcp.claude.gke.nodes_no_default_service_account": {
    "description_base_sha256": "a8b5916f0860841564f7e1da4704f82f80d7752e0f4515a96334c5df791bfc5f",
    "description_fields": {
      "description": "Checks every node pool, or fallback nodeConfig, for default Compute Engine identity selection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "9697399174b953a8b619519402046f9a2973d4929f513ed665a0f5c00757e341",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A node pool selects the default Compute Engine identity."
  },
  "gcp.claude.gke.private_nodes": {
    "description_base_sha256": "3e893b617d5e7cb0aa168d15756f4d12a167131525f6e037b103e7f29bbfa769",
    "description_fields": {
      "description": "Checks legacy or current cluster defaults for private-node enablement."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c014c930fdf9dfba723cf3ceedd4754e32c8efd81df3ebda2a9017b88962e0ec",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster does not declare private-node enablement."
  },
  "gcp.claude.gke.release_channel": {
    "description_base_sha256": "598a491b59797c2c77a8f806093d5dda10b3ca0ba3810639bad415256d4d9121",
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
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "eae389eefab7b48f4e40e52b244af751ae0e95323bafeb52c4519a89b9aaa325",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster does not select a release channel."
  },
  "gcp.claude.gke.subnetwork_private_google_access": {
    "description_base_sha256": "260e50ecc6a208942154eab61b48f493ad75c08327e29571aebba5e29ed0a0dc",
    "description_fields": {
      "description": "Joins the cluster subnet reference to its Private Google Access declaration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1cd818c85249737980c07feb23775d90f060d1ae6d1491ebf29087039278f977",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Private Google Access is disabled on the cluster subnet."
  },
  "gcp.claude.gke.zone_redundant": {
    "description_base_sha256": "5cdc2d4fbac01185878a448d3f6de9f708b442a0e4c8a4739664cd7ae782b865",
    "description_fields": {
      "description": "Checks zonal clusters for at least three distinct node locations in the same region."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "381dffb5e02585b80341e9d1daf5e008bf67d9e80ac798b04503ea4f52799ee9",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The zonal cluster declares fewer than three node zones."
  },
  "gcp.claude.iam_policy.no_all_users": {
    "description_base_sha256": "2a41b64dd28b3c7b564ded1908ad6c725d5798d47f610cec68c6e87027be546f",
    "description_fields": {
      "description": "Checks project, folder or organization IAM bindings for allUsers."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1a6d3280964fb75009750c85a545081c2eb7b2c1de2efc3066170610150e5c32",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "The root IAM policy declares an allUsers grant."
  },
  "gcp.claude.iam_policy.no_project_sa_user_or_token_creator": {
    "description_base_sha256": "17a32c35e8f3777245bb52a78804acca024d4e80845cb8a507a552804d3e9098",
    "description_fields": {
      "description": "Checks project-root IAM bindings for unconditional Service Account User or Token Creator grants."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "abef06640f662f0802ebe4835c42e3113c2b86885189004fe5795677e26653e0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The project declares an unconditional identity-use or token-creator grant."
  },
  "gcp.claude.image.not_public": {
    "description_base_sha256": "245352ac5d2a462f1fd8afe4113f9cba08272c056c0c1864a10856c359214c1b",
    "description_fields": {
      "description": "Checks custom-image IAM bindings for allUsers or allAuthenticatedUsers principals."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "f6f48e46c62531ee74b2a070a22dd03d9a6d7f46308491bccc454f5180ec63bd",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The custom-image IAM policy declares a public principal."
  },
  "gcp.claude.instance.disks_csek": {
    "description_base_sha256": "04e43470dcbc0efc34a68e3e05993e3c8387aa8d033761800cd6f2c06b8707f5",
    "description_fields": {
      "description": "Checks every attached disk for a customer-supplied encryption-key digest."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5faeb6b114ce9426ea4c41df3e66fa5753965c88b4f9a101b66ee22d2cd27da7",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "An attached disk has no customer-supplied key digest."
  },
  "gcp.claude.instance.not_preemptible": {
    "description_base_sha256": "6f04b8e30370a13d35ef01c4ac28769243c8eb27d664dfd6c18992eba1fa85cb",
    "description_fields": {
      "description": "Checks the VM scheduling.preemptible flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "cce1e3647fab624ab79777fba8ecf45756afda1143701cdf7d63279248549be6",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The VM is preemptible."
  },
  "gcp.claude.instance.not_preemptible_or_spot": {
    "description_base_sha256": "5f72adb9be18bf8243baa50c082af0a44ee561d5d4c5693d5e97429fc78ba50d",
    "description_fields": {
      "description": "Checks whether the VM is preemptible or uses the SPOT provisioning model."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "eb65971b61c5577a31eee9f6de893a21da7c8448aceef45c7f367e23c77f4391",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM is preemptible or uses Spot provisioning."
  },
  "gcp.claude.instance.sa_no_basic_role": {
    "description_base_sha256": "52428f2269c1a5586277e8c6cf5cc4390df131dcd8cd4aaa388f5baf71e7465d",
    "description_fields": {
      "description": "Checks attached VM identities for project-root Owner or Editor declarations, excluding labeled GKE nodes."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has an Owner or Editor role declaration."
  },
  "gcp.claude.instance.sa_no_data_destruction_permission": {
    "description_base_sha256": "1c61f045fbae93b32f604b0f454b3618cbf21d9c82411191000362d1bf0ef7c2",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role data destruction permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching data destruction grant declaration."
  },
  "gcp.claude.instance.sa_no_database_write_permission": {
    "description_base_sha256": "9b71ec952a202845960c60cef62871784e015c8d1e18d4a71aba4f4e44347216",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role database write permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching database write grant declaration."
  },
  "gcp.claude.instance.sa_no_deny_policy_write_permission": {
    "description_base_sha256": "7f4d1107dfe0c1a471ffac9529b2473cf6ebec1fab258d2c29c5eb71282f6c5b",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role deny policy write permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching deny policy write grant declaration."
  },
  "gcp.claude.instance.sa_no_deployments_manager_permission": {
    "description_base_sha256": "12f595098f3259ed727c6cdecdfceb8dbd0aa566f0e8039db404194e8b2d66c4",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role deployments manager permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching deployments manager grant declaration."
  },
  "gcp.claude.instance.sa_no_disrupt_logging_permission": {
    "description_base_sha256": "718debb23bb5d7244c1e7b3ff20eba3e140ceb28202c4fcb1ab7f153d1b43718",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role disrupt logging permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching disrupt logging grant declaration."
  },
  "gcp.claude.instance.sa_no_iam_write_permission": {
    "description_base_sha256": "4e96d93706af77c6f8ce9abc226cfb792168dca922b3ce0162a02f9ac8f07fc7",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role iam write permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching iam write grant declaration."
  },
  "gcp.claude.instance.sa_no_service_account_impersonate_permission": {
    "description_base_sha256": "4996f6eeba6293e11795379626407e4a79414b0f3b18d2863e7dc5d6d573a143",
    "description_fields": {
      "description": "Checks attached VM identities against listed project-root roles and custom-role service account impersonate permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "63222b5d064290af60fec34285a45b2d2bc318b8a1846f247f42cbab2d557934",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached VM identity has a matching service account impersonate grant declaration."
  },
  "gcp.claude.instance.suspended_without_disks": {
    "description_base_sha256": "5182e8b113d6501d997b98161f5c095530cce729332884950a4e2e90904b4fd2",
    "description_fields": {
      "description": "Checks SUSPENDED or SUSPENDING VMs for any attached disks."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "16e3f193dfdf23a5e0f4c2b6527f1e87934b3e66484416a49e762438617285bf",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The suspended VM still has attached disks."
  },
  "gcp.claude.instance_group_manager.autohealing": {
    "description_base_sha256": "a41bc3a54730e457d5272ce7ec6a273f60aa3f1447bfbd1d3301d4d793e3ad2f",
    "description_fields": {
      "description": "Checks managed instance-group policies for a nonempty autohealing health-check reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "d4ff2a946e42bbb91826ce33fd502632b240fb09325009ae252cde9119114abc",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance group has no autohealing health-check reference."
  },
  "gcp.claude.instance_group_manager.load_balancer_attached": {
    "description_base_sha256": "df70d72f8a1f02717aa69e26e8c16e8ac27e57f78ff9966337f47cca4031bec4",
    "description_fields": {
      "description": "Joins the managed instance group to backend-service group references."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "d6b520aa77f8c81369644f5f09fae97a04d21e9b3926c1e9feef5aeed085e893",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "No project-local backend reference is confirmed."
  },
  "gcp.claude.instance_group_manager.multiple_zones": {
    "description_base_sha256": "a2c996fd327ae0387ffd5ce31f75c0ef57319651ad5da5ccde99639f099669af",
    "description_fields": {
      "description": "Checks that a managed instance group declares at least two distinct zones."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "548bf039b849dff39e1ccc49af315cdaaf5d7a012d90cc4ede874c2bb56d0aa4",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The managed instance group declares fewer than two zones."
  },
  "gcp.claude.instance_template.no_ip_forwarding": {
    "description_base_sha256": "6853b9dba6aabaaf18d57f9103d6b74a13f5cd205cada42328b6417f9e4bcfa4",
    "description_fields": {
      "description": "Checks the instance template properties.canIpForward flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a405855af1800dfaa1f21ab2f3565fa1a17dc5cca528027355e0ef5c8d0ae2f7",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance template enables IP forwarding."
  },
  "gcp.claude.kms_key.rotation_100_days": {
    "description_base_sha256": "7dc447cd6ebabdcae8097eeef5fe9fa09bc806a52dbd145b4745eff6a28633d0",
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
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1c84a3c889a0678ce7a4052b255f1845615628b8a18385c4fdeb1799bd61feeb",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The key omits an automatic rotation period or declares more than 100 days."
  },
  "gcp.claude.kms_key.users_limited_to_3": {
    "description_base_sha256": "20e0524a30d28f6eb2c9c2b7476742bacde5389fd29afd859cf7264f5566667b",
    "description_fields": {
      "description": "Checks for public key-policy bindings or more than three members in an individual binding."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6bc54ce9503d0a00ba2d5e987c4322d879b6cd0c2855dd3cb2e7b2bbb19b2a3c",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key policy declares a public principal or a binding with more than three members."
  },
  "gcp.claude.logging.metric_alert_audit_configuration_changes": {
    "description_base_sha256": "6df9417780e9d417ff9df65ee0886e676f21c2bf3b2e34a1f665b6c21ce0b890",
    "description_fields": {
      "description": "Matches the audit configuration changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_bucket_iam_changes": {
    "description_base_sha256": "8b836fd01bb81cfeaa66a783e97e1c99a649987ed76df2bcd4475006f03142be",
    "description_fields": {
      "description": "Matches the bucket iam changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_compute_configuration_changes": {
    "description_base_sha256": "bc2701018610ed2ec29b4ae37c5a8cad8c252f5619928f319890b5b166ce8f70",
    "description_fields": {
      "description": "Matches the compute configuration changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_custom_role_changes": {
    "description_base_sha256": "50f33727e66183886607b268d5e76bcca94218bef20f7c1f0283a684745b2919",
    "description_fields": {
      "description": "Matches the custom role changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_custom_role_changes_with_undelete": {
    "description_base_sha256": "89e02335b82d17eeb1cd9a525f7de5133dbde451a345c17c56bea9f766dde5c5",
    "description_fields": {
      "description": "Matches the custom role changes with undelete filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_firewall_rule_changes": {
    "description_base_sha256": "edd3f82d72355da0a74d2ac52c5fc9d5ee4714cfd8a963c6f94eeb94529857f2",
    "description_fields": {
      "description": "Matches the firewall rule changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_network_changes": {
    "description_base_sha256": "0cc2119ba13f3e8a42e1098fcdcc3c77ff77f6d8be710079b84cb9906ea1574b",
    "description_fields": {
      "description": "Matches the network changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_network_changes_beta_methods": {
    "description_base_sha256": "95c006f7520d850622df53c847562c404bc0627d368cd92c80e97cdd3637cfc7",
    "description_fields": {
      "description": "Matches the network changes beta methods filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_project_ownership_changes": {
    "description_base_sha256": "89df7e32b3119bc88db4f7a92b5d9d4ee0866226077e6dda556170fd8162f71a",
    "description_fields": {
      "description": "Matches the project ownership changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_route_changes": {
    "description_base_sha256": "7013a7e3e46484b7868cb0a945f2268ffc3f494f5d6505b9213ffa29d81861c8",
    "description_fields": {
      "description": "Matches the route changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.metric_alert_sql_instance_configuration_changes": {
    "description_base_sha256": "6434bd470da29eac05a0b5d377678d0b6bcf1c504c526f4e0df76c21ce635218",
    "description_fields": {
      "description": "Matches the sql instance configuration changes filter patterns and joins metrics to enabled same-project alert declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5f517c6613a84c14457bb8ad40df037bf233995633b6a339c63c4ad48d49c169",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled alert declaration was found.",
    "native_semantic_followup": {
      "report": "metric-alert-semantic-followup.json",
      "helper": "peaso/checks/gcp_metric_alert_native.py",
      "helper_sha256": "3573b825861e476ff5627840ea21ee445d17e72ba245e5f52c1d4183d35ac91f",
      "prior_predicate_sha256": "ea46d16ec5ddf934820876455e817bb231546bdbc42145e33de47717dd7b66eb"
    }
  },
  "gcp.claude.logging.project_sink_all_entries": {
    "description_base_sha256": "1dc6a3139b1e47d280de4b95f04bc9ae330e30c8e572ca858b535e6d7440920d",
    "description_fields": {
      "description": "Checks project and source-bound ancestor sink routes for an enabled unfiltered path without active exclusions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "829b28ecd416d2401f8fd5916104735eac99a67e5780a26888c6768184bcc83f",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Complete project and ancestor routes contain no qualifying all-entry sink."
  },
  "gcp.claude.network.dns_logging": {
    "description_base_sha256": "794f1bd58da5f56c36855f5f5d6b3a31caa5ac2b84ab3a9da047fd0cb0c19972",
    "description_fields": {
      "description": "Joins the network to a DNS policy and checks its logging flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b47bb1d25448d6a993052c6eade621193fb9a9485ca749e884b213e7cba34214",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The network has no attached DNS policy with logging enabled."
  },
  "gcp.claude.organization.essential_contacts_any": {
    "description_base_sha256": "8f86cde254c04078012d8f1c25513c919228c2a6e31ea9e74e4de21eaf576f56",
    "description_fields": {
      "description": "Counts Essential Contacts belonging to the observed organization."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "113b460b430d26b2613c9c0f987bdbd1c7210b1be932bcdfb960a7b61de2cb2f",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The organization has no Essential Contact."
  },
  "gcp.claude.project.audit_logs_configured": {
    "description_base_sha256": "be4e14c4f33a07566cfe174da5e781a8f0eb193480751c95100038071fe2a7c7",
    "description_fields": {
      "description": "Checks whether project or source-bound ancestor IAM policies declare any auditConfig service."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "01be901884885db03aa3670950394d8a6292c668d4873680dd064d0b129f8b91",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The complete project and ancestor policies declare no auditConfig service."
  },
  "gcp.claude.project.container_scanning_api_enabled": {
    "description_base_sha256": "848ab54c48204c6f77b1265d993228c5f3bc6e1db6eda372113199b2914e2136",
    "description_fields": {
      "description": "Joins the project to the Container Scanning API state and requires ENABLED."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6c441707b910db4392754b3fe3665f7835cd2c4f97b90133013001dcd643af5c",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Container Scanning API is disabled."
  },
  "gcp.claude.project.gemini_api_disabled": {
    "description_base_sha256": "d85448aa5cb9b2e26ec3ddc9b7e28062471de184586082780cf4d7858982ff0e",
    "description_fields": {
      "description": "Joins the project to the Gemini API state and flags ENABLED."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6c441707b910db4392754b3fe3665f7835cd2c4f97b90133013001dcd643af5c",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The Gemini API is enabled."
  },
  "gcp.claude.project.no_api_keys": {
    "description_base_sha256": "95d82c12151d1c63c8beefec51695b41148db549ebda893bb6ccdfe788143cfb",
    "description_fields": {
      "description": "Checks the complete project API-key inventory for keys without a deleteTime."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ed9d3bd4952616ba5841e15655ef4232d4159e66a5eff1dc05b13cb278ff8f0a",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project contains an API key that is not marked deleted."
  },
  "gcp.claude.project.oslogin_enabled": {
    "description_base_sha256": "ca54c30ba5203465d35fd14ed1ca761688dc6dec69953e3bd0ec0d3e1e516afd",
    "description_fields": {
      "description": "Resolves project OS Login metadata and the effective requireOsLogin policy when metadata is unset."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "45bbe8f475feae6018f828d1667a1256b3312807ccf9f7bcedd8e865032e416d",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Project OS Login is disabled and not required by effective policy."
  },
  "gcp.claude.project.storage_data_access_audit_logs": {
    "description_base_sha256": "b08189dcd66a8663c0971af1543e3caf7e6164c39c0e931add4e22d9c129c4d5",
    "description_fields": {
      "description": "Checks project and collected ancestor audit policies for Cloud Storage DATA_READ and DATA_WRITE categories."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ef77ba9427c78371848d42fab25941493a5e8fde8a54a9ac6cb24b8fd6296eae",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Cloud Storage data-access audit category is missing."
  },
  "gcp.claude.project.storage_vpc_service_controls": {
    "description_base_sha256": "ac18741a8af0bc57f575ef12ed6998004e13e89cd8f20b47d0e5e39b1dc23439",
    "description_fields": {
      "description": "Checks enforced service-perimeter status for the project number and storage.googleapis.com."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "682a5132f02decd88acb2b27896d62875bdbebae11b75e82f861314ea7bff6d7",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No enforced perimeter declares this project and Cloud Storage."
  },
  "gcp.claude.pubsub_snapshot.not_public": {
    "description_base_sha256": "5883a152dad0856f1465a8d49752b210ed324f0d430afbf3a35613dd29bc3499",
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2ecd70d4ac187063528ae63dfbd542cf35e0c8fd0ddc0aa7cc6c2efe9ecb839d",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.pubsub_subscription.not_public": {
    "description_base_sha256": "41d4cce515721aa8b366a7950601c8d4ed47186a26ae439a04a25929ad662b6a",
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2ecd70d4ac187063528ae63dfbd542cf35e0c8fd0ddc0aa7cc6c2efe9ecb839d",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.pubsub_topic.not_public": {
    "description_base_sha256": "2a8c67b8a1034063d5f520009cb7d7c8bbfde43ae77e6bd19d17a3a0a804a21e",
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2ecd70d4ac187063528ae63dfbd542cf35e0c8fd0ddc0aa7cc6c2efe9ecb839d",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.secret.not_public": {
    "description_base_sha256": "d43cb3481007b178334b92a92e3a644ae2d33ada70c8ef4e60d62f5b7ed3634b",
    "description_fields": {
      "description": "Checks the resource IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2ecd70d4ac187063528ae63dfbd542cf35e0c8fd0ddc0aa7cc6c2efe9ecb839d",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "The resource IAM policy declares a public principal."
  },
  "gcp.claude.secret.rotation_90_days": {
    "description_base_sha256": "fae99f955291ad7b9bf6bddbc95fc6f0233364ead38bd46e261a2c72b776677a",
    "description_fields": {
      "description": "Checks the secret’s declared rotation notification period and whether nextRotationTime is overdue."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5b65f3c6112b092af2771298b29eed4d0c5ef66c1a17133cb1ea2f3767028b8a",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The secret has no rotation schedule, exceeds 90 days or is overdue."
  },
  "gcp.claude.service_account.recently_used": {
    "description_base_sha256": "7d91faef464299777558a5c7d3349fdb39c86a51c972da5c817086784dc74cd3",
    "description_fields": {
      "description": "Checks Policy Analyzer’s last authentication observation for an enabled service account against 180 elapsed days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "304dc0b8914b44e35dda5fc732cfc734fd84c8b3bde8b385edf608b50704b67b",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "No service-account authentication was observed recently enough."
  },
  "gcp.claude.service_account_key.age_100_days": {
    "description_base_sha256": "24b722d3d0e44253b41076b45a1a70b31c47384ad036b1b02a437470829dac85",
    "description_fields": {
      "description": "Compares user-managed key creation time with midnight UTC 100 days before collection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1c209cf6b251dc3669726044438fbc872bf27e318fccf76ab5b038f4bc65aea0",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user-managed key predates the 100-day UTC-date cutoff."
  },
  "gcp.claude.service_account_key.recently_used": {
    "description_base_sha256": "b566880d8fe2ddc523ea3ba650f835199ce2e5c6a03f99036f30566ef8d69f5f",
    "description_fields": {
      "description": "Checks user-managed enabled keys’ last authentication observation against 180 elapsed days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "afb33386dbd5e3a1deade74acec5cf58f70c102fe2494f34867a15f905106c8c",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "No key authentication was observed recently enough."
  },
  "gcp.claude.snapshot.not_outdated": {
    "description_base_sha256": "24dca4e952211127208a813f90a79f8fc80960889abcb947daa644e2a48a34b0",
    "description_fields": {
      "description": "Compares snapshot creation time with the captured clock and flags more than 90 whole days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c3efd9a9a759ad5a721ca2dfae09f7bcfb7a8bb8ae21c2b77048a4baf734b40c",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The snapshot is more than 90 elapsed whole days old."
  },
  "gcp.claude.sql_instance.private_ip_only": {
    "description_base_sha256": "247012a577b0b9dcc38dcb8b2e8c9ef286f980b4407452c605190e5674e217f4",
    "description_fields": {
      "description": "Checks for a PRIVATE address and private-network reference without a PRIMARY incoming address."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1a124d025f96bb15a48a49916bd1e25eec8ffbbfa432571fe216d8577a4acad9",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance lacks the required private configuration or declares a PRIMARY incoming address."
  },
  "gcp.claude.sql_instance.second_gen_no_public_ip": {
    "description_base_sha256": "e595b5029263a11f5e6da4f646ae33f84d0b0edd90b6f79b4304302f122dec18",
    "description_fields": {
      "description": "Checks SECOND_GEN Cloud SQL instances for a PRIMARY incoming address assignment."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1fb3c35108fa21a66d7a1ad7bad7a43c62de74549d2b4666415cedde2eb0fa1d",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The SECOND_GEN instance declares a PRIMARY incoming address."
  },
  "gcp.claude.target_proxy.https_custom_ssl_policy": {
    "description_base_sha256": "22dc9fce97391a2b012439259c243b4e61ec351e38a2a906b25153c500388d53",
    "description_fields": {
      "description": "Checks HTTPS proxies for a nonempty SSL policy reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5c52ab69c2562b1d71eedf5a8a3485217d831b8360695945846c99f1f2c831de",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The HTTPS proxy has no explicit SSL policy reference."
  },
  "gcp.claude.target_proxy.https_min_tls_1_2": {
    "description_base_sha256": "4d19e2fe88aeea6efa8118ee1619ff5d8edda109b8114a1c5f47b6d09cef0bf1",
    "description_fields": {
      "description": "Joins HTTPS proxies to SSL policies and checks minimum TLS 1.2 or 1.3."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "46aadfed97ba68a5b85e36059f274b0eeb7bf54a9c222ee3a5db8c94c34d885f",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The HTTPS proxy permits a minimum TLS version below 1.2."
  },
  "gcp.claude.workload_identity_provider.multi_tenant_condition": {
    "description_base_sha256": "82e95c2cc40262158bb98eda28bff101116b8bbae2f548ea5952c78fa5caa9c5",
    "description_fields": {
      "description": "Checks active OIDC providers using listed shared issuers for a nonempty attributeCondition."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "437bb4868912200407005f96fceb72f47bb9d93fd3a847f323818127982424a9",
      "source_qualname": "_register.<locals>.decorator.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The active provider trusts a listed shared issuer without an attribute condition."
  },
  "gcp.claude2.api_key.created_within_90_days": {
    "description_base_sha256": "ec2f85bdaa02f1bad9de3d6e053ed561cd8c4344425c9dd33e7f90c297ff7205",
    "description_fields": {
      "description": "Checks undeleted API keys for more than 90 elapsed whole days since creation."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "9810d259b3575f19eadc16e70e7ae4dec9ec1410fae55a131b09a5fc40e6f573",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key is more than 90 elapsed whole days old."
  },
  "gcp.claude2.bigquery_dataset.default_cmek": {
    "description_base_sha256": "18c699a174db231c5e9b86fbc31f751e6e886a8ef205f2c13983f7c36f6e326c",
    "description_fields": {
      "description": "Checks full dataset details for a nonempty default customer-managed key reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "84d2e0e51a893c5c4dbfaddeea65a2fee1020aa34c11e5fd849ea3f605b453ce",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The dataset has no default customer-managed key reference."
  },
  "gcp.claude2.cloudrun_service.invoker_not_public": {
    "description_base_sha256": "15777197e475fa6974d3bbc0d3af442eacf25443c0bcf3218e4798d77f3447b5",
    "description_fields": {
      "description": "Checks disabled invoker IAM checks or unconditional public invoker-role bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1e4adadc371ca5e8559de7dd90eb001dbc4a68c372b59eee05c4926094bdc645",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service declares public invocation or disables invoker IAM checks."
  },
  "gcp.claude2.function.ingress_not_allow_all": {
    "description_base_sha256": "063580b7f918aa59ac0f05b6da60f064d5f1d9a656f13e1d49ed633c1f986794",
    "description_fields": {
      "description": "Checks non-deleting functions for ALLOW_ALL ingress."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "3c10bd748492337345d1a4fb38496843dd6773319867da4b5b3684c61804261e",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function declares ALLOW_ALL ingress."
  },
  "gcp.claude2.function.not_publicly_accessible": {
    "description_base_sha256": "400abe23a6f81048289773ff3bb62db9bdaad1058ae12fae10cf76eb197f4a4a",
    "description_fields": {
      "description": "Checks function public IAM declarations and, for second-generation functions, backing Cloud Run invoker settings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "fa154408277562e2e6cb9d8395bbbd8d65869d742cdb4228c5dbb09f0d2ad95c",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The function or its backing service declares public access or disabled invoker IAM checks."
  },
  "gcp.claude2.function.vpc_connector_configured": {
    "description_base_sha256": "3cda33c8b5de61aa69114cd8d71be8a0e7418e3d41ac93edd74e79f0e04b3014",
    "description_fields": {
      "description": "Checks non-deleting functions for a connector, referring direct or backing-service VPC access for review."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "bc2f41f47aefa7387ec33f4459a2478fba4998cd9d4bc6da43fc5cfaaf214be6",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No function connector or alternate VPC access declaration was found."
  },
  "gcp.claude2.logging.metric_alert_audit_configuration_changes": {
    "description_base_sha256": "96d5d035619d831eaef27113671fa5aac560c0578447fd6f36f3c93d22f51c15",
    "description_fields": {
      "description": "Evaluates the audit configuration changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_bucket_iam_changes": {
    "description_base_sha256": "2618fbd47bac49bba97fb107407eaf58c358cc0b5bc5507f04df69acd9178b9a",
    "description_fields": {
      "description": "Evaluates the bucket iam changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_custom_role_changes": {
    "description_base_sha256": "fcf939884bf2d42e880e3c1ac8000b4a2810cf6d19b5e8f693cfe309520344f2",
    "description_fields": {
      "description": "Evaluates the custom role changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_custom_role_changes_with_undelete": {
    "description_base_sha256": "2a2df685c16482f21de0b9d6a497376314b22554be501d30d037d49f41ea08e5",
    "description_fields": {
      "description": "Evaluates the custom role changes with undelete filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_firewall_rule_changes": {
    "description_base_sha256": "a243fb053334f711612bd78ceea088084b21ed6a7673dd3de80a02f46cb26764",
    "description_fields": {
      "description": "Evaluates the firewall rule changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_network_changes": {
    "description_base_sha256": "434b886cbbea4c2eed63064a122ee9db9b9863628e74f821cf9ce5af3f15e254",
    "description_fields": {
      "description": "Evaluates the network changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_project_ownership_changes": {
    "description_base_sha256": "505deb812e597cec30fd1771dff5f9200b7a0e6906329b0576e3dcfb3b897cdd",
    "description_fields": {
      "description": "Evaluates the project ownership changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_route_changes": {
    "description_base_sha256": "2646075c6a2d747b57cc142202dea1396791c881805e3d6e9f3b11d6a73282c4",
    "description_fields": {
      "description": "Evaluates the route changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.metric_alert_sql_instance_configuration_changes": {
    "description_base_sha256": "749f8d0293ccbb927caf2fc34dd3fb72970c8dd9cb295b29f12fb31915d022dd",
    "description_fields": {
      "description": "Evaluates the sql instance configuration changes filter against synthetic audit entries, then joins a threshold alert and enabled notification channel."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a7e89437754706c9a7316eea1ff24db2944c0d507ea64c56624cac3e55eae801",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No fully qualifying metric, threshold alert and enabled-channel chain was found."
  },
  "gcp.claude2.logging.sink_all_log_entries": {
    "description_base_sha256": "1da933a0aa38523e26c2631fad63f387ae3698458fc6833c63af76fa4537cd79",
    "description_fields": {
      "description": "Checks local or inherited aggregated sinks for an enabled unfiltered route without active exclusions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "9872bae0f1f8b46367428810e0abe80655b82ee695860abebf2fda47caa89e7e",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No qualifying all-entry sink was found."
  },
  "gcp.claude2.sql_instance.only_private_ip_addresses": {
    "description_base_sha256": "72c5383b79164f4cca629a89dc0cbbcd6d2ce81dedf5947b9b8d55454cb6920a",
    "description_fields": {
      "description": "Checks address types for any declaration other than PRIVATE; external primaries are excluded."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "22777eccae03e6b56a37dc1f7dee9f9af58a81cb2fcbb695400198cee89e4b38",
      "source_qualname": "gcp.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Cloud SQL declares an address type other than PRIVATE."
  },
  "gcp.compute.no_external_ip": {
    "description_base_sha256": "fae7d92900cf055ce977cfb22e0e7d734dedc14cfd4ff4084ac2a04f29816645",
    "description_fields": {
      "description": "Checks all VM interfaces for valid external IPv4 or IPv6 address declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8ad4d0fb7ab3d6e208e0cb0f876121a8dc2d31ba2594495ca7193a62b3e9838c",
      "source_qualname": "gcp_ip"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM declares an external IP address."
  },
  "gcp.compute.restrict_internet_ingress": {
    "description_base_sha256": "5b9ccf774ddb161fab2963fedf2def1608f93564653161a4dcb20bd84396b2ec",
    "description_fields": {
      "description": "Checks active ingress allow rules for Internet-wide source ranges, including documented omitted-source defaults."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2df220a54d172d398f95b3da743c7e8cfaf42c2ceed9a2ae223581fbf32006ac",
      "source_qualname": "gcp_ingress"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress."
  },
  "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only": {
    "description_base_sha256": "dfa52ddaa5a9071a61d3733a8609354eb80bb2f474545be240069104a5aa8a57",
    "description_fields": {
      "description": "Compares active TCP ingress sources with the three listed IPv4 IAP and health-check ranges."
    },
    "remediation_base_sha256": "fca1e7abc489246d1a73910b2abaf086796b0f682cfb4e1db9b5d12669fcdabc",
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
      "predicate_source_sha256": "19262e765527f240be9ee45b01113995ddde4b85af38c3134acc4b4f16496582",
      "source_qualname": "iap_lb_sources_only"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The TCP ingress sources are outside the profile’s IAP and health-check list."
  },
  "gcp.gap.iam_user_managed_sa_no_admin_roles": {
    "description_base_sha256": "7e52133581538ce6dfb4555d93e13af4056443dfd868507f6aeab8699f7044ca",
    "description_fields": {
      "description": "Checks user-managed service-account bindings for Owner, Editor or role-name suffix Admin or admin."
    },
    "remediation_base_sha256": "f8e73327dc7365711dd6e0acd5bac115ce093a0d85742ae740d4512780f22c86",
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
      "predicate_source_sha256": "103e14d28539db12d9606fecaf0b270fd6e2bcb24853665b90fb95c1e71c953e",
      "source_qualname": "user_managed_sa_admin_roles"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service account has an Owner, Editor or admin-named role declaration."
  },
  "gcp.gap.sql_3625_trace_flag_off_cis_v1": {
    "description_base_sha256": "bdd31a21e9f2babdced25927f3ab8207e5512939753c09cea816256aa8d2031f",
    "description_fields": {
      "description": "Checks SQL Server trace flag 3625 for explicit off under legacy CIS GCP v1.2 or v1.3."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "cd3b0c87d755a5279d750b868700df66ef6ca2a3cea3c53608788870d40b24e4",
      "source_qualname": "sql_3625_off_cis_v1"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Trace flag 3625 does not meet the legacy explicit-off profile."
  },
  "gcp.gke.authorized_networks": {
    "description_base_sha256": "dd471924daf60a4e706da414d7daaac795a2f0540b551601ce9fc8bf97aefa21",
    "description_fields": {
      "description": "Checks the declared master-authorized-networks enablement flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "efc64627861587afc051ec0f94575a33e97645e0b9ce4a85e82287f5cb7f6af9",
      "source_qualname": "gke_authorized_networks_native"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Control-plane authorized networks are disabled."
  },
  "gcp.gke.control_plane_restricted": {
    "description_base_sha256": "357de4a2da3f8f7842c1adbe02ca8a88292279008fe820a048c87a4816bf6100",
    "description_fields": {
      "description": "Checks IP control-plane endpoint settings and authorized networks for Internet-wide CIDRs."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "68204066409513d29d4ebf904054055c4db6bbb482622b63ed068cb0c911ed22",
      "source_qualname": "gke_control_plane"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The IP control plane is public without a qualifying source restriction."
  },
  "gcp.gke.network_policy": {
    "description_base_sha256": "3ad34686f4ae1966d7185c5bc458d4478940555dc43a6b8f37233d0cf4f4a6ab",
    "description_fields": {
      "description": "Checks NetworkPolicy enforcement settings, accepting Dataplane V2 and Autopilot."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "f6337cee32f44aa165230f6161061979f9a257af7d7566f4fef2128614550071",
      "source_qualname": "network_policy"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "NetworkPolicy enforcement is explicitly disabled."
  },
  "gcp.gke.no_legacy_abac": {
    "description_base_sha256": "97651c7548d798e15e500cfb0f36ee2b28a35e06a308a530ae5d3eb729100a42",
    "description_fields": {
      "description": "Checks whether the cluster declares legacy ABAC authorization enabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "73063e7bce1db15f232c78d03dd3608a628458138024ef1c420eb29e4dcc9c47",
      "source_qualname": "gke_legacy_abac"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Legacy ABAC authorization is enabled."
  },
  "gcp.gke.node_pools_gke_metadata": {
    "description_base_sha256": "78ce650d876491a44248e2e79e2499a3150c29b2061719fab1b86d20dd205010",
    "description_fields": {
      "description": "Checks every node pool for GKE_METADATA or a decisively unsupported metadata mode."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "95ed9c08a1d5e5a7890671bfec26ad2dd42dc599f9f5cb38ae8224d1c2afc71c",
      "source_qualname": "gke_pools_metadata"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A node pool declares an incompatible workload metadata mode."
  },
  "gcp.gke.private_endpoint": {
    "description_base_sha256": "8997956c74597aaaef34c6bc760e5c61a976ff161403e11ca04d5b9d01836353",
    "description_fields": {
      "description": "Checks current and legacy GKE control-plane public/private endpoint settings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "303923a21ae9d2d1a90cf5f5f8fbcbb300158f6d563d9966138f6e245d458dec",
      "source_qualname": "gke_private_endpoint"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The GKE control plane declares a public endpoint."
  },
  "gcp.gke.private_nodes": {
    "description_base_sha256": "276fc3f86c8d54029c72a85795dd43e9f5ceb6b31dbc8ea373b3fcbabdd6018d",
    "description_fields": {
      "description": "Checks cluster defaults for private nodes in legacy and current network configuration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "f61ffb2e1f0a506727ec4516dcca580a9ae2d927f2b53b593c7ec9cd4f972045",
      "source_qualname": "gke_private_nodes_native"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster does not declare private nodes."
  },
  "gcp.gke.shielded_nodes": {
    "description_base_sha256": "ff4b806143d6e0e20be2abfb71e4dd3118209f5cafce80be94c715b124d83180",
    "description_fields": {
      "description": "Checks whether Shielded GKE Nodes are enabled in cluster metadata."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "aea9803607a0fd1ccd07c062f9fd1551314ce46207bfa48b9d4f490adfbb4bab",
      "source_qualname": "gke_shielded_nodes"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Shielded GKE Nodes are disabled."
  },
  "gcp.gke.workload_identity": {
    "description_base_sha256": "49e37a2736d3c6818e0fd32ba03ea6922ff07fd70bc4248ca0888dced6830baf",
    "description_fields": {
      "description": "Checks for a Workload Identity pool; Autopilot clusters are accepted."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6f182d196b0f65975de4bc83f3f62ca4427147ff3a9c944ca547121c200082b2",
      "source_qualname": "gke_workload_identity"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The cluster has no Workload Identity pool."
  },
  "gcp.htbp.appengine.no_default_service_account": {
    "description_base_sha256": "5aebe22cf6af6f75aef360cdddec1c6ae31190a282acf24415d4e9653238d374",
    "description_fields": {
      "description": "Checks the App Engine application serviceAccount against its default identity."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2d4e27b0f9b3d59086c08a352957449583e6d2ca9e8a5433f4d02fa6c5193c72",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The application selects its default App Engine service account."
  },
  "gcp.htbp.artifactregistry.virtual_repo_private_precedence": {
    "description_base_sha256": "acb978318316c0d632b7bfedcec25cf7288f6b69254bbe54754bd010b054e0e4",
    "description_fields": {
      "description": "Compares the highest remote upstream priority with the highest standard upstream priority."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "68ae4739f8ab7685f1fdb918ea53d21e49b0d896711314664d6ff94c0ba21ccc",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A remote upstream priority meets or exceeds the highest standard upstream priority."
  },
  "gcp.htbp.cloudbuild.pr_trigger_gated": {
    "description_base_sha256": "9f06cfc220fec9f93958fda6dc9114b0e32c44ae970dd4c26499034bec8d948b",
    "description_fields": {
      "description": "Checks enabled pull-request triggers for required comments or approvalRequired=true."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "590074848eaf4b712ab5ae0a8dbee89bc062f2aa9ac2aecc2841fddd40219276",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The pull-request trigger requires neither a comment gate nor build approval."
  },
  "gcp.htbp.cloudbuild.trigger_no_default_sa": {
    "description_base_sha256": "01ab7574f01c8636c612b4cc63df5b68ed96e45cc9fe2bdf82dc790626f5bd76",
    "description_fields": {
      "description": "Checks enabled build triggers for an omitted or default Compute Engine or legacy Cloud Build identity."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "13b5e3f68e47e531b54fd029526b08e38ef6d60e655d7794b0d34f2d4ff01fd1",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The build trigger selects a default build identity."
  },
  "gcp.htbp.cloudrun.job_no_default_compute_sa": {
    "description_base_sha256": "337e9bbe9f8e4fdaf3065245d887d9472a503df691b7d7b36071aa74bf15f2a5",
    "description_fields": {
      "description": "Checks the Cloud Run job template.template.serviceAccount for default Compute Engine identity selection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "cf29e975612558d45f987d56d14790f4deea11f45d4dd9e71fbfea97bd271121",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The workload selects the default Compute Engine service account."
  },
  "gcp.htbp.cloudrun.job_secret_env_from_secret_manager": {
    "description_base_sha256": "e9dddb67eb4216847f11c82656014bfd6fb357f86a38dbdb8f807b376101d496",
    "description_fields": {
      "description": "Checks credential-like environment variable names under template.template without valueFrom references."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b86b6fed301d89a2a144a6d1bcc9f61c2daeba436a07d3bc741e8026519c3808",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A credential-like environment variable has no valueFrom reference."
  },
  "gcp.htbp.cloudrun.service_no_default_compute_sa": {
    "description_base_sha256": "761fdd814736c54c18d4230fa6f13bb9c2c6658f51bb09c5a89a327f099898d8",
    "description_fields": {
      "description": "Checks the Cloud Run service template.serviceAccount for default Compute Engine identity selection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "cf29e975612558d45f987d56d14790f4deea11f45d4dd9e71fbfea97bd271121",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The workload selects the default Compute Engine service account."
  },
  "gcp.htbp.cloudrun.service_secret_env_from_secret_manager": {
    "description_base_sha256": "5c2f2cc4b8cc650d1713f90684ad89f5a373dd9a5300c76e84592dc1bfebc60c",
    "description_fields": {
      "description": "Checks credential-like environment variable names under template without valueFrom references."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b86b6fed301d89a2a144a6d1bcc9f61c2daeba436a07d3bc741e8026519c3808",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A credential-like environment variable has no valueFrom reference."
  },
  "gcp.htbp.composer.no_default_compute_sa": {
    "description_base_sha256": "c30d5df802c5238d199312b80207d67d647e5a61bfa016dac6ed0c87bc7c21e5",
    "description_fields": {
      "description": "Checks Composer nodeConfig.serviceAccount for an omitted or default Compute Engine identity."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ce20a36b89d68c17849cb6e14e690d3c2b1ffe027d08ba7fc7a1b5fe344a5612",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Composer environment selects the default Compute Engine identity."
  },
  "gcp.htbp.function.runtime_no_default_sa": {
    "description_base_sha256": "de309641a8de7554aace63465e7c55e01ef0c42e6b93c5a797d97c0bd70b70bf",
    "description_fields": {
      "description": "Checks function runtime identity for omitted, Compute Engine default or App Engine default accounts."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "989126c9300e0082c7ebe2aceff6859c8ce4544f47daa0d3d22882c51a970ba1",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function selects a default runtime service account."
  },
  "gcp.htbp.function.secret_env_from_secret_manager": {
    "description_base_sha256": "5272bedddd328e29b88839685dbb34584ed27a62a8bfffc524f68ed06cd48a56",
    "description_fields": {
      "description": "Checks collected inline environment variable names for credential-like names."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5daddd121f2e9f631bfd899a77bb675ab059e9ed0d066a3e0eceac16de36f4ed",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An inline function environment variable has a credential-like name."
  },
  "gcp.htbp.gke.kubelet_readonly_port_disabled": {
    "description_base_sha256": "da76f4ef9942828f59f694de0f068dded0803879fce90d2320f17546c2157a3a",
    "description_fields": {
      "description": "Resolves node-pool and cluster-default insecureKubeletReadonlyPortEnabled declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "79518285b5f9c4c2ecec09a0b692d551865334c349446a77fae58b5a88fa7627",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool or cluster default explicitly enables the read-only kubelet port."
  },
  "gcp.htbp.iam.policy_no_pool_wide_workload_principal_set": {
    "description_base_sha256": "7a4bda4bcb0f1ea6e9b6de970e9f3d2b1dd190d35a8dfbb5a3e3cde181e7508a",
    "description_fields": {
      "description": "Checks IAM members for a workload identity pool-wide principalSet wildcard."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "99a51954ff70b47c06322ae829e47f4dc8cd28ccee952e53cd4a59cc89b48b1c",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The IAM policy grants a role to a whole workload identity pool."
  },
  "gcp.htbp.iam.sa_no_pool_wide_workload_principal_set": {
    "description_base_sha256": "764005759524ac1ad903930e1bbec2acee87b235db23d65053913e51107119fe",
    "description_fields": {
      "description": "Checks service-account IAM members for a workload identity pool-wide principalSet wildcard."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "d0671ecc7e4b1df7eeeab74b89db1499f5a62cf8010e2eabe1909d2618949368",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service-account policy grants a role to a whole workload identity pool."
  },
  "gcp.htbp.instance_template.no_default_sa_full_scope": {
    "description_base_sha256": "116aef33607c5821bc89c05fee65d12cc9bb7a989e666d689de7eb1a45a14eca",
    "description_fields": {
      "description": "Checks template service accounts for the Compute Engine default identity with cloud-platform OAuth scope."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "571697bd053a73b432dc974ab111876ef0836233089e1922b1ce3f66e65bc319",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The template attaches the default identity with cloud-platform OAuth scope."
  },
  "gcp.htbp.kms.destroy_window_not_shortened": {
    "description_base_sha256": "a68e440efcaea701dee7d9889d401b3bfeed15c777f3c3f38233355891a1e9a8",
    "description_fields": {
      "description": "Checks the key destruction grace period for at least seven days, applying the full-read omission default."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c14602c90db91892cfecb1562450a9601cd8ed8549020f2daa46e025ffb8586e",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key destruction grace period is shorter than seven days."
  },
  "gcp.htbp.logging.default_sink_not_disabled": {
    "description_base_sha256": "32a82101cd001e807707ddadf7813853b41649c88fa4349a0492e1535a2f58dc",
    "description_fields": {
      "description": "Checks the project _Default sink disabled flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "08be2da750829d3e81fd98355c69138ea982bb98afc7ecde7663ea9930fd353b",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project _Default log sink is disabled."
  },
  "gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled": {
    "description_base_sha256": "9d40b42730b988932ee7e386da33d3dd4ba0ae4d595d11bd9e2bac87494c7974",
    "description_fields": {
      "description": "Checks effective iam.disableCrossProjectServiceAccountUsage for an explicit enforce=true rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c784f5a9095ce2506f19c4cce248c446d7b796655fb828f808c0332a654615fe",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The effective policy explicitly permits cross-project service-account attachment."
  },
  "gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled": {
    "description_base_sha256": "a282561e4f6356668fc4c10439c5e23c8664ae0873244897483c7164ce2d28b2",
    "description_fields": {
      "description": "Checks the effective managed or legacy constraint blocking privileged default-service-account grants."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "88dd13b4872b9ec6405a4e2306e4cdf7663ece5533340574205d1392fc0d1091",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The effective default-account automatic-grant guardrail is not enforced."
  },
  "gcp.htbp.orgpolicy.domain_restricted_sharing": {
    "description_base_sha256": "3c5c7aa11ea3261830cc0a2551c6f7e6c921c9e99966d7d5509642ea9fc7c172",
    "description_fields": {
      "description": "Checks effective managed enforcement or legacy allowed-domain restriction presence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "782afbac082ddaaa184d90aaa2abb4c9e230054916aba7c68a3ccb9dd3891713",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The effective domain-restricted-sharing guardrail is not enforced."
  },
  "gcp.htbp.orgpolicy.essential_contacts_domain_restricted": {
    "description_base_sha256": "59d135c2eb8fe23958e4ba4da099cc5ad9f4af657ce1e2880434410f9c86bfca",
    "description_fields": {
      "description": "Checks effective managed enforcement or legacy contact-domain restriction presence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0b887239caba50c62e6a702ec3636654f103df8903b26be54794a396dadb1a83",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "The effective contact-domain restriction is not enforced."
  },
  "gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked": {
    "description_base_sha256": "aa7102f680cc0d39815e027d2f172e779997cde9d4582334180a7517f42d4753",
    "description_fields": {
      "description": "Checks effective managed or legacy constraints for blocking both service-account key creation and upload."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "32f6fada7610413273efb39d3cf10cbca1213e75d4d7862425932aefec89de9c",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Key creation or upload is not blocked by the applicable effective constraint."
  },
  "gcp.htbp.pubsub.push_endpoint_not_tunnel": {
    "description_base_sha256": "5819caee2bc0afa4da41fa0983fd1f4398361a43ae313853ab11bf53e9bd65a6",
    "description_fields": {
      "description": "Checks the push endpoint host for an IP literal or a listed tunnel or request-capture service."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8b4f94081946c3d981e2791388834367541034cb8ebcf5f90bbb3e92bd800776",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The push endpoint uses an IP literal or listed tunnel or request-capture host."
  },
  "gcp.htbp.scheduler.no_recurring_access_regrant": {
    "description_base_sha256": "ad35d8a918f0b1fab9cae1bc3a48bce6e3f87c5fca42cb648e3219df01473768",
    "description_fields": {
      "description": "Matches enabled OAuth HTTP jobs against listed Google API write paths for access-granting configuration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1344ba081c1d26f25cedd347a23791f68498ed0f55d34ae10129455df79dd8ba",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The scheduled OAuth job declares a listed access-changing API write pattern."
  },
  "gcp.htbp.storage.default_object_acl_not_public": {
    "description_base_sha256": "5c70b8a9efb592436e4a487398ebcd5a493fe81eaaea1179a380e82d5a89e249",
    "description_fields": {
      "description": "Checks default object ACL public entities when uniform bucket-level access is disabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8f7e45d77f225ba7951a9770845cba47378991ae8f9f1fef451f1b5461e5df5",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The default object ACL declares a public principal."
  },
  "gcp.htbp.storage.hmac_key_not_stale_or_default_sa": {
    "description_base_sha256": "482b2c54931001e7c71180be9d88bd4ee27f96dffa2a31fbc9bcc4fa446fd8b7",
    "description_fields": {
      "description": "Checks active HMAC key age against 90 elapsed days and its identity for default service accounts."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "fd07f820d28dad6cdad7576b6cb5f71f72ea625b159b253a39fb1f15a22f80f7",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active HMAC key is older than 90 days or uses a default service account."
  },
  "gcp.htbp.storage.notification_topic_in_bucket_project": {
    "description_base_sha256": "99b09b8ae9eb977e80a3744e7f93a0b023dfcec59c17d03d4c82c49f40cb981a",
    "description_fields": {
      "description": "Compares the notification topic project ID with the bucket project ID."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "e77022266e65cbe57bcab09242d8a27fb0fcb0dfabe1646fc7b090fe99b14b8c",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket notification targets a topic in a different project."
  },
  "gcp.htbp.workbench.no_default_compute_sa": {
    "description_base_sha256": "4df6643f26c6a03dc10c3cfbb703c898fadeedd66d17ba586ed0578e7fb5b4f7",
    "description_fields": {
      "description": "Checks Workbench gceSetup service accounts for omission or a default Compute Engine identity."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "af7e3aef32d95aee14b756fafd34e504ec46b7b466f32ad6e88af0481ad0d2d3",
      "source_qualname": "ht_register.<locals>.apply.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Workbench selects the default Compute Engine identity."
  },
  "gcp.iam.avoid_basic_roles": {
    "description_base_sha256": "5d57d8c2f16257322ffc109d0f16a0db75e94e50de84c64d9031bf1b52177cfd",
    "description_fields": {
      "description": "Checks project IAM bindings for Owner or Editor roles, retaining their conditions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "009b45e82a1ceb49864c59a15afdd9b1720dd8e96006767ef0fdda5e41beb89c",
      "source_qualname": "gcp_basic"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The project IAM policy declares an Owner or Editor grant."
  },
  "gcp.iam.data_access_audit": {
    "description_base_sha256": "26d932c3687d9aa9eaef1c058450e7e2019b299abdbc1a5b07d55d04337ad5c0",
    "description_fields": {
      "description": "Checks complete inherited allServices audit configuration for DATA_READ and DATA_WRITE categories."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7ffca99a290fbc31f1ae6719949c8679fe879be736f02f65ed1325fd4cb2740e",
      "source_qualname": "audit"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An all-service data-access audit category is missing."
  },
  "gcp.iam.no_user_managed_sa_keys": {
    "description_base_sha256": "2761ac9152afa40c5cba60ecb5d2da0da81d58004f8712b454c894818b7c5b0e",
    "description_fields": {
      "description": "Checks service-account keyType for USER_MANAGED rather than SYSTEM_MANAGED."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "729fd5ac7399adbd8df40b56f9dcbaa21d0737e087c673cf4785f8d70eb443d3",
      "source_qualname": "sa_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The service-account key is user-managed."
  },
  "gcp.iam.restrict_public_members": {
    "description_base_sha256": "e499952ce0bb810cdc2135fb6d2b3c5f8aa4ea49c0c2866250e5bb8e74a88ca0",
    "description_fields": {
      "description": "Checks project IAM bindings for unconditional allUsers or allAuthenticatedUsers grants."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5c3c244239ffd6d6c2f631f8ffdbe3eea75718cbf0ed4a21059af9e4222ac0a4",
      "source_qualname": "gcp_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The project IAM policy declares an unconditional public-principal grant."
  },
  "gcp.identity.non_service_account_mfa": {
    "description_base_sha256": "b94a510dac878285adfcb3bbd031cc3698fe069f9bc7bad8e8c053b308445128",
    "description_fields": {
      "description": "Checks native two-step verification enrollment and enforcement for active, customer-bound Directory users directly declared in Cloud IAM."
    },
    "remediation_base_sha256": "d4f98eac9f7140894902c2d51572f6ff835e39074459f6ea8f03991855d8a6b2",
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
      "predicate_source_sha256": "50cbbdc399eee40571270f10471855db37bfa5127b30028faefaa73f4c635b99",
      "source_qualname": "_load_52.<locals>.non_service_account_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The directly observed IAM user lacks two-step verification enrollment or enforcement."
  },
  "gcp.identity.super_admin_recovery_group": {
    "description_base_sha256": "86ca35dcdee791efa621202797f5bf5a048b9aebd43af08dfd23ec15c44b93c9",
    "description_fields": {
      "description": "Joins assigned super administrators to same-customer recovery groups and counts distinct direct members matched to active Directory users."
    },
    "remediation_base_sha256": "72b491b2adcfc2713386b94bee0212ceb444df2baff2d66a0998f68e39f6df9f",
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
      "predicate_source_sha256": "bb844feb23d638990eb1739079019b9fc6375e3dba700e40baf1654c1f5a6415",
      "source_qualname": "_load_52.<locals>.super_admin_recovery_group"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The super-admin recovery address is not a group with at least two active members."
  },
  "gcp.identity.super_admin_separation": {
    "description_base_sha256": "3396adef0e121d54d4fc54c3ba8e4ef5a089b2041846a9de26e93c9ba27f73c1",
    "description_fields": {
      "description": "Joins source-bound Directory super-admin assignments and project-to-organization IAM roots for direct broad-role conflicts."
    },
    "remediation_base_sha256": "3b01c9557bd996e312372a44c77aad29bdc920c608200c68eb452358ac6e79fc",
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
      "predicate_source_sha256": "6590e9d85402c8570aa71e387810acc37110aa40443a3bca7403252316bf00b0",
      "source_qualname": "_load_52.<locals>.super_admin_separation"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Workspace super-admin has a direct broad Cloud IAM role declaration."
  },
  "gcp.logging.access_transparency_entries": {
    "description_base_sha256": "354f461e26b579818b973c3d43b0a254fc80ed95d056fc45ab29d85314773383",
    "description_fields": {
      "description": "Counts project-bound Access Transparency entries within 30 days of collection."
    },
    "remediation_base_sha256": "90d0d5888ff7a6912df51cd174e2120bd1ba2c0b512c6a3c482d6e2dbb17a931",
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
      "predicate_source_sha256": "b62be326e2a9d657fd1e477adc948aabb788cae610a6df163746ae3e43e2f3d2",
      "source_qualname": "_load_53.<locals>._evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No recent Access Transparency entry is confirmed."
  },
  "gcp.ports.access_approval_explicit_enrollment": {
    "description_base_sha256": "a0d583942710d53fc64e04841d00532ce160bc8a35e4ef9d07876f4cc3d30496",
    "description_fields": {
      "description": "Checks Access Approval settings for an explicitly BLOCK_ALL-enrolled product."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0701c8d99f12dd5fbd27bbc75994e6acabe48eea1ec1fe7c7aaa366b82802c91",
      "source_qualname": "approval"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No product is explicitly enrolled with BLOCK_ALL."
  },
  "gcp.ports.alloydb_cluster_encrypted_with_cmk": {
    "description_base_sha256": "d6fc0ea204fbbd41adc936d2777e578326a1f470f3eb685737e8e2ec19bd55fe",
    "description_fields": {
      "description": "Checks whether AlloyDB declares customer-managed rather than Google-default encryption."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8466912e72ca0b0e0636c75698a23c4d048dee889172e788d138a1a1ae4b4a60",
      "source_qualname": "alloy_encryption"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB cluster declares Google-managed encryption."
  },
  "gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter": {
    "description_base_sha256": "8a00fea683712770398823c47ce32a8a38af8f2b2ae78264a9b54e11ff539f1e",
    "description_fields": {
      "description": "Checks the AlloyDB log_error_verbosity declaration for default or verbose."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "010e2fffc7de1eee5d8df228479f73dd71563b6fe370f717a50ab8f2c61e9672",
      "source_qualname": "alloy_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB log_error_verbosity flag is absent or outside the accepted values."
  },
  "gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured": {
    "description_base_sha256": "faae706a6aa19905b2360cff8bf357e5eaf3119d8bac43d465d0a32f4dcb4b75",
    "description_fields": {
      "description": "Checks the AlloyDB log_min_error_statement declaration for an explicit value."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "010e2fffc7de1eee5d8df228479f73dd71563b6fe370f717a50ab8f2c61e9672",
      "source_qualname": "alloy_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB log_min_error_statement flag is absent or outside the accepted values."
  },
  "gcp.ports.alloydb_instance_log_min_messages_database_flag_error": {
    "description_base_sha256": "bf9ec97e414015028f5667fc2e1d4adac968491b13e64770627aadb64c03c460",
    "description_fields": {
      "description": "Checks the AlloyDB log_min_messages declaration for error or warning."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "010e2fffc7de1eee5d8df228479f73dd71563b6fe370f717a50ab8f2c61e9672",
      "source_qualname": "alloy_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AlloyDB log_min_messages flag is absent or outside the accepted values."
  },
  "gcp.ports.api_key_elapsed_age_gt90": {
    "description_base_sha256": "ff6f3126ff6bca1e68fff053d49d9c8ecc2ecdc0698b5a7dff7952dc5edd7d13",
    "description_fields": {
      "description": "Compares API-key creation time with the captured clock and flags more than 90 elapsed whole days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "548f2012f60a2c4c09a4fb6426abeb9cfd881518183de981f4e58b9c23e6efcc",
      "source_qualname": "elapsed_age"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key is more than 90 elapsed whole days old."
  },
  "gcp.ports.api_key_meaningful_restrictions": {
    "description_base_sha256": "df57963fcbcb7b65a954e611de731af5434514edc177175c8fd8e2d46831c445",
    "description_fields": {
      "description": "Checks for a specific API target or a narrow caller-restriction declaration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "fd181cad306f39e2598dbcfb9173f3c41c20097b0ab8185f0b00db760b7cd91c",
      "source_qualname": "meaningful_restrictions"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key has neither a specific API target nor a narrow caller restriction."
  },
  "gcp.ports.apikeys_api_restricted_with_gemini_api": {
    "description_base_sha256": "9d558c2a1f67d0c7bad963a5603e6d637a074e34b57b26366e06c1275b7218b4",
    "description_fields": {
      "description": "Checks API-key target restrictions when the project’s Gemini API is enabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a85be7375c0c511c8f2fe6196506f71b5faba5a530545c7625d14f1153117c46",
      "source_qualname": "gemini"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The enabled-Gemini project key has unrestricted or mixed Gemini API targets."
  },
  "gcp.ports.app_engine_application_iap_enabled": {
    "description_base_sha256": "9338ff64c42a17b7057891334bddb90ba1f2a673177208266cf9ebd65c979ea1",
    "description_fields": {
      "description": "Checks the identified App Engine application’s IAP enabled setting."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1cce3f84963cb4a157ea5d4007b013dccd51445a20c334a7e8d6bb74fa9948b3",
      "source_qualname": "app_engine_iap"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "IAP is disabled for the application."
  },
  "gcp.ports.artifacts_container_analysis_enabled": {
    "description_base_sha256": "f6eb56be38543f618ea3662cbdd45c1103dff353672ade260105cd5b6c193485",
    "description_fields": {
      "description": "Joins the project to its Container Analysis API service state and requires ENABLED."
    },
    "remediation_base_sha256": "4c9431766494e6cf85a3bda9ff1e605eb1abf380c1ac4897094978c83de84946",
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
      "predicate_source_sha256": "033a3a8377f6a119712d0821c8842bdc92196a21ab21566489bbe1bddeef2d8e",
      "source_qualname": "service.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Container Analysis API is disabled."
  },
  "gcp.ports.audit_logging_configured_for_all_service": {
    "description_base_sha256": "69b9670279a594e9e02aad892c8d64be183158f3eae5c6e1953142892ad0b782",
    "description_fields": {
      "description": "Checks all-service ADMIN_READ, DATA_READ and DATA_WRITE configuration and flags exemptions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "4c7b6e00de793d4fbad88ac759cdeec39063a94a587318d9cc569be7e437f465",
      "source_qualname": "audit_scope"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "All-service audit categories are missing or include exemptions."
  },
  "gcp.ports.bigquery_dataset_not_publicly_accessible": {
    "description_base_sha256": "ee9f8f7a6e83017d77f3c96b192fdd7674bb1751307fa950a493c37f87488f04",
    "description_fields": {
      "description": "Checks dataset ACLs for allAuthenticatedUsers specialGroup or allUsers iamMember entries."
    },
    "remediation_base_sha256": "e923d4279edf8f4a7d1b827caf8707e2d3f2292cc4265eab6f90b2ad54cfac14",
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
      "predicate_source_sha256": "93b87289349aed55d4647ae8e20af201437c677482e42ec13d60a3203e793225",
      "source_qualname": "dataset_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset ACL contains a public-group or public-IAM entry."
  },
  "gcp.ports.bigquery_table_encrypted_with_cmk": {
    "description_base_sha256": "36d182485dbb3f9ef2dd06eb9b4159bd4800afa78ec2b17885d1f1723682ef0a",
    "description_fields": {
      "description": "Checks stored BigQuery tables for a nonempty customer-managed key reference; logical views are excluded."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "76d84d41629343f34da3509a2748bb708e53991d7499407f8597557acc5ebcf2",
      "source_qualname": "encryption.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The table has an empty customer-managed key reference."
  },
  "gcp.ports.cloud_run_not_publicly_accessible": {
    "description_base_sha256": "f8915d0f0b61e2ac7fa995fd219d572750790a5d39d62f0b7fe52c66e674d866",
    "description_fields": {
      "description": "Checks Cloud Run’s ingress boundary for INGRESS_TRAFFIC_ALL."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2f6af1137097588fad47e2a33b0b7f29bce0a169399b4d88adc88afc4341297f",
      "source_qualname": "run_ingress"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud Run declares unrestricted ingress."
  },
  "gcp.ports.cloud_run_service_policy_prohibit_public_access": {
    "description_base_sha256": "e330cf9b1bff232e851db3c69f2dae90d41382c91a6d72318eb8ad81c1e54c3d",
    "description_fields": {
      "description": "Checks Cloud Run IAM bindings for any role assigned to allUsers or allAuthenticatedUsers."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "329856d982367e45e9041e6fccdd37c08bf77111bc49195572818d43b3b97783",
      "source_qualname": "cloudrun_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cloud Run IAM policy declares a public principal."
  },
  "gcp.ports.cloudfunction_function_no_ingress_settings_allow_all": {
    "description_base_sha256": "12c1adaa534a7925612f8b369adbd9c544114b1535f4314e56df338cd0346677",
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
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "3be2d647ee93d212e571a7dd2d0831402b0f0d3c2ffe9dcb9ea5d39a438f47be",
      "source_qualname": "function_setting.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function declares ALLOW_ALL ingress."
  },
  "gcp.ports.cloudfunction_function_restrict_public_access": {
    "description_base_sha256": "2491c0b78464406e2ffc7b186b57acd358286e5166e92fbceb50bb28b2d2365d",
    "description_fields": {
      "description": "Checks function IAM bindings for public principals."
    },
    "remediation_base_sha256": "f08ac0ad6422a866484857ae947a7908145acc9caa3d01e71f05e6c8ac6c8ab3",
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
      "predicate_source_sha256": "b7998a5a361a0abf13c7fe48481074887c9da30039b32b9a9073862651ac9986",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function IAM policy declares a public principal."
  },
  "gcp.ports.cloudfunction_function_vpc_connector_enabled": {
    "description_base_sha256": "b646203f8525b85f0aab45b4fc61a8fae57ace1cd724c74fe3aba623686bb580",
    "description_fields": {
      "description": "Checks for a nonempty function VPC connector reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "3be2d647ee93d212e571a7dd2d0831402b0f0d3c2ffe9dcb9ea5d39a438f47be",
      "source_qualname": "function_setting.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function has no VPC connector reference."
  },
  "gcp.ports.cloudrun_service_restrict_public_access": {
    "description_base_sha256": "734f028b3353b37de3188acfdde035988d6ff6f64cc447d6e9f5ee5368278ed2",
    "description_fields": {
      "description": "Checks Cloud Run run.invoker bindings for public principals."
    },
    "remediation_base_sha256": "b978910f44e3097cde1166469f1b58954c75a32dcc975775028adc551dc49e1c",
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
      "predicate_source_sha256": "b7998a5a361a0abf13c7fe48481074887c9da30039b32b9a9073862651ac9986",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The service declares a public run.invoker binding."
  },
  "gcp.ports.compute_disk_encrypted_with_csk": {
    "description_base_sha256": "6c7cd240a9704ef9c562c71b7c3f5d8c8897f026337a2ed2ce99bda983ac3752",
    "description_fields": {
      "description": "Checks for a customer-supplied encryption-key digest in disk metadata."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "90f634fd5b416f7c744bd30c088ec842031b6472c6df62941c3dea591cbca821",
      "source_qualname": "csek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The disk has no customer-supplied key digest."
  },
  "gcp.ports.compute_firewall_rule_rdp_access_restricted": {
    "description_base_sha256": "f2c2561157050cb3c6637411ccf5c9bd0c1e8e447a5ac686dfe34f9bda0c6b12",
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide TCP 3389 allowance."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c6c04faabf126c1d1ee736fa53dac9e6c43b53b245cbc12b962c7d1d76b5aac9",
      "source_qualname": "firewall_port.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The firewall rule declares Internet-wide TCP 3389 ingress."
  },
  "gcp.ports.compute_firewall_rule_ssh_access_restricted": {
    "description_base_sha256": "a93db953cd2ed8db89211eeaa834f74b81c4f6a49d80421d61ab0bdec1e09481",
    "description_fields": {
      "description": "Checks active ingress rules for Internet-wide TCP 22 allowance."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c6c04faabf126c1d1ee736fa53dac9e6c43b53b245cbc12b962c7d1d76b5aac9",
      "source_qualname": "firewall_port.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The firewall rule declares Internet-wide TCP 22 ingress."
  },
  "gcp.ports.compute_instance_block_project_wide_ssh_enabled": {
    "description_base_sha256": "54e8653d2510fd9e85a5845191e42ce5f926e8d28a1dab5ec7a09d24b9727d5b",
    "description_fields": {
      "description": "Checks explicit project-SSH-key blocking outside the labeled GKE-node scope."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c6b9d9fbc3fe818a21cfe49cf85fe70f56e6a38edaa4f5f933cd802d91d1ce81",
      "source_qualname": "block_project_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM explicitly allows project-wide SSH keys."
  },
  "gcp.ports.compute_instance_ip_forwarding_disabled": {
    "description_base_sha256": "4b6c31cfa4b68e888578800484e038af6602262299615f6a49c6e44205c31fdf",
    "description_fields": {
      "description": "Checks canIpForward outside the explicitly labeled GKE-node scope."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8f08b37cb508a68ef6cbf3fa3aadf34e29d968a53c8034e94a118790f51e9910",
      "source_qualname": "no_forward"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM allows IP forwarding."
  },
  "gcp.ports.compute_instance_shielded_vm_enabled": {
    "description_base_sha256": "f7043a04f2f1c1ab3fb05bfc04934fa5521cc150296f9494968a8f3351dafdb9",
    "description_fields": {
      "description": "Checks that both vTPM and integrity monitoring are explicitly enabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "03756db024518c133a1ec20f01b7820bae005d848fea7c6547d203c87958e49f",
      "source_qualname": "shielding"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM disables vTPM or integrity monitoring."
  },
  "gcp.ports.compute_instance_with_no_default_service_account": {
    "description_base_sha256": "13e0799976d38b23a9245e19f96953b28121e976addedb74b23b6222e933e4db",
    "description_fields": {
      "description": "Checks non-GKE-scoped VMs for an attached default Compute Engine service account."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ab2404239e7507b434d170e355d15eb9b33a6f1ccabd7611b4aee167e2745f94",
      "source_qualname": "account_rule.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM attaches the default Compute Engine service account."
  },
  "gcp.ports.compute_instance_with_no_default_service_account_with_full_access": {
    "description_base_sha256": "d168d1837eba52a86844b74f200ebb0cba6608c68059176f99b3b9f666402ea5",
    "description_fields": {
      "description": "Checks non-GKE-scoped VMs for the default service account with cloud-platform OAuth scope."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ab2404239e7507b434d170e355d15eb9b33a6f1ccabd7611b4aee167e2745f94",
      "source_qualname": "account_rule.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The default service account has the cloud-platform OAuth scope."
  },
  "gcp.ports.compute_instance_with_no_public_ip_addresses": {
    "description_base_sha256": "6403c91895c8f9fa2d93e14c25a094b4fd7f83c7b205303cbdffa57803257b55",
    "description_fields": {
      "description": "Checks every observed interface for declared external IPv4 or IPv6 addresses."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "56f7b4d652ec4a8ecc62d9f97647a805c1861f3abdfae35c03c3418931bab594",
      "source_qualname": "public_interfaces"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM declares an external IP address."
  },
  "gcp.ports.compute_network_contains_no_legacy_network": {
    "description_base_sha256": "602ab567a39b28d1bc225aba606f3c38457c877e371ec5504d60587ea77b32cd",
    "description_fields": {
      "description": "Checks for the legacy-network IPv4Range property."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "46dc536d72493e75664d1828be096e4b77d4d8432a394c56fde73a1fe6605a8c",
      "source_qualname": "no_legacy"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The network declares the legacy IPv4Range model."
  },
  "gcp.ports.compute_network_dns_logging_scoped": {
    "description_base_sha256": "13ed3e2061d0f542088093f09e27ea8231c9328d257990b3116c0af8d5fef638",
    "description_fields": {
      "description": "Joins the exact network reference to one DNS policy and checks enableLogging."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c5d8a9d2a7c871d41244d8d6d65c0e54f37984cf169ba8ef862c8d7b1bc86a50",
      "source_qualname": "dns_network_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The network has no attached DNS policy with logging enabled."
  },
  "gcp.ports.compute_oslogin_metadata_precedence": {
    "description_base_sha256": "117406d4b057030813e51cf22fc476117f0475583b783043e34c5cfdb56d779d",
    "description_fields": {
      "description": "Resolves OS Login through instance metadata, project metadata and applicable effective organization policy."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "d81957aab5905a0bef035da27052c8ef98474bf9da95b92f571139c27d7fe07b",
      "source_qualname": "oslogin"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The resolved OS Login setting is disabled."
  },
  "gcp.ports.compute_ssl_policy_strict_declaration": {
    "description_base_sha256": "859ba6f4dc5007880eb5f4179d02689fe9961c96ab4328dc66e9974f81e0a7cc",
    "description_fields": {
      "description": "Joins HTTPS or SSL proxies to their SSL policy and compares its profile, minimum TLS version and custom ciphers."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1cc783f22ad11bf69e1b7d4108b398fd0299c52272386f369418f4e77c8eb493",
      "source_qualname": "ssl_policy"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The proxy lacks a qualifying strict SSL policy."
  },
  "gcp.ports.compute_url_map_backend_logging": {
    "description_base_sha256": "8801a079e716e856beab33bb6d44f868a81492c05d68c84fd3ce324989fe9558",
    "description_fields": {
      "description": "Follows URL-map routes to each backend service and checks its logging flag."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "e785c3a20614682b3250c71277e8ca7aa624f05dba5b1b9a08a99435ea896389",
      "source_qualname": "map_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A routed backend service has logging disabled."
  },
  "gcp.ports.dataproc_cluster_encryption_with_cmek": {
    "description_base_sha256": "7d7131807d210b8ac15b5db768af4fa275c60f302422da2d5b68bf8e10186049",
    "description_fields": {
      "description": "Checks Dataproc’s declared persistent-disk customer-managed key reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "76d84d41629343f34da3509a2748bb708e53991d7499407f8597557acc5ebcf2",
      "source_qualname": "encryption.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Dataproc cluster has an empty customer-managed disk key reference."
  },
  "gcp.ports.dns_managed_zone_dnssec_enabled": {
    "description_base_sha256": "ef4062fbec3d26b1298627cda0ad962ff7a1575d7b8e8204ac258026eccfeaba",
    "description_fields": {
      "description": "Checks public-zone DNSSEC state for on or transfer."
    },
    "remediation_base_sha256": "3736f7039da7901f27b5302295d98e9cb0974c9e282a5917dfa285d23d3ca576",
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
      "predicate_source_sha256": "d1435c7638c43effdf7977cfd0ea8d9cc180a2ea2bae77be7a72394daf20c654",
      "source_qualname": "dns.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "DNSSEC is not configured for the public zone."
  },
  "gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1": {
    "description_base_sha256": "02d33756cb6b149ec4cc57398a6d634460a4d308157de5e33de2d2b34ade96a8",
    "description_fields": {
      "description": "Checks public-zone key-signing specifications for RSASHA1."
    },
    "remediation_base_sha256": "e4180b6ba82159f2e49b2f05a884cae0718be039e2f918cbe6115eb254d6beeb",
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
      "predicate_source_sha256": "d1435c7638c43effdf7977cfd0ea8d9cc180a2ea2bae77be7a72394daf20c654",
      "source_qualname": "dns.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key-signing specification uses RSASHA1."
  },
  "gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1": {
    "description_base_sha256": "71d3f1431262c926647fd6a5dd526f55dc3ba6ace3152d1a1598ed97057b05f2",
    "description_fields": {
      "description": "Checks public-zone zone-signing specifications for RSASHA1."
    },
    "remediation_base_sha256": "0e3ee4f11a2ddce623e99fec97ef98333ebf18e94af5a9b68f1bd0f1e397326e",
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
      "predicate_source_sha256": "d1435c7638c43effdf7977cfd0ea8d9cc180a2ea2bae77be7a72394daf20c654",
      "source_qualname": "dns.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The zone-signing specification uses RSASHA1."
  },
  "gcp.ports.firewall_http_lb_proxy_source_restriction": {
    "description_base_sha256": "78cf354eb309ae8c84c5158574ad886ca22dba89b35f4401b1a5d5f6b3b73be0",
    "description_fields": {
      "description": "Compares active TCP ingress source ranges with the documented Google HTTP load-balancer proxy ranges."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1e06218e38d643a203e3bf09f93fb228152a52f61ab1529c099c9011c0888731",
      "source_qualname": "iap_sources.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The TCP ingress rule includes sources outside the HTTP load-balancer proxy ranges."
  },
  "gcp.ports.firewall_iap_tcp_proxy_source_restriction": {
    "description_base_sha256": "4954583e1650efbad844c75022bb6e7ffe9dcbed0e6e7051c78719af69b115f9",
    "description_fields": {
      "description": "Compares active TCP ingress source ranges with the documented IPv4 and IPv6 IAP TCP proxy ranges."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1e06218e38d643a203e3bf09f93fb228152a52f61ab1529c099c9011c0888731",
      "source_qualname": "iap_sources.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The TCP ingress rule includes sources outside the IAP proxy ranges."
  },
  "gcp.ports.function_active_public_binding": {
    "description_base_sha256": "da54cd3bc7781861d6384c9e780c115119cf21ffda2ddc468dd948a5ccd7edad",
    "description_fields": {
      "description": "Checks IAM bindings on ACTIVE functions for public principals."
    },
    "remediation_base_sha256": "d997db04188a0c7529e835a64c2c4d66a63ec23a31288cedafb022ada9bdc038",
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
      "predicate_source_sha256": "b7998a5a361a0abf13c7fe48481074887c9da30039b32b9a9073862651ac9986",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active function IAM policy declares a public principal."
  },
  "gcp.ports.function_active_vpc_connector": {
    "description_base_sha256": "244448e19df7bd30314b8bbfa2a6f6332f96b4dfb7fcb400064c5a918eec46a5",
    "description_fields": {
      "description": "Checks ACTIVE functions for a nonempty VPC connector reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "3be2d647ee93d212e571a7dd2d0831402b0f0d3c2ffe9dcb9ea5d39a438f47be",
      "source_qualname": "function_setting.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active function has no VPC connector reference."
  },
  "gcp.ports.function_basic_role_declarations": {
    "description_base_sha256": "5451ef6958d9acb0e2f38423e5c028d60ba3c74ce8275bcda31bbbdd7200de60",
    "description_fields": {
      "description": "Joins the function identity to project and ancestor Owner or Editor role declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "770536c864c0b576048e7b2b73975556548634a6968ec5bdf54e1c33c934936f",
      "source_qualname": "function_roles.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function identity has an Owner or Editor role declaration."
  },
  "gcp.ports.function_internal_ingress_declaration": {
    "description_base_sha256": "6da5c0d08c8954c12580af79d3da18be54eb1b8031363b29bdb5fad925462441",
    "description_fields": {
      "description": "Checks the function ingress setting for ALLOW_INTERNAL_ONLY."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7525682f486574baf5c95a157dcbf88bc51cc26a91b6af25330025fdd20d2a84",
      "source_qualname": "function_internal"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function does not declare internal-only ingress."
  },
  "gcp.ports.function_legacy_deployment_role_declarations": {
    "description_base_sha256": "4617a1a3aa6b50e7bf1e103870a4c1911e54c4bd51bdf66f17e51b7137dd3954",
    "description_fields": {
      "description": "Joins function identity roles to Deployment Manager create or update permission declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "770536c864c0b576048e7b2b73975556548634a6968ec5bdf54e1c33c934936f",
      "source_qualname": "function_roles.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function identity has a Deployment Manager mutation permission declaration."
  },
  "gcp.ports.function_logging_mutation_declarations": {
    "description_base_sha256": "4505bf643ac473a62ab2f982ad9a6e033b73a1cc1dc0dc49fd46f24a7b54829a",
    "description_fields": {
      "description": "Joins function identity roles to logging update or delete permission declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "770536c864c0b576048e7b2b73975556548634a6968ec5bdf54e1c33c934936f",
      "source_qualname": "function_roles.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The function identity has a logging mutation permission declaration."
  },
  "gcp.ports.iam_api_key_age_90": {
    "description_base_sha256": "ed23af9102dfc09ee402c3aee658ad64fd7bafad034ac868b0c23bb2cb431aed",
    "description_fields": {
      "description": "Compares API-key creation time with midnight UTC 90 days before the collection date."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8fc3e9797a33d611e58ceb5e692475e390c03d5b7c0bf9be1bf64bb8c1038b66",
      "source_qualname": "age.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key was created on or before the 90-day UTC-date cutoff."
  },
  "gcp.ports.iam_api_key_restricts_apis": {
    "description_base_sha256": "cac007ea3efdbce9ad8582c498b3ca20434e63292a03ca15f8b946f7bdb2dae3",
    "description_fields": {
      "description": "Checks for nonempty API targets without the unrestricted cloudapis.googleapis.com target."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "06c5db235ae9fcce8bf3fd91c90adc640862a72d995a93a4572441b46d412c97",
      "source_qualname": "api_targets"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key has no specific API restriction."
  },
  "gcp.ports.iam_api_key_restricts_websites_hosts_apps": {
    "description_base_sha256": "42b0649281fd77f259d8714d8577460480748bd4c60241e715f9db7fc709c968",
    "description_fields": {
      "description": "Checks one caller-restriction mode for a nonempty list without recognized universal entries."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0c1150dccf342586f465f17f67ccbdbb0d30ee1abe22b2a66f96d695eb4c2868",
      "source_qualname": "caller_restrictions"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The API key has no narrow caller restriction."
  },
  "gcp.ports.iam_service_account_gcp_managed_key": {
    "description_base_sha256": "72b9051d1b52e631d0de03a4975de872bd5b752c569a963ab2eb5d191672d994",
    "description_fields": {
      "description": "Joins a service account to collected key metadata and flags user-managed keys."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c396f650a6fbc3b24507337338f3a6a379be6b41c2d0cc17b5f5a0241283724f",
      "source_qualname": "account_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The service account has a user-managed key."
  },
  "gcp.ports.iam_service_account_key_age_90": {
    "description_base_sha256": "fd7dd933b79fcc86cd3d4dd120dab5221db937486a26ec8f39d65c2143a2c662",
    "description_fields": {
      "description": "Compares user-managed key creation time with midnight UTC 90 days before collection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8fc3e9797a33d611e58ceb5e692475e390c03d5b7c0bf9be1bf64bb8c1038b66",
      "source_qualname": "age.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user-managed service-account key predates the 90-day UTC-date cutoff."
  },
  "gcp.ports.iam_user_not_assigned_service_account_user_role_project_level": {
    "description_base_sha256": "7c8abb1397bcd307f5c3ca8ec6dd6820001287ebd0efde8999db3777b4627086",
    "description_fields": {
      "description": "Checks project-root Service Account User or Token Creator bindings for non-service-account-suffix principals."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "cac4efdc7f7312eac401a1ae2fe062faea64d62bc0e797e93b2c032ba4439c50",
      "source_qualname": "project_identity_roles"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A project-root identity-use or token-creator role is assigned to a non-service-account principal."
  },
  "gcp.ports.iam_user_separation_of_duty_scoped": {
    "description_base_sha256": "0d5b0071bf906f8965dcfd02486a1d2275a0d5140bbe3f14151683f2bc9ab03f",
    "description_fields": {
      "description": "Checks project-root user bindings for both Service Account Admin and Service Account User roles."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8cfc95effd0cfde16acaf3adaa4989317b12836041a99027cd051cb856d83f14",
      "source_qualname": "duty.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A user has both service-account administrator and user role declarations."
  },
  "gcp.ports.kms_key_rotated_within_90_day": {
    "description_base_sha256": "cbc02ff378d514d029314b96cd5cac0d6432f19a1b6e38b109fc8fb62d10209b",
    "description_fields": {
      "description": "Checks an applicable active encryption key for an automatic period above zero and at most 90 days."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8cdae549e4babdcc17cf9aa096f9e389d11ff5f002e82a4d04bb2f17b2aa4f40",
      "source_qualname": "kms_period"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The automatic rotation period is disabled or exceeds 90 days."
  },
  "gcp.ports.kms_key_separation_of_duties_enforced": {
    "description_base_sha256": "d28550057027fd7be2eebc831addebad98e8d6e84f89b2892c29cbf99342cf3d",
    "description_fields": {
      "description": "Checks project-root user bindings for both KMS administration and a cryptographic-use role."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "8cfc95effd0cfde16acaf3adaa4989317b12836041a99027cd051cb856d83f14",
      "source_qualname": "duty.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A user has both KMS administrator and cryptographic-use role declarations."
  },
  "gcp.ports.kubernetes_cluster_auto_repair_enabled": {
    "description_base_sha256": "442188ffab64e36d8a839cf51c85f6040b4dc9841daea458ab588e08d1e6c28a",
    "description_fields": {
      "description": "Checks each node pool’s autoRepair management setting."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "9fab1cca896c68e2e6eb989edae77d020cc7b20fb5eea7a1309f8596f4494d09",
      "source_qualname": "node_pool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool disables automatic repair."
  },
  "gcp.ports.kubernetes_cluster_auto_upgrade_enabled": {
    "description_base_sha256": "cbaad18a0619f634a9e94f679d0b43bb289b87db8cbdb72046ae174d743edd65",
    "description_fields": {
      "description": "Checks each node pool’s autoUpgrade management setting."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "9fab1cca896c68e2e6eb989edae77d020cc7b20fb5eea7a1309f8596f4494d09",
      "source_qualname": "node_pool.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool disables automatic upgrades."
  },
  "gcp.ports.kubernetes_cluster_intra_node_visibility_enabled": {
    "description_base_sha256": "259d2df06d5299ea69479a18f56b8d8d9e20657b09ae6a127430277895d6553b",
    "description_fields": {
      "description": "Checks the cluster’s intra-node visibility flag, including known false omission."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "25c0e63217a5fbd81d258db1b319273d8ed943705d479ca80b339fc003647139",
      "source_qualname": "intra_node_visibility"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Intra-node visibility is disabled."
  },
  "gcp.ports.kubernetes_cluster_legacy_endpoints_disabled": {
    "description_base_sha256": "59737be03dbce9ab3651268904b2c262e11238956eef60efe3bc5873928ae0b6",
    "description_fields": {
      "description": "Checks each node pool for disable-legacy-endpoints=true metadata."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b8a4e202ad9e6180f2540eddbbc40eee87840bea8b592243deeccd33a4a3505c",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool explicitly enables legacy metadata endpoints."
  },
  "gcp.ports.kubernetes_cluster_node_config_image_cos_containerd": {
    "description_base_sha256": "164e04e99bc7884fd9896da6d6a4cb882a0ea033ae2fa6006a01215fcbc8b8c3",
    "description_fields": {
      "description": "Checks each node pool imageType for COS_CONTAINERD rather than UBUNTU_CONTAINERD."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b8a4e202ad9e6180f2540eddbbc40eee87840bea8b592243deeccd33a4a3505c",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool declares UBUNTU_CONTAINERD."
  },
  "gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled": {
    "description_base_sha256": "cd286d1154d03f50f20cf33675085fc013cde7edce6abc9ac8d486476ee3d8a2",
    "description_fields": {
      "description": "Checks each node pool’s integrity-monitoring setting, including its true omission default."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b8a4e202ad9e6180f2540eddbbc40eee87840bea8b592243deeccd33a4a3505c",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool disables integrity monitoring."
  },
  "gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled": {
    "description_base_sha256": "6f95b17c3adb9d4d15bdda7239741d14cb43b143e25eb815d9bd6dbcf774ae22",
    "description_fields": {
      "description": "Checks each node pool’s Secure Boot setting, treating known omission as false."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b8a4e202ad9e6180f2540eddbbc40eee87840bea8b592243deeccd33a4a3505c",
      "source_qualname": "pool_scalar.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A node pool does not enable Secure Boot."
  },
  "gcp.ports.kubernetes_cluster_use_ip_aliases": {
    "description_base_sha256": "8708782af63e711be6b3e29214334ef89732da4d47180bc9ee9e15cea27a876d",
    "description_fields": {
      "description": "Checks whether the cluster explicitly selects alias IP ranges rather than route-based networking."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "541f98e24f6580d48ebc1e1457320606e6d8fe2e19bab1acd600f8594b92e7aa",
      "source_qualname": "use_ip_aliases"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster explicitly selects route-based networking."
  },
  "gcp.ports.logging_bucket_retention_policy_enabled": {
    "description_base_sha256": "909c470a352163e3064c8940b07355751f64a5dccfa1d668a59536acf857a145",
    "description_fields": {
      "description": "Joins a Cloud Storage log-sink destination to its bucket and checks retentionPolicy.isLocked."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "1e94fa77b2fb298515842580293698c7a074bfcd1a12bafab461e772a59c5c50",
      "source_qualname": "retained_destination"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log destination bucket has no locked retention policy."
  },
  "gcp.ports.logging_metric_alert_audit_configuration_changes_scoped": {
    "description_base_sha256": "4946eb8c17fe757ade67fcbfee53d38996096ef99ce45c095be993d00ca21101",
    "description_fields": {
      "description": "Matches the audit configuration changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_custom_role_changes_scoped": {
    "description_base_sha256": "85a109ed8490ab689f5e7bcec1e4b58e4d97f5f2b6c7b56625e095ae3d0456ee",
    "description_fields": {
      "description": "Matches the custom role changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role_scoped": {
    "description_base_sha256": "adab7fcc102fc7830c65f1e60111929be77120b8e6dd9224ec2d2a46c00345d5",
    "description_fields": {
      "description": "Matches the custom role changes with iam admin undelete role filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_firewall_rule_changes_scoped": {
    "description_base_sha256": "3b17e2db0bab4c607279838ce7ea0a78d1c7f93098da0dff04916792ebe71888",
    "description_fields": {
      "description": "Matches the firewall rule changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_network_changes_scoped": {
    "description_base_sha256": "b43296be7e669433f605b6f48573cd95f678c87d9ce2c81973cd37747b223810",
    "description_fields": {
      "description": "Matches the network changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_network_route_changes_scoped": {
    "description_base_sha256": "9bb9a9dff7c9882ad4a07463963ba0dd0f6c232a2b95fbf728fb2850b5c15573",
    "description_fields": {
      "description": "Matches the network route changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_project_ownership_assignment_scoped": {
    "description_base_sha256": "d048e42d4ef459da8e3184bf0cfa1a97828d27ce3686c452860725152652b197",
    "description_fields": {
      "description": "Matches the project ownership assignment filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_sql_instance_configuration_changes_scoped": {
    "description_base_sha256": "e546247d371e75bf26a91cfd8eb05d0347ea6111714c66b404c9549237d86b9f",
    "description_fields": {
      "description": "Matches the sql instance configuration changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_metric_alert_storage_iam_permission_changes_scoped": {
    "description_base_sha256": "4100e03dd41e0c0431cd3ff9a905b95ce633eb9e0f579e1c449c374b0054c551",
    "description_fields": {
      "description": "Matches the storage iam permission changes filter template and joins its metric to an enabled same-project threshold alert."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "7d8c29b8ca35c6a721fc7a0f5dbdb3b06f2e196fb0585f16ebafc68180f01cc3",
      "source_qualname": "metric_alert.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No matching same-project metric and enabled threshold alert was found."
  },
  "gcp.ports.logging_sink_all_entries_enabled": {
    "description_base_sha256": "4799840af25ba568b62c27692f6b779b2470f5cb6253d4d3a1df8480869dea09",
    "description_fields": {
      "description": "Checks for an enabled project sink with no filter or active exclusions and a nonempty destination."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "c5beddd578e0261b9b0e6dcdbf39aa3f8791ca40d0b42ed020c1fe4164024ae0",
      "source_qualname": "all_entries"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No qualifying all-entries project sink was found."
  },
  "gcp.ports.organization_essential_contacts_complete": {
    "description_base_sha256": "24d6e6695913fbe8fc19227560baae84ccb401cbe40ea74298eedfd59e113f3a",
    "description_fields": {
      "description": "Combines organization contact subscriptions and checks ALL or the five required categories."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "936fee3d9f6db81386d612cd1e92ae0e057c175c45d6385e403e08da609ae28a",
      "source_qualname": "contacts"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Organization contacts do not cover every required notification category."
  },
  "gcp.ports.project_no_api_key": {
    "description_base_sha256": "d45dcb07869cfee4a42b3ee02cd7077d4989fb4c3f8b8939097f6f3837f2269a",
    "description_fields": {
      "description": "Joins project identifiers to collected API-key metadata and checks for keys."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "594c23cf1410e39cd8f8b139878cb8c01ab639dd9e00e1e42425a34c8dd6e3a8",
      "source_qualname": "project_no_keys"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project has an API key."
  },
  "gcp.ports.project_service_cloudasset_api_enabled": {
    "description_base_sha256": "835cd137007f081180c182f2af58db3539238ab7060a51dbb5519643c14cfc94",
    "description_fields": {
      "description": "Joins the project to its Cloud Asset API service state and requires ENABLED."
    },
    "remediation_base_sha256": "084660d50f1d49011089243087fe0c19b24d4dd025f5227c545ef53d3a15168c",
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
      "predicate_source_sha256": "033a3a8377f6a119712d0821c8842bdc92196a21ab21566489bbe1bddeef2d8e",
      "source_qualname": "service.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Cloud Asset API is disabled."
  },
  "gcp.ports.reference_sql_pg_min_duration": {
    "description_base_sha256": "a6bf621741ae293d7c650989c708701795a4acc11e08350a01adf3257aa6b22f",
    "description_fields": {
      "description": "Compares POSTGRES flag log_min_duration_statement with '-1', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_duration_statement declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sql_pg_min_error": {
    "description_base_sha256": "3525d84c02256e4c10f76405309d17cee13e7e886d419903c3b08beb5e4fbe52",
    "description_fields": {
      "description": "Compares POSTGRES flag log_min_error_statement with 'error', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_error_statement declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sql_pg_min_messages": {
    "description_base_sha256": "785144142df5b6040c2fd0696c6bbb965b72a54eadb0ce66c0d5757f7043e2fe",
    "description_fields": {
      "description": "Compares POSTGRES flag log_min_messages with 'WARNING' or 'ERROR' or 'LOG' or 'FATAL' or 'PANIC' or 'warning' or 'error' or 'log' or 'fatal' or 'panic', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_messages declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sql_ssl_connections": {
    "description_base_sha256": "1431994006a4607531997f5eb29f1f96fabc62f5477b3b2af94f6c96de483d37",
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
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "261e43839b630ca1802fd07ae434982405fadb7e1e0f6024f76bd1d95741a90c",
      "source_qualname": "sql_ssl"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL permits unencrypted client connections.",
    "native_semantic_followup": {
      "report": "sql-transport-semantic-followup.json",
      "helper": "peaso/checks/gcp_sql_transport_native.py",
      "helper_sha256": "51f4f29c98bb0c5bbf593d4eb54ca277f437893c9de75b4197b7aca4378afb86",
      "prior_predicate_sha256": "3a5f3e585d7924c7028fb65f2cc39d1ed04c55243e99a6fbe20972002dfb256b"
    }
  },
  "gcp.ports.reference_sqlserver_contained_database_authentication": {
    "description_base_sha256": "54199a81b5d192b0b650cce8ce0be5f19af574fe03613f8d7524affc4b7d8897",
    "description_fields": {
      "description": "Compares SQLSERVER flag contained database authentication with 'off', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The contained database authentication declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_cross_db_ownership_chaining": {
    "description_base_sha256": "d2e2d84e2e599255f634680b5b9a7fc68f60b48224fe91fab82e2f18d761453f",
    "description_fields": {
      "description": "Compares SQLSERVER flag cross db ownership chaining with 'off', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cross db ownership chaining declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_external_scripts_enabled": {
    "description_base_sha256": "5fd4fcea3a589643856d1299ee053be718152cad5a1082ac91692250747fb10a",
    "description_fields": {
      "description": "Compares SQLSERVER flag external scripts enabled with 'off', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The external scripts enabled declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_remote_access": {
    "description_base_sha256": "efad24543971361e54343c7286ff9ff1311eee39ad11521d75cdc000b3112742",
    "description_fields": {
      "description": "Compares SQLSERVER flag remote access with 'off', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The remote access declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_trace3625": {
    "description_base_sha256": "ed8e2ae1a5a7d3e8d6aba8b591e92ac050682c39f9f500566d1137fc9e3d6de8",
    "description_fields": {
      "description": "Compares SQLSERVER flag 3625 with 'on', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The 3625 declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_user_connections": {
    "description_base_sha256": "354761428f4b7262c95e7677913a5bddd6304f5e94814c14f477320746004b84",
    "description_fields": {
      "description": "Compares SQLSERVER flag user connections with '0', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user connections declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.reference_sqlserver_user_options": {
    "description_base_sha256": "b087a0cb262651981f969f24c1d05e3340f188745bb117e26330adc5443da3c6",
    "description_fields": {
      "description": "Compares SQLSERVER flag user options with '', applying this profile’s omission rule."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a8cc5cf8182c180eeb7decfd16a60a207abd9d306156056f19c341bf389cc45f",
      "source_qualname": "sql.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user options declaration does not meet this profile’s accepted values."
  },
  "gcp.ports.service_account_mutating_role_declarations": {
    "description_base_sha256": "45576d02c5c4ba7dfb17a9be25587fdb387d9d7a5e9876d4ae8caf8207522c17",
    "description_fields": {
      "description": "Joins service-account bindings and role definitions for create, update, delete or setIamPolicy permissions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "dcc9cb3c58e32796e36053c8037398af7541c8e740849312097b1664107b427b",
      "source_qualname": "account_mutations"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An assigned role declares resource mutation permissions."
  },
  "gcp.ports.sql_instance_mysql_binary_log_enabled": {
    "description_base_sha256": "e22ca0dae4db7637df38432a73cfc549c0bdaecc562d15fe047b409f4d8df436",
    "description_fields": {
      "description": "Checks the Cloud SQL binaryLogEnabled backup setting."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "b7079b0ec2cedc09d7a6c43e81426d2045a5eba6942abc9a7087395c71437274",
      "source_qualname": "scalar.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "MySQL binary logging is disabled."
  },
  "gcp.ports.sql_instance_not_open_to_internet": {
    "description_base_sha256": "94124412e5efe05b91b0d3ecb5baf73caa0ce48ec8c62c232f25f0fa9b7dd7ca",
    "description_fields": {
      "description": "Checks Cloud SQL authorized network entries for 0.0.0.0/0 or ::/0."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a1b71395736bd06441778d71b0016fb19effe2252545622253b2409a687cffb1",
      "source_qualname": "sql_authorized"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL authorizes an Internet-wide network range."
  },
  "gcp.ports.sql_instance_not_publicly_accessible": {
    "description_base_sha256": "7662aed552fd5c646306a77a48e31eda48d06eeecdd408cd104b1165ba28af25",
    "description_fields": {
      "description": "Checks for a PRIVATE address and private-network reference, and rejects PRIMARY incoming addresses."
    },
    "remediation_base_sha256": "6312afa0b02259bac193d78f1b7821d8524e3b99ad4e05ec600a61820fec758a",
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
      "predicate_source_sha256": "3ab14333c095aeb73b48224e0057da4d68153592c4516a825904eb01bb88e9cf",
      "source_qualname": "sql_address.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance lacks the required private configuration or declares a PRIMARY public incoming address."
  },
  "gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on": {
    "description_base_sha256": "fea6ff5ced06206df1ba5e3d95e7c810f891b6b4aaebe9aca01ae762949636ff",
    "description_fields": {
      "description": "Checks POSTGRES flag log_checkpoints for on."
    },
    "remediation_base_sha256": "07ebbbfc65bfaf0067857ae8359a3fad55a22d052660d8a716d8e02326d7030e",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_checkpoints flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_duration_database_flag_on": {
    "description_base_sha256": "43c721d71ca5630c12426993f9be592855c9f5987b74bfb06262756521ae4de0",
    "description_fields": {
      "description": "Checks POSTGRES flag log_duration for on."
    },
    "remediation_base_sha256": "6320efe5e84564867197eef99ac5cc3079c1dca3e26774128f8368f263b56c5b",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_duration flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter": {
    "description_base_sha256": "4b95302685b1926fc8305bd49c6fee89879ba05773082d273dad98f7f44e606e",
    "description_fields": {
      "description": "Checks POSTGRES flag log_error_verbosity for default or verbose."
    },
    "remediation_base_sha256": "b15fe6d1ec5ad4719f3527706089138f02813dcb74cb74bc268d1a2c079d46ef",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_error_verbosity flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off": {
    "description_base_sha256": "3724be92c27d17688b6059430dc20856bb835eaa6c973a2d3a8b7a42bca9bb6c",
    "description_fields": {
      "description": "Checks POSTGRES flag log_executor_stats for off."
    },
    "remediation_base_sha256": "e240913e884d3ad994fd04fb9307211d58b8e2bdfff03d142568af88dedf8803",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_executor_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured": {
    "description_base_sha256": "675af5c289b116d2d8dea71165b07ac9d7d19be6dbe73159d11f66fc651b49b7",
    "description_fields": {
      "description": "Checks POSTGRES flag log_hostname for on."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_hostname flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on": {
    "description_base_sha256": "bc653ec487d01e3ac1fda2346e0b9dade790a3f1e29208c5ef69276a915c9853",
    "description_fields": {
      "description": "Checks POSTGRES flag log_lock_waits for on."
    },
    "remediation_base_sha256": "1e54ab36e10885e1d9c8b76ab7a89edf7155149d4354b27bba62a371427c9c8c",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_lock_waits flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled": {
    "description_base_sha256": "cdd18ce17a2bb68018aa3e848d63d19b2473839d56d09bfbf43d7c2721274ef6",
    "description_fields": {
      "description": "Checks POSTGRES flag log_min_duration_statement for -1."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_duration_statement flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured": {
    "description_base_sha256": "a5fab4ebc7953efbb1b4121ebd659900c7c8e48a03e83dd8ee26eb1b8bbf8236",
    "description_fields": {
      "description": "Checks POSTGRES flag log_min_error_statement for an explicit value."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_error_statement flag is not explicitly configured."
  },
  "gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error": {
    "description_base_sha256": "000b566a309960954c16f20e726cd6c9a0088b8c8fbe8c4b34dab22d922d451d",
    "description_fields": {
      "description": "Checks POSTGRES flag log_min_messages for error or warning."
    },
    "remediation_base_sha256": "82d4f4383724343479b95679e520005bf264ea7b7f4f8d3b6d841d6ec306ee88",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_min_messages flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off": {
    "description_base_sha256": "83ef5107da33b434e44ebab2719d8896d8ad2c8f12d96f1ff9b0e678f3ad7654",
    "description_fields": {
      "description": "Checks POSTGRES flag log_parser_stats for off."
    },
    "remediation_base_sha256": "f403462f3929635fb410537aedbfb76db48cf8afebfa9e649e8b718684fb3e7c",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_parser_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off": {
    "description_base_sha256": "6c808def56d7485bc74c869a245cdfbabf6bac0c6460f4d3c1133cbd06c8c939",
    "description_fields": {
      "description": "Checks POSTGRES flag log_planner_stats for off."
    },
    "remediation_base_sha256": "ad700813bff7f08c71477b03268459e081d6d0098e068c773a09bad762e48c57",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_planner_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off": {
    "description_base_sha256": "4d7c5fea6b34e35003d1d9123475bb379706d17941b6a2bcbff7646e59841cbf",
    "description_fields": {
      "description": "Checks POSTGRES flag log_statement_stats for off."
    },
    "remediation_base_sha256": "8aa87d81b9a3f86fe4b2dd60a29533c7a45e82292e87a6583d68ec7f81bccf53",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_statement_stats flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0": {
    "description_base_sha256": "a23afb624e421fdd4ceb7ba9f8a7de23040720623fd56a3eeb6f886c074d13dd",
    "description_fields": {
      "description": "Checks POSTGRES flag log_temp_files for 0."
    },
    "remediation_base_sha256": "fe840789c9dd459044dfbf8e8c4bd65c1d949ac5dd1f6895baf418621c5c6001",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The log_temp_files flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_require_ssl_enabled": {
    "description_base_sha256": "970ae57f5331c919bed0ef1390a2cd04582c2fe8cb36333190d5bb3f58b455f7",
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
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "261e43839b630ca1802fd07ae434982405fadb7e1e0f6024f76bd1d95741a90c",
      "source_qualname": "sql_ssl"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL permits unencrypted client connections.",
    "native_semantic_followup": {
      "report": "sql-transport-semantic-followup.json",
      "helper": "peaso/checks/gcp_sql_transport_native.py",
      "helper_sha256": "51f4f29c98bb0c5bbf593d4eb54ca277f437893c9de75b4197b7aca4378afb86",
      "prior_predicate_sha256": "9762e3d59a15eeba148639267033ae2d6d6cefae54502589fa3655e16faf46f3"
    }
  },
  "gcp.ports.sql_instance_sql_3625_trace_database_flag_on": {
    "description_base_sha256": "f2f4a660467f2f01d7448652ea065a4416aa84c48b6a5fe7f791048a53dd7b0c",
    "description_fields": {
      "description": "Checks SQLSERVER flag 3625 for on."
    },
    "remediation_base_sha256": "752ae84fe4e4595b24c55887b1541ce2a6fa0af6567a49598148ef9faddf0f5e",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The 3625 flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off": {
    "description_base_sha256": "07320353fbd2074dd96f42acb987ed04f2196b8d64d5bd613834bf6f06baa5c0",
    "description_fields": {
      "description": "Checks SQLSERVER flag contained database authentication for off."
    },
    "remediation_base_sha256": "bb1e6437c1bf70bbe0f2afee54d7d1ae952dfce0248ebeb3bb6e90a43cb9e62a",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The contained database authentication flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off": {
    "description_base_sha256": "e6d425efb9b4a67e3bfa8f27045bffae9fa2f6045d9851964b5659b26e807661",
    "description_fields": {
      "description": "Checks SQLSERVER flag cross db ownership chaining for off."
    },
    "remediation_base_sha256": "4a4990e122d02491497be5bb08a8553546ada8526ddc0347f2ccca1e96c6a9c7",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cross db ownership chaining flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off": {
    "description_base_sha256": "3f40646d583635fa38fb8b4b6bde0fd079fc3421bc4dbf7856c141666b6eb7d6",
    "description_fields": {
      "description": "Checks SQLSERVER flag external scripts enabled for off."
    },
    "remediation_base_sha256": "6fbb74da1d5e7f9003db805af0a59d7509df99f84ada33d61117bf19aa4c6f91",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The external scripts enabled flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_remote_access_database_flag_off": {
    "description_base_sha256": "06ff97246a646a0d2462033eaad6f34b5250eb883a88885a5992271b2eac7f52",
    "description_fields": {
      "description": "Checks SQLSERVER flag remote access for off."
    },
    "remediation_base_sha256": "dad46d25b0388ff679381c535f9ba0ef4534c6e20ee1a111a15efab93397213c",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The remote access flag is absent or outside this profile’s accepted values."
  },
  "gcp.ports.sql_instance_sql_user_connections_database_flag_configured": {
    "description_base_sha256": "c122b0bdedee8713e77c82aae06e97d12e1c2843d5496e9c842734fda3ab0838",
    "description_fields": {
      "description": "Checks SQLSERVER flag user connections for an explicit value."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user connections flag is not explicitly configured."
  },
  "gcp.ports.sql_instance_sql_user_options_database_flag_not_configured": {
    "description_base_sha256": "cbb52f4d997c5646e104e8af4cfc5198b27a11818c4ca6338ccdd41c6f7db96a",
    "description_fields": {
      "description": "Checks SQLSERVER flag user options for absence."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "08ed4a213d72afa8f982f9bd5408610cb33dbba7fb32f2ee25d93ad4cd90591f",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The user options flag is explicitly configured."
  },
  "gcp.ports.sql_instance_with_no_public_ips": {
    "description_base_sha256": "4c8751b559f1b1d02ea10e8250f25d5e28e7d59a428a8a39f2706888e6b621fc",
    "description_fields": {
      "description": "Checks SECOND_GEN Cloud SQL address metadata for a PRIMARY public incoming assignment."
    },
    "remediation_base_sha256": "4eef4838fdf3b2cd3a986b5b139d30cc0a348780bf01d2b39766bf7e2aacbb15",
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
      "predicate_source_sha256": "3ab14333c095aeb73b48224e0057da4d68153592c4516a825904eb01bb88e9cf",
      "source_qualname": "sql_address.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The SECOND_GEN instance declares a PRIMARY public incoming address."
  },
  "gcp.ports.sql_no_primary_address": {
    "description_base_sha256": "99073958f2ad266e01b02d7837c9cd4b2e586d961f352ebbe052b990f0a948ec",
    "description_fields": {
      "description": "Checks Cloud SQL address metadata for a PRIMARY incoming address."
    },
    "remediation_base_sha256": "5756d4163ce28e26a0f7bc7466b1c3ad39a3bf0b4b89d46d3b1dfcf43ce66ae0",
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
      "predicate_source_sha256": "3ab14333c095aeb73b48224e0057da4d68153592c4516a825904eb01bb88e9cf",
      "source_qualname": "sql_address.<locals>.evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance declares a PRIMARY public incoming address."
  },
  "gcp.ports.storage_bucket_not_publicly_accessible": {
    "description_base_sha256": "07062ab9ea8fd56345679c2a9baa6c436aec54ef4fd4b24daf79372bee9bf12f",
    "description_fields": {
      "description": "Checks bucket IAM bindings for public principals, retaining role and condition metadata."
    },
    "remediation_base_sha256": "4f3cce1daf85c737d5161418376e9fa08f68769932271b05e467c82473b45881",
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
      "predicate_source_sha256": "b7998a5a361a0abf13c7fe48481074887c9da30039b32b9a9073862651ac9986",
      "source_qualname": "policy_public.<locals>.evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket IAM policy declares a public principal."
  },
  "gcp.reviewed.bigquery.cmek": {
    "description_base_sha256": "8cb224583d04bd0c260b58a0bc4744510724c39cfe83bdc0d3ee3e9a7628ca27",
    "description_fields": {
      "description": "Checks non-anonymous datasets for a default customer-managed key reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "392982acdfd2d9cbef94440ac5e2741ea5ae60f11420390b91c883cda925953b",
      "source_qualname": "bigquery_cmek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset has no default customer-managed key."
  },
  "gcp.reviewed.bigquery.no_public_acl": {
    "description_base_sha256": "b3b011a24cb87f9ee8fb92b09f3e37d1d67ad286ac7e230826b9eba2663bbca1",
    "description_fields": {
      "description": "Checks dataset ACL entries for public IAM or legacy public-group declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ee1de6ea2e476583d2a61ebedc23ec024f43135b5fcaffa45199247e64359655",
      "source_qualname": "bigquery_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset ACL declares public access."
  },
  "gcp.reviewed.compute.block_project_ssh_keys": {
    "description_base_sha256": "448d9ba5f60ba228257a3c5422e226e111f944c7872299eea5ee1dd028ca263b",
    "description_fields": {
      "description": "Checks for one explicit block-project-ssh-keys=true VM metadata entry."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0eb3683e2f305a06586d2ad05e70c23429513194a1faf025b71f01a7f97e0f86",
      "source_qualname": "block_project_keys"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM explicitly allows project-wide SSH keys."
  },
  "gcp.reviewed.compute.disk_auto_delete": {
    "description_base_sha256": "79c27dfec6e5945fc08ca69a51d7bb73b1255fd7035547a29285d3aa429506ac",
    "description_fields": {
      "description": "Checks whether persistent VM disks are configured for deletion with the VM."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2760b839c497dbe15dfb859215b3fbd7aa792f44d4d52e4b932e8b57d92fab72",
      "source_qualname": "disk_auto_delete"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A persistent disk is configured to delete with the VM."
  },
  "gcp.reviewed.compute.ip_forwarding": {
    "description_base_sha256": "8692c5556d31bbda995829fb5d55f9f17791126d383332bf2acbd8132cee6dd5",
    "description_fields": {
      "description": "Checks the VM canIpForward declaration; GKE-named nodes are referred for review."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "84bb654f76d99770ff4ca0d9ae80f465d171c01f5e9cbc13511847e24b8c41f4",
      "source_qualname": "ip_forwarding"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM allows IP forwarding."
  },
  "gcp.reviewed.compute.no_default_full_api": {
    "description_base_sha256": "88f7a04afcaf28b2c28d280a477f6021a4ffcabda33423f5165215ead4b752f6",
    "description_fields": {
      "description": "Checks for the default Compute Engine identity with the cloud-platform OAuth scope."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "450ff5e9a804e6ac242724a1e46e3233e89a874e0372414d1065c8eaa2914a81",
      "source_qualname": "no_default_full_api"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The default Compute Engine service account has the cloud-platform OAuth scope."
  },
  "gcp.reviewed.compute.no_default_service_account": {
    "description_base_sha256": "1fd9e2bfe4c7f88787193afe2bff434f9c91be760b75a93aaba1ba6de265d770",
    "description_fields": {
      "description": "Checks attached identities for the default Compute Engine service account."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6c353fe5586bc189e28bf201bea0f1450f87032a8217244030781dfa3ba18ab1",
      "source_qualname": "no_default_account"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM attaches the default Compute Engine service account."
  },
  "gcp.reviewed.compute.no_serial_console": {
    "description_base_sha256": "eaecd5bef50b153bf2775e81e594205be650fb62708023df9cdc486914854eb9",
    "description_fields": {
      "description": "Checks for one explicit serial-port-enable=false VM metadata entry."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "4a416d4c0113061afc00908b7016d1dcf360ecf63b4bc6a5912ae9e280566bab",
      "source_qualname": "serial_console"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Interactive serial-console access is explicitly enabled."
  },
  "gcp.reviewed.compute.single_interface": {
    "description_base_sha256": "7f905dc770be7e6d262aa92ac685ed24dc378c42635ada91b6345bc44c6c2268",
    "description_fields": {
      "description": "Counts declared VM network interfaces; GKE-named nodes are referred for review."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "2e9cdc2a67b10b199c9c00981894d1f38b1478c440447ca5fc2c282df143b709",
      "source_qualname": "single_interface"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The VM declares more than one network interface."
  },
  "gcp.reviewed.kms.no_public_iam": {
    "description_base_sha256": "2bf996e646779432a682523810923181245798e9daf44ae95dee96b6ea83c993",
    "description_fields": {
      "description": "Checks the key IAM policy for allUsers or allAuthenticatedUsers bindings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "59682bd8d878026f07a8460638daec1568588f6dab1d89c8d643915de5031454",
      "source_qualname": "kms_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The key IAM policy declares a public principal."
  },
  "gcp.reviewed.kms.rotation_90_days": {
    "description_base_sha256": "c01d98a96d2f7144c94ceb59655285189b0e0b8c7f9459b82d4fdbd92611eaf5",
    "description_fields": {
      "description": "Checks a positive rotation period and next scheduled rotation within 90 days of collection."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "fcc5095732552165328b1f0a26f161a47336ec4777bffa566313737ec27be930",
      "source_qualname": "kms_rotation_90"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The rotation period or next scheduled rotation is outside the 90-day window."
  },
  "gcp.reviewed.kms.rotation_enabled": {
    "description_base_sha256": "4695adb76e8a5254b2d56d91c2ec50130853134d32cd199d382614eff62e7cbe",
    "description_fields": {
      "description": "Checks automatic rotation for applicable encryption keys with an active primary version."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "cf785a81401566949634ae66bf5af1b2e7b2b87e0ca96066e6328a226cc9b7ba",
      "source_qualname": "kms_rotation"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Automatic key rotation is not configured."
  },
  "gcp.reviewed.network.flow_logs": {
    "description_base_sha256": "7330c620e9beacd1c7f5d421c53625f88452b4b774a0bb65a7d633a7b44d106d",
    "description_fields": {
      "description": "Checks applicable subnet flow-log settings and matching Network Management configurations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "dca21636a2dcf0da9d8001cfd91087f555660fda82cdcc793d26afe789f7901e",
      "source_qualname": "flow_logs"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No applicable enabled flow-log configuration was found."
  },
  "gcp.reviewed.network.no_default_vpc": {
    "description_base_sha256": "f5a2ca9aa2698f39f3cb30c14f8533cfa8033f667de75d4be07f0056de6b3321",
    "description_fields": {
      "description": "Checks whether the observed network is named default."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "51e2cb35b21376a5cf39765234470e79667f207b9358d3ec16eee5ae20b72d41",
      "source_qualname": "no_default_vpc"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The observed network is named default."
  },
  "gcp.reviewed.project.os_login_2fa": {
    "description_base_sha256": "fed18ed2a734a137524224b5bdb703abbd2274c18e0400a42cf382109d70b24c",
    "description_fields": {
      "description": "Checks the project enable-oslogin-2fa metadata flag when Compute Engine is enabled."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "48b3290b77257fc7b445b5905eb11831853bbf67e0f913d9dd8c92fbecc911c0",
      "source_qualname": "project_os_login_2fa"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The project does not declare OS Login two-step verification."
  },
  "gcp.reviewed.sql.cmek": {
    "description_base_sha256": "ef8b56652a3b8e192a9e046dad9de4cfec4b4367cc17800aeb6d749fbad2f505",
    "description_fields": {
      "description": "Checks primary Cloud SQL instances for a customer-managed KMS key reference."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ca552bc511d74ca9711d161fbd6f16ad597fe235de8633bdf4855f50d4cc78eb",
      "source_qualname": "sql_cmek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The primary Cloud SQL instance has no customer-managed key reference."
  },
  "gcp.reviewed.sql.high_availability": {
    "description_base_sha256": "6ba36c0fe76f63385ad35e44e6d385d49bae6e4de35fd858e5481438e9b72c9e",
    "description_fields": {
      "description": "Checks primary Cloud SQL instances for REGIONAL rather than ZONAL availability."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5ff88206b48e4d2e9e04ff82b8a6e521cc65b55a97b7edc43aada63912d789c5",
      "source_qualname": "sql_ha"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The primary Cloud SQL instance uses zonal availability."
  },
  "gcp.reviewed.sql.mysql_local_infile": {
    "description_base_sha256": "de700887ff358c838f87701d49e5fa588b90bc11a443f58ec8e6434033988883",
    "description_fields": {
      "description": "Checks the explicit MYSQL flag local_infile for exactly off."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared local_infile value differs from off."
  },
  "gcp.reviewed.sql.mysql_skip_show_database": {
    "description_base_sha256": "309a480e9f923e68cce957311d7d2ab7099e21e653fc22e94e1c5bbf654c24ac",
    "description_fields": {
      "description": "Checks the explicit MYSQL flag skip_show_database for exactly on."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared skip_show_database value differs from on."
  },
  "gcp.reviewed.sql.postgres_log_connections": {
    "description_base_sha256": "665118a2ff4d7676fecd029b43e470d487fa6f057c63bf10dde7c8883c327a30",
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_connections for exactly on."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_connections value differs from on."
  },
  "gcp.reviewed.sql.postgres_log_disconnections": {
    "description_base_sha256": "cf47005a159eb0834c1702f1e06ee8b1f6871d775c42974b277a2d39fe192168",
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_disconnections for exactly on."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_disconnections value differs from on."
  },
  "gcp.reviewed.sql.postgres_log_error_verbosity": {
    "description_base_sha256": "57927e1f5743afdf244a77e6369f57c0fb7e362d2f2ef390038c13f24815480e",
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_error_verbosity for exactly default."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_error_verbosity value differs from default."
  },
  "gcp.reviewed.sql.postgres_log_statement": {
    "description_base_sha256": "1f5d5fc81283cf7ebd4ba5ec7bb83b34a238536b49efd0d9319e3af5ae5feda1",
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag log_statement for exactly ddl."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared log_statement value differs from ddl."
  },
  "gcp.reviewed.sql.postgres_pgaudit": {
    "description_base_sha256": "905c18b0e67d2cd06a69f261bd5fdd5d6cdd9080e47021cf853ab02c17ad5273",
    "description_fields": {
      "description": "Checks the explicit POSTGRES flag cloudsql.enable_pgaudit for exactly on."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0bd81d622be55cc051f8d32993d4a7627c0eeae1235667fccad90fc6b042b0",
      "source_qualname": "sql_flag.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The declared cloudsql.enable_pgaudit value differs from on."
  },
  "gcp.reviewed.storage.access_logging": {
    "description_base_sha256": "42aa0f1dba99f6f444eb8bf2a0b8e428b6d04098fb76f81475add953434ee08e",
    "description_fields": {
      "description": "Checks for a nonempty bucket access-log destination."
    },
    "remediation_base_sha256": "348244579a22481cb82e5c797c4f3ea94d2bdaefe82dd4c951eeb08761e1912c",
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
      "predicate_source_sha256": "5ca55acb9dfc4d8d561f5ea5fcb5d986cfcf3c96dba6abab1018a5bf0678e986",
      "source_qualname": "bucket_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket has no access-log destination."
  },
  "gcp.reviewed.storage.lifecycle": {
    "description_base_sha256": "89dcc975654f06ff7451deec2351061e26b51611b02bd7a45b27298683ce9059",
    "description_fields": {
      "description": "Checks for lifecycle rules with recognized actions and nonempty conditions."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "4b0a73c81bbb1497f46b2964e1bb47ca97da25c4c8032514a8e1192c71a2aa83",
      "source_qualname": "lifecycle"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket lacks a qualifying lifecycle rule."
  },
  "gcp.reviewed.storage.soft_delete": {
    "description_base_sha256": "2c65beec187bbd683612fc8bc9b95d9101c14b9681ad552d20e96bbc829b1ebc",
    "description_fields": {
      "description": "Checks whether the bucket declares a positive soft-delete retention duration."
    },
    "remediation_base_sha256": "59b3fa0a0b350db3acd825a66aaab5c90dfebabdede6504ddf2faf64dde90c04",
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
      "predicate_source_sha256": "ef428d0acf3a428434f8357473715ee328d5f619e07f2e10f75bb5a1c23d89b7",
      "source_qualname": "soft_delete"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket declares a zero soft-delete retention duration."
  },
  "gcp.reviewed.storage.versioning": {
    "description_base_sha256": "6b1746c64923d3c2dbccceefaf4665cc211a4e7c4cffa0895b743c2828425079",
    "description_fields": {
      "description": "Checks the bucket versioning declaration, including known omitted-field defaults."
    },
    "remediation_base_sha256": "2cd2b8df700e788e7f075c6f16930a6158f5eeda70f4f902896bc47be63d127b",
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
      "predicate_source_sha256": "464c4fd05fed7e931f59feb4a32cbde038fd6ae06ba0c590b2d0d7791839f89f",
      "source_qualname": "bucket_versioning"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Object versioning is disabled."
  },
  "gcp.sql.deletion_protection": {
    "description_base_sha256": "2e17a9da21d8c819068d55fc6a326982f372d0a15c464b44fbeeeae28596760a",
    "description_fields": {
      "description": "Checks explicit settings.deletionProtectionEnabled on instances from a complete scoped inventory."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "532ecd3a85da81bf8093cef40746b13f65124e77ee5bf7aab76b9d5c40fc4aea",
      "source_qualname": "sql_deletion_protection"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Cloud SQL deletion protection is disabled."
  },
  "gcp.sql.iam_database_authentication": {
    "description_base_sha256": "8a7f9fb94db7a2609d640830460c0e634a3ed85edf4408c9036ebd8405e86971",
    "description_fields": {
      "description": "Checks complete instance-bound MySQL or PostgreSQL user lists for CLOUD_IAM_USER or CLOUD_IAM_SERVICE_ACCOUNT entries."
    },
    "remediation_base_sha256": "d7f70e44822262d30a8ed9a0a097ee2e9bd6c97f59142e6c571ce95221737e38",
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
      "predicate_source_sha256": "56b81d0cf72517af5e0c3840f72b369439e0cd558f6468438fe37dca1379d3ff",
      "source_qualname": "_load_09.<locals>.sql_iam_database_user"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance has no direct IAM database user or service-account entry."
  },
  "gcp.sql.mysql_admin_account_posture": {
    "description_base_sha256": "7adbe7315dc887700a0f74b92b2db9bebaf9aaa549e4fed1394b6845e1ca7539",
    "description_fields": {
      "description": "Joins MySQL user metadata to its instance and flags root or built-in accounts with percent or Internet-wide host patterns."
    },
    "remediation_base_sha256": "11d7b8b17832bbe47b4f387af81ce91b741bdea28d4e04f698ea2586ae128a98",
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
      "predicate_source_sha256": "58db638b3ca725f39796bac960015fd7aaec3764f87488cdf8a59a8f9cc0f700",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A MySQL root or built-in account declares an unrestricted host pattern."
  },
  "gcp.sql.restrict_authorized_networks": {
    "description_base_sha256": "e85235250f9839413622151a3cb8c23c2999d85e75482af24ddae352a6558fcb",
    "description_fields": {
      "description": "Checks Cloud SQL authorized networks for 0.0.0.0/0 or ::/0."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "5d4229e9525d7148bead5519a088bd2ab642b7eceef8b18bd1f0f4d3aa4be47b",
      "source_qualname": "sql_networks"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Cloud SQL authorizes an Internet-wide client range."
  },
  "gcp.storage.no_public_iam": {
    "description_base_sha256": "38dbb0f5fa5bc273ccc5a111b14786c94962bbe090c930a891e860510e43e5a2",
    "description_fields": {
      "description": "Checks bucket IAM bindings for unconditional public principals, considering public-access-prevention configuration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "f087617beb91dd22f9f2df6a3646e34f88d344076884780e779d09255cd0e085",
      "source_qualname": "bucket_public"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The bucket IAM policy declares an unconditional public-principal grant."
  },
  "gcp.storage.public_access_prevention": {
    "description_base_sha256": "9d69b59a2f9d3f415d4ba77e4b18fdd790a729a3ce7338c53301224be5a23da7",
    "description_fields": {
      "description": "Checks public access prevention, resolving inherited settings through the project’s effective organization policy."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6317d85a6cdf0d1fc73c90f7958128b3a9605d9c621baa6324e9b12f22dce588",
      "source_qualname": "gcp_prevention"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The inherited public-access-prevention policy is not enforced."
  },
  "gcp.storage.uniform_access": {
    "description_base_sha256": "bd61009be4897d5c583f8de026138d4ade160841e9e11562972a3d4da5718229",
    "description_fields": {
      "description": "Checks the bucket’s uniformBucketLevelAccess.enabled declaration."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "695b1a4677cd80f611bb0f388579f19e77c3309fd9fbeb89e9b78c1deecfb2b8",
      "source_qualname": "gcp_uniform"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Uniform bucket-level access is disabled."
  },
  "gcp.subnetwork.private_google_access": {
    "description_base_sha256": "b16eb442b23c19112a638d87baba49d733870c7b9c375b20395af993b10f8661",
    "description_fields": {
      "description": "Checks the Private Google Access flag on applicable VM subnets."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "0f0a14e80532401589a10d71f241d7797f83122606d63c5a40172a1bd0253f98",
      "source_qualname": "private_google_access"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "low",
    "static_observed_sentence": "Private Google Access is disabled."
  },
  "gcp_api_keys_active_services_only": {
    "description_base_sha256": "ff8d93eca88dfd696414c5dcf595db91bf4efd836f62fd4392d07b1c6c17316e",
    "description_fields": {
      "description": "Checks undeleted keys from a source-bound inventory for specific API target declarations."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "44f40e6bf0458cebc88b7627ec7dd9eb43651c19b9e7f43d76b3d5617f646f3e",
      "source_qualname": "active_api_key_targets"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active API key has no API target restriction."
  },
  "gcp_autoscaler_capacity_target": {
    "description_base_sha256": "db2c30bca260bc2f7788cd178d5fb827f7dff11c55b27dd20244f7923844fa73",
    "description_fields": {
      "description": "Joins the autoscaler to its group and checks CPU target above 80% or no capacity above targetSize."
    },
    "remediation_base_sha256": "9c5c63eb0034a22f38194e5ef7b5d19fc44283b72f0ba908f908a73ae3d28496",
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
      "predicate_source_sha256": "3c7930cc2843aacd7bb02ff1791d8e1b09f5fa8ec169af2784fea951d442543d",
      "source_qualname": "_load_09.<locals>.autoscaler_capacity"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The autoscaler CPU target exceeds 80% or its maximum leaves no declared growth capacity."
  },
  "gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3": {
    "description_base_sha256": "87c072c624f4f112512882e86fced2512f16c71c78f62e2ee33dbc88269a5011",
    "description_fields": {
      "description": "Checks attached Cloud Armor policies for a nondefault-priority rule with a nonempty match."
    },
    "remediation_base_sha256": "75f6b1f6337b204524e3c9a12e3116437206b897bd6eb3447aeea593bebedd5c",
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
      "predicate_source_sha256": "dbc4dfa6df286cf79e875af6e9a51890044767e5d707be08e00341208bf74ce5",
      "source_qualname": "_load_51.<locals>.armor_nondefault_rule"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The attached Cloud Armor policy has no qualifying nondefault rule."
  },
  "gcp_bucket_logging_enabled_fb7cc594582a": {
    "description_base_sha256": "8d25e65020c26fe8d9d15f634a7be076ad5972876125413b1483bfbf97a89024",
    "description_fields": {
      "description": "Checks the full bucket configuration for a nonblank usage-log destination."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "a421e3ea85643f643c99043ad6ea0b9384ced13e63f9ef891aad144fd9ed6f03",
      "source_qualname": "bucket_usage_log_destination"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The bucket has no usage-log destination."
  },
  "gcp_c5_log_event_fields": {
    "description_base_sha256": "176b1ad3405dd3aa028a03c5b976a5b33a972c310e886c47b34da6ed5c92b3e0",
    "description_fields": {
      "description": "Checks classified authenticated audit events for a timezone-aware timestamp and nonblank principal email."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "ba54290be26fb939cc9050152da3b269a53b6486313037a52b06cbaa444d0c55",
      "source_qualname": "c5_log_event_fields"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The authenticated audit event has an invalid timestamp or missing principal email."
  },
  "gcp_c5_sbom": {
    "description_base_sha256": "9984aec494b32e7d4df5052776c04e2286d41095469ce4fda9d0652853232da1",
    "description_fields": {
      "description": "Joins deployed image digests to repository images and SBOM_REFERENCE occurrences with note names."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "abbfb5037c519417d8887bc8bec14caa6ed656050b17c045280ce0a9cd78e829",
      "source_qualname": "c5_sbom"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A deployed image digest has no matching SBOM reference."
  },
  "gcp_certificate_renewal_30_days": {
    "description_base_sha256": "a28afb67e8a012a617e79432133a45e888bd4b290bdcae32860d00263e976db6",
    "description_fields": {
      "description": "Checks deployed managed certificate replacements against the 30-day-before-expiry threshold with a 24-hour grace window."
    },
    "remediation_base_sha256": "efb623a4f81188114d84af1938050ff12fe3a9d5719406e57916202313bb9419",
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
      "predicate_source_sha256": "232092033282ad414aa5317b81d0c4e8c719903a1d0b2244967b8c7647e3b2bc",
      "source_qualname": "_load_54.<locals>.certificate_renewal"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No timely ACTIVE replacement covers the deployed certificate’s domains."
  },
  "gcp_certificate_rotation_180_days": {
    "description_base_sha256": "47c8958110421c74251912bd873873c27cb1a3af2007423c52e57e2d9757ae24",
    "description_fields": {
      "description": "Checks deployed ACTIVE managed certificate creation age against 180 days."
    },
    "remediation_base_sha256": "8c67de9889f54870631c61270029f880b61d2a6dafeacd6b496cc33404e48428",
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
      "predicate_source_sha256": "78ba491d6730a8d9712524b123c923ea813896f9b91ca57e60718ae28bfeab05",
      "source_qualname": "_load_54.<locals>.certificate_rotation_180"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The deployed ACTIVE managed certificate resource is more than 180 days old."
  },
  "gcp_certificate_rotation_90_days": {
    "description_base_sha256": "8e9ece672dcaf09c6379b54c5a7f0d97c18466c9d7fe646e5b45d29b2b1737b3",
    "description_fields": {
      "description": "Parses the leaf certificate issuance time and compares deployed certificate age with 90 days."
    },
    "remediation_base_sha256": "352f1f96075911b6e5379b1b30090d714e581382630956ccbfeb0b732482d670",
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
      "predicate_source_sha256": "75e24b1507d8888a9f9fa2fdd75c0b54eaca955f1e466e516b900aff9827ab9b",
      "source_qualname": "_load_54.<locals>.certificate_rotation_90"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The associated deployed leaf certificate was issued more than 90 days ago."
  },
  "gcp_certificate_validity": {
    "description_base_sha256": "aa46baf1571c43209c39b26b2d32bd6d62e62d7ec9d7330aa0c872d09c2dc3a4",
    "description_fields": {
      "description": "Checks certificate expiry against collection time and requires ACTIVE managed certificates."
    },
    "remediation_base_sha256": "04fb62096db204ffec9ac1c791adff3833fc94c0840f5167c7f6e32e03d4af09",
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
      "predicate_source_sha256": "e4530346c528ea6c6573122bb6425c898dcb62daa07359e65c219de9b602a328",
      "source_qualname": "_load_09.<locals>.certificate_validity"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The certificate is expired or its managed state is not ACTIVE."
  },
  "gcp_cloud_armor_waf_enabled": {
    "description_base_sha256": "e93c6d22dc9c05b6d9d61b27ea00f8321e92044de5236e42a8643fe4d20d8189",
    "description_fields": {
      "description": "Checks the attached external-backend policy for an enforced preconfigured WAF deny rule and an earlier bypass. It evaluates declared configuration, not public reachability or blocked traffic."
    },
    "remediation_base_sha256": "c30353f4e20ce0b44faccb075a6fd293ca6226be1c419ec835ca28aa194e5980",
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
      "predicate_source_sha256": "0c5951530a2ac5e3b139f7e1297462bb14ebeee54237d9d9555da87f27e69424",
      "source_qualname": "_load_52.<locals>.cloud_armor_waf_enabled"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The attached external-backend policy lacks a supported enforced preconfigured WAF deny rule."
  },
  "gcp_cloudcdn_cookie_ttl": {
    "description_base_sha256": "de08a739fd4a4098839d0bbaf0ca3da57a2d9de98ac2c22f3c9f7015f14fbb6f",
    "description_fields": {
      "description": "Checks GENERATED_COOKIE or HTTP_COOKIE affinityCookieTtlSec for at most 1800 seconds."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "01bf2ff2f32c877c907de32303ca6ca8346b409ad3655b920631df7eff925d55",
      "source_qualname": "backend_cookie_affinity_ttl"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The backend affinity cookie duration exceeds 30 minutes."
  },
  "gcp_cloudsql_backup_failure_alert": {
    "description_base_sha256": "1f1947112bc38c030b286704b73fa089f385400dcbe0a48b525f208210ff8c57",
    "description_fields": {
      "description": "Checks native local alert declarations for failed Cloud SQL automated-backup windows; unsupported filters or thresholds remain unknown."
    },
    "remediation_base_sha256": "3947090a6608694b697045d385336d80c21d9e343f8a2226cf47f97f61ea96f4",
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
      "predicate_source_sha256": "db939ded69928487b29c549a93fa29143249c19a4d1b0de243189ea70abe077d",
      "source_qualname": "_load_53.<locals>._evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No enabled local alert for failed automated-backup windows was found."
  },
  "gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d": {
    "description_base_sha256": "8dcfabe88a6a3f646ddb04c8817c2d682b8281c36c9ec3182e372d61e84850b9",
    "description_fields": {
      "description": "Checks every cluster in the complete scoped inventory for explicit public IP endpoint enablement."
    },
    "remediation_base_sha256": "c41b4b90797874a9e3349a1321097722f0ed627e3ecdd4f5197f59c82d3b5d8d",
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
      "predicate_source_sha256": "73ba3deeab1bb2541c8184fcd12a1d2f29db6de02df8d8b571accf26bbdc36a3",
      "source_qualname": "_load_ke.<locals>.gke_public_ip_endpoint_disabled"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A cluster explicitly enables its public IP control-plane endpoint."
  },
  "gcp_gke_small_cluster_auto_upgrade": {
    "description_base_sha256": "76d68ef2155a6e342c0fe387b0616245de3ba78f4f5decc91555048c46ab2a4f",
    "description_fields": {
      "description": "Joins node-pool instance groups and flags disabled auto-upgrade only below three target nodes."
    },
    "remediation_base_sha256": "dca63f1e0095db0c381258d68f2be04824afc6b77cc0ec9d52f15df68aa641ef",
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
      "predicate_source_sha256": "9637b15211535769a296105b0540945cb31a0611d4489d7f0b37e6755575f343",
      "source_qualname": "_load_54.<locals>.gke_small_cluster_auto_upgrade"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The cluster targets fewer than three nodes and a pool disables auto-upgrade."
  },
  "gcp_https_proxy_mtls_required": {
    "description_base_sha256": "49485d0551c44550df07e2dec6cb89aab2b3ac37bad54e5bd753a8f19c981eda",
    "description_fields": {
      "description": "Joins the HTTPS proxy to its server TLS policy and requires REJECT_INVALID client validation."
    },
    "remediation_base_sha256": "98d7e01dac71b1da78b29d45d5ec5a44fbae777943aae9fc0f90dce64e2b0f52",
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
      "predicate_source_sha256": "a9993bb7aab315c74e481d525c9e3907c999d0adaf38065ecd6ddc96e113c6c3",
      "source_qualname": "_load_09.<locals>.https_proxy_mtls"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The HTTPS proxy lacks a strict client-certificate validation policy."
  },
  "gcp_kms_key_destroy_alert": {
    "description_base_sha256": "9c4bd8ed72e52d9c8bece1a2e95b1d6fd9fcd9589bb80727bc21efac9112916d",
    "description_fields": {
      "description": "Matches the native DestroyCryptoKeyVersion audit event to an enabled, valid positive-count metric alert in the selected project."
    },
    "remediation_base_sha256": "31647bedf3cd96c4264ba9b89c09f9e7c53ed0d9d269b8344a4f5873b2f78b41",
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
      "predicate_source_sha256": "771eeecb955d44c32d23c3c4e393dd04eacf796421f82ce36aa5901bc6a8732a",
      "source_qualname": "_load_54.<locals>.kms_key_destroy_alert"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No qualifying local alert for Cloud KMS key-version destruction was found."
  },
  "gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650": {
    "description_base_sha256": "b2c0f107a503d68638dadae2f10aef462252ce9903b481f6ffdf5834f8d042e3",
    "description_fields": {
      "description": "Joins the key to its versions and checks for DESTROY_SCHEDULED states with valid destruction times."
    },
    "remediation_base_sha256": "6bd97a0f4d39270149852519f897d5995a7fc00623d2a3604834b6bd9aa30b3d",
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
      "predicate_source_sha256": "2a3d1eeae030f384d26971154814c49529b9b6501acf4f826d511f953c9fb07b",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A key version is scheduled for destruction."
  },
  "gcp_lb_server_header_rewrite": {
    "description_base_sha256": "17adb86ddf31a32d0609b021e2586a38f003108702aa6304f817670f7f0fac05",
    "description_fields": {
      "description": "Checks complete effective routes of public URL maps for a replacing Server header set to lb."
    },
    "remediation_base_sha256": "53f903beb8276c3e8bb29a7721f4530c3cbf2e25dd9c924f2517f644dfa2570e",
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
      "predicate_source_sha256": "bc50e0110cf3e6ea83d215bced506c8c0e5c5ecca5507c93ecc5775c0a900e41",
      "source_qualname": "_load_52.<locals>.lb_server_header_rewrite"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A public URL-map route lacks the profile’s Server: lb replacement."
  },
  "gcp_logging_detect_t1110": {
    "description_base_sha256": "56551971ec8f647ac18027039c1827af7be52c7782c78c79830925277456a8cf",
    "description_fields": {
      "description": "Looks for more than nine failed classified authentication events from the same principal and caller IP within five minutes."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "98459ac93d78245bf1678426de8c05ed47414ad1fa436412932cb81bc45038db",
      "source_qualname": "_evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Repeated failed authentication events exceed the five-minute burst threshold."
  },
  "gcp_logging_enumeration_alert": {
    "description_base_sha256": "d9dc748a469af7f6026fc9f1c91b32428c9a64cfe9b96b9976084f7bc734f3f1",
    "description_fields": {
      "description": "Checks the exact list/get metric filter, principal extractor and a five-minute threshold alert at ten or fewer events."
    },
    "remediation_base_sha256": "12d99bc8936b3e8c6a554e3745bfba77a24db3c19f28b4b043923ed89a18a8de",
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
      "predicate_source_sha256": "5e710f318d9f13dda47f72fb3abb2cb00d67bb50184024c6ac3dc98fce09b51c",
      "source_qualname": "_load_54.<locals>.logging_enumeration_alert"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No qualifying principal-grouped enumeration alert was found."
  },
  "gcp_pci_asset_6ee2fef37d98": {
    "description_base_sha256": "32f1d67921f30a80d01c722bd4013cb5f805dbea457dc4cf6a113b74931178dd",
    "description_fields": {
      "description": "Checks the Logging bucket retentionDays against the configured threshold, defaulting to 365 days."
    },
    "remediation_base_sha256": "23c29340fb7ccd0e85aaca36bb5ea8ab4d9a3994b8659267a7cc9ecf8ecd5c38",
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
      "predicate_source_sha256": "078544b8e8836af3313c788eb0002b41f5c540e030e34ec37d1c8fa255d34534",
      "source_qualname": "_load_08.<locals>._install.<locals>.check"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The Logging bucket retention is shorter than the profile threshold."
  },
  "gcp_pci_backend_service_2ce96d36d0bf": {
    "description_base_sha256": "10b3cd6fdb4886c8e115531e74a8e041276323035f36bb5d5a2b9323e00e0cf2",
    "description_fields": {
      "description": "Follows CDN backend URL maps to HTTPS proxies and checks minimum TLS 1.2 or 1.3."
    },
    "remediation_base_sha256": "2b2ee3b38db0fbeab92c3b2b7370e4e0882d1f43cc18a7cd19fed6e4908b83c9",
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
      "predicate_source_sha256": "6ebc779a08531c1adee4e977ab60dd6571e357c8d4a195fc4e0927447cc58751",
      "source_qualname": "_load_51.<locals>.cdn_viewer_tls"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An HTTPS proxy serving the CDN backend permits TLS below 1.2."
  },
  "gcp_pci_bigquery_dataset_6017267cdf32": {
    "description_base_sha256": "bae39d61699f8821a4eb1149edf6aa273a4924276ebb263de0c1cc94a60e2d76",
    "description_fields": {
      "description": "Checks full dataset ACLs for public READER or WRITER role entries."
    },
    "remediation_base_sha256": "a121d2e7254828db1b9fc4d531b49383757d91c2f200e45d0061491df69a26ae",
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
      "predicate_source_sha256": "4d6e2282fa095e443fdd559ae58837e5490c4124f7981b2dde2bdabdb44a63b6",
      "source_qualname": "dataset_no_public_read_write"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset declares a public READER or WRITER ACL entry."
  },
  "gcp_pci_bigquery_dataset_a4e25dbf9640": {
    "description_base_sha256": "89fcab4104305e65ee30da48d43c8d2e7849951a60c67901d7c0840989630044",
    "description_fields": {
      "description": "Checks full dataset ACLs for the exact specialGroup=allUsers and role=READER pair."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "f754068ff3f29c48c220094851da457b6626a51cb0ccb14bb36191e6ccacb615",
      "source_qualname": "no_anonymous_reader"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset declares an allUsers READER special-group ACL."
  },
  "gcp_pci_bigquery_dataset_fb9fcc01d5b7": {
    "description_base_sha256": "8d95b22320838ec45b4d91ce8ecfb6bb5e7649c36a7b015aac45f20a9eaa29a2",
    "description_fields": {
      "description": "Checks full dataset ACLs for any role assigned to allUsers."
    },
    "remediation_base_sha256": "0d83813a01d613de4e2a5cfaf7cc411db7fb889a279a6c268db8d3434aa93864",
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
      "predicate_source_sha256": "f3da42b38490203de0ccc4cfdee12fbfbf49b11fb226497798436738deee4cc6",
      "source_qualname": "dataset_no_all_users"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The dataset ACL assigns a role to allUsers."
  },
  "gcp_pci_bucket_0742bd5dc32c": {
    "description_base_sha256": "1bd56f7f44ddd1b1b630b8fb9690fb7ec4c1a9443e885e6ecc25a20f0dcc8127",
    "description_fields": {
      "description": "Checks versioned buckets for at least one supported lifecycle rule with a nonempty condition."
    },
    "remediation_base_sha256": "f292f429b1dd3c26c90c4715de6ed8d1875301268d0d9ee4ced1378bb8e5a65b",
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
      "predicate_source_sha256": "6bc6473c5c3acee07d7e3b9db33bb9c313b2d9aea0d0d705eb46a84c571dd46c",
      "source_qualname": "bucket_versioning_lifecycle"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The versioned bucket has no supported lifecycle rule."
  },
  "gcp_pci_bucket_157fb0c69361": {
    "description_base_sha256": "1daefffd4e46b04e5b68c41a2e2c0b688cb449f7be39d01be477e4d8d0149080",
    "description_fields": {
      "description": "Checks known local and ancestor public read IAM roles and complete active bucket or object ACL read grants."
    },
    "remediation_base_sha256": "181a43c9ccc3ed881d8da9a6bed4ec147e65d8ff2bcbfe5a4b90ba4f4656e9dc",
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
      "predicate_source_sha256": "2d0622b5e6478316a5d598df9fb5c7169951f443c57a31d56af52dead4fac6b8",
      "source_qualname": "_load_50.<locals>._evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The bucket declares a known public read grant."
  },
  "gcp_pci_bucket_3d76b0b0701e": {
    "description_base_sha256": "362cce1d60a17cbfaf883b32c45ff010ea44d1a20390a5c01c87a5f8d095561d",
    "description_fields": {
      "description": "Checks versioned buckets for a positive retention duration."
    },
    "remediation_base_sha256": "41981b601cd19def87b908bbbafd902f1b362a4738263cc1f6c16c3b29965aad",
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
      "predicate_source_sha256": "56786fa515850f234cfac1db5ffea82419449261b69ec26a1e47af5566b70286",
      "source_qualname": "bucket_versioning_retention"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The versioned bucket has no positive retention duration."
  },
  "gcp_pci_bucket_56c6b1b7f813": {
    "description_base_sha256": "e384cd48ca76026f448d0af061d866e3cb16e1b0e431f26aea3627a303dbac7e",
    "description_fields": {
      "description": "Checks known public write IAM roles, effective-use projections and active ACLs for object-write grants."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "6a982e661984c8686c70b697d0a7e7c262c850a4fdb2f7fb5396b16bb403c51a",
      "source_qualname": "bucket_public_write"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The bucket has a known public object-write grant."
  },
  "gcp_pci_cloudbuild_trigger_3302edf7cb18": {
    "description_base_sha256": "896671484aecf12c0f839bdc64fe05310f81017a05c548734fc30e9ee0bad8a4",
    "description_fields": {
      "description": "Checks enabled inline triggers for logging=NONE, using LEGACY for proven omitted settings."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "eb6cc04f068012eeb281f869615c51dd7b6ceb3e3a6e90197146b6a2b6393570",
      "source_qualname": "trigger_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The enabled inline build trigger declares logging=NONE."
  },
  "gcp_pci_firewall_2080b14f1361": {
    "description_base_sha256": "856980c13052dd1b1ef9175ca16bc8a51bb1773631c07804fcff5f78d8009600",
    "description_fields": {
      "description": "Checks full active ingress allow rules for Internet-wide sources and any declared allowed protocol."
    },
    "remediation_base_sha256": "70156462ec809aa328f644766ed066589e86f5e7e225a702ba81e416b2944b1b",
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
      "predicate_source_sha256": "39165e19d7e7592171321fed159503abedd30513ea01a5b1a0430aeb7c2eefe5",
      "source_qualname": "_load_09.<locals>.public_ingress_firewall"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The firewall rule declares Internet-wide ingress."
  },
  "gcp_pci_instance_template_2e26bed500fc": {
    "description_base_sha256": "744cec3587feb043c661291bbd104e3ce9823caaa78e939c7148588823b9175a",
    "description_fields": {
      "description": "Checks template network interfaces for nonempty IPv4 accessConfigs declarations."
    },
    "remediation_base_sha256": "3ad72153391a584469920f27ec0d830bfdfd9ea03246ffac9fa30c7e3c97251b",
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
      "predicate_source_sha256": "ed6eb881af82605d50e46c6e3bb74645f2d367e05b8b10392ce266099ad9b1a6",
      "source_qualname": "instance_template_no_public_ip"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The template declares an external IPv4 access configuration."
  },
  "gcp_pci_kms_key_a3927a5f3b84": {
    "description_base_sha256": "c3acca0361bd59ead3d0d535671b53ccc22b47c20d6cc4a6667c40df0566a72c",
    "description_fields": {
      "description": "Checks complete effective KMS-use projections for public principals or more than three listed principals."
    },
    "remediation_base_sha256": "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
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
      "predicate_source_sha256": "3569e0dc47d4c4e45971533d94aba1624f1151583eba7f76321836bd395a8022",
      "source_qualname": "kms_effective_users"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The KMS-use projection lists a public principal or more than three principals."
  },
  "gcp_pci_url_map_9ed56c323a05": {
    "description_base_sha256": "9520d15273fb35b8654fa6ec9670d45602ceb55b37fd407fcf2d935982ad8cb4",
    "description_fields": {
      "description": "Joins active HTTP frontends to URL maps and checks enumerated default and path redirects for httpsRedirect=true."
    },
    "remediation_base_sha256": "865b26ac7c782096e9157d520c310da94084c902d797af75e86817381bab9c44",
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
      "predicate_source_sha256": "5be74eedba0b044809fcc0884e2d875bc669210f0186fd38ca979e36fd27fc55",
      "source_qualname": "_load_52.<locals>.pci_url_map_redirect"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An attached HTTP URL-map route does not declare HTTPS redirection."
  },
  "gcp_pubsub_topic_cmek": {
    "description_base_sha256": "7d472eee6f4765fc8e230d7f54863cdd6e053135f190d66ca3391a4a449c86fe",
    "description_fields": {
      "description": "Checks the full Pub/Sub topic for a nonempty customer-managed KMS key reference."
    },
    "remediation_base_sha256": "072489af424fd4bf45b78fc16dda4359f8635b39926d2cbe10c0ef56063fc231",
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
      "predicate_source_sha256": "17fb832243176dbc40e92a7934e36d43c79f1d9cc4e14b450209bd2d7b3c9f56",
      "source_qualname": "pubsub_topic_cmek"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The topic has no customer-managed key reference."
  },
  "gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6": {
    "description_base_sha256": "2a2d1273d7a5392798e693bd7ea751ab0fa00239ce30bfb45c3bb918104d2fb5",
    "description_fields": {
      "description": "Checks the engine-specific MySQL or PostgreSQL IAM authentication flag for on."
    },
    "remediation_base_sha256": "021351212c05070a3aa7a3bb9a06265a09fac47d60da338893b7b692a31cce97",
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
      "predicate_source_sha256": "335c7b9c7a489e2eedcfe439aa973741703dca0bd068a0339c3993f4b2c9c6b8",
      "source_qualname": "_load_09.<locals>.sql_iam_flag"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The instance does not declare its IAM authentication flag on."
  },
  "gcp_sql_trace3625_off": {
    "description_base_sha256": "ecfaf9634ccc42a3924fdd8ff326e58d5c42ba3760ee6e24bbbc7dbba5337b4b",
    "description_fields": {
      "description": "Checks SQL Server trace flag 3625 and flags on under the legacy off profile."
    },
    "remediation_base_sha256": "66f1628047501dfae6e68b5eccb08659b1bdbf5f5612dbfff35ef6b13babc132",
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
      "predicate_source_sha256": "15e2955aa4a37978cdef414f463e8d2cfe5f7217829ab1feb196c667ce5087db",
      "source_qualname": "_load_09.<locals>.sql_trace3625"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Trace flag 3625 is on, contrary to this legacy off profile."
  }
}
''')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    if kind == "description" and check_id in ("gcp.claude.service_account.recently_used", "gcp.claude.service_account_key.recently_used"):
        from peaso.unused_iam_gcp import reviewed_description_successor
        successor = reviewed_description_successor(check_id, original, row["description_base_sha256"])
        if successor is not None:
            return successor
    if _digest(original) != row[kind + "_base_sha256"] or (not isinstance(original, dict) and not (kind == "remediation" and original is None)):
        raise ValueError("Reviewed GCP clarity base changed: " + check_id + " (" + kind + ")")
    updated = deepcopy(original) if original is not None else {}
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
    if review[0] != source_severity:
        raise ValueError("Reviewed GCP source severity changed: " + check_id)
    return review[1]


# Exact admitted extension cohort; independently owned copy and native fixtures.
NATIVE_EXTENSION_REVIEWS = json.loads(r'''
{
  "gcp.compute.os_config_fixable_vulnerabilities": {
    "admission_sha256": "026df0e60b8c5db0ecb0a5abc076d871a0d4375b49b16cff352e731338cf4795",
    "copy_catalog_sha256": "f6d236d35da7f2cc42dcd8000d9272d3c34795337d6c354186946dfc09639b20",
    "fixture_sha256": "094fd5156694c9a8d8dd2a81a57571999ce9083227782f710a67a7ddbefe560b",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_os_security_update_fixtures.json.gz",
        "sha256": "933d8f0acdb115994609ec768fbb87a5c50982b55dce8278009e4cbed0786db7"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_os_security_update_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "b2329dc4fa4389cf81dc687d96be2e9877270d12e8bfdc499ba89afb09d7a649",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_os_security_update_review_20261019.py",
    "source_sha256": "f0d1942d5701f20cdeed4da36cd0baa02b818bd0ca7d169bae8df7275a87408f"
  },
  "gcp.review.app_engine_version.literal_environment_secret_indicators": {
    "admission_sha256": "2be25798f8972e791494e2c853738f0340e00f9dbfafa73111b2ef8ddd544726",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "3664fdb983f8a5d67bcf02936b86ca9c54f6d24b21de6793a2b0cdef2afeb2a2",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_additional_literal_secret_fixtures.json.gz",
        "sha256": "e5a8dda25d2d3ba103376d9462b2ef44cbcf622da57f84fbb2f6b387e96e6953"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "app_engine_version_secret",
      "module": "peaso.checks.gcp_additional_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "appengine",
      "predicate_source_sha256": "984f8b21afccc3abf35b0be5ac8e1f6978ae793e215b0dc4f507fc922edb9e55",
      "source_qualname": "appengine"
    },
    "source": "peaso/checks/gcp_additional_literal_secret_review_20261019.py",
    "source_sha256": "db1e168a8499fde496bc2c1550b76c32d86133c45702096bd081b57675c1a2b4"
  },
  "gcp.review.artifact_image.content_secret_indicators": {
    "admission_sha256": "df9d14c2fa14dadb0cb35c92a36a013f0699cc49499d6a5515dc01482244068b",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "6d43e9e8b618c39c0956acba54737ea4fba3c9618c4e9844a4e2dd46651286f8",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_image_secret_fixtures.json.gz",
        "sha256": "43f37613977f0dd8ae83ca30557a23775074a48e2d54204a76b252552a056c42"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "artifact_image",
      "module": "peaso.checks.gcp_image_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "3e7924e4bccdd5aa1ea83b3e9254deffce20b7322d528e640ba0afafd9c45866",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_image_secret_review_20261019.py",
    "source_sha256": "83fe957437bdb4a8142361bc4329af903dede65cb2e0242d2c35cda5211c79fd",
    "native_source_integration_review": "docs/gcp-review/cloudrun-image-integration.json"
  },
  "gcp.review.artifactregistry.selected_file_secret_indicators": {
    "admission_sha256": "8b3db5bb266772fc0ee4cde6419909f6c8dc3b88f5ab6b53bc5f9efd98258b4a",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "6b59067ce79952ba3c2b764838b395d57804f9cb1223971a91d71ebb90b60245",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_artifact_file_secret_fixtures.json.gz",
        "sha256": "be8b74e08f4ebd873ce3cf8a3bb1a5404ef378f9f94891ee9a1bd6276d3af894"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "artifact_selected_file",
      "module": "peaso.checks.gcp_artifact_file_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "6f4b7c50441776d28a7a4e06f8610bf3b79ea0c9984e11cc49326d7479e5d3a6",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_artifact_file_secret_review_20261019.py",
    "source_sha256": "0fe7d4fcbcd953d913e2ffa1df5b08573f01c8527ff333d351ddd3e037b36e54"
  },
  "gcp.review.batch_job.literal_configuration_secret_indicators": {
    "admission_sha256": "e1e1cf1548213e302c8ebb918b2b19c285eeedad295a1f87bb5b6a3233473b41",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "b27b452e05074a6c373a3daa7fb3923d4cc1bf45e1ef2827d0c757df66cfaee9",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz",
        "sha256": "351d21bf4b7c7701e7d9125897873e436a52f0bfab10232e688479257981454e"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "batch_job",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "0044fd7b54fcad9621302f083b58f07f578d57be039dfeb076083bf550edaa92",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py",
    "source_sha256": "1710755805361a8f035aef2c64d6ed6a432a64a598966d265e2c589fa42313dd"
  },
  "gcp.review.cloudbuild_build.literal_configuration_secret_indicators": {
    "admission_sha256": "0335a0b853382ba1081a50b8e14a2bd0f5711c28ecd75b9b2f326cc51ba40fae",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "5dd1da77946194a2ad82f1d723857e0d884100e89059c995dc5615463106b892",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_build",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudbuild_build",
      "predicate_source_sha256": "c1f24882bca17f78ef1f94d91123d6c8762df9ba5beb03135d6ebe2563396992",
      "source_qualname": "cloudbuild_build"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.cloudbuild_trigger.literal_configuration_secret_indicators": {
    "admission_sha256": "7e1975fbee9aa99ed97524885651beb1ea50d914fdf07d027619306689d8cebc",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "9606eb1a54a888e12bcb20bdaca9c5d63dc933ec723b8cd7634d2aa5e13161be",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_trigger",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudbuild_trigger",
      "predicate_source_sha256": "d1c5d88a8fd2c3c8208cf92c4423694da60e6ebe9e01a0569eb75c69d1805d66",
      "source_qualname": "cloudbuild_trigger"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.cloudrun_job.literal_configuration_secret_indicators": {
    "admission_sha256": "9ea35f881a4ed3e55f31ab3e19c5c0184a7b853a9c5b63b19d970802ee376e63",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "aff71e7c8c26f3a093dad4e9fff5e41ac24a068798886f5b9503e9fa1e374e10",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_job",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudrun_job",
      "predicate_source_sha256": "2abbe88efdbd723e407bc71186dcc6d3857b5bedf4b95e1710125d2a0b78d3d9",
      "source_qualname": "cloudrun_job"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.cloudrun_service.literal_configuration_secret_indicators": {
    "admission_sha256": "8345c5ae651bdcfe082a17163075e3400d51ad5e5d444d85937c69d70d3e3bbd",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "470ac3ab060d75a0c24d00d36216a7ecccc7f6cd8a31f0fdb9b3115e3daf54e5",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudrun_service",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "cloudrun_service",
      "predicate_source_sha256": "7691998e9ab66d23fc1ca418699c1ffe369e215853affb33bb3920d770b79d3d",
      "source_qualname": "cloudrun_service"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.composer.dag_source_secret_indicators": {
    "admission_sha256": "1fe0bcb7e068019e0556ae3b987cd0fcbc4b30e36ed861881b140ece4a0cefe8",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "40d6cc580165450ca78eb475f684a3860f446d2919dbf20159ef9cce2237ae45",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_composer_source_secret_fixtures.json.gz",
        "sha256": "430911930ba429c127d1ee6f71b0c56e2afca14f6db8f5d7944b7c1f5fa50afd"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "composer_dag_source",
      "module": "peaso.checks.gcp_composer_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "f85e0b7feb17116f32cb5f8f3b030c549e00fbbcd6e8c2635da5c52957ff7acf",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_composer_source_secret_review_20261019.py",
    "source_sha256": "d176034b246ff2f901e767f52d3c02832ec192766f361e552852d579dd567027"
  },
  "gcp.review.composer_environment.literal_configuration_secret_indicators": {
    "admission_sha256": "a14778051d66f83609f23bc9049ab4d33bc13ed62bf5fa9dbc05473d55c599c5",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "63263252eac04638893d9a6b23b2e70287ee4a5ffcdf27ab47feb8baf8f8fe30",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_notebook_airflow_secret_fixtures.json.gz",
        "sha256": "5b401634d4af7e5ce05a66943c3b19805f84542cbda32129f226158a93c97ec5"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "composer_environment",
      "module": "peaso.checks.gcp_notebook_airflow_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "b56a4950a0377a0269e28d65d2714d63870d22320b676b1f724d795be36fffc4",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_notebook_airflow_secret_review_20261019.py",
    "source_sha256": "86cc47cb8583d5a0ba81a4e131e49362fb505b8da463aa76f8ede268068c5a2b"
  },
  "gcp.review.dataflow_job.literal_configuration_secret_indicators": {
    "admission_sha256": "a8048e9d0a674a186448018793eb859dce0cc8d08bb04f901ac930e2a1f058e0",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "4943a96083b782b3acc5a30c00645c9063257a6f1d0622fa5b604451eabbdeee",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz",
        "sha256": "351d21bf4b7c7701e7d9125897873e436a52f0bfab10232e688479257981454e"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataflow_job",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "0044fd7b54fcad9621302f083b58f07f578d57be039dfeb076083bf550edaa92",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py",
    "source_sha256": "1710755805361a8f035aef2c64d6ed6a432a64a598966d265e2c589fa42313dd"
  },
  "gcp.review.dataform.selected_file_secret_indicators": {
    "admission_sha256": "4c1374b4162114f6914274429a1a48d742ab4d285659a7e0c367f88c680d0e72",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "0665a89e0a8d93fb901da2cbf7933b9b9a110204752645d9c14fd4e7be39b9a0",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_dataform_secret_fixtures.json.gz",
        "sha256": "659dad36fb1c6bd45c8c2f1a53198300375c6141dae0aa8db1bc764908096b06"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataform_selected_file",
      "module": "peaso.checks.gcp_dataform_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "b335ad9219d20acd1bf1bec018d2078b144f1778655aed2634e61f91173d908f",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_dataform_secret_review_20261019.py",
    "source_sha256": "df2bbc09817426dcba2ea4f54c9b574539b1e197131218b86614cf48a21faf3a"
  },
  "gcp.review.dataproc_cluster.literal_configuration_secret_indicators": {
    "admission_sha256": "d7c29e63ff333d5049c92946c512fe2753b4e11d581d6e81ddd7afd9723b3a8c",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "26653c541699cc48abf7dda10ba02105e792c4276e73ab03331d5dc8236f27dd",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz",
        "sha256": "351d21bf4b7c7701e7d9125897873e436a52f0bfab10232e688479257981454e"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataproc_cluster",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "0044fd7b54fcad9621302f083b58f07f578d57be039dfeb076083bf550edaa92",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py",
    "source_sha256": "1710755805361a8f035aef2c64d6ed6a432a64a598966d265e2c589fa42313dd"
  },
  "gcp.review.dataproc_job.literal_configuration_secret_indicators": {
    "admission_sha256": "ff73967a6743bfbf691867126e11904487dd772cc175509c2842f1ab878e1571",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "147aca938c54c270540f9f943c39ad70941e828929f452322abefd2afaad297b",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_job_literal_secret_fixtures.json.gz",
        "sha256": "351d21bf4b7c7701e7d9125897873e436a52f0bfab10232e688479257981454e"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "dataproc_job",
      "module": "peaso.checks.gcp_job_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "0044fd7b54fcad9621302f083b58f07f578d57be039dfeb076083bf550edaa92",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_job_literal_secret_review_20261019.py",
    "source_sha256": "1710755805361a8f035aef2c64d6ed6a432a64a598966d265e2c589fa42313dd"
  },
  "gcp.review.function.literal_environment_secret_indicators": {
    "admission_sha256": "6dedaec790abdcb45bc8f86e3752a0b83eeceacdcc88926e0d599ea4fd7e3737",
    "copy_catalog_sha256": "373d825d5cfea29c036d3efa2bcf471b51fd97ab0c516a6c2a93cacd99a819fa",
    "fixture_sha256": "44507049c3b622a66dcab830af71a5dd7a77e79054659302070a84f6111ad2de",
    "fixture_sources": [
      {
        "note": "install() constructs the native-shaped fixture locally",
        "path": "peaso/checks/gcp_function_secret_review_20261019.py",
        "sha256": "53a529741f79b2de837cf4deb228c517be8ec1572d8d9ea6e5a4ec975035da14"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "function",
      "module": "peaso.checks.gcp_function_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "511ce21638a098c5c48e781b91b1652770f14d80fbde9b32d831aa36aa4f24cc",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_function_secret_review_20261019.py",
    "source_sha256": "53a529741f79b2de837cf4deb228c517be8ec1572d8d9ea6e5a4ec975035da14"
  },
  "gcp.review.function.resolved_source_archive_secret_indicators": {
    "admission_sha256": "dae7b656407153aa9565f5c41b181fc61e370565ec6e99f63f7bf461392a648f",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "46dcd350e73b019f961ac47140f3e7331534d0b6b47b5d0221c2dfe5ae851810",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_function_source_secret_fixtures.json.gz",
        "sha256": "5abe5283e927c80b97f4b89c6d5d174a70c50ed8c8d69ed7b5e4a43ca468bacd"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "function_source_archive",
      "module": "peaso.checks.gcp_function_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "ee8f6acf855282c0b95c6f41f72336897407eb923ce81c20b80d3cdc6195f6c4",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_function_source_secret_review_20261019.py",
    "source_sha256": "fb51def8c4cc2be7787b0734299753ef51e78e273f51ff9673f2bf2ced4a7b01"
  },
  "gcp.review.gke_workload.literal_configuration_secret_indicators": {
    "admission_sha256": "2fc9295f4438d9f64e7ee8198a0a3f61a150c758b7ae546093a3f69372541b6e",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "c731ba4607ac2eb7237e4a1491a87903db5867213c825afd8d8334f7b0e78e32",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_gke_literal_secret_fixtures.json.gz",
        "sha256": "cdde447292ac3e9a736088bba731f82c834302dd749499935b51ca9f1340178d"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "gke_workload_literal",
      "module": "peaso.checks.gcp_gke_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "f061d951d1ab3876b43189576126341b1897961a3898041969610ab3e9f5f8d0",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_gke_literal_secret_review_20261019.py",
    "source_sha256": "0b4f7908437e0088d1ea3bb76900d3663464a539bd513c3b1a6ca8358b573e68"
  },
  "gcp.review.instance.literal_configuration_secret_indicators": {
    "admission_sha256": "165fd18bc4879f0e9c9ab537fe88943bde445c78b42a252a21f19976e3599faa",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "a47cff23fffd9ca4220de630453a87bee263187e805e3b36f3e1d6533fe2b470",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "instance",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "instance",
      "predicate_source_sha256": "354203a632f37a316848d0a2c4cbc0dc65ca43753f212403968525ccb632005b",
      "source_qualname": "instance"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.instance_template.literal_configuration_secret_indicators": {
    "admission_sha256": "8309826a4880a834a6eb97596f4f2559b29caaeb2d84566f1453195a6141bb9b",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "10dee125630485b387afb3a9d5e61b7d3ea41546e9a485bdb7c0a8c4868e904d",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "instance_template",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "instance_template",
      "predicate_source_sha256": "a5f2716203dcd676c3934f9f68751c2445f41ed4c7254dfcb6add1616589d4fe",
      "source_qualname": "instance_template"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.logging.application_log_secret_indicators": {
    "admission_sha256": "2582ceca7284d2c399f07cd486c73f38a5bd2bec9f45bbfa429cdb84b09fec27",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "aeafd78ea299382caa6e6128ecb7deaba2c2b6604d782897f93f4cfe0f6f57be",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_log_secret_fixtures.json.gz",
        "sha256": "afeac127c0e893c34ad190609a6d6a81216d92532bf02c3078f0f6a838ad535e"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "log_secret_sample",
      "module": "peaso.checks.gcp_log_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "e584714cb0c7284f76afc77694a7725c6274e065a5d8f9a12811f81dcb598f50",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_log_secret_review_20261019.py",
    "source_sha256": "0cd008e9118895183b000ff7fd56b4f6985d83dcaa5eb35f382ea93b83724f02"
  },
  "gcp.review.project.literal_configuration_secret_indicators": {
    "admission_sha256": "29a11df77dc427bbb19953b44dacb25369bd68f4a3d955854aa6a74f1d3ce2f0",
    "copy_catalog_sha256": "9710e39f3fbcc6643c88e9618d51aaae13f65d757c4f7eb93fddd265860a7caf",
    "fixture_sha256": "77fda1e78547bb20f6272bb00bbd2334758e90913f775d2b48411e26d07d0325",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_configuration_secret_fixtures.json.gz",
        "sha256": "5cca35ee4d869d1f099859252689e86b43cc9a6d7123f31f76691415ecde51ed"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "project",
      "module": "peaso.checks.gcp_configuration_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "project",
      "predicate_source_sha256": "a3aa3125aa934c9b12cc0cf3db28a9ce6857b35f8c34309e9293c9f72a746bd2",
      "source_qualname": "project"
    },
    "source": "peaso/checks/gcp_configuration_secret_review_20261019.py",
    "source_sha256": "ec412b06a76abdfa7df9401d21f278c0976b78d040f75531cbd00ffc8df7b125"
  },
  "gcp.review.scheduler_job.literal_target_secret_indicators": {
    "admission_sha256": "65b645f4ba8746603bd9fe45f58196be6bc7048b84d31f8b416b9b1e94b66c97",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "675e6996df808ac372fd530e25d3aa57eb41d9104734d89410cb351464f2e576",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_additional_literal_secret_fixtures.json.gz",
        "sha256": "e5a8dda25d2d3ba103376d9462b2ef44cbcf622da57f84fbb2f6b387e96e6953"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "scheduler_job",
      "module": "peaso.checks.gcp_additional_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "scheduler",
      "predicate_source_sha256": "ad60a56a88774d4df4399054e4a0397b73be606df6b84a50ae1baf8baf85b5ef",
      "source_qualname": "scheduler"
    },
    "source": "peaso/checks/gcp_additional_literal_secret_review_20261019.py",
    "source_sha256": "db1e168a8499fde496bc2c1550b76c32d86133c45702096bd081b57675c1a2b4"
  },
  "gcp.review.storage.selected_archive_secret_indicators": {
    "admission_sha256": "6cbdc735c9c8c3321ce7ab49f3069aff4de27491bb01912c98b2f179c14fcb9f",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "103cf7c55a8e74977d68a905f0574c91a6d8d64f341d5cb242e0c3d41591d29d",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_selected_archive_secret_fixtures.json.gz",
        "sha256": "e4dffce5a79a31fa7a6baf308d56c44bae567ed1b0456aa4464d7a7045193e12"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "gcs_selected_archive",
      "module": "peaso.checks.gcp_selected_archive_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "67ae5ee1485f86d7a817c9ad180dcb5cc1254832d92af29bec618a6f8bff71c1",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_selected_archive_secret_review_20261019.py",
    "source_sha256": "d7636cee350ce0aa0c9fc32f3a71ef141f960050abb0757af082772a4f315a6a"
  },
  "gcp.review.storage.selected_object_secret_indicators": {
    "admission_sha256": "576813862d3a88cd813c401a9b5dffdf737b8b17b2f22df65449746468812759",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "d55449b34aab48a4629ef6202f738507cab3370446adf6ec7c6b635258bfa60b",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_selected_object_secret_fixtures.json.gz",
        "sha256": "de6915e1f9c294aa27777f47e88d8918c43003d66ee767425fc7ffba105efb68"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "gcs_selected_object",
      "module": "peaso.checks.gcp_selected_object_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "f6ab10c5737a9462b4579e1e8d53352da34119b1e44f8ce6f36bf675d9d6202f",
      "source_qualname": "evaluate"
    },
    "source": "peaso/checks/gcp_selected_object_secret_review_20261019.py",
    "source_sha256": "e8d791bf5329b47abd8144fb60958c33cdaf21abb8681733884c9bfccea87236"
  },
  "gcp.review.workbench.public_ip_disabled": {
    "admission_sha256": "4d70c71f2dd6b6ee7f59aa1478ba0e2d97878cc06bbe0210620d20b9a46e7472",
    "copy_catalog_sha256": "5c5fbe584cae9e4e28946f25ab0f76d0dd85ac1a830d25ade7a50cf84d7473c1",
    "fixture_sha256": "e67ca739bf575eb516c1b9b4b05f843bdb17023337335b5db110879bf988a9fc",
    "fixture_sources": [
      {
        "note": "install() constructs the native-shaped fixture locally",
        "path": "peaso/checks/gcp_workbench_review_20261019.py",
        "sha256": "2b64af4029781cfa10f2a106eb72bd30108493fa36ada4f88689e783995a2eda"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "public_ip",
      "predicate_source_sha256": "ad007a94299f01209e7b9f7db2d067b03854a206da35783b38d16df3ccba8228",
      "source_qualname": "public_ip"
    },
    "source": "peaso/checks/gcp_workbench_review_20261019.py",
    "source_sha256": "2b64af4029781cfa10f2a106eb72bd30108493fa36ada4f88689e783995a2eda"
  },
  "gcp.review.workbench.root_access_disabled": {
    "admission_sha256": "34312b3214d2088f524b8f62f168383977fe11e356629556ed903e0d8f740f40",
    "copy_catalog_sha256": "4a01b33aa9e65e8116d82f2d4d6bb06748bddb2d89347a6906b5c9b76b5d520e",
    "fixture_sha256": "1b6506467edaf903ed42b58fd0fbde8da4c8a401bf2ace4f4e554d6cd11d1ea8",
    "fixture_sources": [
      {
        "note": "install() constructs the native-shaped fixture locally",
        "path": "peaso/checks/gcp_workbench_review_20261019.py",
        "sha256": "2b64af4029781cfa10f2a106eb72bd30108493fa36ada4f88689e783995a2eda"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_workbench_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "root_access",
      "predicate_source_sha256": "1376ae92e677e218259070b7b5d4fd92db6a988af185d5032f9116a1d1c079e9",
      "source_qualname": "root_access"
    },
    "source": "peaso/checks/gcp_workbench_review_20261019.py",
    "source_sha256": "2b64af4029781cfa10f2a106eb72bd30108493fa36ada4f88689e783995a2eda"
  },
  "gcp.review.workbench_instance.literal_configuration_secret_indicators": {
    "admission_sha256": "4b8abde5ed33f4faf787314e5d32def0955f368d388e9bd63f4f7007f974c121",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "6756eb00c565acb4c7fda904c854f4a91d4ea001c6491634b7b31981812b9212",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_notebook_airflow_secret_fixtures.json.gz",
        "sha256": "5b401634d4af7e5ce05a66943c3b19805f84542cbda32129f226158a93c97ec5"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workbench_instance",
      "module": "peaso.checks.gcp_notebook_airflow_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "<lambda>",
      "predicate_source_sha256": "b56a4950a0377a0269e28d65d2714d63870d22320b676b1f724d795be36fffc4",
      "source_qualname": "<lambda>"
    },
    "source": "peaso/checks/gcp_notebook_airflow_secret_review_20261019.py",
    "source_sha256": "86cc47cb8583d5a0ba81a4e131e49362fb505b8da463aa76f8ede268068c5a2b"
  },
  "gcp.review.workflow.deployed_source_secret_indicators": {
    "admission_sha256": "2c61de87a953612b1e95f7679a421cbc74fab9fdb12b2bb72f2f84af45d663a4",
    "copy_catalog_sha256": "cae94f897b7d1530b42100f79bd1ba285abec13fbbd048f99f780ad1872ac946",
    "fixture_sha256": "6e263030f8ef35d897bd4f2f936bc316a6bec97a4c32605c5b4d3d428b8b37b4",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_additional_literal_secret_fixtures.json.gz",
        "sha256": "e5a8dda25d2d3ba103376d9462b2ef44cbcf622da57f84fbb2f6b387e96e6953"
      }
    ],
    "reviewed_binding": {
      "closure": {},
      "kind": "workflow_source",
      "module": "peaso.checks.gcp_additional_literal_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "workflow",
      "predicate_source_sha256": "edb59914c6eda6f0ec455f5cbc7cadcaab2536efa923796d6bcc01c96d1e66a1",
      "source_qualname": "workflow"
    },
    "source": "peaso/checks/gcp_additional_literal_secret_review_20261019.py",
    "source_sha256": "db1e168a8499fde496bc2c1550b76c32d86133c45702096bd081b57675c1a2b4"
  },
  "gcp.review.cloudbuild.stored_log_secret_indicators": {
    "admission_sha256": "3d5323c32b35d46d0aba60caaa352c2d43726b5005f6dde0f11e16592baaa91c",
    "copy_catalog_sha256": "9580d4052a717d8b703585859ba46b7b95930d61a638f50565c90a6c89f03274",
    "fixture_sha256": "ca4134b10a861dd1ba9b880906f9c1e8136be6382056bfb74ab65ccbf1e70003",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_cloudbuild_log_secret_review_20261019_fixtures.json.gz",
        "sha256": "500251be960b27060d983b1640adc9e65a423d9cfc5e4751f8ae5f157475c57d"
      }
    ],
    "source": "peaso/checks/gcp_cloudbuild_log_secret_review_20261019.py",
    "source_sha256": "d1f3618df951b59b8ebc73424acb7b1fed9795121f21054571061a4173c01967",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_log_source",
      "module": "peaso.checks.gcp_cloudbuild_log_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "7a4d78e54b01344cae0539f479c8dc841be8b07e5a53fc171499ad080cb9390c",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.appengine.deployment_source_secret_indicators": {
    "admission_sha256": "12bc18e9c3f617c4d5c9ca30e7a863d3ae3769ef8ea661550226000f5fcd794d",
    "copy_catalog_sha256": "a150e416c1e641f5bb865396ee28ad78c8b18946470520ba5fcaa8e93bea046b",
    "fixture_sha256": "0cf6fb3193cbb795b7384b033e79587015e9e98bcb7251c1034a8b0731fdcbbd",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_appengine_source_secret_review_20261019_fixtures.json.gz",
        "sha256": "913856603087ab7e9668ef680c3919abe660e6ca0c3489cb9bbd96c7669d5c27"
      }
    ],
    "source": "peaso/checks/gcp_appengine_source_secret_review_20261019.py",
    "source_sha256": "2dabaf4b09352a4095e89c55e090682638ee95cf5d9efbd7d2699e64a720d2a1",
    "reviewed_binding": {
      "closure": {},
      "kind": "appengine_deployment_source",
      "module": "peaso.checks.gcp_appengine_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "fb5e8835864727ecb41376dd95f3849692ee8edd17a325dfd64dd063bc6afc82",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.cloudbuild.artifact_secret_indicators": {
    "admission_sha256": "10da91e27cb95e40235d2ace390d2e30fa1d6fe367abb1a1be48a15784694966",
    "copy_catalog_sha256": "0a4e81a0d9f2ee76291d78b8b7b282806ecb6a4458469180f17e52bd65928514",
    "fixture_sha256": "59cb56ea9b5b994f8699ba58aa3134ed93c5b1b42fff35c4f7a7034ecba0aef2",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_cloudbuild_artifact_secret_review_20261019_fixtures.json.gz",
        "sha256": "772e086e570e3cbde90e70c4ef8f2e1a393fd84a82ff944165cb9b50f55cf7e2"
      }
    ],
    "source": "peaso/checks/gcp_cloudbuild_artifact_secret_review_20261019.py",
    "source_sha256": "c23a04e0cee0f7392e91f1d9344015ccfd2b9109dcfc08f55d980a677c9e90e0",
    "reviewed_binding": {
      "closure": {},
      "kind": "cloudbuild_artifact_source",
      "module": "peaso.checks.gcp_cloudbuild_artifact_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "d942c80c15c18289a6d0be13bb9668da98f80f37de0dd0ba8986f775ffbaee17",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.clouddeploy.release_source_secret_indicators": {
    "admission_sha256": "2dfe5742eefe0d9d730c5d9386a4fbfe630925f167263da9d7671ea49c50f763",
    "copy_catalog_sha256": "fdf6c63d5c7f81b8ec9761407477086e47d7943e469a6e85f85e6c3d2ad15046",
    "fixture_sha256": "6ea3f79f526a085f528eaebb6cbd0f1c503c143bafe51ebd20a9e84a6be2ff66",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_clouddeploy_source_secret_review_20261019_fixtures.json.gz",
        "sha256": "811fd8fb21a1b4d23aac2eecffcd0de00efffa6f3c03710e43f38bd4c42a2162"
      }
    ],
    "source": "peaso/checks/gcp_clouddeploy_source_secret_review_20261019.py",
    "source_sha256": "e10c324a6eb280c64cb26aa44d579fdedaff199b24d524bd02900f9fd3b2ec71",
    "reviewed_binding": {
      "closure": {},
      "kind": "clouddeploy_release_source",
      "module": "peaso.checks.gcp_clouddeploy_source_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "e2c97d8f4f68011179efea1c878ddf07a01c9aefa12923c196d1ec21534f4c75",
      "source_qualname": "evaluate"
    }
  },
  "gcp.review.sourcerepo.selected_file_secret_indicators": {
    "admission_sha256": "7270dbbc569183afbac5557bc877d8c6a1d459dbe1a4e4c8d65eeac39d107cb9",
    "copy_catalog_sha256": "78be3bcb048698c1be18d8f46bf7cfb0f1c6c0baddfb6b84610410409f0de7d2",
    "fixture_sha256": "4e9b5fb430053355aeeabf8bac78171aec83ec3e545792c93230b2800cb594f1",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_sourcerepo_secret_review_20261019_fixtures.json.gz",
        "sha256": "928251b151458cfd73d568d0a7d96aa7228e92057a9fcc477d742f370c3c8b6c"
      }
    ],
    "source": "peaso/checks/gcp_sourcerepo_secret_review_20261019.py",
    "source_sha256": "f397ee93b511f396bb49fb467e05a88e23a741e492a22dcb93d9f8d99aded5d0",
    "reviewed_binding": {
      "closure": {},
      "kind": "source_repository_file",
      "module": "peaso.checks.gcp_sourcerepo_secret_review_20261019",
      "predicate_bindings": {},
      "predicate_qualname": "evaluate",
      "predicate_source_sha256": "9efdc7277d249274984369dfd0db9cf279fb154c75b31ae00119dbce484d91a5",
      "source_qualname": "evaluate"
    }
  }
}
''')

# Explicitly reviewed selected-content successors; older entries remain unchanged.
NATIVE_EXTENSION_REVIEWS.update(json.loads(r'''
{
  "gcp.review.cloudtasks.selected_payload_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-selected-content-20261020.json",
    "admission_sha256": "356c4f0cbcccf4d85a6dba163a7e4c2010c9ff0e4dec1198123ca2b3badcbc43",
    "source": "peaso/checks/gcp_task_routine_secret_review_20261020.py",
    "source_sha256": "18a4701d7e40fb18bc75291f80383a376713aa4a3fc3c4703b7c7f5c275aeeb1",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_task_routine_secret_review_20261020_fixtures.json.gz",
        "sha256": "567fc1842443b68cc2311415d8420961cdd09441e18b68f4ad31a3399b85ae5a"
      }
    ],
    "fixture_sha256": "58f96ec2f8e0f47e6cafde1377c57d5b74ed520f37af1b798b5dd3edacbee95f",
    "copy_catalog_sha256": "96d4ffc8e8d6285864562f0a942dfc0bdf636f8a1bba3f0e83cb9f73cf19adbb",
    "reviewed_binding": {
      "kind": "cloudtasks_selected_task",
      "module": "peaso.checks.gcp_task_routine_secret_review_20261020",
      "source_qualname": "task_payload",
      "predicate_qualname": "task_payload",
      "predicate_source_sha256": "005b604df84c0134df4b2f09f14d170acc64722934c407c7ff39bdd3f8068878",
      "closure": {},
      "predicate_bindings": {}
    }
  },
  "gcp.review.bigquery.selected_routine_secret_indicators": {
    "admission_path": "docs/compliance-ledgers/native-extensions/gcp-selected-content-20261020.json",
    "admission_sha256": "5570f5f9a9ce19dbe8f919c101469c2d0cb4596d74dbd4e8db76803f1dbfd88c",
    "source": "peaso/checks/gcp_task_routine_secret_review_20261020.py",
    "source_sha256": "18a4701d7e40fb18bc75291f80383a376713aa4a3fc3c4703b7c7f5c275aeeb1",
    "fixture_sources": [
      {
        "path": "peaso/checks/gcp_task_routine_secret_review_20261020_fixtures.json.gz",
        "sha256": "567fc1842443b68cc2311415d8420961cdd09441e18b68f4ad31a3399b85ae5a"
      }
    ],
    "fixture_sha256": "d244fcb84810a81ca61c15db6ca22acc033f3f68e61b80c05b5ca45a502197c7",
    "copy_catalog_sha256": "96d4ffc8e8d6285864562f0a942dfc0bdf636f8a1bba3f0e83cb9f73cf19adbb",
    "reviewed_binding": {
      "kind": "bigquery_selected_routine",
      "module": "peaso.checks.gcp_task_routine_secret_review_20261020",
      "source_qualname": "routine_definition",
      "predicate_qualname": "routine_definition",
      "predicate_source_sha256": "a309571032db42fce9a5993d1cb28d7d183c8b3dcddec747c5b1789bde162c72",
      "closure": {},
      "predicate_bindings": {}
    }
  }
}
'''))
