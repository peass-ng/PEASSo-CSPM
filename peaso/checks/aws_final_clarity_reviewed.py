"""Individually reviewed final AWS native findings; no cloud requests or mutations."""
from copy import deepcopy
import json

VERSION = "aws-final-clarity-20261019"
ROWS = json.loads(r'''
{
  "aws.htbp.cognito.client_no_writable_authorization_attributes": {
    "description_fields": {
      "description": "Checks whether app clients can write custom attributes with authorization-like names, including immutable attributes during self-signup."
    },
    "remediation_fields": {
      "summary": "Keep authorization claims server-controlled and remove client write access to those attributes.",
      "steps": [
        "Keep authorization claims server-controlled and remove client write access to those attributes."
      ],
      "caveats": [
        "Attribute names are a heuristic; application authorization use is not established.",
        "Omitted WriteAttributes is a broad default in the AWS Developer Guide, not an empty allowlist; attribute-name matches are a risk heuristic, not proof of application authorization. Immutable custom claims can be user-supplied at self-service signup. An explicit empty list has unverified API response semantics and cannot establish no-write by itself.",
        "Where name or ID is not safely auto-bound, verify the exact collected identity before replacing the visible placeholder. No command is executed."
      ]
    },
    "static_observed_sentence": "An app client can write an attribute whose name suggests authorization use.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "cognito_user_pool",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "47cd501c8d2966249280214813d16af0a24e4839c02de4594e8f2731704c2a92"
      }
    }
  },
  "aws.htbp.sagemaker.notebook_imdsv2_required": {
    "description_fields": {
      "description": "Compares the notebook\u2019s minimum instance metadata service version with version 2."
    },
    "remediation_fields": {
      "summary": "Require IMDSv2 for the notebook instance.",
      "steps": [
        "Require IMDSv2 for the notebook instance."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested.",
        "Only exact versions 1 and 2 are recognized; changing metadata access can interrupt notebook scripts.",
        "Where name or ID is not safely auto-bound, verify the exact collected identity before replacing the visible placeholder. No command is executed."
      ]
    },
    "static_observed_sentence": "The notebook permits tokenless IMDSv1 requests.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "sagemaker_notebook_instance",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "9d64224ec4f0b1f4ab73e8244b173ff7cdc2158ea569d55d70d334ff92871e86"
      }
    }
  },
  "aws.htbp.glue.dev_endpoint_not_public": {
    "description_fields": {
      "description": "Checks whether the development endpoint declares a nonempty PublicAddress."
    },
    "remediation_fields": {
      "summary": "Restrict access to the required networks or migrate to a private development endpoint.",
      "steps": [
        "Restrict access to the required networks or migrate to a private development endpoint."
      ],
      "caveats": [
        "An address declaration is not proof of an open SSH path.",
        "An endpoint with neither address is UNKNOWN while provisioning; deletion or recreation requires workload owner approval.",
        "Where name or ID is not safely auto-bound, verify the exact collected identity before replacing the visible placeholder. No command is executed."
      ]
    },
    "static_observed_sentence": "The Glue development endpoint has a public address.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "glue_dev_endpoint",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "20f1774b1fe465e1021d00e9393d09ec4b3b6cf3cb6030aac53fc499fc1406f3"
      }
    }
  },
  "aws.htbp.appsync.no_api_key_additional_auth": {
    "description_fields": {
      "description": "Checks additional GraphQL authentication providers for API_KEY."
    },
    "remediation_fields": {
      "summary": "Keep API-key authorization only for fields intended to support it; use stronger authorization for sensitive operations.",
      "steps": [
        "Keep API-key authorization only for fields intended to support it; use stronger authorization for sensitive operations."
      ],
      "caveats": [
        "Field-level directives determine which operations API keys can access; the default authentication mode is checked separately.",
        "Non-GRAPHQL API types are NOT_APPLICABLE; default auth mode is a separate check and field-level access needs separate review.",
        "Where name or ID is not safely auto-bound, verify the exact collected identity before replacing the visible placeholder. No command is executed."
      ]
    },
    "static_observed_sentence": "The GraphQL API includes API_KEY as an additional authentication mode.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "appsync_graphql_api",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "001bcdae7bee401c33527c0e193fca6a52279cbc9fcc3688d495c88957f54398"
      }
    }
  },
  "aws.htbp.lambda.layer_version_trust_boundary": {
    "description_fields": {
      "description": "Compares Lambda layer version policy with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; restrict layer-version permissions where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; restrict layer-version permissions where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "Absent policy passes; unknown organization membership makes an outside account MANUAL, while unconditioned public wildcard fails.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The Lambda layer version policy permits public access or names an account outside the collected organization.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "lambda_layer_version",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "8eddcc56b6b17c043ab8f7fed9472970eadf1a43fb2fe2abc3adbd0612adecf3"
      }
    }
  },
  "aws.htbp.ecr.registry_policy_trust_boundary": {
    "description_fields": {
      "description": "Compares ECR registry policy with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; restrict registry policy principals where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; restrict registry policy principals where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "An absent registry policy passes; outside account is MANUAL if organization membership is unreadable.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The ECR registry policy permits public access or names an account outside the collected organization.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecr_registry",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "c1f6c9e20148a33ba33d4fbf5337fc1ebb1a654bd9cf8be6499947b5ea3ecdec"
      }
    }
  },
  "aws.htbp.ecr.replication_destinations_trust_boundary": {
    "description_fields": {
      "description": "Compares ECR replication destinations with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; restrict replication destinations where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; restrict replication destinations where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "No replication rules passes; outside account is MANUAL when organization membership is unavailable.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The ECR replication destinations names an account outside the collected organization.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecr_registry",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "84c357f65771370eb2379273e3da08621e1e84e055f53b1f484e9ea19a70b01a"
      }
    }
  },
  "aws.htbp.ecr.creation_template_policy_trust_boundary": {
    "description_fields": {
      "description": "Compares ECR repository creation-template policies with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; restrict the creation template\u2019s policy where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; restrict the creation template\u2019s policy where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "Empty templates pass; outside account is MANUAL without verified organization inventory and conditions can restrict wildcard principals.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The ECR repository creation-template policies permits public access or names an account outside the collected organization.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "ecr_registry",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "b001332a87e59ebbce1206aa962dc9cb364b0644ab4be2a8d8705357b6c9693f"
      }
    }
  },
  "aws.htbp.eks.access_entry_principal_trust_boundary": {
    "description_fields": {
      "description": "Compares EKS access-entry principal with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; remove unnecessary external access entries where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; remove unnecessary external access entries where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "An outside account is MANUAL if organization membership is unavailable; do not remove a cluster administrator without tested replacement.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The EKS access-entry principal names an account outside the collected organization.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "eks_access_entry",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "97bd6f987ff23d6ad342b611287eb4b58b4011b45d58c433d0f8299a773007cc"
      }
    }
  },
  "aws.htbp.kms.grant_grantee_trust_boundary": {
    "description_fields": {
      "description": "Compares KMS grant grantee with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; retire or revoke unnecessary external grants where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; retire or revoke unnecessary external grants where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "Service principals pass this source; outside account is MANUAL without organization inventory. Key ARN is operator-confirmed, not auto-bound from grant ID.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The KMS grant grantee names an account outside the collected organization.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "kms_grant",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "02f6c6e6448100a7add97995e832d22f532b9c01ff248d663a04f53411fc142f"
      }
    }
  },
  "aws.htbp.opensearch.connection_peer_trust_boundary": {
    "description_fields": {
      "description": "Compares OpenSearch connection peer account with the account and collected organization membership, checking public declarations where applicable."
    },
    "remediation_fields": {
      "summary": "Keep intended cross-account access; remove unnecessary cross-account connections where access is unnecessary.",
      "steps": [
        "Keep intended cross-account access; remove unnecessary cross-account connections where access is unnecessary."
      ],
      "caveats": [
        "Uncollected organization membership leaves external-account approval undetermined; a declaration does not prove successful access.",
        "Ended states are NOT_APPLICABLE; unknown organization membership makes outside accounts MANUAL, not proven unsafe.",
        "The CLI is read-only display text; no permissions, connections or credential values are changed or retrieved by this template."
      ]
    },
    "static_observed_sentence": "The OpenSearch connection peer account names an account outside the collected organization.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_connection",
      "predicate_qualname": "ht_register.<locals>.apply.<locals>.evaluate",
      "delegate_sources": {
        "function": "c194ac129fa4d7f2131e8ae0b2962e2512514badcf2364acb6365b848d321b70"
      }
    }
  },
  "aws.gap.securityhub.region_hub_enabled": {
    "description_fields": {
      "description": "Looks for a Security Hub hub ARN in the regional inventory."
    },
    "remediation_fields": {
      "summary": "Enable Security Hub in this Region if it is part of the monitoring plan.",
      "steps": [
        "Enable Security Hub in this Region if it is part of the monitoring plan."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested.",
        "Presence alone does not prove standards enabled or findings reviewed.",
        "The CLI is displayed only; no cloud call, secret content, or provider mutation is performed by this review."
      ]
    },
    "static_observed_sentence": "No Security Hub hub was collected in this Region.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "securityhub_hub",
      "predicate_qualname": "securityhub_region",
      "delegate_sources": {}
    }
  },
  "aws.gap.accessanalyzer.no_active_findings": {
    "description_fields": {
      "description": "Looks for active Access Analyzer findings in the collected analyzers."
    },
    "remediation_fields": {
      "summary": "Review active findings and restrict any unintended access they identify.",
      "steps": [
        "Review active findings and restrict any unintended access they identify."
      ],
      "caveats": [
        "An active finding requires investigation; it is not proof of an exploit or data access.",
        "Non-ACTIVE analyzer is NOT_APPLICABLE; a finding is a review item, not proof of exploitation.",
        "The CLI is displayed only; no cloud call, secret content, or provider mutation is performed by this review."
      ]
    },
    "static_observed_sentence": "Access Analyzer reports active findings.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "access_analyzer",
      "predicate_qualname": "analyzer_findings",
      "delegate_sources": {}
    }
  },
  "aws.gap.vpc.sg_world_any_common_ports": {
    "description_fields": {
      "description": "Checks security-group ingress for world-address sources and the profile\u2019s unrestricted or common sensitive ports."
    },
    "remediation_fields": {
      "summary": "Restrict unnecessary Internet-wide ingress to the source networks and ports that need access.",
      "steps": [
        "Restrict unnecessary Internet-wide ingress to the source networks and ports that need access."
      ],
      "caveats": [
        "Rules alone do not establish an attached, reachable listener.",
        "The finding does not include a rule ID or approved CIDR. Changing ingress may interrupt clients; this declaration does not prove reachability."
      ]
    },
    "static_observed_sentence": "A security-group rule permits Internet-wide ingress matching the checked port pattern.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "security_group",
      "predicate_qualname": "sg_common_ports",
      "delegate_sources": {}
    }
  },
  "aws.gap.classic_elb.ssl_listeners_use_acm": {
    "description_fields": {
      "description": "Checks whether Classic ELB HTTPS/SSL listener certificate identifiers are ACM ARNs."
    },
    "remediation_fields": {
      "summary": "Use ACM-managed certificates if centralized lifecycle management is required.",
      "steps": [
        "Use ACM-managed certificates if centralized lifecycle management is required."
      ],
      "caveats": [
        "A non-ACM certificate may still be valid and trusted; the certificate contents are not inspected.",
        "No HTTPS/SSL listeners is NOT_APPLICABLE; certificate ARN prefix does not prove certificate validity.",
        "The CLI is displayed only; no cloud call, secret content, or provider mutation is performed by this review."
      ]
    },
    "static_observed_sentence": "A secure Classic ELB listener lacks an ACM certificate reference.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "classic_load_balancer",
      "predicate_qualname": "clb_acm",
      "delegate_sources": {}
    }
  },
  "aws_cloudfront_origin_failover_configured": {
    "description_fields": {
      "description": "Checks that each declared origin group has two distinct existing origins and supported failover status codes."
    },
    "remediation_fields": {
      "summary": "Configure an origin group if origin failover is needed and ensure the intended cache behavior uses it.",
      "steps": [
        "Configure an origin group if origin failover is needed and ensure the intended cache behavior uses it."
      ],
      "caveats": [
        "An origin group declaration does not establish that a cache behavior references it or that failover works.",
        "Changing a CloudFront distribution can alter production routing and incur secondary-origin costs; review cache behavior targeting the group and rollback before deployment.",
        "The predicate verifies declared origin-group metadata, not live failover availability or origin health."
      ]
    },
    "static_observed_sentence": "No valid CloudFront origin failover group is configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "cloudfront_distribution",
      "predicate_qualname": "cloudfront_origin_failover",
      "delegate_sources": {}
    }
  },
  "aws_config_continuous_inventory": {
    "description_fields": {
      "description": "Requires the recorder recording flag, allSupported flag and default and override frequencies to declare continuous recording; it does not resolve recording strategies or exclusions."
    },
    "remediation_fields": {
      "summary": "Enable continuous recording and remove unintended resource-type coverage restrictions after reviewing cost.",
      "steps": [
        "Enable continuous recording and remove unintended resource-type coverage restrictions after reviewing cost."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested.",
        "Continuous all-supported recording can materially increase Config configuration-item and rule-evaluation costs, particularly for ephemeral resources; confirm the owner policy before changing scope.",
        "This predicate checks the recorder declaration and status only; it does not verify delivery-channel health or all account Regions."
      ]
    },
    "static_observed_sentence": "The Config recorder is stopped, restricted or uses daily recording.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "config_recorder",
      "predicate_qualname": "config_continuous_inventory",
      "delegate_sources": {}
    }
  },
  "aws_acm_certificate_lifecycle": {
    "description_fields": {
      "description": "Checks issuance, expiry and near-expiry renewal eligibility for ACM certificates declared in use."
    },
    "remediation_fields": {
      "summary": "Renew or replace the affected certificate before expiry and verify deployment to its consumers.",
      "steps": [
        "Renew or replace the affected certificate before expiry and verify deployment to its consumers."
      ],
      "caveats": [
        "Certificate metadata does not prove which certificate is served by an endpoint.",
        "Renewal eligibility is not proof renewal has completed or the new certificate was deployed; inspect consumer endpoints before declaring recovery.",
        "Replacing a certificate can break TLS clients, names or trust chains; stage and test the replacement before cutover."
      ]
    },
    "static_observed_sentence": "An in-use certificate is not issued, has expired or is near expiry without renewal eligibility.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "acm_certificate",
      "predicate_qualname": "acm_certificate_lifecycle",
      "delegate_sources": {}
    }
  },
  "aws_nist_cloudwatch_alarm_action_enabled": {
    "description_fields": {
      "description": "Checks ActionsEnabled and whether any ALARM, OK or INSUFFICIENT_DATA action list is nonempty."
    },
    "remediation_fields": {
      "summary": "Enable alarm actions and configure the state notification or action that is needed.",
      "steps": [
        "Enable alarm actions and configure the state notification or action that is needed."
      ],
      "caveats": [
        "An action declaration does not demonstrate notification delivery; OK-only actions satisfy this profile.",
        "Alarm actions can invoke scaling or automation with cost and availability impact; review the selected action and test it safely.",
        "The predicate verifies a configured action and enabled switch, not that the destination is healthy or receives notifications."
      ]
    },
    "static_observed_sentence": "Alarm actions are disabled or no state action is configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "cloudwatch_alarm",
      "predicate_qualname": "cloudwatch_action_enabled",
      "delegate_sources": {}
    }
  },
  "aws_config_recorder_all_supported_resources": {
    "description_fields": {
      "description": "Checks Config\u2019s recording strategy for all supported types without resource exclusions."
    },
    "remediation_fields": {
      "summary": "Remove unintended recording exclusions or configure all-supported resource coverage after reviewing cost.",
      "steps": [
        "Remove unintended recording exclusions or configure all-supported resource coverage after reviewing cost."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested.",
        "Recording all supported resource types can materially increase Config charges and downstream evaluations; review ephemeral workloads before changing policy.",
        "This predicate checks only the recorder's type selection, not whether recording is started, continuous or delivering successfully; aws_config_continuous_inventory covers separate fields."
      ]
    },
    "static_observed_sentence": "The Config recording strategy excludes supported resource types.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "config_recorder",
      "predicate_qualname": "config_all_supported_resources",
      "delegate_sources": {}
    }
  },
  "aws_fedramp_acm_all_certificates_30_day_expiry": {
    "description_fields": {
      "description": "Checks every readable regional ACM certificate for expiry at or before 30 days after capture; renewal eligibility does not exempt certificates."
    },
    "remediation_fields": {
      "summary": "Review renewal status and renew or replace certificates that may expire before their next deployment.",
      "steps": [
        "Review renewal status and renew or replace certificates that may expire before their next deployment."
      ],
      "caveats": [
        "This checks certificate metadata, not the certificate actually served by a listener."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "ACM CertificateDetail",
          "url": "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html"
        }
      ],
      "field_binding": {
        "fields": [
          "complete acm_certificate regional collection",
          "CertificateArn",
          "Certificate.Certificate.Status",
          "Certificate.Certificate.NotAfter",
          "context.created_at"
        ],
        "kind": "acm_certificate",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The collected certificate expires within this profile\u2019s 30-day window or has expired.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "acm_certificate",
      "predicate_qualname": "fedramp_all",
      "delegate_sources": {}
    }
  },
  "aws.nist.acm_all_certificates_expiry_30_days": {
    "description_fields": {
      "description": "Checks issued ACM certificates for expiry at or before 30 days after capture; renewal eligibility does not exempt certificates."
    },
    "remediation_fields": {
      "summary": "Review renewal status and renew or replace certificates that may expire before their next deployment.",
      "steps": [
        "Review renewal status and renew or replace certificates that may expire before their next deployment."
      ],
      "caveats": [
        "This checks certificate metadata, not the certificate actually served by a listener.",
        "This predicate applies only to ISSUED certificates and fails at the exact capture instant plus 30 days as well as earlier; other recognized statuses are NOT_APPLICABLE. Missing, denied, stale or incomplete inventory/detail remains UNKNOWN.",
        "RenewalEligibility is not a predicate input. ACM-managed renewal depends on certificate type, validation and use; never assume a certificate will renew or that a renewed certificate is already deployed.",
        "Replacing an in-use certificate can interrupt clients. Preserve the prior certificate and consumer configuration for an owner-approved rollback until replacement and TLS behavior are verified."
      ]
    },
    "static_observed_sentence": "The collected certificate expires within this profile\u2019s 30-day window or has expired.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "acm_certificate",
      "predicate_qualname": "nist_issued_closed",
      "delegate_sources": {}
    }
  },
  "aws_nist_acm_certificate_expires_30_days": {
    "description_fields": {
      "description": "Checks issued ACM certificates for expiry strictly before 30 days after capture; renewal eligibility does not exempt certificates."
    },
    "remediation_fields": {
      "summary": "Review renewal status and renew or replace certificates that may expire before their next deployment.",
      "steps": [
        "Review renewal status and renew or replace certificates that may expire before their next deployment."
      ],
      "caveats": [
        "This checks certificate metadata, not the certificate actually served by a listener."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "ACM CertificateDetail",
          "url": "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html"
        }
      ],
      "field_binding": {
        "fields": [
          "complete acm_certificate regional collection",
          "CertificateArn",
          "Certificate.Certificate.Status",
          "Certificate.Certificate.NotAfter for issued certificates",
          "context.created_at"
        ],
        "kind": "acm_certificate",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The collected certificate expires within this profile\u2019s 30-day window or has expired.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "acm_certificate",
      "predicate_qualname": "nist_issued_strict",
      "delegate_sources": {}
    }
  },
  "aws_g6_acm_all_certificates_30_day_expiry": {
    "description_fields": {
      "description": "Checks every readable regional ACM certificate for expiry before the capture calendar date plus 30 days; renewal eligibility does not exempt certificates."
    },
    "remediation_fields": {
      "summary": "Review renewal status and renew or replace certificates that may expire before their next deployment.",
      "steps": [
        "Review renewal status and renew or replace certificates that may expire before their next deployment."
      ],
      "caveats": [
        "This checks certificate metadata, not the certificate actually served by a listener."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "ACM CertificateDetail",
          "url": "https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html"
        }
      ],
      "field_binding": {
        "fields": [
          "complete acm_certificate regional collection",
          "CertificateArn",
          "Certificate.Certificate.Status",
          "Certificate.Certificate.NotAfter",
          "context.created_at UTC date"
        ],
        "kind": "acm_certificate",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The collected certificate expires within this profile\u2019s 30-day window or has expired.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "acm_certificate",
      "predicate_qualname": "g6_all_calendar",
      "delegate_sources": {}
    }
  },
  "aws_backup_cross_region_copy": {
    "description_fields": {
      "description": "Checks every backup-plan rule for a copy action naming a vault in another Region of the same AWS partition."
    },
    "remediation_fields": {
      "summary": "Add cross-Region copy actions if protection against regional loss is required.",
      "steps": [
        "Add cross-Region copy actions if protection against regional loss is required."
      ],
      "caveats": [
        "Copy-action configuration does not prove successful copies or restoration."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "AWS Backup plan rules",
          "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupRule.html"
        }
      ],
      "field_binding": {
        "fields": [
          "context.provider, scope, Account, metadata.caller_identities[].Arn",
          "complete scoped backup_plan inventory and BackupPlanArn",
          "Plan.collection_status=collected",
          "Plan.BackupPlan.Rules[].CopyActions[].DestinationBackupVaultArn"
        ],
        "kind": "backup_plan",
        "target": "resource"
      }
    },
    "static_observed_sentence": "A backup-plan rule has no declared cross-Region copy action.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "backup_plan",
      "predicate_qualname": "cross_region_copy",
      "delegate_sources": {}
    }
  },
  "aws_guardduty_no_active_high_findings": {
    "description_fields": {
      "description": "Checks complete detector finding inventories for unarchived GuardDuty findings with severity from 7 inclusive to 9 exclusive."
    },
    "remediation_fields": {
      "summary": "Investigate the reported findings and remediate their causes before archiving them.",
      "steps": [
        "Investigate the reported findings and remediate their causes before archiving them."
      ],
      "caveats": [
        "Critical findings at severity 9 or above are outside this specific interval."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "GuardDuty findings",
          "url": "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Finding.html"
        }
      ],
      "field_binding": {
        "fields": [
          "guardduty_detector collection status and DetectorId",
          "guardduty_detector.Configuration.Status",
          "guardduty_detector.FindingIds.collection_status",
          "guardduty_detector.FindingIds.items",
          "guardduty_finding collection status",
          "guardduty_finding.Id",
          "guardduty_finding.AccountId",
          "guardduty_finding.Region",
          "guardduty_finding.Service.DetectorId",
          "guardduty_finding.Service.Archived",
          "guardduty_finding.Severity"
        ],
        "kind": "guardduty_finding",
        "target": "scope"
      }
    },
    "static_observed_sentence": "GuardDuty reports an unarchived finding with severity at least 7 and below 9.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "guardduty_finding",
      "predicate_qualname": "no_active_high_findings",
      "delegate_sources": {}
    }
  },
  "aws.pci.apigateway.all_methods_logging": {
    "description_fields": {
      "description": "Checks declared stage wildcard and method logging settings for explicit ERROR or INFO coverage."
    },
    "remediation_fields": {
      "summary": "Enable the required method logging and remove unintended OFF overrides.",
      "steps": [
        "Enable the required method logging and remove unintended OFF overrides."
      ],
      "caveats": [
        "These stage settings do not establish deployed-route coverage or log delivery.",
        "GetStages settings do not prove that logs reach CloudWatch; account logging permissions and delivery must be verified separately.",
        "An absent wildcard or omitted loggingLevel in an override remains UNKNOWN because deployed-route coverage and field inheritance are unproven.",
        "Avoid request or response data tracing unless separately approved because it may record sensitive data."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null
    },
    "static_observed_sentence": "A declared method override explicitly disables execution logging.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rest_api_stage",
      "predicate_qualname": "all_methods_logging",
      "delegate_sources": {}
    }
  },
  "aws.pci.apigateway.all_methods_cache_encrypted": {
    "description_fields": {
      "description": "Checks declared enabled method caches for encryption on an available stage cache cluster."
    },
    "remediation_fields": {
      "summary": "Enable encryption for the affected method caches after reviewing cache replacement and application behavior.",
      "steps": [
        "Enable encryption for the affected method caches after reviewing cache replacement and application behavior."
      ],
      "caveats": [
        "This checks declared settings, not cached response contents or complete deployed-route coverage.",
        "A disabled stage cache or disabled method caching is outside this encryption predicate; do not enable hourly-billed caching solely to clear the finding.",
        "A wildcard with encryption disabled does not prove an active deployed method exists; absent route proof remains UNKNOWN unless an explicit enabled unencrypted override is present.",
        "Changing cache encryption settings can flush or alter cache behavior; plan the change with the API owner."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null
    },
    "static_observed_sentence": "A declared enabled method cache has encryption disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rest_api_stage",
      "predicate_qualname": "all_enabled_method_caches_encrypted",
      "delegate_sources": {}
    }
  },
  "aws_inspector2_ec2_no_high_critical_findings": {
    "description_fields": {
      "description": "Checks active Inspector findings for HIGH or CRITICAL EC2 findings; a clean result requires enabled regional scanning coverage."
    },
    "remediation_fields": {
      "summary": "Patch or otherwise remediate the reported EC2 vulnerability findings.",
      "steps": [
        "Patch or otherwise remediate the reported EC2 vulnerability findings."
      ],
      "caveats": [
        "Account coverage does not prove that every instance was recently scanned or remediation succeeded."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "Inspector Finding",
          "url": "https://docs.aws.amazon.com/inspector/v2/APIReference/API_Finding.html"
        }
      ],
      "field_binding": {
        "fields": [
          "complete scoped inspector2_finding inventory from paginated ACTIVE ListFindings",
          "findingArn, status, severity, awsAccountId and resources[].type",
          "complete scoped inspector2_account_status inventory",
          "accountId, State.status and ResourceState.ec2.status",
          "context.created_at"
        ],
        "kind": "inspector2_finding",
        "target": "scope"
      }
    },
    "static_observed_sentence": "Inspector reports an active HIGH or CRITICAL finding affecting an EC2 instance.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "inspector2_finding",
      "predicate_qualname": "ec2_no_high_critical_findings",
      "delegate_sources": {}
    }
  },
  "aws_config_all_resources_recorded": {
    "description_fields": {
      "description": "Checks for one running, successful customer-managed Config recorder with all-supported resource coverage in this Region."
    },
    "remediation_fields": {
      "summary": "Start or repair the recorder and remove unintended recording restrictions.",
      "steps": [
        "Start or repair the recorder and remove unintended recording restrictions."
      ],
      "caveats": [
        "The regional result does not certify recording in other Regions."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "Config recording group",
          "url": "https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html"
        }
      ],
      "field_binding": {
        "fields": [
          "complete config_recorder regional collection (DescribeConfigurationRecorders without arguments)",
          "name",
          "servicePrincipal",
          "recordingGroup.allSupported",
          "recordingGroup.resourceTypes",
          "recordingGroup.recordingStrategy.useOnly",
          "recordingGroup.exclusionByResourceTypes.resourceTypes",
          "Status.ConfigurationRecordersStatus[].name",
          "Status.ConfigurationRecordersStatus[].recording",
          "Status.ConfigurationRecordersStatus[].lastStatus"
        ],
        "kind": "config_recorder",
        "target": "scope"
      }
    },
    "static_observed_sentence": "This Region lacks a successful, running Config recorder covering all supported resource types.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "config_recorder",
      "predicate_qualname": "config_all_supported",
      "delegate_sources": {}
    }
  },
  "aws.pci.wafv2.rule_group_metrics": {
    "description_fields": {
      "description": "Checks CloudWatchMetricsEnabled in the rule group\u2019s VisibilityConfig."
    },
    "remediation_fields": {
      "summary": "Enable CloudWatch metrics if this rule group needs monitoring.",
      "steps": [
        "Enable CloudWatch metrics if this rule group needs monitoring."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested.",
        "Missing GetRuleGroup detail or ownership is UNKNOWN; a metrics setting does not establish effective web-ACL protection or log delivery.",
        "UpdateRuleGroup replaces the mutable group specification and requires a fresh lock token; preserve all rules and visibility fields. CloudFront scope uses us-east-1 and CloudWatch metrics may incur charges."
      ]
    },
    "static_observed_sentence": "CloudWatch metrics are disabled for the WAFv2 rule group.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "wafv2_rule_group",
      "predicate_qualname": "rule_group_metrics",
      "delegate_sources": {}
    }
  },
  "aws.pci.wafv2.rule_group_nonempty": {
    "description_fields": {
      "description": "Checks whether the WAFv2 rule group contains any rules."
    },
    "remediation_fields": {
      "summary": "Add rules if this group is intended to protect traffic, or remove an unused group through its configuration owner.",
      "steps": [
        "Add rules if this group is intended to protect traffic, or remove an unused group through its configuration owner."
      ],
      "caveats": [
        "An empty unused group does not establish that application traffic is unprotected.",
        "A nonempty Rules list does not prove web-ACL attachment, effective protection or blocking behavior; Count-only and unattached configurations require separate review.",
        "The signed predicate supplies no approved rule baseline: do not invent or automatically install rules. UpdateRuleGroup replaces the mutable specification and may affect shared consumers; CloudFront scope uses us-east-1."
      ]
    },
    "static_observed_sentence": "The WAFv2 rule group has no rules.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "wafv2_rule_group",
      "predicate_qualname": "rule_group_nonempty",
      "delegate_sources": {}
    }
  },
  "aws.pci.vpc.peering_dns_resolution": {
    "description_fields": {
      "description": "Checks remote DNS-resolution options on both sides of an active VPC peering connection."
    },
    "remediation_fields": {
      "summary": "Enable remote DNS resolution only on the peering sides that need it.",
      "steps": [
        "Enable remote DNS resolution only on the peering sides that need it."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "VPC peering DNS options",
          "url": "https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-dns.html"
        }
      ],
      "field_binding": {
        "fields": [
          "new read-only API call ec2:DescribeVpcPeeringConnections; requester/accepter PeeringOptions.AllowDnsResolutionFromRemoteVpc",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "vpc_peering_connection",
        "target": "resource"
      }
    },
    "static_observed_sentence": "Remote DNS resolution is disabled on at least one peering side.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "vpc_peering_connection",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "be8c5c71f5fda828355a8b726b0e35965dbc61499e0e2390cb3f60cffe0789b8"
      }
    }
  },
  "aws_vpc_uses_amazonprovided_dns": {
    "description_fields": {
      "description": "Joins VPC DHCP options and compares the DNS server set with AmazonProvidedDNS alone."
    },
    "remediation_fields": {
      "summary": "Keep the configured DNS servers if intentional; use AmazonProvidedDNS where required by the workload.",
      "steps": [
        "Keep the configured DNS servers if intentional; use AmazonProvidedDNS where required by the workload."
      ],
      "caveats": [
        "Custom DNS is a supported architecture, not inherently a security defect."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "VPC DHCP options",
          "url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_DHCP_Options.html"
        }
      ],
      "field_binding": {
        "fields": [
          "ec2:DescribeVpcs Vpcs[].VpcId, DhcpOptionsId; ec2:DescribeDhcpOptions DhcpOptions[].DhcpConfigurations[Key=domain-name-servers].Values[].Value",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "vpc",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The VPC DHCP options do not exclusively select AmazonProvidedDNS.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "vpc",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "cac27d666c0200a3c59e52763df5552bbfeee466958b0865abd83a613e3e2525"
      }
    }
  },
  "aws_g6_elbv2_only_https_tls_listeners": {
    "description_fields": {
      "description": "Checks that ALB/NLB listeners use HTTPS or TLS and declare a certificate."
    },
    "remediation_fields": {
      "summary": "Use TLS where this load balancer terminates encryption; preserve intentional encrypted TCP passthrough.",
      "steps": [
        "Use TLS where this load balancer terminates encryption; preserve intentional encrypted TCP passthrough."
      ],
      "caveats": [
        "TCP passthrough may carry end-to-end TLS; a protocol label alone cannot determine application encryption."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "ELB listener configuration",
          "url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Listener.html"
        }
      ],
      "field_binding": {
        "fields": [
          "elasticloadbalancingv2:DescribeLoadBalancers Type and DescribeListeners Protocol,Certificates for every application and network load balancer",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "load_balancer_v2",
        "target": "resource"
      }
    },
    "static_observed_sentence": "A listener uses another protocol or lacks a declared TLS certificate.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "load_balancer_v2",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "9f5b7d48aee4a7314a74fb70d02ef55879873a5a7b88dd751cc3a5990b93dfd2"
      }
    }
  },
  "aws_g6_api_stage_valid_client_certificate": {
    "description_fields": {
      "description": "Checks the stage\u2019s referenced API Gateway client certificate identity and expiry against collection time."
    },
    "remediation_fields": {
      "summary": "Configure or renew a client certificate if the backend uses API Gateway client-certificate authentication.",
      "steps": [
        "Configure or renew a client certificate if the backend uses API Gateway client-certificate authentication."
      ],
      "caveats": [
        "This client certificate authenticates API Gateway to its backend, not browser users."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "API Gateway Stage",
          "url": "https://docs.aws.amazon.com/apigateway/latest/api/API_Stage.html"
        }
      ],
      "field_binding": {
        "fields": [
          "apigateway:GetStages stageName,clientCertificateId; apigateway:GetClientCertificate clientCertificateId,expirationDate; scan capture time",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "rest_api_stage",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The stage has no matching unexpired client certificate.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rest_api_stage",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "9ed7beb8b41175ba2d755664b724393696dedc4d08be1825e578a63327ee9bc2"
      }
    }
  },
  "aws_shield_automatic_application_layer_response": {
    "description_fields": {
      "description": "Checks automatic application-layer response status for Shield-protected ALB and CloudFront resources."
    },
    "remediation_fields": {
      "summary": "Enable automatic application-layer response if appropriate for this Shield Advanced protection.",
      "steps": [
        "Enable automatic application-layer response if appropriate for this Shield Advanced protection."
      ],
      "caveats": [
        "This optional Advanced feature is separate from Shield Standard protection."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "Shield protection",
          "url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_Protection.html"
        }
      ],
      "field_binding": {
        "fields": [
          "new read-only API calls shield:DescribeProtection; ApplicationLayerAutomaticResponse.Status",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "shield_protection",
        "target": "resource"
      }
    },
    "static_observed_sentence": "Shield automatic application-layer response is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "shield_protection",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "9eb1f6afc507104ea1bd101655697b4a267fadcf5b17104781859c6b879282b6"
      }
    }
  },
  "aws_shield_protection_health_checks": {
    "description_fields": {
      "description": "Joins each configured Shield health-check ID to its collected Route53 health-check detail."
    },
    "remediation_fields": {
      "summary": "Associate a suitable health check if health-based Shield detection is needed, or repair missing referenced checks.",
      "steps": [
        "Associate a suitable health check if health-based Shield detection is needed, or repair missing referenced checks."
      ],
      "caveats": [
        "The check validates association and existence, not current endpoint health."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "Shield protection",
          "url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_Protection.html"
        }
      ],
      "field_binding": {
        "fields": [
          "existing shield_protection collector: shield:ListProtections (HealthCheckIds); new read-only route53:GetHealthCheck",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "shield_protection",
        "target": "resource"
      }
    },
    "static_observed_sentence": "No usable Route53 health-check association was found for this Shield protection.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "shield_protection",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "fdce52587a94f52c4c316c8f4beff701c4d2fd369359627ab83a9fc5ccb14da5"
      }
    }
  },
  "aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days": {
    "description_fields": {
      "description": "For joined Redis replication-group members, checks snapshot retention against a 15-day minimum; Valkey and other engines are not applicable."
    },
    "remediation_fields": {
      "summary": "Set snapshot retention to at least 15 days if suitable for the workload\u2019s recovery needs.",
      "steps": [
        "Set snapshot retention to at least 15 days if suitable for the workload\u2019s recovery needs."
      ],
      "caveats": [
        "Only the recorded configuration is assessed; runtime behavior is not independently tested."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "ElastiCache backup retention",
          "url": "https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-automatic.html"
        }
      ],
      "field_binding": {
        "fields": [
          "elasticache:DescribeReplicationGroups SnapshotRetentionLimit and automatic snapshot settings",
          "same-account and same-Region resource inventory and per-field collection coverage"
        ],
        "kind": "elasticache_replication_group",
        "target": "resource"
      }
    },
    "static_observed_sentence": "Snapshot retention is below 15 days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "elasticache_replication_group",
      "predicate_qualname": "callback.<locals>.evaluate",
      "delegate_sources": {
        "fn": "77f96cd1c6f1369392dc1aeb2d268e239a3f3886bada2b9f6efb2fa76f905be5"
      }
    }
  },
  "aws_cis_elbv2_only_tls_listeners": {
    "description_fields": {
      "description": "Checks ALB/NLB listener declarations for HTTP or TCP where this profile expects TLS termination; internal and Internet-facing load balancers are both assessed."
    },
    "remediation_fields": {
      "summary": "Use HTTPS/TLS termination where needed; retain intentional end-to-end encrypted TCP passthrough.",
      "steps": [
        "Use HTTPS/TLS termination where needed; retain intentional end-to-end encrypted TCP passthrough."
      ],
      "caveats": [
        "This profile does not inspect the application protocol carried through a TCP listener."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "ELB listener configuration",
          "url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Listener.html"
        }
      ],
      "field_binding": {
        "fields": [
          "complete scoped load_balancer inventory",
          "DescribeListeners Listeners[].Protocol",
          "Listeners[].ListenerArn and DefaultActions[].Type",
          "load balancer Type and ARN"
        ],
        "kind": "load_balancer",
        "target": "resource"
      }
    },
    "static_observed_sentence": "A listener declares HTTP or TCP rather than HTTPS/TLS termination.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "load_balancer",
      "predicate_qualname": "elbv2_tls_listeners",
      "delegate_sources": {}
    }
  },
  "aws.nist.rds_cluster_member_enhanced_monitoring": {
    "description_fields": {
      "description": "Checks every cluster member for an accepted Enhanced Monitoring interval and an in-account IAM role ARN."
    },
    "remediation_fields": {
      "summary": "Configure Enhanced Monitoring for members that need operating-system metrics.",
      "steps": [
        "Configure Enhanced Monitoring for members that need operating-system metrics."
      ],
      "caveats": [
        "Monitoring configuration does not demonstrate metric delivery or operational response."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "RDS Enhanced Monitoring",
          "url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html"
        }
      ],
      "field_binding": {
        "fields": [
          "rds:DescribeDBClusters DBClusterIdentifier, DBClusterMembers[].DBInstanceIdentifier; rds:DescribeDBInstances DBInstanceIdentifier, MonitoringInterval, MonitoringRoleArn, Engine",
          "complete identity-bound scoped native inventory and matching resource projection",
          "scope/provider/tenant or account/Region provenance and dependency collection status"
        ],
        "kind": "rds_cluster",
        "target": "resource"
      }
    },
    "static_observed_sentence": "A cluster member lacks the required monitoring interval or IAM role declaration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "rds_cluster_member_monitoring",
      "delegate_sources": {}
    }
  },
  "aws.pci.secretsmanager.kms_encryption_any": {
    "description_fields": {
      "description": "Resolves the secret\u2019s declared KMS key and checks that its metadata state is Enabled without reading secret values."
    },
    "remediation_fields": {
      "summary": "Repair the secret\u2019s KMS key availability while preserving decrypt access for existing consumers.",
      "steps": [
        "Repair the secret\u2019s KMS key availability while preserving decrypt access for existing consumers."
      ],
      "caveats": [
        "Key state does not establish effective decrypt permissions; no secret value is retrieved."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "DescribeSecret",
          "url": "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html"
        }
      ],
      "field_binding": {
        "fields": [
          "secretsmanager:DescribeSecret KmsKeyId; kms:DescribeKey KeyMetadata.KeyManager, KeyState",
          "complete identity-bound scoped native inventory and matching resource projection",
          "scope/provider/tenant or account/Region provenance and dependency collection status"
        ],
        "kind": "secret",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The secret\u2019s resolved KMS key is not enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "secret",
      "predicate_qualname": "secret_uses_enabled_kms",
      "delegate_sources": {}
    }
  },
  "aws_nist_efs_access_point_enforce_root_directory": {
    "description_fields": {
      "description": "Checks whether the access point declares a nonempty root directory other than /."
    },
    "remediation_fields": {
      "summary": "Set a dedicated root directory if this access point should confine clients to a subtree.",
      "steps": [
        "Set a dedicated root directory if this access point should confine clients to a subtree."
      ],
      "caveats": [
        "The configured root path does not by itself certify mount authorization or tenant isolation."
      ],
      "review_status": "approved",
      "cli": [],
      "iac": null,
      "references": [
        {
          "title": "EFS access point root directory",
          "url": "https://docs.aws.amazon.com/efs/latest/ug/enforce-root-directory-access-point.html"
        }
      ],
      "field_binding": {
        "fields": [
          "DescribeAccessPoints.AccessPointArn and complete RootDirectory representation",
          "RootDirectory.Path with exact regional account identity"
        ],
        "kind": "efs_access_point",
        "target": "resource"
      }
    },
    "static_observed_sentence": "The access point has no dedicated non-root directory.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "efs_access_point",
      "predicate_qualname": "efs_root",
      "delegate_sources": {}
    }
  }
}
''' )

def _apply(cid, original, kind):
    row = ROWS.get(cid)
    if row is None:
        return original
    result = deepcopy(original) if isinstance(original, dict) else {}
    result.update(deepcopy(row[kind + '_fields']))
    return result

def description(cid,original):
    return _apply(cid,original,'description')

def remediation(cid,original):
    return _apply(cid,original,'remediation')

REVIEWED_RISKS = {cid:(row['reviewed_source_severity'],row['reviewed_severity']) for cid,row in ROWS.items()}

def evidence_summary(finding):
    """Describe decisive captured fields only; a legacy verdict is not evidence."""
    if not isinstance(finding,dict) or finding.get('provider') != 'aws' or finding.get('status') != 'FAIL':
        return None
    cid=finding.get('check_id');e=finding.get('evidence')
    if cid not in ROWS or not isinstance(e,dict):return None
    def strings(value):return isinstance(value,list) and all(isinstance(x,str) and x for x in value)
    def positive(value):return type(value)is int and value>0
    def present(key):return strings(e.get(key)) and bool(e[key])
    def names(key):return ', '.join(e[key][:3])+(' and more' if len(e[key])>3 else '')
    if cid.endswith('_trust_boundary'):
        label={'aws.htbp.lambda.layer_version_trust_boundary':'Lambda layer policy','aws.htbp.ecr.registry_policy_trust_boundary':'ECR registry policy','aws.htbp.ecr.creation_template_policy_trust_boundary':'Repository creation-template policy'}.get(cid)
        if e.get('public') is True and label:
            return label+' declares an unrestricted public principal.'
        if e.get('public') is False and e.get('organization_inventory') is True and present('external_accounts') and all(len(x)==12 and x.isdecimal() for x in e['external_accounts']):
            return 'The declaration names accounts outside the collected organization: '+names('external_accounts')+'.'
        return None
    if cid=='aws_cloudfront_origin_failover_configured':
        if e.get('origin_group_count')==0 and type(e.get('origin_group_count')) is int:return 'No CloudFront origin failover group is configured.'
        if positive(e.get('origin_group_count')) and present('invalid_origin_groups'):return 'Origin groups failing the declared member or failover-code checks: '+names('invalid_origin_groups')+'.'
        return None
    if cid=='aws_config_continuous_inventory':
        if e.get('recording') is False:return 'The Config recorder reports recording disabled.'
        if e.get('all_supported') is False:return 'The Config recorder does not declare allSupported=true.'
        if e.get('frequency')=='DAILY':return 'The Config recorder declares DAILY default recording.'
        if strings(e.get('override_frequencies')) and 'DAILY' in e['override_frequencies']:return 'A Config recording-frequency override declares DAILY recording.'
        return None
    if cid=='aws_config_recorder_all_supported_resources':
        if e.get('all_supported') is False or e.get('strategy')=='INCLUSION_BY_RESOURCE_TYPES' or present('excluded_resource_types'):return 'The Config recording declaration does not cover all supported resource types.'
        return None
    if cid=='aws_config_all_resources_recorded':
        if e.get('recorder')=='absent':return 'No customer-managed Config recorder was found in this regional inventory.'
        if e.get('run_state') in ('stopped','failed'):return 'The customer-managed Config recorder reports '+e['run_state']+'.'
        if e.get('recording_scope')=='restricted':return 'The customer-managed Config recorder declares restricted resource-type coverage.'
        return None
    if cid=='aws_acm_certificate_lifecycle':
        if e.get('status') in ('PENDING_VALIDATION','INACTIVE','EXPIRED','VALIDATION_TIMED_OUT','REVOKED','FAILED') and positive(e.get('in_use_by_count')):return 'The in-use certificate reports status '+e['status']+'.'
        if e.get('status')=='ISSUED' and positive(e.get('in_use_by_count')) and isinstance(e.get('expiry'),str) and isinstance(e.get('observation_time'),str):
            from datetime import datetime,timedelta
            try:
                expiry=datetime.fromisoformat(e['expiry']);now=datetime.fromisoformat(e['observation_time'])
                if expiry.tzinfo is None or now.tzinfo is None:return None
                if expiry<=now:return 'The in-use certificate expired at '+e['expiry']+'.'
                if expiry<=now+timedelta(days=30) and e.get('renewal_eligibility')=='INELIGIBLE':return 'The in-use certificate expires within 30 days and is not eligible for managed renewal.'
            except ValueError:return None
        return None
    if cid in {'aws_fedramp_acm_all_certificates_30_day_expiry','aws.nist.acm_all_certificates_expiry_30_days','aws_nist_acm_certificate_expires_30_days','aws_g6_acm_all_certificates_30_day_expiry'}:
        from datetime import datetime
        try:
            expiry=datetime.fromisoformat(e.get('not_after',''));threshold=datetime.fromisoformat(e.get('threshold',''))
            boundary=e.get('boundary')
            if expiry.tzinfo is None or threshold.tzinfo is None:return None
            matched=expiry<=threshold if boundary=='closed_instant' else expiry<threshold if boundary=='strict_instant' else expiry.date()<threshold.date() if boundary=='strict_date' else False
            if matched:return 'The certificate expires at '+e['not_after']+'.'
        except (ValueError,TypeError):pass
        return None
    # Each entry below binds a specific reviewed predicate to its decisive field.
    guards={
      'aws.htbp.sagemaker.notebook_imdsv2_required':e.get('minimum_imds_version')=='1',
      'aws.htbp.glue.dev_endpoint_not_public':isinstance(e.get('public_address'),str) and bool(e['public_address']),
      'aws.htbp.appsync.no_api_key_additional_auth':strings(e.get('additional_authentication_types')) and 'API_KEY' in e['additional_authentication_types'],
      'aws.htbp.cognito.client_no_writable_authorization_attributes':isinstance(e.get('clients'),list) and any(isinstance(c,dict) and isinstance(c.get('client_id'),str) and strings(c.get('attributes')) and c['attributes'] for c in e['clients']),
      'aws.gap.securityhub.region_hub_enabled':e.get('hubs')==[],
      'aws.gap.accessanalyzer.no_active_findings':positive(e.get('active_findings')),
      'aws.gap.vpc.sg_world_any_common_ports':positive(e.get('matching_rules')),
      'aws.gap.classic_elb.ssl_listeners_use_acm':isinstance(e.get('non_acm_certificates'),list) and bool(e['non_acm_certificates']),
      'aws_nist_cloudwatch_alarm_action_enabled':e.get('actions_enabled') is False or (e.get('actions_enabled') is True and e.get('state_actions')=={'AlarmActions':0,'OKActions':0,'InsufficientDataActions':0}),
      'aws_backup_cross_region_copy':isinstance(e.get('missing_cross_region_rules'),list) and bool(e['missing_cross_region_rules']) and all(positive(x) for x in e['missing_cross_region_rules']),
      'aws_guardduty_no_active_high_findings':present('active_high_finding_ids') and e.get('high_severity_range')=='7.0 <= Severity < 9.0',
      'aws.pci.apigateway.all_methods_logging':present('unsafe_method_overrides'),
      'aws.pci.apigateway.all_methods_cache_encrypted':present('unencrypted_enabled_overrides'),
      'aws_inspector2_ec2_no_high_critical_findings':present('active_high_critical_ec2_findings'),
      'aws.pci.wafv2.rule_group_metrics':e.get('cloudwatch_metrics_enabled') is False,
      'aws.pci.wafv2.rule_group_nonempty':type(e.get('rule_count')) is int and e['rule_count']==0,
      'aws_vpc_uses_amazonprovided_dns':strings(e.get('dns_servers')) and set(e['dns_servers'])!={'AmazonProvidedDNS'},
      'aws_g6_api_stage_valid_client_certificate':e.get('reason') in ('no client certificate','certificate not found'),
      'aws_shield_protection_health_checks':e.get('reason') in ('no health checks','health check does not exist'),
      'aws_nist_elasticache_redis_cluster_automatic_backup_retention_15_days':type(e.get('retention_days')) is int and 0<=e['retention_days']<15,
      'aws_cis_elbv2_only_tls_listeners':present('plaintext_listener_arns'),
      'aws.nist.rds_cluster_member_enhanced_monitoring':present('members_without_monitoring'),
      'aws.pci.secretsmanager.kms_encryption_any':e.get('key_state') in ('Disabled','PendingDeletion','PendingImport','Unavailable','Creating','Updating','PendingReplicaDeletion'),
      'aws_nist_efs_access_point_enforce_root_directory':isinstance(e.get('root_path'),str) and e['root_path'] in ('','/'),
    }
    # Some legacy callbacks return {}; protocol alone cannot prove a missing
    # certificate on an HTTPS listener. Leave those observations unexpanded.
    return ROWS[cid]['static_observed_sentence'] if guards.get(cid) is True else None
