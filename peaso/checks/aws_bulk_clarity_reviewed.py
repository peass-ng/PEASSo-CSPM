"""52 reviewed AWS bulk predicates with concise, bounded, text-only guidance.

Legacy labels remain stable; actual native joins and callback bindings determine
these descriptions. Two custom-scope controls are historical only.
"""
from copy import deepcopy
import json
VERSION="aws-bulk-clarity-v1"
ROWS=json.loads(r'''
{
  "aws.nist.cloudtrail_cloudwatch_destination_kms": {
    "description_fields": {
      "description": "Joins home-region trails that declare a CloudWatch destination and requires enabled customer-managed keys for both the trail and destination log group."
    },
    "remediation_fields": {
      "caveats": [
        "AWS-managed encryption is still encryption; key metadata does not prove live delivery or key usability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "cloudtrail:DescribeTrails CloudWatchLogsLogGroupArn, KmsKeyId; logs:DescribeLogGroups arn,kmsKeyId; kms:DescribeKey key metadata",
          "Complete inventories: cloudtrail_account_inventory, log_group, kms_key"
        ],
        "kind": "cloudtrail",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS AWSCLOUDTRAIL Trail API",
          "url": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable customer-managed keys where this trail-and-destination key profile is required."
      ],
      "summary": "Configure suitable customer-managed keys where this trail-and-destination key profile is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_BUCKET_LOG_IDS": [
          "aws.nist.all_cloudtrail_destination_bucket_access_logging",
          "aws_g6_all_cloudtrail_destination_bucket_access_logging",
          "aws_nist_cloudtrail_s3_logging_enabled"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_INTEGRATION_IDS": [
          "aws.nist.cloudtrail_cloudwatch_integration",
          "aws_g6_cloudtrail_all_trails_cloudwatch_integration",
          "aws_nist_cloudtrail_trail_integrated_with_logs"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_KMS_IDS": [
          "aws.nist.cloudtrail_cloudwatch_destination_kms",
          "aws_g6_cloudtrail_kms_destination_join",
          "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54::_TRAIL_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/[^/]+$"
        }
      },
      "defaults": [
        "aws.nist.cloudtrail_cloudwatch_destination_kms"
      ],
      "kind": "cloudtrail",
      "module": "peaso.checks._bulk_pending_compliance_new_sw35",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket:106": "e493342d52113857ba0d0af8ddd5f32503d2944564dc0051a3554de726460ccc",
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket_logging:113": "68fc91ccd885bd01b93f958ea79dd31166c6af13c042d6770923cd2ca019aaa0",
        "peaso.checks._bulk_pending_compliance_new_sw35._buckets:95": "227115d6eb587786a120a21452bc2f26db85062029a81d9f4ad1158a7bab8d8b",
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206": "7fc7f38f518800a5a237de0a0c8b4937dcdf8c6ca2e10d180f0e5337f75b16ba",
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167": "96e40d1857f7bb7cb2660935c2e41b65c401e24c3cb3b516e384e178ce1aa3b9",
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18": "48b3eff2b783841a7478854de3ef23f3c9600d0b262b1794a8582bc34b330809",
        "peaso.checks._bulk_pending_compliance_new_sw35._evaluate:571": "db6c233dce944c8523f68ebf521fbf5bdfa8a548e3ea4b098f3373cc2bd71944",
        "peaso.checks._bulk_pending_compliance_new_sw35._fresh:199": "9cdf65b158b6f51314e700fefa8857746f70b9f0287e7aabed574b1fb078cddb",
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155": "b5ce980ad26baadef5b7298e7ec5d315b91962928303c5b94d059ccf6e59f538",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141": "d9daab07009418426d93241d4368f389c07d6cdcce215e3919bd12e5fcf8718e",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129": "641b90e97047905dd88770f7df2172cea89b1c98fa63561da9e2eb5700ff59f7",
        "peaso.checks._bulk_pending_compliance_new_sw35._logging_trails:86": "bd9ce49432fd6c17fd2dd9fc90940c119a3b72129ee39f3823cd16dcfc70ffd0",
        "peaso.checks._bulk_pending_compliance_new_sw35._policy:454": "e452be311f5a85f4efe2ece666384392fdbedd6ad6fde9a6fcc855f5c34fa881",
        "peaso.checks._bulk_pending_compliance_new_sw35._registered:586": "0b9679c5acb0a2c3d4d45db82a7142195783c971b43ac1b6a32e30874dd41d7e",
        "peaso.checks._bulk_pending_compliance_new_sw35._rows:27": "21633a64b94ae91fc79c7b380b07edc77a245adcb678b19112a3bd43ac0085b3",
        "peaso.checks._bulk_pending_compliance_new_sw35._ssm:482": "e5813f4c7b7a39967a90b4b2cf87b5aacaef0883016be87d60241c2c2d7637b1",
        "peaso.checks._bulk_pending_compliance_new_sw35._time:187": "5784d81b10523f17207ad7111a67f6f185f2737a625cb9ed54cd01eadac1cdcb",
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54": "f1daede05c5e264575b3ddd0844fb83c3a1df06eebd07ec719f1223e889bfb25",
        "peaso.checks._bulk_pending_compliance_new_sw35._versions_at_least:471": "6ffde1815a868afa5d9dfa65e34edb92a5ddc9bfcc6d28d1794b4530b9b959f8"
      },
      "source_qualname": "_registered"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A trail or its CloudWatch destination lacks an enabled customer-managed key."
  },
  "aws.nist.ec2_instance_effective_public_reachability": {
    "description_fields": {
      "description": "Joins the instance to a complete configured-ingress projection or independently reconstructs a supported direct IPv4 public-path witness."
    },
    "remediation_fields": {
      "caveats": [
        "This is a configuration model, not a packet test; a supported public witness does not evaluate all remaining paths."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ec2:DescribeInstances public IPv4/IPv6, ENI addresses, security groups; ec2:DescribeRouteTables routes and gateways; elbv2:DescribeTargetGroups/DescribeLoadBalancers public listeners and targets",
          "Complete inventories: ec2_instance, ec2_effective_ingress"
        ],
        "kind": "ec2_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS EC2 Describe Instances API",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict only unnecessary ingress sources, ports or listeners on the identified path."
      ],
      "summary": "Restrict only unnecessary ingress sources, ports or listeners on the identified path."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58::GLOBAL_KINDS": [
          "cloudfront_distribution",
          "iam_credential_report",
          "iam_user",
          "organization",
          "organization_account",
          "organization_delegated_admin",
          "organization_effective_scp",
          "organization_resource_policy",
          "organization_service_access",
          "shield_drt_access",
          "shield_protection",
          "shield_subscription"
        ]
      },
      "defaults": null,
      "kind": "ec2_instance",
      "module": "peaso.checks._bulk_pending_compliance_new_sw37",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw37._account:110": "0557de7589935ca7b17b5b8dc886a28467bd2215fbea66e5f56b4a1d2b9cc0a3",
        "peaso.checks._bulk_pending_compliance_new_sw37._account_arn:118": "cbe535c81de20cad9dfe261f71512b3fbf0dd31e80f22074851df19136624e09",
        "peaso.checks._bulk_pending_compliance_new_sw37._arn:112": "02e5f0b4567d6d6d86e112d77838553a42c689d583f06de9bc12577c5c8dd7ef",
        "peaso.checks._bulk_pending_compliance_new_sw37._member:76": "fda5bf12e8ded3a344b7c874792e44850970b257a931b645269ff38a2629c81f",
        "peaso.checks._bulk_pending_compliance_new_sw37._reachability:437": "357dd32f925f816f886add4925521a711d6c3d733537c144a3a8a09d962801cc",
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58": "8f7abdaf6cebf992749e3e83418d8091f5891d38bb9c1bd1bbe61277d5daf8c3",
        "peaso.checks._bulk_pending_compliance_new_sw37._scope:49": "9af44f1b2451ca6be4b5bf54996ddc2943adac973d2722464f7d18e54302b501",
        "peaso.checks._bulk_pending_compliance_new_sw37.nist_reach:475": "b33a8b0ff9cc8416e162375ec23e4935106cc7fd10a0a3525a6425895c2576bf"
      },
      "source_qualname": "nist_reach"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance has a modeled public configuration path."
  },
  "aws.nist.waf_classic_regional_acl_logging": {
    "description_fields": {
      "description": "Checks complete account-wide regional WAF Classic ACL inventory for nonempty valid logging destinations."
    },
    "remediation_fields": {
      "caveats": [
        "Destination declarations do not prove log delivery; WAFv2 and global Classic are separate in this check."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "waf-regional:ListWebACLs; waf-regional:GetLoggingConfiguration for each WebACLId",
          "Complete inventories: waf_account_acl_inventory"
        ],
        "kind": "waf_web_acl",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS WAF Get Logging Configuration API",
          "url": "https://docs.aws.amazon.com/waf/latest/APIReference/API_GetLoggingConfiguration.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure appropriate logging destinations for the affected regional Classic ACLs."
      ],
      "summary": "Configure appropriate logging destinations for the affected regional Classic ACLs."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "waf_web_acl",
      "module": "peaso.checks._bulk_pending_compliance_new_sw38",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw38._arn_account_region:248": "2bde834fe5016372e0c5f00ff742ec437576a6a557f30ba2ec1624030625caaa",
        "peaso.checks._bulk_pending_compliance_new_sw38._logging_missing:662": "8abb2889bffdc51d81b59f83b35bad279d99bd3f7cdb9d083fc04afe8ff366dd",
        "peaso.checks._bulk_pending_compliance_new_sw38._objects:242": "47c20e21db77e817c51f8826e59d29f887b7756d85eac5308b25b9ef4b47d4ec",
        "peaso.checks._bulk_pending_compliance_new_sw38._rows:185": "f53fe1b0ef2c2bd14680a16afeb1f238c0e883c8840a18502f037aaa39466d60",
        "peaso.checks._bulk_pending_compliance_new_sw38._scope:175": "7b34c7e1ffd89c0d626acc87d44ac8a20319570b3d16ccc0206405a628047d99",
        "peaso.checks._bulk_pending_compliance_new_sw38._strings:235": "9780c759d804462d107a20b3da9a860b0b18be05957a46ac9955cb5a2c763271",
        "peaso.checks._bulk_pending_compliance_new_sw38._waf_account:627": "0844e2b98795b85f534db3ad6c088ed65fd73e5a038bd2109ee76da783c318b6",
        "peaso.checks._bulk_pending_compliance_new_sw38._waf_scope:653": "add82ad6b345c668aa09f91ace51c6f5c357a0fe30c37b89692d624b3fd53f5b",
        "peaso.checks._bulk_pending_compliance_new_sw38.waf_classic_regional_logging:676": "d02378387d61cbe1a693abadc42f18abb110a5cbe95eb72518e67e177a6e6a2a"
      },
      "source_qualname": "waf_classic_regional_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A regional WAF Classic ACL has no configured logging destination."
  },
  "aws.pci.appsync.waf_web_acl": {
    "description_fields": {
      "description": "Joins each AppSync API to its uniquely scoped WAFv2 association record."
    },
    "remediation_fields": {
      "caveats": [
        "An association does not prove effective rules or actual blocked requests."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only API calls appsync:ListGraphqlApis and wafv2:ListResourcesForWebACL; apiArn and associated resource ARNs",
          "Complete inventories: appsync_graphql_api, wafv2_appsync_association"
        ],
        "kind": "appsync_graphql_api",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS WAF Get Web ACL For Resource API",
          "url": "https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACLForResource.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Associate a suitable WAF ACL if this API requires request filtering."
      ],
      "summary": "Associate a suitable WAF ACL if this API requires request filtering."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw49._arn:90::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12})?:(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw49._context:29::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/(global|[a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "appsync_graphql_api",
      "module": "peaso.checks._bulk_pending_compliance_new_sw49",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw49._arn:90": "03ee16d7b213cbddd913d031852b20cd10f145dc1f68943c366596313e81bd4a",
        "peaso.checks._bulk_pending_compliance_new_sw49._context:29": "5899669342e76e9917020ef86d4fa2e41b0a7c953dd4907ad561177bb230d5ec",
        "peaso.checks._bulk_pending_compliance_new_sw49._inventory:40": "03bb5a00591d148a03ea9445b405fcc1fcf0fae1e74e8e24df180a7d508af6ce",
        "peaso.checks._bulk_pending_compliance_new_sw49._member:68": "f22c2d0f53827f9ef9b90cbd1de206d5633976e1cd75cbfdfcabdc6fdb621358",
        "peaso.checks._bulk_pending_compliance_new_sw49.appsync_waf_web_acl:393": "b26736ef849c75af40c5bd252ce7cf974a8b32f429bf1000bb2fb76ebfa21647"
      },
      "source_qualname": "appsync_waf_web_acl"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The AppSync API has no WAFv2 web ACL association."
  },
  "aws.pci.classic_elb.predefined_ssl_policy": {
    "description_fields": {
      "description": "Compares each HTTPS/SSL listener\u2019s policy name, type and attributes with the native predefined policy catalog."
    },
    "remediation_fields": {
      "caveats": [
        "Equivalent customer-named settings remain UNKNOWN without a proven catalog reference; no live TLS negotiation is performed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "elb:DescribeLoadBalancers ListenerDescriptions[].Listener.Protocol, PolicyNames; elb:DescribeLoadBalancerPolicies PolicyDescriptions[].PolicyTypeName, PolicyAttributeDescriptions",
          "Complete inventories: classic_elb"
        ],
        "kind": "classic_elb",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS Elastic Load Balancing Describe Load Balancer Policies API",
          "url": "https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancerPolicies.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Attach a suitable provider predefined SSL policy if this profile is required; preserve client compatibility."
      ],
      "summary": "Attach a suitable provider predefined SSL policy if this profile is required; preserve client compatibility."
    },
    "reviewed_binding": {
      "closure": {
        "identifier": "aws.pci.classic_elb.predefined_ssl_policy"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811::EVALUATORS": {
          "aws.nist.sc_36_coverage": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._recovery"
          },
          "aws.pci.classic_elb.custom_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.classic_elb.predefined_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.redshift.expected_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._redshift"
          },
          "aws.pci.secretsmanager.kms_encryption_any": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._kms"
          },
          "aws_autoscaling_userdata_plaintext_aws_key": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._userdata"
          },
          "aws_ecr_repository_lifecycle_retention": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecr"
          },
          "aws_g6_ecs_fargate_storage_encryption": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecs"
          },
          "aws_nist_cloudformation_stack_drift_detection_check": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._drift"
          },
          "aws_nist_config_enabled_all_regions": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._config"
          },
          "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rds"
          },
          "aws_nist_secretsmanager_secret_automatic_rotation_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rotation"
          },
          "aws_organizations_environment_account_separation": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._separation"
          },
          "aws_sagemaker_model_clarify_bias_job": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._clarify"
          },
          "aws_vpn_tunnel_encryption_configuration": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._vpn"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[a-z0-9-]*:[0-9]{12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_SCOPE": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z0-9-]+$"
        }
      },
      "defaults": null,
      "kind": "classic_elb",
      "module": "peaso.checks._bulk_pending_compliance_new_sw48",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>:785": "b8af46bb1835d7114b6ba6d3a258be4c36a5113ccd4f95c47dd0441dff877e9c",
        "peaso.checks._bulk_pending_compliance_new_sw48._date:75": "f13c9643257a1622f65e0310d7cb12d44d686e3adc05922fafa1ba1857321844",
        "peaso.checks._bulk_pending_compliance_new_sw48._elb:357": "1a45e7c916c2388034750142fa1c2ac9f66a7b8f04cc5540527eb153e8daaefc",
        "peaso.checks._bulk_pending_compliance_new_sw48._elb_policy_source:337": "a3606f09ca6397aa0100d1f0ccc4a64dcff7b3047ecceaf8791e3006cd5e0f46",
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811": "ae35cf3acf73d2d9b595a8f64672eba95725a8530d896346dfb770b772644588",
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34": "28c7fa38621503a88a0564acb5b0abd82e7036874d3c1edd271d85c2aecb2d9e",
        "peaso.checks._bulk_pending_compliance_new_sw48._policy:65": "f681afe0df759e520b3aca7e331f5beed0948345f9fe927c049e80fee2992865"
      },
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A TLS listener lacks a policy matching the native predefined catalog."
  },
  "aws.pci.client_vpn.no_authorize_all_groups": {
    "description_fields": {
      "description": "Finds active Client VPN authorization rules allowing all groups, excluding customer-approved endpoint exceptions."
    },
    "remediation_fields": {
      "caveats": [
        "This historical profile requires a customer-approved exception list and is excluded from native-only execution."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ec2:DescribeClientVpnAuthorizationRules for each collected ClientVpnEndpointId",
          "Complete inventories: client_vpn_endpoint"
        ],
        "kind": "client_vpn_endpoint",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS EC2 Client Vpn Authorization Rule API",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ClientVpnAuthorizationRule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Use group-specific authorization where access should not extend to every authenticated client."
      ],
      "summary": "Use group-specific authorization where access should not extend to every authenticated client."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "client_vpn_endpoint",
      "module": "peaso.checks._bulk_pending_compliance_new_sw06",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw06._inventory:16": "5bd61e1e4f0be89d2d273e4b5786d149d7d9989d1e5c632f77ba27cd68ca4ab5",
        "peaso.checks._bulk_pending_compliance_new_sw06._params:70": "50297c14c44c45816a47d59b42a05765dca7e673cb564415871ff94e56bf23cc",
        "peaso.checks._bulk_pending_compliance_new_sw06._strings:76": "2297de791071e29f8ba7abeb31f57285261e5759709760d39cf47a5c3a9029f9",
        "peaso.checks._bulk_pending_compliance_new_sw06._vpn_all_groups:409": "04d9b4704ebacffb1d752f10904fd2f6b20d68331ed428e12c7c1a293dded1b2",
        "peaso.checks._bulk_pending_compliance_new_sw06.check_aws_pci_client_vpn_no_authorize_all_groups:597": "7523eaf87482d2705fa541ba4fd105456c7a6d43d04da9af38c499c9baaedcfb"
      },
      "source_qualname": "check_aws_pci_client_vpn_no_authorize_all_groups"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An active Client VPN authorization rule allows all groups without a listed endpoint exception."
  },
  "aws.pci.iam.nonconsole_mfa_policy": {
    "description_fields": {
      "description": "Checks selected administrator wildcard Allow statements for Bool aws:MultiFactorAuthPresent=true; Deny and negative-action semantics remain UNKNOWN."
    },
    "remediation_fields": {
      "caveats": [
        "This literal MFA-condition check does not prove effective permissions and may not fit federated or workload credentials."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "existing collected type iam_policy + PolicyDocument.Statement[].Condition and IAM principal MFA devices",
          "Complete inventories: iam_policy"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS IAM Get Account Authorization Details API",
          "url": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Constrain administrator grants and require suitable authentication controls for their intended callers."
      ],
      "summary": "Constrain administrator grants and require suitable authentication controls for their intended callers."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw40._context:35::_ACCOUNT": {
          "flags": 32,
          "regex": "^[0-9]{12}$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw40._managed_document:114::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):iam::([0-9]{12}|aws):policy/.+$"
        }
      },
      "defaults": null,
      "kind": "iam_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw40",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw40._context:35": "24a3c8c283d7e2dfbeafd355205c183825acd121eaf5fdf0fa2bae69b6fbcd4d",
        "peaso.checks._bulk_pending_compliance_new_sw40._document:67": "443dbbf716af6733c37d3ae2e8571caf84ee580049ad297693a60a9d53d2b938",
        "peaso.checks._bulk_pending_compliance_new_sw40._managed_document:114": "e14f3335c4b709fb4993bd3a1af08aba587f7c41b87eeac45b0bd3b8de729094",
        "peaso.checks._bulk_pending_compliance_new_sw40._nonconsole_mfa:470": "c668145b412de5faf632486dd8024826446f1a96e75bb1a3ea527fd06215f0f3",
        "peaso.checks._bulk_pending_compliance_new_sw40._one_policy:199": "6ee380ad5a0b2960cebbffa47092548f43b2eb0de3833993e630d04ca8281d69",
        "peaso.checks._bulk_pending_compliance_new_sw40._rows:46": "71e3728469f5a6dc199c8eafcdbedfd62ba427a00c7d102d47bb64e881bc2811",
        "peaso.checks._bulk_pending_compliance_new_sw40._statement:90": "ae6867f60cc6c897e61ebde06158e2f45a589b700b1bba5d2f87249728a8372d",
        "peaso.checks._bulk_pending_compliance_new_sw40._terms:82": "a0e5e7ede6cbc70e0315a593bc570fcacd7fe888b49e6c0f5b4f4d976bbeba62"
      },
      "source_qualname": "_nonconsole_mfa"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "An administrator wildcard statement lacks this profile\u2019s explicit MFA-present condition."
  },
  "aws.pci.iam.policy_attached_to_active_principal": {
    "description_fields": {
      "description": "Joins policy attachments to users, populated groups or roles with declared usable trust, validating native attachment counts."
    },
    "remediation_fields": {
      "caveats": [
        "A declared attachment or trust witness does not prove recent principal activity despite the legacy label."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Complete iam:GetAccountAuthorizationDetails policy, user, group, and role inventories",
          "AttachmentCount and each principal's AttachedManagedPolicies",
          "UserDetail.GroupList membership and RoleDetail.AssumeRolePolicyDocument trust"
        ],
        "kind": "iam_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS IAM Get Account Authorization Details API",
          "url": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unused policies or attach only where required after reviewing actual usage."
      ],
      "summary": "Remove unused policies or attach only where required after reviewing actual usage."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw40._context:35::_ACCOUNT": {
          "flags": 32,
          "regex": "^[0-9]{12}$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw40._managed_document:114::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):iam::([0-9]{12}|aws):policy/.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw40._native_policy_attachment:233::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):iam::([0-9]{12}|aws):policy/.+$"
        }
      },
      "defaults": null,
      "kind": "iam_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw40",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw40._context:35": "24a3c8c283d7e2dfbeafd355205c183825acd121eaf5fdf0fa2bae69b6fbcd4d",
        "peaso.checks._bulk_pending_compliance_new_sw40._declared_role_trust:378": "42340d84284104aa79293cd08e7629f61c91c0ff129d4f5693181075caab79ac",
        "peaso.checks._bulk_pending_compliance_new_sw40._document:67": "443dbbf716af6733c37d3ae2e8571caf84ee580049ad297693a60a9d53d2b938",
        "peaso.checks._bulk_pending_compliance_new_sw40._managed_document:114": "e14f3335c4b709fb4993bd3a1af08aba587f7c41b87eeac45b0bd3b8de729094",
        "peaso.checks._bulk_pending_compliance_new_sw40._native_policy_attachment:233": "a5b87fc74d8e4f40f988152706bf8d3a5b866263aff5bb49665672be982db81a",
        "peaso.checks._bulk_pending_compliance_new_sw40._one_policy:199": "6ee380ad5a0b2960cebbffa47092548f43b2eb0de3833993e630d04ca8281d69",
        "peaso.checks._bulk_pending_compliance_new_sw40._policy_attachment:417": "c23ca6c480aabdd58eff36a2502c84adcc3201cfa0fec0978cc3f2d7b2a3bb2c",
        "peaso.checks._bulk_pending_compliance_new_sw40._rows:46": "71e3728469f5a6dc199c8eafcdbedfd62ba427a00c7d102d47bb64e881bc2811"
      },
      "source_qualname": "_policy_attachment"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The policy lacks an attachment satisfying this source\u2019s principal and trust criteria."
  },
  "aws.pci.shield.protection_all_internet_resources": {
    "description_fields": {
      "description": "Compares Shield protections with internet-facing ALBs, Classic ELBs, CloudFront distributions and Elastic IPs in complete scoped inventories."
    },
    "remediation_fields": {
      "caveats": [
        "This optional paid protection profile does not test exposure, attack resistance or every resource family."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "shield:ListProtections plus elasticloadbalancing:DescribeLoadBalancers, cloudfront:ListDistributions and ec2:DescribeAddresses",
          "Complete inventories: shield_protection, load_balancer, classic_load_balancer, cloudfront_distribution, elastic_ip"
        ],
        "kind": "shield_protection",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS WAF Protection API",
          "url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_Protection.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Consider Shield Advanced protection for the identified resources if their availability requirements justify it."
      ],
      "summary": "Consider Shield Advanced protection for the identified resources if their availability requirements justify it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58::GLOBAL_KINDS": [
          "cloudfront_distribution",
          "iam_credential_report",
          "iam_user",
          "organization",
          "organization_account",
          "organization_delegated_admin",
          "organization_effective_scp",
          "organization_resource_policy",
          "organization_service_access",
          "shield_drt_access",
          "shield_protection",
          "shield_subscription"
        ]
      },
      "defaults": null,
      "kind": "shield_protection",
      "module": "peaso.checks._bulk_pending_compliance_new_sw37",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw37._account:110": "0557de7589935ca7b17b5b8dc886a28467bd2215fbea66e5f56b4a1d2b9cc0a3",
        "peaso.checks._bulk_pending_compliance_new_sw37._account_arn:118": "cbe535c81de20cad9dfe261f71512b3fbf0dd31e80f22074851df19136624e09",
        "peaso.checks._bulk_pending_compliance_new_sw37._arn:112": "02e5f0b4567d6d6d86e112d77838553a42c689d583f06de9bc12577c5c8dd7ef",
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58": "8f7abdaf6cebf992749e3e83418d8091f5891d38bb9c1bd1bbe61277d5daf8c3",
        "peaso.checks._bulk_pending_compliance_new_sw37._scope:49": "9af44f1b2451ca6be4b5bf54996ddc2943adac973d2722464f7d18e54302b501",
        "peaso.checks._bulk_pending_compliance_new_sw37.shield_all:134": "dc06f37adafd426bbe1e07b3401d7cb50c3c5875bbff1d67a66548584132a0f3"
      },
      "source_qualname": "shield_all"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A resource in the modeled public-resource set lacks a Shield protection record."
  },
  "aws.pci.sns.delivery_status_logging": {
    "description_fields": {
      "description": "Joins topic subscriptions to supported protocols and requires success/failure feedback roles plus a positive success-sampling rate for each."
    },
    "remediation_fields": {
      "caveats": [
        "These declarations do not prove role usability or delivered logs; unsupported protocol mappings remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only API call sns:GetTopicAttributes; *FailureFeedbackRoleArn, *SuccessFeedbackRoleArn, *SuccessFeedbackSampleRate by endpoint protocol",
          "Complete inventories: sns_topic, sns_subscription"
        ],
        "kind": "sns_topic",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS SNS sns topic attributes",
          "url": "https://docs.aws.amazon.com/sns/latest/dg/sns-topic-attributes.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure both feedback roles and an appropriate positive success-sampling rate for the affected protocols."
      ],
      "summary": "Configure both feedback roles and an appropriate positive success-sampling rate for the affected protocols."
    },
    "reviewed_binding": {
      "closure": {
        "check_id": "aws.pci.sns.delivery_status_logging"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw07._register.<locals>.evaluate:842::_EVALUATORS": {
          "aws.nist.codebuild_exact_aws_key_env_names": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._codebuild_exact_plaintext"
          },
          "aws.pci.codebuild.aws_key_environment_vars": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._codebuild_any_type"
          },
          "aws.pci.iam.role_required_managed_policies": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._role_required_policies"
          },
          "aws.pci.sns.delivery_status_logging": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._sns_feedback"
          },
          "aws_account_expected_organization_master": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._expected_org_master"
          },
          "aws_backup_failure_notification": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._backup_notification"
          },
          "aws_cis_batch_job_cloudwatch_logging": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._batch_job_logs"
          },
          "aws_cloudwatch_metric_alarm_has_threshold": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._threshold_policy"
          },
          "aws_ec2_ami_trusted_principals": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._ami_trusted"
          },
          "aws_ec2_running_instance_cpu_alarm_present": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._cpu_alarm"
          },
          "aws_ec2_status_alarm": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._status_alarm"
          },
          "aws_external_key_store_connected": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._external_store"
          },
          "aws_g6_redshift_automatic_version_upgrade": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._redshift_upgrade"
          },
          "aws_sns_delivery_failure_alarm_present": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._sns_alarm"
          },
          "aws_wafv2_baseline_managed_rules": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._waf_baseline"
          },
          "aws_wafv2_blanket_rate_rule": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._waf_blanket_rate"
          },
          "aws_wafv2_managed_rule_groups": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._waf_extra_managed"
          },
          "aws_wafv2_scoped_rate_rules": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._waf_scoped_rate"
          },
          "aws_wafv2_service_exclusion_rules": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw07._waf_exclusions"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw07._sns_feedback:700::_FEEDBACK_PREFIX": {
          "application": "Application",
          "firehose": "Firehose",
          "http": "HTTP",
          "https": "HTTP",
          "lambda": "Lambda",
          "sqs": "SQS"
        }
      },
      "defaults": null,
      "kind": "sns_topic",
      "module": "peaso.checks._bulk_pending_compliance_new_sw07",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw07._context:162": "8e712cd1ab1a1a2b666d0728570caccf05b43f7f02ddb31596ea05c1ac1c6976",
        "peaso.checks._bulk_pending_compliance_new_sw07._inventory:172": "e764102d7a59ae2f400784ba520b497188338d2ee12867ddddff89cd12d2c916",
        "peaso.checks._bulk_pending_compliance_new_sw07._register.<locals>.evaluate:842": "9498de41fed32ac7fff0f826bb0be1235279fd7f102d205f95b8a0f2db5c6dcf",
        "peaso.checks._bulk_pending_compliance_new_sw07._sns_feedback:700": "e9ce5287f9aebe9e3dbeeea33fbce82ec626a2a96ece5526663c65d2ea32f528",
        "peaso.checks._bulk_pending_compliance_new_sw07._subject:238": "469d27bb3acb69b5156258877aa58fd30b125f76df886602136f50608e5231fa"
      },
      "source_qualname": "_register.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A subscribed protocol lacks complete success/failure delivery-feedback settings."
  },
  "aws.pci.vpc.antispoofing_ingress": {
    "description_fields": {
      "description": "Models ordered internet ingress DROP/PASS rules against customer-defined internal source and PCI destination CIDRs."
    },
    "remediation_fields": {
      "caveats": [
        "This historical control needs customer-approved PCI scope and is excluded from native-only execution; partial overlaps remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only API calls network-firewall:DescribeFirewallPolicy and network-firewall:DescribeRuleGroup; stateless/stateful ingress rules and protected CIDR inventory",
          "Complete inventories: network_firewall_policy"
        ],
        "kind": "network_firewall_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS NETWORK-FIREWALL Stateless Rule API",
          "url": "https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_StatelessRule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Place appropriate anti-spoofing drops before conflicting permits after validating the intended traffic model."
      ],
      "summary": "Place appropriate anti-spoofing drops before conflicting permits after validating the intended traffic model."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw44._inventory:37::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "network_firewall_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw44",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw44._inventory:37": "1ca26c1109be269b1f41477cba4821a2735aa6472fa41dfd8147ecb10b1fcff7",
        "peaso.checks._bulk_pending_compliance_new_sw44._net:121": "ed351ad5262f54585d2e59bbd40305a5bde3167a7951a25ce212e834de52863d",
        "peaso.checks._bulk_pending_compliance_new_sw44._nonempty:94": "02de01ce8c9c420fbc6ae2a651497039dfa6e588da7e5315296141e3ed62ef75",
        "peaso.checks._bulk_pending_compliance_new_sw44.antispoofing:336": "cfdaeda0f545c475f85f7c20a2197f4ede031fa2a718a266d783df4e57735ac3"
      },
      "source_qualname": "antispoofing"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The modeled ordered ingress rules do not establish the required anti-spoofing drop."
  },
  "aws_api_customer_log_delivery": {
    "description_fields": {
      "description": "Checks REST stage method logging and access-log destination/format for request ID, request time and status."
    },
    "remediation_fields": {
      "caveats": [
        "The result concerns configuration, not log delivery or customer availability; unproven wildcard coverage remains UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "apigateway:GetStages; methodSettings.*.loggingLevel, accessLogSettings.destinationArn, accessLogSettings.format",
          "Complete inventories: apigateway_stage"
        ],
        "kind": "apigateway_stage",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS APIGATEWAY Stage API",
          "url": "https://docs.aws.amazon.com/apigateway/latest/api/API_Stage.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable required method logging and a suitable access-log destination with those fields."
      ],
      "summary": "Enable required method logging and a suitable access-log destination with those fields."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw49._arn:90::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12})?:(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw49._context:29::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/(global|[a-z]{2}(?:-[a-z]+)+-[0-9])$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw49.api_customer_log_delivery:194::_METHODS": [
          "ANY",
          "DELETE",
          "GET",
          "HEAD",
          "OPTIONS",
          "PATCH",
          "POST",
          "PUT"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw49.api_customer_log_delivery:194::_METHOD_PATH": {
          "flags": 32,
          "regex": "^~1[A-Za-z0-9~{}+._%-]*$"
        }
      },
      "defaults": null,
      "kind": "apigateway_stage",
      "module": "peaso.checks._bulk_pending_compliance_new_sw49",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw49._arn:90": "03ee16d7b213cbddd913d031852b20cd10f145dc1f68943c366596313e81bd4a",
        "peaso.checks._bulk_pending_compliance_new_sw49._context:29": "5899669342e76e9917020ef86d4fa2e41b0a7c953dd4907ad561177bb230d5ec",
        "peaso.checks._bulk_pending_compliance_new_sw49._inventory:40": "03bb5a00591d148a03ea9445b405fcc1fcf0fae1e74e8e24df180a7d508af6ce",
        "peaso.checks._bulk_pending_compliance_new_sw49._member:68": "f22c2d0f53827f9ef9b90cbd1de206d5633976e1cd75cbfdfcabdc6fdb621358",
        "peaso.checks._bulk_pending_compliance_new_sw49.api_customer_log_delivery:194": "fe30d9540045114e3ec7d174e8f4d7ead4a0b5670843b00d85d1975795b2d0d6"
      },
      "source_qualname": "api_customer_log_delivery"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The REST stage has disabled method logging or incomplete access-log settings."
  },
  "aws_autoscaling_userdata_plaintext_aws_key": {
    "description_fields": {
      "description": "Reads the native user-data inspection status and AWS key-pair indicator without exposing secret values."
    },
    "remediation_fields": {
      "caveats": [
        "The indicator is a pattern finding, not a credential-validity test; secret values are not shown."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "extend existing autoscaling:DescribeLaunchConfigurations collector to inspect UserData in memory and project boolean UserDataIndicators.HasAwsKeyPair; raw UserData remains redacted",
          "Complete inventories: autoscaling_launch_configuration"
        ],
        "kind": "autoscaling_launch_configuration",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS Auto Scaling Launch Configuration API",
          "url": "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_LaunchConfiguration.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Confirm the detected credential, rotate it if real and move authentication out of user data."
      ],
      "summary": "Confirm the detected credential, rotate it if real and move authentication out of user data."
    },
    "reviewed_binding": {
      "closure": {
        "identifier": "aws_autoscaling_userdata_plaintext_aws_key"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811::EVALUATORS": {
          "aws.nist.sc_36_coverage": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._recovery"
          },
          "aws.pci.classic_elb.custom_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.classic_elb.predefined_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.redshift.expected_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._redshift"
          },
          "aws.pci.secretsmanager.kms_encryption_any": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._kms"
          },
          "aws_autoscaling_userdata_plaintext_aws_key": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._userdata"
          },
          "aws_ecr_repository_lifecycle_retention": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecr"
          },
          "aws_g6_ecs_fargate_storage_encryption": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecs"
          },
          "aws_nist_cloudformation_stack_drift_detection_check": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._drift"
          },
          "aws_nist_config_enabled_all_regions": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._config"
          },
          "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rds"
          },
          "aws_nist_secretsmanager_secret_automatic_rotation_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rotation"
          },
          "aws_organizations_environment_account_separation": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._separation"
          },
          "aws_sagemaker_model_clarify_bias_job": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._clarify"
          },
          "aws_vpn_tunnel_encryption_configuration": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._vpn"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[a-z0-9-]*:[0-9]{12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_SCOPE": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z0-9-]+$"
        }
      },
      "defaults": null,
      "kind": "autoscaling_launch_configuration",
      "module": "peaso.checks._bulk_pending_compliance_new_sw48",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811": "ae35cf3acf73d2d9b595a8f64672eba95725a8530d896346dfb770b772644588",
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34": "28c7fa38621503a88a0564acb5b0abd82e7036874d3c1edd271d85c2aecb2d9e",
        "peaso.checks._bulk_pending_compliance_new_sw48._userdata:691": "7f17e4839c2352be0a68c3596c21ece5af57c7533f13557e07603faa9ebb898d"
      },
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "User-data inspection detected an AWS access-key-pair pattern."
  },
  "aws_backup_recent_restore_test": {
    "description_fields": {
      "description": "Joins restore-testing plans, selected resource types and completed test jobs; requires a success within 365 days for every selected plan/type pair."
    },
    "remediation_fields": {
      "caveats": [
        "A completed test job is not proof that every protected asset was restored or that application validation succeeded."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "backup:ListRestoreTestingPlans/ListRestoreTestingSelections/ListRestoreJobs; RestoreTestingPlanArn, ResourceType, Status, CompletionDate",
          "Complete inventories: backup_restore_testing_plan, backup_restore_testing_selection, backup_restore_job"
        ],
        "kind": "backup_restore_job",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS Backup restore testing",
          "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Investigate missing test results and schedule suitable restore validation for the affected plan/resource types."
      ],
      "summary": "Investigate missing test results and schedule suitable restore validation for the affected plan/resource types."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "backup_restore_job",
      "module": "peaso.checks._bulk_pending_compliance_new_sw42",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw42._arn_scope:100": "518b8c9bc4295ae8abe707706c5c781da024195632a3de19d9090c7fa77b8652",
        "peaso.checks._bulk_pending_compliance_new_sw42._rows:63": "849fde7ce1d4d00e72606efd399c2fd3f200edca6864a9c492ae5d57034d198b",
        "peaso.checks._bulk_pending_compliance_new_sw42._scope:53": "d54ebef4ffc206be4869114911f42814e9060cd7dd84b2f04843e84d6ccb80f8",
        "peaso.checks._bulk_pending_compliance_new_sw42._timestamp:125": "e0cb541c5d63dd170fd5aca7c8d6af24f81d5b4d82c84cfd0835056c241406c8",
        "peaso.checks._bulk_pending_compliance_new_sw42.backup_recent_restore_test:679": "b910b4b875305ffcc203d5132b9d4d5e30de95458d33106a2075e041f9de348b"
      },
      "source_qualname": "backup_recent_restore_test"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A selected restore-testing plan/resource type lacks a completed test job within 365 days."
  },
  "aws_cis_aws_resource_policy_unrestricted_principal": {
    "description_fields": {
      "description": "Finds wildcard-principal grants without supported account, organization or network boundaries; covering Denies are considered, and unresolved policy interactions remain UNKNOWN."
    },
    "remediation_fields": {
      "caveats": [
        "This statement model does not prove effective access across all identity, organization and resource controls."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "aws_resource_policy.ResourceArn, Policy.Statement[].Effect, Principal, NotPrincipal, Action, NotAction, Resource, NotResource, Condition; read-only recipe provenance",
          "Complete inventories: aws_resource_policy; incomplete collections retain confirmed unrestricted grants"
        ],
        "kind": "aws_resource_policy",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS IAM reference policies elements principal",
          "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict unnecessary wildcard grants to intended principals and scoped conditions."
      ],
      "summary": "Restrict unnecessary wildcard grants to intended principals and scoped conditions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "aws_resource_policy",
      "module": "peaso.checks.aws_resource_policy_scope",
      "predicate_sources": {
        "peaso.checks.aws_resource_policy_scope.boundary:21": "943b6378296017248a5280ff979532deb375da89709c111cf5fdef4f68d6b434",
        "peaso.checks.aws_resource_policy_scope.evaluate:242": "6245ad771e3d648a1490c7689a84253272ce7b147429beea63ae1668de7ce47f",
        "peaso.checks.aws_resource_policy_scope.principal_values:112": "d595ee47d9abacb7c622dd625cf5b42fb58ad9c5d94bbdbc0b9e5aa4fe86b4c7",
        "peaso.checks.aws_resource_policy_scope.public_principal:103": "28636f5d545145ef276774b629e59996ceb47bd0a7a0bd87b1a6683839a7ed61",
        "peaso.checks.aws_resource_policy_scope.review_document:122": "8a18550fe06208a0683cdd4c424d9e22d7f88ac7d5dcff43bb438676eed2fb9e",
        "peaso.checks.aws_resource_policy_scope.strings:14": "2c45d9d20c0a590ec34c3f99d287ee597b7ee4772ef376f56d1895d8a647fbef"
      },
      "source_qualname": "evaluate"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The resource policy declares an unrestricted wildcard-principal Allow under this model."
  },
  "aws_cis_lightsail_bucket_private": {
    "description_fields": {
      "description": "Checks Lightsail public bucket rules and permitted object ACL overrides, considering account public-access-block ambiguity."
    },
    "remediation_fields": {
      "caveats": [
        "This is declared-access evidence; unresolved account-block interactions remain UNKNOWN and no object contents are fetched."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "lightsail:GetBuckets buckets[].name,accessRules.getObject,accessRules.allowPublicOverrides; s3control:GetPublicAccessBlock PublicAccessBlockConfiguration; s3:ListObjectsV2 Contents[].Key and s3:GetObjectAcl Grants[].Grantee,Permission when public overrides are permitted",
          "Complete inventories: lightsail_bucket"
        ],
        "kind": "lightsail_bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS LIGHTSAIL Bucket API",
          "url": "https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_Bucket.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove unnecessary public bucket or object grants after preserving intended readers."
      ],
      "summary": "Remove unnecessary public bucket or object grants after preserving intended readers."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "lightsail_bucket",
      "module": "peaso.checks._bulk_pending_compliance_new_sw42",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw42._arn_scope:100": "518b8c9bc4295ae8abe707706c5c781da024195632a3de19d9090c7fa77b8652",
        "peaso.checks._bulk_pending_compliance_new_sw42._item:91": "9d982a09093381f5b3e0c96e00f59e44c72b7d7079b3a95ee80613872d455cbe",
        "peaso.checks._bulk_pending_compliance_new_sw42._rows:63": "849fde7ce1d4d00e72606efd399c2fd3f200edca6864a9c492ae5d57034d198b",
        "peaso.checks._bulk_pending_compliance_new_sw42._scope:53": "d54ebef4ffc206be4869114911f42814e9060cd7dd84b2f04843e84d6ccb80f8",
        "peaso.checks._bulk_pending_compliance_new_sw42.lightsail_bucket_private:293": "5598062e7ad6d17f35f81dc0217dc9f6a0ff045958e83764c0290fc4dba135e4"
      },
      "source_qualname": "lightsail_bucket_private"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "The Lightsail bucket or a supported object ACL declares public read access."
  },
  "aws_cis_organizations_policy_management_delegated": {
    "description_fields": {
      "description": "Looks for an active member account granted create, update and attach policy actions by an unconditional Organizations resource policy."
    },
    "remediation_fields": {
      "caveats": [
        "Delegation is optional; the grant witness does not prove recent use or effective privileges across all controls."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "organizations:DescribeResourcePolicy ResourcePolicy.Content JSON Statement.Principal, Action, Resource, Effect; organizations:DescribeOrganization Id and ManagementAccountId; organizations:ListAccounts Accounts[].Id,Status",
          "Complete inventories: organization, organization_resource_policy, organization_account"
        ],
        "kind": "organization",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS ORGANIZATIONS orgs manage policies delegated administrator",
          "url": "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_delegated-administrator.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Delegate policy management only where the organization\u2019s administration model requires it."
      ],
      "summary": "Delegate policy management only where the organization\u2019s administration model requires it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58::GLOBAL_KINDS": [
          "cloudfront_distribution",
          "iam_credential_report",
          "iam_user",
          "organization",
          "organization_account",
          "organization_delegated_admin",
          "organization_effective_scp",
          "organization_resource_policy",
          "organization_service_access",
          "shield_drt_access",
          "shield_protection",
          "shield_subscription"
        ]
      },
      "defaults": null,
      "kind": "organization",
      "module": "peaso.checks._bulk_pending_compliance_new_sw37",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw37._member:76": "fda5bf12e8ded3a344b7c874792e44850970b257a931b645269ff38a2629c81f",
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58": "8f7abdaf6cebf992749e3e83418d8091f5891d38bb9c1bd1bbe61277d5daf8c3",
        "peaso.checks._bulk_pending_compliance_new_sw37._scope:49": "9af44f1b2451ca6be4b5bf54996ddc2943adac973d2722464f7d18e54302b501",
        "peaso.checks._bulk_pending_compliance_new_sw37.org_policy_delegate:251": "e3b9f2200a747572e6b6e2102cdfe782b50839c95e12e290d8afcbb891a2242f"
      },
      "source_qualname": "org_policy_delegate"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No active member account matches this policy-management delegation profile."
  },
  "aws_cloudtrail_bucket_lifecycle_retention_365": {
    "description_fields": {
      "description": "Checks overlapping enabled CloudTrail log lifecycle rules for deletion before 365 days, then requires a qualifying default Object Lock retention for PASS."
    },
    "remediation_fields": {
      "caveats": [
        "Missing qualifying Object Lock is UNKNOWN; governance retention can be bypassed and existing-object retention is not established."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "cloudtrail:DescribeTrails, s3:GetBucketLifecycleConfiguration, s3:GetObjectLockConfiguration; S3BucketName, S3KeyPrefix, Rules, ObjectLockEnabled, DefaultRetention",
          "Complete inventories: cloudtrail_account_inventory, bucket"
        ],
        "kind": "cloudtrail",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS AWSCLOUDTRAIL Trail API",
          "url": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove premature log expiry and choose suitable retention protections for the required audit window."
      ],
      "summary": "Remove premature log expiry and choose suitable retention protections for the required audit window."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_BUCKET_LOG_IDS": [
          "aws.nist.all_cloudtrail_destination_bucket_access_logging",
          "aws_g6_all_cloudtrail_destination_bucket_access_logging",
          "aws_nist_cloudtrail_s3_logging_enabled"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_INTEGRATION_IDS": [
          "aws.nist.cloudtrail_cloudwatch_integration",
          "aws_g6_cloudtrail_all_trails_cloudwatch_integration",
          "aws_nist_cloudtrail_trail_integrated_with_logs"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_KMS_IDS": [
          "aws.nist.cloudtrail_cloudwatch_destination_kms",
          "aws_g6_cloudtrail_kms_destination_join",
          "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54::_TRAIL_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/[^/]+$"
        }
      },
      "defaults": [
        "aws_cloudtrail_bucket_lifecycle_retention_365"
      ],
      "kind": "cloudtrail",
      "module": "peaso.checks._bulk_pending_compliance_new_sw35",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket:106": "e493342d52113857ba0d0af8ddd5f32503d2944564dc0051a3554de726460ccc",
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket_logging:113": "68fc91ccd885bd01b93f958ea79dd31166c6af13c042d6770923cd2ca019aaa0",
        "peaso.checks._bulk_pending_compliance_new_sw35._buckets:95": "227115d6eb587786a120a21452bc2f26db85062029a81d9f4ad1158a7bab8d8b",
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206": "7fc7f38f518800a5a237de0a0c8b4937dcdf8c6ca2e10d180f0e5337f75b16ba",
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167": "96e40d1857f7bb7cb2660935c2e41b65c401e24c3cb3b516e384e178ce1aa3b9",
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18": "48b3eff2b783841a7478854de3ef23f3c9600d0b262b1794a8582bc34b330809",
        "peaso.checks._bulk_pending_compliance_new_sw35._evaluate:571": "db6c233dce944c8523f68ebf521fbf5bdfa8a548e3ea4b098f3373cc2bd71944",
        "peaso.checks._bulk_pending_compliance_new_sw35._fresh:199": "9cdf65b158b6f51314e700fefa8857746f70b9f0287e7aabed574b1fb078cddb",
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155": "b5ce980ad26baadef5b7298e7ec5d315b91962928303c5b94d059ccf6e59f538",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141": "d9daab07009418426d93241d4368f389c07d6cdcce215e3919bd12e5fcf8718e",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129": "641b90e97047905dd88770f7df2172cea89b1c98fa63561da9e2eb5700ff59f7",
        "peaso.checks._bulk_pending_compliance_new_sw35._logging_trails:86": "bd9ce49432fd6c17fd2dd9fc90940c119a3b72129ee39f3823cd16dcfc70ffd0",
        "peaso.checks._bulk_pending_compliance_new_sw35._policy:454": "e452be311f5a85f4efe2ece666384392fdbedd6ad6fde9a6fcc855f5c34fa881",
        "peaso.checks._bulk_pending_compliance_new_sw35._registered:586": "0b9679c5acb0a2c3d4d45db82a7142195783c971b43ac1b6a32e30874dd41d7e",
        "peaso.checks._bulk_pending_compliance_new_sw35._rows:27": "21633a64b94ae91fc79c7b380b07edc77a245adcb678b19112a3bd43ac0085b3",
        "peaso.checks._bulk_pending_compliance_new_sw35._ssm:482": "e5813f4c7b7a39967a90b4b2cf87b5aacaef0883016be87d60241c2c2d7637b1",
        "peaso.checks._bulk_pending_compliance_new_sw35._time:187": "5784d81b10523f17207ad7111a67f6f185f2737a625cb9ed54cd01eadac1cdcb",
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54": "f1daede05c5e264575b3ddd0844fb83c3a1df06eebd07ec719f1223e889bfb25",
        "peaso.checks._bulk_pending_compliance_new_sw35._versions_at_least:471": "6ffde1815a868afa5d9dfa65e34edb92a5ddc9bfcc6d28d1794b4530b9b959f8"
      },
      "source_qualname": "_registered"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An enabled lifecycle rule can delete CloudTrail audit objects or versions before 365 days."
  },
  "aws_cloudtrail_s3_siem_delivery": {
    "description_fields": {
      "description": "Checks organization trails for recent error-free S3 delivery and a fresh object under the trail\u2019s AWSLogs prefix."
    },
    "remediation_fields": {
      "caveats": [
        "This verifies bounded S3 delivery evidence, not downstream SIEM receipt or every expected event."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "cloudtrail:GetTrailStatus LatestDeliveryTime, LatestDeliveryError; cloudtrail:DescribeTrails S3BucketName; s3:ListObjectsV2 Contents[].LastModified under AWSLogs prefix; approved AWS SIEM-forwarder ARN inventory",
          "Complete inventories: cloudtrail_account_inventory, bucket"
        ],
        "kind": "cloudtrail",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS AWSCLOUDTRAIL Trail API",
          "url": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Resolve the identified S3 delivery error or stale log-object evidence."
      ],
      "summary": "Resolve the identified S3 delivery error or stale log-object evidence."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_BUCKET_LOG_IDS": [
          "aws.nist.all_cloudtrail_destination_bucket_access_logging",
          "aws_g6_all_cloudtrail_destination_bucket_access_logging",
          "aws_nist_cloudtrail_s3_logging_enabled"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_INTEGRATION_IDS": [
          "aws.nist.cloudtrail_cloudwatch_integration",
          "aws_g6_cloudtrail_all_trails_cloudwatch_integration",
          "aws_nist_cloudtrail_trail_integrated_with_logs"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_KMS_IDS": [
          "aws.nist.cloudtrail_cloudwatch_destination_kms",
          "aws_g6_cloudtrail_kms_destination_join",
          "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54::_TRAIL_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/[^/]+$"
        }
      },
      "defaults": [
        "aws_cloudtrail_s3_siem_delivery"
      ],
      "kind": "cloudtrail",
      "module": "peaso.checks._bulk_pending_compliance_new_sw35",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket:106": "e493342d52113857ba0d0af8ddd5f32503d2944564dc0051a3554de726460ccc",
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket_logging:113": "68fc91ccd885bd01b93f958ea79dd31166c6af13c042d6770923cd2ca019aaa0",
        "peaso.checks._bulk_pending_compliance_new_sw35._buckets:95": "227115d6eb587786a120a21452bc2f26db85062029a81d9f4ad1158a7bab8d8b",
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206": "7fc7f38f518800a5a237de0a0c8b4937dcdf8c6ca2e10d180f0e5337f75b16ba",
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167": "96e40d1857f7bb7cb2660935c2e41b65c401e24c3cb3b516e384e178ce1aa3b9",
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18": "48b3eff2b783841a7478854de3ef23f3c9600d0b262b1794a8582bc34b330809",
        "peaso.checks._bulk_pending_compliance_new_sw35._evaluate:571": "db6c233dce944c8523f68ebf521fbf5bdfa8a548e3ea4b098f3373cc2bd71944",
        "peaso.checks._bulk_pending_compliance_new_sw35._fresh:199": "9cdf65b158b6f51314e700fefa8857746f70b9f0287e7aabed574b1fb078cddb",
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155": "b5ce980ad26baadef5b7298e7ec5d315b91962928303c5b94d059ccf6e59f538",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141": "d9daab07009418426d93241d4368f389c07d6cdcce215e3919bd12e5fcf8718e",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129": "641b90e97047905dd88770f7df2172cea89b1c98fa63561da9e2eb5700ff59f7",
        "peaso.checks._bulk_pending_compliance_new_sw35._logging_trails:86": "bd9ce49432fd6c17fd2dd9fc90940c119a3b72129ee39f3823cd16dcfc70ffd0",
        "peaso.checks._bulk_pending_compliance_new_sw35._policy:454": "e452be311f5a85f4efe2ece666384392fdbedd6ad6fde9a6fcc855f5c34fa881",
        "peaso.checks._bulk_pending_compliance_new_sw35._registered:586": "0b9679c5acb0a2c3d4d45db82a7142195783c971b43ac1b6a32e30874dd41d7e",
        "peaso.checks._bulk_pending_compliance_new_sw35._rows:27": "21633a64b94ae91fc79c7b380b07edc77a245adcb678b19112a3bd43ac0085b3",
        "peaso.checks._bulk_pending_compliance_new_sw35._ssm:482": "e5813f4c7b7a39967a90b4b2cf87b5aacaef0883016be87d60241c2c2d7637b1",
        "peaso.checks._bulk_pending_compliance_new_sw35._time:187": "5784d81b10523f17207ad7111a67f6f185f2737a625cb9ed54cd01eadac1cdcb",
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54": "f1daede05c5e264575b3ddd0844fb83c3a1df06eebd07ec719f1223e889bfb25",
        "peaso.checks._bulk_pending_compliance_new_sw35._versions_at_least:471": "6ffde1815a868afa5d9dfa65e34edb92a5ddc9bfcc6d28d1794b4530b9b959f8"
      },
      "source_qualname": "_registered"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An organization trail has failed or stale S3 log delivery evidence."
  },
  "aws_elbv2_stickiness_duration_30_minutes": {
    "description_fields": {
      "description": "Checks ALB cookie stickiness in target groups and forward rules for durations above 1,800 seconds."
    },
    "remediation_fields": {
      "caveats": [
        "Stickiness duration is a routing preference, not the lifetime or security of application login sessions."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "elasticloadbalancingv2:DescribeRules Rules[].Actions[].ForwardConfig.TargetGroupStickinessConfig.Enabled, DurationSeconds; elasticloadbalancingv2:DescribeTargetGroupAttributes Attributes[].Key, Value for stickiness.enabled and stickiness.lb_cookie.duration_seconds",
          "Complete inventories: load_balancer, target_group"
        ],
        "kind": "load_balancer",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS Elastic Load Balancing Describe Target Health API",
          "url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetHealth.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Shorten stickiness if the application\u2019s session-routing requirements permit it."
      ],
      "summary": "Shorten stickiness if the application\u2019s session-routing requirements permit it."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "load_balancer",
      "module": "peaso.checks._bulk_pending_compliance_new_sw42",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw42._arn_scope:100": "518b8c9bc4295ae8abe707706c5c781da024195632a3de19d9090c7fa77b8652",
        "peaso.checks._bulk_pending_compliance_new_sw42._child:137": "fd87692bf3e63e7b21bcb376ad9805b37b79bf472080676a016e7c46dc897242",
        "peaso.checks._bulk_pending_compliance_new_sw42._item:91": "9d982a09093381f5b3e0c96e00f59e44c72b7d7079b3a95ee80613872d455cbe",
        "peaso.checks._bulk_pending_compliance_new_sw42._lb:382": "1eb411cff35f465083c9a478352fb48cd1bd614ea74749152415fbed8c146b54",
        "peaso.checks._bulk_pending_compliance_new_sw42._rows:63": "849fde7ce1d4d00e72606efd399c2fd3f200edca6864a9c492ae5d57034d198b",
        "peaso.checks._bulk_pending_compliance_new_sw42._scope:53": "d54ebef4ffc206be4869114911f42814e9060cd7dd84b2f04843e84d6ccb80f8",
        "peaso.checks._bulk_pending_compliance_new_sw42._strings:119": "e782dad9f877bd54cfec4a92763e21690814cd62b17c2d706965c4e1d4638932",
        "peaso.checks._bulk_pending_compliance_new_sw42._target_groups:433": "1cbdd96f6ffa3be075cefadfc01f3367223f9a6e7f0409e8c7260a13b81a968b",
        "peaso.checks._bulk_pending_compliance_new_sw42.elbv2_stickiness:453": "288e4e61abb0f5cb7ebfafaa201f752b04cf962ed68558bc7d61fe8704c38353"
      },
      "source_qualname": "elbv2_stickiness"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An ALB cookie-stickiness duration exceeds 30 minutes."
  },
  "aws_fedramp_cloudtrail_cloudwatch_integration": {
    "description_fields": {
      "description": "Checks active trails for a log group, delivery role and bounded allowed IAM simulation decisions for stream creation and event writing."
    },
    "remediation_fields": {
      "caveats": [
        "IAM simulation does not prove live delivery or organization-policy effects."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "existing collected cloudtrail_trail.CloudWatchLogsLogGroupArn, CloudWatchLogsRoleArn, IsLogging; IAM role trust and policy reads",
          "Complete inventories: cloudtrail_trail, cloudtrail_delivery_permission"
        ],
        "kind": "cloudtrail_trail",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS AWSCLOUDTRAIL Trail API",
          "url": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the missing destination or delivery-role permissions needed by the trail."
      ],
      "summary": "Configure the missing destination or delivery-role permissions needed by the trail."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw47._arn:153::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw47._context:143::_SCOPE": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw47._rows:162::_IDS": {
          "backup_recovery_point": "RecoveryPointArn",
          "backup_vault": "BackupVaultArn",
          "cloudtrail_delivery_permission": "role_arn",
          "cloudtrail_trail": "TrailARN",
          "cloudwatch_log_group": "arn",
          "codebuild_project": "name",
          "cost_anomaly_monitor": "MonitorArn",
          "cost_anomaly_subscription": "SubscriptionArn",
          "eks_cluster": "name",
          "eks_version_catalog": "region",
          "elastic_beanstalk_environment": "EnvironmentArn",
          "iam_role": "Arn",
          "k8s_admission_policy": "cluster_arn",
          "kms_key": "KeyArn"
        },
        "peaso.checks._bulk_pending_compliance_new_sw47._subject:195::_IDS": {
          "backup_recovery_point": "RecoveryPointArn",
          "backup_vault": "BackupVaultArn",
          "cloudtrail_delivery_permission": "role_arn",
          "cloudtrail_trail": "TrailARN",
          "cloudwatch_log_group": "arn",
          "codebuild_project": "name",
          "cost_anomaly_monitor": "MonitorArn",
          "cost_anomaly_subscription": "SubscriptionArn",
          "eks_cluster": "name",
          "eks_version_catalog": "region",
          "elastic_beanstalk_environment": "EnvironmentArn",
          "iam_role": "Arn",
          "k8s_admission_policy": "cluster_arn",
          "kms_key": "KeyArn"
        }
      },
      "defaults": [
        {
          "callable": "peaso.checks._bulk_pending_compliance_new_sw47._cloudwatch_integration"
        }
      ],
      "kind": "cloudtrail_trail",
      "module": "peaso.checks._bulk_pending_compliance_new_sw47",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw47._arn:153": "bdb87f5416ecd5919e4ada7124bd335ada2977617a05a135f1dcc473a3927eb3",
        "peaso.checks._bulk_pending_compliance_new_sw47._cloudwatch_integration:379": "91cc38e4f2c1ccd59e072ada8c89c393a18062b08eda55a446053a55d773abca",
        "peaso.checks._bulk_pending_compliance_new_sw47._context:143": "921e78f0da06442a08d6bb00bea89450b296576f4a0f1433dabd18b0c0252c77",
        "peaso.checks._bulk_pending_compliance_new_sw47._delivery_permission:360": "4bd57f6d7d215093898fa4d177b2b55a6df3da93e674a2b7c8e6dc7252c7883c",
        "peaso.checks._bulk_pending_compliance_new_sw47._evaluate:832": "99bdd26e9c1fc8833e997fdbc16598cf633a793518a7f6fc7509becf02358868",
        "peaso.checks._bulk_pending_compliance_new_sw47._rows:162": "c9d3f7c33713c0eabea34df7098e0f2d11ee9174ed8ec911a081ef62af7eec26",
        "peaso.checks._bulk_pending_compliance_new_sw47._subject:195": "267076456b4804b7b80f24325a64c65536bfa2729c172e8ced675fd19b753956",
        "peaso.checks._bulk_pending_compliance_new_sw47._trail_status:304": "db0819d9cf3e30ec96e23ca7bbcf44bd04cc9cba3cbaa8a2cee6a71e66fbcabe"
      },
      "source_qualname": "_evaluate"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The active trail lacks a destination, role or required simulated delivery permission."
  },
  "aws_fedramp_ec2_effective_public_exposure": {
    "description_fields": {
      "description": "Joins the instance to a complete configured-ingress projection or independently reconstructs a supported direct IPv4 public-path witness."
    },
    "remediation_fields": {
      "caveats": [
        "This is a configuration model, not a packet test; a supported public witness does not evaluate all remaining paths."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "EC2 DescribeInstances NetworkInterfaces.Association.PublicIp, Ipv6Addresses, subnet routes, security-group ingress; ELB target groups and public listener reads",
          "Complete inventories: ec2_instance, ec2_effective_ingress"
        ],
        "kind": "ec2_instance",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS EC2 Describe Instances API",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restrict only unnecessary ingress sources, ports or listeners on the identified path."
      ],
      "summary": "Restrict only unnecessary ingress sources, ports or listeners on the identified path."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58::GLOBAL_KINDS": [
          "cloudfront_distribution",
          "iam_credential_report",
          "iam_user",
          "organization",
          "organization_account",
          "organization_delegated_admin",
          "organization_effective_scp",
          "organization_resource_policy",
          "organization_service_access",
          "shield_drt_access",
          "shield_protection",
          "shield_subscription"
        ]
      },
      "defaults": null,
      "kind": "ec2_instance",
      "module": "peaso.checks._bulk_pending_compliance_new_sw37",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw37._account:110": "0557de7589935ca7b17b5b8dc886a28467bd2215fbea66e5f56b4a1d2b9cc0a3",
        "peaso.checks._bulk_pending_compliance_new_sw37._account_arn:118": "cbe535c81de20cad9dfe261f71512b3fbf0dd31e80f22074851df19136624e09",
        "peaso.checks._bulk_pending_compliance_new_sw37._arn:112": "02e5f0b4567d6d6d86e112d77838553a42c689d583f06de9bc12577c5c8dd7ef",
        "peaso.checks._bulk_pending_compliance_new_sw37._member:76": "fda5bf12e8ded3a344b7c874792e44850970b257a931b645269ff38a2629c81f",
        "peaso.checks._bulk_pending_compliance_new_sw37._reachability:437": "357dd32f925f816f886add4925521a711d6c3d733537c144a3a8a09d962801cc",
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58": "8f7abdaf6cebf992749e3e83418d8091f5891d38bb9c1bd1bbe61277d5daf8c3",
        "peaso.checks._bulk_pending_compliance_new_sw37._scope:49": "9af44f1b2451ca6be4b5bf54996ddc2943adac973d2722464f7d18e54302b501",
        "peaso.checks._bulk_pending_compliance_new_sw37.fedramp_reach:479": "04919e19b4fd4deb85140758da46d1784cb4d76d008645e1c20c9f3635212bdb"
      },
      "source_qualname": "fedramp_reach"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The instance has a modeled public configuration path."
  },
  "aws_fedramp_iam_all_policies_no_admin_star": {
    "description_fields": {
      "description": "Scans all customer-managed default policy documents for literal full-administrator Allow actions on Resource:*, including unattached policies."
    },
    "remediation_fields": {
      "caveats": [
        "Conditions and effective denies are not resolved by this literal grant profile; negative-action cases can remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam:ListPolicies Scope=Local OnlyAttached=False; iam:GetPolicyVersion default version document"
        ],
        "kind": "iam_policy",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS IAM Get Account Authorization Details API",
          "url": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace unnecessary wildcard grants with the actions and resources required for the workload."
      ],
      "summary": "Replace unnecessary wildcard grants with the actions and resources required for the workload."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "iam_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw40",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw40.<lambda>:824": "1e0fff8980591420b520ace5d6ec5e67cd99958da01905482ff2532034038b49"
      },
      "source_qualname": "<lambda>"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A customer-managed default policy contains a full-administrator Allow on all resources."
  },
  "aws_fedramp_iam_all_policies_no_service_wildcard": {
    "description_fields": {
      "description": "Scans all customer-managed default policy documents for literal service-wide wildcard Allow actions on Resource:*, including unattached policies."
    },
    "remediation_fields": {
      "caveats": [
        "Conditions and effective denies are not resolved by this literal grant profile; negative-action cases can remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "iam:ListPolicies Scope=Local OnlyAttached=False; iam:GetPolicyVersion default version document"
        ],
        "kind": "iam_policy",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS IAM Get Account Authorization Details API",
          "url": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace unnecessary wildcard grants with the actions and resources required for the workload."
      ],
      "summary": "Replace unnecessary wildcard grants with the actions and resources required for the workload."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "iam_policy",
      "module": "peaso.checks._bulk_pending_compliance_new_sw40",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw40.<lambda>:825": "1ab5db62a8ce43345a2cec37a4fcac97a263f44d2d04cea68da505182ce974f3"
      },
      "source_qualname": "<lambda>"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A customer-managed default policy contains a service-wide wildcard Allow on all resources."
  },
  "aws_g6_api_stage_effective_waf_acl": {
    "description_fields": {
      "description": "Compares the stage\u2019s declared ACL with its unique native association and complete WAFv2 ACL inventory."
    },
    "remediation_fields": {
      "caveats": [
        "Consistent references do not establish rule effectiveness or actual request blocking."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "apigateway:GetStages stageArn,webAclArn; wafv2:GetWebACL and wafv2:GetWebACLForResource on the stage ARN",
          "Complete inventories: rest_api_stage, stage_waf_association, wafv2_web_acl"
        ],
        "kind": "rest_api_stage",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS APIGATEWAY Method Setting API",
          "url": "https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Associate the intended ACL consistently if the stage requires WAF protection."
      ],
      "summary": "Associate the intended ACL consistently if the stage requires WAF protection."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58::GLOBAL_KINDS": [
          "cloudfront_distribution",
          "iam_credential_report",
          "iam_user",
          "organization",
          "organization_account",
          "organization_delegated_admin",
          "organization_effective_scp",
          "organization_resource_policy",
          "organization_service_access",
          "shield_drt_access",
          "shield_protection",
          "shield_subscription"
        ]
      },
      "defaults": null,
      "kind": "rest_api_stage",
      "module": "peaso.checks._bulk_pending_compliance_new_sw37",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw37._arn:112": "02e5f0b4567d6d6d86e112d77838553a42c689d583f06de9bc12577c5c8dd7ef",
        "peaso.checks._bulk_pending_compliance_new_sw37._member:76": "fda5bf12e8ded3a344b7c874792e44850970b257a931b645269ff38a2629c81f",
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58": "8f7abdaf6cebf992749e3e83418d8091f5891d38bb9c1bd1bbe61277d5daf8c3",
        "peaso.checks._bulk_pending_compliance_new_sw37._scope:49": "9af44f1b2451ca6be4b5bf54996ddc2943adac973d2722464f7d18e54302b501",
        "peaso.checks._bulk_pending_compliance_new_sw37._stage:123": "11093e44e590ec6456483e0cf568266ea4c629ec474de86c2ea26e196a6a1ab8",
        "peaso.checks._bulk_pending_compliance_new_sw37.stage_waf:178": "baf66029830b945c4e1ac870a34c4a40e826c5da70253e5bd28ea68c507bc562"
      },
      "source_qualname": "stage_waf"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The stage ACL declaration is absent, inconsistent or missing from the scoped WAF inventory."
  },
  "aws_g6_cloudtrail_region_logging_trail_present": {
    "description_fields": {
      "description": "Checks enabled regions for an active home-region or multi-region trail in complete account-wide trail inventory."
    },
    "remediation_fields": {
      "caveats": [
        "An active trail does not prove complete event selectors or successful delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ec2:DescribeRegions enabled Regions; cloudtrail:DescribeTrails and GetTrailStatus Name,HomeRegion,IsMultiRegionTrail,IsLogging across those Regions",
          "Complete inventories: aws_region, cloudtrail_account_inventory"
        ],
        "kind": "aws_region",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS AWSCLOUDTRAIL cloudtrail multi region trails",
          "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-multi-region-trails.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable an appropriate trail that covers the affected region."
      ],
      "summary": "Enable an appropriate trail that covers the affected region."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw44._inventory:37::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "aws_region",
      "module": "peaso.checks._bulk_pending_compliance_new_sw44",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw44._inventory:37": "1ca26c1109be269b1f41477cba4821a2735aa6472fa41dfd8147ecb10b1fcff7",
        "peaso.checks._bulk_pending_compliance_new_sw44._rows:73": "c41f364ce4766b9fc2bd95d90624992a5af0c4e166548b9c8c3d145497581789",
        "peaso.checks._bulk_pending_compliance_new_sw44.cloudtrail_region:137": "5fae8df52a43971bfb88633f765afead65f9f5ac5d0829d247d5a964eb39d9ba"
      },
      "source_qualname": "cloudtrail_region"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The enabled region has no covering trail with logging enabled."
  },
  "aws_guardduty_high_finding_alert": {
    "description_fields": {
      "description": "Looks for an enabled EventBridge rule covering GuardDuty high findings with a configured notification target."
    },
    "remediation_fields": {
      "caveats": [
        "Rule and target configuration do not prove successful delivery, response or detection coverage."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only events:ListRules, events:ListTargetsByRule",
          "Complete inventories: eventbridge_rule"
        ],
        "kind": "eventbridge_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EVENTBRIDGE Rule API",
          "url": "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable GuardDuty high-finding routing and an intended notification target."
      ],
      "summary": "Configure suitable GuardDuty high-finding routing and an intended notification target."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw36._rule_rows:258::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw36._rule_rows:258::_VALID_RULE_STATES": [
          "DISABLED",
          "ENABLED",
          "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw36._scope:27::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw36.guardduty_high_finding_alert:682::_ENABLED_RULE_STATES": [
          "ENABLED",
          "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
        ]
      },
      "defaults": null,
      "kind": "eventbridge_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw36",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw36._event_pattern:226": "403cb2adb050db14f47aab3d644cf3e9d43db6ec1125eb3d3bf8fbb81f6cab29",
        "peaso.checks._bulk_pending_compliance_new_sw36._event_scope:288": "28284a5a685a5b74bab259c68319c44ae5c5df941b19f5e1010adf621076b0cc",
        "peaso.checks._bulk_pending_compliance_new_sw36._exact_field:243": "97b33a13bfae522ab8010a8ff8ca4aea9dc9f8c4124b4a1299512982b297a8ed",
        "peaso.checks._bulk_pending_compliance_new_sw36._guardduty_high:661": "d0f72b28ec75794f8373fae4466c4013c1ed354e64fe35df2edb8b865f8d54d1",
        "peaso.checks._bulk_pending_compliance_new_sw36._list_fact:148": "abeaeabd79fcb2db168feb70f4d56d2bcf12f77be1a265fdee64611fe83eaeaa",
        "peaso.checks._bulk_pending_compliance_new_sw36._rows:48": "dc9eea3dc8777b8e42d22987da4b17f4915dce71a7144751ac029ff54dbf7587",
        "peaso.checks._bulk_pending_compliance_new_sw36._rule_rows:258": "fd033cc32363b97de904b48ad0e29b208aa92233593e0a1ce79fe7bfdcb9a821",
        "peaso.checks._bulk_pending_compliance_new_sw36._scope:27": "cc989afc0fe719579ed92b1f6e574ca50e30202adadcb93137bbc89d72d7bc96",
        "peaso.checks._bulk_pending_compliance_new_sw36._targets:284": "912b0b86b21404ff19bd803abfe4ba46753468cda44b5c02b79d866a03058b64",
        "peaso.checks._bulk_pending_compliance_new_sw36.guardduty_high_finding_alert:682": "a20deb06e51596025c849c03afcdb39964b45cb43c671948e10583c1e5b5cedf"
      },
      "source_qualname": "guardduty_high_finding_alert"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No supported enabled rule routes GuardDuty high findings to a notification target."
  },
  "aws_identity_center_sso_configured": {
    "description_fields": {
      "description": "Checks Identity Center instances for an enabled user account assignment bound to the audited account."
    },
    "remediation_fields": {
      "caveats": [
        "One enabled assignment does not establish all-user coverage, MFA or successful sign-in."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "sso-admin:ListInstances Instances[].InstanceArn, IdentityStoreId; sso-admin:ListAccountAssignments AccountAssignments[].PrincipalId, AccountId; identitystore:DescribeUser UserId, UserStatus",
          "Complete inventories: identity_center"
        ],
        "kind": "identity_center",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS SINGLESIGNON Account Assignment API",
          "url": "https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_AccountAssignment.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure appropriate Identity Center account assignments if centralized SSO is required."
      ],
      "summary": "Configure appropriate Identity Center account assignments if centralized SSO is required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw44._inventory:37::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "identity_center",
      "module": "peaso.checks._bulk_pending_compliance_new_sw44",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw44._inventory:37": "1ca26c1109be269b1f41477cba4821a2735aa6472fa41dfd8147ecb10b1fcff7",
        "peaso.checks._bulk_pending_compliance_new_sw44._nonempty:94": "02de01ce8c9c420fbc6ae2a651497039dfa6e588da7e5315296141e3ed62ef75",
        "peaso.checks._bulk_pending_compliance_new_sw44.identity_center:196": "ccece33a8206c3634ed49d291e9c6460a9e9ef19dc53145d7eda0a09e73b2e1f"
      },
      "source_qualname": "identity_center"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The account has no enabled user assignment in the observed Identity Center inventory."
  },
  "aws_inspector_critical_image_findings_alert": {
    "description_fields": {
      "description": "Checks enabled targeted EventBridge rules cover critical Inspector findings for both EC2 instances and ECR images."
    },
    "remediation_fields": {
      "caveats": [
        "Despite the image-only legacy label, both types are required; targets do not prove alert delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only API calls events:ListRules and events:ListTargetsByRule; Inspector2 finding severity, resourceType, Targets",
          "Complete inventories: event_rule"
        ],
        "kind": "event_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EVENTBRIDGE Rule API",
          "url": "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure supported critical-finding routing for both EC2 and ECR resource types."
      ],
      "summary": "Configure supported critical-finding routing for both EC2 and ECR resource types."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "event_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw45",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199": "cd29dfee9c28637ab5a70c78802687ad8992a25ac34ed35c139869be8ca0914e",
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150": "dcbb098304c8c01130962b40e93a2cf654e0b524aacf3aea387fc3852867c066",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_relevance:553": "094861aa6da3736545011e7d43db0c6a8d834af513bc11e1f9c44cfb0bfee4af",
        "peaso.checks._bulk_pending_compliance_new_sw45._events:516": "5b07813ba3441ef7b944d0d3eee0012dddf309db9e0870384632e6b4ef430caf",
        "peaso.checks._bulk_pending_compliance_new_sw45._inventory:161": "96f64e73f8106c570a5764453d39e03968457d4a89f7184f75008c472c0c6228",
        "peaso.checks._bulk_pending_compliance_new_sw45._literal_selector_relevance:542": "85598dbf0be0d556e5e0d1ac2a48a6a9f96ed5cbc8d6310f7ca991a19cce7355",
        "peaso.checks._bulk_pending_compliance_new_sw45._native_scheduled_only:564": "c46daeda404bd2e8bd6348b6ce486671264e14ad40c9a1ea0eac5bc06f0f759b",
        "peaso.checks._bulk_pending_compliance_new_sw45._objects:210": "9d1a3637de24029d955da7eb29fa168e69a3f9d24bbbe86547038ae21ad97e81",
        "peaso.checks._bulk_pending_compliance_new_sw45._pattern:530": "0de478ed4ab94a51df52906d84736e6fef33e6265e043ce7c2409657975aef88",
        "peaso.checks._bulk_pending_compliance_new_sw45._strings:218": "8bed843582a7903e48dee7e7a44b633cc19ce599016fe2a8a8f4941aff78a744",
        "peaso.checks._bulk_pending_compliance_new_sw45._targets:611": "c1e10accbca5baef2e45806acf644f23cd77b32423ded27f861967a1926c9a40",
        "peaso.checks._bulk_pending_compliance_new_sw45.inspector_critical_image_findings_alert:674": "9f4d5315fe7fad341393d58d219b0cf21325e9ed6537ab0a3a5656c13caa5b4f"
      },
      "source_qualname": "inspector_critical_image_findings_alert"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Critical Inspector finding routing lacks EC2 or ECR resource-type coverage."
  },
  "aws_kms_compromised_key_restricted": {
    "description_fields": {
      "description": "For keys tagged Compromised=true, accepts Disabled or flags an enabled key with an unconditional encryption/data-key Allow; Deny interactions remain UNKNOWN."
    },
    "remediation_fields": {
      "caveats": [
        "The tag does not prove compromise, and the policy model does not compute every effective permission."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "existing collected kms_key tags plus new read-only kms:GetKeyPolicy; tagged Compromised=true, KeyState and policy kms:Encrypt/kms:GenerateDataKey grants",
          "Complete inventories: kms_key"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS KMS Key Metadata API",
          "url": "https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Investigate the compromise marker and restrict new encryption use while preserving required recovery access."
      ],
      "summary": "Investigate the compromise marker and restrict new encryption use while preserving required recovery access."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw40._context:35::_ACCOUNT": {
          "flags": 32,
          "regex": "^[0-9]{12}$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw40._kms:495::_KEY_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/.+$"
        }
      },
      "defaults": null,
      "kind": "kms_key",
      "module": "peaso.checks._bulk_pending_compliance_new_sw40",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw40._context:35": "24a3c8c283d7e2dfbeafd355205c183825acd121eaf5fdf0fa2bae69b6fbcd4d",
        "peaso.checks._bulk_pending_compliance_new_sw40._document:67": "443dbbf716af6733c37d3ae2e8571caf84ee580049ad297693a60a9d53d2b938",
        "peaso.checks._bulk_pending_compliance_new_sw40._kms:495": "d93bbe33e0afed9abfc9cd3ea7fba06965f9c087292fcd1e947fd6bcfd4bfa9e",
        "peaso.checks._bulk_pending_compliance_new_sw40._kms_compromised:610": "f6dd6c7fe66330faf69653019c8acf6602c582fb6f1e17ed5186fd756f035149",
        "peaso.checks._bulk_pending_compliance_new_sw40._kms_policy:510": "7eb73c3b31d3d5fabbd48237cb18af5b6b2500bbfe49cd51ef9e1cba67d5a10a",
        "peaso.checks._bulk_pending_compliance_new_sw40._rows:46": "71e3728469f5a6dc199c8eafcdbedfd62ba427a00c7d102d47bb64e881bc2811",
        "peaso.checks._bulk_pending_compliance_new_sw40._statement:90": "ae6867f60cc6c897e61ebde06158e2f45a589b700b1bba5d2f87249728a8372d",
        "peaso.checks._bulk_pending_compliance_new_sw40._terms:82": "a0e5e7ede6cbc70e0315a593bc570fcacd7fe888b49e6c0f5b4f4d976bbeba62"
      },
      "source_qualname": "_kms_compromised"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "critical",
    "static_observed_sentence": "A key marked compromised remains enabled with a modeled unconditional encryption or data-key grant."
  },
  "aws_kms_key_expiry": {
    "description_fields": {
      "description": "Compares imported key-material expiry with the snapshot and checks Retired=true keys are Disabled."
    },
    "remediation_fields": {
      "caveats": [
        "AWS-generated key material has no expiry in this predicate; the retirement tag is a native marker, not proof of business intent."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "existing collected kms_key plus new read-only kms:DescribeKey; KeyState, Enabled, CreationDate and import ValidTo",
          "Complete inventories: kms_key"
        ],
        "kind": "kms_key",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS KMS Key Metadata API",
          "url": "https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Replace expired imported material or disable a genuinely retired key after checking dependent data."
      ],
      "summary": "Replace expired imported material or disable a genuinely retired key after checking dependent data."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "kms_key",
      "module": "peaso.checks._bulk_pending_compliance_new_sw06",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw06._inventory:16": "5bd61e1e4f0be89d2d273e4b5786d149d7d9989d1e5c632f77ba27cd68ca4ab5",
        "peaso.checks._bulk_pending_compliance_new_sw06._kms_expiry:286": "af15f00a1b3def08d9f9944e6a4dbaee20ccba6d917020baeef0a915a60d9826",
        "peaso.checks._bulk_pending_compliance_new_sw06.check_aws_kms_key_expiry:565": "43d3179f916ec01b2125055c77f6463577ac7cf53ea220a171ca34a554d5c617"
      },
      "source_qualname": "check_aws_kms_key_expiry"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "Imported key material has expired or a key marked retired is not disabled."
  },
  "aws_log_archive_immutable": {
    "description_fields": {
      "description": "Joins account-global CloudTrail destination buckets and checks versioning plus a valid positive Object Lock default retention."
    },
    "remediation_fields": {
      "caveats": [
        "Defaults do not establish retention on existing objects, and governance retention can be bypassed by authorized principals."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "account-global bucket.Name",
          "cloudtrail_account_inventory with complete enabled-Region and caller/capture binding",
          "cloudtrail.S3BucketName",
          "bucket.Versioning.Status",
          "bucket.ObjectLock.ObjectLockConfiguration.ObjectLockEnabled",
          "bucket.ObjectLock.ObjectLockConfiguration.Rule.DefaultRetention.Mode, Days or Years"
        ],
        "kind": "s3_bucket",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS S3 Object Lock Configuration API",
          "url": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ObjectLockConfiguration.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable versioning and retention protections if required; assess irreversible settings and existing-object coverage first."
      ],
      "summary": "Configure suitable versioning and retention protections if required; assess irreversible settings and existing-object coverage first."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "s3_bucket",
      "module": "peaso.checks._bulk_pending_compliance_new_sw36",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw36._archive_authority:501": "757267c9e3d394ced255c19663071bc2360426f6b629dc35c3df341ee12a7e8a",
        "peaso.checks._bulk_pending_compliance_new_sw36._archive_scope:37": "b2cf5a5b312dcd63ebe6e4f52940b3182c9bcf89fb0d4af82c3a0f3dde093994",
        "peaso.checks._bulk_pending_compliance_new_sw36._detail:193": "81beb54d5dce5cdcdf0f53190efed85bf5eda66c94047e8c76a7916f2a5e75ce",
        "peaso.checks._bulk_pending_compliance_new_sw36._lock_state:201": "74a8b93aacc06b8217f07fce6d5a6ff460e4fcea76bb5b13b8cae76ef522e89d",
        "peaso.checks._bulk_pending_compliance_new_sw36.log_archive_immutable:515": "d41261739fb5284f6e8e2ea6ff0c720740bd52da38f30545be3873774219d002"
      },
      "source_qualname": "log_archive_immutable"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "A CloudTrail destination bucket lacks versioning or a valid Object Lock default retention."
  },
  "aws_nist_apigateway_stage_cache_encryption_at_rest_enabled": {
    "description_fields": {
      "description": "Resolves deployed REST methods and wildcard/explicit cache settings, flagging enabled caches with encryption disabled."
    },
    "remediation_fields": {
      "caveats": [
        "Stages without a cache cluster are outside scope; ambiguous method overrides remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "apigateway:GetStages methodSettings for each REST API stage",
          "Complete inventories: rest_api_stage, rest_api_method"
        ],
        "kind": "rest_api_stage",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS APIGATEWAY Method Setting API",
          "url": "https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable encryption for the affected cached methods, or disable caching if unnecessary."
      ],
      "summary": "Enable encryption for the affected cached methods, or disable caching if unnecessary."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58::GLOBAL_KINDS": [
          "cloudfront_distribution",
          "iam_credential_report",
          "iam_user",
          "organization",
          "organization_account",
          "organization_delegated_admin",
          "organization_effective_scp",
          "organization_resource_policy",
          "organization_service_access",
          "shield_drt_access",
          "shield_protection",
          "shield_subscription"
        ]
      },
      "defaults": null,
      "kind": "rest_api_stage",
      "module": "peaso.checks._bulk_pending_compliance_new_sw37",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw37._member:76": "fda5bf12e8ded3a344b7c874792e44850970b257a931b645269ff38a2629c81f",
        "peaso.checks._bulk_pending_compliance_new_sw37._rows:58": "8f7abdaf6cebf992749e3e83418d8091f5891d38bb9c1bd1bbe61277d5daf8c3",
        "peaso.checks._bulk_pending_compliance_new_sw37._scope:49": "9af44f1b2451ca6be4b5bf54996ddc2943adac973d2722464f7d18e54302b501",
        "peaso.checks._bulk_pending_compliance_new_sw37._stage:123": "11093e44e590ec6456483e0cf568266ea4c629ec474de86c2ea26e196a6a1ab8",
        "peaso.checks._bulk_pending_compliance_new_sw37.stage_cache:193": "a9a89882cf8dbd5f852f073a268aa6c627b99ec613e638bd4217252b345fc671"
      },
      "source_qualname": "stage_cache"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A deployed REST API method enables caching without cache encryption."
  },
  "aws_nist_apigateway_stage_logging_enabled": {
    "description_fields": {
      "description": "Checks deployed REST methods\u2019 effective logging settings and validates WebSocket stage logging; HTTP APIs have no execution-logging applicability."
    },
    "remediation_fields": {
      "caveats": [
        "This is stage/method configuration; log delivery is unverified and HTTP API execution logging is unsupported."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "Read-only native REST GetStages and stage-bound GetDeployment(embed=apisummary) method inventory; v2 GetApis ProtocolType joined to GetStages DefaultRouteSettings and RouteSettings. Complete regional source inventories required.",
          "REST exact method and wildcard loggingLevel inheritance",
          "WebSocket LoggingLevel defaults and sparse route overrides",
          "v2 parent ProtocolType binding"
        ],
        "kind": "http_api_stage",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS APIGATEWAY set up logging",
          "url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable appropriate execution logging on the affected deployed REST methods."
      ],
      "summary": "Enable appropriate execution logging on the affected deployed REST methods."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw43._context:149::_ACCOUNT": {
          "flags": 32,
          "regex": "[0-9]{12}"
        },
        "peaso.checks._bulk_pending_compliance_new_sw43._context:149::_REGION": {
          "flags": 32,
          "regex": "[a-z]{2}(?:-[a-z]+)+-[0-9]"
        },
        "peaso.checks._bulk_pending_compliance_new_sw43._inventory:160::_GLOBAL": [
          "aws_account_configuration",
          "organization_account",
          "scp_policy"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw43._inventory:160::_IDS": {
          "backup_plan": "BackupPlanArn",
          "backup_restore_job": "RestoreJobId",
          "backup_selection": "id",
          "capacity_group": "id",
          "dynamodb_table": "TableName",
          "ecr_image": "imageDigest",
          "ecr_oci_artifact": "artifactDigest",
          "efs_access_point": "AccessPointArn",
          "efs_file_system": "FileSystemArn",
          "http_api_stage": "id",
          "organization_account": "Id",
          "rds_cluster": "DBClusterIdentifier",
          "rds_db_cluster": "DBClusterIdentifier",
          "rds_instance": "DBInstanceIdentifier",
          "rest_api_method": "id",
          "rest_api_stage": "id",
          "scp_policy": "Id"
        }
      },
      "defaults": [
        {
          "callable": "peaso.checks._bulk_pending_compliance_new_sw43._stage_logging"
        }
      ],
      "kind": "http_api_stage",
      "module": "peaso.checks._bulk_pending_compliance_new_sw43",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw43._context:149": "1aa5b2041689f81b99598c362ff562486a2dd4b76a014de0d22fb2d22de950f5",
        "peaso.checks._bulk_pending_compliance_new_sw43._evaluate:843": "ee842f8a3599092126ec189037cbc6fc57a65b3af746985a2dca092ab9f7f4cc",
        "peaso.checks._bulk_pending_compliance_new_sw43._inventory:160": "4250f56d50686a39dd8d4ecc949fc56746f71ddf4f63a040b356d0ec1e385f5e",
        "peaso.checks._bulk_pending_compliance_new_sw43._logging_level:337": "78627e1fd7fe82524c8dec18d215fc2d945de345d377927ca889b2e2c4b8b350",
        "peaso.checks._bulk_pending_compliance_new_sw43._rest_stage:367": "8cd8302dff569dc2bf09f7396aee714e98fe7b4538a652335b3bc5707813930a",
        "peaso.checks._bulk_pending_compliance_new_sw43._stage_bound:346": "d336da2cd61325fa6e1b2280978be1acba5b5a80e85351851fd3225ae54e9595",
        "peaso.checks._bulk_pending_compliance_new_sw43._stage_logging:453": "da1e8370e21b3d9ed530c894a9b85420384461062cb10c1d325ee52969f8fb84",
        "peaso.checks._bulk_pending_compliance_new_sw43._websocket_stage:429": "caf4db134d2e3f543caf75cce79841e5225420e4ce842ad18fd59c444645fa7a"
      },
      "source_qualname": "_evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A deployed REST method has execution logging disabled."
  },
  "aws_nist_cloudtrail_trail_integrated_with_logs": {
    "description_fields": {
      "description": "Checks logging trails\u2019 CloudWatch destinations, delivery-role trust and bounded native stream permission proofs."
    },
    "remediation_fields": {
      "caveats": [
        "PASS is declared same-account stream permission coverage, not live delivery or verified SCP/RCP effects; organization trails remain unresolved."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "cloudtrail:DescribeTrails CloudWatchLogsLogGroupArn/CloudWatchLogsRoleArn; logs:DescribeLogGroups and IAM role trust/permissions",
          "Complete inventories: cloudtrail_account_inventory, log_group"
        ],
        "kind": "cloudtrail",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS AWSCLOUDTRAIL Trail API",
          "url": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Correct missing destinations, role trust or stream permissions required for CloudTrail delivery."
      ],
      "summary": "Correct missing destinations, role trust or stream permissions required for CloudTrail delivery."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_BUCKET_LOG_IDS": [
          "aws.nist.all_cloudtrail_destination_bucket_access_logging",
          "aws_g6_all_cloudtrail_destination_bucket_access_logging",
          "aws_nist_cloudtrail_s3_logging_enabled"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_INTEGRATION_IDS": [
          "aws.nist.cloudtrail_cloudwatch_integration",
          "aws_g6_cloudtrail_all_trails_cloudwatch_integration",
          "aws_nist_cloudtrail_trail_integrated_with_logs"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206::_KMS_IDS": [
          "aws.nist.cloudtrail_cloudwatch_destination_kms",
          "aws_g6_cloudtrail_kms_destination_join",
          "aws_nist_cloudtrail_trail_logs_encrypted_with_kms_cmk"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155::_KMS_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):kms:([a-z0-9-]+):([0-9]{12}):key/[^/]+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129::_LOG_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):logs:([a-z0-9-]+):([0-9]{12}):log-group:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54::_TRAIL_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/[^/]+$"
        }
      },
      "defaults": [
        "aws_nist_cloudtrail_trail_integrated_with_logs"
      ],
      "kind": "cloudtrail",
      "module": "peaso.checks._bulk_pending_compliance_new_sw35",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket:106": "e493342d52113857ba0d0af8ddd5f32503d2944564dc0051a3554de726460ccc",
        "peaso.checks._bulk_pending_compliance_new_sw35._bucket_logging:113": "68fc91ccd885bd01b93f958ea79dd31166c6af13c042d6770923cd2ca019aaa0",
        "peaso.checks._bulk_pending_compliance_new_sw35._buckets:95": "227115d6eb587786a120a21452bc2f26db85062029a81d9f4ad1158a7bab8d8b",
        "peaso.checks._bulk_pending_compliance_new_sw35._cloudtrail:206": "7fc7f38f518800a5a237de0a0c8b4937dcdf8c6ca2e10d180f0e5337f75b16ba",
        "peaso.checks._bulk_pending_compliance_new_sw35._cmk:167": "96e40d1857f7bb7cb2660935c2e41b65c401e24c3cb3b516e384e178ce1aa3b9",
        "peaso.checks._bulk_pending_compliance_new_sw35._context:18": "48b3eff2b783841a7478854de3ef23f3c9600d0b262b1794a8582bc34b330809",
        "peaso.checks._bulk_pending_compliance_new_sw35._evaluate:571": "db6c233dce944c8523f68ebf521fbf5bdfa8a548e3ea4b098f3373cc2bd71944",
        "peaso.checks._bulk_pending_compliance_new_sw35._fresh:199": "9cdf65b158b6f51314e700fefa8857746f70b9f0287e7aabed574b1fb078cddb",
        "peaso.checks._bulk_pending_compliance_new_sw35._keys:155": "b5ce980ad26baadef5b7298e7ec5d315b91962928303c5b94d059ccf6e59f538",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_group:141": "d9daab07009418426d93241d4368f389c07d6cdcce215e3919bd12e5fcf8718e",
        "peaso.checks._bulk_pending_compliance_new_sw35._log_groups:129": "641b90e97047905dd88770f7df2172cea89b1c98fa63561da9e2eb5700ff59f7",
        "peaso.checks._bulk_pending_compliance_new_sw35._logging_trails:86": "bd9ce49432fd6c17fd2dd9fc90940c119a3b72129ee39f3823cd16dcfc70ffd0",
        "peaso.checks._bulk_pending_compliance_new_sw35._policy:454": "e452be311f5a85f4efe2ece666384392fdbedd6ad6fde9a6fcc855f5c34fa881",
        "peaso.checks._bulk_pending_compliance_new_sw35._registered:586": "0b9679c5acb0a2c3d4d45db82a7142195783c971b43ac1b6a32e30874dd41d7e",
        "peaso.checks._bulk_pending_compliance_new_sw35._rows:27": "21633a64b94ae91fc79c7b380b07edc77a245adcb678b19112a3bd43ac0085b3",
        "peaso.checks._bulk_pending_compliance_new_sw35._ssm:482": "e5813f4c7b7a39967a90b4b2cf87b5aacaef0883016be87d60241c2c2d7637b1",
        "peaso.checks._bulk_pending_compliance_new_sw35._time:187": "5784d81b10523f17207ad7111a67f6f185f2737a625cb9ed54cd01eadac1cdcb",
        "peaso.checks._bulk_pending_compliance_new_sw35._trails:54": "f1daede05c5e264575b3ddd0844fb83c3a1df06eebd07ec719f1223e889bfb25",
        "peaso.checks._bulk_pending_compliance_new_sw35._versions_at_least:471": "6ffde1815a868afa5d9dfa65e34edb92a5ddc9bfcc6d28d1794b4530b9b959f8"
      },
      "source_qualname": "_registered"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A logging trail lacks a valid CloudWatch destination, role or required permission proof."
  },
  "aws_nist_config_enabled_all_regions": {
    "description_fields": {
      "description": "Validates native account-wide region discovery and checks each enabled region has an active unrestricted recorder and delivery channel."
    },
    "remediation_fields": {
      "caveats": [
        "Unproven global-resource applicability or run state remains UNKNOWN; this does not prove successful delivery of every configuration item."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "config:DescribeConfigurationRecorders, DescribeConfigurationRecorderStatus, DescribeDeliveryChannels in every enabled account Region",
          "Complete inventories: config_recorder, config_delivery_channel"
        ],
        "kind": "config_account_region_coverage",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS CONFIG Configuration Recorder API",
          "url": "https://docs.aws.amazon.com/config/latest/APIReference/API_ConfigurationRecorder.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the missing recorder, delivery channel or required recording coverage in affected regions."
      ],
      "summary": "Configure the missing recorder, delivery channel or required recording coverage in affected regions."
    },
    "reviewed_binding": {
      "closure": {
        "identifier": "aws_nist_config_enabled_all_regions"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811::EVALUATORS": {
          "aws.nist.sc_36_coverage": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._recovery"
          },
          "aws.pci.classic_elb.custom_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.classic_elb.predefined_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.redshift.expected_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._redshift"
          },
          "aws.pci.secretsmanager.kms_encryption_any": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._kms"
          },
          "aws_autoscaling_userdata_plaintext_aws_key": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._userdata"
          },
          "aws_ecr_repository_lifecycle_retention": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecr"
          },
          "aws_g6_ecs_fargate_storage_encryption": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecs"
          },
          "aws_nist_cloudformation_stack_drift_detection_check": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._drift"
          },
          "aws_nist_config_enabled_all_regions": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._config"
          },
          "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rds"
          },
          "aws_nist_secretsmanager_secret_automatic_rotation_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rotation"
          },
          "aws_organizations_environment_account_separation": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._separation"
          },
          "aws_sagemaker_model_clarify_bias_job": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._clarify"
          },
          "aws_vpn_tunnel_encryption_configuration": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._vpn"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[a-z0-9-]*:[0-9]{12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_SCOPE": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z0-9-]+$"
        }
      },
      "defaults": null,
      "kind": "config_account_region_coverage",
      "module": "peaso.checks._bulk_pending_compliance_new_sw48",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw48._config:87": "f72de6e0c0c2a9c8fa1b33ad03d67351efd8a2ccbd6dd40a137b00aa7b4b71a2",
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811": "ae35cf3acf73d2d9b595a8f64672eba95725a8530d896346dfb770b772644588",
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34": "28c7fa38621503a88a0564acb5b0abd82e7036874d3c1edd271d85c2aecb2d9e"
      },
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An enabled region lacks an active recorder, delivery channel or required recording coverage."
  },
  "aws_nist_elb_application_gateway_network_lb_multiple_az_configured": {
    "description_fields": {
      "description": "Joins target groups and observed target-health records, requiring healthy instance/IP targets in at least two declared load-balancer zones."
    },
    "remediation_fields": {
      "caveats": [
        "Despite its placement label, this checks healthy-target evidence; Lambda and ALB targets do not count toward the two-zone witness."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "elbv2:DescribeLoadBalancers AvailabilityZones; DescribeTargetGroups/DescribeTargetHealth target AvailabilityZone and Health",
          "Complete inventories: load_balancer, target_group"
        ],
        "kind": "load_balancer",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS Elastic Load Balancing Describe Target Health API",
          "url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetHealth.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Restore suitable healthy targets in multiple zones where this availability profile applies."
      ],
      "summary": "Restore suitable healthy targets in multiple zones where this availability profile applies."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "load_balancer",
      "module": "peaso.checks._bulk_pending_compliance_new_sw42",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw42._arn_scope:100": "518b8c9bc4295ae8abe707706c5c781da024195632a3de19d9090c7fa77b8652",
        "peaso.checks._bulk_pending_compliance_new_sw42._item:91": "9d982a09093381f5b3e0c96e00f59e44c72b7d7079b3a95ee80613872d455cbe",
        "peaso.checks._bulk_pending_compliance_new_sw42._lb:382": "1eb411cff35f465083c9a478352fb48cd1bd614ea74749152415fbed8c146b54",
        "peaso.checks._bulk_pending_compliance_new_sw42._rows:63": "849fde7ce1d4d00e72606efd399c2fd3f200edca6864a9c492ae5d57034d198b",
        "peaso.checks._bulk_pending_compliance_new_sw42._scope:53": "d54ebef4ffc206be4869114911f42814e9060cd7dd84b2f04843e84d6ccb80f8",
        "peaso.checks._bulk_pending_compliance_new_sw42._strings:119": "e782dad9f877bd54cfec4a92763e21690814cd62b17c2d706965c4e1d4638932",
        "peaso.checks._bulk_pending_compliance_new_sw42._target_groups:433": "1cbdd96f6ffa3be075cefadfc01f3367223f9a6e7f0409e8c7260a13b81a968b",
        "peaso.checks._bulk_pending_compliance_new_sw42.elbv2_healthy_targets_multi_az:497": "0630002855f90eb98d9f0f6a2b299039cc409db3d05356b85c3ed2a22d98088b"
      },
      "source_qualname": "elbv2_healthy_targets_multi_az"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The load balancer has healthy instance/IP targets in fewer than two declared zones."
  },
  "aws_nist_rds_db_cluster_aurora_backtracking_enabled": {
    "description_fields": {
      "description": "Checks supported Aurora/MySQL clusters for a positive BacktrackWindow; missing or zero windows fail."
    },
    "remediation_fields": {
      "caveats": [
        "Backtracking is optional and distinct from backups, point-in-time recovery and tested restores."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "rds:DescribeDBClusters Engine, BacktrackWindow",
          "Complete inventories: rds_cluster"
        ],
        "kind": "rds_cluster",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS RDS Aurora My SQL.Managing.Backtrack",
          "url": "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Managing.Backtrack.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable a suitable backtrack window if this supported cluster needs backtracking; assess deployment constraints first."
      ],
      "summary": "Enable a suitable backtrack window if this supported cluster needs backtracking; assess deployment constraints first."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw43._context:149::_ACCOUNT": {
          "flags": 32,
          "regex": "[0-9]{12}"
        },
        "peaso.checks._bulk_pending_compliance_new_sw43._context:149::_REGION": {
          "flags": 32,
          "regex": "[a-z]{2}(?:-[a-z]+)+-[0-9]"
        },
        "peaso.checks._bulk_pending_compliance_new_sw43._inventory:160::_GLOBAL": [
          "aws_account_configuration",
          "organization_account",
          "scp_policy"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw43._inventory:160::_IDS": {
          "backup_plan": "BackupPlanArn",
          "backup_restore_job": "RestoreJobId",
          "backup_selection": "id",
          "capacity_group": "id",
          "dynamodb_table": "TableName",
          "ecr_image": "imageDigest",
          "ecr_oci_artifact": "artifactDigest",
          "efs_access_point": "AccessPointArn",
          "efs_file_system": "FileSystemArn",
          "http_api_stage": "id",
          "organization_account": "Id",
          "rds_cluster": "DBClusterIdentifier",
          "rds_db_cluster": "DBClusterIdentifier",
          "rds_instance": "DBInstanceIdentifier",
          "rest_api_method": "id",
          "rest_api_stage": "id",
          "scp_policy": "Id"
        },
        "peaso.checks._bulk_pending_compliance_new_sw43._subject:193::_IDS": {
          "backup_plan": "BackupPlanArn",
          "backup_restore_job": "RestoreJobId",
          "backup_selection": "id",
          "capacity_group": "id",
          "dynamodb_table": "TableName",
          "ecr_image": "imageDigest",
          "ecr_oci_artifact": "artifactDigest",
          "efs_access_point": "AccessPointArn",
          "efs_file_system": "FileSystemArn",
          "http_api_stage": "id",
          "organization_account": "Id",
          "rds_cluster": "DBClusterIdentifier",
          "rds_db_cluster": "DBClusterIdentifier",
          "rds_instance": "DBInstanceIdentifier",
          "rest_api_method": "id",
          "rest_api_stage": "id",
          "scp_policy": "Id"
        }
      },
      "defaults": [
        {
          "callable": "peaso.checks._bulk_pending_compliance_new_sw43._backtracking"
        }
      ],
      "kind": "rds_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw43",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw43._backtracking:275": "9234aa04f3c833db7ca95d90b607e48d8dc23792f0ed0b7d0de64f95196802ec",
        "peaso.checks._bulk_pending_compliance_new_sw43._context:149": "1aa5b2041689f81b99598c362ff562486a2dd4b76a014de0d22fb2d22de950f5",
        "peaso.checks._bulk_pending_compliance_new_sw43._evaluate:843": "ee842f8a3599092126ec189037cbc6fc57a65b3af746985a2dca092ab9f7f4cc",
        "peaso.checks._bulk_pending_compliance_new_sw43._inventory:160": "4250f56d50686a39dd8d4ecc949fc56746f71ddf4f63a040b356d0ec1e385f5e",
        "peaso.checks._bulk_pending_compliance_new_sw43._subject:193": "17a0dc6ebd0c801af657c9d23794a870b1fcbfa70b9e77688c185566192d0720"
      },
      "source_qualname": "_evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The backtracking-capable Aurora cluster has no positive backtrack window."
  },
  "aws_nist_secretsmanager_secret_automatic_rotation_enabled": {
    "description_fields": {
      "description": "Checks enabled secret rotation, a supported positive schedule and a proven Lambda or supported managed-service rotation method."
    },
    "remediation_fields": {
      "caveats": [
        "This is configuration, not evidence of successful past rotations or application compatibility."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "secret.ARN bound to native DescribeSecret",
          "secret.RotationEnabled",
          "secret.RotationRules.AutomaticallyAfterDays or ScheduleExpression",
          "secret.OwningService",
          "secret.RotationLambdaARN"
        ],
        "kind": "secret",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS SECRETSMANAGER Describe Secret API",
          "url": "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required rotation schedule and method if automatic rotation is appropriate."
      ],
      "summary": "Configure the required rotation schedule and method if automatic rotation is appropriate."
    },
    "reviewed_binding": {
      "closure": {
        "identifier": "aws_nist_secretsmanager_secret_automatic_rotation_enabled"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811::EVALUATORS": {
          "aws.nist.sc_36_coverage": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._recovery"
          },
          "aws.pci.classic_elb.custom_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.classic_elb.predefined_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.redshift.expected_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._redshift"
          },
          "aws.pci.secretsmanager.kms_encryption_any": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._kms"
          },
          "aws_autoscaling_userdata_plaintext_aws_key": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._userdata"
          },
          "aws_ecr_repository_lifecycle_retention": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecr"
          },
          "aws_g6_ecs_fargate_storage_encryption": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecs"
          },
          "aws_nist_cloudformation_stack_drift_detection_check": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._drift"
          },
          "aws_nist_config_enabled_all_regions": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._config"
          },
          "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rds"
          },
          "aws_nist_secretsmanager_secret_automatic_rotation_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rotation"
          },
          "aws_organizations_environment_account_separation": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._separation"
          },
          "aws_sagemaker_model_clarify_bias_job": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._clarify"
          },
          "aws_vpn_tunnel_encryption_configuration": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._vpn"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[a-z0-9-]*:[0-9]{12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_SCOPE": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z0-9-]+$"
        }
      },
      "defaults": null,
      "kind": "secret",
      "module": "peaso.checks._bulk_pending_compliance_new_sw48",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811": "ae35cf3acf73d2d9b595a8f64672eba95725a8530d896346dfb770b772644588",
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34": "28c7fa38621503a88a0564acb5b0abd82e7036874d3c1edd271d85c2aecb2d9e",
        "peaso.checks._bulk_pending_compliance_new_sw48._positive_int:71": "de07747c00353dda877ce4b36eecc9d03f7694a69b9fa35deb025a9c1c072141",
        "peaso.checks._bulk_pending_compliance_new_sw48._rotation:255": "3d0afc1b3c2bc448ca41c5adb038708115c411a64c29f04225b3a3aca758309f",
        "peaso.checks._bulk_pending_compliance_new_sw48._valid_rotation_schedule:186": "40050b7cb74c0707d4c426b9355bc16362d9118c174ca2e055537952def1e448"
      },
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The secret lacks enabled rotation, a supported schedule or its required Lambda method."
  },
  "aws_nist_sns_topic_notification_delivery_status_enabled": {
    "description_fields": {
      "description": "Joins topic subscriptions to supported protocols and requires success/failure feedback roles plus a positive success-sampling rate for each."
    },
    "remediation_fields": {
      "caveats": [
        "These declarations do not prove role usability or delivered logs; unsupported protocol mappings remain UNKNOWN."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "sns:GetTopicAttributes endpoint-specific FailureFeedbackRoleArn, SuccessFeedbackRoleArn and SuccessFeedbackSampleRate",
          "Complete inventories: sns_topic, sns_subscription"
        ],
        "kind": "sns_topic",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS SNS sns topic attributes",
          "url": "https://docs.aws.amazon.com/sns/latest/dg/sns-topic-attributes.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure both feedback roles and an appropriate positive success-sampling rate for the affected protocols."
      ],
      "summary": "Configure both feedback roles and an appropriate positive success-sampling rate for the affected protocols."
    },
    "reviewed_binding": {
      "closure": {
        "cid": "aws_nist_sns_topic_notification_delivery_status_enabled"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw46._make.<locals>.evaluate:868::_EVALUATORS": {
          "aws.pci.cloudwatch.metric_alarm_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._alarm_settings"
          },
          "aws.pci.cloudwatch.resource_metric_alarm": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._resource_alarm"
          },
          "aws.pci.iam.third_party_temporary_access": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._temporary_access"
          },
          "aws_cloudwatch_alarm_missing_data_realert": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._inactivity_alarm"
          },
          "aws_ec2_ai_nitro_instance_type": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._ec2_nitro"
          },
          "aws_ec2_instance_time_offset_monitored": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._ec2_time"
          },
          "aws_g6_sns_no_named_cross_account_principals": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._sns_policy"
          },
          "aws_guardduty_doh_threat_list": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_doh"
          },
          "aws_guardduty_suppression_filters": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_filters"
          },
          "aws_guardduty_threat_feed": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_feed"
          },
          "aws_guardduty_trusted_administrator": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_admin"
          },
          "aws_nist_ec2_instance_not_publicly_accessible": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._ec2_public"
          },
          "aws_nist_sns_topic_notification_delivery_status_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._sns_delivery"
          },
          "aws_partner_role_external_id_present": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._partner_external"
          },
          "aws_shield_ddos_detected_alarm": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._shield_alarm"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw46._resource:193::_IDS": {
          "cloudwatch_alarm": "AlarmArn",
          "guardduty_detector": "DetectorId",
          "iam_role": "Arn",
          "instance": "InstanceId",
          "sns_topic": "TopicArn"
        },
        "peaso.checks._bulk_pending_compliance_new_sw46._sns_delivery:708::_FEEDBACK_PREFIX": {
          "application": "Application",
          "firehose": "Firehose",
          "http": "HTTP",
          "https": "HTTP",
          "lambda": "Lambda",
          "sqs": "SQS"
        }
      },
      "defaults": null,
      "kind": "sns_topic",
      "module": "peaso.checks._bulk_pending_compliance_new_sw46",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw46._api_optional:238": "2e6404f397abc368c015cc90ab14a37994de0529e44d89967fc736d53c995f76",
        "peaso.checks._bulk_pending_compliance_new_sw46._context:163": "ce8cdfe50b2c464f192bf1c0bf6758b378bea24fc143c9c82e94a432e35ab2c2",
        "peaso.checks._bulk_pending_compliance_new_sw46._items:174": "16e61710deb6df288724e7db42adf118cf428f64e20cc43b8dd1d4e305ac79f3",
        "peaso.checks._bulk_pending_compliance_new_sw46._make.<locals>.evaluate:868": "ece643fcf7b6f37ee64c32732f3b18acfd79f12d26ebdc595399679a8338ee88",
        "peaso.checks._bulk_pending_compliance_new_sw46._resource:193": "a195dda5c5c9b79d722c180b9ba9681b248ebed8532587909b503ec49eafcadc",
        "peaso.checks._bulk_pending_compliance_new_sw46._sns_delivery:708": "1952feb2b136498e1b3f88bd82a6f75ea77de9eea8b2ee2ca7271fc2753860af"
      },
      "source_qualname": "_make.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A subscribed protocol lacks complete success/failure delivery-feedback settings."
  },
  "aws_nist_waf_web_acl_logging_enabled": {
    "description_fields": {
      "description": "Checks complete account inventory of global Classic, regional Classic and WAFv2 ACLs for valid nonempty logging destinations."
    },
    "remediation_fields": {
      "caveats": [
        "The scope includes all three families; destination configuration does not prove log delivery."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "waf:GetWebACL/ListLoggingConfigurations; waf-regional:GetWebACL/ListLoggingConfigurations; wafv2:ListWebACLs/GetLoggingConfiguration",
          "Complete inventories: waf_web_acl, waf_account_acl_inventory"
        ],
        "kind": "waf_web_acl",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS WAF Get Logging Configuration API",
          "url": "https://docs.aws.amazon.com/waf/latest/APIReference/API_GetLoggingConfiguration.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable logging destinations for the identified ACLs."
      ],
      "summary": "Configure suitable logging destinations for the identified ACLs."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "waf_web_acl",
      "module": "peaso.checks._bulk_pending_compliance_new_sw38",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw38._arn_account_region:248": "2bde834fe5016372e0c5f00ff742ec437576a6a557f30ba2ec1624030625caaa",
        "peaso.checks._bulk_pending_compliance_new_sw38._logging_missing:662": "8abb2889bffdc51d81b59f83b35bad279d99bd3f7cdb9d083fc04afe8ff366dd",
        "peaso.checks._bulk_pending_compliance_new_sw38._objects:242": "47c20e21db77e817c51f8826e59d29f887b7756d85eac5308b25b9ef4b47d4ec",
        "peaso.checks._bulk_pending_compliance_new_sw38._rows:185": "f53fe1b0ef2c2bd14680a16afeb1f238c0e883c8840a18502f037aaa39466d60",
        "peaso.checks._bulk_pending_compliance_new_sw38._scope:175": "7b34c7e1ffd89c0d626acc87d44ac8a20319570b3d16ccc0206405a628047d99",
        "peaso.checks._bulk_pending_compliance_new_sw38._strings:235": "9780c759d804462d107a20b3da9a860b0b18be05957a46ac9955cb5a2c763271",
        "peaso.checks._bulk_pending_compliance_new_sw38._waf_account:627": "0844e2b98795b85f534db3ad6c088ed65fd73e5a038bd2109ee76da783c318b6",
        "peaso.checks._bulk_pending_compliance_new_sw38._waf_scope:653": "add82ad6b345c668aa09f91ace51c6f5c357a0fe30c37b89692d624b3fd53f5b",
        "peaso.checks._bulk_pending_compliance_new_sw38.waf_all_logging:690": "db256503347c2a550f3a15aeb803d28c07faeaada6e0c2ca4a8a0e61a24960f8"
      },
      "source_qualname": "waf_all_logging"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A global Classic, regional Classic or WAFv2 ACL has no logging destination."
  },
  "aws_nist_waf_web_acl_resource_associated": {
    "description_fields": {
      "description": "Checks regional Classic WAF ALB/API Gateway association coverage and requires at least one associated resource."
    },
    "remediation_fields": {
      "caveats": [
        "Global Classic and WAFv2 associations are outside this control; unused ACLs can be intentional."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "waf:ListWebACLs/GetWebACL; waf-regional:ListResourcesForWebACL; wafv2:ListResourcesForWebACL; cloudfront:ListDistributions WebACLId",
          "Complete inventories: wafregional_web_acl"
        ],
        "kind": "wafregional_web_acl",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS WAF waf Regional List Resources For Web ACL API",
          "url": "https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_ListResourcesForWebACL.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Associate the ACL if needed or retire an unused ACL after checking dependencies."
      ],
      "summary": "Associate the ACL if needed or retire an unused ACL after checking dependencies."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "wafregional_web_acl",
      "module": "peaso.checks._bulk_pending_compliance_new_sw39",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw39._arn_scope:113": "330f3e33d1d20980e4c418ac5ad0ba25ec5197e16a6787674078aa3e7b6f0a7a",
        "peaso.checks._bulk_pending_compliance_new_sw39._item:73": "bfb5da8658d714038370d20892a3e5c2e30122b50e98ca2e3ccf949352292128",
        "peaso.checks._bulk_pending_compliance_new_sw39._rows:53": "3a2a7cab83381143eb3887a72bca8de6612e454f71370bffeb1f21a439526a86",
        "peaso.checks._bulk_pending_compliance_new_sw39._scope:43": "d54ebef4ffc206be4869114911f42814e9060cd7dd84b2f04843e84d6ccb80f8",
        "peaso.checks._bulk_pending_compliance_new_sw39._strings:95": "770978f6e1f35209f0556e176fe97764cd2a9a2664494a5de70ad2bc55be26e1",
        "peaso.checks._bulk_pending_compliance_new_sw39.waf_associated:127": "bdc9d1624d5598c60f5e5ef9dcdf610c6c1a4746166f1c87038dfd5d507c88f7"
      },
      "source_qualname": "waf_associated"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "The regional Classic WAF ACL has no associated ALB or API Gateway resource."
  },
  "aws_route53resolver_blocked_query_alert": {
    "description_fields": {
      "description": "Checks each completely associated DNS Firewall VPC has a matching BlockedQueries CloudWatch alarm with enabled actions."
    },
    "remediation_fields": {
      "caveats": [
        "Metric-alarm configuration does not establish that a notification was delivered."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only route53resolver:ListFirewallRuleGroupAssociations, cloudwatch:DescribeAlarms",
          "Complete inventories: event_rule, resolver_firewall_association, cloudwatch_alarm"
        ],
        "kind": "event_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EVENTBRIDGE Rule API",
          "url": "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable blocked-query alarms for VPCs that require this notification."
      ],
      "summary": "Configure suitable blocked-query alarms for VPCs that require this notification."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "event_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw45",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw45._alarms:247": "94551d4dc659b623ee1c17e863a468ad506e0e808e75e86845d18fd404a11949",
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199": "cd29dfee9c28637ab5a70c78802687ad8992a25ac34ed35c139869be8ca0914e",
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150": "dcbb098304c8c01130962b40e93a2cf654e0b524aacf3aea387fc3852867c066",
        "peaso.checks._bulk_pending_compliance_new_sw45._events:516": "5b07813ba3441ef7b944d0d3eee0012dddf309db9e0870384632e6b4ef430caf",
        "peaso.checks._bulk_pending_compliance_new_sw45._inventory:161": "96f64e73f8106c570a5764453d39e03968457d4a89f7184f75008c472c0c6228",
        "peaso.checks._bulk_pending_compliance_new_sw45.resolver_blocked_query_alert:739": "57844bc04ad69a0afaf91a969b10f746d1f659743234aad497501fdab4df8631"
      },
      "source_qualname": "resolver_blocked_query_alert"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A DNS Firewall VPC lacks a matching enabled-action BlockedQueries alarm."
  },
  "aws_securityhub_critical_findings_alert": {
    "description_fields": {
      "description": "Looks for an enabled targeted EventBridge rule covering imported Security Hub findings with CRITICAL severity."
    },
    "remediation_fields": {
      "caveats": [
        "Configured event coverage is not proof of delivery or incident response."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only events:ListRules, events:ListTargetsByRule",
          "Complete inventories: eventbridge_rule"
        ],
        "kind": "eventbridge_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EVENTBRIDGE Rule API",
          "url": "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure critical-finding routing to an intended notification target."
      ],
      "summary": "Configure critical-finding routing to an intended notification target."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw36._rule_rows:258::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw36._rule_rows:258::_VALID_RULE_STATES": [
          "DISABLED",
          "ENABLED",
          "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
        ],
        "peaso.checks._bulk_pending_compliance_new_sw36._scope:27::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw36.securityhub_critical_findings_alert:738::_ENABLED_RULE_STATES": [
          "ENABLED",
          "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
        ]
      },
      "defaults": null,
      "kind": "eventbridge_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw36",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw36._event_match:637": "415aa15f54a620fb185b5367b838de63450f5db2bc2914aab2cb36ffa2aeff26",
        "peaso.checks._bulk_pending_compliance_new_sw36._event_pattern:226": "403cb2adb050db14f47aab3d644cf3e9d43db6ec1125eb3d3bf8fbb81f6cab29",
        "peaso.checks._bulk_pending_compliance_new_sw36._event_scope:288": "28284a5a685a5b74bab259c68319c44ae5c5df941b19f5e1010adf621076b0cc",
        "peaso.checks._bulk_pending_compliance_new_sw36._exact_field:243": "97b33a13bfae522ab8010a8ff8ca4aea9dc9f8c4124b4a1299512982b297a8ed",
        "peaso.checks._bulk_pending_compliance_new_sw36._list_fact:148": "abeaeabd79fcb2db168feb70f4d56d2bcf12f77be1a265fdee64611fe83eaeaa",
        "peaso.checks._bulk_pending_compliance_new_sw36._rows:48": "dc9eea3dc8777b8e42d22987da4b17f4915dce71a7144751ac029ff54dbf7587",
        "peaso.checks._bulk_pending_compliance_new_sw36._rule_rows:258": "fd033cc32363b97de904b48ad0e29b208aa92233593e0a1ce79fe7bfdcb9a821",
        "peaso.checks._bulk_pending_compliance_new_sw36._scope:27": "cc989afc0fe719579ed92b1f6e574ca50e30202adadcb93137bbc89d72d7bc96",
        "peaso.checks._bulk_pending_compliance_new_sw36._targets:284": "912b0b86b21404ff19bd803abfe4ba46753468cda44b5c02b79d866a03058b64",
        "peaso.checks._bulk_pending_compliance_new_sw36.securityhub_critical_findings_alert:738": "df592b09fdef7867f8180a5ce75f8ea3302918aa5214eed219f698fe37173d1a"
      },
      "source_qualname": "securityhub_critical_findings_alert"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "No supported enabled rule routes imported critical Security Hub findings to a target."
  },
  "aws_securityhub_findings_alerted": {
    "description_fields": {
      "description": "Requires one enabled targeted EventBridge rule whose supported pattern covers both HIGH and CRITICAL imported Security Hub findings."
    },
    "remediation_fields": {
      "caveats": [
        "Separate severity-specific rules do not satisfy this literal single-rule profile; delivery remains unverified."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "events:ListRules/DescribeRule/ListTargetsByRule; EventPattern.source, EventPattern.detail.findings.Severity.Label, State, Targets[].Arn",
          "Complete inventories: event_rule"
        ],
        "kind": "event_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EVENTBRIDGE Rule API",
          "url": "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure a supported rule covering both required severities with an intended target."
      ],
      "summary": "Configure a supported rule covering both required severities with an intended target."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "event_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw45",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199": "cd29dfee9c28637ab5a70c78802687ad8992a25ac34ed35c139869be8ca0914e",
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150": "dcbb098304c8c01130962b40e93a2cf654e0b524aacf3aea387fc3852867c066",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_coverage:619": "b28597951bb04bad7ec6efda6e42b08d08e7180b5f06e6cc6351401167a20b0d",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_match:583": "9b287bea1e4b03b17158b9c031d550538d12208c813d48152ed14f4f878ba0b3",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_relevance:553": "094861aa6da3736545011e7d43db0c6a8d834af513bc11e1f9c44cfb0bfee4af",
        "peaso.checks._bulk_pending_compliance_new_sw45._events:516": "5b07813ba3441ef7b944d0d3eee0012dddf309db9e0870384632e6b4ef430caf",
        "peaso.checks._bulk_pending_compliance_new_sw45._inventory:161": "96f64e73f8106c570a5764453d39e03968457d4a89f7184f75008c472c0c6228",
        "peaso.checks._bulk_pending_compliance_new_sw45._literal_selector_relevance:542": "85598dbf0be0d556e5e0d1ac2a48a6a9f96ed5cbc8d6310f7ca991a19cce7355",
        "peaso.checks._bulk_pending_compliance_new_sw45._native_scheduled_only:564": "c46daeda404bd2e8bd6348b6ce486671264e14ad40c9a1ea0eac5bc06f0f759b",
        "peaso.checks._bulk_pending_compliance_new_sw45._objects:210": "9d1a3637de24029d955da7eb29fa168e69a3f9d24bbbe86547038ae21ad97e81",
        "peaso.checks._bulk_pending_compliance_new_sw45._pattern:530": "0de478ed4ab94a51df52906d84736e6fef33e6265e043ce7c2409657975aef88",
        "peaso.checks._bulk_pending_compliance_new_sw45._strings:218": "8bed843582a7903e48dee7e7a44b633cc19ce599016fe2a8a8f4941aff78a744",
        "peaso.checks._bulk_pending_compliance_new_sw45._targets:611": "c1e10accbca5baef2e45806acf644f23cd77b32423ded27f861967a1926c9a40",
        "peaso.checks._bulk_pending_compliance_new_sw45.securityhub_findings_alerted:660": "3a64a68b690323a5b9feedfa8761fba2c275437fa2d26bf64485c04d62edf48c"
      },
      "source_qualname": "securityhub_findings_alerted"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "high",
    "static_observed_sentence": "No single supported notification rule covers both high and critical Security Hub findings."
  },
  "aws_securityhub_medium_findings_alert": {
    "description_fields": {
      "description": "Checks the union of enabled targeted EventBridge rules covers MEDIUM, LOW and INFORMATIONAL imported Security Hub findings."
    },
    "remediation_fields": {
      "caveats": [
        "Despite the medium-only legacy label, all three severities are required; delivery is unverified."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only API calls events:ListRules and events:ListTargetsByRule; EventPattern and Targets",
          "Complete inventories: event_rule"
        ],
        "kind": "event_rule",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EVENTBRIDGE Rule API",
          "url": "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure the required severity coverage if these findings need notifications."
      ],
      "summary": "Configure the required severity coverage if these findings need notifications."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "event_rule",
      "module": "peaso.checks._bulk_pending_compliance_new_sw45",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199": "cd29dfee9c28637ab5a70c78802687ad8992a25ac34ed35c139869be8ca0914e",
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150": "dcbb098304c8c01130962b40e93a2cf654e0b524aacf3aea387fc3852867c066",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_coverage:619": "b28597951bb04bad7ec6efda6e42b08d08e7180b5f06e6cc6351401167a20b0d",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_match:583": "9b287bea1e4b03b17158b9c031d550538d12208c813d48152ed14f4f878ba0b3",
        "peaso.checks._bulk_pending_compliance_new_sw45._event_relevance:553": "094861aa6da3736545011e7d43db0c6a8d834af513bc11e1f9c44cfb0bfee4af",
        "peaso.checks._bulk_pending_compliance_new_sw45._events:516": "5b07813ba3441ef7b944d0d3eee0012dddf309db9e0870384632e6b4ef430caf",
        "peaso.checks._bulk_pending_compliance_new_sw45._inventory:161": "96f64e73f8106c570a5764453d39e03968457d4a89f7184f75008c472c0c6228",
        "peaso.checks._bulk_pending_compliance_new_sw45._literal_selector_relevance:542": "85598dbf0be0d556e5e0d1ac2a48a6a9f96ed5cbc8d6310f7ca991a19cce7355",
        "peaso.checks._bulk_pending_compliance_new_sw45._native_scheduled_only:564": "c46daeda404bd2e8bd6348b6ce486671264e14ad40c9a1ea0eac5bc06f0f759b",
        "peaso.checks._bulk_pending_compliance_new_sw45._objects:210": "9d1a3637de24029d955da7eb29fa168e69a3f9d24bbbe86547038ae21ad97e81",
        "peaso.checks._bulk_pending_compliance_new_sw45._pattern:530": "0de478ed4ab94a51df52906d84736e6fef33e6265e043ce7c2409657975aef88",
        "peaso.checks._bulk_pending_compliance_new_sw45._strings:218": "8bed843582a7903e48dee7e7a44b633cc19ce599016fe2a8a8f4941aff78a744",
        "peaso.checks._bulk_pending_compliance_new_sw45._targets:611": "c1e10accbca5baef2e45806acf644f23cd77b32423ded27f861967a1926c9a40",
        "peaso.checks._bulk_pending_compliance_new_sw45.securityhub_medium_findings_alert:667": "5ae5e77154dabd91b6bf24b2cd977afe24664c7ed764b4bfe1a1c7c7a3ef0cc4"
      },
      "source_qualname": "securityhub_medium_findings_alert"
    },
    "reviewed_severity": "info",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Notification rules do not cover every required medium, low and informational Security Hub severity."
  },
  "aws_securityhub_no_critical_findings": {
    "description_fields": {
      "description": "Checks complete critical-finding results for every audited region and flags ACTIVE findings not RESOLVED or SUPPRESSED."
    },
    "remediation_fields": {
      "caveats": [
        "Workflow state does not prove remediation; this imports Security Hub severity rather than independently confirming exploitability."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only securityhub:GetFindings with Severity.Label=CRITICAL, RecordState=ACTIVE",
          "Complete inventories: securityhub_hub"
        ],
        "kind": "securityhub_hub",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS SECURITYHUB Get Findings API",
          "url": "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Review and resolve the underlying critical findings; suppress only verified accepted exceptions."
      ],
      "summary": "Review and resolve the underlying critical findings; suppress only verified accepted exceptions."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {},
      "defaults": null,
      "kind": "securityhub_hub",
      "module": "peaso.checks._bulk_pending_compliance_new_sw06",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw06._inventory:16": "5bd61e1e4f0be89d2d273e4b5786d149d7d9989d1e5c632f77ba27cd68ca4ab5",
        "peaso.checks._bulk_pending_compliance_new_sw06._params:70": "50297c14c44c45816a47d59b42a05765dca7e673cb564415871ff94e56bf23cc",
        "peaso.checks._bulk_pending_compliance_new_sw06._securityhub_critical:253": "854006907e44013186ceceea8ef82720dcebf85a98a9304c877d5c443102a678",
        "peaso.checks._bulk_pending_compliance_new_sw06._strings:76": "2297de791071e29f8ba7abeb31f57285261e5759709760d39cf47a5c3a9029f9",
        "peaso.checks._bulk_pending_compliance_new_sw06.check_aws_securityhub_no_critical_findings:559": "340d5f961e85be9d06560051670414f62f2248eb49e532c1820e7c519fc6f09b"
      },
      "source_qualname": "check_aws_securityhub_no_critical_findings"
    },
    "reviewed_severity": "high",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "Active critical Security Hub findings remain unresolved and unsuppressed."
  },
  "aws_shield_ddos_detected_alarm": {
    "description_fields": {
      "description": "Joins regional Shield protections to exact ResourceArn DDoSDetected alarms that alert on 1 rather than 0 and have enabled actions."
    },
    "remediation_fields": {
      "caveats": [
        "Alarm configuration does not prove a detected attack or delivered notification."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only shield:ListProtections, cloudwatch:DescribeAlarms",
          "Complete inventories: cloudwatch_alarm, shield_protection_region"
        ],
        "kind": "cloudwatch_alarm",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS CloudWatch Metric Alarm API",
          "url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricAlarm.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Configure suitable DDoSDetected alarms for the identified protected resources."
      ],
      "summary": "Configure suitable DDoSDetected alarms for the identified protected resources."
    },
    "reviewed_binding": {
      "closure": {
        "cid": "aws_shield_ddos_detected_alarm"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw46._make.<locals>.evaluate:868::_EVALUATORS": {
          "aws.pci.cloudwatch.metric_alarm_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._alarm_settings"
          },
          "aws.pci.cloudwatch.resource_metric_alarm": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._resource_alarm"
          },
          "aws.pci.iam.third_party_temporary_access": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._temporary_access"
          },
          "aws_cloudwatch_alarm_missing_data_realert": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._inactivity_alarm"
          },
          "aws_ec2_ai_nitro_instance_type": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._ec2_nitro"
          },
          "aws_ec2_instance_time_offset_monitored": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._ec2_time"
          },
          "aws_g6_sns_no_named_cross_account_principals": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._sns_policy"
          },
          "aws_guardduty_doh_threat_list": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_doh"
          },
          "aws_guardduty_suppression_filters": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_filters"
          },
          "aws_guardduty_threat_feed": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_feed"
          },
          "aws_guardduty_trusted_administrator": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._guardduty_admin"
          },
          "aws_nist_ec2_instance_not_publicly_accessible": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._ec2_public"
          },
          "aws_nist_sns_topic_notification_delivery_status_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._sns_delivery"
          },
          "aws_partner_role_external_id_present": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._partner_external"
          },
          "aws_shield_ddos_detected_alarm": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw46._shield_alarm"
          }
        }
      },
      "defaults": null,
      "kind": "cloudwatch_alarm",
      "module": "peaso.checks._bulk_pending_compliance_new_sw46",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw46._actions_enabled:342": "2a880f61963cf4898c5e68af57a1117ff1c56e3892539412981706136018cdac",
        "peaso.checks._bulk_pending_compliance_new_sw46._alarm_identity:318": "1a574332d9f0cd67191cdcbf104f49eebe205944661900902fccca27e9f09c78",
        "peaso.checks._bulk_pending_compliance_new_sw46._alarm_rows:306": "14065bcbdb27debb0cbb01e6e2b24548079b7e8f2a82be9c9f67a46544bbe0a6",
        "peaso.checks._bulk_pending_compliance_new_sw46._context:163": "ce8cdfe50b2c464f192bf1c0bf6758b378bea24fc143c9c82e94a432e35ab2c2",
        "peaso.checks._bulk_pending_compliance_new_sw46._dimensions:330": "b3832e421a29b4ad90a6c8cc6ef935af519f4cc716164bfde7254d639247542c",
        "peaso.checks._bulk_pending_compliance_new_sw46._items:174": "16e61710deb6df288724e7db42adf118cf428f64e20cc43b8dd1d4e305ac79f3",
        "peaso.checks._bulk_pending_compliance_new_sw46._make.<locals>.evaluate:868": "ece643fcf7b6f37ee64c32732f3b18acfd79f12d26ebdc595399679a8338ee88",
        "peaso.checks._bulk_pending_compliance_new_sw46._metric:326": "7b432966593b63e0b18ce62eba61e000ff6dc517053ed5eb782b6f01bdb3ed06",
        "peaso.checks._bulk_pending_compliance_new_sw46._number:232": "2d77364e588d5fe0c3625bd04e4fd1f0dcfb7ee2a7a7d64fff413975cba262c9",
        "peaso.checks._bulk_pending_compliance_new_sw46._scope_item:425": "ccb4998e9ef2e017dd20dd941f83c3c51df0639b838203191a4d2c7acace7cca",
        "peaso.checks._bulk_pending_compliance_new_sw46._shield_alarm:516": "647bc249b0b3f97361fd4ffeedc3422e8c2300465cd756d3a3817f8381ee2d37",
        "peaso.checks._bulk_pending_compliance_new_sw46._strings:224": "5f8b52c64fb02bb0a6105938189cbbc3a2facd31e84ae8699b61d8f56995f3e5"
      },
      "source_qualname": "_make.<locals>.evaluate"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A Shield-protected resource lacks the required enabled-action DDoSDetected alarm."
  },
  "aws_ssm_application_inventory_fresh": {
    "description_fields": {
      "description": "Joins running EC2 instances to SSM application inventory and requires every capture timestamp within the preceding 24 hours."
    },
    "remediation_fields": {
      "caveats": [
        "Inventory freshness does not prove software vulnerability assessment or full application completeness."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "existing collected instance and ssm_managed_instance plus new read-only ssm:ListInventoryEntries TypeName=AWS:Application; CaptureTime, Name, Version",
          "Complete inventories: instance, ssm_managed_instance"
        ],
        "kind": "ssm_managed_instance",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS SYSTEMS-MANAGER Inventory Result Item API",
          "url": "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_InventoryResultItem.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable or repair SSM application inventory collection for the affected running instances."
      ],
      "summary": "Enable or repair SSM application inventory collection for the affected running instances."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw36._scope:27::_ACCOUNT_REGION": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]$"
        }
      },
      "defaults": null,
      "kind": "ssm_managed_instance",
      "module": "peaso.checks._bulk_pending_compliance_new_sw36",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw36._application_entries:174": "dfb393d1d748acaba539d6a01537a85ee10d120380ab517111bb9f27b66d34f3",
        "peaso.checks._bulk_pending_compliance_new_sw36._list_fact:148": "abeaeabd79fcb2db168feb70f4d56d2bcf12f77be1a265fdee64611fe83eaeaa",
        "peaso.checks._bulk_pending_compliance_new_sw36._rows:48": "dc9eea3dc8777b8e42d22987da4b17f4915dce71a7144751ac029ff54dbf7587",
        "peaso.checks._bulk_pending_compliance_new_sw36._scope:27": "cc989afc0fe719579ed92b1f6e574ca50e30202adadcb93137bbc89d72d7bc96",
        "peaso.checks._bulk_pending_compliance_new_sw36._time:129": "18e0cd6b55832bedce6e7108ff9331281924e44ba9e43ac29f5bd0c24b54b793",
        "peaso.checks._bulk_pending_compliance_new_sw36.application_inventory_fresh:305": "d86fbadac9af75b4cba4b930eb810d449e08e467fed865ade3fa737813892292"
      },
      "source_qualname": "application_inventory_fresh"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A running instance lacks SSM application inventory or has capture times outside the 24-hour window."
  },
  "aws_vpn_tunnel_encryption_configuration": {
    "description_fields": {
      "description": "Checks available VPN tunnel encryption lists for empty/AES128/DES entries and available Client VPNs for certificate and transport declarations."
    },
    "remediation_fields": {
      "caveats": [
        "This is a narrow declared-setting profile, not negotiated cryptography, certificate trust or a live VPN test."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "ec2:DescribeVpnConnections (VpnConnectionId, State, Options.TunnelOptions[].Phase1EncryptionAlgorithms[].Value, Options.TunnelOptions[].Phase2EncryptionAlgorithms[].Value) and ec2:DescribeClientVpnEndpoints (ClientVpnEndpointId, Status.Code, ServerCertificateArn, TransportProtocol)",
          "Complete inventories: vpn_connection, client_vpn_endpoint"
        ],
        "kind": "vpn_connection",
        "target": "scope"
      },
      "references": [
        {
          "title": "AWS EC2 Tunnel Option API",
          "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TunnelOption.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Remove disallowed tunnel algorithms or correct missing Client VPN certificate/transport settings where this profile is required."
      ],
      "summary": "Remove disallowed tunnel algorithms or correct missing Client VPN certificate/transport settings where this profile is required."
    },
    "reviewed_binding": {
      "closure": {
        "identifier": "aws_vpn_tunnel_encryption_configuration"
      },
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811::EVALUATORS": {
          "aws.nist.sc_36_coverage": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._recovery"
          },
          "aws.pci.classic_elb.custom_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.classic_elb.predefined_ssl_policy": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48.<lambda>"
          },
          "aws.pci.redshift.expected_settings": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._redshift"
          },
          "aws.pci.secretsmanager.kms_encryption_any": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._kms"
          },
          "aws_autoscaling_userdata_plaintext_aws_key": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._userdata"
          },
          "aws_ecr_repository_lifecycle_retention": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecr"
          },
          "aws_g6_ecs_fargate_storage_encryption": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._ecs"
          },
          "aws_nist_cloudformation_stack_drift_detection_check": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._drift"
          },
          "aws_nist_config_enabled_all_regions": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._config"
          },
          "aws_nist_rds_db_instance_and_cluster_enhanced_monitoring_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rds"
          },
          "aws_nist_secretsmanager_secret_automatic_rotation_enabled": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._rotation"
          },
          "aws_organizations_environment_account_separation": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._separation"
          },
          "aws_sagemaker_model_clarify_bias_job": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._clarify"
          },
          "aws_vpn_tunnel_encryption_configuration": {
            "callable": "peaso.checks._bulk_pending_compliance_new_sw48._vpn"
          }
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_ARN": {
          "flags": 32,
          "regex": "^arn:aws(?:-[a-z0-9-]+)?:[^:]+:[a-z0-9-]*:[0-9]{12}:.+$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34::_SCOPE": {
          "flags": 32,
          "regex": "^[0-9]{12}/[a-z0-9-]+$"
        }
      },
      "defaults": null,
      "kind": "vpn_connection",
      "module": "peaso.checks._bulk_pending_compliance_new_sw48",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw48._install.<locals>.check:811": "ae35cf3acf73d2d9b595a8f64672eba95725a8530d896346dfb770b772644588",
        "peaso.checks._bulk_pending_compliance_new_sw48._inventory:34": "28c7fa38621503a88a0564acb5b0abd82e7036874d3c1edd271d85c2aecb2d9e",
        "peaso.checks._bulk_pending_compliance_new_sw48._vpn:410": "ec5d7b228ae34d875eb8bbd4e822af1ce6d39140f59256129be1bd4b6db06a0a"
      },
      "source_qualname": "_install.<locals>.check"
    },
    "reviewed_severity": "medium",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An available VPN has tunnel algorithms or client settings rejected by this profile."
  },
  "aws_wafv2_rate_rule_alarm": {
    "description_fields": {
      "description": "Checks top-level rate-based rules have metrics enabled and an exact ACL/rule-dimension alarm for the configured rule metric."
    },
    "remediation_fields": {
      "caveats": [
        "This source expects the rule metric name, not a universal BlockedRequests alarm; delivery and nested statements are not assessed."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "new read-only API calls wafv2:GetWebACL and cloudwatch:DescribeAlarms; RateBasedStatement, MetricName, AlarmActions",
          "Complete inventories: wafv2_web_acl, cloudwatch_alarm"
        ],
        "kind": "wafv2_web_acl",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS WAF Rule API",
          "url": "https://docs.aws.amazon.com/waf/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Enable required rule metrics and configure the matching alarm if rate-rule notifications are needed."
      ],
      "summary": "Enable required rule metrics and configure the matching alarm if rate-rule notifications are needed."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "wafv2_web_acl",
      "module": "peaso.checks._bulk_pending_compliance_new_sw45",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw45._alarms:247": "94551d4dc659b623ee1c17e863a468ad506e0e808e75e86845d18fd404a11949",
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199": "cd29dfee9c28637ab5a70c78802687ad8992a25ac34ed35c139869be8ca0914e",
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150": "dcbb098304c8c01130962b40e93a2cf654e0b524aacf3aea387fc3852867c066",
        "peaso.checks._bulk_pending_compliance_new_sw45._inventory:161": "96f64e73f8106c570a5764453d39e03968457d4a89f7184f75008c472c0c6228",
        "peaso.checks._bulk_pending_compliance_new_sw45._objects:210": "9d1a3637de24029d955da7eb29fa168e69a3f9d24bbbe86547038ae21ad97e81",
        "peaso.checks._bulk_pending_compliance_new_sw45._policy:226": "591e8fff859be75586e62bb088ce725b0b92814f8b334e16a3c6a2cc23d34f08",
        "peaso.checks._bulk_pending_compliance_new_sw45._waf:233": "db665ec257e9517bad8ab83d79dfe8a4ed3d662a89758712fcddfdd6987c0c6e",
        "peaso.checks._bulk_pending_compliance_new_sw45._waf_alarm:275": "cceadc63bff2f93a7ed9b91efe8aaf53dda469f0b97faf876c8907eb025fc571",
        "peaso.checks._bulk_pending_compliance_new_sw45.rate_rule_alarm:380": "a6653253b5402012541c529566c2fa4a93ec7c5a648dee73cb2cc9e9d19d2e0d"
      },
      "source_qualname": "rate_rule_alarm"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "A top-level WAF rate rule lacks enabled metrics or its matching alarm."
  },
  "aws_wafv2_request_validation_rules": {
    "description_fields": {
      "description": "Checks internet-facing ALBs for an associated ACL declaring AWSManagedRulesCommonRuleSet with no group-level override."
    },
    "remediation_fields": {
      "caveats": [
        "The rule-group marker does not validate every inner rule override or prove effective blocking."
      ],
      "cli": [],
      "field_binding": {
        "fields": [
          "elbv2:DescribeLoadBalancers (LoadBalancers[].LoadBalancerArn, Scheme) and wafv2:GetWebACLForResource/GetWebACL (WebACL.ARN, Rules[].Statement.ManagedRuleGroupStatement.VendorName/Name, Rules[].OverrideAction)",
          "Complete inventories: wafv2_web_acl, load_balancer_v2"
        ],
        "kind": "wafv2_web_acl",
        "target": "resource"
      },
      "references": [
        {
          "title": "AWS WAF Rule API",
          "url": "https://docs.aws.amazon.com/waf/latest/APIReference/API_Rule.html"
        }
      ],
      "review_status": "approved",
      "steps": [
        "Associate suitable request-validation rules with the identified public ALBs if required."
      ],
      "summary": "Associate suitable request-validation rules with the identified public ALBs if required."
    },
    "reviewed_binding": {
      "closure": {},
      "constants": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199::_ARN": {
          "flags": 32,
          "regex": "^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$"
        },
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150::_SCOPE": {
          "flags": 32,
          "regex": "^([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])$"
        }
      },
      "defaults": null,
      "kind": "wafv2_web_acl",
      "module": "peaso.checks._bulk_pending_compliance_new_sw45",
      "predicate_sources": {
        "peaso.checks._bulk_pending_compliance_new_sw45._arn:199": "cd29dfee9c28637ab5a70c78802687ad8992a25ac34ed35c139869be8ca0914e",
        "peaso.checks._bulk_pending_compliance_new_sw45._context:150": "dcbb098304c8c01130962b40e93a2cf654e0b524aacf3aea387fc3852867c066",
        "peaso.checks._bulk_pending_compliance_new_sw45._inventory:161": "96f64e73f8106c570a5764453d39e03968457d4a89f7184f75008c472c0c6228",
        "peaso.checks._bulk_pending_compliance_new_sw45._objects:210": "9d1a3637de24029d955da7eb29fa168e69a3f9d24bbbe86547038ae21ad97e81",
        "peaso.checks._bulk_pending_compliance_new_sw45._waf:233": "db665ec257e9517bad8ab83d79dfe8a4ed3d662a89758712fcddfdd6987c0c6e",
        "peaso.checks._bulk_pending_compliance_new_sw45.request_validation_rules:472": "a04daeec45cc8512d267064e3128b41ff9dc6ef08e1ea145285d984785c9069e"
      },
      "source_qualname": "request_validation_rules"
    },
    "reviewed_severity": "low",
    "reviewed_source_severity": "medium",
    "static_observed_sentence": "An internet-facing ALB lacks the required associated Common Rule Set declaration."
  }
}
''')
def _apply(check_id,original,kind):
    row=ROWS.get(check_id)
    if row is None:return deepcopy(original)
    updated=deepcopy(original) if isinstance(original,dict) else {}
    updated.update(deepcopy(row[kind+"_fields"]))
    return updated
def description(check_id,original):return _apply(check_id,original,"description")
def remediation(check_id,original):return _apply(check_id,original,"remediation")
REVIEWED_RISKS={cid:(row["reviewed_source_severity"],row["reviewed_severity"]) for cid,row in ROWS.items()}
def severity_review(check_id,source_severity):
    review=REVIEWED_RISKS.get(check_id)
    if review is None:return None
    return review[1]
