"""Individually reviewed AWS database findings; no cloud requests or mutations."""
from copy import deepcopy
import json
import re

VERSION = "aws-database-clarity-20261019"
ROWS = json.loads(r'''
{
  "aws.cb.rds.cluster_backtrack_window_positive": {
    "description_fields": {
      "description": "Checks for a positive Backtrack window on supported Aurora MySQL versions and Regions."
    },
    "remediation_fields": {
      "summary": "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster.",
      "steps": [
        "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster."
      ]
    },
    "static_observed_sentence": "Backtrack is disabled: its window is zero seconds.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_backtrack"
    }
  },
  "aws.cb.rds.aurora_backtracking_configured": {
    "description_fields": {
      "description": "Checks for a positive Backtrack window on supported Aurora MySQL versions and Regions."
    },
    "remediation_fields": {
      "summary": "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster.",
      "steps": [
        "If Backtrack is needed, restore or replace the cluster with Backtrack enabled; it cannot be enabled on an existing disabled cluster."
      ]
    },
    "static_observed_sentence": "Backtrack is disabled: its window is zero seconds.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "aurora_backtracking"
    }
  },
  "aws.cb.rds.cluster_cloudwatch_log_exports": {
    "description_fields": {
      "description": "Checks whether the cluster declares any CloudWatch log exports."
    },
    "remediation_fields": {
      "summary": "Enable the database log exports needed for investigation.",
      "steps": [
        "Enable the database log exports needed for investigation."
      ],
      "caveats": [
        "Export settings do not demonstrate log delivery or database audit settings.",
        "Other engines are NOT_APPLICABLE; one declared export passes this exact predicate, not proof that audit/error logs are complete or delivered. Export changes can expose SQL or user data and add log ingestion charges."
      ]
    },
    "static_observed_sentence": "The cluster declares no CloudWatch log exports.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_cw"
    }
  },
  "aws.cb.rds.cluster_log_exports_declared": {
    "description_fields": {
      "description": "Checks whether the cluster declares any CloudWatch log exports."
    },
    "remediation_fields": {
      "summary": "Enable the database log exports needed for investigation.",
      "steps": [
        "Enable the database log exports needed for investigation."
      ],
      "caveats": [
        "Export settings do not demonstrate log delivery or database audit settings.",
        "This check is the cluster half of a source UNION labeled enhanced monitoring, but it evaluates log exports only; enabling OS Enhanced Monitoring alone does not clear it. Nonempty exports do not prove event delivery or retention."
      ]
    },
    "static_observed_sentence": "The cluster declares no CloudWatch log exports.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_exports"
    }
  },
  "aws.cb.rds.multi_az_cluster_minor_upgrade": {
    "description_fields": {
      "description": "Checks AutoMinorVersionUpgrade on applicable Multi-AZ DB clusters."
    },
    "remediation_fields": {
      "summary": "Enable automatic minor upgrades after checking maintenance and application compatibility.",
      "steps": [
        "Enable automatic minor upgrades after checking maintenance and application compatibility."
      ]
    },
    "static_observed_sentence": "Automatic minor version upgrades are disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_minor"
    }
  },
  "aws.cb.rds.cluster_engine_default_port_prowler": {
    "description_fields": {
      "description": "Compares the database port with this profile\u2019s engine-default port map."
    },
    "remediation_fields": {
      "summary": "Keep the default port if required; restrict database access to the necessary networks and identities.",
      "steps": [
        "Keep the default port if required; restrict database access to the necessary networks and identities."
      ],
      "caveats": [
        "A nondefault port does not restrict access or replace authentication.",
        "DocumentDB is not applicable. The source uses a substring engine/default-port map including Db2; a non-default port does not prevent discovery or authorize clients. Port changes can cause downtime and application failures, so no generic modification flag is offered without engine and deployment review."
      ]
    },
    "static_observed_sentence": "The database uses its engine\u2019s default port.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "_port.<locals>.evaluate"
    }
  },
  "aws.cb.rds.instance_engine_default_port_prowler": {
    "description_fields": {
      "description": "Compares the database port with this profile\u2019s engine-default port map."
    },
    "remediation_fields": {
      "summary": "Keep the default port if required; restrict database access to the necessary networks and identities.",
      "steps": [
        "Keep the default port if required; restrict database access to the necessary networks and identities."
      ],
      "caveats": [
        "A nondefault port does not restrict access or replace authentication.",
        "DocumentDB is not applicable. The source uses a substring engine/default-port map including Db2; a non-default port does not prevent discovery or authorize clients. Port changes can cause downtime and application failures, so no generic modification flag is offered without engine and deployment review."
      ]
    },
    "static_observed_sentence": "The database uses its engine\u2019s default port.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_port.<locals>.evaluate"
    }
  },
  "aws.cb.rds.cluster_in_backup_plan_selection": {
    "description_fields": {
      "description": "Matches the database ARN against AWS Backup selection ARNs and supported wildcards."
    },
    "remediation_fields": {
      "summary": "Add this database to an appropriate AWS Backup plan if it should be covered.",
      "steps": [
        "Add this database to an appropriate AWS Backup plan if it should be covered."
      ],
      "caveats": [
        "Selection membership does not prove successful backups or restoration.",
        "DocumentDB is not applicable. The source accepts exact cluster ARN, a broad partition cluster wildcard or *; selection presence does not prove a successful backup or restore. Avoid broad * solely to clear the finding."
      ]
    },
    "static_observed_sentence": "No AWS Backup selection matches this database ARN.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_selected"
    }
  },
  "aws.cb.rds.instance_in_backup_plan_selection": {
    "description_fields": {
      "description": "Matches the database ARN against AWS Backup selection ARNs and supported wildcards."
    },
    "remediation_fields": {
      "summary": "Add this database to an appropriate AWS Backup plan if it should be covered.",
      "steps": [
        "Add this database to an appropriate AWS Backup plan if it should be covered."
      ],
      "caveats": [
        "Selection membership does not prove successful backups or restoration.",
        "Aurora and DocumentDB instances are not applicable. Selection presence is only policy intent; it does not prove recovery points or successful restore, and a broad * could protect unintended resources."
      ]
    },
    "static_observed_sentence": "No AWS Backup selection matches this database ARN.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_selected"
    }
  },
  "aws.cb.rds.aurora_cluster_protected_resource": {
    "description_fields": {
      "description": "Looks for the database ARN and its resource type in AWS Backup protected resources."
    },
    "remediation_fields": {
      "summary": "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database.",
      "steps": [
        "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database."
      ],
      "caveats": [
        "A protected-resource record is not a restore test or proof of current backup freshness.",
        "The source checks a protected-resource record, which AWS can retain regardless of recovery point status. It does not prove the latest point is valid or restorable; non-Aurora engines are not applicable."
      ]
    },
    "static_observed_sentence": "AWS Backup has no matching protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "aurora_protected"
    }
  },
  "aws.cb.rds.instance_protected_resource": {
    "description_fields": {
      "description": "Looks for the database ARN and its resource type in AWS Backup protected resources."
    },
    "remediation_fields": {
      "summary": "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database.",
      "steps": [
        "Check backup coverage and investigate why AWS Backup has no protected-resource record for this database."
      ],
      "caveats": [
        "A protected-resource record is not a restore test or proof of current backup freshness.",
        "The record is evidence of a historical AWS Backup recovery point regardless of status; it does not prove the most recent job completed or restore works. A backup plan selection alone does not satisfy this row."
      ]
    },
    "static_observed_sentence": "AWS Backup has no matching protected-resource record.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_protected"
    }
  },
  "aws.cb.rds.instance_in_backup_selection_or_tag": {
    "description_fields": {
      "description": "Matches the instance ARN or exact tag key and value against collected AWS Backup selections."
    },
    "remediation_fields": {
      "summary": "Verify the database\u2019s effective backup selection and tag conditions, then add coverage if needed.",
      "steps": [
        "Verify the database\u2019s effective backup selection and tag conditions, then add coverage if needed."
      ],
      "caveats": [
        "Tag conditions require an exact key and value; unsupported exclusions or conditions remain unknown.",
        "A matching selection does not prove that a backup completed or that recovery works."
      ]
    },
    "static_observed_sentence": "Neither the database ARN nor an exact tag key and value matches a collected backup selection.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_in_plan"
    }
  },
  "aws.cb.rds.aurora_postgres_postgresql_log_export": {
    "description_fields": {
      "description": "Checks whether Aurora PostgreSQL declares the postgresql CloudWatch log export."
    },
    "remediation_fields": {
      "summary": "Enable the postgresql log export.",
      "steps": [
        "Enable the postgresql log export."
      ],
      "caveats": [
        "An export declaration does not demonstrate log delivery.",
        "Other engines are NOT_APPLICABLE. A declared postgresql export does not by itself ensure useful server logging or that a CloudWatch log group has correct access and retention."
      ]
    },
    "static_observed_sentence": "The postgresql log export is not configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "aurora_pg_logs"
    }
  },
  "aws.cb.rds.instance_enhanced_monitoring_except_m1_small": {
    "description_fields": {
      "description": "Checks EnhancedMonitoringResourceArn; db.m1.small is excluded."
    },
    "remediation_fields": {
      "summary": "Configure Enhanced Monitoring if operating-system metrics are required.",
      "steps": [
        "Configure Enhanced Monitoring if operating-system metrics are required."
      ],
      "caveats": [
        "This checks the resource ARN, not monitoring frequency or metric delivery.",
        "db.m1.small is NOT_APPLICABLE under this source. EnhancedMonitoringResourceArn presence alone does not prove current metric delivery, correct retention or a safe monitoring role.",
        "Enabling monitoring grants an IAM role to the service and can add CloudWatch Logs charges. The role name, ARN and interval are operator-reviewed placeholders; do not create or broaden a role from this finding."
      ]
    },
    "static_observed_sentence": "The instance has no Enhanced Monitoring resource ARN.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_em"
    }
  },
  "aws.cb.rds.cluster_tls_parameters": {
    "description_fields": {
      "description": "Checks the engine-appropriate cluster parameter: rds.force_ssl=1 or require_secure_transport=ON/1."
    },
    "remediation_fields": {
      "summary": "Enable the engine\u2019s TLS-enforcement parameter and update clients before applying any required restart.",
      "steps": [
        "Enable the engine\u2019s TLS-enforcement parameter and update clients before applying any required restart."
      ],
      "caveats": [
        "Parameter configuration is checked; no TLS handshake is performed.",
        "DocumentDB is NOT_APPLICABLE. The evaluator accepts either parameter independent of engine; the owner must choose the setting supported by the actual engine, not set both blindly. A configured parameter alone does not prove all clients use TLS."
      ]
    },
    "static_observed_sentence": "The engine\u2019s collected TLS-enforcement parameter is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_cluster",
      "predicate_qualname": "cluster_tls"
    }
  },
  "aws.cb.rds.postgres_force_ssl_parameter": {
    "description_fields": {
      "description": "Checks whether the applicable engine parameter rds.force_ssl is 1."
    },
    "remediation_fields": {
      "summary": "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change.",
      "steps": [
        "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change."
      ],
      "caveats": [
        "The parameter value is checked; no network handshake is performed.",
        "The generated PostgreSQL source also names literal Engine=sqlserver, but RDS SQL Server engines use sqlserver-*; this row applies to PostgreSQL in practice. A parameter value alone does not prove connection behavior or client certificate verification; a shared group change can affect other instances."
      ]
    },
    "static_observed_sentence": "The collected rds.force_ssl parameter does not enforce TLS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_param_check.<locals>.evaluate"
    }
  },
  "aws.cb.rds.mariadb_require_secure_transport": {
    "description_fields": {
      "description": "Checks whether the applicable engine parameter require_secure_transport is ON or 1."
    },
    "remediation_fields": {
      "summary": "Set require_secure_transport to ON or 1 and verify client TLS compatibility before applying the change.",
      "steps": [
        "Set require_secure_transport to ON or 1 and verify client TLS compatibility before applying the change."
      ],
      "caveats": [
        "MariaDB applies only from version 10.5; no network handshake is performed.",
        "MariaDB before 10.5 does not support this parameter and is NOT_APPLICABLE. An absent or malformed version/value is UNKNOWN, not a finding that can be cleared by applying a guessed setting.",
        "This check verifies the collected parameter value, not a negotiated TLS session or client certificate verification. A shared group affects other instances; a client unable to establish encrypted transport can lose access."
      ]
    },
    "static_observed_sentence": "The collected require_secure_transport parameter does not enforce TLS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_param_check.<locals>.evaluate"
    }
  },
  "aws.cb.rds.sqlserver_force_ssl_parameter": {
    "description_fields": {
      "description": "Checks whether the applicable engine parameter rds.force_ssl is 1."
    },
    "remediation_fields": {
      "summary": "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change.",
      "steps": [
        "Set rds.force_ssl to 1 and verify client TLS compatibility before applying the change."
      ],
      "caveats": [
        "The parameter value is checked; no network handshake is performed.",
        "Only Engine names beginning sqlserver are applicable. A parameter value alone does not prove connection behavior or client certificate verification; a shared group change can affect other instances."
      ]
    },
    "static_observed_sentence": "The collected rds.force_ssl parameter does not enforce TLS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_param_check.<locals>.evaluate"
    }
  },
  "aws.cb.rds.mariadb_log_exports": {
    "description_fields": {
      "description": "Checks whether the applicable database exports audit, error, general and slowquery logs."
    },
    "remediation_fields": {
      "summary": "Enable the missing audit, error, general and slowquery log exports needed for investigation.",
      "steps": [
        "Enable the missing audit, error, general and slowquery log exports needed for investigation."
      ],
      "caveats": [
        "Export declarations do not demonstrate log contents or delivery.",
        "Only the mariadb engine family is applicable. This check compares declared types, not actual delivery, useful logging parameters or CloudWatch retention."
      ]
    },
    "static_observed_sentence": "The database does not export all required audit, error, general and slowquery logs.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_logs.<locals>.evaluate"
    }
  },
  "aws.cb.rds.postgres_log_exports": {
    "description_fields": {
      "description": "Checks whether the applicable database exports postgresql and upgrade logs."
    },
    "remediation_fields": {
      "summary": "Enable the missing postgresql and upgrade log exports needed for investigation.",
      "steps": [
        "Enable the missing postgresql and upgrade log exports needed for investigation."
      ],
      "caveats": [
        "Export declarations do not demonstrate log contents or delivery.",
        "Only the postgres engine family is applicable. This check compares declared types, not actual delivery, useful logging parameters or CloudWatch retention."
      ]
    },
    "static_observed_sentence": "The database does not export all required postgresql and upgrade logs.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_logs.<locals>.evaluate"
    }
  },
  "aws.cb.rds.sqlserver_error_log_export": {
    "description_fields": {
      "description": "Checks whether the applicable database exports error logs."
    },
    "remediation_fields": {
      "summary": "Enable the missing error log exports needed for investigation.",
      "steps": [
        "Enable the missing error log exports needed for investigation."
      ],
      "caveats": [
        "Export declarations do not demonstrate log contents or delivery.",
        "Only the sqlserver-ee engine family is applicable. This check compares declared types, not actual delivery, useful logging parameters or CloudWatch retention."
      ]
    },
    "static_observed_sentence": "The database does not export all required error logs.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_logs.<locals>.evaluate"
    }
  },
  "aws.cb.rds.aurora_postgres_local_file_read_versions": {
    "description_fields": {
      "description": "Matches EngineVersion against the profile\u2019s affected versions: 10.11\u201310.13 and 11.6\u201311.8."
    },
    "remediation_fields": {
      "summary": "Upgrade to a supported release after checking compatibility and the relevant security advisory.",
      "steps": [
        "Upgrade to a supported release after checking compatibility and the relevant security advisory."
      ],
      "caveats": [
        "A version outside this finite list is not a general vulnerability assessment.",
        "The upstream label says DB cluster, but this native evaluator reads rds_instance rows; Aurora engine upgrades are cluster operations. A nonmatching EngineVersion is not proof of current patching. Major upgrades may require application changes and downtime."
      ]
    },
    "static_observed_sentence": "The database version matches this profile\u2019s known affected-version list.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_vuln.<locals>.evaluate"
    }
  },
  "aws.cb.rds.postgres_local_file_read_versions": {
    "description_fields": {
      "description": "Matches EngineVersion against the profile\u2019s affected versions: 10.11\u201310.13 and 11.6\u201311.8."
    },
    "remediation_fields": {
      "summary": "Upgrade to a supported release after checking compatibility and the relevant security advisory.",
      "steps": [
        "Upgrade to a supported release after checking compatibility and the relevant security advisory."
      ],
      "caveats": [
        "A version outside this finite list is not a general vulnerability assessment.",
        "The predicate is exact string equality against six historic versions, not a general vulnerability feed or support-policy check. A nonmatching EngineVersion is not proof of current patching. Major upgrades may require application changes and downtime."
      ]
    },
    "static_observed_sentence": "The database version matches this profile\u2019s known affected-version list.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "_vuln.<locals>.evaluate"
    }
  },
  "aws.cb.rds.instance_backup_retention_nonzero_all": {
    "description_fields": {
      "description": "Checks whether automated backup retention is at least one day."
    },
    "remediation_fields": {
      "summary": "Configure an automated backup retention period suitable for recovery.",
      "steps": [
        "Configure an automated backup retention period suitable for recovery."
      ]
    },
    "static_observed_sentence": "Automated backup retention is zero days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_backup"
    }
  },
  "aws.cb.rds.instance_copy_tags_all_engines": {
    "description_fields": {
      "description": "Checks CopyTagsToSnapshot on the instance."
    },
    "remediation_fields": {
      "summary": "Enable copying tags to snapshots if these tags are needed for ownership or lifecycle management.",
      "steps": [
        "Enable copying tags to snapshots if these tags are needed for ownership or lifecycle management."
      ]
    },
    "static_observed_sentence": "Copying instance tags to snapshots is disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_copy_tags"
    }
  },
  "aws.cb.rds.instance_iam_auth_supported_engines": {
    "description_fields": {
      "description": "Checks IAM database authentication on MySQL, MariaDB and PostgreSQL instances."
    },
    "remediation_fields": {
      "summary": "Consider enabling IAM database authentication if it suits the application\u2019s connection model.",
      "steps": [
        "Consider enabling IAM database authentication if it suits the application\u2019s connection model."
      ],
      "caveats": [
        "This is an authentication-option preference; it does not prove that existing database credentials are weak.",
        "Unsupported engines are not applicable here. Enabling IAM authentication does not automatically create database users or change existing password logins; cluster members require the cluster-level operation. Token expiry and connection pooling need application review."
      ]
    },
    "static_observed_sentence": "IAM database authentication is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_iam_supported"
    }
  },
  "aws.cb.rds.instance_default_master_username": {
    "description_fields": {
      "description": "Checks whether the instance or resolved cluster uses master username admin or postgres."
    },
    "remediation_fields": {
      "summary": "Review master-account use and restrict its access; a familiar username alone does not justify database replacement.",
      "steps": [
        "Review master-account use and restrict its access; a familiar username alone does not justify database replacement."
      ],
      "caveats": [
        "A default username does not demonstrate a default or compromised password.",
        "MasterUsername cannot be changed on an existing RDS instance or cluster through a simple modify flag; a new deployment and data migration are required. A missing cluster join fails this source even when the actual username may be safe; confirm inventory completeness first."
      ]
    },
    "static_observed_sentence": "The master username matches this profile\u2019s default-name list.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_admin"
    }
  },
  "aws.cb.rds.instance_multi_az_or_cluster": {
    "description_fields": {
      "description": "Checks MultiAZ on the applicable instance or its resolved parent cluster."
    },
    "remediation_fields": {
      "summary": "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage.",
      "steps": [
        "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage."
      ],
      "caveats": [
        "A zonal availability preference; not evidence of unauthorized access.",
        "DocumentDB is not applicable. A missing referenced cluster fails until inventory is resolved; blindly modifying the instance may not fix a cluster-level MultiAZ value. Multi-AZ can increase cost and change failover behavior."
      ]
    },
    "static_observed_sentence": "Multi-AZ is not enabled in the evaluated database configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_multi"
    }
  },
  "aws.cb.rds.instance_multi_az_non_aurora": {
    "description_fields": {
      "description": "Checks MultiAZ on the applicable instance or its resolved parent cluster."
    },
    "remediation_fields": {
      "summary": "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage.",
      "steps": [
        "Enable Multi-AZ if the workload requires resilience to an Availability Zone outage."
      ],
      "caveats": [
        "A zonal availability preference; not evidence of unauthorized access.",
        "Aurora engines are not applicable to this branch. Multi-AZ adds a standby and can cause a brief outage during conversion or failover; it does not replace backups or cross-Region recovery."
      ]
    },
    "static_observed_sentence": "Multi-AZ is not enabled in the evaluated database configuration.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_multi_c"
    }
  },
  "aws.cb.rds.instance_extended_support": {
    "description_fields": {
      "description": "Checks whether EngineLifecycleSupport selects open-source-rds-extended-support."
    },
    "remediation_fields": {
      "summary": "Plan a compatible upgrade if Extended Support is no longer needed.",
      "steps": [
        "Plan a compatible upgrade if Extended Support is no longer needed."
      ],
      "caveats": [
        "Extended Support enrollment does not mean that security patches are unavailable.",
        "Extended Support keeps older open-source engines available for a fee; disabling it before a supported upgrade can be rejected or disrupt availability. The source only checks the string value, not whether a future major version is operationally compatible."
      ]
    },
    "static_observed_sentence": "The database is enrolled in RDS Extended Support.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_extended"
    }
  },
  "aws.cb.rds.ca_certificate_valid_3_months": {
    "description_fields": {
      "description": "Compares the joined CA certificate expiry with collection time plus three calendar months."
    },
    "remediation_fields": {
      "summary": "Plan a CA rotation and update client trust stores before expiry.",
      "steps": [
        "Plan a CA rotation and update client trust stores before expiry."
      ],
      "caveats": [
        "This evaluates the CA metadata, not the leaf certificate served by the database endpoint.",
        "DocumentDB is not applicable. The source joins CACertificateIdentifier to one collected rds_certificate and returns UNKNOWN if unresolved; exactly three calendar months remaining still fails. Client trust stores must be updated before rotation. Some engine versions support rotation without restart while others need a restart; do not assume either behavior without checking the instance capabilities."
      ]
    },
    "static_observed_sentence": "The collected RDS CA certificate expires within the required window or has expired.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "ca_three_months"
    }
  },
  "aws.cb.rds.ca_certificate_not_expiring_7_days": {
    "description_fields": {
      "description": "Compares the joined CA certificate expiry with collection time plus seven days."
    },
    "remediation_fields": {
      "summary": "Plan a CA rotation and update client trust stores before expiry.",
      "steps": [
        "Plan a CA rotation and update client trust stores before expiry."
      ],
      "caveats": [
        "This evaluates the CA metadata, not the leaf certificate served by the database endpoint.",
        "This check includes every engine and truncates the day component of the expiry delta; a certificate close to eight days can enter the seven-day band. Missing certificate join is UNKNOWN, not proof of expiry. Some engine versions support rotation without restart while others need a restart; do not assume either behavior without checking the instance capabilities."
      ]
    },
    "static_observed_sentence": "The collected RDS CA certificate expires within the required window or has expired.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "ca_seven"
    }
  },
  "aws.cb.rds.engine_version_available": {
    "description_fields": {
      "description": "Looks for the database\u2019s exact engine/version pair in collected RDS engine-version inventory."
    },
    "remediation_fields": {
      "summary": "Review the engine\u2019s support status and plan a supported compatible upgrade if needed.",
      "steps": [
        "Review the engine\u2019s support status and plan a supported compatible upgrade if needed."
      ],
      "caveats": [
        "Being offered by the API is not proof that an engine version has no vulnerabilities.",
        "DocumentDB is not applicable. Absence from offered versions does not identify an automatically safe target or prove the engine is exploitable; a major upgrade may require intermediate versions and downtime."
      ]
    },
    "static_observed_sentence": "The engine/version pair is absent from collected RDS engine-version inventory.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "engine_version"
    }
  },
  "aws.cb.rds.instance_internet_exposed": {
    "description_fields": {
      "description": "Combines PubliclyAccessible, active security-group access to the TCP endpoint port and a DB subnet\u2019s Internet-gateway default route."
    },
    "remediation_fields": {
      "summary": "Remove Internet-wide ingress to the database port; retain only the networks that need database access.",
      "steps": [
        "Remove Internet-wide ingress to the database port; retain only the networks that need database access."
      ],
      "caveats": [
        "This is a configuration-path model; no connection or authentication attempt is made.",
        "DocumentDB is not applicable. This native conjunction can pass a publicly accessible instance when no matching open SG or public subnet is collected; that PASS is not a blanket internet-exposure guarantee. Disabling public access before clients migrate can cause an outage."
      ]
    },
    "static_observed_sentence": "The declared public database configuration includes Internet-wide ingress to its endpoint port.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_instance",
      "predicate_qualname": "instance_exposed"
    }
  },
  "aws.cb.rds.instance_snapshot_restore_not_all_exact": {
    "description_fields": {
      "description": "Checks whether the snapshot\u2019s restore attribute includes the public principal all."
    },
    "remediation_fields": {
      "summary": "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access.",
      "steps": [
        "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access."
      ]
    },
    "static_observed_sentence": "The snapshot restore attribute permits public access.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_snapshot",
      "predicate_qualname": "_snapshots.<locals>.exact"
    }
  },
  "aws.cb.rds.instance_snapshot_not_public_prowler": {
    "description_fields": {
      "description": "Checks whether any collected snapshot attribute contains the public value all."
    },
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot attributes."
      ],
      "caveats": [
        "This profile inspects every attribute, rather than only the restore attribute.",
        "DocumentDB snapshots are not applicable. This branch detects all even when other account IDs share the same list; removing all preserves named shares but still needs consumer review."
      ]
    },
    "static_observed_sentence": "A snapshot attribute contains the public sharing value all.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_snapshot",
      "predicate_qualname": "_snapshots.<locals>.prowler_public"
    }
  },
  "aws.cb.rds.instance_snapshot_shared_accounts_review": {
    "description_fields": {
      "description": "Lists snapshot share accounts for manual trust review; no automatic failing verdict is defined."
    },
    "remediation_fields": {
      "summary": "Review snapshot sharing only through an explicitly configured organizational approval process.",
      "steps": [
        "Review snapshot sharing only through an explicitly configured organizational approval process."
      ],
      "caveats": [
        "Archived: deciding whether another account is trusted requires a customer-approved list.",
        "This native branch returns MANUAL for any share value and PASS only for no values; it cannot decide whether a named recipient account is trusted. Do not remove an approved recovery share solely to obtain PASS."
      ]
    },
    "static_observed_sentence": "The snapshot is shared with another account.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_snapshot",
      "predicate_qualname": "_snapshots.<locals>.shared"
    }
  },
  "aws.cb.rds.cluster_snapshot_restore_not_all_exact": {
    "description_fields": {
      "description": "Checks whether the snapshot\u2019s restore attribute includes the public principal all."
    },
    "remediation_fields": {
      "summary": "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access.",
      "steps": [
        "Remove all from the snapshot\u2019s restore attribute; retain only the account IDs that need access."
      ]
    },
    "static_observed_sentence": "The snapshot restore attribute permits public access.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "_snapshots.<locals>.exact"
    }
  },
  "aws.cb.rds.cluster_snapshot_not_public_prowler": {
    "description_fields": {
      "description": "Checks whether any collected snapshot attribute contains the public value all."
    },
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot attributes."
      ],
      "caveats": [
        "This profile inspects every attribute, rather than only the restore attribute.",
        "DocumentDB snapshots are not applicable. This branch detects all even when other account IDs share the same list; removing all preserves named shares but still needs consumer review."
      ]
    },
    "static_observed_sentence": "A snapshot attribute contains the public sharing value all.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "_snapshots.<locals>.prowler_public"
    }
  },
  "aws.cb.rds.cluster_snapshot_shared_accounts_review": {
    "description_fields": {
      "description": "Lists snapshot share accounts for manual trust review; no automatic failing verdict is defined."
    },
    "remediation_fields": {
      "summary": "Review snapshot sharing only through an explicitly configured organizational approval process.",
      "steps": [
        "Review snapshot sharing only through an explicitly configured organizational approval process."
      ],
      "caveats": [
        "Archived: deciding whether another account is trusted requires a customer-approved list.",
        "This native branch returns MANUAL for any share value and PASS only for no values; it cannot decide whether a named recipient account is trusted. Do not remove an approved recovery share solely to obtain PASS."
      ]
    },
    "static_observed_sentence": "The snapshot is shared with another account.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "_snapshots.<locals>.shared"
    }
  },
  "aws.cb.rds.cluster_snapshot_encrypted": {
    "description_fields": {
      "description": "Checks StorageEncrypted on non-DocumentDB cluster snapshots."
    },
    "remediation_fields": {
      "summary": "Create and verify an encrypted snapshot copy before removing any unencrypted recovery copy.",
      "steps": [
        "Create and verify an encrypted snapshot copy before removing any unencrypted recovery copy."
      ],
      "caveats": [
        "Keep a recoverable copy until the encrypted replacement has been verified.",
        "Snapshot encryption is immutable for the existing snapshot; copying creates a new resource and does not convert the original finding. DocumentDB is not applicable. Deleting the old copy before KMS and restore validation can destroy recovery capability."
      ]
    },
    "static_observed_sentence": "The cluster snapshot is not encrypted.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "csnap_encrypted"
    }
  },
  "aws.cb.rds.cluster_critical_event_subscription": {
    "description_fields": {
      "description": "Looks for an enabled regional db-cluster subscription covering failure and maintenance."
    },
    "remediation_fields": {
      "summary": "Configure an enabled db-cluster event subscription for failure and maintenance and its notification destination.",
      "steps": [
        "Configure an enabled db-cluster event subscription for failure and maintenance and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-cluster subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_cluster resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-cluster subscription covers the required event categories.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate"
    }
  },
  "aws.cb.rds.instance_critical_event_subscription": {
    "description_fields": {
      "description": "Looks for an enabled regional db-instance subscription covering configuration change, failure and maintenance."
    },
    "remediation_fields": {
      "summary": "Configure an enabled db-instance event subscription for configuration change, failure and maintenance and its notification destination.",
      "steps": [
        "Configure an enabled db-instance event subscription for configuration change, failure and maintenance and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-instance subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_instance resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-instance subscription covers the required event categories.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate"
    }
  },
  "aws.cb.rds.parameter_group_critical_event_subscription": {
    "description_fields": {
      "description": "Looks for an enabled regional db-parameter-group subscription covering configuration change."
    },
    "remediation_fields": {
      "summary": "Configure an enabled db-parameter-group event subscription for configuration change and its notification destination.",
      "steps": [
        "Configure an enabled db-parameter-group event subscription for configuration change and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-parameter-group subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_instance resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-parameter-group subscription covers the required event categories.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate"
    }
  },
  "aws.cb.rds.security_group_critical_event_subscription": {
    "description_fields": {
      "description": "Looks for an enabled regional db-security-group subscription covering configuration change and failure."
    },
    "remediation_fields": {
      "summary": "Configure an enabled db-security-group event subscription for configuration change and failure and its notification destination.",
      "steps": [
        "Configure an enabled db-security-group event subscription for configuration change and failure and its notification destination."
      ],
      "caveats": [
        "Subscription configuration does not demonstrate notification delivery or timely response.",
        "The native regional predicate accepts any one enabled db-security-group subscription whose category list is empty or includes the required set, regardless of whether SourceIds include every database or SNS delivery works. A Region without rds_instance resources is not applicable; verify resource coverage and delivery operationally."
      ]
    },
    "static_observed_sentence": "No enabled regional db-security-group subscription covers the required event categories.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "rds_event_subscription",
      "predicate_qualname": "_subscription.<locals>.evaluate"
    }
  },
  "aws.cb.neptune.backup_retention_7_days": {
    "description_fields": {
      "description": "Checks whether Neptune backup retention is at least seven days."
    },
    "remediation_fields": {
      "summary": "Set backup retention to at least seven days if it meets the workload\u2019s recovery needs.",
      "steps": [
        "Set backup retention to at least seven days if it meets the workload\u2019s recovery needs."
      ]
    },
    "static_observed_sentence": "Neptune backup retention is below seven days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "nep_backup"
    }
  },
  "aws.cb.neptune.audit_log_export": {
    "description_fields": {
      "description": "Checks whether the Neptune cluster declares the audit CloudWatch log export."
    },
    "remediation_fields": {
      "summary": "Enable the audit log export and the corresponding database audit setting.",
      "steps": [
        "Enable the audit log export and the corresponding database audit setting."
      ],
      "caveats": [
        "The predicate checks the export declaration only, not audit generation or delivery.",
        "Other DB cluster engines are not applicable. The check sees only the export list; audit events also require neptune_enable_audit_log and a working log group. A shared parameter group change may affect other clusters or require a reboot."
      ]
    },
    "static_observed_sentence": "The Neptune audit log export is not configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "nep_audit"
    }
  },
  "aws.cb.neptune.snapshot_encrypted": {
    "description_fields": {
      "description": "Checks StorageEncrypted on Neptune cluster snapshots."
    },
    "remediation_fields": {
      "summary": "Create and verify an encrypted snapshot copy before removing an unencrypted recovery copy.",
      "steps": [
        "Create and verify an encrypted snapshot copy before removing an unencrypted recovery copy."
      ]
    },
    "static_observed_sentence": "The Neptune snapshot is not encrypted.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "nep_snap_enc"
    }
  },
  "aws.cb.neptune.snapshot_not_public_prowler": {
    "description_fields": {
      "description": "Checks whether any Neptune snapshot attribute includes all."
    },
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot\u2019s restore attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot\u2019s restore attributes."
      ]
    },
    "static_observed_sentence": "A Neptune snapshot attribute includes the public value all.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "nep_snap_public"
    }
  },
  "aws.cb.neptune.snapshot_restore_not_all_exact": {
    "description_fields": {
      "description": "Checks whether the Neptune snapshot restore attribute includes all."
    },
    "remediation_fields": {
      "summary": "Remove unintended public sharing from the snapshot\u2019s restore attributes.",
      "steps": [
        "Remove unintended public sharing from the snapshot\u2019s restore attributes."
      ]
    },
    "static_observed_sentence": "The Neptune snapshot restore attribute permits public access.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "rds_cluster_snapshot",
      "predicate_qualname": "nep_snap_exact"
    }
  },
  "aws.cb.neptune.no_public_subnet_prowler": {
    "description_fields": {
      "description": "Resolves DB subnets and their effective IPv4 default routes to an Internet gateway."
    },
    "remediation_fields": {
      "summary": "Use database subnets without an Internet-gateway default route if public routing is unnecessary.",
      "steps": [
        "Use database subnets without an Internet-gateway default route if public routing is unnecessary."
      ],
      "caveats": [
        "NAT-only egress is not public ingress; routes alone do not demonstrate database reachability.",
        "The source detects an IGW default route only; it does not prove the Neptune endpoint is publicly reachable through security groups or authentication. DBSubnetGroup is absent from ModifyDBCluster, so changing the cluster placement requires replacement and endpoint migration. An unresolved route-table join is UNKNOWN."
      ]
    },
    "static_observed_sentence": "A Neptune DB subnet has an Internet-gateway default route.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "_nep_subnet.<locals>.evaluate"
    }
  },
  "aws.cb.neptune.no_public_subnet_steampipe": {
    "description_fields": {
      "description": "Resolves DB subnets and their effective IPv4 default routes to an Internet gateway."
    },
    "remediation_fields": {
      "summary": "Use database subnets without an Internet-gateway default route if public routing is unnecessary.",
      "steps": [
        "Use database subnets without an Internet-gateway default route if public routing is unnecessary."
      ],
      "caveats": [
        "NAT-only egress is not public ingress; routes alone do not demonstrate database reachability.",
        "The source detects an IGW default route only; it does not prove the Neptune endpoint is publicly reachable through security groups or authentication. DBSubnetGroup is absent from ModifyDBCluster, so changing the cluster placement requires replacement and endpoint migration. An unresolved route-table join is UNKNOWN. The pinned Steampipe text also treated outbound NAT as public; this native check correctly tests an ingress-capable IGW route instead."
      ]
    },
    "static_observed_sentence": "A Neptune DB subnet has an Internet-gateway default route.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "neptune_cluster",
      "predicate_qualname": "_nep_subnet.<locals>.evaluate"
    }
  },
  "aws.cb.redshift.non_default_master_username": {
    "description_fields": {
      "description": "Compares MasterUsername with the profile\u2019s default name awsuser."
    },
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "ModifyCluster has no MasterUsername field; an in-place flag would be invalid. Replacement and credential migration can interrupt authentication, so no deletion or automatic cutover command is offered."
      ]
    },
    "static_observed_sentence": "MasterUsername uses the default name awsuser.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "_not_default.<locals>.evaluate"
    }
  },
  "aws.cb.redshift.non_default_database_name": {
    "description_fields": {
      "description": "Compares DBName with the profile\u2019s default name dev."
    },
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "ModifyCluster has no DBName field, so an in-place cluster setting command would be invalid. SQL-level database renames may not change the cluster metadata field this predicate reads."
      ]
    },
    "static_observed_sentence": "DBName uses the default name dev.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "_not_default.<locals>.evaluate"
    }
  },
  "aws.cb.redshiftserverless.non_default_admin_username": {
    "description_fields": {
      "description": "Compares adminUsername with the profile\u2019s default name admin."
    },
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "Changing the username can break clients and secret references; coordinate the credential rotation and connection cutover. The check compares only the literal admin and does not assess password strength or IAM access."
      ]
    },
    "static_observed_sentence": "adminUsername uses the default name admin.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshiftserverless_namespace",
      "predicate_qualname": "_ns.<locals>.evaluate"
    }
  },
  "aws.cb.redshiftserverless.non_default_database_name": {
    "description_fields": {
      "description": "Compares dbName with the profile\u2019s default name dev."
    },
    "remediation_fields": {
      "summary": "Review naming if required; prioritize access controls and strong authentication over renaming.",
      "steps": [
        "Review naming if required; prioritize access controls and strong authentication over renaming."
      ],
      "caveats": [
        "A default name is not evidence of weak credentials or unauthorized access.",
        "dbName is a CreateNamespace field but absent from UpdateNamespace; no in-place rename flag is offered for this check. Replacement can interrupt clients and incur data migration cost; a separate SQL database rename would not necessarily change the namespace dbName field."
      ]
    },
    "static_observed_sentence": "dbName uses the default name dev.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "redshiftserverless_namespace",
      "predicate_qualname": "_ns.<locals>.evaluate"
    }
  },
  "aws.cb.redshift.audit_logging": {
    "description_fields": {
      "description": "Checks the collected Redshift LoggingEnabled setting."
    },
    "remediation_fields": {
      "summary": "Enable Redshift audit logging and configure its destination.",
      "steps": [
        "Enable Redshift audit logging and configure its destination."
      ],
      "caveats": [
        "The setting does not demonstrate log delivery.",
        "The check reads LoggingStatus.LoggingEnabled only and does not prove log delivery or user-activity content. User activity events additionally require enable_user_activity_logging=true in the cluster parameter group."
      ]
    },
    "static_observed_sentence": "Redshift audit logging is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_logging"
    }
  },
  "aws.cb.redshift.encrypted_and_logging": {
    "description_fields": {
      "description": "Checks that Redshift storage encryption and audit logging are both enabled."
    },
    "remediation_fields": {
      "summary": "Enable any missing storage encryption or audit logging; plan migration before replacing storage.",
      "steps": [
        "Enable any missing storage encryption or audit logging; plan migration before replacing storage."
      ]
    },
    "static_observed_sentence": "Redshift encryption or audit logging is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_enc_logging"
    }
  },
  "aws.cb.redshift.require_ssl": {
    "description_fields": {
      "description": "Checks whether the require_ssl cluster parameter is the case-insensitive string true."
    },
    "remediation_fields": {
      "summary": "Require SSL and update clients to use TLS before applying the parameter.",
      "steps": [
        "Require SSL and update clients to use TLS before applying the parameter."
      ]
    },
    "static_observed_sentence": "The require_ssl cluster parameter is absent or not true.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_ssl"
    }
  },
  "aws.cb.redshift.has_snapshot": {
    "description_fields": {
      "description": "Looks for any collected Redshift snapshot matching the cluster identifier."
    },
    "remediation_fields": {
      "summary": "Create a recoverable snapshot and investigate missing backup coverage.",
      "steps": [
        "Create a recoverable snapshot and investigate missing backup coverage."
      ],
      "caveats": [
        "The predicate counts any matching snapshot; it does not check freshness or restore success.",
        "The evaluator counts any matching snapshot, including manual or in-progress; it does not prove a recent, completed or restorable snapshot. Automated snapshots can be deleted when retention becomes zero."
      ]
    },
    "static_observed_sentence": "No collected Redshift snapshot matches this cluster.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_snapshot"
    }
  },
  "aws.cb.redshift.snapshot_retention_7_days": {
    "description_fields": {
      "description": "Compares automated snapshot retention with seven days."
    },
    "remediation_fields": {
      "summary": "Configure at least seven days of automated snapshots if suitable for recovery.",
      "steps": [
        "Configure at least seven days of automated snapshots if suitable for recovery."
      ]
    },
    "static_observed_sentence": "Automated Redshift snapshot retention is below seven days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_retention"
    }
  },
  "aws.cb.redshift.maintenance_settings": {
    "description_fields": {
      "description": "Checks AllowVersionUpgrade and automated snapshot retention of at least seven days."
    },
    "remediation_fields": {
      "summary": "Enable version upgrades and adjust snapshot retention after reviewing maintenance and recovery needs.",
      "steps": [
        "Enable version upgrades and adjust snapshot retention after reviewing maintenance and recovery needs."
      ]
    },
    "static_observed_sentence": "Version upgrades are disabled or automated snapshot retention is below seven days.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_maint"
    }
  },
  "aws.cb.redshift.kms_key_declared": {
    "description_fields": {
      "description": "Checks that storage encryption is enabled and KmsKeyId is present."
    },
    "remediation_fields": {
      "summary": "Enable storage encryption with an appropriate KMS key; plan migration if required.",
      "steps": [
        "Enable storage encryption with an appropriate KMS key; plan migration if required."
      ]
    },
    "static_observed_sentence": "Storage encryption is disabled or no KMS key is declared.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_kms"
    }
  },
  "aws.cb.redshift.cmk_encryption": {
    "description_fields": {
      "description": "Checks storage encryption and the joined KMS key\u2019s KeyManager=CUSTOMER."
    },
    "remediation_fields": {
      "summary": "Use a customer-managed KMS key if separate key administration is required.",
      "steps": [
        "Use a customer-managed KMS key if separate key administration is required."
      ],
      "caveats": [
        "An AWS-managed key still provides encryption; key ownership is a separate requirement.",
        "The evaluator joins KMS metadata; a missing key row is unknown rather than evidence of AWS-managed encryption. The documented in-place modify flow explicitly covers enabling encryption on an unencrypted cluster; do not assume an existing encrypted cluster can switch keys with the same flag."
      ]
    },
    "static_observed_sentence": "Storage is unencrypted or its resolved key is not customer managed.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_cmk"
    }
  },
  "aws.cb.redshift.internet_exposed": {
    "description_fields": {
      "description": "Combines an endpoint, PubliclyAccessible, a public subnet and the source profile\u2019s world-address security-group ingress rule."
    },
    "remediation_fields": {
      "summary": "Restrict Internet-wide database ingress to the networks that need access.",
      "steps": [
        "Restrict Internet-wide database ingress to the networks that need access."
      ],
      "caveats": [
        "No connection is attempted; this source profile\u2019s security-group test is broader than a single endpoint-port test.",
        "This conjunctive predicate does not fail every publicly accessible cluster or every world-open rule by itself. A route-table declaration and broad rule do not prove effective reachability; shared security groups and endpoint changes can break other clients."
      ]
    },
    "static_observed_sentence": "The declared Redshift network configuration matches the profile\u2019s public-exposure path.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "critical",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_exposed"
    }
  },
  "aws.cb.redshift.security_group_port_restricted": {
    "description_fields": {
      "description": "Checks attached security groups for a world CIDR and a range covering the cluster port, default 5439."
    },
    "remediation_fields": {
      "summary": "Restrict the database port to the client networks that need it.",
      "steps": [
        "Restrict the database port to the client networks that need it."
      ],
      "caveats": [
        "This source profile counts any protocol with a matching port range; it does not prove a TCP connection.",
        "The evaluator accepts any protocol whose port range covers the endpoint port and protocol -1 without explicit ports; it does not require actual public route reachability. Shared security groups can serve other workloads, so removal needs dependency review."
      ]
    },
    "static_observed_sentence": "A security-group rule permits world-address ingress matching the database port.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshift_cluster",
      "predicate_qualname": "rs_sg"
    }
  },
  "aws.cb.redshiftserverless.connection_user_log_exports": {
    "description_fields": {
      "description": "Checks that namespace logExports contains connectionlog and userlog."
    },
    "remediation_fields": {
      "summary": "Enable connectionlog and userlog exports needed for investigation.",
      "steps": [
        "Enable connectionlog and userlog exports needed for investigation."
      ]
    },
    "static_observed_sentence": "The namespace is missing connectionlog or userlog exports.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "redshiftserverless_namespace",
      "predicate_qualname": "ns_logs"
    }
  },
  "aws.cb.redshiftserverless.require_ssl": {
    "description_fields": {
      "description": "Looks for a workgroup config parameter require_ssl with value true."
    },
    "remediation_fields": {
      "summary": "Require SSL for workgroup connections and check client compatibility.",
      "steps": [
        "Require SSL for workgroup connections and check client compatibility."
      ]
    },
    "static_observed_sentence": "The workgroup does not declare require_ssl=true.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "redshiftserverless_workgroup",
      "predicate_qualname": "wg_ssl"
    }
  },
  "aws.cb.opensearch.encryption_at_rest": {
    "description_fields": {
      "description": "Checks EncryptionAtRestOptions.Enabled on the domain."
    },
    "remediation_fields": {
      "summary": "Enable encryption at rest; plan a replacement domain if the existing deployment cannot be updated.",
      "steps": [
        "Enable encryption at rest; plan a replacement domain if the existing deployment cannot be updated."
      ]
    },
    "static_observed_sentence": "OpenSearch encryption at rest is disabled.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_enc"
    }
  },
  "aws.cb.opensearch.fine_grained_access_control": {
    "description_fields": {
      "description": "Checks AdvancedSecurityOptions.Enabled on the domain."
    },
    "remediation_fields": {
      "summary": "Enable fine-grained access control and map users to the minimum required index permissions.",
      "steps": [
        "Enable fine-grained access control and map users to the minimum required index permissions."
      ]
    },
    "static_observed_sentence": "OpenSearch fine-grained access control is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_fgac"
    }
  },
  "aws.cb.opensearch.internal_user_database_disabled": {
    "description_fields": {
      "description": "Checks the source profile\u2019s preference for disabling the internal user database."
    },
    "remediation_fields": {
      "summary": "Disable the internal user database only if an alternative authentication model is intended and working.",
      "steps": [
        "Disable the internal user database only if an alternative authentication model is intended and working."
      ],
      "caveats": [
        "Internal users are a supported authentication option; this profile conflicts with an internal-user-enabled profile.",
        "The evaluator treats an absent InternalUserDatabaseEnabled field as false; absence alone does not prove federation is working. Switching the master user can disable HTTP basic authentication without deleting internal user records."
      ]
    },
    "static_observed_sentence": "The OpenSearch internal user database is enabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_iudb"
    }
  },
  "aws.cb.opensearch.service_software_current": {
    "description_fields": {
      "description": "Checks ServiceSoftwareOptions.UpdateAvailable on the domain."
    },
    "remediation_fields": {
      "summary": "Review and schedule the available service software update.",
      "steps": [
        "Review and schedule the available service software update."
      ],
      "caveats": [
        "Availability of an update is not evidence of an actively exploited vulnerability.",
        "A service software patch differs from an engine-version upgrade. A pending request may take hours or days and can temporarily strain master capacity; the field may remain true until the deployment finishes."
      ]
    },
    "static_observed_sentence": "An OpenSearch service software update is available.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_sw"
    }
  },
  "aws.cb.opensearch.data_node_fault_tolerance": {
    "description_fields": {
      "description": "Checks for at least three data nodes and enabled zone awareness."
    },
    "remediation_fields": {
      "summary": "Use sufficient nodes and zone awareness if the workload requires zonal fault tolerance.",
      "steps": [
        "Use sufficient nodes and zone awareness if the workload requires zonal fault tolerance."
      ]
    },
    "static_observed_sentence": "The domain has fewer than three data nodes or zone awareness is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_data"
    }
  },
  "aws.cb.opensearch.dedicated_master_nodes": {
    "description_fields": {
      "description": "Checks that dedicated masters are enabled and their count is at least three."
    },
    "remediation_fields": {
      "summary": "Use at least three dedicated masters where the domain\u2019s availability requirements justify them.",
      "steps": [
        "Use at least three dedicated masters where the domain\u2019s availability requirements justify them."
      ]
    },
    "static_observed_sentence": "Dedicated masters are disabled or fewer than three are configured.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_master"
    }
  },
  "aws.cb.opensearch.cognito_dashboards_auth": {
    "description_fields": {
      "description": "Checks CognitoOptions.Enabled for the Dashboards authentication profile."
    },
    "remediation_fields": {
      "summary": "Enable Cognito only if it is the intended Dashboards authentication method.",
      "steps": [
        "Enable Cognito only if it is the intended Dashboards authentication method."
      ],
      "caveats": [
        "Other valid authentication methods can protect Dashboards; Cognito absence alone does not mean anonymous access.",
        "This check requires Cognito specifically; a working SAML or IAM login does not make it pass. Pool IDs and service role are owner-supplied, and merely setting Enabled does not prove users can sign in."
      ]
    },
    "static_observed_sentence": "Cognito authentication for Dashboards is disabled.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "info",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_cognito"
    }
  },
  "aws.cb.opensearch.cognito_or_saml_dashboards_auth": {
    "description_fields": {
      "description": "Checks whether Cognito or SAML is enabled for Dashboards."
    },
    "remediation_fields": {
      "summary": "Configure Cognito or SAML if that is the intended authentication model.",
      "steps": [
        "Configure Cognito or SAML if that is the intended authentication model."
      ],
      "caveats": [
        "This does not establish that every other authentication method is absent.",
        "The evaluator accepts either option, but does not prove correct IdP metadata or role mapping. SAML requires fine-grained access control and an identity-provider setup; do not interpolate metadata or secrets into commands."
      ]
    },
    "static_observed_sentence": "Neither Cognito nor SAML authentication is enabled for Dashboards.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_cognito_saml"
    }
  },
  "aws.cb.opensearch.node_to_node_encryption": {
    "description_fields": {
      "description": "Checks NodeToNodeEncryptionOptions.Enabled within the source profile\u2019s regional scope."
    },
    "remediation_fields": {
      "summary": "Enable node-to-node encryption; plan migration if the deployment cannot be updated.",
      "steps": [
        "Enable node-to-node encryption; plan migration if the deployment cannot be updated."
      ],
      "caveats": [
        "The setting is checked; encrypted traffic is not independently captured.",
        "Existing-domain enablement requires OpenSearch or Elasticsearch 6.7 or later; after enabling, it cannot be disabled in place. An older incompatible domain needs upgrade or snapshot-based replacement."
      ]
    },
    "static_observed_sentence": "OpenSearch node-to-node encryption is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_n2n"
    }
  },
  "aws.cb.opensearch.node_to_node_encryption_region_skip": {
    "description_fields": {
      "description": "Checks NodeToNodeEncryptionOptions.Enabled within the source profile\u2019s regional scope."
    },
    "remediation_fields": {
      "summary": "Enable node-to-node encryption; plan migration if the deployment cannot be updated.",
      "steps": [
        "Enable node-to-node encryption; plan migration if the deployment cannot be updated."
      ],
      "caveats": [
        "The region-exception variant omits its four explicitly listed legacy Regions.",
        "The source marks af-south-1, eu-south-1, cn-north-1 and cn-northwest-1 NOT_APPLICABLE without checking the setting. Existing-domain enablement requires OpenSearch or Elasticsearch 6.7 or later; after enabling, it cannot be disabled in place. An older incompatible domain needs upgrade or snapshot-based replacement."
      ]
    },
    "static_observed_sentence": "OpenSearch node-to-node encryption is disabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_n2n_skip"
    }
  },
  "aws.cb.opensearch.enforce_https": {
    "description_fields": {
      "description": "Checks whether the OpenSearch domain requires HTTPS."
    },
    "remediation_fields": {
      "summary": "Require HTTPS and update clients that still use HTTP.",
      "steps": [
        "Require HTTPS and update clients that still use HTTP."
      ]
    },
    "static_observed_sentence": "The OpenSearch domain does not enforce HTTPS.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_https"
    }
  },
  "aws.cb.opensearch.audit_logs_enabled": {
    "description_fields": {
      "description": "Checks whether OpenSearch audit log publishing is enabled."
    },
    "remediation_fields": {
      "summary": "Enable audit log publishing and configure a usable CloudWatch destination.",
      "steps": [
        "Enable audit log publishing and configure a usable CloudWatch destination."
      ],
      "caveats": [
        "Publishing configuration does not prove log delivery.",
        "This check reads Enabled only; it does not verify a CloudWatch log group ARN, resource policy or actual events. Audit logging requires fine-grained access control and a separate in-cluster audit setting."
      ]
    },
    "static_observed_sentence": "Audit log publishing is not enabled.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_audit"
    }
  },
  "aws.cb.opensearch.slow_logs_enabled": {
    "description_fields": {
      "description": "Checks that search and index slow-log publishing are both enabled."
    },
    "remediation_fields": {
      "summary": "Enable the slow logs needed for operational diagnosis and configure thresholds.",
      "steps": [
        "Enable the slow logs needed for operational diagnosis and configure thresholds."
      ],
      "caveats": [
        "Slow logs are an operational diagnostic setting, not a general audit trail.",
        "Enabled flags alone do not guarantee events; shard slow logs remain quiet until index thresholds are set and requests exceed them. Log publication can increase cost and reveal query data, so access and retention require review."
      ]
    },
    "static_observed_sentence": "Search or index slow-log publishing is disabled.",
    "reviewed_source_severity": "low",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_slow"
    }
  },
  "aws.cb.opensearch.enabled_logs_have_log_group": {
    "description_fields": {
      "description": "Checks that each enabled supported log type declares a CloudWatch log-group ARN."
    },
    "remediation_fields": {
      "summary": "Set a CloudWatch log-group destination for each enabled log type.",
      "steps": [
        "Set a CloudWatch log-group destination for each enabled log type."
      ],
      "caveats": [
        "A declared log-group ARN does not establish delivery permissions or received logs.",
        "An empty but present LogPublishingOptions map passes this evaluator; it does not require any log type to be enabled. Destination presence does not prove resource-policy permission or successful delivery."
      ]
    },
    "static_observed_sentence": "A supported enabled log type has no log-group ARN, or log publishing configuration is absent.",
    "reviewed_source_severity": "medium",
    "reviewed_severity": "low",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_log_groups"
    }
  },
  "aws.cb.opensearch.in_vpc_private_subnets": {
    "description_fields": {
      "description": "Checks VPCId and rejects domain subnets with an explicitly associated Internet-gateway default route."
    },
    "remediation_fields": {
      "summary": "Use private VPC subnets when public placement is unnecessary.",
      "steps": [
        "Use private VPC subnets when public placement is unnecessary."
      ],
      "caveats": [
        "This source profile uses explicit route-table associations; it does not resolve an inherited main route table.",
        "AWS cannot move an existing public-endpoint domain into a VPC in place. This evaluator only checks explicitly associated route tables for a 0.0.0.0/0 Internet Gateway route; it does not inspect main-table inheritance or effective reachability."
      ]
    },
    "static_observed_sentence": "The domain has no VPC ID or one of its subnets has an explicit public route.",
    "reviewed_source_severity": "high",
    "reviewed_severity": "medium",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_vpc"
    }
  },
  "aws.cb.opensearch.access_policy_not_public": {
    "description_fields": {
      "description": "Checks the source profile\u2019s public Allow statements on domains outside a VPC."
    },
    "remediation_fields": {
      "summary": "Restrict the access policy to the identities and conditions that need domain access.",
      "steps": [
        "Restrict the access policy to the identities and conditions that need domain access."
      ],
      "caveats": [
        "A policy statement is evaluated; no request is sent to the endpoint.",
        "Domains with VPCId pass without inspecting the policy, and an absent policy also passes; neither proves private reachability. Restricting an access policy can immediately block workloads, so the replacement document needs owner approval and rollback."
      ]
    },
    "static_observed_sentence": "The non-VPC domain access policy contains a public Allow statement.",
    "reviewed_source_severity": "critical",
    "reviewed_severity": "high",
    "reviewed_binding": {
      "kind": "opensearch_domain",
      "predicate_qualname": "os_public"
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

def _strings(value, *, nonempty=False):
    return isinstance(value,list) and (not nonempty or bool(value)) and all(isinstance(v,str) and bool(v) for v in value)


def _false(evidence,key):return key in evidence and evidence[key] is False

def _true(evidence,key):return key in evidence and evidence[key] is True

def _absent(evidence,key):return key in evidence and (evidence[key] is None or evidence[key]=='')

def _integer(evidence,key,low,high):
    value=evidence.get(key)
    return type(value) is int and low<=value<=high


def _ca_within(evidence,months=None,days=None):
    from datetime import datetime,timedelta
    from calendar import monthrange
    try:
        expiry=evidence['valid_till'];capture=evidence['evaluated_at']
        if not isinstance(expiry,str) or not isinstance(capture,str):return False
        expiry=datetime.fromisoformat(expiry.replace('Z','+00:00'))
        capture=datetime.fromisoformat(capture.replace('Z','+00:00'))
        if expiry.tzinfo is None or capture.tzinfo is None:return False
        if months is not None:
            month=capture.month-1+months;year=capture.year+month//12;month=month%12+1
            cutoff=capture.replace(year=year,month=month,day=min(capture.day,monthrange(year,month)[1]))
        else:cutoff=capture+timedelta(days=days)
        return expiry<=cutoff
    except (KeyError,ValueError,OverflowError):return False


def _decisive_failure(cid,e):
    # A stored FAIL label alone is not evidence of the displayed claim.
    if cid.endswith('_snapshot_shared_accounts_review'):return False
    if cid in {'aws.cb.rds.cluster_backtrack_window_positive','aws.cb.rds.aurora_backtracking_configured'}:
        return _integer(e,'backtrack_window',0,0)
    if cid in {'aws.cb.rds.cluster_cloudwatch_log_exports','aws.cb.rds.cluster_log_exports_declared'}:
        return _strings(e.get('exports')) and not e['exports']
    requirements={
        'aws.cb.rds.aurora_postgres_postgresql_log_export':{'postgresql'},
        'aws.cb.rds.mariadb_log_exports':{'audit','error','general','slowquery'},
        'aws.cb.rds.postgres_log_exports':{'postgresql','upgrade'},
        'aws.cb.rds.sqlserver_error_log_export':{'error'},
        'aws.cb.neptune.audit_log_export':{'audit'},
        'aws.cb.redshiftserverless.connection_user_log_exports':{'connectionlog','userlog'},
    }
    if cid in requirements:
        key='log_exports' if 'redshiftserverless' in cid else 'exports'
        return _strings(e.get(key)) and not requirements[cid]<=set(e[key])
    booleans_false={
        'aws.cb.rds.multi_az_cluster_minor_upgrade':'auto_minor_version_upgrade',
        'aws.cb.rds.instance_copy_tags_all_engines':'copy_tags_to_snapshot',
        'aws.cb.rds.instance_iam_auth_supported_engines':'iam_database_authentication',
        'aws.cb.rds.instance_multi_az_or_cluster':'multi_az',
        'aws.cb.rds.instance_multi_az_non_aurora':'multi_az',
        'aws.cb.rds.cluster_snapshot_encrypted':'storage_encrypted',
        'aws.cb.neptune.snapshot_encrypted':'storage_encrypted',
        'aws.cb.redshift.audit_logging':'logging_enabled',
        'aws.cb.redshiftserverless.require_ssl':'require_ssl_enabled',
        'aws.cb.opensearch.encryption_at_rest':'enabled',
        'aws.cb.opensearch.fine_grained_access_control':'enabled',
        'aws.cb.opensearch.cognito_dashboards_auth':'cognito',
        'aws.cb.opensearch.node_to_node_encryption':'enabled',
        'aws.cb.opensearch.node_to_node_encryption_region_skip':'enabled',
        'aws.cb.opensearch.enforce_https':'enforce_https',
    }
    if cid in booleans_false:return _false(e,booleans_false[cid])
    booleans_true={
        'aws.cb.neptune.snapshot_not_public_prowler':'public_attribute_value_detected',
        'aws.cb.neptune.snapshot_restore_not_all_exact':'public_restore_attribute',
        'aws.cb.opensearch.internal_user_database_disabled':'internal_user_database',
        'aws.cb.opensearch.service_software_current':'update_available',
        'aws.cb.opensearch.access_policy_not_public':'public',
    }
    if cid in booleans_true:return _true(e,booleans_true[cid])
    if cid in {'aws.cb.rds.cluster_engine_default_port_prowler','aws.cb.rds.instance_engine_default_port_prowler'}:
        defaults={3306:('mysql','mariadb','aurora-mysql'),5432:('postgres','aurora-postgresql'),1521:('oracle',),1433:('sqlserver',),50000:('db2',)}
        return isinstance(e.get('engine'),str) and type(e.get('port')) is int and any(name in e['engine'].lower() for name in defaults.get(e['port'],()))
    matching={
        'aws.cb.rds.cluster_in_backup_plan_selection':'backup_selection_match',
        'aws.cb.rds.instance_in_backup_plan_selection':'backup_selection_match',
        'aws.cb.rds.aurora_cluster_protected_resource':'protected_resource_match',
        'aws.cb.rds.instance_protected_resource':'protected_resource_match',
        'aws.cb.rds.instance_in_backup_selection_or_tag':'selection_or_tag_key_match',
    }
    if cid in matching:
        arn=e.get('resource_arn')
        return _false(e,matching[cid]) and isinstance(arn,str) and re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:rds:[a-z0-9-]+:[0-9]{12}:(?:cluster|db):[A-Za-z0-9._-]+',arn) is not None
    if cid=='aws.cb.rds.instance_enhanced_monitoring_except_m1_small':return _absent(e,'enhanced_monitoring_resource_arn')
    if cid in {'aws.cb.rds.cluster_tls_parameters','aws.cb.rds.postgres_force_ssl_parameter','aws.cb.rds.mariadb_require_secure_transport','aws.cb.rds.sqlserver_force_ssl_parameter'}:
        param=e.get('parameter');value=e.get('value')
        if not isinstance(value,str):return False
        if cid=='aws.cb.rds.cluster_tls_parameters':return (param=='rds.force_ssl' and value=='0') or (param=='require_secure_transport' and value in {'0','OFF'})
        expected='require_secure_transport' if 'mariadb' in cid else 'rds.force_ssl'
        return param==expected and value in ({'0','OFF'} if 'mariadb' in cid else {'0'})
    if cid in {'aws.cb.rds.aurora_postgres_local_file_read_versions','aws.cb.rds.postgres_local_file_read_versions'}:
        return e.get('engine_version') in ('10.11','10.12','10.13','11.6','11.7','11.8')
    if cid=='aws.cb.rds.instance_backup_retention_nonzero_all':return _integer(e,'backup_retention_days',0,0)
    if cid=='aws.cb.rds.instance_default_master_username':return e.get('master_username') in ('admin','postgres')
    if cid=='aws.cb.rds.instance_extended_support':return e.get('engine_lifecycle_support')=='open-source-rds-extended-support'
    if cid=='aws.cb.rds.ca_certificate_valid_3_months':return _ca_within(e,months=3)
    if cid=='aws.cb.rds.ca_certificate_not_expiring_7_days':return _ca_within(e,days=7)
    if cid=='aws.cb.rds.engine_version_available':
        return _false(e,'engine_version_available') and all(isinstance(e.get(k),str) and e[k] for k in ('engine','engine_version'))
    if cid=='aws.cb.rds.instance_internet_exposed':
        return _strings(e.get('open_security_groups'),nonempty=True) and _strings(e.get('public_subnets'),nonempty=True) and _integer(e,'endpoint_port',1,65535)
    if cid in {'aws.cb.rds.instance_snapshot_restore_not_all_exact','aws.cb.rds.cluster_snapshot_restore_not_all_exact'}:
        return _strings(e.get('public_attributes')) and 'restore' in e['public_attributes']
    if cid in {'aws.cb.rds.instance_snapshot_not_public_prowler','aws.cb.rds.cluster_snapshot_not_public_prowler'}:
        # The current callback emits attribute NAMES only, including on PASS.
        # Never infer the all VALUE from attributes=['restore'] or stored FAIL.
        return _true(e,'public_attribute_value_detected') or _true(e,'public_restore_attribute')
    if cid.endswith('_critical_event_subscription'):
        return isinstance(e.get('scope'),str) and re.fullmatch(r'[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]',e['scope']) is not None and _strings(e.get('matching_subscriptions')) and not e['matching_subscriptions']
    if cid=='aws.cb.neptune.backup_retention_7_days':return _integer(e,'backup_retention_days',0,6)
    if cid in {'aws.cb.neptune.no_public_subnet_prowler','aws.cb.neptune.no_public_subnet_steampipe'}:
        return _strings(e.get('public_subnets'),nonempty=True)
    names={
        'aws.cb.redshift.non_default_master_username':('MasterUsername','awsuser'),
        'aws.cb.redshift.non_default_database_name':('DBName','dev'),
        'aws.cb.redshiftserverless.non_default_admin_username':('adminUsername','admin'),
        'aws.cb.redshiftserverless.non_default_database_name':('dbName','dev'),
    }
    if cid in names:
        key,value=names[cid];return e.get(key)==value
    if cid=='aws.cb.redshift.encrypted_and_logging':return _false(e,'encrypted') or (_true(e,'encrypted') and _false(e,'logging_enabled'))
    if cid=='aws.cb.redshift.require_ssl':return 'require_ssl' in e and (e['require_ssl'] is None or isinstance(e['require_ssl'],str) and e['require_ssl'].lower()!='true')
    if cid=='aws.cb.redshift.has_snapshot':return _integer(e,'snapshots',0,0)
    if cid=='aws.cb.redshift.snapshot_retention_7_days':return _integer(e,'retention_days',0,6)
    if cid=='aws.cb.redshift.maintenance_settings':return _false(e,'allow_version_upgrade') or (_true(e,'allow_version_upgrade') and _integer(e,'retention_days',0,6))
    if cid=='aws.cb.redshift.kms_key_declared':return _false(e,'encrypted') or (_true(e,'encrypted') and _absent(e,'kms_key_id'))
    if cid=='aws.cb.redshift.cmk_encryption':return _false(e,'encrypted') or (_true(e,'encrypted') and e.get('key_manager')=='AWS')
    if cid=='aws.cb.redshift.internet_exposed':return _strings(e.get('open_security_groups'),nonempty=True)
    if cid=='aws.cb.redshift.security_group_port_restricted':return _integer(e,'port',1,65535) and _strings(e.get('offending_security_groups'),nonempty=True)
    if cid=='aws.cb.opensearch.data_node_fault_tolerance':
        return type(e.get('instance_count')) is int and e['instance_count']>=0 and type(e.get('zone_awareness')) is bool and (e['instance_count']<3 or not e['zone_awareness'])
    if cid=='aws.cb.opensearch.dedicated_master_nodes':return _false(e,'dedicated_master') or _integer(e,'dedicated_master_count',0,2)
    if cid=='aws.cb.opensearch.cognito_or_saml_dashboards_auth':return _false(e,'cognito') and _false(e,'saml')
    if cid=='aws.cb.opensearch.audit_logs_enabled':return 'audit_logs' in e and (e['audit_logs'] is None or e['audit_logs'] is False)
    if cid=='aws.cb.opensearch.slow_logs_enabled':return type(e.get('search_slow')) is bool and type(e.get('index_slow')) is bool and not (e['search_slow'] and e['index_slow'])
    if cid=='aws.cb.opensearch.enabled_logs_have_log_group':
        missing=e.get('enabled_without_log_group')
        return ('log_publishing_options' in e and e['log_publishing_options'] is None) or (_strings(missing,nonempty=True) and set(missing)<={'AUDIT_LOGS','INDEX_SLOW_LOGS','SEARCH_SLOW_LOGS','ES_APPLICATION_LOGS'})
    if cid=='aws.cb.opensearch.in_vpc_private_subnets':return _absent(e,'vpc_id') or (isinstance(e.get('vpc_id'),str) and bool(e['vpc_id']) and _strings(e.get('public_subnets'),nonempty=True))
    return False


def evidence_summary(finding):
    if not isinstance(finding,dict) or finding.get('provider') != 'aws' or finding.get('status') != 'FAIL' or not isinstance(finding.get('evidence'),dict):
        return None
    cid=finding.get('check_id');row=ROWS.get(cid)
    if row is None or not _decisive_failure(cid,finding['evidence']):return None
    return row['static_observed_sentence']
