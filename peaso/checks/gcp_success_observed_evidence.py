"""Explicit per-check positive observations from typed native GCP fields.

Source settings are named by reviewed field labels, never by generic title
humanization. A positive verdict does not create an absent observation.
"""
import json
import math
import re
from datetime import datetime

RULES=json.loads(r'''
{
  "gcp.compute.shielded_vtpm": {
    "mode": "configured",
    "field": "shieldedInstanceConfig.enableVtpm",
    "label": "The VM virtual TPM",
    "kind": "bool"
  },
  "gcp.compute.integrity_monitoring": {
    "mode": "configured",
    "field": "shieldedInstanceConfig.enableIntegrityMonitoring",
    "label": "Shielded VM integrity monitoring",
    "kind": "bool"
  },
  "gcp.compute.secure_boot": {
    "mode": "configured",
    "field": "shieldedInstanceConfig.enableSecureBoot",
    "label": "Secure Boot",
    "kind": "bool"
  },
  "gcp.sql.backups": {
    "mode": "configured",
    "field": "settings.backupConfiguration.enabled",
    "label": "Automatic Cloud SQL backup scheduling",
    "kind": "bool"
  },
  "gcp.sql.no_public_ip": {
    "mode": "configured",
    "field": "settings.ipConfiguration.ipv4Enabled",
    "label": "Public IPv4 for Cloud SQL",
    "kind": "bool"
  },
  "gcp.gke.secrets_encryption": {
    "mode": "configured",
    "field": "databaseEncryption.state",
    "label": "Application-layer GKE Secrets encryption",
    "kind": "string"
  },
  "gcp.network.custom_subnets": {
    "mode": "configured",
    "field": "autoCreateSubnetworks",
    "label": "Automatic VPC subnet creation",
    "kind": "bool"
  },
  "gcp.iam.no_user_managed_sa_keys": {
    "mode": "string",
    "field": "key_type",
    "label": "The service-account key type"
  },
  "gcp.sql.restrict_authorized_networks": {
    "mode": "empty",
    "field": "broad_authorized_networks",
    "noun": "internet-wide SQL authorized networks"
  },
  "gcp.subnetwork.private_google_access": {
    "mode": "configured",
    "field": "privateIpGoogleAccess",
    "label": "Private Google Access",
    "kind": "bool"
  },
  "gcp.gke.no_legacy_abac": {
    "mode": "bool",
    "field": "legacy_abac_enabled",
    "noun": "Legacy ABAC",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.gke.shielded_nodes": {
    "mode": "bool",
    "field": "shielded_nodes_enabled",
    "noun": "Shielded Nodes",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.gke.network_policy": {
    "mode": "bool",
    "field": "network_policy_enabled",
    "noun": "GKE network policy",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.gke.workload_identity": {
    "mode": "string",
    "field": "workload_pool",
    "label": "The GKE Workload Identity pool"
  },
  "gcp.reviewed.compute.deletion_protection": {
    "mode": "configured",
    "field": "deletionProtection",
    "label": "VM deletion protection",
    "kind": "bool"
  },
  "gcp.reviewed.compute.automatic_restart": {
    "mode": "configured",
    "field": "scheduling.automaticRestart",
    "label": "Automatic restart after a host failure",
    "kind": "bool"
  },
  "gcp.reviewed.compute.maintenance_migrate": {
    "mode": "configured",
    "field": "scheduling.onHostMaintenance",
    "label": "The VM host maintenance policy",
    "kind": "string"
  },
  "gcp.reviewed.compute.confidential_computing": {
    "mode": "configured",
    "field": "confidentialInstanceConfig.enableConfidentialCompute",
    "label": "Confidential Computing",
    "kind": "bool"
  },
  "gcp.reviewed.loadbalancer.backend_logging": {
    "mode": "configured",
    "field": "logConfig.enable",
    "label": "Backend request logging",
    "kind": "bool"
  },
  "gcp.reviewed.network.flow_logs": {
    "mode": "bool",
    "field": "flow_logs_enabled",
    "noun": "VPC flow logging",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.reviewed.compute.ip_forwarding": {
    "mode": "bool",
    "field": "canIpForward",
    "noun": "IP forwarding",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.reviewed.compute.single_interface": {
    "mode": "number",
    "field": "interface_count",
    "sentence": "The VM declares {value} network interfaces."
  },
  "gcp.reviewed.compute.no_default_service_account": {
    "mode": "empty",
    "field": "accounts",
    "noun": "matching default service-account attachments"
  },
  "gcp.reviewed.compute.no_default_full_api": {
    "mode": "empty",
    "field": "accounts",
    "noun": "matching default service-account attachments"
  },
  "gcp.reviewed.compute.disk_auto_delete": {
    "mode": "empty",
    "field": "auto_delete_devices",
    "noun": "disks configured for automatic deletion"
  },
  "gcp.reviewed.compute.block_project_ssh_keys": {
    "mode": "bool",
    "field": "block_project_ssh_keys",
    "noun": "Project-wide SSH keys",
    "true": "blocked",
    "false": "not blocked"
  },
  "gcp.reviewed.compute.no_serial_console": {
    "mode": "bool",
    "field": "serial_port_enable",
    "noun": "Serial-console access",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.reviewed.project.os_login_2fa": {
    "mode": "bool",
    "field": "enable_oslogin_2fa",
    "noun": "Project OS Login two-factor authentication",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.reviewed.network.no_default_vpc": {
    "mode": "string",
    "field": "network_name",
    "label": "The VPC network name"
  },
  "gcp.reviewed.storage.soft_delete": {
    "mode": "number",
    "field": "retention_seconds",
    "sentence": "The declared retention interval is {value} seconds."
  },
  "gcp.reviewed.storage.versioning": {
    "mode": "configured",
    "field": "versioning.enabled",
    "label": "Bucket versioning",
    "kind": "bool"
  },
  "gcp.reviewed.storage.access_logging": {
    "mode": "string",
    "field": "log_bucket",
    "label": "The declared access-log destination"
  },
  "gcp.reviewed.storage.lifecycle": {
    "mode": "number",
    "field": "valid_rule_count",
    "sentence": "The bucket declares {value} valid lifecycle rules."
  },
  "gcp.reviewed.sql.high_availability": {
    "mode": "string",
    "field": "availability_type",
    "label": "Cloud SQL availability"
  },
  "gcp.reviewed.sql.cmek": {
    "mode": "string",
    "field": "kms_key_name",
    "label": "The declared customer-managed key"
  },
  "gcp.reviewed.sql.mysql_local_infile": {
    "mode": "sql_flag",
    "name": "local_infile",
    "field": "configured"
  },
  "gcp.reviewed.sql.mysql_skip_show_database": {
    "mode": "sql_flag",
    "name": "skip_show_database",
    "field": "configured"
  },
  "gcp.reviewed.sql.postgres_pgaudit": {
    "mode": "sql_flag",
    "name": "cloudsql.enable_pgaudit",
    "field": "configured"
  },
  "gcp.reviewed.sql.postgres_log_connections": {
    "mode": "sql_flag",
    "name": "log_connections",
    "field": "configured"
  },
  "gcp.reviewed.sql.postgres_log_disconnections": {
    "mode": "sql_flag",
    "name": "log_disconnections",
    "field": "configured"
  },
  "gcp.reviewed.sql.postgres_log_statement": {
    "mode": "sql_flag",
    "name": "log_statement",
    "field": "configured"
  },
  "gcp.reviewed.sql.postgres_log_error_verbosity": {
    "mode": "sql_flag",
    "name": "log_error_verbosity",
    "field": "configured"
  },
  "gcp.reviewed.kms.rotation_enabled": {
    "mode": "number",
    "field": "rotation_seconds",
    "sentence": "The declared automatic key-rotation interval is {value} seconds."
  },
  "gcp.reviewed.kms.rotation_90_days": {
    "mode": "number",
    "field": "rotation_seconds",
    "sentence": "The declared automatic key-rotation interval is {value} seconds."
  },
  "gcp.reviewed.kms.no_public_iam": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.reviewed.bigquery.cmek": {
    "mode": "string",
    "field": "kms_key_name",
    "label": "The declared customer-managed key"
  },
  "gcp.reviewed.bigquery.no_public_acl": {
    "mode": "empty",
    "field": "public_access_entries",
    "noun": "public dataset ACL entries"
  },
  "gcp.ports.app_engine_application_iap_enabled": {
    "mode": "configured",
    "field": "iap.enabled",
    "label": "App Engine Identity-Aware Proxy",
    "kind": "bool"
  },
  "gcp.ports.sql_instance_mysql_binary_log_enabled": {
    "mode": "configured",
    "field": "settings.backupConfiguration.binaryLogEnabled",
    "label": "Cloud SQL binary-log backup configuration",
    "kind": "bool"
  },
  "gcp.ports.kubernetes_cluster_legacy_endpoints_disabled": {
    "mode": "empty",
    "field": "failing_node_pools",
    "noun": "node pools with legacy metadata endpoints enabled"
  },
  "gcp.ports.kubernetes_cluster_node_config_image_cos_containerd": {
    "mode": "empty",
    "field": "failing_node_pools",
    "noun": "node pools using an image other than COS_CONTAINERD"
  },
  "gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled": {
    "mode": "empty",
    "field": "failing_node_pools",
    "noun": "node pools without integrity monitoring enabled"
  },
  "gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled": {
    "mode": "empty",
    "field": "failing_node_pools",
    "noun": "node pools without Secure Boot enabled"
  },
  "gcp.ports.kubernetes_cluster_use_ip_aliases": {
    "mode": "configured",
    "field": "ipAllocationPolicy.useIpAliases",
    "label": "GKE alias-IP allocation",
    "kind": "bool"
  },
  "gcp.ports.kubernetes_cluster_intra_node_visibility_enabled": {
    "mode": "configured",
    "field": "networkConfig.enableIntraNodeVisibility",
    "label": "GKE intra-node visibility",
    "kind": "bool"
  },
  "gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on": {
    "mode": "sql_flag",
    "name": "log_checkpoints",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_duration_database_flag_on": {
    "mode": "sql_flag",
    "name": "log_duration",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured": {
    "mode": "sql_flag",
    "name": "log_hostname",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on": {
    "mode": "sql_flag",
    "name": "log_lock_waits",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off": {
    "mode": "sql_flag",
    "name": "log_executor_stats",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off": {
    "mode": "sql_flag",
    "name": "log_parser_stats",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off": {
    "mode": "sql_flag",
    "name": "log_planner_stats",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off": {
    "mode": "sql_flag",
    "name": "log_statement_stats",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter": {
    "mode": "sql_flag",
    "name": "log_error_verbosity",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled": {
    "mode": "sql_flag",
    "name": "log_min_duration_statement",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured": {
    "mode": "sql_flag",
    "name": "log_min_error_statement",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error": {
    "mode": "sql_flag",
    "name": "log_min_messages",
    "field": "configured"
  },
  "gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0": {
    "mode": "sql_flag",
    "name": "log_temp_files",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off": {
    "mode": "sql_flag",
    "name": "contained database authentication",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off": {
    "mode": "sql_flag",
    "name": "cross db ownership chaining",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off": {
    "mode": "sql_flag",
    "name": "external scripts enabled",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_remote_access_database_flag_off": {
    "mode": "sql_flag",
    "name": "remote access",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_3625_trace_database_flag_on": {
    "mode": "sql_flag",
    "name": "3625",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_user_connections_database_flag_configured": {
    "mode": "sql_flag",
    "name": "user connections",
    "field": "configured"
  },
  "gcp.ports.sql_instance_sql_user_options_database_flag_not_configured": {
    "mode": "sql_flag",
    "name": "user options",
    "field": "configured"
  },
  "gcp.ports.kubernetes_cluster_auto_repair_enabled": {
    "mode": "empty",
    "field": "node_pools_needing_review",
    "noun": "node pools without automatic repair enabled"
  },
  "gcp.ports.kubernetes_cluster_auto_upgrade_enabled": {
    "mode": "empty",
    "field": "node_pools_needing_review",
    "noun": "node pools without automatic upgrade enabled"
  },
  "gcp.ports.compute_instance_with_no_default_service_account": {
    "mode": "empty",
    "field": "declared_default_accounts",
    "noun": "matching default service-account attachments"
  },
  "gcp.ports.compute_instance_with_no_default_service_account_with_full_access": {
    "mode": "empty",
    "field": "declared_default_accounts",
    "noun": "matching default service-account attachments"
  },
  "gcp.ports.compute_instance_with_no_public_ip_addresses": {
    "mode": "empty",
    "field": "declared_external_addresses",
    "noun": "external interface IP addresses"
  },
  "gcp.ports.sql_instance_require_ssl_enabled": {
    "mode": "string",
    "field": "sslMode",
    "label": "The SQL SSL mode"
  },
  "gcp.ports.kms_key_rotated_within_90_day": {
    "mode": "number",
    "field": "rotation_seconds",
    "sentence": "The declared automatic key-rotation interval is {value} seconds."
  },
  "gcp.ports.iam_api_key_restricts_apis": {
    "mode": "sequence",
    "field": "restricted_services",
    "label": "The API key declares these API targets"
  },
  "gcp.ports.bigquery_table_encrypted_with_cmk": {
    "mode": "string",
    "field": "key_reference",
    "label": "The declared customer-managed key reference"
  },
  "gcp.ports.dataproc_cluster_encryption_with_cmek": {
    "mode": "string",
    "field": "key_reference",
    "label": "The declared customer-managed key reference"
  },
  "gcp.ports.iam_service_account_gcp_managed_key": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.ports.reference_sql_pg_min_duration": {
    "mode": "declared",
    "name": "log_min_duration_statement",
    "field": "declared"
  },
  "gcp.ports.reference_sql_pg_min_error": {
    "mode": "declared",
    "name": "log_min_error_statement",
    "field": "declared"
  },
  "gcp.ports.reference_sql_pg_min_messages": {
    "mode": "declared",
    "name": "log_min_messages",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_contained_database_authentication": {
    "mode": "declared",
    "name": "contained database authentication",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_cross_db_ownership_chaining": {
    "mode": "declared",
    "name": "cross db ownership chaining",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_external_scripts_enabled": {
    "mode": "declared",
    "name": "external scripts enabled",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_remote_access": {
    "mode": "declared",
    "name": "remote access",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_user_connections": {
    "mode": "declared",
    "name": "user connections",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_user_options": {
    "mode": "declared",
    "name": "user options",
    "field": "declared"
  },
  "gcp.ports.reference_sqlserver_trace3625": {
    "mode": "declared",
    "name": "3625",
    "field": "declared"
  },
  "gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter": {
    "mode": "declared",
    "name": "log_error_verbosity",
    "field": "declared"
  },
  "gcp.ports.alloydb_instance_log_min_messages_database_flag_error": {
    "mode": "declared",
    "name": "log_min_messages",
    "field": "declared"
  },
  "gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured": {
    "mode": "declared",
    "name": "log_min_error_statement",
    "field": "declared"
  },
  "gcp.ports.alloydb_cluster_encrypted_with_cmk": {
    "mode": "string",
    "field": "encryption_type",
    "label": "The storage encryption mode"
  },
  "gcp.ports.apikeys_api_restricted_with_gemini_api": {
    "mode": "sequence",
    "field": "restricted_services",
    "label": "The API key declares these API targets"
  },
  "gcp.ports.iam_user_not_assigned_service_account_user_role_project_level": {
    "mode": "empty",
    "field": "broad_project_role_declarations",
    "noun": "matching broad project-level impersonation-role declarations"
  },
  "gcp.ports.service_account_mutating_role_declarations": {
    "mode": "empty",
    "field": "mutating_role_declarations",
    "noun": "service-account role declarations containing mutation verbs"
  },
  "gcp.ports.compute_oslogin_metadata_precedence": {
    "mode": "bool",
    "field": "instance_enable_oslogin",
    "noun": "Instance OS Login",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.ports.compute_disk_encrypted_with_csk": {
    "mode": "bool",
    "field": "csek_digest_present",
    "noun": "A customer-supplied disk-encryption key digest",
    "true": "recorded",
    "false": "not recorded"
  },
  "gcp.ports.compute_url_map_backend_logging": {
    "mode": "empty",
    "field": "backend_services_without_logging",
    "noun": "routed backend services missing logging"
  },
  "gcp.ports.organization_essential_contacts_complete": {
    "mode": "sequence",
    "field": "configured_categories",
    "label": "Essential Contact subscriptions declare these categories"
  },
  "gcp.ports.access_approval_explicit_enrollment": {
    "mode": "sequence",
    "field": "enrolled_products",
    "label": "Access Approval declares these product enrollments"
  },
  "gcp.ports.cloud_run_not_publicly_accessible": {
    "mode": "string",
    "field": "ingress",
    "label": "The service ingress mode"
  },
  "gcp.ports.sql_instance_not_open_to_internet": {
    "mode": "empty",
    "field": "declared_authorized_ranges",
    "noun": "internet-wide authorized SQL ranges"
  },
  "gcp.ports.reference_sql_ssl_connections": {
    "mode": "string",
    "field": "ssl_mode",
    "label": "The SQL SSL mode"
  },
  "gcp.ports.function_internal_ingress_declaration": {
    "mode": "string",
    "field": "ingress",
    "label": "The service ingress mode"
  },
  "gcp.claude.firewall.logging_enabled": {
    "mode": "bool",
    "field": "log_config_enable",
    "noun": "Firewall logging",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.instance.sa_no_basic_role": {
    "mode": "sequence",
    "field": "service_accounts",
    "label": "The workload declares these service accounts"
  },
  "gcp.claude.project.oslogin_enabled": {
    "mode": "bool",
    "field": "enable_oslogin",
    "noun": "OS Login",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.instance.not_preemptible": {
    "mode": "bool",
    "field": "preemptible",
    "noun": "Preemptible VM scheduling",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.instance.not_preemptible_or_spot": {
    "mode": "bool",
    "field": "preemptible",
    "noun": "Preemptible VM scheduling",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.instance.disks_csek": {
    "mode": "empty",
    "field": "disks_without_csek",
    "noun": "disks without a declared customer-supplied key digest"
  },
  "gcp.claude.instance.suspended_without_disks": {
    "mode": "string",
    "field": "status",
    "label": "The resource state"
  },
  "gcp.claude.instance_template.no_ip_forwarding": {
    "mode": "bool",
    "field": "can_ip_forward",
    "noun": "IP forwarding",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.project.no_api_keys": {
    "mode": "empty",
    "field": "api_keys",
    "noun": "API-key metadata entries"
  },
  "gcp.claude.image.not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude.snapshot.not_outdated": {
    "mode": "number",
    "field": "age_days",
    "sentence": "The object was created {value} days before capture."
  },
  "gcp.claude.instance_group_manager.autohealing": {
    "mode": "sequence",
    "field": "health_checks",
    "label": "The instance group declares these autohealing health checks"
  },
  "gcp.claude.instance_group_manager.multiple_zones": {
    "mode": "sequence",
    "field": "zones",
    "label": "The instance group declares these zones"
  },
  "gcp.claude.instance_group_manager.load_balancer_attached": {
    "mode": "sequence",
    "field": "backend_services",
    "label": "The instance group is referenced by these backend services"
  },
  "gcp.claude.backend_service.external_iap": {
    "mode": "bool",
    "field": "iap_enabled",
    "noun": "Backend Identity-Aware Proxy",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.target_proxy.https_custom_ssl_policy": {
    "mode": "string",
    "field": "ssl_policy",
    "label": "The declared SSL policy"
  },
  "gcp.claude.target_proxy.https_min_tls_1_2": {
    "mode": "string",
    "field": "min_tls_version",
    "label": "The minimum TLS version"
  },
  "gcp.claude.network.dns_logging": {
    "mode": "bool",
    "field": "enable_logging",
    "noun": "DNS policy logging",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.dns_zone.dnssec_enabled": {
    "mode": "string",
    "field": "dnssec_state",
    "label": "DNSSEC state"
  },
  "gcp.claude.dns_zone.ksk_not_rsasha1": {
    "mode": "number",
    "field": "rsasha1_specs",
    "sentence": "The recorded DNSSEC specification contains {value} RSASHA1 algorithm entries."
  },
  "gcp.claude.dns_zone.zsk_not_rsasha1": {
    "mode": "number",
    "field": "rsasha1_specs",
    "sentence": "The recorded DNSSEC specification contains {value} RSASHA1 algorithm entries."
  },
  "gcp.claude.bucket.log_sink_retention_locked": {
    "mode": "bool",
    "field": "retention_locked",
    "noun": "Log retention locking",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.bucket.log_sink_retention_policy": {
    "mode": "number",
    "field": "retention_period",
    "sentence": "The declared bucket retention period is {value} seconds."
  },
  "gcp.claude.bucket.log_sink_not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude.bucket.log_sink_versioning": {
    "mode": "bool",
    "field": "versioning_enabled",
    "noun": "Object versioning",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.bucket.retention_90_days": {
    "mode": "number",
    "field": "retention_days",
    "sentence": "The declared retention interval is {value} days."
  },
  "gcp.claude.project.storage_vpc_service_controls": {
    "mode": "sequence",
    "field": "perimeters",
    "label": "The project is included in these enforced service perimeters"
  },
  "gcp.claude.project.storage_data_access_audit_logs": {
    "mode": "sequence",
    "field": "declared_log_types",
    "label": "The Cloud Storage audit policy declares these log categories"
  },
  "gcp.claude.project.audit_logs_configured": {
    "mode": "sequence",
    "field": "audit_config_services",
    "label": "The project audit policy names these services"
  },
  "gcp.claude.iam_policy.no_all_users": {
    "mode": "empty",
    "field": "public_roles",
    "noun": "matching public IAM role bindings"
  },
  "gcp.claude.iam_policy.no_project_sa_user_or_token_creator": {
    "mode": "empty",
    "field": "project_level_bindings",
    "noun": "matching project-level service-account impersonation bindings"
  },
  "gcp.claude.service_account.recently_used": {
    "mode": "number",
    "field": "idle_days",
    "sentence": "The recorded identity has been idle for {value} days."
  },
  "gcp.claude.service_account_key.recently_used": {
    "mode": "number",
    "field": "idle_days",
    "sentence": "The recorded identity has been idle for {value} days."
  },
  "gcp.claude.workload_identity_provider.multi_tenant_condition": {
    "mode": "bool",
    "field": "attribute_condition",
    "noun": "A Workload Identity attribute condition",
    "true": "configured",
    "false": "not configured"
  },
  "gcp.claude.organization.essential_contacts_any": {
    "mode": "number",
    "field": "contacts",
    "sentence": "The organization declares {value} essential contacts."
  },
  "gcp.claude.kms_key.users_limited_to_3": {
    "mode": "special"
  },
  "gcp.claude.kms_key.rotation_100_days": {
    "mode": "number",
    "field": "rotation_seconds",
    "sentence": "The declared automatic key-rotation interval is {value} seconds."
  },
  "gcp.claude.pubsub_topic.not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude.pubsub_subscription.not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude.pubsub_snapshot.not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude.secret.not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude.secret.rotation_90_days": {
    "mode": "number",
    "field": "rotation_seconds",
    "sentence": "The declared automatic key-rotation interval is {value} seconds."
  },
  "gcp.claude.sql_instance.second_gen_no_public_ip": {
    "mode": "sequence",
    "field": "ip_address_types",
    "label": "Cloud SQL declares these IP address types"
  },
  "gcp.claude.sql_instance.private_ip_only": {
    "mode": "sequence",
    "field": "ip_address_types",
    "label": "Cloud SQL declares these IP address types"
  },
  "gcp.claude.bigquery_dataset.no_gmail_access": {
    "mode": "empty",
    "field": "matching_entries",
    "noun": "dataset ACL entries naming gmail.com accounts"
  },
  "gcp.claude.bigquery_dataset.no_googlegroups_access": {
    "mode": "empty",
    "field": "matching_entries",
    "noun": "dataset ACL entries naming googlegroups.com groups"
  },
  "gcp.claude.gke.binary_authorization": {
    "mode": "string",
    "field": "evaluation_mode",
    "label": "Binary Authorization mode"
  },
  "gcp.claude.gke.no_client_certificate": {
    "mode": "bool",
    "field": "client_certificate_issued",
    "noun": "Legacy GKE client-certificate issuance",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.gke.no_kubernetes_alpha": {
    "mode": "bool",
    "field": "enable_kubernetes_alpha",
    "noun": "Kubernetes alpha features",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.gke.http_load_balancing": {
    "mode": "bool",
    "field": "http_load_balancing_disabled",
    "noun": "GKE HTTP load balancing",
    "true": "disabled",
    "false": "enabled"
  },
  "gcp.claude.gke.dashboard_disabled": {
    "mode": "bool",
    "field": "dashboard_disabled",
    "noun": "Kubernetes Dashboard",
    "true": "disabled",
    "false": "enabled"
  },
  "gcp.claude.gke.logging_enabled": {
    "mode": "string",
    "field": "loggingService",
    "label": "The GKE logging service"
  },
  "gcp.claude.gke.monitoring_enabled": {
    "mode": "string",
    "field": "monitoringService",
    "label": "The GKE monitoring service"
  },
  "gcp.claude.gke.no_default_network": {
    "mode": "string",
    "field": "network",
    "label": "The declared network"
  },
  "gcp.claude.gke.nodes_no_default_service_account": {
    "mode": "empty",
    "field": "default_service_account_pools",
    "noun": "node pools using the default service account"
  },
  "gcp.claude.gke.release_channel": {
    "mode": "string",
    "field": "channel",
    "label": "The GKE release channel"
  },
  "gcp.claude.gke.zone_redundant": {
    "mode": "number",
    "field": "distinct_zone_count",
    "sentence": "The GKE cluster declares {value} distinct node zones."
  },
  "gcp.claude.gke.subnetwork_private_google_access": {
    "mode": "bool",
    "field": "private_ip_google_access",
    "noun": "Private Google Access",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude.gke.network_no_untargeted_public_ingress": {
    "mode": "empty",
    "field": "untargeted_public_rules",
    "noun": "untargeted public ingress rules"
  },
  "gcp.claude.gke.master_authorized_networks_restricted": {
    "mode": "sequence",
    "field": "cidr_blocks",
    "label": "Control-plane authorized networks declare these source ranges"
  },
  "gcp.claude.gke.private_nodes": {
    "mode": "bool",
    "field": "private_nodes",
    "noun": "Private GKE nodes",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.claude2.logging.metric_alert_project_ownership_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "project-ownership changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_audit_configuration_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "audit-configuration changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_custom_role_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "custom-role changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_custom_role_changes_with_undelete": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "custom-role changes including undelete log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_firewall_rule_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "firewall-rule changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_route_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "route changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_network_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "network changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_bucket_iam_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "bucket IAM changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.logging.metric_alert_sql_instance_configuration_changes": {
    "mode": "empty",
    "field": "unnotified",
    "noun": "SQL-instance configuration changes log metrics lacking a qualifying alert chain"
  },
  "gcp.claude2.function.ingress_not_allow_all": {
    "mode": "string",
    "field": "ingress_settings",
    "label": "The function ingress mode"
  },
  "gcp.claude2.function.not_publicly_accessible": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude2.function.vpc_connector_configured": {
    "mode": "string",
    "field": "vpc_connector",
    "label": "The declared VPC connector"
  },
  "gcp.claude2.cloudrun_service.invoker_not_public": {
    "mode": "empty",
    "field": "public_bindings",
    "noun": "public-principal IAM bindings"
  },
  "gcp.claude2.api_key.created_within_90_days": {
    "mode": "number",
    "field": "age_days",
    "sentence": "The object was created {value} days before capture."
  },
  "gcp.claude2.bigquery_dataset.default_cmek": {
    "mode": "string",
    "field": "kms_key_name",
    "label": "The declared customer-managed key"
  },
  "gcp.claude2.sql_instance.only_private_ip_addresses": {
    "mode": "sequence",
    "field": "ip_address_types",
    "label": "Cloud SQL declares these IP address types"
  },
  "gcp.ports.logging_bucket_retention_policy_enabled": {
    "mode": "bool",
    "field": "retention_locked",
    "noun": "Log retention locking",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp.ports.sql_instance_with_no_public_ips": {
    "mode": "sequence",
    "field": "address_types",
    "label": "Cloud SQL declares these IP address types"
  },
  "gcp.ports.sql_instance_not_publicly_accessible": {
    "mode": "sequence",
    "field": "address_types",
    "label": "Cloud SQL declares these IP address types"
  },
  "gcp.ports.sql_no_primary_address": {
    "mode": "sequence",
    "field": "address_types",
    "label": "Cloud SQL declares these IP address types"
  },
  "gcp.ports.project_no_api_key": {
    "mode": "empty",
    "field": "key_metadata_names",
    "noun": "API-key metadata entries"
  },
  "gcp.htbp.cloudrun.service_no_default_compute_sa": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.cloudrun.job_no_default_compute_sa": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.cloudrun.service_secret_env_from_secret_manager": {
    "mode": "empty",
    "field": "literal_credential_variables",
    "noun": "environment-variable names matching the credential heuristic"
  },
  "gcp.htbp.cloudrun.job_secret_env_from_secret_manager": {
    "mode": "empty",
    "field": "literal_credential_variables",
    "noun": "environment-variable names matching the credential heuristic"
  },
  "gcp.htbp.function.runtime_no_default_sa": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.appengine.no_default_service_account": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.instance_template.no_default_sa_full_scope": {
    "mode": "empty",
    "field": "default_accounts_with_full_scope",
    "noun": "default service accounts with the broad cloud-platform scope"
  },
  "gcp.htbp.logging.default_sink_not_disabled": {
    "mode": "bool",
    "field": "disabled",
    "noun": "The default log sink",
    "true": "disabled",
    "false": "enabled"
  },
  "gcp.htbp.storage.default_object_acl_not_public": {
    "mode": "empty",
    "field": "public_entities",
    "noun": "public entities in the default object ACL"
  },
  "gcp.htbp.pubsub.push_endpoint_not_tunnel": {
    "mode": "string",
    "field": "push_host",
    "label": "The configured Pub/Sub push host"
  },
  "gcp.htbp.function.secret_env_from_secret_manager": {
    "mode": "empty",
    "field": "literal_credential_variables",
    "noun": "environment-variable names matching the credential heuristic"
  },
  "gcp.htbp.cloudbuild.pr_trigger_gated": {
    "mode": "bool",
    "field": "approval_required",
    "noun": "Build approval",
    "true": "required",
    "false": "not required"
  },
  "gcp.htbp.cloudbuild.trigger_no_default_sa": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.storage.hmac_key_not_stale_or_default_sa": {
    "mode": "number",
    "field": "age_days",
    "sentence": "The object was created {value} days before capture."
  },
  "gcp.htbp.composer.no_default_compute_sa": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.workbench.no_default_compute_sa": {
    "mode": "sequence",
    "field": "service_accounts",
    "label": "The workload declares these service accounts"
  },
  "gcp.htbp.scheduler.no_recurring_access_regrant": {
    "mode": "string",
    "field": "service_account",
    "label": "The configured service account"
  },
  "gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled": {
    "mode": "bool",
    "field": "enforced",
    "noun": "The cross-project service-account usage restriction",
    "true": "enforced",
    "false": "not enforced"
  },
  "gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled": {
    "mode": "bool",
    "field": "enforced",
    "noun": "The default-service-account automatic-grant restriction",
    "true": "enforced",
    "false": "not enforced"
  },
  "gcp.htbp.orgpolicy.domain_restricted_sharing": {
    "mode": "bool",
    "field": "enforced",
    "noun": "The permitted IAM-member domain constraint",
    "true": "enforced",
    "false": "not enforced"
  },
  "gcp.htbp.orgpolicy.essential_contacts_domain_restricted": {
    "mode": "bool",
    "field": "enforced",
    "noun": "The Essential Contacts domain restriction",
    "true": "enforced",
    "false": "not enforced"
  },
  "gcp.htbp.iam.sa_no_pool_wide_workload_principal_set": {
    "mode": "empty",
    "field": "pool_wide_bindings",
    "noun": "pool-wide Workload Identity principal-set bindings"
  },
  "gcp.htbp.iam.policy_no_pool_wide_workload_principal_set": {
    "mode": "empty",
    "field": "pool_wide_bindings",
    "noun": "pool-wide Workload Identity principal-set bindings"
  },
  "gcp.gap.iam_user_managed_sa_no_admin_roles": {
    "mode": "empty",
    "field": "admin_role_bindings",
    "noun": "matching administrator-role bindings"
  },
  "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only": {
    "mode": "empty",
    "field": "ranges_outside_cis_list",
    "noun": "source ranges outside the IAP and health-check list"
  },
  "gcp.gap.sql_3625_trace_flag_off_cis_v1": {
    "mode": "sql_flag",
    "name": "3625",
    "field": "configured"
  },
  "gcp_pci_bucket_0742bd5dc32c": {
    "mode": "bool",
    "field": "versioning_enabled",
    "noun": "Object versioning",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp_pci_bucket_3d76b0b0701e": {
    "mode": "bool",
    "field": "versioning_enabled",
    "noun": "Object versioning",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp_pci_instance_template_2e26bed500fc": {
    "mode": "empty",
    "field": "external_interfaces",
    "noun": "interfaces declaring external IP addresses"
  },
  "gcp_pubsub_topic_cmek": {
    "mode": "string",
    "field": "kms_key_name",
    "label": "The declared customer-managed key"
  },
  "gcp_pci_bigquery_dataset_6017267cdf32": {
    "mode": "empty",
    "field": "public_read_write_entries",
    "noun": "public dataset read/write ACL entries"
  },
  "gcp_pci_bigquery_dataset_fb9fcc01d5b7": {
    "mode": "empty",
    "field": "all_users_roles",
    "noun": "allUsers dataset role bindings"
  },
  "gcp_cloudcdn_cookie_ttl": {
    "mode": "number",
    "field": "affinity_cookie_ttl_sec",
    "sentence": "The backend affinity cookie TTL is {value} seconds."
  },
  "gcp_pci_bigquery_dataset_a4e25dbf9640": {
    "mode": "empty",
    "field": "all_users_reader_entries",
    "noun": "allUsers READER dataset ACL entries"
  },
  "gcp.sql.deletion_protection": {
    "mode": "bool",
    "field": "deletion_protection_enabled",
    "noun": "Cloud SQL deletion protection",
    "true": "enabled",
    "false": "disabled"
  },
  "gcp_bucket_logging_enabled_fb7cc594582a": {
    "mode": "string",
    "field": "log_bucket",
    "label": "The declared access-log destination"
  },
  "gcp_pci_cloudbuild_trigger_3302edf7cb18": {
    "mode": "string",
    "field": "logging",
    "label": "The build logging mode"
  },
  "gcp_api_keys_active_services_only": {
    "mode": "sequence",
    "field": "restricted_services",
    "label": "The API key declares these API targets"
  },
  "gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650": {
    "mode": "empty",
    "field": "scheduled_versions",
    "noun": "key versions scheduled for destruction"
  },
  "gcp_pci_asset_6ee2fef37d98": {
    "mode": "number",
    "field": "retention_days",
    "sentence": "The declared retention interval is {value} days."
  },
  "gcp.sql.mysql_admin_account_posture": {
    "mode": "string",
    "field": "user_name",
    "label": "The SQL user name"
  },
  "gcp.sql.iam_database_authentication": {
    "mode": "bool",
    "field": "iam_user_found",
    "noun": "An IAM database-authentication user",
    "true": "recorded",
    "false": "not recorded"
  },
  "gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6": {
    "mode": "sql_flag",
    "name": "cloudsql.iam_authentication",
    "field": "value"
  },
  "gcp_sql_trace3625_off": {
    "mode": "string",
    "field": "trace_flag_3625",
    "label": "SQL trace flag 3625"
  },
  "gcp.appengine.version_https_only": {
    "mode": "sequence",
    "field": "handler_levels",
    "label": "App Engine handlers declare these transport-security levels"
  },
  "gcp_https_proxy_mtls_required": {
    "mode": "string",
    "field": "client_validation_mode",
    "label": "Client-certificate validation mode"
  },
  "gcp_autoscaler_capacity_target": {
    "mode": "number",
    "field": "cpu_target",
    "sentence": "The autoscaler CPU target is {value}."
  },
  "gcp_pci_firewall_2080b14f1361": {
    "mode": "bool",
    "field": "public_source",
    "noun": "The firewall source",
    "true": "internet-wide",
    "false": "not internet-wide"
  },
  "gcp_pci_backend_service_2ce96d36d0bf": {
    "mode": "empty",
    "field": "weak_https_proxies",
    "noun": "serving HTTPS proxies with an insufficient TLS policy"
  },
  "gcp.identity.non_service_account_mfa": {
    "mode": "bool",
    "field": "isEnrolledIn2Sv",
    "noun": "Two-step verification enrollment",
    "true": "present",
    "false": "absent"
  },
  "gcp.identity.super_admin_separation": {
    "mode": "empty",
    "field": "conflicting_roles",
    "noun": "matching non-super-admin access roles"
  },
  "gcp_lb_server_header_rewrite": {
    "mode": "empty",
    "field": "unrewritten_route_indexes",
    "noun": "routes missing the required response-header rewrite"
  },
  "gcp_pci_url_map_9ed56c323a05": {
    "mode": "empty",
    "field": "unredirected_routes",
    "noun": "routes missing the required HTTPS redirect"
  },
  "gcp.logging.access_transparency_entries": {
    "mode": "number",
    "field": "recent_access_transparency_entries",
    "sentence": "The captured window contains {value} Access Transparency entries."
  },
  "gcp_cloudsql_backup_failure_alert": {
    "mode": "sequence",
    "field": "enabled_alert_policies",
    "label": "The project declares these enabled backup-failure alerts"
  },
  "gcp_certificate_rotation_180_days": {
    "mode": "number",
    "field": "age_days",
    "sentence": "The object was created {value} days before capture."
  },
  "gcp_certificate_rotation_90_days": {
    "mode": "number",
    "field": "age_days",
    "sentence": "The object was created {value} days before capture."
  },
  "gcp_gke_small_cluster_auto_upgrade": {
    "mode": "empty",
    "field": "pools_without_auto_upgrade",
    "noun": "node pools with automatic upgrade disabled"
  },
  "gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d": {
    "mode": "empty",
    "field": "public_ip_endpoint_clusters",
    "noun": "clusters declaring a public IP control-plane endpoint"
  },
  "gcp.iam.data_access_audit": {
    "mode": "special"
  },
  "gcp.gke.private_endpoint": {
    "mode": "special"
  },
  "gcp.gke.private_nodes": {
    "mode": "special"
  },
  "gcp.gke.authorized_networks": {
    "mode": "special"
  },
  "gcp.gke.node_pools_gke_metadata": {
    "mode": "special"
  },
  "gcp.ports.compute_instance_shielded_vm_enabled": {
    "mode": "special"
  },
  "gcp.ports.compute_network_contains_no_legacy_network": {
    "mode": "special"
  },
  "gcp.ports.compute_firewall_rule_ssh_access_restricted": {
    "mode": "firewall"
  },
  "gcp.ports.compute_firewall_rule_rdp_access_restricted": {
    "mode": "firewall"
  },
  "gcp.ports.audit_logging_configured_for_all_service": {
    "mode": "special"
  },
  "gcp.ports.iam_api_key_age_90": {
    "mode": "created",
    "field": "created_at",
    "noun": "API key",
    "clock": "observed_at"
  },
  "gcp.ports.iam_service_account_key_age_90": {
    "mode": "created",
    "field": "created_at",
    "noun": "service-account key",
    "clock": "observed_at"
  },
  "gcp.ports.iam_api_key_restricts_websites_hosts_apps": {
    "mode": "special"
  },
  "gcp.ports.project_service_cloudasset_api_enabled": {
    "mode": "service_state"
  },
  "gcp.ports.artifacts_container_analysis_enabled": {
    "mode": "service_state"
  },
  "gcp.ports.kms_key_separation_of_duties_enforced": {
    "mode": "empty",
    "field": "overlapping_role_declarations",
    "noun": "overlapping duty-role declarations"
  },
  "gcp.ports.iam_user_separation_of_duty_scoped": {
    "mode": "empty",
    "field": "overlapping_role_declarations",
    "noun": "overlapping duty-role declarations"
  },
  "gcp.ports.firewall_iap_tcp_proxy_source_restriction": {
    "mode": "firewall"
  },
  "gcp.ports.firewall_http_lb_proxy_source_restriction": {
    "mode": "firewall"
  },
  "gcp.gke.control_plane_restricted": {
    "mode": "special"
  },
  "gcp.claude.firewall.public_ingress_dns_port_53": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_ftp_port_21": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_http_port_80": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_smtp_port_25": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_microsoft_ds_port_445": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_mongo_db_port_27017": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_mysql_db_port_3306": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_netbios_snn_port_139": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_oracle_db_port_1521": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_pop3_port_110": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_postgresql_port_5432": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_telnet_port_23": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_kubelet_port_10250": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_kubelet_read_only_port_10255": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_9090": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_9200_9300": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_7000_7001": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_7199": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_8888": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_9042": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_9160": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_61620_61621": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_6379": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_137_to_139": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_27017_to_27019": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_port_636": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_udp_port_389": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_udp_port_11211": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_udp_port_11214_to_11215": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_udp_port_2483_to_2484": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_all_protocols": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_without_target": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.default_rules_not_open": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_common_ports": {
    "mode": "firewall"
  },
  "gcp.claude.firewall.public_ingress_tcp_udp": {
    "mode": "firewall"
  },
  "gcp.claude.backend_bucket.bucket_exists": {
    "mode": "string",
    "field": "bucket",
    "label": "The resolved backend bucket"
  },
  "gcp.claude.service_account_key.age_100_days": {
    "mode": "created",
    "field": "valid_after",
    "noun": "service-account key",
    "clock": "observed_at"
  },
  "gcp.claude.project.container_scanning_api_enabled": {
    "mode": "service_state"
  },
  "gcp.claude.project.gemini_api_disabled": {
    "mode": "service_state"
  },
  "gcp.claude.logging.metric_alert_audit_configuration_changes": {
    "mode": "metric_alert",
    "event": "audit-configuration changes"
  },
  "gcp.claude.logging.metric_alert_custom_role_changes": {
    "mode": "metric_alert",
    "event": "custom-role changes"
  },
  "gcp.claude.logging.metric_alert_custom_role_changes_with_undelete": {
    "mode": "metric_alert",
    "event": "custom-role changes and restoration"
  },
  "gcp.claude.logging.metric_alert_firewall_rule_changes": {
    "mode": "metric_alert",
    "event": "firewall-rule changes"
  },
  "gcp.claude.logging.metric_alert_network_changes_beta_methods": {
    "mode": "metric_alert",
    "event": "network changes"
  },
  "gcp.claude.logging.metric_alert_network_changes": {
    "mode": "metric_alert",
    "event": "network changes"
  },
  "gcp.claude.logging.metric_alert_route_changes": {
    "mode": "metric_alert",
    "event": "route changes"
  },
  "gcp.claude.logging.metric_alert_project_ownership_changes": {
    "mode": "metric_alert",
    "event": "project ownership changes"
  },
  "gcp.claude.logging.metric_alert_sql_instance_configuration_changes": {
    "mode": "metric_alert",
    "event": "Cloud SQL configuration changes"
  },
  "gcp.claude.logging.metric_alert_bucket_iam_changes": {
    "mode": "metric_alert",
    "event": "bucket IAM changes"
  },
  "gcp.claude.logging.metric_alert_compute_configuration_changes": {
    "mode": "metric_alert",
    "event": "VM configuration changes"
  },
  "gcp.claude.logging.project_sink_all_entries": {
    "mode": "sink"
  },
  "gcp.ports.logging_metric_alert_audit_configuration_changes_scoped": {
    "mode": "metric_alert",
    "event": "audit-configuration changes"
  },
  "gcp.ports.logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role_scoped": {
    "mode": "metric_alert",
    "event": "custom-role changes and restoration"
  },
  "gcp.ports.logging_metric_alert_custom_role_changes_scoped": {
    "mode": "metric_alert",
    "event": "custom-role changes"
  },
  "gcp.ports.logging_metric_alert_firewall_rule_changes_scoped": {
    "mode": "metric_alert",
    "event": "firewall-rule changes"
  },
  "gcp.ports.logging_metric_alert_network_changes_scoped": {
    "mode": "metric_alert",
    "event": "network changes"
  },
  "gcp.ports.logging_metric_alert_network_route_changes_scoped": {
    "mode": "metric_alert",
    "event": "route changes"
  },
  "gcp.ports.logging_metric_alert_project_ownership_assignment_scoped": {
    "mode": "metric_alert",
    "event": "project ownership changes"
  },
  "gcp.ports.logging_metric_alert_sql_instance_configuration_changes_scoped": {
    "mode": "metric_alert",
    "event": "Cloud SQL configuration changes"
  },
  "gcp.ports.logging_metric_alert_storage_iam_permission_changes_scoped": {
    "mode": "metric_alert",
    "event": "storage IAM changes"
  },
  "gcp.ports.logging_sink_all_entries_enabled": {
    "mode": "sink"
  },
  "gcp.ports.dns_managed_zone_dnssec_enabled": {
    "mode": "string",
    "field": "state",
    "label": "DNSSEC state"
  },
  "gcp.ports.cloudfunction_function_no_ingress_settings_allow_all": {
    "mode": "string",
    "field": "configured",
    "label": "The function ingress mode"
  },
  "gcp.ports.cloudfunction_function_vpc_connector_enabled": {
    "mode": "string",
    "field": "configured",
    "label": "The declared VPC connector"
  },
  "gcp.ports.function_active_vpc_connector": {
    "mode": "string",
    "field": "configured",
    "label": "The declared VPC connector"
  },
  "gcp.ports.api_key_elapsed_age_gt90": {
    "mode": "created",
    "field": "created_at",
    "noun": "API key",
    "clock": "captured_at"
  },
  "gcp.htbp.gke.kubelet_readonly_port_disabled": {
    "mode": "special"
  },
  "gcp.htbp.kms.destroy_window_not_shortened": {
    "mode": "special"
  },
  "gcp.htbp.artifactregistry.virtual_repo_private_precedence": {
    "mode": "special"
  },
  "gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked": {
    "mode": "special"
  },
  "gcp.htbp.storage.notification_topic_in_bucket_project": {
    "mode": "special"
  }
}
''')


def _text(v):return isinstance(v,str) and bool(v) and len(v)<=200 and not any(ord(c)<32 for c in v)
def _strings(v):return isinstance(v,list) and all(_text(x) for x in v)
def _number(v):return type(v)in (int,float) and math.isfinite(v)
def _items(v):return ', '.join(v[:2])+(' and '+str(len(v)-2)+' others' if len(v)>2 else '')
def _date(v):
 if not _text(v):return None
 try:
  d=datetime.fromisoformat(v.replace('Z','+00:00'))
  return d if d.tzinfo else None
 except ValueError:return None


def evidence_summary(finding):
 if not isinstance(finding,dict) or finding.get('provider')!='gcp' or finding.get('status')!='PASS':return None
 cid=finding.get('check_id');e=finding.get('evidence')
 if not isinstance(cid,str) or not isinstance(e,dict):return None
 rule=RULES.get(cid)
 if not rule:return None
 mode=rule['mode'];field=rule.get('field');v=e.get(field)
 if mode=='sql_flag':
  if e.get('flag')!=rule['name']:return None
  if field in e and v is None:return 'No explicit Cloud SQL '+rule['name']+' flag is recorded.'
  if not _text(v):return None
  return 'Cloud SQL flag '+rule['name']+' is set to '+v+'.'
 if mode=='declared':
  if e.get('field')!=rule['name']:return None
  if v is None or v=='':return 'No explicit '+rule['name']+' setting was recorded.' if field in e else None
  if _text(v):return 'The recorded '+rule['name']+' setting is '+v+'.'
 if mode=='configured':
  if e.get('field')!=rule['field']:return None
  v=e.get('configured')
  if rule['kind']=='bool' and type(v)is bool:return rule['label']+' is '+('enabled.' if v else 'disabled.')
  if rule['kind']=='string' and _text(v):return rule['label']+' is '+v+'.'
 if mode=='empty':return 'No '+rule['noun']+' were recorded.' if field in e and e[field]==[] else None
 if mode=='bool' and type(v)is bool:return rule['noun']+(' are ' if rule['noun']in {'Project-wide SSH keys','Private GKE nodes','Kubernetes alpha features'} else ' is ')+rule['true' if v else 'false']+'.'
 if mode=='string' and _text(v):return rule['label']+' is '+v+'.'
 if mode=='number':
  if _number(v):return rule['sentence'].format(value=str(v) if type(v)is int else format(v,'.12f').rstrip('0').rstrip('.'))
  if _text(v) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',v):return rule['sentence'].format(value=v)
 if mode=='sequence' and _strings(v):return rule['label']+': '+_items(v)+'.' if v else rule['label']+': none.'
 if mode=='created':
  d=_date(v);clock=_date(e.get(rule['clock']))
  if d and clock and clock>=d:return 'The '+rule['noun']+' was created '+str((clock-d).days)+' days before capture.'
  if d:return 'The '+rule['noun']+' was created on '+d.date().isoformat()+'.'
 if mode=='service_state' and _text(e.get('service')) and e.get('state')in {'ENABLED','DISABLED'}:return 'The '+e['service']+' API is '+e['state'].lower()+'.'
 if mode=='metric_alert':
  alerts=e.get('declared_alerts');links=e.get('alerting');metrics=e.get('matching_metrics')
  if _strings(alerts) and alerts:return 'An enabled log-metric alert is declared for '+rule['event']+'.'
  if _strings(metrics) and metrics and isinstance(links,list) and links and all(isinstance(link,dict) and _text(link.get('alert')) and link.get('metric_type')in metrics for link in links):return 'A log metric for '+rule['event']+' is linked to a configured alert.'
 if mode=='sink':
  sinks=e.get('declared_sinks',e.get('sinks'))
  if _strings(sinks) and sinks:return 'An enabled all-entry project log sink is declared.'
 if mode=='firewall':return _firewall(cid,e)
 if mode=='special':return _special(cid,e)
 return None


def _firewall(cid,e):
 ranges=e.get('source_ranges',e.get('declared_source_ranges'))
 entries=e.get('matching_allow_entries')
 if isinstance(entries,list) and entries and _strings(ranges):
  labels=[]
  for row in entries[:2]:
   if not isinstance(row,dict) or row.get('protocol')not in {'tcp','udp','all','6','17'} or not _text(row.get('ports')):return None
   labels.append(str(row['protocol']).upper()+'/'+row['ports'])
  return 'The firewall rule declares '+', '.join(labels)+' from '+_items(ranges)+'.'
 if entries==[] and isinstance(e.get('ports'),list):return 'No allow entry matches the checked common-port list.'
 if _strings(ranges):
  if type(e.get('port'))is int and 0<=e['port']<=65535:return 'The firewall rule declares TCP/'+str(e['port'])+' from '+_items(ranges)+'.'
  if _strings(e.get('approved_proxy_ranges')):return 'The declared proxy-source ranges are '+_items(ranges)+'.'
  if _strings(e.get('target_tags')) and e['target_tags']:return 'The rule targets instance tags '+_items(e['target_tags'])+'.'
  if _strings(e.get('protocols')):return 'The firewall rule declares protocols '+_items(e['protocols'])+'.'
  if _text(e.get('name')):return 'The firewall rule is named '+e['name']+'.'
 return None


def _special(cid,e):
 if cid=='gcp.claude.kms_key.users_limited_to_3':
  if e.get('public_roles')==[] and e.get('broad_bindings')==[]:return 'The key policy has no public grants or bindings with more than three members.'
 if cid=='gcp.iam.data_access_audit':
  if _strings(e.get('configured_types')) and _strings(e.get('evaluated_scopes')) and e.get('missing_scopes')==[]:return 'The resolved audit policy declares '+_items(e['configured_types'])+' across the assessed hierarchy.'
 if cid=='gcp.ports.audit_logging_configured_for_all_service':
  if _strings(e.get('configured_log_types')) and e.get('exempted_members')==[]:return 'The project audit policy declares '+_items(e['configured_log_types'])+' without exempted members.'
 if cid=='gcp.gke.private_endpoint' and type(e.get('enable_public_endpoint'))is bool:return 'The GKE public IP endpoint is '+('enabled.' if e['enable_public_endpoint'] else 'disabled.')
 if cid=='gcp.gke.private_nodes':
  a,b=e.get('private_cluster_config_private_nodes'),e.get('network_config_default_private_nodes')
  if type(a)is bool and type(b)is bool:return 'Private nodes are '+('enabled' if b else 'disabled')+' in network defaults and '+('enabled' if a else 'disabled')+' in legacy cluster configuration.'
 if cid=='gcp.gke.authorized_networks':
  a,b=e.get('master_authorized_networks_enabled'),e.get('ip_endpoints_authorized_networks_enabled')
  if type(a)is bool and type(b)is bool:return 'Authorized networks are '+('enabled' if b else 'disabled')+' for IP endpoints and '+('enabled' if a else 'disabled')+' in legacy master configuration.'
 if cid in {'gcp.gke.node_pools_gke_metadata','gcp.htbp.gke.kubelet_readonly_port_disabled'}:
  pools=e.get('node_pools')
  if _strings(pools):return str(len(pools))+' node pools were assessed; their '+('metadata modes' if cid=='gcp.gke.node_pools_gke_metadata' else 'read-only-port settings')+' were not stored.'
 if cid=='gcp.ports.compute_instance_shielded_vm_enabled':
  a,b=e.get('enableVtpm'),e.get('enableIntegrityMonitoring')
  if type(a)is bool and type(b)is bool:return 'The VM virtual TPM is '+('enabled' if a else 'disabled')+'; integrity monitoring is '+('enabled.' if b else 'disabled.')
 if cid=='gcp.ports.compute_network_contains_no_legacy_network':
  if 'legacy_ipv4_range'in e and e['legacy_ipv4_range']is None:return 'No legacy-network IPv4 range is declared.'
 if cid=='gcp.ports.iam_api_key_restricts_websites_hosts_apps':
  if e.get('restriction_mode')in {'serverKeyRestrictions','browserKeyRestrictions','androidKeyRestrictions','iosKeyRestrictions'} and _strings(e.get('allowed')):return 'The API key declares '+str(len(e['allowed']))+' caller restrictions using '+e['restriction_mode']+'.'
 if cid=='gcp.gke.control_plane_restricted':
  if e.get('private_endpoint')is True:return 'A private GKE control-plane endpoint is declared.'
  if e.get('authorized_networks_enabled')is True and _strings(e.get('authorized_networks')):return 'The public control-plane endpoint declares authorized networks '+_items(e['authorized_networks'])+'.'
 if cid=='gcp.htbp.kms.destroy_window_not_shortened':
  v=e.get('destroy_scheduled_duration')
  if _text(v) and re.fullmatch(r'[0-9]+s',v):return 'The scheduled key-destruction recovery window is '+f'{int(v[:-1])/86400:g}'+' days.'
 if cid=='gcp.htbp.artifactregistry.virtual_repo_private_precedence':
  a,b=e.get('standard_priorities'),e.get('remote_priorities')
  if isinstance(a,list) and a and isinstance(b,list) and b and all(type(v)is int for v in a+b):return 'The highest private-upstream priority is '+str(max(a))+'; the highest remote-upstream priority is '+str(max(b))+'.'
 if cid=='gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked':
  a,b=e.get('key_creation_blocked'),e.get('key_upload_blocked')
  if type(a)is bool and type(b)is bool:return 'Service-account key creation is '+('blocked' if a else 'not blocked')+'; key upload is '+('blocked.' if b else 'not blocked.')
 if cid=='gcp.htbp.storage.notification_topic_in_bucket_project':
  a,b=e.get('bucket_project'),e.get('topic_project')
  if _text(a) and _text(b):return 'The bucket project is '+a+'; the notification-topic project is '+b+'.'
 return None
