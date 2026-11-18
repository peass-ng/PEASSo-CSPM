import { leakKeys } from "./foundSecretValue";
import { awsWorkloadCommandObservation } from "./awsWorkloadCommandEvidence";
import { gcpConsolidatedSecretObservation } from "./gcpConsolidatedSecretEvidence";
import { azureConfiguredPackageObservation } from "./azureConfiguredPackageEvidence";
import { publicSourceSecretObservation } from "./publicSourceSecretEvidence";
import type { Finding } from "./types";
const rules: Record<string, readonly [string, string, string]> = {
  "aws.review.codebuild.selected_inline_buildspec_secret_indicators": ["aws", "selected_returned_inline_buildspec_only", "the selected inline CodeBuild buildspec"],
  "gcp.review.dataflow.selected_package_referenced_source_secret_indicators": ["gcp", "selected_current_referenced_package_only", "the selected Dataflow package source"],
  "gcp.review.batch.selected_mounted_script_source_secret_indicators": ["gcp", "selected_captured_mounted_script_source_only", "the selected Batch mounted script source"],
  "gcp.review.workbench.selected_referenced_source_secret_indicators_20261020": ["gcp", "selected_captured_referenced_source_only", "the selected Workbench referenced source"],
  "k8s.review.selected_metadata.secret_indicators": ["k8s", "selected_object_metadata_only", "the selected object labels and annotations"],
 "gcp.review.dataproc.selected_job_referenced_source_secret_indicators": ["gcp", "selected_captured_referenced_source_only", "the selected Dataproc referenced source"],
 "gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators": ["gcp", "selected_captured_referenced_source_only", "the selected Dataproc referenced source"],
  "azure.review.machine_learning.selected_code_file_secret_indicators": ["azure", "selected_captured_ml_asset_text_only", "the selected associated code file"],
  "azure.review.machine_learning.selected_environment_conda_secret_indicators": ["azure", "selected_captured_ml_asset_text_only", "the selected inline Conda text"],
  "azure.review.databricks.selected_notebook_source_secret_indicators": ["azure", "selected_notebook_export_only", "the selected Databricks notebook source"],
  "k8s.review.selected_container_logs.secret_indicators": ["k8s", "selected_current_container_sample_only", "selected current-container log samples and resource names"],
  "azure.review.machine_learning.selected_command_job_secret_indicators": ["azure", "selected_command_environment_declarations_only", "selected Machine Learning Command-job literals"],
  "aws.review.s3.selected_source_secret_indicators": ["aws", "selected_s3_source_text_only", "the selected S3 source text"],
  "azure.review.log_analytics.selected_message_sample_secret_indicators": ["azure", "selected_message_sample_only", "the selected Log Analytics message sample"],
  "azure.review.application_insights.selected_trace_sample_secret_indicators": ["azure", "selected_message_sample_only", "the selected Application Insights trace sample"],
  "azure.review.app_configuration.selected_value_secret_indicators": ["azure", "selected_public_literals_only", "the selected App Configuration value"],
  "azure.review.data_factory.selected_declaration_secret_indicators": ["azure", "selected_public_literals_only", "selected Data Factory declarations"],
  "azure.review.synapse.selected_pipeline_secret_indicators": ["azure", "selected_public_literals_only", "the selected Synapse pipeline"],
  "aws.review.configuration.selected_content_secret_indicators": ["aws", "selected_returned_literals_only", "selected AWS configuration literals"],
  "azure.review.configuration.selected_content_secret_indicators": ["azure", "selected_arm_literals_only", "selected Azure configuration literals"],
  "azure.review.storage.selected_source_secret_indicators": ["azure", "selected_captured_stored_source_only", "the selected Azure stored source"],
  "azure.review.devops.selected_content_secret_indicators": ["azure", "selected_devops_literals_only", "selected Azure DevOps literals"],
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const validLeak = (leak: unknown): boolean => {
  if (!object(leak) || leakKeys(leak) !== "detectors,fingerprint,locations"
      || typeof leak.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(leak.fingerprint)
      || !Array.isArray(leak.detectors) || !leak.detectors.length || !Array.isArray(leak.locations) || !leak.locations.length) return false;
  if (!leak.detectors.every(d => object(d) && Object.keys(d).sort().join(",") === "engine,rule"
      && ["kingfisher", "trufflehog"].includes(String(d.engine)) && typeof d.rule === "string" && /^[A-Za-z0-9_.:/ -]{1,160}$/.test(d.rule))) return false;
  return leak.locations.every(location => object(location) && typeof location.path === "string"
    && Object.entries(location).every(([field, value]) => ["path", "line", "layer", "timestamp", "resource_id", "scope"].includes(field)
      && (["line", "timestamp"].includes(field) ? typeof value === "number" && Number.isInteger(value) && value >= (field === "line" ? 1 : 0)
        : typeof value === "string" && value.length > 0 && value.length <= 4096)));
};
/** Only complete, coherent detector facts support an absence sentence. */
export function selectedConfigurationContentObservation(finding: Finding): string | undefined {
  const command = awsWorkloadCommandObservation(finding);
  if (command) return command;
  const grouped = publicSourceSecretObservation(finding);
  if (grouped) return grouped;
  const configured = azureConfiguredPackageObservation(finding);
  if (configured) return configured;
  const consolidated = gcpConsolidatedSecretObservation(finding);
  if (consolidated) return consolidated;
  const rule = rules[finding.check_id], e = finding.evidence;
  const mergedPartial = object(e) && e.complete === false && e.coverage === "incomplete";
  const mergedHit = object(e) && !("complete" in e) && !("coverage" in e);
  if (finding.provider === "aws" && finding.check_id === "aws.review.codebuild.selected_inline_buildspec_secret_indicators"
      && finding.status === "FAIL" && object(e) && (mergedPartial || mergedHit) && e.credential_validation === "not_attempted") {
    if (finding.linked_check_ids?.length !== 1 || finding.linked_check_ids[0] !== finding.check_id
        || !Array.isArray(e.secret_leaks) || e.secret_leaks.length !== 1 || !validLeak(e.secret_leaks[0])) return;
    const leak = e.secret_leaks[0] as Record<string, unknown>;
    if (finding.secret_fingerprint !== leak.fingerprint || !(leak.locations as Record<string, unknown>[]).every(loc =>
        typeof loc.resource_id === "string" && /^codebuild_selected_inline_buildspec:[0-9a-f]{64}$/.test(loc.resource_id)
        && loc.path === loc.resource_id + ".source.buildspec" && typeof loc.scope === "string" && /^[0-9]{12}\/[a-z0-9-]+$/.test(loc.scope))) return;
    return "A likely secret was detected in the selected inline CodeBuild buildspec. It was not validated"
      + (mergedPartial ? "; inspection is incomplete." : ".");
  }
  if (finding.provider === "k8s" && finding.check_id === "k8s.review.selected_metadata.secret_indicators" && finding.status === "FAIL"
      && object(e) && (mergedPartial || mergedHit) && e.credential_validation === "not_attempted") {
    if (finding.linked_check_ids?.length !== 1 || finding.linked_check_ids[0] !== finding.check_id
        || !Array.isArray(e.secret_leaks) || e.secret_leaks.length !== 1 || !validLeak(e.secret_leaks[0])) return;
    const leak = e.secret_leaks[0] as Record<string, unknown>;
    if (finding.secret_fingerprint !== leak.fingerprint || !(leak.locations as Record<string, unknown>[]).every(loc =>
        typeof loc.resource_id === "string" && /^k8s_selected_metadata:[0-9a-f]{64}$/.test(loc.resource_id)
        && loc.path === loc.resource_id + ".literals")) return;
    return "A likely secret was detected in the selected object labels or annotations. It was not validated"
      + (mergedPartial ? "; inspection is incomplete." : ".");
  }
  const partial = finding.check_id === "k8s.review.selected_metadata.secret_indicators" && finding.status === "FAIL"
    && object(e) && e.complete === false && e.coverage === "incomplete_selected_object_metadata";
  if (!rule || rule[0] !== finding.provider || !["PASS", "FAIL"].includes(finding.status) || !object(e)
      || (!partial && (e.complete !== true || e.coverage !== rule[1])) || e.credential_validation !== "not_attempted") return;
  const parts = rule[0] === "aws" && ["selected_returned_literals_only", "selected_returned_inline_buildspec_only"].includes(rule[1]) ? [{ complete: true, engines: e.engines }] : e.parts;
  if (!Array.isArray(parts) || !parts.length || parts.length > 256) return;
  if (partial && parts.length !== 1) return;
  const versions: Record<string, string> = { kingfisher: "1.4.0", trufflehog: "3.92.5" };
  let completed = new Set<string>();
  for (const part of parts) {
    if (!object(part) || !Array.isArray(part.engines) || part.engines.length !== 2) return;
    const names = new Set<string>();
    completed = new Set<string>();
    for (const engine of part.engines) {
      if (!object(engine) || typeof engine.engine !== "string" || versions[engine.engine] !== engine.version
          || !(partial ? ["complete", "unavailable"] : ["complete"]).includes(String(engine.status))) return;
      names.add(engine.engine);
      if (engine.status === "complete") completed.add(engine.engine);
    }
    if (names.size !== 2 || !completed.size || (partial ? typeof part.complete !== "boolean" || part.complete !== (completed.size === 2) : part.complete !== true)) return;
  }
  if (!Array.isArray(e.secret_leaks) || (finding.status === "FAIL") !== (e.secret_leaks.length > 0)
      || !e.secret_leaks.every(validLeak)
      || new Set(e.secret_leaks.map(leak => object(leak) ? leak.fingerprint : undefined)).size !== e.secret_leaks.length) return;
  if (partial) {
    if (e.secret_leaks.some(leak => !object(leak) || !Array.isArray(leak.detectors)
        || leak.detectors.some(d => !object(d) || !completed.has(String(d.engine))))) return;
    return `A likely secret was detected in ${rule[2]}. It was not validated; inspection is incomplete.`;
  }
  return e.secret_leaks.length ? `A likely secret was detected in ${rule[2]}. It was not validated.`
    : `Both offline detectors found no supported secret in ${rule[2]}.`;
}
