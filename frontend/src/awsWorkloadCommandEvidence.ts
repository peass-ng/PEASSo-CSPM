import { leakKeys } from "./foundSecretValue";
import type { Finding } from "./types";
const CHECK = "aws.review.workload.selected_command_literal_secret_indicators";
const unknown = new Set([
  "Selected command literal coverage was incomplete. Secret absence could not be assessed.",
  "Selected command literal evidence was unavailable. Secret absence could not be assessed.",
  "Selected command literal evidence was missing, unsupported, incomplete or unbound. Secret absence could not be assessed.",
  "Selected ECS/classic Batch command evidence was unavailable, incomplete or unbound; images, environment files and EKS Batch are outside this check.",
]);
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
export function awsWorkloadCommandObservation(f: Finding): string | undefined {
  const e = f.evidence;
  if (f.provider !== "aws" || f.check_id !== CHECK || !object(e)) return;
  if (f.status === "UNKNOWN" && typeof e.observed === "string" && unknown.has(e.observed))
    return "The selected ECS or Batch command literals could not be completely inspected.";
  if (e.credential_validation !== "not_attempted" || !Array.isArray(e.secret_leaks)) return;
  if (f.status === "PASS" && !e.secret_leaks.length && e.complete === true && e.coverage === "selected_definition_command_literals_only")
    return "Both offline detectors found no supported secret in the selected ECS or Batch command literals.";
  const leak = e.secret_leaks[0];
  if (f.status !== "FAIL" || e.secret_leaks.length !== 1 || !object(leak)
      || leakKeys(leak) !== "detectors,fingerprint,locations"
      || typeof leak.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(leak.fingerprint)
      || f.secret_fingerprint !== leak.fingerprint || f.linked_check_ids?.length !== 1 || f.linked_check_ids[0] !== CHECK
      || !Array.isArray(leak.detectors) || !leak.detectors.length || !leak.detectors.every(d => object(d)
        && Object.keys(d).sort().join(",") === "engine,rule" && ["kingfisher", "trufflehog"].includes(String(d.engine))
        && typeof d.rule === "string" && /^[A-Za-z0-9_.:/ -]{1,160}$/.test(d.rule))
      || !Array.isArray(leak.locations) || !leak.locations.length || !leak.locations.every(l => object(l)
        && Object.keys(l).every(k => ["path", "line", "resource_id", "scope"].includes(k))
        && typeof l.resource_id === "string" && /^aws_selected_workload_command_literals:leak:[0-9a-f]{64}$/.test(l.resource_id)
        && typeof l.path === "string" && /^aws_selected_workload_command_literals:[0-9a-f]{64}:[0-9a-f]{64}$/.test(l.path)
        && typeof l.scope === "string" && /^[0-9]{12}\/[a-z0-9-]+$/.test(l.scope)
        && (l.line === undefined || typeof l.line === "number" && Number.isInteger(l.line) && l.line > 0))) return;
  if (e.complete === false && e.coverage !== "incomplete") return;
  return "A likely secret was detected in selected ECS or Batch command literals. It was not validated"
    + (e.complete === false ? "; inspection is incomplete." : ".");
}
