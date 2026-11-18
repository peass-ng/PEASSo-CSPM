import { leakKeys } from "./foundSecretValue";
import type { Finding } from "./types";

const check = "gcp.review.cloudrun_job.declared_image_secret_indicators";
export const jobImageUnknown = "Evidence for the selected Cloud Run Job’s declared image is incomplete or unbound. Secret absence and the executed image were not established; credentials were not validated.";
const limit = "Credentials and the executed image were not verified.";
const project = "[a-z][a-z0-9-]{4,28}[a-z0-9]";
const label = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const suffix = "/locations/[a-z][a-z0-9-]{0,62}/jobs/[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?";
const digest = /^sha256:[0-9a-f]{64}$/;
const versions: Record<string, string> = { kingfisher: "1.4.0", trufflehog: "3.92.5" };
type Row = Record<string, unknown>;
type Leak = { fingerprint: string; detectors: Row[]; locations: Row[] };
const object = (v: unknown): v is Row => v !== null && typeof v === "object" && !Array.isArray(v);
const match = (pattern: string | RegExp, v: unknown): v is string => typeof v === "string" && (typeof pattern === "string" ? new RegExp("^(?:" + pattern + ")$") : pattern).test(v);
const keys = (r: Row, allowed: string[]) => Object.keys(r).every(k => allowed.includes(k));

function leaks(value: unknown, publicFinding: boolean, scope: string): Leak[] | undefined {
  if (!Array.isArray(value) || value.length > 256) return;
  const result: Leak[] = [], seen = new Set<string>();
  let count = 0;
  for (const row of value) {
    if (!object(row) || leakKeys(row) !== "detectors,fingerprint,locations"
        || !match(/^[0-9a-f]{64}$/, row.fingerprint) || seen.has(row.fingerprint)
        || !Array.isArray(row.detectors) || !row.detectors.length || row.detectors.length > 128
        || !Array.isArray(row.locations) || !row.locations.length) return;
    seen.add(row.fingerprint);
    for (const d of row.detectors) {
      if (!object(d) || Object.keys(d).sort().join() !== "engine,rule"
          || typeof d.engine !== "string" || !Object.hasOwn(versions, d.engine)
          || !match(/^[A-Za-z0-9_.:/ -]{1,160}$/, d.rule)) return;
    }
    for (const l of row.locations) {
      if (!object(l) || !keys(l, publicFinding ? ["path", "line", "layer", "resource_id", "scope"] : ["path", "line", "layer"])
          || !match(digest, l.layer) || !match(/^(?:image-config\.json|member-[1-9][0-9]{0,3})$/, l.path)
          || "line" in l && (typeof l.line !== "number" || !Number.isInteger(l.line) || l.line < 1)
          || publicFinding && (l.scope !== scope || !match(scope + suffix + "#container=" + label, l.resource_id))) return;
      count++;
    }
    if (new Set(row.detectors.map(d => JSON.stringify(d))).size !== row.detectors.length
        || new Set(row.locations.map(l => JSON.stringify(l))).size !== row.locations.length) return;
    result.push(row as Leak);
  }
  return count <= 2000 ? result : undefined;
}

/** Actual native declaration facts and the smaller public dedup DTO stay distinct. */
export function gcpCloudRunJobImageObservation(f: Finding): string | undefined {
  if (f.provider !== "gcp" || f.check_id !== check || !["PASS", "FAIL", "UNKNOWN", "DENIED"].includes(f.status)) return;
  if (["UNKNOWN", "DENIED"].includes(f.status)) return jobImageUnknown;
  const e: unknown = f.evidence;
  if (!object(e) || e.credential_validation !== "not_attempted" || !match("projects/" + project, f.scope)) return jobImageUnknown;
  const scope = f.scope, publicFinding = "secret_fingerprint" in f || "linked_check_ids" in f;
  const observed = leaks(e.secret_leaks, publicFinding, scope);
  if (!observed) return jobImageUnknown;
  let text: string;
  if (publicFinding) {
    if (f.status !== "FAIL" || f.linked_check_ids?.length !== 1 || f.linked_check_ids[0] !== check
        || !match(/^[0-9a-f]{64}$/, f.secret_fingerprint) || f.resource_id !== "secret:" + f.secret_fingerprint
        || observed.length !== 1 || observed[0].fingerprint !== f.secret_fingerprint
        || "complete" in e && typeof e.complete !== "boolean"
        || (e.complete === false) !== (e.coverage === "incomplete")) return jobImageUnknown;
    text = "A likely secret was detected in image bytes linked to the selected Cloud Run Job declaration.";
  } else {
    const d = e.job_declaration, image = e.image_uri;
    const component = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
    const imagePattern = "[a-z0-9-]+-docker\\.pkg\\.dev/" + scope.slice(9) + "/[a-z][a-z0-9_-]{0,62}/" + component + "(?:/" + component + ")*@sha256:[0-9a-f]{64}";
    if (e.association_kind !== "desired_digest_declaration" || e.runtime_association_status !== "UNKNOWN"
        || !("observed_runtime_digest" in e) || e.observed_runtime_digest !== null || e.deployed_bytes_proven !== false
        || typeof e.complete !== "boolean" || !object(d) || d.api_version !== "run.googleapis.com/v2" || d.kind !== "Job"
        || d.project_id !== scope.slice(9) || !match(scope + suffix, d.name) || !match(label, d.container_name)
        || !match(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, d.uid)
        || !match(/^[1-9][0-9]{0,18}$/, d.generation) || typeof d.etag !== "string" || !d.etag.length || d.etag.length > 256
        || !match(/^\/template\/template\/containers\/(?:[0-9]|1[0-5])\/image$/, d.image_json_pointer)
        || typeof image !== "string" || image.length > 512 || !match(imagePattern, image)) return jobImageUnknown;
    const engines = e.config_engines, layers = e.layer_coverage, requests = e.source_requests;
    if (!Array.isArray(engines) || engines.length !== 2 || engines.some(r => !object(r)
          || Object.keys(r).sort().join() !== "engine,status,version" || typeof r.engine !== "string"
          || !Object.hasOwn(versions, r.engine) || versions[r.engine] !== r.version || !["complete", "unavailable"].includes(String(r.status)))
        || new Set(engines.map(r => r.engine)).size !== 2 || !Array.isArray(layers) || !layers.length || layers.length > 16
        || layers.some(r => !object(r) || !match(digest, r.digest) || !["complete", "unavailable"].includes(String(r.status)))
        || !Array.isArray(requests) || requests.length < 10 || requests.length > 26 || new Set(requests).size !== requests.length
        || requests.some(r => !match(/^request-[1-9][0-9]*$/, r)) || (f.status === "FAIL") !== !!observed.length
        || e.complete && [...engines, ...layers].some(r => r.status !== "complete")) return jobImageUnknown;
    if (f.status === "PASS") return e.complete
      ? "Both offline detectors found no supported secret in the immutable image declared by the selected Cloud Run Job container. Credentials and the executed image were not verified."
      : jobImageUnknown;
    text = "A likely secret was detected in the immutable image declared by the selected Cloud Run Job container.";
  }
  if (e.complete === false) text += " Inspection is incomplete.";
  return text + " " + limit;
}
