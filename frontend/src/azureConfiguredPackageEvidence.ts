import { leakKeys } from "./foundSecretValue";
import type { Finding } from "./types";
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const keys = (v: Record<string, unknown>, names: string) => Object.keys(v).sort().join(",") === names;
const versions: Record<string, string> = { kingfisher: "1.4.0", trufflehog: "3.92.5" };
type Leak = { fingerprint: string; detectors: { engine: string; rule: string }[]; locations: { path: string }[] };
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
function normalizedLeaks(value: unknown): Leak[] | undefined {
  if (!Array.isArray(value) || value.length > 128) return;
  const result: Leak[] = [];
  for (const row of value) {
    if (!object(row) || leakKeys(row) !== "detectors,fingerprint,locations" || typeof row.fingerprint !== "string"
        || !Array.isArray(row.detectors) || row.detectors.length > 256 || !Array.isArray(row.locations) || row.locations.length > 512) return;
    const detectors: Leak["detectors"] = [], locations: Leak["locations"] = [];
    for (const d of row.detectors) {
      if (!object(d) || !keys(d, "engine,rule") || typeof d.engine !== "string" || typeof d.rule !== "string") return;
      detectors.push({ engine: d.engine, rule: d.rule });
    }
    for (const l of row.locations) {
      if (!object(l) || !keys(l, "path") || typeof l.path !== "string") return;
      locations.push({ path: l.path });
    }
    result.push({ fingerprint: row.fingerprint, detectors: detectors.sort((a,b) => compare(a.engine,b.engine) || compare(a.rule,b.rule)),
      locations: locations.sort((a,b) => compare(a.path,b.path)) });
  }
  return result.sort((a,b) => compare(a.fingerprint,b.fingerprint));
}

/** Inspect native per-member facts; a partial negative never supplies clean prose. */
export function azureConfiguredPackageObservation(finding: Finding): string | undefined {
  if (finding.check_id !== "azure.review.function.selected_package_source_secret_indicators" || finding.provider !== "azure"
      || !["PASS", "FAIL"].includes(finding.status)) return;
  const e = finding.evidence;
  if (!object(e) || typeof e.complete !== "boolean" || e.coverage !== "selected_configured_stored_package_only"
      || e.credential_validation !== "not_attempted" || e.runtime_bytes !== "unknown" || e.cloud_authenticity !== "not_established"
      || !Array.isArray(e.parts) || e.parts.length < 1 || e.parts.length > 128) return;
  const first = e.parts[0];
  if (!object(first) || typeof first.path !== "string") return;
  const stem = /^(azure_storage_selected_source:[0-9a-f]{64})\.file-1$/.exec(first.path)?.[1];
  if (!stem) return;
  const merged = new Map<string, Leak>();
  let bytes = 0;
  for (const [i, part] of e.parts.entries()) {
    if (!object(part) || !keys(part, "bytes,complete,engines,leaks,path") || part.path !== `${stem}.file-${i + 1}`
        || typeof part.bytes !== "number" || !Number.isInteger(part.bytes) || part.bytes < 1 || part.bytes > 1048576
        || typeof part.complete !== "boolean" || !Array.isArray(part.engines) || part.engines.length !== 2
        || !Array.isArray(part.leaks) || part.leaks.length > 128) return;
    bytes += part.bytes;
    const completed = new Set<string>();
    for (const [n, engine] of part.engines.entries()) {
      const name = Object.keys(versions)[n];
      if (!object(engine) || !keys(engine, "engine,status,version") || engine.engine !== name || engine.version !== versions[name]
          || !["complete", "unavailable"].includes(String(engine.status))) return;
      if (engine.status === "complete") completed.add(name);
    }
    if (part.complete !== (completed.size === 2) || (e.complete && !part.complete)) return;
    let previous = "";
    for (const leak of part.leaks) {
      if (!object(leak) || leakKeys(leak) !== "detectors,fingerprint,locations" || typeof leak.fingerprint !== "string"
          || !/^[0-9a-f]{64}$/.test(leak.fingerprint) || leak.fingerprint <= previous || !Array.isArray(leak.detectors)
          || !leak.detectors.length || leak.detectors.length > 128 || !Array.isArray(leak.locations)
          || JSON.stringify(leak.locations) !== JSON.stringify([{ path: part.path }])) return;
      previous = leak.fingerprint;
      const seen = new Set<string>();
      for (const d of leak.detectors) {
        if (!object(d) || !keys(d, "engine,rule") || typeof d.engine !== "string" || !completed.has(d.engine)
            || typeof d.rule !== "string" || !/^[A-Za-z0-9_.:/ -]{1,160}$/.test(d.rule) || d.rule.includes("://")) return;
        const key = JSON.stringify([d.engine, d.rule]);
        if (seen.has(key)) return;
        seen.add(key);
      }
      const row = merged.get(leak.fingerprint) || { fingerprint: leak.fingerprint, detectors: [], locations: [] };
      for (const d of leak.detectors as Leak["detectors"]) if (!row.detectors.some(x => x.engine === d.engine && x.rule === d.rule)) row.detectors.push({ ...d });
      if (!row.locations.some(x => x.path === part.path)) row.locations.push({ path: String(part.path) });
      merged.set(leak.fingerprint, row);
    }
  }
  const expected = normalizedLeaks([...merged.values()])!;
  if (bytes > 8388608 || expected.length > 128 || expected.reduce((sum,l) => sum + l.locations.length,0) > 512
      || JSON.stringify(expected) !== JSON.stringify(normalizedLeaks(e.secret_leaks))
      || (finding.status === "FAIL") !== Boolean(expected.length) || (!e.complete && finding.status !== "FAIL")) return;
  return expected.length ? "A likely secret was detected in the selected stored deployment package. It was not validated"
    + (e.complete ? "." : "; inspection is incomplete.")
    : "Both offline detectors found no supported secret in the selected stored deployment package.";
}
