import { leakKeys } from "./foundSecretValue";
import type { Finding } from "./types";
import profile from "../../peaso/checks/gcp_consolidated_secret_profiles_20261020.json" with { type: "json" };
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const allowed = new Set<string>(profile.checks);
const subjects: Record<string, string> = profile.subjects;
export function gcpConsolidatedSecretObservation(finding: Finding): string | undefined {
  const e = finding.evidence, linked = finding.linked_check_ids;
  if (finding.provider !== "gcp" || finding.status !== "FAIL" || !allowed.has(finding.check_id) || !object(e)
      || !linked?.length || new Set(linked).size !== linked.length || !linked.includes(finding.check_id) || !linked.every(id => allowed.has(id))) return;
  const partial = e.complete === false && e.coverage === "incomplete";
  if (Object.keys(e).sort().join(",") !== (partial ? "complete,coverage,credential_validation,observed,secret_leaks" : "credential_validation,observed,secret_leaks")
      || e.credential_validation !== "not_attempted" || !Array.isArray(e.secret_leaks) || e.secret_leaks.length !== 1) return;
  const leak = e.secret_leaks[0];
  if (!object(leak) || leakKeys(leak) !== "detectors,fingerprint,locations"
      || typeof leak.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(leak.fingerprint) || finding.secret_fingerprint !== leak.fingerprint
      || !Array.isArray(leak.detectors) || !leak.detectors.length || !Array.isArray(leak.locations) || !leak.locations.length) return;
  if (!leak.detectors.every(d => object(d) && Object.keys(d).sort().join(",") === "engine,rule"
      && ["kingfisher", "trufflehog"].includes(String(d.engine)) && typeof d.rule === "string" && /^[A-Za-z0-9_.:/ -]{1,160}$/.test(d.rule))
      || new Set(leak.detectors.map(d => `${d.engine}\0${d.rule}`)).size !== leak.detectors.length) return;
  const fields = ["path", "line", "layer", "timestamp", "resource_id", "scope"];
  if (!leak.locations.every(loc => object(loc) && typeof loc.path === "string" && loc.path.length > 0
      && Object.entries(loc).every(([key, value]) => fields.includes(key)
        && (["line", "timestamp"].includes(key) ? typeof value === "number" && Number.isInteger(value) && value >= (key === "line" ? 1 : 0)
          : typeof value === "string" && value.length > 0 && value.length <= 4096)))
      || new Set(leak.locations.map(loc => JSON.stringify(fields.map(key => loc[key])))).size !== leak.locations.length) return;
  const count = leak.locations.length;
  const retained = typeof leak.value === "string"
    ? ` Its matched value is shown in clear text so it can be rotated${leak.value_truncated === true ? ` (first ${leak.value.length} characters).` : "."}`
    : " This scan did not retain its matched value.";
  // Reports stored before found values were shown say "Its value is hidden.".
  const legacy = typeof leak.value === "string" ? [] : [" Its value is hidden."];
  if (![retained, ...legacy].some(text =>
    e.observed === `The same secret was detected in ${count} scanned location(s).${text}${partial ? " Coverage is incomplete." : ""}`)) return;
  const locators: Record<string, {kind: string; prefix: string; part: boolean}> = profile.locators;
  if (linked.every(id => id in locators)) {
    const seen = new Set<string>();
    for (const loc of leak.locations) {
      if (typeof loc.scope !== "string" || !/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(loc.scope)) return;
      const matches = linked.filter(id => {
        const item = locators[id];
        const suffix = item.part ? "\\.part-(?:[1-9][0-9]?|100)" : "\\.source";
        const match = new RegExp(`^(${item.prefix}:[0-9a-f]{64})${suffix}$`).exec(String(loc.path));
        return match && loc.resource_id === `//gcp/${loc.scope}/global/${item.kind}/${match[1]}`;
      });
      if (matches.length !== 1) return;
      seen.add(matches[0]);
    }
    if (seen.size !== linked.length) return;
  }
  const subject = linked.length === 1 && subjects[linked[0]] ? subjects[linked[0]]
    : linked.every(id => id in subjects) ? `selected ${[...new Set(linked.map(id => subjects[id].split(" ")[2]))].sort().join(" and ")} sources`
      : `${count} selected source ${count === 1 ? "location" : "locations"}`;
  return `A likely secret was detected in ${subject}. It was not validated${partial ? "; inspection is incomplete." : "."}`;
}
