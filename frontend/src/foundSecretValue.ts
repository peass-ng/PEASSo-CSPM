/** Found secrets are shown in clear text so the tenant can rotate them. */
export type FoundSecretValue = { fingerprint: string; value: string; value_truncated?: true; context?: string };
const FOUND_FIELDS = ["value", "value_truncated", "context"];
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown) => typeof v === "string" && v.length > 0;

/** Sorted structural keys of a secret leak; "" when its optional found-value fields are malformed. */
export function leakKeys(leak: Record<string, unknown>): string {
  if (("value" in leak && !text(leak.value)) || ("context" in leak && !text(leak.context))
      || ("value_truncated" in leak && leak.value_truncated !== true)) return "";
  return Object.keys(leak).filter(key => !FOUND_FIELDS.includes(key)).sort().join(",");
}

/** The clear-text values carried by a finding's grouped secret leaks. */
export function foundSecretValues(evidence: unknown): FoundSecretValue[] {
  const leaks = object(evidence) && Array.isArray(evidence.secret_leaks) ? evidence.secret_leaks : [];
  return leaks.flatMap((leak): FoundSecretValue[] => object(leak) && typeof leak.fingerprint === "string" && text(leak.value) && leakKeys(leak)
    ? [{ fingerprint: leak.fingerprint, value: leak.value as string,
        ...(leak.value_truncated === true ? { value_truncated: true as const } : {}),
        ...(text(leak.context) ? { context: leak.context as string } : {}) }]
    : []);
}
