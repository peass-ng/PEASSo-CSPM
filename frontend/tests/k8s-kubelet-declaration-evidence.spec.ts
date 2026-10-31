import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";
import { kubeletDeclarationObservation } from "../src/k8sKubeletDeclarationEvidence";
const rules = JSON.parse(readFileSync(new URL("../../peaso/checks/k8s_kubelet_declaration_observed_20261020.json", import.meta.url), "utf8"));
for (const [id, row] of Object.entries(rules) as [string, { field: string; PASS: string; FAIL: string }][]) {
  test(`${id}: brief declaration and malformed guard`, () => {
    for (const status of ["PASS", "FAIL"] as const) {
      const evidence = { observed: row[status], field: row.field, scope: "native_named_configmap_declaration_only", raw_content_retained: false };
      const finding = { provider: "k8s", check_id: id, status, evidence } as unknown as Finding;
      expect(explainObservedEvidence(finding, "fallback")).toBe(row[status]);
      for (const [key, value] of Object.entries({ observed: "All nodes are secure.", field: "unknown", scope: "node_runtime", raw_content_retained: true })) {
        expect(kubeletDeclarationObservation({ ...finding, evidence: { ...evidence, [key]: value } } as unknown as Finding)).toBeUndefined();
      }
      expect(kubeletDeclarationObservation({ ...finding, status: status === "PASS" ? "FAIL" : "PASS" })).toBeUndefined();
    }
  });
}

const uncertainCases = JSON.parse(readFileSync(new URL("../../tests/fixtures/k8s-kubelet-unknown-native-observations-20261020.json", import.meta.url), "utf8"));
for (const [id, rows] of Object.entries(uncertainCases) as [string, Record<string, Finding>][]) {
  test(`${id}: actual UNKNOWN and empty declaration stay uncertain`, () => {
    for (const finding of Object.values(rows)) {
      const before = structuredClone(finding);
      const summary = kubeletDeclarationObservation(finding);
      expect(summary).toContain("Node configuration was not assessed.");
      expect(summary!.split(/\s+/).length).toBeLessThan(40);
      expect(explainObservedEvidence(finding, "fallback")).toBe(summary);
      expect(finding).toEqual(before);
      for (const [key, value] of Object.entries({ observed: "Nodes are secure.", field: "invented", scope: "node_runtime", raw_content_retained: true }))
        expect(kubeletDeclarationObservation({ ...finding, evidence: { ...finding.evidence, [key]: value } } as Finding)).toBeUndefined();
      for (const status of ["PASS", "FAIL", "DENIED"] as const)
        expect(kubeletDeclarationObservation({ ...finding, status })).toBeUndefined();
    }
  });
}
