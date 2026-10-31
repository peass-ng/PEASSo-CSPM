import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { selectedConfigurationContentObservation } from "../src/selectedConfigurationContentEvidence";

const proof = JSON.parse(readFileSync(new URL("../../tests/fixtures/public_secret_captures/aws-codebuild-buildspec-runtime-public-native-20261020.json", import.meta.url), "utf8"));
for (const branch of ["pass", "fail", "partial"]) {
  test(`actual public CodeBuild ${branch} stays brief and scoped`, () => {
    const f = structuredClone(proof.cases[branch].findings.find((f: Finding) => f.status !== "UNKNOWN")) as Finding;
    const before = structuredClone(f), text = selectedConfigurationContentObservation(f);
    expect(text).toContain("inline CodeBuild buildspec");
    expect(text!.split(/\s+/).length).toBeLessThanOrEqual(35);
    if (branch === "pass") expect(text).toContain("Both offline detectors");
    else {
      expect(text).toContain("not validated");
      expect(selectedConfigurationContentObservation({ ...f, secret_fingerprint: "0".repeat(64) })).toBeUndefined();
    }
    if (branch === "partial") expect(text).toContain("incomplete");
    expect(f).toEqual(before);
  });
}
