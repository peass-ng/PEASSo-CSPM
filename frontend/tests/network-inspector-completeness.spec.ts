import { expect, test } from "@playwright/test";
import type { Graph } from "../src/types";
import { networkModel, networkView } from "../src/networkPresentation";

const projectedId = "analysis:cccccccccccccccccccccccc";
const nativeId = (index: number) => `analysis:${(index + 1).toString(16).padStart(24, "0")}`;
const projectedMemberId = (index: number) => `analysis:${(index + 1001).toString(16).padStart(24, "0")}`;

function fixture(): Graph {
  const scope = "444444444444/us-east-1";
  return { nodes: [
    { id: "many-vpc-a", label: "many-vpc-a", type: "vpc", provider: "aws", scope },
    { id: "many-vpc-b", label: "many-vpc-b", type: "vpc", provider: "aws", scope },
    { id: "many-sg", label: "many-sg", type: "security_group", provider: "aws", scope, parent_id: "many-vpc-a" },
    ...Array.from({ length: 125 }, (_, i) => ({ id: `eni-${i}`, label: `eni-${i}`, type: "network_interface", provider: "aws", scope, parent_id: "many-vpc-a" })),
  ], edges: [
    ...Array.from({ length: 125 }, (_, i) => ({ id: nativeId(i), source: "many-vpc-a", target: "many-vpc-b", type: "declared_network_reference", evidence: { source: { path: `native.path.${i}` } } })),
    { id: projectedId, source: "many-vpc-a", target: "many-vpc-b", type: "declared_network_reference", aggregate: true, underlying_count: 7, edge_refs: Array.from({ length: 7 }, (_, i) => projectedMemberId(i)) },
    ...Array.from({ length: 125 }, (_, i) => ({ id: `attachment-${i}`, source: "many-sg", target: `eni-${i}`, type: "protected_by" })),
  ] };
}

async function clickDeclaredRelationship(page: import("@playwright/test").Page) {
  const sourceNode = page.locator('.react-flow__node[data-id="network:many-vpc-a"]');
  const targetNode = page.locator('.react-flow__node[data-id="network:many-vpc-b"]');
  await expect(sourceNode).toBeVisible();
  await expect(targetNode).toBeVisible();
  const source = await sourceNode.boundingBox();
  const target = await targetNode.boundingBox();
  if (!source || !target) throw new Error("Network edge endpoints were not rendered");
  // Click the drawn line between the source and target handles, as a user does.
  await page.mouse.click((source.x + source.width + target.x) / 2, source.y + source.height / 2);
  await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
}

test("relationship membership retains all loaded indices and distinguishes unresolved projection references", () => {
  const graph = fixture();
  const edge = networkView(networkModel(graph), "aws", "", "", "").edges.find(item => item.type === "declared_network_reference")!;
  expect(edge.count).toBe(132);
  expect(edge.availableCount).toBe(125);
  expect(edge.unresolvedCount).toBe(7);
  expect(edge.records).toHaveLength(20);
  expect(edge.recordIndices).toHaveLength(126);
  expect(edge.recordIndices.map(index => graph.edges[index].id)).toContain(nativeId(124));
  expect(edge.recordIndices.map(index => graph.edges[index].id)).toContain(projectedId);
});

test("relationship and attachment inspectors page through the final loaded records without raw JSON", async ({ page }) => {
  const graph = fixture();
  const explicitBatches: string[][] = [];
  await page.route("**/api/**", route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path.endsWith("/graphs/network/edges")) {
      const ids = url.searchParams.getAll("ids");
      explicitBatches.push(ids);
      return route.fulfill({ json: { items: ids.map(id => ({ id, type: "declared_network_reference", layer: "structural", confidence: "high", source: { id: "many-vpc-a", label: "many-vpc-a" }, target: { id: "many-vpc-b", label: "many-vpc-b" }, evidence_refs: [{ path: `record.${id}` }], evidence_status: "source_reference" })), total: ids.length, next_cursor: null, group_id: null, snapshot_id: "snapshot-one" } });
    }
    const json = path.endsWith("/scans") ? { items: [{ id: "network-scan", status: "completed", categories: ["network"], created_at: "2026-01-01" }] }
      : path.endsWith("/summary") ? { resources: [], findings: [], coverage: [], graphs: {}, stats: {} }
      : path.endsWith("/graphs/network") ? graph
      : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/me") ? { email: "tester@example.test", plan: "test" }
      : { items: [] };
    return route.fulfill({ json });
  });
  await page.goto("/#Network%20Map");
  await expect(page.getByRole("tab", { name: /AWS/ })).toBeVisible();
  await clickDeclaredRelationship(page);
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("132 represented supplied relationships");
  await expect(dialog).toContainText("125 loaded individual records");
  await expect(dialog).toContainText("7 underlying records not loaded in the graph");
  await expect(dialog.locator('[aria-label="Loaded relationship records"] tbody tr')).toHaveCount(100);
  await dialog.getByRole("button", { name: "Load native details for 100 records on this page" }).click();
  await expect(dialog.locator('[aria-label="Native relationship details"] tbody tr')).toHaveCount(100);
  expect(explicitBatches[0]).toHaveLength(100);
  await dialog.getByRole("button", { name: "Next relationship page" }).click();
  await expect(dialog).toContainText("Loaded records 101–126 of 126");
  await expect(dialog.locator('[aria-label="Loaded relationship records"]')).toContainText(nativeId(124));
  await expect(dialog.locator('[aria-label="Loaded relationship records"]')).toContainText(projectedId);
  await dialog.getByRole("button", { name: "Load native details for 25 records on this page" }).click();
  await expect(dialog.locator('[aria-label="Native relationship details"] tbody tr')).toHaveCount(25);
  expect(explicitBatches[1]).toHaveLength(25);
  expect(explicitBatches[1].at(-1)).toBe(nativeId(124));
  await expect(dialog.locator("pre")).toHaveCount(0);
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByLabel("Search loaded network resources").fill("many-sg");
  await page.locator(".network-table-row").getByRole("button", { name: /many-sg/ }).click();
  await expect(dialog).toContainText("Loaded attachment records · 125");
  await expect(dialog.locator('[aria-label="Loaded attachment records"] tbody tr')).toHaveCount(100);
  await dialog.getByRole("button", { name: "Next attachment page" }).click();
  await expect(dialog).toContainText("Attachment records 101–125 of 125");
  await expect(dialog.locator('[aria-label="Loaded attachment records"]')).toContainText("eni-124");
  await expect(dialog.locator("pre")).toHaveCount(0);
  const disclosure = dialog.locator('details').last();
  const readingFont = (element: Element) => {
    const style = getComputedStyle(element);
    return { family: style.fontFamily, size: style.fontSize, lineHeight: style.lineHeight };
  };
  expect(await disclosure.locator('summary').evaluate(readingFont)).toEqual(await disclosure.evaluate(readingFont));
});

test("stored projected group cursor reaches its final native member", async ({ page }) => {
  const graph = fixture();
  graph.edges[125] = { ...graph.edges[125], underlying_count: 125, edge_refs: Array.from({ length: 125 }, (_, i) => projectedMemberId(i)) };
  let requestedCursor = "";
  await page.route("**/api/**", route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path.endsWith("/graphs/network/edges")) {
      requestedCursor = url.searchParams.get("cursor") || "";
      const offset = Number(requestedCursor || 0);
      const items = Array.from({ length: Math.min(100, 125 - offset) }, (_, i) => ({
        id: projectedMemberId(offset + i), type: "declared_network_reference", source: { id: "many-vpc-a", label: "many-vpc-a" },
        target: { id: "many-vpc-b", label: "many-vpc-b" }, evidence_refs: [{ path: `record.${offset + i}` }], evidence_status: "source_reference",
      }));
      return route.fulfill({ json: { items, total: 125, next_cursor: offset + items.length < 125 ? String(offset + items.length) : null, group_id: projectedId, snapshot_id: "snapshot-one" } });
    }
    const json = path.endsWith("/scans") ? { items: [{ id: "network-scan", status: "completed", categories: ["network"], created_at: "2026-01-01" }] }
      : path.endsWith("/summary") ? { resources: [], findings: [], coverage: [], graphs: {}, stats: {} }
      : path.endsWith("/graphs/network") ? graph
      : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/me") ? { email: "tester@example.test", plan: "test" }
      : { items: [] };
    return route.fulfill({ json });
  });
  await page.goto("/#Network%20Map");
  await expect(page.getByRole("tab", { name: /AWS/ })).toBeVisible();
  await clickDeclaredRelationship(page);
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Next relationship page" }).click();
  await dialog.getByRole("button", { name: `Load native records for projected group ${projectedId}` }).click();
  await expect(dialog).toContainText("Native records loaded 100 of 125");
  await dialog.getByRole("button", { name: "Next native relationship page" }).click();
  await expect(dialog).toContainText("Native records loaded 125 of 125");
  await expect(dialog.locator('[aria-label="Native relationship details"]').last()).toContainText(projectedMemberId(124));
  expect(requestedCursor).toBe("100");
  await expect(dialog.locator("pre")).toHaveCount(0);
});
