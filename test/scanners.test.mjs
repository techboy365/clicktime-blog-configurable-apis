import test from "node:test";
import assert from "node:assert/strict";
import { checkWebRisk, classifyUrlscanResult, getFreshCachedVerdict, inspectUrl, runUrlscan } from "../src/scanners.mjs";

test("fresh exact-URL verdicts fast-path; expired or pending entries do not", () => {
  const now = 1_000_000;
  assert.equal(getFreshCachedVerdict({ verdict: "clean", checked_at: now - 1_000, reason: "clean" }, now)?.verdict, "clean");
  assert.equal(getFreshCachedVerdict({ verdict: "malicious", checked_at: now - 1_000, reason: "bad" }, now)?.verdict, "malicious");
  assert.equal(getFreshCachedVerdict({ verdict: "clean", checked_at: now - 301_000, reason: "old" }, now), null);
  assert.equal(getFreshCachedVerdict({ verdict: "pending", checked_at: now - 1_000, reason: "pending" }, now), null);
  assert.equal(getFreshCachedVerdict({ verdict: "unknown", checked_at: now - 1_000, reason: "unknown" }, now)?.verdict, "unknown");
  assert.equal(getFreshCachedVerdict({ verdict: "clean", checked_at: now - 1_000, joe_checked: 0 }, now, { requireJoe: true }), null);
  assert.equal(getFreshCachedVerdict({ verdict: "clean", checked_at: now - 1_000, joe_checked: 1 }, now, { requireJoe: true })?.verdict, "clean");
});

test("urlscan malicious verdicts block", () => {
  assert.equal(classifyUrlscanResult({ verdicts: { overall: { malicious: true } } }).verdict, "malicious");
  assert.equal(classifyUrlscanResult({ verdicts: { urlscan: { score: 72 } } }).verdict, "malicious");
});

test("urlscan only allows strongly negative scores; neutral/missing scores stay unknown", () => {
  assert.equal(classifyUrlscanResult({ verdicts: { urlscan: { score: -72 } } }).verdict, "clean");
  assert.equal(classifyUrlscanResult({ verdicts: { urlscan: { score: 0 } } }).verdict, "unknown");
  assert.equal(classifyUrlscanResult({ verdicts: { urlscan: { score: -80 }, engines: { score: 12 } } }).verdict, "unknown");
  assert.equal(classifyUrlscanResult({ verdicts: {} }).verdict, "unknown");
});

test("Web Risk reports a threat-list match", async () => {
  let requested;
  const result = await checkWebRisk("https://example.com", "key", async (url) => {
    requested = new URL(url);
    return { ok: true, json: async () => ({ threat: { threatTypes: ["SOCIAL_ENGINEERING"] } }) };
  });
  assert.equal(result.verdict, "malicious");
  assert.equal(requested.searchParams.get("uri"), "https://example.com");
  assert.deepEqual(requested.searchParams.getAll("threatTypes"), ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]);
});

test("Web Risk endpoint can be replaced through configuration", async () => {
  let requestedUrl;
  await checkWebRisk("https://example.com", "key", async (url) => {
    requestedUrl = new URL(url).origin + new URL(url).pathname;
    return { ok: true, json: async () => ({}) };
  }, "https://webrisk.example.test/custom/check");
  assert.equal(requestedUrl, "https://webrisk.example.test/custom/check");
});

test("Web Risk miss is not mislabeled as a clean result", async () => {
  const result = await checkWebRisk("https://example.com", "key", async () => ({ ok: true, json: async () => ({}) }));
  assert.equal(result.verdict, "not-listed");
});

test("urlscan submits privately and polls for a result", async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    if (String(url).endsWith("/scan/")) {
      return { ok: true, json: async () => ({ uuid: "abc-123" }) };
    }
    return { ok: true, json: async () => ({ verdicts: { urlscan: { score: -80 } } }) };
  };
  const result = await runUrlscan("https://example.com", "scan-key", { fetchImpl, waitMs: 0 });
  assert.equal(result.verdict, "clean");
  assert.equal(requests.length, 2);
  assert.match(requests[0].options.headers["API-Key"], /scan-key/);
  assert.equal(JSON.parse(requests[0].options.body).visibility, "private");
});

test("urlscan API base can be replaced through configuration", async () => {
  const requests = [];
  await runUrlscan("https://example.com", "scan-key", {
    apiUrl: "https://scanner.example.test/api/",
    fetchImpl: async (url) => {
      requests.push(String(url));
      if (String(url).endsWith("/scan/")) return { ok: true, json: async () => ({ uuid: "custom-id" }) };
      return { ok: true, json: async () => ({ verdicts: { urlscan: { score: -80 } } }) };
    },
    waitMs: 0,
  });
  assert.deepEqual(requests, [
    "https://scanner.example.test/api/scan/",
    "https://scanner.example.test/api/result/custom-id/",
  ]);
});

test("an unconfigured reputation provider fails closed before browser scan", async () => {
  let calledUrlscan = false;
  const result = await inspectUrl("https://example.com", {
    webRiskKey: "",
    urlscanKey: "configured",
    fetchImpl: async () => { calledUrlscan = true; throw new Error("should not call"); },
  });
  assert.equal(result.verdict, "unknown");
  assert.equal(calledUrlscan, false);
});