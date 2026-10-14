import test from "node:test";
import assert from "node:assert/strict";
import { pollJoeSandboxSubmission, submitJoeSandboxUrl } from "../src/joe-sandbox.mjs";

test("Joe Sandbox URL submission requires explicit terms acceptance", async () => {
  await assert.rejects(
    () => submitJoeSandboxUrl("https://example.com", { apiKey: "key" }),
    /terms acceptance/,
  );
});

test("Joe Sandbox submits URLs in fast mode with reuse enabled and external reputation off", async () => {
  let request;
  const result = await submitJoeSandboxUrl("https://example.com/path", {
    apiKey: "secret-key",
    acceptTerms: true,
    fetchImpl: async (url, options) => {
      request = { url: String(url), options };
      return { ok: true, json: async () => ({ data: { submission_id: "submission-42" } }) };
    },
  });
  assert.deepEqual(result, { submissionId: "submission-42" });
  assert.equal(request.url, "https://jbxcloud.joesecurity.org/api/v2/submission/new");
  const body = new URLSearchParams(request.options.body);
  assert.equal(body.get("apikey"), "secret-key");
  assert.equal(body.get("accept-tac"), "1");
  assert.equal(body.get("url"), "https://example.com/path");
  assert.equal(body.get("fast-mode"), "1");
  assert.equal(body.get("report-cache"), "1");
  assert.equal(body.get("url-reputation"), "0");
});

test("Joe Sandbox polling treats finished clean results as clean", async () => {
  const endpoints = [];
  const result = await pollJoeSandboxSubmission("submission-42", {
    apiKey: "secret-key",
    fetchImpl: async (url, options) => {
      endpoints.push(String(url));
      const body = new URLSearchParams(options.body);
      if (String(url).endsWith("/v2/submission/info")) {
        assert.equal(body.get("submission_id"), "submission-42");
        return { ok: true, json: async () => ({ data: { analyses: [{ webid: 1234 }] } }) };
      }
      assert.equal(String(url).endsWith("/v2/analysis/info"), true);
      assert.equal(body.get("webid"), "1234");
      return { ok: true, json: async () => ({ data: { status: "finished", detection: "clean" } }) };
    },
  });
  assert.equal(result.verdict, "clean");
  assert.deepEqual(result.webids, ["1234"]);
  assert.equal(endpoints.length, 2);
});

test("Joe Sandbox polling blocks malicious and holds incomplete/unclear results", async () => {
  const malicious = await pollJoeSandboxSubmission("sub", {
    apiKey: "key",
    fetchImpl: async (url) => String(url).endsWith("/v2/submission/info")
      ? { ok: true, json: async () => ({ data: { analyses: [{ webid: "1" }] } }) }
      : { ok: true, json: async () => ({ data: { status: "finished", detection: "suspicious" } }) },
  });
  assert.equal(malicious.verdict, "malicious");

  const pending = await pollJoeSandboxSubmission("sub", {
    apiKey: "key",
    fetchImpl: async (url) => String(url).endsWith("/v2/submission/info")
      ? { ok: true, json: async () => ({ data: { analyses: [{ webid: "1" }] } }) }
      : { ok: true, json: async () => ({ data: { status: "running" } }) },
  });
  assert.equal(pending.verdict, "pending");
});