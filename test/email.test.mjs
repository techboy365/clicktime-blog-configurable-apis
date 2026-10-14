import test from "node:test";
import assert from "node:assert/strict";
import { sendEmail } from "../src/email.mjs";

test("Resend adapter posts the newsletter with bearer auth", async () => {
  let request;
  const result = await sendEmail({
    apiKey: "test-key",
    from: "Journal <news@example.com>",
    to: "reader@example.com",
    subject: "A note",
    html: "<p>Hello</p>",
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, json: async () => ({ id: "email-id" }) };
    },
  });
  assert.equal(result.id, "email-id");
  assert.equal(request.url, "https://api.resend.com/emails");
  assert.equal(request.options.headers.Authorization, "Bearer test-key");
  assert.equal(JSON.parse(request.options.body).to, "reader@example.com");
});

test("email endpoint can be replaced through configuration", async () => {
  let requestedUrl;
  await sendEmail({
    apiKey: "test-key",
    apiUrl: "https://mail.example.test/v1/send",
    from: "Journal <news@example.com>",
    to: "reader@example.com",
    subject: "A note",
    html: "<p>Hello</p>",
    fetchImpl: async (url) => {
      requestedUrl = String(url);
      return { ok: true, json: async () => ({ id: "email-id" }) };
    },
  });
  assert.equal(requestedUrl, "https://mail.example.test/v1/send");
});

test("email adapter refuses to send without provider configuration", async () => {
  await assert.rejects(
    () => sendEmail({ apiKey: "", from: "", to: "x@example.com", subject: "x", html: "x" }),
    /not configured/,
  );
});