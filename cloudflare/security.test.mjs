import test from "node:test";
import assert from "node:assert/strict";
import {
  assertPublicDns, decryptLinkTarget, encryptLinkTarget, isPrivateAddress, makeProtectedPath,
  normalizePublicUrl, renderMarkdown, scannerSafeUrl, verifyProtectedToken,
} from "./security.mjs";

const secret = "security-test-secret-with-at-least-32-bytes";

test("Worker link tokens are bound to ID, expiry, and signing secret", async () => {
  const id = "c95409bc-fc17-4bb1-92c9-5df4c8c63144";
  const path = await makeProtectedPath(id, secret, 1_800_000_000);
  const token = path.slice("/go/".length);
  assert.equal(await verifyProtectedToken(token, secret, 1_800_000_001), id);
  assert.equal(await verifyProtectedToken(token, `${secret}x`, 1_800_000_001), null);
  assert.equal(await verifyProtectedToken(token, secret, 1_900_000_000), null);
  const parts = token.split(".");
  parts[2] = `${parts[2][0] === "a" ? "b" : "a"}${parts[2].slice(1)}`;
  assert.equal(await verifyProtectedToken(parts.join("."), secret, 1_800_000_001), null);
});

test("Worker AES-GCM target encryption detects tampering", async () => {
  const url = "https://example.com/path?campaign=one";
  const encrypted = await encryptLinkTarget(url, secret);
  assert.equal(await decryptLinkTarget(encrypted, secret), url);
  const [version, iv, ciphertext] = encrypted.split(".");
  const replacement = `${ciphertext[0] === "a" ? "b" : "a"}${ciphertext.slice(1)}`;
  await assert.rejects(decryptLinkTarget(`${version}.${iv}.${replacement}`, secret));
});

test("Worker URL policy rejects private and non-web destinations", () => {
  for (const host of ["localhost", "127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.2", "[::1]", "fd12::1", "169.254.10.1"]) {
    assert.equal(isPrivateAddress(host), true, host);
  }
  assert.equal(normalizePublicUrl("https://example.com/a"), "https://example.com/a");
  assert.throws(() => normalizePublicUrl("file:///etc/passwd"));
  assert.throws(() => normalizePublicUrl("http://192.168.0.2/"));
  assert.throws(() => scannerSafeUrl("https://example.com/?session=secret"), /Sensitive query/);
});

test("Worker DNS policy fails closed when a hostname has no A or AAAA answers", async () => {
  const noAnswers = async () => Response.json({ Status: 3, Answer: [] });
  await assert.rejects(assertPublicDns("missing.example", noAnswers), /did not resolve/);
});

test("Worker Markdown escapes HTML and permits only safe links", () => {
  const rendered = renderMarkdown("<script>alert(1)</script>\n\n[good](https://example.com)\n\n[bad](javascript:alert(1))");
  assert.doesNotMatch(rendered, /<script>/);
  assert.match(rendered, /&lt;script&gt;/);
  assert.match(rendered, /href="https:\/\/example\.com\/"/);
  assert.doesNotMatch(rendered, /href="javascript:/);
});