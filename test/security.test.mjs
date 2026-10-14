import test from "node:test";
import assert from "node:assert/strict";
import {
  decryptLinkTarget, encryptLinkTarget, hasSensitiveQuery, isPrivateAddress, makeLegacyProtectedPath,
  makeProtectedPath, normalizePublicUrl,
  renderMarkdown, scannerSafeUrl, slugify, verifyProtectedToken,
} from "../src/security.mjs";

const secret = "test-only-secret-that-is-more-than-thirty-two-bytes";

test("accepts public-looking HTTP and HTTPS destinations", () => {
  assert.equal(normalizePublicUrl("https://example.com/a?x=1"), "https://example.com/a?x=1");
  assert.equal(normalizePublicUrl("http://mycirt.com"), "http://mycirt.com/");
});

test("rejects unsafe schemes, credentials, localhost, and private IP literals", () => {
  for (const value of [
    "javascript:alert(1)",
    "file:///etc/passwd",
    "https://user:pass@example.com/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://10.1.2.3/",
    "http://172.20.1.2/",
    "http://192.168.1.1/",
    "http://[::1]/",
  ]) assert.throws(() => normalizePublicUrl(value));
});

test("identifies sensitive query keys and refuses to send them to scanners", () => {
  assert.equal(hasSensitiveQuery("https://example.com/?access_token=secret"), true);
  assert.equal(hasSensitiveQuery("https://example.com/?utm_source=mail"), false);
  assert.throws(() => scannerSafeUrl("https://example.com/?email=reader@example.com"));
});

test("protected links are signed and reject tampering", () => {
  const id = "3b12f1df-5232-4804-897e-917bf397618a";
  const path = makeProtectedPath(id, secret);
  const token = path.slice("/go/".length);
  assert.match(path, /^\/go\/[0-9a-f-]{36}\.\d{10}\.[\w-]{43}$/);
  assert.doesNotMatch(path, /example\.com|\/path/);
  assert.equal(verifyProtectedToken(token, secret), id);
  const parts = token.split(".");
  assert.equal(verifyProtectedToken(`${id}.${Number(parts[1]) - 365 * 24 * 60 * 60 - 1}.${parts[2]}`, secret), null);
  assert.equal(verifyProtectedToken(token.slice(0, -1) + "x", secret), null);
  assert.equal(verifyProtectedToken(token, "a-different-long-secret-value-which-is-long-enough"), null);
  const legacyPath = makeLegacyProtectedPath(id, secret, "https://example.com/path");
  assert.match(legacyPath, /^\/v2\/___https:\/example\.com\/path\/___.+/);
  const legacyToken = legacyPath.slice(legacyPath.lastIndexOf("/___.") + 5);
  assert.equal(verifyProtectedToken(legacyToken, secret), null);
  assert.equal(verifyProtectedToken(legacyToken, secret, { allowLegacy: true }), id);
});

test("stored destinations are encrypted and tampering is detected", () => {
  const url = "https://example.com/path?token=private-value";
  const encrypted = encryptLinkTarget(url, secret);
  assert.doesNotMatch(encrypted, /private-value|example\.com/);
  assert.equal(decryptLinkTarget(encrypted, secret), url);
  const parts = encrypted.split(".");
  parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
  assert.throws(() => decryptLinkTarget(parts.join("."), secret));
});

test("Markdown renderer escapes raw HTML and only creates HTTP(S) links", () => {
  const html = renderMarkdown('A <script>alert(1)</script> [safe](https://example.com/?a=1&b=2) [bad](javascript:alert(2))');
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /href="https:\/\/example\.com\/\?a=1&amp;b=2"/);
  assert.doesNotMatch(html, /href="javascript:/);
});

test("slugify makes stable readable identifiers", () => {
  assert.equal(slugify("A Thoughtful Note!"), "a-thoughtful-note");
  assert.equal(slugify("###"), "post");
});

test("private address checks include shared and documentation ranges", () => {
  for (const ip of ["0.0.0.0", "100.64.1.2", "169.254.2.3", "198.51.100.4", "203.0.113.5", "::1", "fd00::1"]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateAddress("2001:4860:4860::8888"), false);
});