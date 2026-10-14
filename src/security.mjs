import { createCipheriv, createDecipheriv, createHmac, createHash, hkdfSync, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

const PRIVATE_V4 = [
  [/^0\./, "unspecified"],
  [/^10\./, "private"],
  [/^172\.(?:1[6-9]|2\d|3[01])\./, "private"],
  [/^127\./, "loopback"],
  [/^169\.254\./, "link-local"],
  [/^192\.168\./, "private"],
  [/^192\.0\.0\./, "special use"],
  [/^192\.0\.2\./, "documentation"],
  [/^198\.51\.100\./, "documentation"],
  [/^203\.0\.113\./, "documentation"],
  [/^192\.88\.99\./, "deprecated relay"],
  [/^198\.(?:18|19)\./, "benchmark"],
  [/^(?:22[4-9]|23\d|24\d|25[0-5])\./, "multicast/reserved"],
  [/^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, "shared address"],
];

export function isPrivateAddress(hostname) {
  let host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") ||
      host.endsWith(".local") || host.endsWith(".internal") ||
      host.endsWith(".test") || host.endsWith(".invalid") ||
      host.endsWith(".lan") || host.endsWith(".home.arpa") ||
      host.endsWith(".onion")) return true;

  const kind = isIP(host);
  if (kind === 4) return PRIVATE_V4.some(([pattern]) => pattern.test(host));
  if (kind === 6) {
    if (host === "::" || host === "::1") return true;
    if (host.startsWith("2001:db8:")) return true;
    if (/^(?:fc|fd|fe[89ab]|ff)/i.test(host)) return true;
    if (/^::ffff:/i.test(host)) {
      const mapped = host.slice(host.lastIndexOf(":") + 1);
      if (isIP(mapped) === 4) return isPrivateAddress(mapped);
      // Hexadecimal IPv4-mapped IPv6 addresses are conservatively rejected.
      return true;
    }
  }
  return false;
}

export function normalizePublicUrl(input) {
  if (typeof input !== "string" || input.length > 4096) {
    throw new Error("URL must be a string under 4096 characters.");
  }
  let url;
  try { url = new URL(input.trim()); }
  catch { throw new Error("Enter a complete URL, including https://."); }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS links are supported.");
  }
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed.");
  if (!url.hostname || isPrivateAddress(url.hostname)) {
    throw new Error("Local, private, and reserved destinations are not allowed.");
  }
  if (url.port && !/^\d+$/.test(url.port)) throw new Error("Invalid URL port.");
  return url.toString();
}

export function hasSensitiveQuery(input) {
  const url = new URL(input);
  const sensitive = /^(?:token|access_token|refresh_token|id_token|auth|authorization|session|sessionid|password|passwd|secret|email|e-mail|code|state|signature|sig|key|api_key|apikey|otp|nonce)$/i;
  return [...url.searchParams.keys()].some((key) => sensitive.test(key));
}

export function scannerSafeUrl(input) {
  const url = new URL(normalizePublicUrl(input));
  url.hash = "";
  if (hasSensitiveQuery(url.toString())) {
    throw new Error("Sensitive query parameter detected; the URL was not sent to external scanners.");
  }
  return url.toString();
}

export function signLinkId(id, secret) {
  return createHmac("sha256", secret).update(id).digest("base64url");
}

export function makeProtectedPath(id, secret) {
  const expiresAt = Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60;
  const signature = createHmac("sha256", secret).update(`${id}.${expiresAt}`).digest("base64url");
  return `/go/${id}.${expiresAt}.${signature}`;
}

// Keep accepting links created by the original MVP. New links use the opaque
// /go/ route so the destination domain and path are not exposed in email URLs.
export function makeLegacyProtectedPath(id, secret, target) {
  const url = new URL(normalizePublicUrl(target));
  const displayPath = url.pathname.replace(/\/+$/, "");
  const displayDestination = `${url.protocol.slice(0, -1)}:/${url.host}${displayPath}`;
  return `/v2/___${displayDestination}/___.${id}.${signLinkId(id, secret)}`;
}

export function verifyProtectedToken(token, secret, {
  allowLegacy = false,
  nowSeconds = Math.floor(Date.now() / 1000),
} = {}) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  const legacy = parts.length === 2 && allowLegacy;
  if ((!legacy && parts.length !== 3) || (legacy && parts.length !== 2)) return null;
  const [id, expiry, suppliedSignature] = legacy ? [parts[0], null, parts[1]] : parts;
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(id) ||
      !/^[\w-]{43}$/.test(suppliedSignature)) return null;
  if (!legacy) {
    if (!/^\d{10}$/.test(expiry)) return null;
    const expiresAt = Number(expiry);
    if (expiresAt <= nowSeconds || expiresAt > nowSeconds + 365 * 24 * 60 * 60 + 300) return null;
  }
  const payload = legacy ? id : `${id}.${expiry}`;
  const expected = Buffer.from(createHmac("sha256", secret).update(payload).digest("base64url"));
  const received = Buffer.from(suppliedSignature);
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) return null;
  return id;
}

export function hashValue(value) {
  return createHash("sha256").update(value).digest("hex");
}

function targetEncryptionKey(secret) {
  return Buffer.from(hkdfSync("sha256", Buffer.from(secret), Buffer.alloc(0), "fieldnotes-link-target-v1", 32));
}

export function encryptLinkTarget(value, secret) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", targetEncryptionKey(secret), nonce);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return `v1.${nonce.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${ciphertext.toString("base64url")}`;
}

export function decryptLinkTarget(payload, secret) {
  const [version, noncePart, tagPart, ciphertextPart] = String(payload).split(".");
  if (version !== "v1" || !noncePart || !tagPart || !ciphertextPart) throw new Error("Protected URL record is invalid.");
  const decipher = createDecipheriv("aes-256-gcm", targetEncryptionKey(secret), Buffer.from(noncePart, "base64url"));
  decipher.setAuthTag(Buffer.from(tagPart, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextPart, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export function newId() {
  return randomUUID();
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function inlineMarkdown(text) {
  const linkPattern = /\[([^\]]{1,300})\]\((https?:\/\/[^)\s]{1,4096})\)/g;
  let out = "";
  let cursor = 0;
  for (const match of text.matchAll(linkPattern)) {
    const index = match.index ?? 0;
    out += escapeHtml(text.slice(cursor, index));
    try {
      const href = normalizePublicUrl(match[2]);
      out += `<a href="${escapeHtml(href)}" rel="noopener noreferrer">${escapeHtml(match[1])}</a>`;
    } catch {
      out += escapeHtml(match[1]);
    }
    cursor = index + match[0].length;
  }
  out += escapeHtml(text.slice(cursor));
  return out
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
}

export function renderMarkdown(markdown) {
  const lines = String(markdown ?? "").replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let paragraph = [];
  let list = [];
  const flushParagraph = () => {
    if (paragraph.length) blocks.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (list.length) blocks.push(`<ul>${list.map((item) => `<li>${inlineMarkdown(item)}</li>`).join("")}</ul>`);
    list = [];
  };
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { flushParagraph(); flushList(); continue; }
    const heading = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushParagraph(); flushList();
      const level = heading[1].length + 1;
      blocks.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
    } else if (/^[-*]\s+/.test(trimmed)) {
      flushParagraph();
      list.push(trimmed.replace(/^[-*]\s+/, ""));
    } else {
      flushList();
      paragraph.push(trimmed);
    }
  }
  flushParagraph();
  flushList();
  return blocks.join("\n");
}

export function slugify(value) {
  const slug = String(value).toLowerCase().normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 70);
  return slug || "post";
}