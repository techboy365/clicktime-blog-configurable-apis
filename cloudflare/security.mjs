const encoder = new TextEncoder();
const decoder = new TextDecoder();
const UUID_PATTERN = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url value.");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function ipv4IsPrivate(host) {
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return true;
  const [a, b] = parts.map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168 || b === 88)) ||
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0);
}

function ipv6IsPrivate(host) {
  const value = host.replace(/^\[|\]$/g, "").toLowerCase();
  // Conservatively reject mapped/compatible forms and all non-global-unicast ranges.
  if (value === "::" || value === "::1" || value.startsWith("::ffff:") ||
      /^(?:fc|fd|fe[89ab]|ff)/.test(value) || value.startsWith("2001:db8:")) return true;
  const parts = value.split(":");
  const first = Number.parseInt(parts[0] || "0", 16);
  const second = Number.parseInt(parts[1] || "0", 16);
  if ((first === 0x2001 && second <= 0x01ff) || first === 0x2002) return true;
  return !Number.isFinite(first) || first < 0x2000 || first > 0x3fff;
}

export function isPrivateAddress(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || /\.(?:localhost|local|internal|test|invalid|lan|onion)$/.test(host) ||
      host === "home.arpa" || host.endsWith(".home.arpa")) return true;
  const unwrapped = host.replace(/^\[|\]$/g, "");
  if (unwrapped.includes(":")) return ipv6IsPrivate(unwrapped);
  if (/^\d+(?:\.\d+){3}$/.test(unwrapped)) return ipv4IsPrivate(unwrapped);
  return false;
}

export function normalizePublicUrl(input) {
  if (typeof input !== "string" || input.length > 4096) throw new Error("URL must be a string under 4096 characters.");
  let url;
  try { url = new URL(input.trim()); } catch { throw new Error("Enter a complete URL, including https://."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS links are supported.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed.");
  if (!url.hostname || isPrivateAddress(url.hostname)) throw new Error("Local, private, and reserved destinations are not allowed.");
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
  if (hasSensitiveQuery(url.toString())) throw new Error("Sensitive query parameter detected; the URL was not sent to external scanners.");
  return url.toString();
}

export async function assertPublicDns(hostname, fetchImpl = fetch) {
  if (isPrivateAddress(hostname)) throw new Error("Private or reserved destination rejected.");
  // Literal public IPs need no lookup. Hostnames are resolved immediately before
  // a scanner submission and again before redirecting a cached-clean result.
  const unwrapped = String(hostname).replace(/^\[|\]$/g, "");
  if (unwrapped.includes(":") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(unwrapped)) return true;
  let foundAddress = false;
  for (const type of ["A", "AAAA"]) {
    const resolver = new URL("https://cloudflare-dns.com/dns-query");
    resolver.searchParams.set("name", hostname);
    resolver.searchParams.set("type", type);
    const response = await fetchImpl(resolver, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) throw new Error("Destination DNS validation is unavailable.");
    const result = await response.json();
    if (result.Status !== 0 && result.Status !== 3) throw new Error("Destination DNS validation failed.");
    for (const answer of result.Answer || []) {
      if (![1, 28].includes(answer.type)) continue;
      foundAddress = true;
      if (isPrivateAddress(answer.data)) throw new Error("Destination resolves to a private or reserved address.");
    }
  }
  if (!foundAddress) throw new Error("Destination did not resolve to a public IP address.");
  return true;
}

export async function signLinkId(id, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(id))));
}

export async function makeProtectedPath(id, secret, nowSeconds = Math.floor(Date.now() / 1000)) {
  const expiresAt = nowSeconds + 365 * 24 * 60 * 60;
  const payload = `${id}.${expiresAt}`;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payload))));
  return `/go/${payload}.${signature}`;
}

export async function verifyProtectedToken(token, secret, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (typeof token !== "string") return null;
  const [id, expiry, signature, ...extra] = token.split(".");
  if (extra.length || !UUID_PATTERN.test(id || "") || !/^\d{10}$/.test(expiry || "") ||
      !SIGNATURE_PATTERN.test(signature || "")) return null;
  const expiresAt = Number(expiry);
  if (expiresAt <= nowSeconds || expiresAt > nowSeconds + 365 * 24 * 60 * 60 + 300) return null;
  try {
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    return await crypto.subtle.verify("HMAC", key, base64UrlToBytes(signature), encoder.encode(`${id}.${expiry}`)) ? id : null;
  } catch { return null; }
}

export async function hashValue(value) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

async function encryptionKey(secret) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode("fieldnotes-link-target-v1") },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

export async function encryptLinkTarget(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return `v1.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(ciphertext))}`;
}

export async function decryptLinkTarget(payload, secret) {
  const [version, ivPart, ciphertextPart, ...extra] = String(payload).split(".");
  if (version !== "v1" || !ivPart || !ciphertextPart || extra.length) throw new Error("Protected URL record is invalid.");
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(ivPart) },
    await encryptionKey(secret), base64UrlToBytes(ciphertextPart),
  );
  return decoder.decode(clear);
}

export function newId() { return crypto.randomUUID(); }

export function newToken() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function inlineMarkdown(text) {
  const linkPattern = /\[([^\]]{1,300})\]\((https?:\/\/[^)\s]{1,4096})\)/g;
  let output = "";
  let cursor = 0;
  for (const match of text.matchAll(linkPattern)) {
    const index = match.index ?? 0;
    output += escapeHtml(text.slice(cursor, index));
    try {
      const href = normalizePublicUrl(match[2]);
      output += `<a href="${escapeHtml(href)}" rel="noopener noreferrer">${escapeHtml(match[1])}</a>`;
    } catch { output += escapeHtml(match[1]); }
    cursor = index + match[0].length;
  }
  output += escapeHtml(text.slice(cursor));
  return output.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>").replace(/`([^`]+)`/g, "<code>$1</code>");
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
      flushParagraph(); list.push(trimmed.replace(/^[-*]\s+/, ""));
    } else {
      flushList(); paragraph.push(trimmed);
    }
  }
  flushParagraph(); flushList();
  return blocks.join("\n");
}

export function slugify(value) {
  return String(value).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 70) || "post";
}