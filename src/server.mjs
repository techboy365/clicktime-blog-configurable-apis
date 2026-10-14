import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { checkWebRisk, getFreshCachedVerdict, runUrlscan } from "./scanners.mjs";
import { pollJoeSandboxSubmission, submitJoeSandboxUrl } from "./joe-sandbox.mjs";
import { sendEmail } from "./email.mjs";
import {
  decryptLinkTarget, encryptLinkTarget, escapeHtml, hashValue, makeLegacyProtectedPath, makeProtectedPath, newId,
  normalizePublicUrl, renderMarkdown, scannerSafeUrl, slugify, verifyProtectedToken,
} from "./security.mjs";

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`).replace(/\/+$/, "");
const LINK_SIGNING_SECRET = process.env.LINK_SIGNING_SECRET || "";
const PROXY_SHARED_SECRET = process.env.PROXY_SHARED_SECRET || "";
const DATABASE_PATH = resolve(process.env.DATABASE_PATH || "./data/blog.sqlite");
const ADMIN_USER = process.env.ADMIN_USER || "editor";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const WEBRISK_API_KEY = process.env.WEBRISK_API_KEY || "";
const WEBRISK_API_URL = process.env.WEBRISK_API_URL || undefined;
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY || "";
const URLSCAN_API_URL = process.env.URLSCAN_API_URL || undefined;
const URLSCAN_POLL_MS = Number(process.env.URLSCAN_POLL_MS || 1000);
const URLSCAN_CLEAN_CACHE_SECONDS = Number(process.env.URLSCAN_CLEAN_CACHE_SECONDS || 300);
const JOESANDBOX_API_KEY = process.env.JOESANDBOX_API_KEY || "";
const JOESANDBOX_API_URL = process.env.JOESANDBOX_API_URL || undefined;
const JOESANDBOX_ACCEPT_TAC = process.env.JOESANDBOX_ACCEPT_TAC === "1";
const JOESANDBOX_TIMEOUT_MS = Number(process.env.JOESANDBOX_TIMEOUT_MS || 5000);
const JOESANDBOX_POLL_MS = Number(process.env.JOESANDBOX_POLL_MS || 5000);
const SCAN_JOB_MAX_WAIT_MS = Number(process.env.SCAN_JOB_MAX_WAIT_MS || 15 * 60_000);
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_API_URL = process.env.RESEND_API_URL || undefined;
const EMAIL_FROM = process.env.EMAIL_FROM || "";

if (Buffer.byteLength(LINK_SIGNING_SECRET) < 32) {
  throw new Error("LINK_SIGNING_SECRET must be configured with at least 32 bytes. See .env.example.");
}
if (PROXY_SHARED_SECRET && Buffer.byteLength(PROXY_SHARED_SECRET) < 32) {
  throw new Error("PROXY_SHARED_SECRET must be at least 32 bytes when configured.");
}
const originUrl = new URL(PUBLIC_ORIGIN);
if (!["http:", "https:"].includes(originUrl.protocol) || originUrl.pathname !== "/" ||
    originUrl.search || originUrl.hash || originUrl.username || originUrl.password) {
  throw new Error("PUBLIC_ORIGIN must be an HTTP(S) origin without a path.");
}
if (process.env.NODE_ENV === "production" && originUrl.protocol !== "https:") {
  throw new Error("PUBLIC_ORIGIN must use HTTPS in production.");
}
if (process.env.NODE_ENV === "production" && !ADMIN_PASSWORD) {
  throw new Error("ADMIN_PASSWORD must be set in production.");
}

mkdirSync(dirname(DATABASE_PATH), { recursive: true });
const db = new DatabaseSync(DATABASE_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    markdown TEXT NOT NULL,
    published_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS subscribers (
    email TEXT PRIMARY KEY COLLATE NOCASE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'unsubscribed')),
    confirm_hash TEXT,
    consent_at TEXT NOT NULL,
    confirmed_at TEXT
  );
  CREATE TABLE IF NOT EXISTS unsubscribe_tokens (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE,
    created_at TEXT NOT NULL,
    FOREIGN KEY (email) REFERENCES subscribers(email) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS protected_links (
    id TEXT PRIMARY KEY,
    post_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS scan_cache (
    url_hash TEXT PRIMARY KEY,
    scan_id TEXT,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    checked_at INTEGER NOT NULL,
    joe_checked INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS scan_jobs (
    url_hash TEXT PRIMARY KEY,
    encrypted_url TEXT NOT NULL,
    web_risk_done INTEGER NOT NULL DEFAULT 0,
    urlscan_id TEXT,
    urlscan_done INTEGER NOT NULL DEFAULT 0,
    joe_required INTEGER NOT NULL DEFAULT 0,
    joe_submission_id TEXT,
    joe_webids TEXT NOT NULL DEFAULT '[]',
    joe_done INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    next_run_at INTEGER NOT NULL,
    last_error TEXT
  );
  CREATE TABLE IF NOT EXISTS click_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id TEXT NOT NULL,
    clicked_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    provider TEXT NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY (link_id) REFERENCES protected_links(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS newsletter_sends (
    post_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    recipient_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    error TEXT,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS click_events_link_idx ON click_events(link_id);
`);

const scanCacheColumns = new Set(db.prepare("PRAGMA table_info(scan_cache)").all().map((column) => column.name));
if (!scanCacheColumns.has("joe_checked")) {
  db.exec("ALTER TABLE scan_cache ADD COLUMN joe_checked INTEGER NOT NULL DEFAULT 0");
}

if (db.prepare("SELECT COUNT(*) AS n FROM posts").get().n === 0) {
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO posts (id, slug, title, summary, markdown, published_at)
    VALUES (?, ?, ?, ?, ?, ?)`).run(
    newId(),
    "welcome-to-the-journal",
    "Welcome to the journal",
    "A small, calm place for thoughtful updates.",
    "This is the starter post. Use the protected editor to publish your own article and send it to confirmed subscribers.\n\nWhen a published post is emailed, external links are rewritten to this site and checked when clicked.\n\n[Visit an example website](https://example.com/)",
    now,
  );
}

const rateBuckets = new Map();
function rateAllowed(key, max = 12, windowMs = 60_000) {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (bucket.count >= max) return false;
  bucket.count += 1;
  return true;
}

function setHeaders(res, contentType = "text/html; charset=utf-8") {
  res.setHeader("Content-Type", contentType);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; connect-src 'self'");
}

function sendHtml(res, status, html) {
  setHeaders(res);
  res.writeHead(status);
  res.end(html);
}

function sendText(res, status, text) {
  setHeaders(res, "text/plain; charset=utf-8");
  res.writeHead(status);
  res.end(text);
}

function layout(title, content, { description = "A thoughtful blog with links inspected at click time." } = {}) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${escapeHtml(description)}">
  <meta name="theme-color" content="#f8f7f4">
  <title>${escapeHtml(title)} · Fieldnotes</title>
  <link rel="stylesheet" href="/styles.css">
  <script src="/app.js" defer></script>
</head>
<body>
  <header class="site-header">
    <a class="brand" href="/" aria-label="Fieldnotes home"><span class="brand-mark">f</span><span>fieldnotes</span></a>
    <nav aria-label="Primary navigation">
      <a href="/#latest">Journal</a>
      <a href="/#subscribe">Newsletter</a>
      <a class="nav-admin" href="/admin">Editor</a>
    </nav>
  </header>
  <main>${content}</main>
  <footer class="site-footer">
    <span>Notes worth keeping.</span>
    <span>Thoughtful writing · safer links</span>
  </footer>
</body>
</html>`;
}

function safeEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value) && value.length <= 254;
}

async function readBody(req, maxBytes = 200_000) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maxBytes) throw new Error("Request body is too large.");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function formData(body) {
  return Object.fromEntries(new URLSearchParams(body));
}

function requireAdmin(req, res) {
  if (!ADMIN_PASSWORD) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Blog editor", charset="UTF-8"');
    sendHtml(res, 503, layout("Editor setup required", `<section class="notice-card"><p class="eyebrow">Setup needed</p><h1>Editor access is not configured</h1><p>Set <code>ADMIN_PASSWORD</code> in your local environment before using the editor.</p></section>`));
    return false;
  }
  const [scheme, encoded] = String(req.headers.authorization || "").split(" ");
  let suppliedUser = "";
  let suppliedPassword = "";
  try {
    if (scheme === "Basic" && encoded) {
      const decoded = Buffer.from(encoded, "base64").toString("utf8");
      const colon = decoded.indexOf(":");
      suppliedUser = decoded.slice(0, colon);
      suppliedPassword = decoded.slice(colon + 1);
    }
  } catch { /* handled as failed authentication */ }
  const userOk = constantStringEqual(suppliedUser, ADMIN_USER);
  const passOk = constantStringEqual(suppliedPassword, ADMIN_PASSWORD);
  if (!userOk || !passOk) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Blog editor", charset="UTF-8"');
    sendHtml(res, 401, layout("Sign in", `<section class="notice-card"><p class="eyebrow">Private editor</p><h1>Sign in to continue</h1><p>Your browser should ask for the editor credentials configured on this server.</p></section>`));
    return false;
  }
  return true;
}

function constantStringEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function sameOriginPost(req, res) {
  let requestOrigin;
  try { requestOrigin = new URL(req.headers.origin || "").origin; }
  catch { requestOrigin = ""; }
  if (requestOrigin !== PUBLIC_ORIGIN) {
    sendHtml(res, 403, layout("Request rejected", `<section class="notice-card"><p class="eyebrow">Security check</p><h1>Request rejected</h1><p>This form must be submitted from this site.</p></section>`));
    return false;
  }
  return true;
}

function postBySlug(slug) {
  return db.prepare("SELECT * FROM posts WHERE slug = ?").get(slug);
}

function postList() {
  return db.prepare("SELECT * FROM posts ORDER BY published_at DESC").all();
}

function externalLinkRewriter(postId) {
  return (html) => html.replace(/href="(https?:\/\/[^"]+)"/gi, (whole, escapedHref) => {
    const href = escapedHref.replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
    try {
      const target = normalizePublicUrl(href);
      if (new URL(target).origin === PUBLIC_ORIGIN) return `href="${escapeHtml(target)}"`;
      const id = newId();
      db.prepare("INSERT INTO protected_links (id, post_id, target_url, created_at) VALUES (?, ?, ?, ?)")
        .run(id, postId, encryptLinkTarget(target, LINK_SIGNING_SECRET), new Date().toISOString());
      return `href="${escapeHtml(PUBLIC_ORIGIN + makeProtectedPath(id, LINK_SIGNING_SECRET))}"`;
    } catch {
      return whole;
    }
  });
}

function renderArticle(post, { email = false } = {}) {
  let body = renderMarkdown(post.markdown);
  if (email) body = externalLinkRewriter(post.id)(body);
  const date = new Date(post.published_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  if (email) {
    return `<div style="max-width:640px;margin:0 auto;padding:28px 20px;font-family:Arial,sans-serif;color:#2c2c2b;line-height:1.65">
      <p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#7d7a75">FIELDNOTES JOURNAL</p>
      <h1 style="font-size:30px;line-height:1.2">${escapeHtml(post.title)}</h1>
      <p style="color:#7d7a75">${escapeHtml(date)}</p>
      <p style="font-size:18px">${escapeHtml(post.summary)}</p>
      ${body}
      <hr style="border:0;border-top:1px solid #e6e5e3;margin:32px 0">
      <p style="font-size:12px;color:#7d7a75">Links in this email are checked when clicked. <a href="${escapeHtml(PUBLIC_ORIGIN)}/unsubscribe?token={{UNSUBSCRIBE_TOKEN}}">Unsubscribe</a></p>
    </div>`;
  }
  return `<article class="article">
    <a class="back-link" href="/#latest">← All notes</a>
    <p class="eyebrow">${escapeHtml(date)} <span>·</span> 4 min read</p>
    <h1>${escapeHtml(post.title)}</h1>
    <p class="article-summary">${escapeHtml(post.summary)}</p>
    <div class="article-body">${body}</div>
    <div class="article-end"><span class="end-dot"></span><span class="end-dot"></span><span class="end-dot"></span></div>
  </article>`;
}

function homePage() {
  const posts = postList();
  const cards = posts.length ? posts.map((post, index) => `
    <article class="post-card ${index === 0 ? "post-featured" : ""}">
      <div class="post-meta"><span>${new Date(post.published_at).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}</span><span class="meta-dot">·</span><span>Journal</span></div>
      <h3><a href="/p/${encodeURIComponent(post.slug)}">${escapeHtml(post.title)}</a></h3>
      <p>${escapeHtml(post.summary)}</p>
      <a class="read-link" href="/p/${encodeURIComponent(post.slug)}">Read note <span aria-hidden="true">↗</span></a>
    </article>`).join("") : `<p class="empty-state">The first note is on its way.</p>`;
  const content = `
    <section class="hero">
      <div class="hero-copy">
        <p class="eyebrow"><span class="hero-spark"></span> THE FIELDNOTES JOURNAL</p>
        <h1>Good ideas,<br><em>kept close.</em></h1>
        <p class="hero-intro">A small journal for considered perspectives, practical discoveries, and the details worth sharing.</p>
        <a class="button button-dark" href="#latest">Explore the journal <span aria-hidden="true">↓</span></a>
      </div>
      <div class="hero-art" aria-hidden="true">
        <div class="art-label">A quieter<br>corner of the web</div>
        <div class="art-number">01 / 26</div>
      </div>
      <div class="hero-caption"><span>Ideas for the in-between</span><span>Est. 2026</span></div>
    </section>
    <section class="latest-section" id="latest">
      <div class="section-heading"><div><p class="eyebrow">FROM THE JOURNAL</p><h2>Latest notes</h2></div><span class="section-count">${String(posts.length).padStart(2, "0")} notes</span></div>
      <div class="post-grid">${cards}</div>
    </section>
    <section class="newsletter-section" id="subscribe">
      <div class="newsletter-copy"><p class="eyebrow">A LETTER, OCCASIONALLY</p><h2>Make room for<br><em>good reading.</em></h2><p>New notes, sent with care. No noise, and you can leave whenever you like.</p></div>
      <form class="subscribe-form" action="/subscribe" method="post">
        <label for="subscriber-email">Your email address</label>
        <div class="subscribe-row"><input id="subscriber-email" type="email" name="email" autocomplete="email" placeholder="you@example.com" required><button type="submit" class="button button-blue">Subscribe <span aria-hidden="true">↗</span></button></div>
        <label class="consent"><input type="checkbox" name="consent" value="yes" required><span>I agree to receive the newsletter and understand I can unsubscribe at any time.</span></label>
        <p class="form-note">We’ll send a confirmation email before adding you to the list.</p>
        <p class="form-message" role="status" aria-live="polite"></p>
      </form>
    </section>
    <section class="safety-strip"><div class="safety-icon">✓</div><div><strong>Thoughtful links, checked at click time.</strong><p>Email links are checked before readers reach the destination.</p></div><a href="#subscribe" aria-label="Subscribe to Fieldnotes">Stay in the loop ↗</a></section>`;
  return layout("A journal for thoughtful reading", content);
}

function articlePage(post) {
  return layout(post.title, renderArticle(post), { description: post.summary });
}

function adminPage() {
  const posts = postList();
  const subscribers = db.prepare("SELECT COUNT(*) AS n FROM subscribers WHERE status = 'active'").get().n;
  const sends = db.prepare("SELECT post_id, status, recipient_count, updated_at FROM newsletter_sends ORDER BY updated_at DESC LIMIT 5").all();
  const scannerState = !WEBRISK_API_KEY || !URLSCAN_API_KEY
    ? "Needs keys"
    : JOESANDBOX_API_KEY && !JOESANDBOX_ACCEPT_TAC
      ? "Joe terms needed"
      : "Configured";
  const postOptions = posts.map((post) => `<option value="${escapeHtml(post.id)}">${escapeHtml(post.title)}</option>`).join("");
  const postItems = posts.map((post) => {
    const send = sends.find((item) => item.post_id === post.id);
    const locked = ["sent", "sending", "partial"].includes(send?.status);
    const buttonText = send?.status === "sent" ? "Sent" : send?.status === "partial" ? "Review partial send" : send?.status === "sending" ? "Sending…" : "Email subscribers";
    return `<div class="admin-post"><div><strong>${escapeHtml(post.title)}</strong><span>${escapeHtml(post.slug)} · ${send ? `${escapeHtml(send.status)} (${send.recipient_count})` : "not emailed"}</span></div><form method="post" action="/admin/posts/${encodeURIComponent(post.id)}/send"><button class="button button-small" type="submit" ${locked ? "disabled" : ""}>${buttonText}</button></form></div>`;
  }).join("");
  return layout("Editor", `
    <section class="admin-top"><p class="eyebrow">PRIVATE EDITOR</p><h1>Make a new note.</h1><p>Write in the simple Markdown format below. External links in newsletters will be protected automatically.</p></section>
    <section class="admin-stats"><div><span>Published notes</span><strong>${posts.length}</strong></div><div><span>Confirmed readers</span><strong>${subscribers}</strong></div><div><span>Protection</span><strong>${scannerState}</strong></div></section>
    <section class="editor-panel">
      <form action="/admin/posts" method="post" class="editor-form">
        <label for="title">Title</label><input id="title" name="title" maxlength="120" required placeholder="A clear, thoughtful title">
        <label for="summary">Short summary</label><input id="summary" name="summary" maxlength="220" required placeholder="One sentence for the journal card and email">
        <label for="markdown">Article</label><textarea id="markdown" name="markdown" rows="12" required placeholder="Write a paragraph. Use [link text](https://example.com) for links, ## for section headings, and - for bullets."></textarea>
        <span class="field-helper" id="word-count">0 words</span>
        <button class="button button-dark" type="submit">Publish note <span aria-hidden="true">↗</span></button>
      </form>
    </section>
    <section class="admin-list"><div class="section-heading"><div><p class="eyebrow">YOUR JOURNAL</p><h2>Published notes</h2></div></div>${postItems || `<p class="empty-state">No notes published yet.</p>`}</section>
    <section class="admin-test">
      <div><p class="eyebrow">PROTECTED-LINK TEST</p><h2>Try the click flow</h2><p>Create a signed first-party link without sending an email. A cache miss is queued immediately; it redirects only after all enabled scanners return a clean verdict.</p></div>
      <form action="/admin/links" method="post" class="test-link-form">
        <label for="test-target">Destination URL</label><input id="test-target" type="url" name="target_url" placeholder="https://example.com/" required>
        <label for="test-post">Attach to note</label><select id="test-post" name="post_id" required>${postOptions}</select>
        <button class="button button-blue" type="submit">Create protected link <span aria-hidden="true">↗</span></button>
      </form>
    </section>
    <section class="admin-footnote"><strong>Before sending:</strong> confirm your sender domain in Resend and configure Google Web Risk and urlscan keys. If Joe Sandbox is enabled, also accept its terms in configuration. Uncertain scans remain on the hold page.</section>`);
}

function statusHtml(title, heading, message, status = 200, { retry = false, autoRetry = false } = {}, retryPath = "/") {
  const retryLink = retry
    ? `<a class="button button-dark" href="${escapeHtml(retryPath)}" ${autoRetry ? 'data-auto-retry="true"' : ""}>${autoRetry ? "Checking again shortly…" : "Check again"}</a>`
    : `<a class="button button-dark" href="/">Back to journal</a>`;
  return { status, html: layout(title, `<section class="notice-card"><p class="eyebrow">LINK PROTECTION</p><h1>${escapeHtml(heading)}</h1><p>${escapeHtml(message)}</p>${retryLink}</section>`) };
}

function createLink(target, postId) {
  const normalized = normalizePublicUrl(target);
  const id = newId();
  db.prepare("INSERT INTO protected_links (id, post_id, target_url, created_at) VALUES (?, ?, ?, ?)")
    .run(id, postId, encryptLinkTarget(normalized, LINK_SIGNING_SECRET), new Date().toISOString());
  return PUBLIC_ORIGIN + makeProtectedPath(id, LINK_SIGNING_SECRET);
}

const SCAN_JOB_POLL_MS = Math.max(1000, Math.min(60_000, Number(process.env.SCAN_JOB_POLL_MS || JOESANDBOX_POLL_MS)));
let scanQueueTimer = null;
let scanQueueScheduledAt = 0;
let scanQueueRunning = false;

function scheduleScanQueue(delayMs = 0) {
  if (scanQueueRunning) return;
  const scheduledAt = Date.now() + Math.max(0, delayMs);
  if (scanQueueTimer && scanQueueScheduledAt <= scheduledAt) return;
  if (scanQueueTimer) clearTimeout(scanQueueTimer);
  scanQueueScheduledAt = scheduledAt;
  scanQueueTimer = setTimeout(() => {
    scanQueueTimer = null;
    scanQueueScheduledAt = 0;
    void processScanQueue();
  }, Math.max(0, delayMs));
  scanQueueTimer.unref?.();
}

function updateScanJob(urlHash, updates) {
  const allowed = new Set([
    "web_risk_done", "urlscan_id", "urlscan_done", "joe_submission_id",
    "joe_webids", "joe_done", "next_run_at", "updated_at", "last_error",
  ]);
  const entries = Object.entries(updates).filter(([key]) => allowed.has(key));
  if (!entries.length) return;
  const setters = entries.map(([key]) => `"${key}" = ?`).join(", ");
  db.prepare(`UPDATE scan_jobs SET ${setters} WHERE url_hash = ?`)
    .run(...entries.map(([, value]) => value), urlHash);
}

function cacheScanResult(urlHash, verdict, reason, {
  scanId = null, joeChecked = false,
} = {}) {
  db.prepare(`INSERT OR REPLACE INTO scan_cache
    (url_hash, scan_id, verdict, reason, checked_at, joe_checked)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .run(urlHash, scanId, verdict, String(reason || "").slice(0, 500), Date.now(), joeChecked ? 1 : 0);
  db.prepare("DELETE FROM scan_jobs WHERE url_hash = ?").run(urlHash);
}

function retryScanJob(job, reason, delayMs = SCAN_JOB_POLL_MS) {
  const now = Date.now();
  db.prepare(`UPDATE scan_jobs SET attempts = attempts + 1, updated_at = ?, next_run_at = ?, last_error = ?
    WHERE url_hash = ?`)
    .run(now, now + Math.max(1000, Math.min(60_000, delayMs)), String(reason || "Inspection pending.").slice(0, 500), job.url_hash);
}

async function processScanJob(job) {
  const now = Date.now();
  if (now - job.created_at > SCAN_JOB_MAX_WAIT_MS) {
    cacheScanResult(job.url_hash, "unknown", "Inspection timed out before a conclusive verdict was available.", {
      scanId: job.urlscan_id,
      joeChecked: false,
    });
    return;
  }

  let safeUrl;
  try {
    safeUrl = scannerSafeUrl(decryptLinkTarget(job.encrypted_url, LINK_SIGNING_SECRET));
  } catch (error) {
    cacheScanResult(job.url_hash, "unknown", `Inspection could not use this destination: ${error.message}`);
    return;
  }

  if (Number(job.web_risk_done) !== 1) {
    let reputation;
    try {
      reputation = await checkWebRisk(safeUrl, WEBRISK_API_KEY, fetch, WEBRISK_API_URL);
    } catch (error) {
      retryScanJob(job, `Web Risk lookup failed: ${error.message}`);
      return;
    }
    if (reputation.verdict === "malicious") {
      cacheScanResult(job.url_hash, "malicious", reputation.reason);
      return;
    }
    if (reputation.verdict !== "not-listed") {
      retryScanJob(job, reputation.reason || "Web Risk did not return a conclusive result.");
      return;
    }
    job.web_risk_done = 1;
    updateScanJob(job.url_hash, { web_risk_done: 1, updated_at: now });
  }

  let pendingReason = "";
  if (Number(job.urlscan_done) !== 1) {
    try {
      const browser = await runUrlscan(safeUrl, URLSCAN_API_KEY, {
        scanId: job.urlscan_id || null,
        waitMs: 0,
        pollMs: URLSCAN_POLL_MS,
        apiUrl: URLSCAN_API_URL,
      });
      if (browser.verdict === "malicious") {
        cacheScanResult(job.url_hash, "malicious", browser.reason, { scanId: browser.scanId });
        return;
      }
      if (browser.verdict === "clean") {
        job.urlscan_done = 1;
        job.urlscan_id = browser.scanId || job.urlscan_id;
        updateScanJob(job.url_hash, {
          urlscan_done: 1, urlscan_id: job.urlscan_id, updated_at: Date.now(),
        });
      } else {
        job.urlscan_id = browser.scanId || job.urlscan_id;
        updateScanJob(job.url_hash, { urlscan_id: job.urlscan_id, updated_at: Date.now() });
        pendingReason = browser.reason || "urlscan inspection is still running.";
      }
    } catch (error) {
      pendingReason = `urlscan inspection failed: ${error.message}`;
    }
  }

  if (Number(job.joe_required) === 1 && Number(job.joe_done) !== 1) {
    try {
      if (!JOESANDBOX_API_KEY || !JOESANDBOX_ACCEPT_TAC) {
        retryScanJob(job, "Joe Sandbox is enabled but its API key or explicit terms acceptance is missing.");
        return;
      }
      if (!job.joe_submission_id) {
        const submission = await submitJoeSandboxUrl(safeUrl, {
          apiKey: JOESANDBOX_API_KEY,
          apiUrl: JOESANDBOX_API_URL,
          acceptTerms: JOESANDBOX_ACCEPT_TAC,
          timeoutMs: JOESANDBOX_TIMEOUT_MS,
        });
        job.joe_submission_id = submission.submissionId;
        updateScanJob(job.url_hash, {
          joe_submission_id: job.joe_submission_id,
          updated_at: Date.now(),
        });
        pendingReason = "Joe Sandbox analysis was submitted and is running.";
      } else {
        let knownWebids = [];
        try { knownWebids = JSON.parse(job.joe_webids || "[]"); }
        catch { knownWebids = []; }
        const joe = await pollJoeSandboxSubmission(job.joe_submission_id, {
          apiKey: JOESANDBOX_API_KEY,
          apiUrl: JOESANDBOX_API_URL,
          timeoutMs: JOESANDBOX_TIMEOUT_MS,
          knownWebids,
        });
        if (joe.verdict === "malicious") {
          cacheScanResult(job.url_hash, "malicious", joe.reason);
          return;
        }
        if (joe.verdict === "clean") {
          job.joe_done = 1;
          updateScanJob(job.url_hash, {
            joe_done: 1,
            joe_webids: JSON.stringify(joe.webids || knownWebids),
            updated_at: Date.now(),
          });
        } else {
          job.joe_webids = JSON.stringify(joe.webids || knownWebids);
          updateScanJob(job.url_hash, {
            joe_webids: job.joe_webids,
            updated_at: Date.now(),
          });
          pendingReason = joe.reason || "Joe Sandbox analysis is still running.";
        }
      }
    } catch (error) {
      pendingReason = `Joe Sandbox inspection failed: ${error.message}`;
    }
  }

  if (Number(job.urlscan_done) === 1 &&
      (Number(job.joe_required) !== 1 || Number(job.joe_done) === 1)) {
    const providers = Number(job.joe_required) === 1
      ? "Google Web Risk, urlscan, and Joe Sandbox returned clean verdicts."
      : "Google Web Risk and urlscan returned clean verdicts.";
    cacheScanResult(job.url_hash, "clean", providers, {
      scanId: job.urlscan_id,
      joeChecked: Number(job.joe_required) === 1,
    });
    return;
  }
  retryScanJob(job, pendingReason || "One or more inspections are still running.");
}

async function processScanQueue() {
  if (scanQueueRunning) return;
  scanQueueRunning = true;
  try {
    const now = Date.now();
    const job = db.prepare(`SELECT * FROM scan_jobs WHERE next_run_at <= ?
      ORDER BY created_at ASC LIMIT 1`).get(now);
    if (job) await processScanJob(job);
  } catch (error) {
    console.error("[scan-queue]", error?.message || error);
  } finally {
    scanQueueRunning = false;
    const next = db.prepare("SELECT MIN(next_run_at) AS next_run_at FROM scan_jobs").get().next_run_at;
    if (next !== null && next !== undefined) {
      scheduleScanQueue(Math.max(100, Math.min(30_000, Number(next) - Date.now())));
    }
  }
}

function scanDestination(target) {
  let safe;
  try { safe = scannerSafeUrl(target); }
  catch (error) {
    return { verdict: "unknown", provider: "privacy-gate", reason: error.message };
  }
  const urlHash = hashValue(safe);
  const now = Date.now();
  const cached = db.prepare("SELECT * FROM scan_cache WHERE url_hash = ?").get(urlHash);
  const fresh = getFreshCachedVerdict(cached, now, {
    cleanTtlMs: URLSCAN_CLEAN_CACHE_SECONDS * 1000,
    unknownTtlMs: 30_000,
    requireJoe: Boolean(JOESANDBOX_API_KEY),
  });
  if (fresh) {
    return fresh;
  }

  const existingJob = db.prepare("SELECT url_hash FROM scan_jobs WHERE url_hash = ?").get(urlHash);
  if (existingJob) {
    scheduleScanQueue(0);
    return { verdict: "pending", provider: "scan-queue", reason: "Inspection is queued or running." };
  }

  if (!WEBRISK_API_KEY || !URLSCAN_API_KEY) {
    return { verdict: "unknown", provider: "configuration", reason: "Google Web Risk and urlscan API keys are required." };
  }
  if (JOESANDBOX_API_KEY && !JOESANDBOX_ACCEPT_TAC) {
    return { verdict: "unknown", provider: "configuration", reason: "Set JOESANDBOX_ACCEPT_TAC=1 only after accepting Joe Sandbox's terms." };
  }

  db.prepare(`INSERT OR IGNORE INTO scan_jobs
    (url_hash, encrypted_url, joe_required, created_at, updated_at, next_run_at)
    VALUES (?, ?, ?, ?, ?, ?)`)
    .run(
      urlHash,
      encryptLinkTarget(safe, LINK_SIGNING_SECRET),
      JOESANDBOX_API_KEY ? 1 : 0,
      now,
      now,
      now,
    );
  scheduleScanQueue(0);
  return { verdict: "pending", provider: "scan-queue", reason: "Inspection has started in the background." };
}

function getClientKey(req) {
  if (PROXY_SHARED_SECRET && req.headers["cf-connecting-ip"]) {
    return String(req.headers["cf-connecting-ip"]);
  }
  return req.socket.remoteAddress || "unknown";
}

function newToken() {
  return randomBytes(32).toString("base64url");
}

async function sendConfirmation(email, token) {
  const url = new URL("/confirm", PUBLIC_ORIGIN);
  url.searchParams.set("token", token);
  const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:36px auto;color:#2c2c2b;line-height:1.6"><p style="letter-spacing:.12em;color:#7d7a75">FIELDNOTES</p><h1>Confirm your subscription</h1><p>One quick step to receive new notes from the journal.</p><p><a href="${escapeHtml(url.toString())}" style="display:inline-block;background:#2c2c2b;color:#fff;padding:12px 18px;text-decoration:none">Confirm subscription</a></p><p style="font-size:13px;color:#7d7a75">If you didn’t request this, you can ignore this email.</p></div>`;
  return sendEmail({
    apiKey: RESEND_API_KEY, apiUrl: RESEND_API_URL,
    from: EMAIL_FROM, to: email, subject: "Confirm your Fieldnotes subscription", html,
  });
}

async function emailPost(post, subscriber) {
  const token = newToken();
  db.prepare("INSERT INTO unsubscribe_tokens (token_hash, email, created_at) VALUES (?, ?, ?)")
    .run(hashValue(token), subscriber.email, new Date().toISOString());
  let html = renderArticle(post, { email: true });
  html = html.replace("{{UNSUBSCRIBE_TOKEN}}", encodeURIComponent(token));
  return sendEmail({
    apiKey: RESEND_API_KEY,
    apiUrl: RESEND_API_URL,
    from: EMAIL_FROM,
    to: subscriber.email,
    subject: post.title,
    html,
  });
}

async function handle(req, res) {
  setHeaders(res);
  if (PROXY_SHARED_SECRET &&
      !constantStringEqual(req.headers["x-clicktime-proxy-token"] || "", PROXY_SHARED_SECRET)) {
    sendText(res, 403, "Forbidden");
    return;
  }
  const requestUrl = new URL(req.url || "/", PUBLIC_ORIGIN);
  const pathname = requestUrl.pathname;
  const clientKey = getClientKey(req);

  if (req.method === "GET" && pathname === "/styles.css") {
    setHeaders(res, "text/css; charset=utf-8");
    res.writeHead(200);
    res.end(await (await import("node:fs/promises")).readFile(new URL("../public/styles.css", import.meta.url)));
    return;
  }
  if (req.method === "GET" && pathname === "/app.js") {
    setHeaders(res, "text/javascript; charset=utf-8");
    res.writeHead(200);
    res.end(await (await import("node:fs/promises")).readFile(new URL("../public/app.js", import.meta.url)));
    return;
  }
  if (req.method === "GET" && pathname === "/") {
    sendHtml(res, 200, homePage());
    return;
  }
  if (req.method === "GET" && pathname.startsWith("/p/")) {
    const slug = pathname.slice(3);
    const post = postBySlug(slug);
    if (!post) { sendHtml(res, 404, layout("Not found", `<section class="notice-card"><p class="eyebrow">404</p><h1>That note isn’t here.</h1><p>It may have moved, or the address may be mistyped.</p><a class="button button-dark" href="/">Back to journal</a></section>`)); return; }
    sendHtml(res, 200, articlePage(post));
    return;
  }
  if (req.method === "GET" && pathname === "/admin") {
    if (requireAdmin(req, res)) sendHtml(res, 200, adminPage());
    return;
  }
  if (req.method === "POST" && pathname === "/admin/posts") {
    if (!requireAdmin(req, res) || !sameOriginPost(req, res)) return;
    const fields = formData(await readBody(req));
    const title = (fields.title || "").trim().slice(0, 120);
    const summary = (fields.summary || "").trim().slice(0, 220);
    const markdown = (fields.markdown || "").trim().slice(0, 20_000);
    if (!title || !summary || !markdown) {
      sendHtml(res, 400, layout("Missing details", `<section class="notice-card"><h1>Complete all fields.</h1><p>Title, summary, and article are required.</p><a class="button button-dark" href="/admin">Return to editor</a></section>`));
      return;
    }
    const base = slugify(title);
    const slug = db.prepare("SELECT slug FROM posts WHERE slug = ?").get(base) ? `${base}-${randomBytes(3).toString("hex")}` : base;
    const id = newId();
    db.prepare("INSERT INTO posts (id, slug, title, summary, markdown, published_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(id, slug, title, summary, markdown, new Date().toISOString());
    res.writeHead(303, { Location: "/admin" });
    res.end();
    return;
  }
  if (req.method === "POST" && pathname === "/admin/links") {
    if (!requireAdmin(req, res) || !sameOriginPost(req, res)) return;
    const fields = formData(await readBody(req));
    const post = db.prepare("SELECT id FROM posts WHERE id = ?").get(fields.post_id || "");
    if (!post) {
      sendHtml(res, 400, layout("Choose a note", `<section class="notice-card"><h1>Select a published note.</h1><a class="button button-dark" href="/admin">Return to editor</a></section>`));
      return;
    }
    let protectedUrl;
    try { protectedUrl = createLink(fields.target_url || "", post.id); }
    catch (error) {
      sendHtml(res, 400, layout("Destination not allowed", `<section class="notice-card"><p class="eyebrow">PROTECTED-LINK TEST</p><h1>That destination can’t be used.</h1><p>${escapeHtml(error.message)}</p><a class="button button-dark" href="/admin">Return to editor</a></section>`));
      return;
    }
    sendHtml(res, 201, layout("Protected link created", `<section class="notice-card"><p class="eyebrow">PROTECTED-LINK TEST</p><h1>Your first-party link is ready.</h1><p>Clicking it queues the configured reputation and sandbox checks. The first cache miss returns a hold page immediately; it redirects only after all enabled providers report clean.</p><p class="protected-link-output"><a href="${escapeHtml(protectedUrl)}">${escapeHtml(protectedUrl)}</a></p><a class="button button-dark" href="/admin">Back to editor</a></section>`));
    return;
  }
  if (req.method === "POST" && /^\/admin\/posts\/[0-9a-f-]+\/send$/.test(pathname)) {
    if (!requireAdmin(req, res) || !sameOriginPost(req, res)) return;
    if (!rateAllowed(`send:${clientKey}`, 2, 60_000)) {
      sendHtml(res, 429, layout("Slow down", `<section class="notice-card"><h1>Please wait a minute.</h1><p>Newsletter sends are temporarily rate-limited.</p><a class="button button-dark" href="/admin">Back to editor</a></section>`));
      return;
    }
    const postId = pathname.split("/")[3];
    const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(postId);
    if (!post) { sendHtml(res, 404, layout("Not found", `<section class="notice-card"><h1>Post not found.</h1></section>`)); return; }
    const prior = db.prepare("SELECT status FROM newsletter_sends WHERE post_id = ?").get(postId);
    if (prior && ["sent", "sending", "partial"].includes(prior.status)) {
      const detail = prior.status === "partial"
        ? "Some recipients may already have received it. Review the delivery provider before taking any manual action."
        : "We prevent accidental duplicate newsletters.";
      sendHtml(res, 409, layout("Already sent", `<section class="notice-card"><h1>This note has already been sent or is in progress.</h1><p>${detail}</p><a class="button button-dark" href="/admin">Back to editor</a></section>`));
      return;
    }
    const subscribers = db.prepare("SELECT email FROM subscribers WHERE status = 'active' ORDER BY email").all();
    if (!subscribers.length) {
      sendHtml(res, 409, layout("No readers yet", `<section class="notice-card"><h1>No confirmed subscribers yet.</h1><p>Send will be available when readers confirm their subscription.</p><a class="button button-dark" href="/admin">Back to editor</a></section>`));
      return;
    }
    db.prepare(`INSERT OR REPLACE INTO newsletter_sends (post_id, status, recipient_count, updated_at, error)
      VALUES (?, 'sending', 0, ?, NULL)`).run(postId, new Date().toISOString());
    let sent = 0;
    let error = "";
    try {
      for (const subscriber of subscribers) {
        await emailPost(post, subscriber);
        sent += 1;
      }
      db.prepare("UPDATE newsletter_sends SET status = 'sent', recipient_count = ?, updated_at = ?, error = NULL WHERE post_id = ?")
        .run(sent, new Date().toISOString(), postId);
    } catch (err) {
      error = err.message.slice(0, 500);
      db.prepare("UPDATE newsletter_sends SET status = 'partial', recipient_count = ?, updated_at = ?, error = ? WHERE post_id = ?")
        .run(sent, new Date().toISOString(), error, postId);
    }
    const message = error
      ? `Sent to ${sent} reader(s) before an email provider error. Check the provider dashboard before retrying.`
      : `The note was emailed to ${sent} confirmed reader(s).`;
    sendHtml(res, error ? 502 : 200, layout(error ? "Partial send" : "Newsletter sent", `<section class="notice-card"><p class="eyebrow">${error ? "CHECK DELIVERY" : "SENT"}</p><h1>${error ? "Some mail may not have gone out." : "Your note is on its way."}</h1><p>${escapeHtml(message)}</p><a class="button button-dark" href="/admin">Return to editor</a></section>`));
    return;
  }
  if (req.method === "POST" && pathname === "/subscribe") {
    if (!sameOriginPost(req, res)) return;
    if (!rateAllowed(`subscribe:${clientKey}`, 5, 10 * 60_000)) {
      sendHtml(res, 429, layout("Try later", `<section class="notice-card"><h1>Please try again later.</h1><p>We received too many subscription requests from this connection.</p></section>`));
      return;
    }
    const fields = formData(await readBody(req));
    const email = (fields.email || "").trim().toLowerCase();
    if (!safeEmail(email) || fields.consent !== "yes") {
      sendHtml(res, 400, layout("Check the form", `<section class="notice-card"><h1>Enter a valid email and confirm consent.</h1><a class="button button-dark" href="/">Return to journal</a></section>`));
      return;
    }
    const existing = db.prepare("SELECT status FROM subscribers WHERE email = ?").get(email);
    if (existing?.status === "active") {
      sendHtml(res, 200, layout("Already subscribed", `<section class="notice-card"><p class="eyebrow">THANK YOU</p><h1>You’re already on the list.</h1><p>We’ll send the next note when it’s ready.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
      return;
    }
    const token = newToken();
    db.prepare(`INSERT INTO subscribers (email, status, confirm_hash, consent_at, confirmed_at)
      VALUES (?, 'pending', ?, ?, NULL)
      ON CONFLICT(email) DO UPDATE SET status = 'pending', confirm_hash = excluded.confirm_hash, consent_at = excluded.consent_at`)
      .run(email, hashValue(token), new Date().toISOString());
    try { await sendConfirmation(email, token); }
    catch (error) {
      sendHtml(res, 503, layout("Email not sent", `<section class="notice-card"><h1>We couldn’t send the confirmation.</h1><p>${escapeHtml(error.message)}</p><p>Your address is not subscribed; please try again later.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
      return;
    }
    sendHtml(res, 200, layout("Check your inbox", `<section class="notice-card"><p class="eyebrow">ONE QUICK STEP</p><h1>Check your inbox.</h1><p>We sent a confirmation link to ${escapeHtml(email)}. You’ll be subscribed after you confirm.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
    return;
  }
  if (req.method === "GET" && pathname === "/confirm") {
    const token = requestUrl.searchParams.get("token") || "";
    sendHtml(res, 200, layout("Confirm subscription", `<section class="notice-card"><p class="eyebrow">NEWSLETTER</p><h1>Confirm your subscription.</h1><p>Press confirm to add your address to the journal list.</p><form method="post" action="/confirm"><input type="hidden" name="token" value="${escapeHtml(token)}"><button class="button button-dark" type="submit">Confirm subscription</button></form></section>`));
    return;
  }
  if (req.method === "POST" && pathname === "/confirm") {
    if (!sameOriginPost(req, res)) return;
    const { token = "" } = formData(await readBody(req));
    const subscriber = db.prepare("SELECT email FROM subscribers WHERE confirm_hash = ? AND status = 'pending'").get(hashValue(token));
    if (!subscriber || token.length < 20) {
      sendHtml(res, 400, layout("Invalid confirmation", `<section class="notice-card"><h1>This confirmation link is invalid or already used.</h1><a class="button button-dark" href="/">Back to journal</a></section>`));
      return;
    }
    db.prepare("UPDATE subscribers SET status = 'active', confirmed_at = ?, confirm_hash = NULL WHERE email = ?")
      .run(new Date().toISOString(), subscriber.email);
    sendHtml(res, 200, layout("Confirmed", `<section class="notice-card"><p class="eyebrow">YOU’RE IN</p><h1>Subscription confirmed.</h1><p>Thanks for joining. The next note will arrive by email.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
    return;
  }
  if (req.method === "GET" && pathname === "/unsubscribe") {
    const token = requestUrl.searchParams.get("token") || "";
    sendHtml(res, 200, layout("Unsubscribe", `<section class="notice-card"><p class="eyebrow">NEWSLETTER</p><h1>Leave the list?</h1><p>Confirm below and we’ll stop sending journal updates.</p><form method="post" action="/unsubscribe"><input type="hidden" name="token" value="${escapeHtml(token)}"><button class="button button-dark" type="submit">Unsubscribe</button></form></section>`));
    return;
  }
  if (req.method === "POST" && pathname === "/unsubscribe") {
    if (!sameOriginPost(req, res)) return;
    const { token = "" } = formData(await readBody(req));
    const tokenHash = hashValue(token);
    const record = db.prepare("SELECT email FROM unsubscribe_tokens WHERE token_hash = ?").get(tokenHash);
    if (!record || token.length < 20) {
      sendHtml(res, 400, layout("Invalid link", `<section class="notice-card"><h1>This unsubscribe link is invalid.</h1><a class="button button-dark" href="/">Back to journal</a></section>`));
      return;
    }
    db.prepare("UPDATE subscribers SET status = 'unsubscribed' WHERE email = ?").run(record.email);
    sendHtml(res, 200, layout("Unsubscribed", `<section class="notice-card"><p class="eyebrow">DONE</p><h1>You’re off the list.</h1><p>You won’t receive future journal emails at this address.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
    return;
  }
  if (req.method === "GET" && (pathname.startsWith("/go/") || pathname.startsWith("/v2/___"))) {
    if (!rateAllowed(`click:${clientKey}`, 60, 60_000)) {
      sendHtml(res, 429, layout("Try again soon", `<section class="notice-card"><h1>Please wait a moment.</h1><p>Too many link checks from this connection.</p></section>`));
      return;
    }
    const legacyLink = pathname.startsWith("/v2/___");
    const marker = legacyLink ? pathname.lastIndexOf("/___.") : -1;
    const token = legacyLink
      ? marker < 0 ? "" : pathname.slice(marker + 5)
      : pathname.slice("/go/".length);
    const id = verifyProtectedToken(token, LINK_SIGNING_SECRET, { allowLegacy: legacyLink });
    if (!id) {
      sendHtml(res, 403, layout("Invalid link", `<section class="notice-card"><p class="eyebrow">LINK PROTECTION</p><h1>This protected link is invalid.</h1><p>The link may have been changed or is not recognized.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
      return;
    }
    const link = db.prepare("SELECT * FROM protected_links WHERE id = ?").get(id);
    if (!link) {
      sendHtml(res, 404, layout("Link unavailable", `<section class="notice-card"><h1>This protected link is no longer available.</h1><p>Ask the sender for a fresh copy of the email.</p></section>`));
      return;
    }
    let targetUrl;
    try { targetUrl = normalizePublicUrl(decryptLinkTarget(link.target_url, LINK_SIGNING_SECRET)); }
    catch {
      db.prepare("INSERT INTO click_events (link_id, clicked_at, verdict, provider, reason) VALUES (?, ?, 'malicious', 'destination-validation', 'Destination rejected by URL policy.')")
        .run(id, new Date().toISOString());
      sendHtml(res, 403, layout("Blocked", `<section class="notice-card risk-card"><p class="eyebrow">DESTINATION BLOCKED</p><h1>This destination is not allowed.</h1><p>The link points to an invalid, local, or private destination.</p></section>`));
      return;
    }
    const expectedPath = legacyLink
      ? makeLegacyProtectedPath(id, LINK_SIGNING_SECRET, targetUrl)
      : `/go/${token}`;
    if (pathname !== expectedPath) {
      sendHtml(res, 403, layout("Link mismatch", `<section class="notice-card"><p class="eyebrow">LINK PROTECTION</p><h1>The destination in this link was changed.</h1><p>For your protection, this link will not be opened.</p></section>`));
      return;
    }
    const result = await scanDestination(targetUrl);
    db.prepare("INSERT INTO click_events (link_id, clicked_at, verdict, provider, reason) VALUES (?, ?, ?, ?, ?)")
      .run(id, new Date().toISOString(), result.verdict, result.provider || "unknown", String(result.reason || "").slice(0, 500));
    if (result.verdict === "clean") {
      res.writeHead(302, { Location: targetUrl, "Cache-Control": "no-store" });
      res.end();
      return;
    }
    const malicious = result.verdict === "malicious";
    const queued = result.verdict === "pending";
    const page = statusHtml(
      malicious ? "Destination blocked" : queued ? "Inspection in progress" : "Link inspection required",
      malicious ? "DESTINATION BLOCKED" : queued ? "CHECKING DESTINATION" : "INSPECTION REQUIRED",
      malicious
        ? "This destination was flagged as potentially harmful."
        : queued
          ? "This page responds while checks run in the background. Please check again in a few seconds; the link will not open until every enabled scanner reports clean."
          : "We couldn’t verify this destination yet, so we’re holding the link for your safety.",
      malicious ? 403 : queued ? 202 : 503,
      { retry: !malicious, autoRetry: queued },
      req.url || "/",
    );
    sendHtml(res, page.status, page.html);
    return;
  }

  sendHtml(res, 404, layout("Not found", `<section class="notice-card"><p class="eyebrow">404</p><h1>That page isn’t here.</h1><p>Try returning to the journal.</p><a class="button button-dark" href="/">Back to journal</a></section>`));
}

const server = createServer((req, res) => {
  Promise.resolve(handle(req, res)).catch((error) => {
    console.error("[request-error]", error?.message || error);
    if (res.headersSent) { res.end(); return; }
    sendHtml(res, 500, layout("Something went wrong", `<section class="notice-card"><p class="eyebrow">SERVER ERROR</p><h1>We couldn’t complete that request.</h1><p>Please try again. If it continues, contact the site administrator.</p></section>`));
  });
});

server.listen(PORT, () => {
  console.log(`Fieldnotes is running at ${PUBLIC_ORIGIN}`);
  console.log(`Editor: ${ADMIN_PASSWORD ? "enabled" : "disabled (set ADMIN_PASSWORD)"}`);
  console.log(`Scanning: ${WEBRISK_API_KEY && URLSCAN_API_KEY ? "provider keys configured" : "fail-closed (provider keys required)"}`);
  console.log(`Joe Sandbox: ${JOESANDBOX_API_KEY ? JOESANDBOX_ACCEPT_TAC ? "enabled" : "API key set; explicit terms acceptance required" : "optional (not enabled)"}`);
  scheduleScanQueue(0);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}