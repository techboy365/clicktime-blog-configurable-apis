import { sendEmail } from "../src/email.mjs";
import { checkWebRisk, runUrlscan } from "../src/scanners.mjs";
import { pollJoeSandboxSubmission, submitJoeSandboxUrl } from "../src/joe-sandbox.mjs";
import {
  assertPublicDns, decryptLinkTarget, encryptLinkTarget, escapeHtml, hashValue,
  makeProtectedPath, newId, newToken, normalizePublicUrl, renderMarkdown,
  scannerSafeUrl, slugify, verifyProtectedToken,
} from "./security.mjs";

const SAFE_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; connect-src 'self'",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};
const DEFAULT_WEBRISK_API_URL = "https://webrisk.googleapis.com/v1/uris:search";
const DEFAULT_URLSCAN_API_URL = "https://urlscan.io/api/v1";
const DEFAULT_JOE_API_URL = "https://jbxcloud.joesecurity.org/api";
const LOCAL_LIMITS = new Map();

function htmlResponse(html, status = 200, headers = {}) {
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...SAFE_HEADERS, ...headers },
  });
}

function page(title, content, description = "A thoughtful blog with links inspected at click time.") {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${escapeHtml(description)}"><meta name="theme-color" content="#f8f7f4">
<title>${escapeHtml(title)} · Fieldnotes</title><link rel="stylesheet" href="/styles.css"><script src="/app.js" defer></script></head>
<body><header class="site-header"><a class="brand" href="/" aria-label="Fieldnotes home"><span class="brand-mark">f</span><span>fieldnotes</span></a>
<nav aria-label="Primary navigation"><a href="/#latest">Journal</a><a href="/#subscribe">Newsletter</a><a class="nav-admin" href="/admin">Editor</a></nav></header>
<main>${content}</main><footer class="site-footer"><span>Notes worth keeping.</span><span>Thoughtful writing · safer links</span></footer></body></html>`;
}

function notice(title, heading, message, status = 200, retry = false) {
  const button = retry
    ? `<a class="button button-dark" href="${escapeHtml(retry)}" data-auto-retry="true">Checking again shortly…</a>`
    : `<a class="button button-dark" href="/">Back to journal</a>`;
  return htmlResponse(page(title, `<section class="notice-card"><p class="eyebrow">LINK PROTECTION</p><h1>${escapeHtml(heading)}</h1><p>${escapeHtml(message)}</p>${button}</section>`), status);
}

function getPublicOrigin(request, env) {
  return String(env.PUBLIC_ORIGIN || new URL(request.url).origin).replace(/\/+$/, "");
}

function constantEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  let mismatch = a.length ^ b.length;
  const size = Math.max(a.length, b.length);
  for (let index = 0; index < size; index += 1) mismatch |= (a[index] || 0) ^ (b[index] || 0);
  return mismatch === 0;
}

function decodeBasicAuth(value) {
  try {
    const [scheme, encoded] = String(value || "").split(" ");
    if (scheme !== "Basic" || !encoded) return ["", ""];
    const decoded = atob(encoded);
    const colon = decoded.indexOf(":");
    if (colon < 0) return ["", ""];
    return [decoded.slice(0, colon), decoded.slice(colon + 1)];
  } catch { return ["", ""]; }
}

function requireAdmin(request, env) {
  const password = env.ADMIN_PASSWORD || "";
  if (!password || password.length < 16) {
    return htmlResponse(page("Editor setup required", `<section class="notice-card"><p class="eyebrow">SETUP NEEDED</p><h1>Editor access is not configured.</h1><p>Set a strong ADMIN_PASSWORD Worker secret before using the editor.</p></section>`), 503);
  }
  const [user, suppliedPassword] = decodeBasicAuth(request.headers.get("authorization"));
  if (!constantEqual(user, env.ADMIN_USER || "editor") || !constantEqual(suppliedPassword, password)) {
    return htmlResponse(page("Sign in", `<section class="notice-card"><p class="eyebrow">PRIVATE EDITOR</p><h1>Sign in to continue.</h1><p>Your browser should ask for the editor credentials configured for this site.</p></section>`), 401, {
      "www-authenticate": 'Basic realm="Blog editor", charset="UTF-8"',
    });
  }
  return null;
}

function sameOriginPost(request, env) {
  const expected = getPublicOrigin(request, env);
  return request.headers.get("origin") === expected;
}

async function readForm(request, maxBytes = 200_000) {
  const text = await request.text();
  if (new TextEncoder().encode(text).length > maxBytes) throw new Error("Request body is too large.");
  return Object.fromEntries(new URLSearchParams(text));
}

async function rateAllowed(env, key, limit, periodSeconds = 60, binding = null) {
  const rateLimitBinding = binding || env.RATE_LIMITER;
  if (rateLimitBinding) {
    const result = await rateLimitBinding.limit({ key });
    return result.success;
  }
  // Local-only fallback for `wrangler dev`; production binds Cloudflare's limiter.
  const now = Date.now();
  const bucket = LOCAL_LIMITS.get(key);
  if (!bucket || bucket.resetAt <= now) {
    LOCAL_LIMITS.set(key, { count: 1, resetAt: now + periodSeconds * 1000 });
    return true;
  }
  if (bucket.count >= limit) return false;
  bucket.count += 1;
  return true;
}

function clientKey(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

function dateLabel(value, options = { year: "numeric", month: "long", day: "numeric" }) {
  return new Date(value).toLocaleDateString("en-US", options);
}

async function postList(env) {
  const result = await env.DB.prepare("SELECT * FROM posts ORDER BY published_at DESC").all();
  return result.results || [];
}

export async function renderArticle(post, env, {
  email = false, origin: requestedOrigin, recipientEmail = null,
} = {}) {
  const origin = String(requestedOrigin || env.PUBLIC_ORIGIN || "https://example.invalid").replace(/\/+$/, "");
  let body = renderMarkdown(post.markdown);
  if (email) {
    const matches = [...body.matchAll(/href="(https?:\/\/[^"]+)"/gi)];
    for (const match of matches) {
      const href = match[1].replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
      try {
        const target = normalizePublicUrl(href);
        if (new URL(target).origin === origin) continue;
        const id = newId();
        await env.DB.prepare(`INSERT INTO protected_links
(id, post_id, target_url, created_at, recipient_email) VALUES (?, ?, ?, ?, ?)`)
          .bind(id, post.id, await encryptLinkTarget(target, env.LINK_SIGNING_SECRET),
            new Date().toISOString(), recipientEmail).run();
        const signedPath = await makeProtectedPath(id, env.LINK_SIGNING_SECRET);
        body = body.replace(match[0], `href="${escapeHtml(origin + signedPath)}"`);
      } catch { /* Keep malformed or disallowed article links unchanged. */ }
    }
  }
  const date = dateLabel(post.published_at);
  if (email) {
    return `<div style="max-width:640px;margin:0 auto;padding:28px 20px;font-family:Arial,sans-serif;color:#2c2c2b;line-height:1.65">
<p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#7d7a75">FIELDNOTES JOURNAL</p>
<h1 style="font-size:30px;line-height:1.2">${escapeHtml(post.title)}</h1><p style="color:#7d7a75">${escapeHtml(date)}</p>
<p style="font-size:18px">${escapeHtml(post.summary)}</p>${body}<hr style="border:0;border-top:1px solid #e6e5e3;margin:32px 0">
<p style="font-size:12px;color:#7d7a75">Links in this email are checked when clicked. <a href="${escapeHtml(origin)}/unsubscribe?token={{UNSUBSCRIBE_TOKEN}}">Unsubscribe</a></p></div>`;
  }
  return `<article class="article"><a class="back-link" href="/#latest">← All notes</a>
<p class="eyebrow">${escapeHtml(date)} <span>·</span> 4 min read</p><h1>${escapeHtml(post.title)}</h1>
<p class="article-summary">${escapeHtml(post.summary)}</p><div class="article-body">${body}</div>
<div class="article-end"><span class="end-dot"></span><span class="end-dot"></span><span class="end-dot"></span></div></article>`;
}

async function homePage(env) {
  const posts = await postList(env);
  const cards = posts.length ? posts.map((post, index) => `<article class="post-card ${index === 0 ? "post-featured" : ""}">
<div class="post-meta"><span>${dateLabel(post.published_at)}</span><span class="meta-dot">·</span><span>Journal</span></div>
<h3><a href="/p/${encodeURIComponent(post.slug)}">${escapeHtml(post.title)}</a></h3><p>${escapeHtml(post.summary)}</p>
<a class="read-link" href="/p/${encodeURIComponent(post.slug)}">Read note <span aria-hidden="true">↗</span></a></article>`).join("")
    : `<p class="empty-state">The first note is on its way.</p>`;
  const content = `<section class="hero"><div class="hero-copy"><p class="eyebrow"><span class="hero-spark"></span> THE FIELDNOTES JOURNAL</p>
<h1>Good ideas,<br><em>kept close.</em></h1><p class="hero-intro">A small journal for considered perspectives, practical discoveries, and the details worth sharing.</p>
<a class="button button-dark" href="#latest">Explore the journal <span aria-hidden="true">↓</span></a></div>
<div class="hero-art" aria-hidden="true"><div class="art-label">A quieter<br>corner of the web</div><div class="art-number">01 / 26</div></div>
<div class="hero-caption"><span>Ideas for the in-between</span><span>Est. 2026</span></div></section>
<section class="latest-section" id="latest"><div class="section-heading"><div><p class="eyebrow">FROM THE JOURNAL</p><h2>Latest notes</h2></div>
<span class="section-count">${String(posts.length).padStart(2, "0")} notes</span></div><div class="post-grid">${cards}</div></section>
<section class="newsletter-section" id="subscribe"><div class="newsletter-copy"><p class="eyebrow">A LETTER, OCCASIONALLY</p>
<h2>Make room for<br><em>good reading.</em></h2><p>New notes, sent with care. No noise, and you can leave whenever you like.</p></div>
<form class="subscribe-form" action="/subscribe" method="post"><label for="subscriber-email">Your email address</label>
<div class="subscribe-row"><input id="subscriber-email" type="email" name="email" autocomplete="email" placeholder="you@example.com" required>
<button type="submit" class="button button-blue">Subscribe <span aria-hidden="true">↗</span></button></div>
<label class="consent"><input type="checkbox" name="consent" value="yes" required><span>I agree to receive the newsletter and understand I can unsubscribe at any time.</span></label>
<p class="form-note">We’ll send a confirmation email before adding you to the list.</p><p class="form-message" role="status" aria-live="polite"></p></form></section>
<section class="safety-strip"><div class="safety-icon">✓</div><div><strong>Thoughtful links, checked at click time.</strong><p>Email links are checked before readers reach the destination.</p></div><a href="#subscribe" aria-label="Subscribe to Fieldnotes">Stay in the loop ↗</a></section>`;
  return page("A journal for thoughtful reading", content);
}

async function adminPage(env) {
  const [posts, subscriberCount, sendsResult, flaggedClicksResult] = await Promise.all([
    postList(env),
    env.DB.prepare("SELECT COUNT(*) AS n FROM subscribers WHERE status = 'active'").first(),
    env.DB.prepare("SELECT post_id, status, recipient_count, updated_at FROM newsletter_sends ORDER BY updated_at DESC LIMIT 5").all(),
    env.DB.prepare(`SELECT click_events.clicked_at, click_events.provider, click_events.reason,
  protected_links.recipient_email, posts.title AS post_title
FROM click_events
JOIN protected_links ON protected_links.id = click_events.link_id
JOIN posts ON posts.id = protected_links.post_id
WHERE click_events.verdict = 'malicious'
ORDER BY click_events.clicked_at DESC LIMIT 20`).all(),
  ]);
  const sends = sendsResult.results || [];
  const flaggedClicks = flaggedClicksResult.results || [];
  const scannerState = !env.WEBRISK_API_KEY || !env.URLSCAN_API_KEY ? "Needs keys"
    : env.JOESANDBOX_API_KEY && env.JOESANDBOX_ACCEPT_TAC !== "1" ? "Joe terms needed" : "Configured";
  const options = posts.map((post) => `<option value="${escapeHtml(post.id)}">${escapeHtml(post.title)}</option>`).join("");
  const rows = posts.map((post) => {
    const send = sends.find((item) => item.post_id === post.id);
    const locked = ["sent", "sending", "partial"].includes(send?.status);
    const label = send?.status === "sent" ? "Sent" : send?.status === "partial" ? "Review partial send" : send?.status === "sending" ? "Sending…" : "Email subscribers";
    return `<div class="admin-post"><div><strong>${escapeHtml(post.title)}</strong><span>${escapeHtml(post.slug)} · ${send ? `${escapeHtml(send.status)} (${send.recipient_count})` : "not emailed"}</span></div>
<form method="post" action="/admin/posts/${encodeURIComponent(post.id)}/send"><button class="button button-small" type="submit" ${locked ? "disabled" : ""}>${label}</button></form></div>`;
  }).join("");
  const content = `<section class="admin-top"><p class="eyebrow">PRIVATE EDITOR</p><h1>Make a new note.</h1>
<p>Write and publish an article, add protected external links, then email it to confirmed subscribers.</p></section>
<section class="admin-stats"><div><span>Published notes</span><strong>${posts.length}</strong></div><div><span>Confirmed readers</span><strong>${subscriberCount?.n || 0}</strong></div><div><span>Protection</span><strong>${scannerState}</strong></div></section>
<section class="admin-workflow"><strong>How to send a post</strong><ol><li>Write your article and insert external links below.</li><li>Click <b>Publish note</b>. Publishing adds it to the website; it does not email it yet.</li><li>Find the new post under <b>Published notes</b> and click <b>Email subscribers</b>.</li></ol><p>Only confirmed subscribers receive the email.</p></section>
<section class="editor-panel"><form action="/admin/posts" method="post" class="editor-form"><label for="title">Title</label><input id="title" name="title" maxlength="120" required placeholder="A clear, thoughtful title">
<label for="summary">Short summary</label><input id="summary" name="summary" maxlength="220" required placeholder="One sentence for the journal card and email">
<label for="markdown">Article</label><textarea id="markdown" name="markdown" rows="12" required placeholder="Write your article here. You can insert a link with the tool below."></textarea>
<div class="link-tool"><strong>Add an external link</strong><p>Enter the words readers will see and the destination URL. The link will be inserted at the cursor in your article.</p>
<div class="link-tool-fields"><div><label for="link-text">Link text</label><input id="link-text" type="text" maxlength="300" placeholder="Read the full report"></div>
<div><label for="link-url">Destination URL</label><input id="link-url" type="url" placeholder="https://example.com/report"></div></div>
<div class="link-tool-actions"><button class="button button-small" type="button" id="insert-link">Insert link into article</button><span class="field-helper" id="link-status" role="status" aria-live="polite"></span></div></div>
<span class="field-helper" id="word-count">0 words</span><button class="button button-dark" type="submit">Publish note <span aria-hidden="true">↗</span></button></form></section>
<section class="admin-list" id="published-notes"><div class="section-heading"><div><p class="eyebrow">STEP 3 — SEND</p><h2>Published notes</h2></div></div>
<p>After publishing, use <b>Email subscribers</b> beside a post to send it. Links in the email are rewritten and checked when clicked.</p>${rows || `<p class="empty-state">Publish your first note to see it here.</p>`}</section>
<section class="admin-list"><div class="section-heading"><div><p class="eyebrow">CLICK-TIME FORENSICS</p><h2>Flagged link clicks</h2></div></div>
<p>Recipient-level attribution shows who a newsletter link was issued to. If an email was forwarded, it cannot identify the person who actually clicked.</p>
${flaggedClicks.length ? flaggedClicks.map((click) => `<div class="admin-post"><div><strong>${escapeHtml(click.recipient_email || "No newsletter recipient recorded")}</strong>
<span>${escapeHtml(click.post_title)} · ${escapeHtml(dateLabel(click.clicked_at))} · ${escapeHtml(click.provider)}</span>
<span>${escapeHtml(click.reason || "Flagged by a scanner.")}</span></div></div>`).join("")
  : `<p class="empty-state">No malicious link clicks have been recorded.</p>`}</section>
<section class="admin-test"><div><p class="eyebrow">PROTECTED-LINK TEST</p><h2>Try the click flow</h2>
<p>Create a signed first-party link without sending an email. A cache miss is queued immediately; it redirects only after all enabled scanners return clean.</p></div>
<form action="/admin/links" method="post" class="test-link-form"><label for="test-target">Destination URL</label><input id="test-target" type="url" name="target_url" placeholder="https://example.com/" required>
<label for="test-post">Attach to note</label><select id="test-post" name="post_id" required>${options}</select>
<button class="button button-blue" type="submit">Create protected link <span aria-hidden="true">↗</span></button></form></section>
<section class="admin-footnote"><strong>Before sending:</strong> confirm your sender domain in Resend and configure Google Web Risk and urlscan keys. Uncertain scans remain on the hold page.</section>`;
  return page("Editor", content);
}

async function recordClick(env, id, verdict, provider, reason, urlHash = null) {
  await env.DB.prepare(`INSERT INTO click_events
(link_id, clicked_at, verdict, provider, reason, url_hash) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(id, new Date().toISOString(), verdict, provider || "unknown",
      String(reason || "").slice(0, 500), urlHash).run();
}

async function updatePendingClickEvents(env, urlHash, verdict, provider, reason) {
  await env.DB.prepare(`UPDATE click_events
SET verdict = ?, provider = ?, reason = ?
WHERE url_hash = ? AND verdict = 'pending'`)
    .bind(verdict, provider, String(reason || "").slice(0, 500), urlHash).run();
}

async function cachedVerdict(env, hash) {
  const cached = await env.DB.prepare("SELECT * FROM scan_cache WHERE url_hash = ?").bind(hash).first();
  if (!cached || !Number.isFinite(Number(cached.checked_at))) return null;
  const age = Date.now() - Number(cached.checked_at);
  if (cached.verdict === "clean" && age < Number(env.URLSCAN_CLEAN_CACHE_SECONDS || 300) * 1000 &&
      (!env.JOESANDBOX_API_KEY || Number(cached.joe_checked) === 1)) return cached;
  if (cached.verdict === "malicious" && age < 86_400_000) return cached;
  if (cached.verdict === "unknown" && age < 30_000) return cached;
  return null;
}

async function clickRoute(request, env, token) {
  if (!await rateAllowed(env, `click:${clientKey(request)}`, 60, 60, env.CLICK_RATE_LIMITER)) {
    return notice("Try again soon", "Please wait a moment.", "Too many link checks came from this connection.", 429);
  }
  const id = await verifyProtectedToken(token, env.LINK_SIGNING_SECRET || "");
  if (!id) return notice("Invalid link", "This protected link is invalid.", "The link may have been changed or is not recognized.", 403);
  const link = await env.DB.prepare("SELECT * FROM protected_links WHERE id = ?").bind(id).first();
  if (!link) return notice("Link unavailable", "This protected link is no longer available.", "Ask the sender for a fresh copy of the email.", 404);
  let target;
  try {
    target = normalizePublicUrl(await decryptLinkTarget(link.target_url, env.LINK_SIGNING_SECRET));
    if (request.url.split("?")[0] !== `${getPublicOrigin(request, env)}/go/${token}`) throw new Error("Link path does not match its signed token.");
  } catch {
    await recordClick(env, id, "malicious", "destination-validation", "Stored destination or link path was rejected.");
    return notice("Blocked", "This destination is not allowed.", "The link points to an invalid or disallowed destination.", 403);
  }

  let safe;
  try { safe = scannerSafeUrl(target); }
  catch (error) {
    await recordClick(env, id, "unknown", "privacy-gate", error.message);
    return notice("Inspection required", "This link needs review.", "The destination contains data that is not sent to external scanners.", 503);
  }
  const hash = await hashValue(safe);
  const cached = await cachedVerdict(env, hash);
  if (cached?.verdict === "malicious") {
    await recordClick(env, id, "malicious", "cached", cached.reason, hash);
    return notice("Destination blocked", "DESTINATION BLOCKED", "This destination was flagged as potentially harmful.", 403);
  }
  if (cached?.verdict === "clean") {
    try {
      await assertPublicDns(new URL(target).hostname);
      await recordClick(env, id, "clean", "cached", cached.reason, hash);
      return new Response(null, { status: 302, headers: { location: target, ...SAFE_HEADERS } });
    } catch (error) {
      await recordClick(env, id, "unknown", "dns-policy", error.message, hash);
      return notice("Inspection required", "We couldn’t verify this destination.", "DNS validation failed, so the link remains on hold.", 503);
    }
  }
  if (!env.WEBRISK_API_KEY || !env.URLSCAN_API_KEY || !env.SCAN_QUEUE) {
    await recordClick(env, id, "unknown", "configuration", "Scanner keys or the background scan queue are not configured.", hash);
    return notice("Inspection required", "Link inspection required", "Scanning is not configured yet, so this link will not open.", 503);
  }
  // Record the recipient's click before publishing work, so a very fast Queue
  // consumer cannot finish the scan before there is an event to attribute.
  await recordClick(env, id, "pending", "scan-queue", "Inspection is queued or running.", hash);
  const justCompleted = await cachedVerdict(env, hash);
  if (justCompleted?.verdict === "malicious") {
    await updatePendingClickEvents(env, hash, "malicious", "cached", justCompleted.reason);
    return notice("Destination blocked", "DESTINATION BLOCKED", "This destination was flagged as potentially harmful.", 403);
  }
  if (justCompleted?.verdict === "clean") {
    try {
      await assertPublicDns(new URL(target).hostname);
      await updatePendingClickEvents(env, hash, "clean", "cached", justCompleted.reason);
      return new Response(null, { status: 302, headers: { location: target, ...SAFE_HEADERS } });
    } catch (error) {
      await updatePendingClickEvents(env, hash, "unknown", "dns-policy", error.message);
      return notice("Inspection required", "We couldn’t verify this destination.", "DNS validation failed, so the link remains on hold.", 503);
    }
  }
  const existing = await env.DB.prepare("SELECT url_hash FROM scan_jobs WHERE url_hash = ?").bind(hash).first();
  if (!existing) {
    try {
      const inserted = await env.DB.prepare(`INSERT OR IGNORE INTO scan_jobs
(url_hash, encrypted_url, joe_required, created_at, updated_at, next_run_at)
VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(hash, await encryptLinkTarget(safe, env.LINK_SIGNING_SECRET),
          env.JOESANDBOX_API_KEY ? 1 : 0, Date.now(), Date.now(), Date.now()).run();
      if (Number(inserted.meta?.changes || 0) > 0) {
        await env.SCAN_QUEUE.send({ type: "scan", urlHash: hash });
      }
    } catch (error) {
      await env.DB.prepare("DELETE FROM scan_jobs WHERE url_hash = ?").bind(hash).run();
      await updatePendingClickEvents(env, hash, "unknown", "queue", "Could not queue destination inspection.");
      return notice("Inspection unavailable", "We couldn’t start the safety check.", "Please try again later.", 503);
    }
  }
  return notice("Inspection in progress", "CHECKING DESTINATION", "Checks run in the background. This link will not open until every enabled scanner reports clean.", 202, "/go/" + token);
}

async function cacheScanResult(env, urlHash, verdict, reason, scanId = null, joeChecked = false, provider = "scan-worker") {
  await env.DB.prepare(`INSERT OR REPLACE INTO scan_cache (url_hash, scan_id, verdict, reason, checked_at, joe_checked)
VALUES (?, ?, ?, ?, ?, ?)`).bind(urlHash, scanId, verdict, String(reason || "").slice(0, 500), Date.now(), joeChecked ? 1 : 0).run();
  await updatePendingClickEvents(env, urlHash, verdict, provider, reason);
  await env.DB.prepare("DELETE FROM scan_jobs WHERE url_hash = ?").bind(urlHash).run();
}

async function retryScan(env, job, reason, delaySeconds = 10) {
  const attempts = Number(job.attempts || 0) + 1;
  const age = Date.now() - Number(job.created_at || Date.now());
  if (attempts >= 12 || age > Number(env.SCAN_JOB_MAX_WAIT_MS || 900_000)) {
    await cacheScanResult(env, job.url_hash, "unknown", `Inspection ended without a conclusive verdict: ${String(reason || "timeout").slice(0, 350)}`);
    return;
  }
  const delay = Math.min(300, Math.max(5, delaySeconds));
  await env.DB.prepare("UPDATE scan_jobs SET attempts = ?, updated_at = ?, next_run_at = ?, last_error = ? WHERE url_hash = ?")
    .bind(attempts, Date.now(), Date.now() + delay * 1000, String(reason || "").slice(0, 500), job.url_hash).run();
  await env.SCAN_QUEUE.send({ type: "scan", urlHash: job.url_hash }, { delaySeconds: delay });
}

async function processScan(env, urlHash) {
  let job = await env.DB.prepare("SELECT * FROM scan_jobs WHERE url_hash = ?").bind(urlHash).first();
  if (!job) return;
  if (Date.now() - Number(job.created_at) > Number(env.SCAN_JOB_MAX_WAIT_MS || 900_000)) {
    return cacheScanResult(env, urlHash, "unknown", "Inspection timed out before a conclusive verdict was available.", job.urlscan_id);
  }
  let url;
  try {
    url = scannerSafeUrl(await decryptLinkTarget(job.encrypted_url, env.LINK_SIGNING_SECRET));
    await assertPublicDns(new URL(url).hostname);
  } catch (error) {
    return cacheScanResult(env, urlHash, "unknown", `Destination validation failed: ${error.message}`, null, false, "dns-policy");
  }
  if (!Number(job.web_risk_done)) {
    let reputation;
    try {
      reputation = await checkWebRisk(url, env.WEBRISK_API_KEY, fetch, env.WEBRISK_API_URL || DEFAULT_WEBRISK_API_URL);
    } catch (error) {
      return retryScan(env, job, `Web Risk lookup failed: ${error.message}`, Math.min(60, 5 * (Number(job.attempts || 0) + 1)));
    }
    if (reputation.verdict === "malicious") return cacheScanResult(env, urlHash, "malicious", reputation.reason, null, false, "web-risk");
    if (reputation.verdict !== "not-listed") return retryScan(env, job, reputation.reason || "Web Risk did not establish a clean result.");
    await env.DB.prepare("UPDATE scan_jobs SET web_risk_done = 1, updated_at = ? WHERE url_hash = ?")
      .bind(Date.now(), urlHash).run();
    job.web_risk_done = 1;
  }
  if (!Number(job.urlscan_done)) {
    try {
      const browser = await runUrlscan(url, env.URLSCAN_API_KEY, {
        scanId: job.urlscan_id || null, waitMs: 0,
        pollMs: Number(env.URLSCAN_POLL_MS || 1000),
        apiUrl: env.URLSCAN_API_URL || DEFAULT_URLSCAN_API_URL,
      });
      if (browser.verdict === "malicious") return cacheScanResult(env, urlHash, "malicious", browser.reason, browser.scanId, false, "urlscan");
      if (browser.verdict === "clean") {
        await env.DB.prepare("UPDATE scan_jobs SET urlscan_done = 1, urlscan_id = ?, updated_at = ? WHERE url_hash = ?")
          .bind(browser.scanId || job.urlscan_id, Date.now(), urlHash).run();
        job.urlscan_done = 1;
        job.urlscan_id = browser.scanId || job.urlscan_id;
      } else {
        await env.DB.prepare("UPDATE scan_jobs SET urlscan_id = ?, updated_at = ? WHERE url_hash = ?")
          .bind(browser.scanId || job.urlscan_id, Date.now(), urlHash).run();
        job.urlscan_id = browser.scanId || job.urlscan_id;
        return retryScan(env, job, browser.reason || "urlscan inspection is still running.", 10);
      }
    } catch (error) {
      return retryScan(env, job, `urlscan inspection failed: ${error.message}`);
    }
  }
  if (Number(job.joe_required) === 1 && !Number(job.joe_done)) {
    if (!env.JOESANDBOX_API_KEY || env.JOESANDBOX_ACCEPT_TAC !== "1") {
      return cacheScanResult(env, urlHash, "unknown", "Joe Sandbox is enabled but its API key or terms acceptance is missing.", job.urlscan_id, false, "configuration");
    }
    try {
      if (!job.joe_submission_id) {
        const submission = await submitJoeSandboxUrl(url, {
          apiKey: env.JOESANDBOX_API_KEY,
          apiUrl: env.JOESANDBOX_API_URL || DEFAULT_JOE_API_URL,
          acceptTerms: true,
          timeoutMs: Number(env.JOESANDBOX_TIMEOUT_MS || 5000),
        });
        await env.DB.prepare("UPDATE scan_jobs SET joe_submission_id = ?, updated_at = ? WHERE url_hash = ?")
          .bind(submission.submissionId, Date.now(), urlHash).run();
        job.joe_submission_id = submission.submissionId;
        return retryScan(env, job, "Joe Sandbox analysis is running.", Number(env.JOESANDBOX_POLL_MS || 5000) / 1000);
      }
      const knownWebids = JSON.parse(job.joe_webids || "[]");
      const result = await pollJoeSandboxSubmission(job.joe_submission_id, {
        apiKey: env.JOESANDBOX_API_KEY, apiUrl: env.JOESANDBOX_API_URL || DEFAULT_JOE_API_URL,
        timeoutMs: Number(env.JOESANDBOX_TIMEOUT_MS || 5000), knownWebids,
      });
      if (result.verdict === "malicious") return cacheScanResult(env, urlHash, "malicious", result.reason, job.urlscan_id, true, "joe-sandbox");
      if (result.verdict !== "clean") {
        await env.DB.prepare("UPDATE scan_jobs SET joe_webids = ?, updated_at = ? WHERE url_hash = ?")
          .bind(JSON.stringify(result.webids || knownWebids), Date.now(), urlHash).run();
        job.joe_webids = JSON.stringify(result.webids || knownWebids);
        return retryScan(env, job, result.reason || "Joe Sandbox analysis is pending.", Number(env.JOESANDBOX_POLL_MS || 5000) / 1000);
      }
      await env.DB.prepare("UPDATE scan_jobs SET joe_done = 1, joe_webids = ?, updated_at = ? WHERE url_hash = ?")
        .bind(JSON.stringify(result.webids || knownWebids), Date.now(), urlHash).run();
      job.joe_done = 1;
    } catch (error) {
      return retryScan(env, job, `Joe Sandbox inspection failed: ${error.message}`);
    }
  }
  if (Number(job.urlscan_done) === 1 && (Number(job.joe_required) !== 1 || Number(job.joe_done) === 1)) {
    const reason = Number(job.joe_required) === 1
      ? "Google Web Risk, urlscan, and Joe Sandbox returned clean verdicts."
      : "Google Web Risk and urlscan returned clean verdicts.";
    return cacheScanResult(env, urlHash, "clean", reason, job.urlscan_id, Number(job.joe_required) === 1);
  }
  return retryScan(env, job, "One or more inspections are still running.");
}

async function sendConfirmation(email, token, env, origin) {
  const url = new URL("/confirm", origin);
  url.searchParams.set("token", token);
  const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:36px auto;color:#2c2c2b;line-height:1.6"><p style="letter-spacing:.12em;color:#7d7a75">FIELDNOTES</p><h1>Confirm your subscription</h1><p>One quick step to receive new notes from the journal.</p><p><a href="${escapeHtml(url.toString())}" style="display:inline-block;background:#2c2c2b;color:#fff;padding:12px 18px;text-decoration:none">Confirm subscription</a></p><p style="font-size:13px;color:#7d7a75">If you didn’t request this, you can ignore this email.</p></div>`;
  return sendEmail({ apiKey: env.RESEND_API_KEY, apiUrl: env.RESEND_API_URL || "https://api.resend.com/emails", from: env.EMAIL_FROM, to: email, subject: "Confirm your Fieldnotes subscription", html });
}

async function emailPost(post, subscriber, env, origin) {
  const token = newToken();
  await env.DB.prepare("INSERT INTO unsubscribe_tokens (token_hash, email, created_at) VALUES (?, ?, ?)")
    .bind(await hashValue(token), subscriber.email, new Date().toISOString()).run();
  const html = (await renderArticle(post, env, {
    email: true, origin, recipientEmail: subscriber.email,
  })).replace("{{UNSUBSCRIBE_TOKEN}}", encodeURIComponent(token));
  return sendEmail({
    apiKey: env.RESEND_API_KEY, apiUrl: env.RESEND_API_URL || "https://api.resend.com/emails",
    from: env.EMAIL_FROM, to: subscriber.email, subject: post.title, html,
  });
}

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = getPublicOrigin(request, env);
  if (path === "/styles.css" || path === "/app.js" || path === "/favicon.ico") {
    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Static assets unavailable", { status: 404 });
  }
  if (request.method === "GET" && path === "/") return htmlResponse(await homePage(env));
  if (request.method === "GET" && path.startsWith("/p/")) {
    const slug = decodeURIComponent(path.slice(3));
    const post = await env.DB.prepare("SELECT * FROM posts WHERE slug = ?").bind(slug).first();
    return post
      ? htmlResponse(page(post.title, await renderArticle(post, env), post.summary))
      : htmlResponse(page("Not found", `<section class="notice-card"><p class="eyebrow">404</p><h1>That note isn’t here.</h1><p>It may have moved, or the address may be mistyped.</p><a class="button button-dark" href="/">Back to journal</a></section>`), 404);
  }
  if (request.method === "GET" && path === "/admin") {
    const auth = requireAdmin(request, env);
    return auth || htmlResponse(await adminPage(env));
  }
  if (request.method === "POST" && path.startsWith("/admin/")) {
    const auth = requireAdmin(request, env);
    if (auth) return auth;
    if (!sameOriginPost(request, env)) return notice("Request rejected", "Request rejected", "This form must be submitted from this site.", 403);
  }
  if (request.method === "POST" && path === "/admin/posts") {
    const fields = await readForm(request);
    const title = (fields.title || "").trim().slice(0, 120);
    const summary = (fields.summary || "").trim().slice(0, 220);
    const markdown = (fields.markdown || "").trim().slice(0, 20_000);
    if (!title || !summary || !markdown) return notice("Missing details", "Complete all fields.", "Title, summary, and article are required.", 400);
    const base = slugify(title);
    const exists = await env.DB.prepare("SELECT slug FROM posts WHERE slug = ?").bind(base).first();
    const slug = exists ? `${base}-${crypto.randomUUID().slice(0, 6)}` : base;
    await env.DB.prepare("INSERT INTO posts (id, slug, title, summary, markdown, published_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(newId(), slug, title, summary, markdown, new Date().toISOString()).run();
    return Response.redirect(new URL("/admin", origin), 303);
  }
  if (request.method === "POST" && path === "/admin/links") {
    const fields = await readForm(request);
    const post = await env.DB.prepare("SELECT id FROM posts WHERE id = ?").bind(fields.post_id || "").first();
    if (!post) return notice("Choose a note", "Select a published note.", "Return to the editor and select a note.", 400);
    try {
      const target = normalizePublicUrl(fields.target_url || "");
      const id = newId();
      await env.DB.prepare("INSERT INTO protected_links (id, post_id, target_url, created_at) VALUES (?, ?, ?, ?)")
        .bind(id, post.id, await encryptLinkTarget(target, env.LINK_SIGNING_SECRET), new Date().toISOString()).run();
      const protectedUrl = origin + await makeProtectedPath(id, env.LINK_SIGNING_SECRET);
      return htmlResponse(page("Protected link created", `<section class="notice-card"><p class="eyebrow">PROTECTED-LINK TEST</p><h1>Your first-party link is ready.</h1><p>Clicking queues configured safety checks. New destinations stay on hold until every enabled scanner reports clean.</p><p class="protected-link-output"><a href="${escapeHtml(protectedUrl)}">${escapeHtml(protectedUrl)}</a></p><a class="button button-dark" href="/admin">Back to editor</a></section>`), 201);
    } catch (error) {
      return notice("Destination not allowed", "That destination can’t be used.", error.message, 400);
    }
  }
  const sendMatch = path.match(/^\/admin\/posts\/([0-9a-f-]+)\/send$/);
  if (request.method === "POST" && sendMatch) {
    if (!await rateAllowed(env, `send:${clientKey(request)}`, 2, 60, env.SEND_RATE_LIMITER)) return notice("Slow down", "Please wait a minute.", "Newsletter sends are temporarily rate-limited.", 429);
    const post = await env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(sendMatch[1]).first();
    if (!post) return notice("Not found", "Post not found.", "Return to the editor.", 404);
    const prior = await env.DB.prepare("SELECT status FROM newsletter_sends WHERE post_id = ?").bind(post.id).first();
    if (prior && ["sent", "sending", "partial"].includes(prior.status)) return notice("Already sent", "This note has already been sent or is in progress.", "We prevent accidental duplicate newsletters.", 409);
    const subscribers = await env.DB.prepare("SELECT email FROM subscribers WHERE status = 'active' ORDER BY email").all();
    if (!subscribers.results?.length) return notice("No readers yet", "No confirmed subscribers yet.", "Send will be available when readers confirm their subscription.", 409);
    await env.DB.prepare(`INSERT OR REPLACE INTO newsletter_sends (post_id, status, recipient_count, updated_at, error)
VALUES (?, 'sending', 0, ?, NULL)`).bind(post.id, new Date().toISOString()).run();
    let sent = 0;
    let error = "";
    try {
      for (const subscriber of subscribers.results) {
        await emailPost(post, subscriber, env, origin);
        sent += 1;
      }
      await env.DB.prepare("UPDATE newsletter_sends SET status = 'sent', recipient_count = ?, updated_at = ?, error = NULL WHERE post_id = ?")
        .bind(sent, new Date().toISOString(), post.id).run();
    } catch (cause) {
      error = String(cause?.message || cause).slice(0, 500);
      await env.DB.prepare("UPDATE newsletter_sends SET status = 'partial', recipient_count = ?, updated_at = ?, error = ? WHERE post_id = ?")
        .bind(sent, new Date().toISOString(), error, post.id).run();
    }
    return htmlResponse(page(error ? "Partial send" : "Newsletter sent", `<section class="notice-card"><p class="eyebrow">${error ? "CHECK DELIVERY" : "SENT"}</p><h1>${error ? "Some mail may not have gone out." : "Your note is on its way."}</h1><p>${escapeHtml(error ? `Sent to ${sent} reader(s) before an email provider error. Check the provider dashboard before taking action.` : `The note was emailed to ${sent} confirmed reader(s).`)}</p><a class="button button-dark" href="/admin">Return to editor</a></section>`), error ? 502 : 200);
  }
  if (request.method === "POST" && path === "/subscribe") {
    if (!await rateAllowed(env, `subscribe:${clientKey(request)}`, 5, 60, env.SUBSCRIBE_RATE_LIMITER)) return notice("Try later", "Please try again later.", "We received too many subscription requests from this connection.", 429);
    if (!sameOriginPost(request, env)) return notice("Request rejected", "Request rejected", "This form must be submitted from this site.", 403);
    const fields = await readForm(request);
    const email = (fields.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254 || fields.consent !== "yes") {
      return notice("Check the form", "Enter a valid email and confirm consent.", "Return to the journal and try again.", 400);
    }
    const existing = await env.DB.prepare("SELECT status FROM subscribers WHERE email = ?").bind(email).first();
    if (existing?.status === "active") return notice("Already subscribed", "You’re already on the list.", "We’ll send the next note when it’s ready.");
    const token = newToken();
    await env.DB.prepare(`INSERT INTO subscribers (email, status, confirm_hash, consent_at, confirmed_at)
VALUES (?, 'pending', ?, ?, NULL)
ON CONFLICT(email) DO UPDATE SET status = 'pending', confirm_hash = excluded.confirm_hash, consent_at = excluded.consent_at`)
      .bind(email, await hashValue(token), new Date().toISOString()).run();
    try {
      await sendConfirmation(email, token, env, origin);
    } catch (error) {
      console.error("[email-confirmation]", error?.message || error);
      return notice("Email not sent", "We couldn’t send the confirmation.", "Your address is still pending; please try again later.", 503);
    }
    return notice("Check your inbox", "Check your inbox.", `We sent a confirmation link to ${email}. You’ll be subscribed after you confirm.`);
  }
  if (request.method === "GET" && path === "/confirm") {
    const token = url.searchParams.get("token") || "";
    return htmlResponse(page("Confirm subscription", `<section class="notice-card"><p class="eyebrow">NEWSLETTER</p><h1>Confirm your subscription.</h1><p>Press confirm to add your address to the journal list.</p><form method="post" action="/confirm"><input type="hidden" name="token" value="${escapeHtml(token)}"><button class="button button-dark" type="submit">Confirm subscription</button></form></section>`));
  }
  if (request.method === "POST" && path === "/confirm") {
    if (!sameOriginPost(request, env)) return notice("Request rejected", "Request rejected", "This form must be submitted from this site.", 403);
    const { token = "" } = await readForm(request);
    const subscriber = await env.DB.prepare("SELECT email FROM subscribers WHERE confirm_hash = ? AND status = 'pending'").bind(await hashValue(token)).first();
    if (!subscriber || token.length < 20) return notice("Invalid confirmation", "This confirmation link is invalid or already used.", "Return to the journal.", 400);
    await env.DB.prepare("UPDATE subscribers SET status = 'active', confirmed_at = ?, confirm_hash = NULL WHERE email = ?")
      .bind(new Date().toISOString(), subscriber.email).run();
    return notice("Confirmed", "Subscription confirmed.", "Thanks for joining. The next note will arrive by email.");
  }
  if (request.method === "GET" && path === "/unsubscribe") {
    const token = url.searchParams.get("token") || "";
    return htmlResponse(page("Unsubscribe", `<section class="notice-card"><p class="eyebrow">NEWSLETTER</p><h1>Leave the list?</h1><p>Confirm below and we’ll stop sending journal updates.</p><form method="post" action="/unsubscribe"><input type="hidden" name="token" value="${escapeHtml(token)}"><button class="button button-dark" type="submit">Unsubscribe</button></form></section>`));
  }
  if (request.method === "POST" && path === "/unsubscribe") {
    if (!sameOriginPost(request, env)) return notice("Request rejected", "Request rejected", "This form must be submitted from this site.", 403);
    const { token = "" } = await readForm(request);
    const record = await env.DB.prepare("SELECT email FROM unsubscribe_tokens WHERE token_hash = ?").bind(await hashValue(token)).first();
    if (!record || token.length < 20) return notice("Invalid link", "This unsubscribe link is invalid.", "Return to the journal.", 400);
    await env.DB.prepare("UPDATE subscribers SET status = 'unsubscribed' WHERE email = ?").bind(record.email).run();
    return notice("Unsubscribed", "You’re off the list.", "You won’t receive future journal emails at this address.");
  }
  if (request.method === "GET" && path.startsWith("/go/")) return clickRoute(request, env, path.slice("/go/".length));
  if (request.method === "GET" && env.ASSETS) return env.ASSETS.fetch(request);
  return htmlResponse(page("Not found", `<section class="notice-card"><p class="eyebrow">404</p><h1>That page isn’t here.</h1><a class="button button-dark" href="/">Back to journal</a></section>`), 404);
}

export async function handleRequest(request, env, ctx) {
  if (!env.DB) return new Response("D1 binding DB is required.", { status: 503 });
  if (!env.LINK_SIGNING_SECRET || new TextEncoder().encode(env.LINK_SIGNING_SECRET).length < 32) {
    return new Response("Worker secret LINK_SIGNING_SECRET must be at least 32 bytes.", { status: 503 });
  }
  try {
    return await route(request, env, ctx);
  } catch (error) {
    console.error("[worker]", error?.message || error);
    return htmlResponse(page("Temporary error", `<section class="notice-card"><h1>Something went wrong.</h1><p>Please try again shortly.</p></section>`), 500);
  }
}

export async function handleQueue(batch, env) {
  for (const message of batch.messages) {
    const payload = message.body || {};
    if (payload.type !== "scan" || typeof payload.urlHash !== "string") {
      message.ack();
      continue;
    }
    try {
      await processScan(env, payload.urlHash);
    } catch (error) {
      const job = await env.DB.prepare("SELECT * FROM scan_jobs WHERE url_hash = ?").bind(payload.urlHash).first();
      if (job) await retryScan(env, job, `Worker scan failed: ${error?.message || error}`);
      console.error("[scan-queue]", error?.message || error);
    }
    message.ack();
  }
}

export default {
  fetch: handleRequest,
  queue: handleQueue,
};