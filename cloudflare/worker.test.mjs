import test from "node:test";
import assert from "node:assert/strict";
import { handleQueue, handleRequest, renderArticle } from "./worker.mjs";
import {
  assertPublicDns, decryptLinkTarget, encryptLinkTarget, isPrivateAddress,
  makeProtectedPath, normalizePublicUrl, verifyProtectedToken,
} from "./security.mjs";

const secret = "worker-test-secret-at-least-32-bytes-long";

function fakeDb(posts = []) {
  return {
    prepare(sql) {
      return {
        bind() { return this; },
        async all() {
          if (sql.includes("FROM posts ORDER BY")) return { results: posts };
          return { results: [] };
        },
        async first() { return null; },
        async run() { return { success: true, meta: { changes: 1 } }; },
      };
    },
  };
}

function memoryD1() {
  const state = { posts: [{ id: "post-id", slug: "test", title: "Test", summary: "Summary", markdown: "Text", published_at: "2026-01-01T00:00:00.000Z" }], links: new Map(), jobs: new Map(), cache: new Map(), clicks: [] };
  return {
    state,
    prepare(sql) {
      let params = [];
      return {
        bind(...values) { params = values; return this; },
        async all() {
          if (sql.includes("FROM posts ORDER BY")) return { results: state.posts };
          return { results: [] };
        },
        async first() {
          if (sql.includes("SELECT id FROM posts")) return { id: state.posts[0].id };
          if (sql.includes("SELECT * FROM protected_links")) return state.links.get(params[0]) || null;
          if (sql.includes("SELECT * FROM scan_cache")) return state.cache.get(params[0]) || null;
          if (sql.includes("SELECT url_hash FROM scan_jobs")) return state.jobs.has(params[0]) ? { url_hash: params[0] } : null;
          return null;
        },
        async run() {
          if (sql.includes("INSERT INTO protected_links")) {
            const [id, post_id, target_url, created_at] = params;
            state.links.set(id, { id, post_id, target_url, created_at });
          } else if (sql.includes("INSERT OR IGNORE INTO scan_jobs")) {
            if (state.jobs.has(params[0])) return { meta: { changes: 0 } };
            const [url_hash, encrypted_url, joe_required, created_at, updated_at, next_run_at] = params;
            state.jobs.set(url_hash, { url_hash, encrypted_url, joe_required, created_at, updated_at, next_run_at, attempts: 0 });
            return { meta: { changes: 1 } };
          } else if (sql.includes("INSERT INTO click_events")) {
            state.clicks.push(params);
          }
          return { meta: { changes: 1 } };
        },
      };
    },
  };
}

test("Worker serves the blog homepage from D1", async () => {
  const env = {
    DB: fakeDb([{ id: "1", slug: "hello", title: "Hello", summary: "A test post", markdown: "Body", published_at: "2026-01-01T00:00:00.000Z" }]),
    LINK_SIGNING_SECRET: secret,
  };
  const response = await handleRequest(new Request("https://journal.example/"), env, {});
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Hello/);
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
});

test("Worker rejects invalid protected-link signatures before database access", async () => {
  const response = await handleRequest(new Request("https://journal.example/go/not-a-token"), {
    DB: fakeDb(),
    LINK_SIGNING_SECRET: secret,
  }, {});
  assert.equal(response.status, 403);
  assert.match(await response.text(), /protected link is invalid/i);
});

test("Admin-created links enter D1 and enqueue a scan in the same Worker", async () => {
  const DB = memoryD1();
  const sent = [];
  const env = {
    DB,
    LINK_SIGNING_SECRET: secret,
    ADMIN_PASSWORD: "long-test-admin-password",
    WEBRISK_API_KEY: "test-webrisk-key",
    URLSCAN_API_KEY: "test-urlscan-key",
    SCAN_QUEUE: {
      async send(message) {
        assert.equal(DB.state.clicks.at(-1)?.[2], "pending", "click evidence must exist before queue work is published");
        sent.push(message);
      },
    },
  };
  const auth = `Basic ${btoa(`editor:${env.ADMIN_PASSWORD}`)}`;
  const createResponse = await handleRequest(new Request("https://journal.example/admin/links", {
    method: "POST",
    headers: { authorization: auth, origin: "https://journal.example", "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ post_id: "post-id", target_url: "https://example.com/path" }),
  }), env, {});
  assert.equal(createResponse.status, 201);
  const html = await createResponse.text();
  const link = html.match(/href="(https:\/\/journal\.example\/go\/[^"]+)"/)?.[1];
  assert.ok(link, "response should contain a signed protected link");

  const firstClick = await handleRequest(new Request(link), env, {});
  assert.equal(firstClick.status, 202);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, "scan");
  const retryClick = await handleRequest(new Request(link), env, {});
  assert.equal(retryClick.status, 202);
  assert.equal(sent.length, 1, "repeat click should not duplicate the initial queue message");
});

test("Newsletter links store their intended recipient for click forensics", async () => {
  const insertedLinks = [];
  const env = {
    LINK_SIGNING_SECRET: secret,
    DB: {
      prepare(sql) {
        let params = [];
        return {
          bind(...values) { params = values; return this; },
          async run() {
            if (sql.includes("INSERT INTO protected_links")) {
              insertedLinks.push({ sql, params });
            }
            return { meta: { changes: 1 } };
          },
        };
      },
    },
  };
  const html = await renderArticle({
    id: "newsletter-post",
    title: "A note",
    summary: "Summary",
    markdown: "[Visit](https://example.com/offer)",
    published_at: "2026-10-14T00:00:00.000Z",
  }, env, {
    email: true,
    origin: "https://journal.example",
    recipientEmail: "reader@example.net",
  });
  assert.match(html, /href="https:\/\/journal\.example\/go\//);
  assert.equal(insertedLinks.length, 1);
  assert.match(insertedLinks[0].sql, /recipient_email/);
  assert.equal(insertedLinks[0].params[4], "reader@example.net");
});

test("Admin dashboard shows malicious clicks with recipient attribution", async () => {
  const env = {
    DB: {
      prepare(sql) {
        return {
          bind() { return this; },
          async first() { return sql.includes("COUNT(*)") ? { n: 1 } : null; },
          async all() {
            if (sql.includes("FROM posts ORDER BY")) return { results: [{
              id: "october-post",
              slug: "october-note",
              title: "October note",
              summary: "A published note",
              markdown: "Body",
              published_at: "2026-10-14T00:00:00.000Z",
            }] };
            if (sql.includes("FROM click_events")) return {
              results: [{
                clicked_at: "2026-10-14T12:00:00.000Z",
                provider: "web-risk",
                reason: "SOCIAL_ENGINEERING",
                recipient_email: "reader@example.net",
                post_title: "October note",
              }],
            };
            return { results: [] };
          },
        };
      },
    },
    LINK_SIGNING_SECRET: secret,
    ADMIN_PASSWORD: "long-test-admin-password",
  };
  const response = await handleRequest(new Request("https://journal.example/admin", {
    headers: { authorization: `Basic ${btoa(`editor:${env.ADMIN_PASSWORD}`)}` },
  }), env, {});
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /reader@example\.net/);
  assert.match(html, /October note/);
  assert.match(html, /cannot identify the person who actually clicked/i);
  assert.match(html, /Add an external link/);
  assert.match(html, /Insert link into article/);
  assert.match(html, /Email subscribers/);
});

test("Queue consumer rechecks DNS and caches a clean verdict only after both scanners agree", async () => {
  const urlHash = "test-url-hash";
  const job = {
    url_hash: urlHash,
    encrypted_url: await encryptLinkTarget("https://example.com/", secret),
    web_risk_done: 0,
    urlscan_id: null,
    urlscan_done: 0,
    joe_required: 0,
    joe_done: 0,
    joe_webids: "[]",
    attempts: 0,
    created_at: Date.now(),
    updated_at: Date.now(),
  };
  const state = {
    job,
    cache: null,
    clickEvents: [{ url_hash: urlHash, verdict: "pending", provider: "scan-queue" }],
  };
  const DB = {
    prepare(sql) {
      let params = [];
      return {
        bind(...values) { params = values; return this; },
        async first() { return sql.includes("FROM scan_jobs") && params[0] === urlHash ? state.job : null; },
        async run() {
          if (sql.includes("UPDATE scan_jobs SET web_risk_done")) state.job.web_risk_done = 1;
          else if (sql.includes("UPDATE scan_jobs SET urlscan_done")) {
            state.job.urlscan_done = 1;
            state.job.urlscan_id = params[0];
          } else if (sql.includes("INSERT OR REPLACE INTO scan_cache")) {
            state.cache = { url_hash: params[0], scan_id: params[1], verdict: params[2], reason: params[3], checked_at: params[4], joe_checked: params[5] };
          } else if (sql.includes("UPDATE click_events")) {
            for (const event of state.clickEvents) {
              if (event.url_hash === params[3] && event.verdict === "pending") {
                [event.verdict, event.provider, event.reason] = params.slice(0, 3);
              }
            }
          } else if (sql.includes("DELETE FROM scan_jobs")) state.job = null;
          return { meta: { changes: 1 } };
        },
      };
    },
  };
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const requestUrl = new URL(String(input));
    calls.push(requestUrl.hostname);
    if (requestUrl.hostname === "cloudflare-dns.com") {
      return requestUrl.searchParams.get("type") === "A"
        ? Response.json({ Status: 0, Answer: [{ type: 1, data: "8.8.8.8" }] })
        : Response.json({ Status: 3, Answer: [] });
    }
    if (requestUrl.hostname === "webrisk.test") return Response.json({});
    if (requestUrl.pathname.endsWith("/scan/")) return Response.json({ uuid: "scan-123" });
    if (requestUrl.pathname.includes("/result/")) return Response.json({ verdicts: { overall: { score: -50 } } });
    throw new Error(`Unexpected provider request ${requestUrl.href} ${init.method || "GET"}`);
  };
  let acknowledged = 0;
  try {
    await handleQueue({ messages: [{ body: { type: "scan", urlHash }, ack() { acknowledged += 1; } }] }, {
      DB,
      LINK_SIGNING_SECRET: secret,
      WEBRISK_API_KEY: "webrisk-test-key",
      WEBRISK_API_URL: "https://webrisk.test/v1/lookup",
      URLSCAN_API_KEY: "urlscan-test-key",
      URLSCAN_API_URL: "https://urlscan.test/api/v1",
      SCAN_JOB_MAX_WAIT_MS: "900000",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(acknowledged, 1);
  assert.equal(state.cache?.verdict, "clean");
  assert.equal(state.job, null);
  assert.equal(state.clickEvents[0].verdict, "clean", "the initial pending click should receive the eventual scan verdict");
  assert.equal(state.clickEvents[0].provider, "scan-worker");
  assert.ok(calls.includes("cloudflare-dns.com"));
  assert.ok(calls.includes("webrisk.test"));
  assert.ok(calls.includes("urlscan.test"));
});

test("Asynchronous malicious verdict updates the original pending recipient click", async () => {
  const urlHash = "flagged-url-hash";
  const state = {
    job: {
      url_hash: urlHash,
      encrypted_url: await encryptLinkTarget("https://bad.example/path", secret),
      web_risk_done: 0,
      urlscan_id: null,
      urlscan_done: 0,
      joe_required: 0,
      attempts: 0,
      created_at: Date.now(),
      updated_at: Date.now(),
    },
    event: { url_hash: urlHash, verdict: "pending", provider: "scan-queue" },
    cache: null,
  };
  const DB = {
    prepare(sql) {
      let params = [];
      return {
        bind(...values) { params = values; return this; },
        async first() { return sql.includes("FROM scan_jobs") ? state.job : null; },
        async run() {
          if (sql.includes("INSERT OR REPLACE INTO scan_cache")) {
            state.cache = { verdict: params[2], reason: params[3] };
          } else if (sql.includes("UPDATE click_events")) {
            if (state.event.url_hash === params[3] && state.event.verdict === "pending") {
              [state.event.verdict, state.event.provider, state.event.reason] = params.slice(0, 3);
            }
          } else if (sql.includes("DELETE FROM scan_jobs")) {
            state.job = null;
          }
          return { meta: { changes: 1 } };
        },
      };
    },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const requestUrl = new URL(String(input));
    if (requestUrl.hostname === "cloudflare-dns.com") {
      return requestUrl.searchParams.get("type") === "A"
        ? Response.json({ Status: 0, Answer: [{ type: 1, data: "8.8.4.4" }] })
        : Response.json({ Status: 3, Answer: [] });
    }
    if (requestUrl.hostname === "webrisk.test") {
      return Response.json({ threat: { threatTypes: ["SOCIAL_ENGINEERING"] } });
    }
    throw new Error(`Unexpected provider request ${requestUrl.href}`);
  };
  try {
    await handleQueue({ messages: [{ body: { type: "scan", urlHash }, ack() {} }] }, {
      DB,
      LINK_SIGNING_SECRET: secret,
      WEBRISK_API_KEY: "webrisk-test-key",
      WEBRISK_API_URL: "https://webrisk.test/v1/lookup",
      URLSCAN_API_KEY: "urlscan-test-key",
      URLSCAN_API_URL: "https://urlscan.test/api/v1",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(state.cache?.verdict, "malicious");
  assert.equal(state.event.verdict, "malicious");
  assert.equal(state.event.provider, "web-risk");
  assert.match(state.event.reason, /SOCIAL_ENGINEERING/);
});

test("Worker fails closed when its required signing secret is missing", async () => {
  const response = await handleRequest(new Request("https://journal.example/"), { DB: fakeDb() }, {});
  assert.equal(response.status, 503);
  assert.match(await response.text(), /LINK_SIGNING_SECRET/);
});

test("Worker crypto signs, expires, encrypts, and authenticates destinations", async () => {
  const id = crypto.randomUUID();
  const path = await makeProtectedPath(id, secret, 1_800_000_000);
  const token = path.slice("/go/".length);
  assert.equal(await verifyProtectedToken(token, secret, 1_800_000_001), id);
  assert.equal(await verifyProtectedToken(token, secret, 1_900_000_000), null);
  const tokenParts = token.split(".");
  tokenParts[2] = `${tokenParts[2][0] === "a" ? "b" : "a"}${tokenParts[2].slice(1)}`;
  assert.equal(await verifyProtectedToken(tokenParts.join("."), secret, 1_800_000_001), null);
  const encrypted = await encryptLinkTarget("https://example.com/a?b=c", secret);
  assert.equal(await decryptLinkTarget(encrypted, secret), "https://example.com/a?b=c");
  const encryptedParts = encrypted.split(".");
  encryptedParts[2] = `${encryptedParts[2][0] === "a" ? "b" : "a"}${encryptedParts[2].slice(1)}`;
  await assert.rejects(decryptLinkTarget(encryptedParts.join("."), secret));
});

test("URL policy rejects private hosts and only accepts HTTP(S)", () => {
  for (const host of ["127.0.0.1", "10.2.3.4", "192.168.1.1", "169.254.1.1", "fd00::1", "[::1]", "localhost"]) {
    assert.equal(isPrivateAddress(host), true, host);
  }
  assert.equal(normalizePublicUrl("https://example.com/path"), "https://example.com/path");
  assert.throws(() => normalizePublicUrl("file:///etc/passwd"));
  assert.throws(() => normalizePublicUrl("http://127.0.0.1/"));
});

test("DNS policy rejects private DNS answers and accepts a public answer", async () => {
  const privateFetch = async () => Response.json({ Status: 0, Answer: [{ type: 1, data: "10.0.0.8" }] });
  await assert.rejects(assertPublicDns("rebind.example", privateFetch), /private or reserved/);
  let count = 0;
  const publicFetch = async () => {
    count += 1;
    return Response.json(count === 1
      ? { Status: 0, Answer: [{ type: 1, data: "8.8.8.8" }] }
      : { Status: 3, Answer: [] });
  };
  assert.equal(await assertPublicDns("example.com", publicFetch), true);
});