import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { randomUUID } from "node:crypto";
import { encryptLinkTarget, hashValue, makeProtectedPath, scannerSafeUrl } from "../src/security.mjs";

async function getFreePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

test("a queued cache-miss returns an inspection page without waiting on scanners", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clicktime-fast-click-"));
  const databasePath = join(directory, "blog.sqlite");
  const port = await getFreePort();
  const origin = `http://127.0.0.1:${port}`;
  const signingSecret = "integration-test-link-signing-secret-more-than-32-bytes";
  const child = spawn(process.execPath, ["src/server.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      PUBLIC_ORIGIN: origin,
      DATABASE_PATH: databasePath,
      LINK_SIGNING_SECRET: signingSecret,
      PROXY_SHARED_SECRET: "",
      WEBRISK_API_KEY: "",
      URLSCAN_API_KEY: "",
      JOESANDBOX_API_KEY: "",
      NODE_ENV: "development",
    },
    stdio: "ignore",
  });

  t.after(async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2000))]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
    await rm(directory, { recursive: true, force: true });
  });

  let ready = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`test server exited with ${child.exitCode}`);
    try {
      const response = await fetch(origin);
      if (response.ok) { ready = true; break; }
    } catch { /* retry while the child server starts */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(ready, true, "test server should start");

  const db = new DatabaseSync(databasePath);
  const post = db.prepare("SELECT id FROM posts LIMIT 1").get();
  const id = randomUUID();
  const destination = "https://example.com/queued-test";
  const scannerUrl = scannerSafeUrl(destination);
  const now = Date.now();
  db.prepare("INSERT INTO protected_links (id, post_id, target_url, created_at) VALUES (?, ?, ?, ?)")
    .run(id, post.id, encryptLinkTarget(destination, signingSecret), new Date().toISOString());
  db.prepare(`INSERT INTO scan_jobs
    (url_hash, encrypted_url, joe_required, created_at, updated_at, next_run_at)
    VALUES (?, ?, 0, ?, ?, ?)`)
    .run(hashValue(scannerUrl), encryptLinkTarget(scannerUrl, signingSecret), now, now, now + 60_000);
  db.close();

  const started = performance.now();
  const response = await fetch(`${origin}${makeProtectedPath(id, signingSecret)}`);
  const elapsedMs = performance.now() - started;
  assert.equal(response.status, 202);
  assert.ok(elapsedMs < 1000, `inspection response took ${elapsedMs.toFixed(1)} ms`);
  assert.match(await response.text(), /data-auto-retry="true"/);
});