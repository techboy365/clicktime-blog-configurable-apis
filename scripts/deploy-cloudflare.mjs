import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const configPath = resolve(root, "wrangler.jsonc");
const secretPath = resolve(root, ".deploy-secrets.json");
const config = JSON.parse(readFileSync(configPath, "utf8"));
const cli = process.platform === "win32" ? "npx.cmd" : "npx";

function run(args, { allowFailure = false, input } = {}) {
  const result = spawnSync(cli, ["wrangler", ...args], {
    cwd: root, encoding: "utf8", input, maxBuffer: 8 * 1024 * 1024,
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  if (result.status !== 0 && !allowFailure) {
    throw new Error(`wrangler ${args.join(" ")} failed${output ? `:\n${output}` : "."}`);
  }
  return { ok: result.status === 0, output };
}

function findNamedId(value, name) {
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findNamedId(item, name);
      if (found) return found;
    }
  } else if (value && typeof value === "object") {
    const ownName = value.name || value.database_name || value.queue_name;
    if (ownName === name) {
      for (const key of ["database_id", "databaseId", "uuid", "id"]) {
        if (typeof value[key] === "string") return value[key];
      }
    }
    for (const item of Object.values(value)) {
      const found = findNamedId(item, name);
      if (found) return found;
    }
  }
  return null;
}

function parseDatabaseId(output, name) {
  const uuidPattern = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ig;
  try {
    const first = output.search(/[\[{]/);
    if (first >= 0) {
      const parsed = JSON.parse(output.slice(first));
      const named = findNamedId(parsed, name);
      if (named) return named;
    }
  } catch { /* Wrangler versions may include human-readable output around JSON. */ }
  const match = output.match(new RegExp(`(?:database_id|uuid|id)\\s*[:=]\\s*["']?(${uuidPattern.source})`, "i"));
  return match?.[1] || null;
}

function loadSecrets() {
  if (existsSync(secretPath)) {
    chmodSync(secretPath, 0o600);
    return JSON.parse(readFileSync(secretPath, "utf8"));
  }
  const secrets = {
    LINK_SIGNING_SECRET: randomBytes(48).toString("base64url"),
    ADMIN_PASSWORD: randomBytes(32).toString("base64url"),
    WEBRISK_API_KEY: "",
    URLSCAN_API_KEY: "",
    RESEND_API_KEY: "",
    JOESANDBOX_API_KEY: "",
    JOESANDBOX_ACCEPT_TAC: "0",
    EMAIL_FROM: "",
  };
  writeFileSync(secretPath, `${JSON.stringify(secrets, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(secretPath, 0o600);
  return secrets;
}

function saveConfig() {
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
}

run(["whoami"]);
const database = config.d1_databases?.find((item) => item.binding === "DB");
if (!database) throw new Error("wrangler.jsonc must define the D1 binding named DB.");

let databaseId = database.database_id;
if (!databaseId || databaseId === "00000000-0000-0000-0000-000000000000") {
  const list = run(["d1", "list", "--json"], { allowFailure: true });
  databaseId = list.ok ? parseDatabaseId(list.output, database.database_name) : null;
  if (!databaseId) {
    const created = run(["d1", "create", database.database_name, "--config", "wrangler.jsonc"], { allowFailure: true });
    databaseId = created.ok ? parseDatabaseId(created.output, database.database_name) : null;
  }
  if (!databaseId) throw new Error(`Could not find/create D1 database "${database.database_name}". Create it in Cloudflare and set its ID in wrangler.jsonc.`);
  database.database_id = databaseId;
  saveConfig();
}

for (const queueName of ["clicktime-blog-scans", "clicktime-blog-scans-dlq"]) {
  const listing = run(["queues", "list", "--config", "wrangler.jsonc"], { allowFailure: true });
  const exists = listing.ok && listing.output.includes(queueName);
  if (!exists) {
    const created = run(["queues", "create", queueName, "--config", "wrangler.jsonc"], { allowFailure: true });
    if (!created.ok && !/already exists|duplicate/i.test(created.output)) {
      throw new Error(`Could not create Queue "${queueName}".\n${created.output}`);
    }
  }
}

const secrets = loadSecrets();
if (!secrets.LINK_SIGNING_SECRET || Buffer.byteLength(secrets.LINK_SIGNING_SECRET) < 32 ||
    !secrets.ADMIN_PASSWORD || secrets.ADMIN_PASSWORD.length < 20) {
  throw new Error(`${secretPath} must contain a 32-byte LINK_SIGNING_SECRET and an ADMIN_PASSWORD of at least 20 characters.`);
}
if (secrets.JOESANDBOX_API_KEY && secrets.JOESANDBOX_ACCEPT_TAC !== "1") {
  throw new Error("Set JOESANDBOX_ACCEPT_TAC to 1 only after the account owner has accepted Joe Sandbox's terms.");
}
if (secrets.EMAIL_FROM) config.vars = { ...config.vars, EMAIL_FROM: secrets.EMAIL_FROM };
else delete config.vars.EMAIL_FROM;

const secretNames = [
  "LINK_SIGNING_SECRET", "ADMIN_PASSWORD",
  "WEBRISK_API_KEY", "URLSCAN_API_KEY", "RESEND_API_KEY", "JOESANDBOX_API_KEY",
];
for (const name of secretNames) {
  const value = String(secrets[name] || "");
  if (value) run(["secret", "put", name, "--config", "wrangler.jsonc"], { input: `${value}\n` });
}
config.vars = { ...config.vars, JOESANDBOX_ACCEPT_TAC: secrets.JOESANDBOX_ACCEPT_TAC || "0" };
saveConfig();

run(["d1", "migrations", "apply", database.database_name, "--remote", "--config", "wrangler.jsonc"]);
run(["deploy", "--config", "wrangler.jsonc"]);

console.log("\nWorker deployed. The Cloudflare URL is shown above.");
console.log(`Admin username: ${config.vars.ADMIN_USER || "editor"}`);
console.log(`Admin password is stored in ${secretPath}; keep that file private and backed up.`);
if (!secrets.WEBRISK_API_KEY || !secrets.URLSCAN_API_KEY) {
  console.warn("WARNING: Web Risk and urlscan keys are missing; protected links will remain held. Add them to the private secrets file and rerun.");
}
if (!secrets.RESEND_API_KEY || !secrets.EMAIL_FROM) {
  console.warn("WARNING: Resend API key or verified EMAIL_FROM is missing; subscription/newsletter email will not work.");
}