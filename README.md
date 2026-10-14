# Click-time protected blog — Cloudflare Worker edition

This version serves the **entire app from one Cloudflare Worker**. There is no Node origin, proxy Worker, `ORIGIN_BASE_URL`, or `PROXY_SHARED_SECRET`.

The Worker serves the blog, editor, subscription/confirmation/unsubscribe flows, and protected `/go/` links. **D1** stores posts, subscribers, protected destinations, scan results, and click events. A Cloudflare **Queue** runs link scans outside the click request. The CSS and browser script are deployed as static assets with the Worker.

## What is included

- Public journal and article pages, with a Basic-Auth-protected editor that has a visible link-insertion control. Publish first, then use the per-post **Email subscribers** button in the dashboard.
- Double-opt-in subscriptions, unsubscribe links, and Resend-compatible newsletter delivery.
- Opaque, one-year HMAC-signed `/go/<id>.<expiry>.<signature>` URLs. The original destination is AES-GCM encrypted in D1.
- Click-time checks using Google Web Risk and private urlscan.io scans; Joe Sandbox is optional.
- A D1 cache and a durable queue for scans. Unknown results, provider failures, sensitive-query URLs, and missing scanner configuration are held—not redirected.
- Recipient-specific protected links for newsletter sends, with an admin report for malicious click events. If a scan flags a URL after the initial click, the pending click record is updated so that the original recipient appears in the report. Attribution identifies the intended recipient of a link, not necessarily the actual clicker if the email was forwarded.
- Worker-side DNS checks reject private/reserved IP literals and DNS answers before scanning and again before redirecting a cached-clean destination. This reduces DNS-rebinding risk, but cannot guarantee an external scanning provider resolves the hostname identically.
- Cloudflare rate-limit bindings for clicks, subscriptions, and newsletter sends.

## One-time Cloudflare setup and deploy

Requires a Cloudflare account, Node.js, and `npm install`. The setup script uses the Wrangler CLI to create/find the D1 database and queues, apply migrations, set generated signing/admin secrets, and deploy the single Worker to its `workers.dev` hostname:

```sh
npm install
npm run cf:setup-deploy
```

The script creates `.deploy-secrets.json` with a random signing secret and admin password, and sets restrictive local file permissions. **Keep this file private and backed up**; do not commit or share it. It is ignored by Git.

To enable actual click-through scanning and email delivery, edit the private `.deploy-secrets.json` and fill in:

- `WEBRISK_API_KEY` and `URLSCAN_API_KEY` (required for links to ever redirect).
- `RESEND_API_KEY` and `EMAIL_FROM` (required to send confirmations and newsletters; `EMAIL_FROM` must be a verified sender).
- Optional `JOESANDBOX_API_KEY`; set `JOESANDBOX_ACCEPT_TAC` to `"1"` only after accepting Joe Sandbox's terms.

Run `npm run cf:setup-deploy` again to apply updated secrets and deploy. Provider keys are never included in the Worker source or `wrangler.jsonc`. Endpoint overrides can be added to the `vars` object there if using compatible API endpoints.

`workers.dev` is enabled, so a custom domain is optional. If you attach a custom domain, Cloudflare still serves this same Worker; no separate origin is needed. Set `PUBLIC_ORIGIN` in `wrangler.jsonc` only if you need a canonical origin different from the incoming hostname.

## Local Worker development

Copy `.dev.vars.example` to `.dev.vars`, then run:

```sh
npm run cf:migrate:local
npm run cf:dev
```

The example local credentials are development-only. Configure local provider keys if you want to test external integrations; never reuse the example secrets in production. Wrangler emulates the Worker, D1, static assets, and Queues locally.

## Validation

```sh
npm test
node --test
npx wrangler deploy --dry-run
```

`npm test` runs the Worker-focused request, signing/encryption, URL/DNS policy, queue-consumer, scanner-verdict, and email/Joe Sandbox adapter tests. `node --test` also runs the retained Node/SQLite migration-reference tests. Provider calls in tests are mocked. Tests and a Wrangler dry run are **not** a deployment or staging smoke test; the actual account resources, domain, provider credentials, deliverability, and live click path still need verification in the target account.

## Important migration and launch caveats

- This is an architecture migration, not a settings-only change. The old ZIP's Node/SQLite application and proxy Worker are no longer the deployment target.
- No old SQLite data is automatically imported. Existing posts, subscribers, protected-link records, and in-flight links must be exported/migrated separately before switching traffic. Old protected links will not resolve against the new, empty D1 database. Do not cut over while existing newsletter links are still expected to work.
- Without both Web Risk and urlscan keys, protected links remain held. Without Resend configuration, confirmation and newsletter mail cannot be sent. The setup script can deploy without these third-party credentials, but that is **not production-ready**.
- Newsletter sends still run serially in a request. This is suitable only for a small list; larger lists need an email Queue and idempotent delivery records before launch.
- DNS checks are not a guarantee against rebinding/time-of-check-to-time-of-use attacks because a third-party scanner controls its own DNS resolution. Validate the providers' privacy terms, quotas, and service levels; submitted URLs can disclose path/query data.
- Review consent/privacy language, abuse protection, bounce/complaint handling, retention/deletion policies, backups, operational alerts, and key rotation before a public launch. Keep `LINK_SIGNING_SECRET` stable; changing it invalidates existing signed links and encrypted destinations.
- Click attribution stores subscriber email alongside the protected link and exposes that email in the admin forensic report for malicious clicks. Disclose this tracking, restrict admin access, and set an appropriate retention/deletion policy before enabling it with real recipients.
- The project has not been deployed to or smoke-tested against a Cloudflare account from this workspace. Treat the first deployment as staging; verify signup/confirmation, editor auth, email delivery, queued scans, retries, cached-clean redirect, malicious block, and DNS-failure hold before production traffic.

## Source layout

- `cloudflare/worker.mjs` — the single Worker entry point and Queue consumer.
- `cloudflare/security.mjs` — Worker/Web Crypto, URL policy, DNS checks, and safe Markdown.
- `migrations/0001_initial.sql` — D1 schema and starter post.
- `migrations/0002_recipient_click_attribution.sql` — recipient association and forensic-query indexes.
- `migrations/0003_link_click_scan_correlation.sql` — joins queued scan outcomes back to the original click records.
- `public/` — static assets served by the Worker.
- `scripts/deploy-cloudflare.mjs` — resource setup, secret provisioning, migration, and deployment.

The original Node files under `src/server.mjs` and `src/security.mjs` are retained only as migration reference; they are not invoked by Wrangler or the deployment scripts.