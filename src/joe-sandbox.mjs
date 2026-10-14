export const DEFAULT_JOESANDBOX_API_URL = "https://jbxcloud.joesecurity.org/api";
const DEFAULT_TIMEOUT_MS = 5000;

function apiEndpoint(apiUrl, path) {
  let base;
  try {
    base = new URL(apiUrl || DEFAULT_JOESANDBOX_API_URL);
  } catch {
    throw new Error("Joe Sandbox API URL is invalid.");
  }
  const localHttp = base.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname);
  if (base.protocol !== "https:" && !localHttp) {
    throw new Error("Joe Sandbox API must use HTTPS.");
  }
  if (base.username || base.password || base.search || base.hash) {
    throw new Error("Joe Sandbox API URL must not include credentials, a query, or a fragment.");
  }
  return `${base.origin}${base.pathname.replace(/\/+$/, "")}${path}`;
}

async function joePost(path, params, {
  apiKey, apiUrl = DEFAULT_JOESANDBOX_API_URL, fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!apiKey) throw new Error("JOESANDBOX_API_KEY is not configured.");
  const response = await fetchImpl(apiEndpoint(apiUrl, path), {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "user-agent": "ClickTime-Protection/1.0",
    },
    body: new URLSearchParams({ apikey: apiKey, ...params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.errors?.length) {
    const message = payload.errors?.[0]?.message || `HTTP ${response.status}`;
    throw new Error(`Joe Sandbox API request failed: ${String(message).slice(0, 240)}`);
  }
  if (!Object.hasOwn(payload, "data")) {
    throw new Error("Joe Sandbox API returned an unexpected response.");
  }
  return payload.data;
}

export async function submitJoeSandboxUrl(url, {
  apiKey, apiUrl, acceptTerms = false, fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!acceptTerms) {
    throw new Error("Joe Sandbox terms acceptance is not enabled.");
  }
  const data = await joePost("/v2/submission/new", {
    "accept-tac": "1",
    url,
    "fast-mode": "1",
    "report-cache": "1",
    "url-reputation": "0",
  }, { apiKey, apiUrl, fetchImpl, timeoutMs });
  const submissionId = data?.submission_id;
  if (typeof submissionId !== "string" && typeof submissionId !== "number") {
    throw new Error("Joe Sandbox did not return a submission ID.");
  }
  return { submissionId: String(submissionId) };
}

function collectWebids(value, found = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) collectWebids(item, found);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (["webid", "_jb_webid"].includes(key.toLowerCase()) &&
          (typeof child === "string" || typeof child === "number")) {
        found.add(String(child));
      } else if (child && typeof child === "object") {
        collectWebids(child, found);
      }
    }
  }
  return [...found];
}

function classifyAnalysis(info) {
  const status = String(info?.status || "").trim().toLowerCase();
  if (!["finished", "complete", "completed"].includes(status)) {
    return { verdict: "pending", reason: "Joe Sandbox analysis is still running." };
  }
  const detection = String(info?.detection || info?.verdict || "").trim().toLowerCase();
  if (["malicious", "suspicious", "threat"].includes(detection)) {
    return { verdict: "malicious", reason: `Joe Sandbox detection: ${detection}.` };
  }
  if (["clean", "benign", "no threat", "no-threat"].includes(detection)) {
    return { verdict: "clean", reason: "Joe Sandbox completed with a clean detection." };
  }
  return { verdict: "unknown", reason: "Joe Sandbox finished without a recognized clean or malicious detection." };
}

export async function pollJoeSandboxSubmission(submissionId, {
  apiKey, apiUrl, fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS, knownWebids = [],
} = {}) {
  let webids = [...new Set(knownWebids.map(String))];
  if (!webids.length) {
    const submission = await joePost("/v2/submission/info", {
      submission_id: String(submissionId),
      "include-reverser-analyses": "0",
    }, { apiKey, apiUrl, fetchImpl, timeoutMs });
    webids = collectWebids(submission);
  }
  if (!webids.length) {
    return { verdict: "pending", webids: [], reason: "Joe Sandbox has not assigned an analysis ID yet." };
  }

  const analyses = await Promise.all(webids.map((webid) =>
    joePost("/v2/analysis/info", { webid }, { apiKey, apiUrl, fetchImpl, timeoutMs })
      .then((info) => ({ webid, ...classifyAnalysis(info) }))
      .catch((error) => ({ webid, verdict: "unknown", reason: error.message }))
  ));
  const malicious = analyses.find((analysis) => analysis.verdict === "malicious");
  if (malicious) return { verdict: "malicious", webids, reason: malicious.reason };
  if (analyses.some((analysis) => analysis.verdict === "pending" || analysis.verdict === "unknown")) {
    return { verdict: "pending", webids, reason: "Joe Sandbox analysis is pending or inconclusive." };
  }
  return { verdict: "clean", webids, reason: "All completed Joe Sandbox analyses were clean." };
}