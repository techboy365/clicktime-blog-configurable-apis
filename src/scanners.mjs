const WEB_RISK_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"];
export const DEFAULT_WEBRISK_API_URL = "https://webrisk.googleapis.com/v1/uris:search";
export const DEFAULT_URLSCAN_API_URL = "https://urlscan.io/api/v1";

export function getFreshCachedVerdict(cached, now, {
  cleanTtlMs = 300_000,
  maliciousTtlMs = 86_400_000,
  unknownTtlMs = 15_000,
  requireJoe = false,
} = {}) {
  if (!cached || !Number.isFinite(Number(cached.checked_at))) return null;
  const age = now - Number(cached.checked_at);
  if (age < 0) return null;
  if (cached.verdict === "malicious" && age < maliciousTtlMs) {
    return { verdict: "malicious", provider: "cached", reason: cached.reason, scanId: cached.scan_id };
  }
  if (cached.verdict === "unknown" && age < unknownTtlMs) {
    return { verdict: "unknown", provider: "cached", reason: cached.reason, scanId: cached.scan_id };
  }
  if (cached.verdict === "clean" && age < cleanTtlMs) {
    if (requireJoe && Number(cached.joe_checked) !== 1) return null;
    return { verdict: "clean", provider: "cached", reason: cached.reason, scanId: cached.scan_id };
  }
  return null;
}

export async function checkWebRisk(
  url,
  apiKey,
  fetchImpl = fetch,
  apiUrl = DEFAULT_WEBRISK_API_URL,
) {
  if (!apiKey) return { verdict: "unavailable", provider: "web-risk", reason: "API key is not configured." };
  const endpoint = new URL(apiUrl);
  endpoint.searchParams.set("key", apiKey);
  endpoint.searchParams.set("uri", url);
  for (const type of WEB_RISK_TYPES) endpoint.searchParams.append("threatTypes", type);
  const response = await fetchImpl(endpoint, { signal: AbortSignal.timeout(7000) });
  if (!response.ok) throw new Error(`Google Web Risk returned HTTP ${response.status}.`);
  const data = await response.json();
  return data.threat
    ? { verdict: "malicious", provider: "web-risk", reason: data.threat.threatTypes?.join(", ") || "Threat match." }
    : { verdict: "not-listed", provider: "web-risk", reason: "No known threat-list match; this is not a clean verdict." };
}

export function classifyUrlscanResult(data) {
  const v = data?.verdicts ?? {};
  const knownFlags = [
    v.overall?.malicious, v.malicious, v.urlscan?.malicious,
    v.engines?.malicious, v.community?.malicious,
  ];
  if (knownFlags.some((flag) => flag === true)) {
    return { verdict: "malicious", reason: "urlscan marked the page malicious." };
  }
  const scores = [v.overall?.score, v.score, v.urlscan?.score, v.engines?.score]
    .filter((score) => typeof score === "number" && Number.isFinite(score));
  if (scores.some((score) => score >= 50)) {
    return { verdict: "malicious", reason: "urlscan maliciousness score exceeded the conservative threshold." };
  }
  // A negative score is required; a missing/neutral score is not treated as safe.
  if (scores.length > 0 && scores.every((score) => score <= -50)) {
    return { verdict: "clean", reason: "urlscan returned a strongly negative maliciousness score." };
  }
  return { verdict: "unknown", reason: "urlscan result did not establish a sufficiently clear verdict." };
}

export async function runUrlscan(url, apiKey, {
  scanId = null, fetchImpl = fetch, waitMs = 10000, pollMs = 1000,
  apiUrl = DEFAULT_URLSCAN_API_URL,
} = {}) {
  if (!apiKey) return { verdict: "unavailable", scanId, reason: "API key is not configured." };
  const apiBase = apiUrl.replace(/\/+$/, "");
  let id = scanId;
  if (!id) {
    const submission = await fetchImpl(`${apiBase}/scan/`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "API-Key": apiKey },
      body: JSON.stringify({ url, visibility: "private" }),
      signal: AbortSignal.timeout(10000),
    });
    if (!submission.ok) throw new Error(`urlscan submission returned HTTP ${submission.status}.`);
    const payload = await submission.json();
    if (!payload.uuid) throw new Error("urlscan did not return a scan ID.");
    id = payload.uuid;
  }

  const deadline = Date.now() + Math.max(0, waitMs);
  const resultUrl = `${apiBase}/result/${encodeURIComponent(id)}/`;
  do {
    const response = await fetchImpl(resultUrl, {
      headers: { "API-Key": apiKey },
      signal: AbortSignal.timeout(7000),
    });
    if (response.ok) {
      const result = await response.json();
      return { ...classifyUrlscanResult(result), scanId: id };
    }
    if (response.status !== 404 && response.status !== 429 && response.status < 500) {
      throw new Error(`urlscan result returned HTTP ${response.status}.`);
    }
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, Math.max(100, pollMs)));
  } while (Date.now() <= deadline);

  return { verdict: "pending", scanId: id, reason: "The private browser scan is still running." };
}

export async function inspectUrl(url, {
  webRiskKey, webRiskApiUrl = DEFAULT_WEBRISK_API_URL,
  urlscanKey, urlscanApiUrl = DEFAULT_URLSCAN_API_URL, fetchImpl = fetch, scanId = null,
  waitMs = 10000, pollMs = 1000,
} = {}) {
  let webRisk;
  try {
    webRisk = await checkWebRisk(url, webRiskKey, fetchImpl, webRiskApiUrl);
  } catch (error) {
    return { verdict: "unknown", provider: "web-risk", reason: `Reputation check failed: ${error.message}`, scanId };
  }
  if (webRisk.verdict === "malicious") {
    return { verdict: "malicious", provider: "web-risk", reason: webRisk.reason, scanId: null };
  }
  if (webRisk.verdict !== "not-listed") {
    return { verdict: "unknown", provider: "web-risk", reason: webRisk.reason, scanId };
  }

  try {
    const browser = await runUrlscan(url, urlscanKey, {
      scanId, fetchImpl, waitMs, pollMs, apiUrl: urlscanApiUrl,
    });
    if (browser.verdict === "clean" || browser.verdict === "malicious") {
      return { ...browser, provider: "web-risk+urlscan" };
    }
    return { ...browser, provider: "web-risk+urlscan" };
  } catch (error) {
    return { verdict: "unknown", provider: "urlscan", reason: `Browser inspection failed: ${error.message}`, scanId };
  }
}