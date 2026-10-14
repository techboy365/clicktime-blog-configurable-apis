export async function sendEmail({
  apiKey, apiUrl = "https://api.resend.com/emails",
  from, to, subject, html, fetchImpl = fetch,
}) {
  if (!apiKey || !from) throw new Error("Email delivery is not configured (RESEND_API_KEY and EMAIL_FROM are required).");
  const response = await fetchImpl(apiUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from, to, subject, html }),
    signal: AbortSignal.timeout(15000),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`Email provider returned HTTP ${response.status}: ${result.message || "request failed"}`);
  }
  return result;
}