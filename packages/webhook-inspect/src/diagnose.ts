import { fromBase64, fromHex } from "./crypto.js";
import { detectProvider } from "./explain.js";
import { bodyString, normalizeHeaders, parseStripeHeader, SIGNATURE_HEADERS, verify, type VerifyInput, type VerifyResult } from "./verify.js";

export type DiagnosisCode =
  | "verified"
  | "missing_secret"
  | "wrong_secret_type"
  | "secret_whitespace"
  | "secret_prefix"
  | "secret_encoding"
  | "missing_header"
  | "malformed_header"
  | "wrong_provider"
  | "legacy_header"
  | "empty_body"
  | "body_reserialized"
  | "body_newline"
  | "body_compact_json"
  | "timestamp_skew"
  | "timestamp_milliseconds"
  | "url_mismatch"
  | "missing_url"
  | "encoding_mismatch"
  | "signature_mismatch";

export interface Diagnosis {
  code: DiagnosisCode;
  /** `confirmed` = we reproduced the fix; `likely` = strong signal; `info` = context. */
  level: "confirmed" | "likely" | "info";
  message: string;
  hint: string;
}

export interface DiagnoseResult {
  ok: boolean;
  result: VerifyResult;
  diagnoses: Diagnosis[];
}

/** Does the signature verify with `patch` applied? The replay window is ignored so stale captures can still confirm a fix. */
async function passes(input: VerifyInput, patch: Partial<VerifyInput>): Promise<boolean> {
  return (await verify({ ...input, toleranceSec: Number.MAX_SAFE_INTEGER, ...patch })).ok;
}

function bodyVariants(body: string): Array<{ label: string; code: DiagnosisCode; body: string }> {
  const out: Array<{ label: string; code: DiagnosisCode; body: string }> = [];
  const add = (label: string, code: DiagnosisCode, b: string): void => {
    if (b !== body && !out.some((o) => o.body === b)) out.push({ label, code, body: b });
  };
  add("trailing newline removed", "body_newline", body.replace(/\r?\n$/, ""));
  add("trailing newline added", "body_newline", `${body}\n`);
  add("CRLF line endings converted to LF", "body_newline", body.replace(/\r\n/g, "\n"));
  add("LF line endings converted to CRLF", "body_newline", body.replace(/\r?\n/g, "\r\n"));
  try {
    const parsed: unknown = JSON.parse(body);
    const forms: Array<[string, string]> = [
      ["compact formatting (JSON.stringify(obj))", JSON.stringify(parsed)],
      ["2-space indentation", JSON.stringify(parsed, null, 2)],
      ["4-space indentation", JSON.stringify(parsed, null, 4)],
    ];
    for (const [label, text] of forms) {
      add(`its original ${label}`, "body_reserialized", text);
      add(`its original ${label} and a trailing newline`, "body_reserialized", `${text}\n`);
    }
  } catch {
    // not JSON
  }
  return out;
}

function urlVariants(url: string): string[] {
  const out = new Set<string>();
  try {
    const u = new URL(url);
    const flip = new URL(url);
    flip.protocol = u.protocol === "https:" ? "http:" : "https:";
    out.add(flip.toString());
    const noPort = new URL(url);
    noPort.port = "";
    out.add(noPort.toString());
    const httpsNoPort = new URL(noPort.toString());
    httpsNoPort.protocol = "https:";
    out.add(httpsNoPort.toString());
    out.add(url.endsWith("/") ? url.slice(0, -1) : `${url}/`);
    const noQuery = new URL(url);
    noQuery.search = "";
    out.add(noQuery.toString());
  } catch {
    // invalid URL; nothing to try
  }
  out.delete(url);
  return [...out];
}

function secretTypeProblem(provider: VerifyInput["provider"], secret: string): string | undefined {
  if (provider === "stripe") {
    if (/^(sk|rk)_(live|test)_/.test(secret)) return "This is a Stripe API key, not a webhook signing secret. Use the endpoint's signing secret (starts with whsec_).";
    if (/^pk_(live|test)_/.test(secret)) return "This is a Stripe publishable key, not a webhook signing secret (whsec_...).";
  }
  if (provider === "slack" && /^xox[abpr]-/.test(secret)) return "This is a Slack OAuth token. Slack signs requests with the app's Signing Secret (Basic Information → App Credentials).";
  if (provider === "twilio") {
    if (/^AC[0-9a-f]{32}$/i.test(secret)) return "This is a Twilio Account SID. Twilio signs with your Auth Token.";
    if (/^SK[0-9a-f]{32}$/i.test(secret)) return "This is a Twilio API Key SID. Twilio request signatures use the account's primary Auth Token.";
  }
  if (provider === "shopify" && /^shp(at|ca|pa)_/.test(secret)) return "This is a Shopify access token. Webhooks are signed with the app's client secret (API secret key).";
  if (provider === "github" && /^(gh[pousr]_|github_pat_)/.test(secret)) return "This is a GitHub token. Webhook signatures use the secret you typed in the webhook settings.";
  return undefined;
}

/**
 * Explain why a signature fails. Tries concrete fixes (trimmed secret, original body formatting,
 * alternate URLs, the right provider) and reports the ones that make verification pass as `confirmed`.
 */
export async function diagnose(input: VerifyInput): Promise<DiagnoseResult> {
  const result = await verify(input);
  const out: Diagnosis[] = [];
  if (result.ok) {
    out.push({ code: "verified", level: "confirmed", message: `Signature verified (${result.provider}).`, hint: "Nothing to fix." });
    return { ok: true, result, diagnoses: out };
  }
  const h = normalizeHeaders(input.headers);
  const body = bodyString(input.body);
  const secret = typeof input.secret === "string" ? input.secret : "";
  const provider = input.provider;

  if (result.code === "missing_secret") {
    out.push({ code: "missing_secret", level: "confirmed", message: "No signing secret was provided.", hint: "Pass the provider's webhook signing secret." });
    return { ok: false, result, diagnoses: out };
  }

  // Header / provider problems.
  if (result.code === "missing_header" || result.code === "malformed_header") {
    const detected = detectProvider(input.headers);
    if (detected && detected.provider !== provider) {
      out.push({
        code: "wrong_provider",
        level: "likely",
        message: `This request carries ${detected.header}, which looks like ${detected.provider}, but it was verified as ${provider}.`,
        hint: `Verify with --provider ${detected.provider}.`,
      });
    } else if (provider === "github" && h["x-hub-signature"]) {
      out.push({ code: "legacy_header", level: "likely", message: "Only the legacy SHA-1 X-Hub-Signature header is present.", hint: "Read X-Hub-Signature-256 (HMAC-SHA256); GitHub sends both when a secret is configured." });
    } else if (result.code === "malformed_header") {
      out.push({
        code: "malformed_header",
        level: "confirmed",
        message: result.reason ?? "The signature header is malformed.",
        hint: "The header is present but not in the provider's format. Check that it was not truncated, re-encoded or copied from a different provider.",
      });
    } else {
      const expected = provider === "generic" ? (input.generic?.header ?? "x-signature") : SIGNATURE_HEADERS[provider];
      const present = Object.keys(h).filter((k) => /sign|hmac|timestamp/.test(k));
      out.push({
        code: "missing_header",
        level: "confirmed",
        message: `${result.reason} Signature-like headers present: ${present.length ? present.join(", ") : "none"}.`,
        hint: `Make sure your proxy/framework forwards the ${expected} header unchanged (header names are case-insensitive).`,
      });
    }
  }

  if (result.code === "missing_url") {
    out.push({ code: "missing_url", level: "confirmed", message: result.reason ?? "Missing URL.", hint: "Pass the exact public URL configured in Twilio, e.g. https://example.com/sms?x=1." });
  }

  if (secret) {
    const typeProblem = secretTypeProblem(provider, secret);
    if (typeProblem) out.push({ code: "wrong_secret_type", level: "likely", message: typeProblem, hint: "Copy the webhook signing secret from the provider's webhook settings." });

    if (secret !== secret.trim() || /^["'].*["']$/.test(secret.trim())) {
      const cleaned = secret.trim().replace(/^["'](.*)["']$/, "$1");
      const fixed = await passes(input, { secret: cleaned });
      out.push({
        code: "secret_whitespace",
        level: fixed ? "confirmed" : "likely",
        message: "The secret has surrounding whitespace, a newline or quotes (common when read from a .env file).",
        hint: fixed ? "Trimming the secret makes the signature verify." : "Trim the secret before using it.",
      });
    }
    if (provider === "stripe" && !secret.startsWith("whsec_") && !typeProblem && (await passes(input, { secret: `whsec_${secret}` }))) {
      out.push({ code: "secret_prefix", level: "confirmed", message: "The whsec_ prefix was stripped from the secret.", hint: "Stripe uses the entire secret, including whsec_, as the HMAC key." });
    }
    const decoded = [fromBase64(secret.replace(/^whsec_/, "")), fromHex(secret)].filter((x): x is Uint8Array => !!x && x.length > 0);
    for (const key of decoded) {
      if (await passes(input, { secret: key })) {
        out.push({ code: "secret_encoding", level: "confirmed", message: "The signature verifies when the secret is decoded (base64/hex) before use.", hint: "Decode the secret to bytes before computing the HMAC for this sender." });
        break;
      }
    }
  }

  if (result.code === "signature_mismatch" || result.code === "body_hash_mismatch" || result.code === "timestamp_outside_tolerance") {
    if (body.length === 0) {
      out.push({ code: "empty_body", level: "likely", message: "The body is empty.", hint: "Your framework probably consumed or parsed the body before verification. Read the raw body (e.g. express.raw(), request.text())." });
    }
    for (const v of bodyVariants(body)) {
      if (await passes(input, { body: v.body })) {
        out.push({
          code: v.code,
          level: "confirmed",
          message:
            v.code === "body_reserialized"
              ? `The signature matches when the JSON is restored to ${v.label.replace(/^its original /, "")}: the body was parsed and re-serialized before verification.`
              : `The signature matches the body with ${v.label}: the body you verified is not the raw bytes the provider sent.`,
          hint: "Verify against the raw request body before any JSON parsing or re-serialization (express.raw({type: 'application/json'}), await request.text(), Next.js route `await req.text()`).",
        });
        break;
      }
    }
    if (provider === "stripe" && body.trim().startsWith("{") && !body.includes("\n") && !out.some((d) => d.code === "body_reserialized")) {
      out.push({
        code: "body_compact_json",
        level: "likely",
        message: "Stripe sends pretty-printed JSON, but this body is a single compact line.",
        hint: "A framework likely parsed and re-serialized the JSON. Capture the raw body instead.",
      });
    }
  }

  // Timestamp problems (Stripe/Slack).
  const ts = result.timestamp ?? (provider === "stripe" && h["stripe-signature"] ? parseStripeHeader(h["stripe-signature"]).t : undefined);
  if (ts !== undefined && ts > 1e12) {
    out.push({ code: "timestamp_milliseconds", level: "likely", message: "The timestamp looks like milliseconds, not seconds.", hint: "Signed timestamps are unix seconds." });
  }
  if (result.code === "timestamp_outside_tolerance") {
    const age = result.ageSec ?? 0;
    out.push({
      code: "timestamp_skew",
      level: "confirmed",
      message: `The signature is valid but the event was signed ${Math.abs(age)}s ${age >= 0 ? "ago" : "in the future"} (outside the replay window).`,
      hint: age > 3600 ? "This looks like a replayed or re-delivered old request. Re-send it from the provider, or re-sign it (webhook-inspect replay --resign)." : "Check the server clock (NTP) and that requests are not queued before verification.",
    });
  }

  if (provider === "twilio" && result.code === "signature_mismatch" && input.url) {
    for (const u of urlVariants(input.url)) {
      if (await passes(input, { url: u })) {
        out.push({ code: "url_mismatch", level: "confirmed", message: `The signature matches URL ${u}, not ${input.url}.`, hint: "A proxy or load balancer changed the scheme, host, port or path. Validate against the public URL Twilio called." });
        break;
      }
    }
  }

  if (provider === "shopify" && result.code === "signature_mismatch" && /^[0-9a-f]{64}$/i.test(h["x-shopify-hmac-sha256"] ?? "")) {
    out.push({ code: "encoding_mismatch", level: "likely", message: "The Shopify header looks hex-encoded; Shopify sends base64.", hint: "Compare base64 digests." });
  }

  if (!out.some((d) => d.level === "confirmed") && (result.code === "signature_mismatch" || result.code === "body_hash_mismatch")) {
    out.push({
      code: "signature_mismatch",
      level: "likely",
      message: result.reason ?? "Signature mismatch.",
      hint: [
        "Most common causes, in order:",
        "1) wrong secret (each endpoint, environment, and `stripe listen` session has its own),",
        "2) body changed before verification (parsed/re-serialized JSON, charset conversion),",
        provider === "twilio" ? "3) URL differs from the one Twilio called (http vs https, port, query)." : "3) verifying a different request than the one that was signed.",
      ].join(" "),
    });
  }

  return { ok: false, result, diagnoses: out };
}
