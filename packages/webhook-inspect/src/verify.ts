import { digest, hmac, timingSafeEqual, toBytes, type Encoding, type HashAlg } from "./crypto.js";

export type Provider = "stripe" | "github" | "shopify" | "slack" | "twilio" | "generic";
export const PROVIDERS: readonly Provider[] = ["stripe", "github", "shopify", "slack", "twilio", "generic"];

/** Plain object (Node `req.headers`), `[name, value]` pairs, or any iterable of pairs such as a Fetch `Headers`. */
export type HeaderBag = Record<string, string | string[] | undefined> | Iterable<[string, string]>;

export interface GenericOptions {
  /** Header carrying the signature. Default `x-signature`. */
  header?: string;
  algorithm?: HashAlg;
  encoding?: Encoding;
  /** Prefix in the header value, e.g. `sha256=`. Auto-stripped when it looks like `<alg>=`. */
  prefix?: string;
}

export interface VerifyInput {
  provider: Provider;
  /** Signing secret exactly as the provider shows it (Stripe `whsec_...`, Slack Signing Secret, Twilio Auth Token, ...). */
  secret: string | Uint8Array;
  headers: HeaderBag;
  /** Raw request body, byte-for-byte as received. Never a re-serialized JSON object. */
  body: string | Uint8Array;
  /** Twilio only: the full public URL Twilio requested, including query string. */
  url?: string;
  /** Stripe/Slack replay window in seconds. Default 300. */
  toleranceSec?: number;
  /** Current time in unix seconds (for tests). */
  now?: number;
  generic?: GenericOptions;
}

export type FailureCode =
  | "missing_secret"
  | "missing_header"
  | "malformed_header"
  | "missing_url"
  | "signature_mismatch"
  | "timestamp_outside_tolerance"
  | "body_hash_mismatch";

export interface VerifyResult {
  ok: boolean;
  provider: Provider;
  code?: FailureCode;
  reason?: string;
  /** Header name that carried the signature. */
  header?: string;
  timestamp?: number;
  ageSec?: number;
}

export const SIGNATURE_HEADERS: Record<Exclude<Provider, "generic">, string> = {
  stripe: "stripe-signature",
  github: "x-hub-signature-256",
  shopify: "x-shopify-hmac-sha256",
  slack: "x-slack-signature",
  twilio: "x-twilio-signature",
};

/** Lower-case header names and collapse multi-value headers to their first value. */
export function normalizeHeaders(headers: HeaderBag): Record<string, string> {
  const out: Record<string, string> = {};
  const iterable = Symbol.iterator in headers && typeof (headers as Iterable<[string, string]>)[Symbol.iterator] === "function";
  const entries: Array<[string, string | string[] | undefined]> = iterable
    ? [...(headers as Iterable<[string, string]>)]
    : Object.entries(headers as Record<string, string | string[] | undefined>);
  for (const [k, v] of entries) {
    const value = Array.isArray(v) ? v[0] : v;
    if (typeof value === "string") out[k.toLowerCase()] = value;
  }
  return out;
}

const DEFAULT_TOLERANCE = 300;
const nowSec = (input: VerifyInput): number => input.now ?? Math.floor(Date.now() / 1000);

/** Replay window; an invalid value (NaN, negative, Infinity) falls back to the default instead of disabling the check. */
function tolerance(input: VerifyInput): number {
  const t = input.toleranceSec;
  return typeof t === "number" && Number.isFinite(t) && t >= 0 ? t : DEFAULT_TOLERANCE;
}

/** `prefix` + raw body bytes, so binary/BOM bodies are signed exactly as received. */
function prefixed(prefix: string, body: string | Uint8Array): Uint8Array {
  const head = toBytes(prefix);
  const tail = toBytes(body);
  const out = new Uint8Array(head.length + tail.length);
  out.set(head, 0);
  out.set(tail, head.length);
  return out;
}

function fail(provider: Provider, code: FailureCode, reason: string, extra: Partial<VerifyResult> = {}): VerifyResult {
  return { ok: false, provider, code, reason, ...extra };
}

export function parseStripeHeader(value: string): { t?: number; v1: string[]; v0: string[] } {
  const out: { t?: number; v1: string[]; v0: string[] } = { v1: [], v0: [] };
  for (const part of value.split(",")) {
    const [k, ...rest] = part.trim().split("=");
    const v = rest.join("=");
    if (k === "t" && /^\d+$/.test(v)) out.t = Number(v);
    else if (k === "v1") out.v1.push(v);
    else if (k === "v0") out.v0.push(v);
  }
  return out;
}

async function verifyStripe(input: VerifyInput, h: Record<string, string>): Promise<VerifyResult> {
  const header = h["stripe-signature"];
  if (!header) return fail("stripe", "missing_header", "No Stripe-Signature header.");
  const parsed = parseStripeHeader(header);
  if (parsed.t === undefined || parsed.v1.length === 0) {
    return fail("stripe", "malformed_header", "Stripe-Signature must look like `t=<unix>,v1=<hex>`.", { header: "stripe-signature" });
  }
  const expected = await hmac("SHA-256", input.secret, prefixed(`${parsed.t}.`, input.body), "hex");
  const ageSec = nowSec(input) - parsed.t;
  const base = { header: "stripe-signature", timestamp: parsed.t, ageSec };
  if (!parsed.v1.some((s) => timingSafeEqual(s, expected))) {
    return fail("stripe", "signature_mismatch", "No v1 signature matches HMAC-SHA256(secret, `${t}.${rawBody}`).", base);
  }
  const tol = tolerance(input);
  if (Math.abs(ageSec) > tol) {
    return fail("stripe", "timestamp_outside_tolerance", `Signature is valid but the timestamp is ${ageSec}s old (tolerance ${tol}s).`, base);
  }
  return { ok: true, provider: "stripe", ...base };
}

async function verifySlack(input: VerifyInput, h: Record<string, string>): Promise<VerifyResult> {
  const sig = h["x-slack-signature"];
  const ts = h["x-slack-request-timestamp"];
  if (!sig) return fail("slack", "missing_header", "No X-Slack-Signature header.");
  if (!ts || !/^\d+$/.test(ts)) return fail("slack", "missing_header", "No valid X-Slack-Request-Timestamp header.", { header: "x-slack-signature" });
  if (!sig.startsWith("v0=")) return fail("slack", "malformed_header", "X-Slack-Signature must start with `v0=`.", { header: "x-slack-signature" });
  const t = Number(ts);
  const expected = `v0=${await hmac("SHA-256", input.secret, prefixed(`v0:${ts}:`, input.body), "hex")}`;
  const ageSec = nowSec(input) - t;
  const base = { header: "x-slack-signature", timestamp: t, ageSec };
  if (!timingSafeEqual(sig, expected)) return fail("slack", "signature_mismatch", "Signature does not match HMAC-SHA256(secret, `v0:${timestamp}:${rawBody}`).", base);
  const tol = tolerance(input);
  if (Math.abs(ageSec) > tol) return fail("slack", "timestamp_outside_tolerance", `Signature is valid but the timestamp is ${ageSec}s old (tolerance ${tol}s).`, base);
  return { ok: true, provider: "slack", ...base };
}

async function verifyGithub(input: VerifyInput, h: Record<string, string>): Promise<VerifyResult> {
  const sig = h["x-hub-signature-256"];
  if (!sig) {
    const legacy = h["x-hub-signature"] ? " Only the legacy SHA-1 X-Hub-Signature header is present." : "";
    return fail("github", "missing_header", `No X-Hub-Signature-256 header.${legacy}`);
  }
  if (!sig.startsWith("sha256=")) return fail("github", "malformed_header", "X-Hub-Signature-256 must start with `sha256=`.", { header: "x-hub-signature-256" });
  const expected = `sha256=${await hmac("SHA-256", input.secret, input.body, "hex")}`;
  return timingSafeEqual(sig, expected)
    ? { ok: true, provider: "github", header: "x-hub-signature-256" }
    : fail("github", "signature_mismatch", "Signature does not match HMAC-SHA256(secret, rawBody).", { header: "x-hub-signature-256" });
}

async function verifyShopify(input: VerifyInput, h: Record<string, string>): Promise<VerifyResult> {
  const sig = h["x-shopify-hmac-sha256"];
  if (!sig) return fail("shopify", "missing_header", "No X-Shopify-Hmac-Sha256 header.");
  const expected = await hmac("SHA-256", input.secret, input.body, "base64");
  return timingSafeEqual(sig.trim(), expected)
    ? { ok: true, provider: "shopify", header: "x-shopify-hmac-sha256" }
    : fail("shopify", "signature_mismatch", "Signature does not match base64(HMAC-SHA256(secret, rawBody)).", { header: "x-shopify-hmac-sha256" });
}

/** Twilio: base64(HMAC-SHA1(authToken, url + sorted form params concatenated as key+value)). */
export function twilioSigningString(url: string, body: string, contentType?: string): string {
  if (/bodySHA256=/.test(url) || (contentType && !/x-www-form-urlencoded/i.test(contentType))) return url;
  const params = [...new URLSearchParams(body).entries()].sort(([ak, av], [bk, bv]) => (ak === bk ? (av < bv ? -1 : av > bv ? 1 : 0) : ak < bk ? -1 : 1));
  return url + params.map(([k, v]) => k + v).join("");
}

async function verifyTwilio(input: VerifyInput, h: Record<string, string>): Promise<VerifyResult> {
  const sig = h["x-twilio-signature"];
  if (!sig) return fail("twilio", "missing_header", "No X-Twilio-Signature header.");
  if (!input.url) return fail("twilio", "missing_url", "Twilio signatures cover the full request URL; pass the exact public URL Twilio called.", { header: "x-twilio-signature" });
  const body = bodyString(input.body);
  const isForm = !h["content-type"] || /x-www-form-urlencoded/i.test(h["content-type"]);
  const bodyHash = /[?&]bodySHA256=([^&#]*)/.exec(input.url)?.[1];
  // A non-form body is only covered by the signature through bodySHA256; without it the body is unauthenticated.
  if (!isForm && !bodyHash && toBytes(input.body).length > 0) {
    return fail("twilio", "body_hash_mismatch", "Non-form body without a bodySHA256 URL parameter: the body is not covered by the signature.", { header: "x-twilio-signature" });
  }
  const expected = await hmac("SHA-1", input.secret, twilioSigningString(input.url, isForm ? body : "", h["content-type"]), "base64");
  if (!timingSafeEqual(sig.trim(), expected)) {
    return fail("twilio", "signature_mismatch", "Signature does not match base64(HMAC-SHA1(authToken, url + sortedParams)).", { header: "x-twilio-signature" });
  }
  if (bodyHash && bodyHash !== (await digest("SHA-256", input.body, "hex"))) {
    return fail("twilio", "body_hash_mismatch", "URL signature is valid but the body does not match the bodySHA256 query parameter.", { header: "x-twilio-signature" });
  }
  return { ok: true, provider: "twilio", header: "x-twilio-signature" };
}

async function verifyGeneric(input: VerifyInput, h: Record<string, string>): Promise<VerifyResult> {
  const opts = input.generic ?? {};
  const name = (opts.header ?? "x-signature").toLowerCase();
  let sig = h[name];
  if (!sig) return fail("generic", "missing_header", `No ${name} header.`);
  const alg = opts.algorithm ?? "SHA-256";
  if (opts.prefix && sig.startsWith(opts.prefix)) sig = sig.slice(opts.prefix.length);
  else sig = sig.replace(/^(?:sha1|sha256|sha512|v1)=/i, "");
  const encoding: Encoding = opts.encoding ?? (/^[0-9a-f]+$/i.test(sig) ? "hex" : "base64");
  const expected = await hmac(alg, input.secret, input.body, encoding);
  const match = encoding === "hex" ? timingSafeEqual(sig.toLowerCase(), expected) : timingSafeEqual(sig, expected);
  return match
    ? { ok: true, provider: "generic", header: name }
    : fail("generic", "signature_mismatch", `Signature does not match ${encoding}(HMAC-${alg}(secret, rawBody)).`, { header: name });
}

const dec = new TextDecoder();
export function bodyString(body: string | Uint8Array): string {
  return typeof body === "string" ? body : dec.decode(body);
}

/** Verify a webhook signature. Never throws for bad input; returns `{ ok: false, code, reason }`. */
export async function verify(input: VerifyInput): Promise<VerifyResult> {
  if (input.secret === undefined || input.secret.length === 0) return fail(input.provider, "missing_secret", "No signing secret provided.");
  const h = normalizeHeaders(input.headers);
  switch (input.provider) {
    case "stripe":
      return verifyStripe(input, h);
    case "slack":
      return verifySlack(input, h);
    case "github":
      return verifyGithub(input, h);
    case "shopify":
      return verifyShopify(input, h);
    case "twilio":
      return verifyTwilio(input, h);
    case "generic":
      return verifyGeneric(input, h);
  }
}

export interface SignInput {
  provider: Provider;
  secret: string | Uint8Array;
  body: string;
  /** Unix seconds for Stripe/Slack. Defaults to now. */
  timestamp?: number;
  url?: string;
  contentType?: string;
  generic?: GenericOptions;
}

/** Produce the signature header(s) a provider would send. Useful for tests and for re-signing replays. */
export async function sign(input: SignInput): Promise<Record<string, string>> {
  const t = input.timestamp ?? Math.floor(Date.now() / 1000);
  switch (input.provider) {
    case "stripe":
      return { "stripe-signature": `t=${t},v1=${await hmac("SHA-256", input.secret, `${t}.${input.body}`, "hex")}` };
    case "slack":
      return {
        "x-slack-request-timestamp": String(t),
        "x-slack-signature": `v0=${await hmac("SHA-256", input.secret, `v0:${t}:${input.body}`, "hex")}`,
      };
    case "github":
      return { "x-hub-signature-256": `sha256=${await hmac("SHA-256", input.secret, input.body, "hex")}` };
    case "shopify":
      return { "x-shopify-hmac-sha256": await hmac("SHA-256", input.secret, input.body, "base64") };
    case "twilio": {
      if (!input.url) throw new Error("Twilio signing needs the full request URL.");
      return { "x-twilio-signature": await hmac("SHA-1", input.secret, twilioSigningString(input.url, input.body, input.contentType ?? "application/x-www-form-urlencoded"), "base64") };
    }
    case "generic": {
      const o = input.generic ?? {};
      const sig = await hmac(o.algorithm ?? "SHA-256", input.secret, input.body, o.encoding ?? "hex");
      return { [(o.header ?? "x-signature").toLowerCase()]: `${o.prefix ?? ""}${sig}` };
    }
  }
}
