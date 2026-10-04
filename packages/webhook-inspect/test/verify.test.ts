import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { detectProvider, diagnose, explain, mask, sign, verify } from "../src/index.js";

// Independent reference signer (node:crypto) so the WebCrypto implementation is checked against a second implementation.
const hex = (alg: string, key: string, data: string): string => createHmac(alg, key).update(data).digest("hex");
const b64 = (alg: string, key: string, data: string): string => createHmac(alg, key).update(data).digest("base64");

const NOW = 1_760_000_000;
const STRIPE_SECRET = "whsec_test_" + "c2VjcmV0LWZvci10ZXN0cw";
const stripeBody = JSON.stringify(
  { id: "evt_1Test", object: "event", type: "payment_intent.succeeded", livemode: false, created: NOW, data: { object: { id: "pi_1Test", object: "payment_intent", amount: 2000, currency: "usd", status: "succeeded", customer: "cus_Test" } } },
  null,
  2,
);
const stripeHeader = (body = stripeBody, t = NOW, secret = STRIPE_SECRET): string => `t=${t},v1=${hex("sha256", secret, `${t}.${body}`)}`;

describe("Stripe", () => {
  it("verifies a valid signature", async () => {
    const r = await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "Stripe-Signature": stripeHeader() }, body: stripeBody, now: NOW + 10 });
    expect(r).toMatchObject({ ok: true, provider: "stripe", timestamp: NOW, ageSec: 10 });
  });
  it("accepts any matching v1 when several are present (secret rotation)", async () => {
    const header = `t=${NOW},v1=${"0".repeat(64)},v1=${hex("sha256", STRIPE_SECRET, `${NOW}.${stripeBody}`)}`;
    expect((await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "stripe-signature": header }, body: stripeBody, now: NOW })).ok).toBe(true);
  });
  it("rejects a tampered body", async () => {
    const r = await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "stripe-signature": stripeHeader() }, body: stripeBody.replace("2000", "1"), now: NOW });
    expect(r).toMatchObject({ ok: false, code: "signature_mismatch" });
  });
  it("rejects a stale timestamp even when the signature is valid", async () => {
    const r = await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "stripe-signature": stripeHeader() }, body: stripeBody, now: NOW + 301 });
    expect(r).toMatchObject({ ok: false, code: "timestamp_outside_tolerance", ageSec: 301 });
    expect((await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "stripe-signature": stripeHeader() }, body: stripeBody, now: NOW + 301, toleranceSec: 600 })).ok).toBe(true);
  });
  it("reports missing and malformed headers", async () => {
    expect((await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: {}, body: stripeBody })).code).toBe("missing_header");
    expect((await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "stripe-signature": "garbage" }, body: stripeBody })).code).toBe("malformed_header");
  });
  it("sign() output matches the reference implementation", async () => {
    expect(await sign({ provider: "stripe", secret: STRIPE_SECRET, body: stripeBody, timestamp: NOW })).toEqual({ "stripe-signature": stripeHeader() });
  });
});

describe("GitHub", () => {
  const secret = "gh-webhook-secret";
  const body = JSON.stringify({ action: "opened", repository: { full_name: "acme/app" }, sender: { login: "octo" }, pull_request: { number: 7, title: "Fix" } });
  it("verifies X-Hub-Signature-256", async () => {
    const headers = { "X-Hub-Signature-256": `sha256=${hex("sha256", secret, body)}`, "X-GitHub-Event": "pull_request" };
    expect((await verify({ provider: "github", secret, headers, body })).ok).toBe(true);
  });
  it("rejects the wrong secret", async () => {
    const headers = { "x-hub-signature-256": `sha256=${hex("sha256", "other", body)}` };
    expect((await verify({ provider: "github", secret, headers, body })).code).toBe("signature_mismatch");
  });
  it("explains the legacy-header situation", async () => {
    const d = await diagnose({ provider: "github", secret, headers: { "x-hub-signature": `sha1=${hex("sha1", secret, body)}`, "x-github-event": "push" }, body });
    expect(d.diagnoses.map((x) => x.code)).toContain("legacy_header");
  });
});

describe("Shopify", () => {
  const secret = "shopify-client-secret";
  const body = JSON.stringify({ id: 820982911946154500, name: "#1001", total_price: "19.99", currency: "USD" });
  it("verifies base64 X-Shopify-Hmac-Sha256", async () => {
    expect((await verify({ provider: "shopify", secret, headers: { "X-Shopify-Hmac-Sha256": b64("sha256", secret, body) }, body })).ok).toBe(true);
  });
  it("rejects tampering and flags hex-encoded digests", async () => {
    const d = await diagnose({ provider: "shopify", secret, headers: { "x-shopify-hmac-sha256": hex("sha256", secret, body) }, body });
    expect(d.ok).toBe(false);
    expect(d.diagnoses.map((x) => x.code)).toContain("encoding_mismatch");
  });
});

describe("Slack", () => {
  const secret = "8f742231b10e8888abcd99yyyzzz85a5";
  const body = "token=x&team_id=T1&team_domain=acme&channel_name=general&user_name=sam&command=%2Fweather&text=94070";
  const headers = (ts = NOW, b = body) => ({ "X-Slack-Request-Timestamp": String(ts), "X-Slack-Signature": `v0=${hex("sha256", secret, `v0:${ts}:${b}`)}` });
  it("verifies v0 signatures", async () => {
    expect((await verify({ provider: "slack", secret, headers: headers(), body, now: NOW })).ok).toBe(true);
  });
  it("rejects tampering and stale timestamps", async () => {
    expect((await verify({ provider: "slack", secret, headers: headers(), body: body + "&x=1", now: NOW })).code).toBe("signature_mismatch");
    expect((await verify({ provider: "slack", secret, headers: headers(NOW - 600), body, now: NOW })).code).toBe("timestamp_outside_tolerance");
  });
  it("requires the timestamp header", async () => {
    expect((await verify({ provider: "slack", secret, headers: { "x-slack-signature": "v0=abc" }, body })).code).toBe("missing_header");
  });
  it("explains slash commands", () => {
    const e = explain("slack", body, headers());
    expect(e.eventType).toBe("slash_command /weather");
  });
});

describe("Twilio", () => {
  const token = "12345678901234567890123456789012";
  const url = "https://mycompany.example/sms?tenant=1";
  const body = "To=%2B15550100&From=%2B15550123456&Body=Hello&MessageSid=SM123&AccountSid=AC123&SmsStatus=received";
  // Reference: url + params sorted by key, concatenated as key+value.
  const params = [...new URLSearchParams(body).entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  const expected = b64("sha1", token, url + params.map(([k, v]) => k + v).join(""));
  it("verifies form-encoded requests", async () => {
    expect((await verify({ provider: "twilio", secret: token, headers: { "X-Twilio-Signature": expected }, body, url })).ok).toBe(true);
  });
  it("requires the URL and detects proxy URL rewrites", async () => {
    expect((await verify({ provider: "twilio", secret: token, headers: { "x-twilio-signature": expected }, body })).code).toBe("missing_url");
    const d = await diagnose({ provider: "twilio", secret: token, headers: { "x-twilio-signature": expected }, body, url: url.replace("https:", "http:") });
    expect(d.diagnoses[0]).toMatchObject({ code: "url_mismatch", level: "confirmed" });
  });
  it("verifies JSON bodies via bodySHA256", async () => {
    const json = JSON.stringify({ hello: "world" });
    const u = `https://mycompany.example/hook?bodySHA256=${createHash("sha256").update(json).digest("hex")}`;
    const sig = b64("sha1", token, u);
    expect((await verify({ provider: "twilio", secret: token, headers: { "x-twilio-signature": sig, "content-type": "application/json" }, body: json, url: u })).ok).toBe(true);
    const bad = await verify({ provider: "twilio", secret: token, headers: { "x-twilio-signature": sig, "content-type": "application/json" }, body: "{}", url: u });
    expect(bad.code).toBe("body_hash_mismatch");
  });
  it("explains inbound SMS with masked numbers", () => {
    const e = explain("twilio", body);
    expect(e.eventType).toBe("message.inbound");
    expect(e.summary).not.toContain("15550123456");
  });
});

describe("generic HMAC", () => {
  it("verifies hex and base64, with or without a sha256= prefix", async () => {
    const body = '{"event":"invoice.paid","id":"inv_1"}';
    const secret = "generic-secret";
    expect((await verify({ provider: "generic", secret, headers: { "x-signature": hex("sha256", secret, body) }, body })).ok).toBe(true);
    expect((await verify({ provider: "generic", secret, headers: { "x-signature": `sha256=${hex("sha256", secret, body)}` }, body })).ok).toBe(true);
    expect((await verify({ provider: "generic", secret, headers: { "x-sig": b64("sha512", secret, body) }, body, generic: { header: "X-Sig", algorithm: "SHA-512", encoding: "base64" } })).ok).toBe(true);
    expect((await verify({ provider: "generic", secret, headers: { "x-signature": hex("sha256", "nope", body) }, body })).ok).toBe(false);
  });
});

describe("diagnose()", () => {
  const base = { provider: "stripe" as const, headers: { "stripe-signature": stripeHeader() }, body: stripeBody, now: NOW };
  it("confirms a re-serialized JSON body", async () => {
    const d = await diagnose({ ...base, secret: STRIPE_SECRET, body: JSON.stringify(JSON.parse(stripeBody)) });
    expect(d.diagnoses[0]).toMatchObject({ code: "body_reserialized", level: "confirmed" });
  });
  it("confirms a trailing-newline change", async () => {
    const d = await diagnose({ ...base, secret: STRIPE_SECRET, body: `${stripeBody}\n` });
    expect(d.diagnoses.map((x) => x.code)).toContain("body_newline");
  });
  it("confirms whitespace in the secret", async () => {
    const d = await diagnose({ ...base, secret: `${STRIPE_SECRET}\n` });
    expect(d.diagnoses.find((x) => x.code === "secret_whitespace")?.level).toBe("confirmed");
  });
  it("confirms a stripped whsec_ prefix", async () => {
    const d = await diagnose({ ...base, secret: STRIPE_SECRET.slice("whsec_".length) });
    expect(d.diagnoses.map((x) => x.code)).toContain("secret_prefix");
  });
  it("recognizes an API key used as the signing secret", async () => {
    const d = await diagnose({ ...base, secret: ["sk", "test", "abcdefghijklmnop"].join("_") });
    expect(d.diagnoses.map((x) => x.code)).toContain("wrong_secret_type");
  });
  it("explains timestamp skew", async () => {
    const d = await diagnose({ ...base, secret: STRIPE_SECRET, now: NOW + 7200 });
    expect(d.diagnoses[0]).toMatchObject({ code: "timestamp_skew", level: "confirmed" });
    expect(d.diagnoses[0]?.hint).toMatch(/replay/);
  });
  it("points at the right provider when the header belongs to another one", async () => {
    const d = await diagnose({ provider: "github", secret: STRIPE_SECRET, headers: base.headers, body: stripeBody });
    expect(d.diagnoses[0]).toMatchObject({ code: "wrong_provider" });
    expect(d.diagnoses[0]?.hint).toContain("stripe");
  });
  it("falls back to an ordered list of causes for a plain mismatch", async () => {
    const d = await diagnose({ ...base, secret: "whsec_wrong" });
    expect(d.diagnoses.at(-1)?.code).toBe("signature_mismatch");
  });
  it("reports success", async () => {
    const d = await diagnose({ ...base, secret: STRIPE_SECRET });
    expect(d.ok).toBe(true);
    expect(d.diagnoses[0]?.code).toBe("verified");
  });
});

describe("detectProvider() and explain()", () => {
  it.each([
    [{ "Stripe-Signature": "t=1,v1=a" }, "stripe"],
    [{ "X-GitHub-Event": "push" }, "github"],
    [{ "X-Shopify-Topic": "orders/create" }, "shopify"],
    [{ "X-Slack-Signature": "v0=a" }, "slack"],
    [{ "X-Twilio-Signature": "a" }, "twilio"],
    [{ "X-Webhook-Signature": "a" }, "generic"],
  ])("detects %o as %s", (headers, provider) => {
    expect(detectProvider(headers)?.provider).toBe(provider);
  });
  it("returns null for unsigned requests", () => {
    expect(detectProvider({ "content-type": "application/json" })).toBeNull();
  });
  it("summarizes Stripe events", () => {
    const e = explain("stripe", stripeBody);
    expect(e).toMatchObject({ eventType: "payment_intent.succeeded", eventId: "evt_1Test" });
    expect(e.summary).toContain("20.00 USD");
    expect(e.summary).toContain("test mode");
  });
  it("summarizes GitHub and Shopify events using headers", () => {
    const g = explain("github", JSON.stringify({ action: "opened", repository: { full_name: "acme/app" } }), { "x-github-event": "issues", "x-github-delivery": "d-1" });
    expect(g).toMatchObject({ eventType: "issues.opened", eventId: "d-1" });
    const s = explain("shopify", JSON.stringify({ name: "#1001", total_price: "10.00", currency: "USD" }), { "x-shopify-topic": "orders/create", "x-shopify-shop-domain": "acme.myshopify.com" });
    expect(s.summary).toBe("Shopify orders/create from acme.myshopify.com — #1001");
  });
  it("tells you to echo the Slack challenge", () => {
    const e = explain("slack", JSON.stringify({ type: "url_verification", challenge: "abc" }));
    expect(e.hints[0]).toMatch(/challenge/);
  });
  it("masks emails and phone numbers", () => {
    expect(mask("jane@acme.example")).toBe("j***@acme.example");
    expect(mask("+15550123456")).toBe("+1555***3456");
  });
});

describe("header inputs", () => {
  it("accepts Fetch Headers, plain objects and pair arrays", async () => {
    const secret = "s3cret-value";
    const body = "{}";
    const sig = `sha256=${hex("sha256", secret, body)}`;
    for (const headers of [new Headers({ "X-Hub-Signature-256": sig }), { "x-hub-signature-256": [sig] }, [["X-Hub-Signature-256", sig]] as Array<[string, string]>]) {
      expect((await verify({ provider: "github", secret, headers, body })).ok).toBe(true);
    }
  });
});

describe("review hardening", () => {
  it("an invalid tolerance never disables the replay check", async () => {
    const r = await verify({ provider: "stripe", secret: STRIPE_SECRET, headers: { "stripe-signature": stripeHeader() }, body: stripeBody, now: NOW + 3600, toleranceSec: Number.NaN });
    expect(r.code).toBe("timestamp_outside_tolerance");
  });
  it("Twilio rejects a non-form body that is not covered by bodySHA256", async () => {
    const token = "12345678901234567890123456789012";
    const url = "https://mycompany.example/hook";
    const sig = b64("sha1", token, url);
    const r = await verify({ provider: "twilio", secret: token, headers: { "x-twilio-signature": sig, "content-type": "application/json" }, body: '{"forged":true}', url });
    expect(r.ok).toBe(false);
  });
  it("Stripe signs raw bytes, including a UTF-8 BOM", async () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(stripeBody)]);
    const sig = createHmac("sha256", STRIPE_SECRET).update(Buffer.concat([Buffer.from(`${NOW}.`), Buffer.from(bytes)])).digest("hex");
    const headers = { "stripe-signature": `t=${NOW},v1=${sig}` };
    expect((await verify({ provider: "stripe", secret: STRIPE_SECRET, headers, body: bytes, now: NOW })).ok).toBe(true);
    expect((await verify({ provider: "stripe", secret: STRIPE_SECRET, headers, body: stripeBody, now: NOW })).ok).toBe(false);
  });
  it("diagnoses malformed headers as malformed, not missing", async () => {
    const d = await diagnose({ provider: "github", secret: "s", headers: { "x-hub-signature-256": "deadbeef" }, body: "{}" });
    expect(d.diagnoses[0]?.code).toBe("malformed_header");
  });
  it("confirms secret fixes on stale captures", async () => {
    const d = await diagnose({ provider: "stripe", secret: STRIPE_SECRET.slice("whsec_".length), headers: { "stripe-signature": stripeHeader() }, body: stripeBody, now: NOW + 86400 });
    expect(d.diagnoses.map((x) => x.code)).toContain("secret_prefix");
  });
});
