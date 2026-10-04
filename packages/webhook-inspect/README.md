# @teamshift-io/webhook-inspect

**webhook-inspect is an open-source tool that verifies Stripe, GitHub, Shopify, Slack, Twilio and generic HMAC webhook signatures, explains what each event is, and tells you exactly why a signature check fails.**

It has three parts:

- A **browser-safe core** built on WebCrypto (`globalThis.crypto.subtle`), so the same code runs in Node.js 20+, browsers, Deno, Bun and edge runtimes.
- A **local capture server** that prints and saves every request.
- A **replay command** for re-sending captured events to your app. It can re-sign them with a fresh timestamp.

**Try it in your browser:** [teamshift.io/tools/webhook-inspect](https://teamshift.io/tools/webhook-inspect). Paste headers, body and secret; verification happens client-side.

## Quickstart

```bash
# Verify one request (prints the verdict, a diagnosis, and an explanation of the event)
npx @teamshift-io/webhook-inspect verify --provider stripe --secret whsec_... \
  --header 't=1760000000,v1=5257a8...' --body-file body.json

# Capture webhooks locally: prints headers, verification and explanation, saves to .webhook-inspect/
npx @teamshift-io/webhook-inspect listen --port 8787 --secret whsec_...

# Re-send a captured event to your app, re-signed with a fresh timestamp
npx @teamshift-io/webhook-inspect replay .webhook-inspect/2026-10-04T01-20-39-562Z-001-stripe.json \
  --to http://localhost:3000/api/webhooks/stripe --resign --secret whsec_...
```

`--header` accepts a bare signature value (for `--provider`'s signature header) or `Name: value`, and can be repeated. The secret can also come from `WEBHOOK_SECRET`. `verify` exits `0` when the signature verifies and `1` when it doesn't.

## Example output

A valid Stripe event:

```text
  signature  ✓ verified (stripe, stripe-signature)
  event      Stripe payment_intent.succeeded (evt_3PqTest0001) for payment_intent pi_3PqTest0001 — 125.00 USD status succeeded [test mode]
    event            payment_intent.succeeded
    event id         evt_3PqTest0001
    mode             test
    object           payment_intent pi_3PqTest0001
    amount           125.00 USD
    customer         cus_QTest0001
    hint: Respond 2xx quickly and process asynchronously; Stripe retries non-2xx responses for up to 3 days in live mode.
    hint: Deduplicate on the event id (evt_3PqTest0001); Stripe can deliver the same event more than once.
```

The same request after a framework parsed the JSON and re-serialized it (the most common cause of "No signatures found matching the expected signature"):

```text
  signature  ✗ signature_mismatch  No v1 signature matches HMAC-SHA256(secret, `${t}.${rawBody}`).
    confirmed: The signature matches when the JSON is restored to 2-space indentation and a trailing newline: the body was parsed and re-serialized before verification.
      → Verify against the raw request body before any JSON parsing or re-serialization (express.raw({type: 'application/json'}), await request.text(), Next.js route `await req.text()`).
```

`listen` prints one block per request and saves it as JSON:

```text
── #1 POST /stripe/webhook  2026-10-04T01:20:39.562Z  stripe ────────
  content-type                 application/json
  stripe-signature             t=1791076839,v1=0157ef76d4f7f36870db90e758e2264c9c11e5bed3d9514590269f5344e2851a
  user-agent                   Stripe/1.0 (+https://stripe.com/docs/webhooks)
  body       380 bytes
  signature  ✓ verified (stripe, stripe-signature)
  event      Stripe payment_intent.succeeded (evt_3PqTest0001) for payment_intent pi_3PqTest0001 — 125.00 USD status succeeded [test mode]
  saved      .webhook-inspect/2026-10-04T01-20-39-562Z-001-stripe.json
```

## Providers

| Provider | Header(s) | Algorithm | Signed content | Replay window |
|---|---|---|---|---|
| Stripe | `Stripe-Signature: t=…,v1=…` | HMAC-SHA256, hex | `${t}.${rawBody}`; the key is the full `whsec_…` secret | 300 s (configurable) |
| GitHub | `X-Hub-Signature-256: sha256=…` | HMAC-SHA256, hex | raw body | — |
| Shopify | `X-Shopify-Hmac-Sha256` | HMAC-SHA256, base64 | raw body, keyed with the app's client secret | — |
| Slack | `X-Slack-Signature: v0=…`, `X-Slack-Request-Timestamp` | HMAC-SHA256, hex | `v0:${timestamp}:${rawBody}` | 300 s (configurable) |
| Twilio | `X-Twilio-Signature` | HMAC-SHA1, base64 | full URL + form params sorted by name (`key+value`); for JSON bodies, the URL with `bodySHA256` plus a SHA-256 body check | — |
| Generic | configurable (default `X-Signature`) | HMAC-SHA1/256/512, hex or base64 | raw body; `sha256=`-style prefixes stripped | — |

`detectProvider(headers)` picks the provider from these headers automatically.

## What `diagnose()` checks

When verification fails, webhook-inspect tries concrete fixes. If a fix makes the signature verify, the cause is reported as `confirmed`.

| Code | Meaning |
|---|---|
| `body_reserialized` | The signature matches the JSON at its original formatting, so your framework parsed and re-serialized the body |
| `body_newline` | A trailing newline or CRLF/LF change broke the signature |
| `body_compact_json` | A Stripe body arrived compact, though Stripe sends pretty-printed JSON |
| `empty_body` | The body stream was consumed before verification |
| `secret_whitespace` | A newline, spaces or quotes in the secret (typical of `.env` files) |
| `secret_prefix` | The `whsec_` prefix was stripped (Stripe uses the whole string) |
| `secret_encoding` | The sender expects the secret decoded from base64 or hex |
| `wrong_secret_type` | An API key or OAuth token was used instead of the signing secret (`sk_…`, `xoxb-…`, `shpat_…`, an Account SID, …) |
| `timestamp_skew` | The signature is valid but outside the replay window: a replayed request or clock skew |
| `timestamp_milliseconds` | The timestamp is in milliseconds instead of seconds |
| `url_mismatch` | Twilio: the signature matches a different scheme, host, port or path (proxy rewrite) |
| `wrong_provider` / `legacy_header` / `missing_header` / `malformed_header` | Header problems, e.g. a GitHub request with only the SHA-1 header, or a Stripe header without `t=`/`v1=` |
| `encoding_mismatch` | Hex digest where base64 is expected (Shopify) |

## Library use

```ts
import { verify, diagnose, explain, detectProvider, sign } from "@teamshift-io/webhook-inspect";

const rawBody = await request.text(); // raw bytes, never JSON.stringify(req.body)
const result = await verify({ provider: "stripe", secret: env.STRIPE_WEBHOOK_SECRET, headers: request.headers, body: rawBody });
if (!result.ok) {
  const { diagnoses } = await diagnose({ provider: "stripe", secret: env.STRIPE_WEBHOOK_SECRET, headers: request.headers, body: rawBody });
  console.warn(result.code, diagnoses.map((d) => d.message));
}
console.log(explain("stripe", rawBody).summary);
```

`headers` accepts a Fetch `Headers` instance, a plain object such as Node's `req.headers`, or an array of `[name, value]` pairs. `verify()` never throws on bad input: it returns `{ ok: false, code, reason }`. Comparisons are constant-time.

## FAQ

### How do I verify a Stripe webhook signature?

Read the `Stripe-Signature` header (`t=<timestamp>,v1=<signature>`) and compute HMAC-SHA256 over `${t}.${rawBody}`, keyed with your endpoint's full `whsec_…` secret. Compare the hex result to each `v1` value in constant time, and reject timestamps older than your tolerance (Stripe's libraries default to 300 seconds). `webhook-inspect verify --provider stripe` does exactly this, and `verify()` does it in code.

### Why does my webhook signature verification fail?

Usually for one of three reasons:

1. **The body was changed before verification.** A body parser turned it into an object and back (`JSON.stringify` changes whitespace), or a newline was added.
2. **The secret is wrong.** It comes from a different endpoint or environment, a `stripe listen` session that has its own secret, an API key used instead of the signing secret, or a secret with a trailing newline from `.env`.
3. **The timestamp is outside the replay window.** The request was replayed or the server clock is off.

`webhook-inspect verify` tests each of these and marks the confirmed cause.

### How do I get the raw request body in Express or Next.js?

In Express, mount `express.raw({ type: "application/json" })` on the webhook route, before `express.json()`. In Next.js route handlers, Remix, Hono, Cloudflare Workers and Deno, call `await request.text()` before anything parses the body. Verify that exact string, and only then `JSON.parse` it.

### How do I verify a GitHub webhook?

Compute `sha256=` + hex HMAC-SHA256 of the raw body, keyed with your webhook secret, and compare it to `X-Hub-Signature-256` in constant time. The older `X-Hub-Signature` header uses SHA-1. GitHub recommends the SHA-256 header.

### How do I verify a Shopify webhook HMAC?

Compute base64 HMAC-SHA256 of the raw body, keyed with your app's client secret (not the access token), and compare it to `X-Shopify-Hmac-Sha256`.

### How do I verify Slack request signatures?

Build the base string `v0:{X-Slack-Request-Timestamp}:{rawBody}` and compute HMAC-SHA256 with your app's Signing Secret (not the bot token). Compare `v0=<hex>` to `X-Slack-Signature`, and reject timestamps older than five minutes.

### Why does Twilio signature validation fail behind a proxy or load balancer?

Twilio signs the exact URL it requested, including the scheme, host, port and query string. If a proxy terminates TLS or rewrites the host, your app sees a different URL. Validate against the public URL; `diagnose()` tries common variants and reports the one that matches.

### How do I replay a webhook to my local server?

Capture it with `webhook-inspect listen` (point the provider or a tunnel at it), then run `webhook-inspect replay <file> --to http://localhost:3000/hook`. Add `--resign --secret …` so Stripe and Slack timestamps fall inside the tolerance window again.

### Does it work in the browser or on edge runtimes?

Yes. The core uses only WebCrypto, `TextEncoder`, `URL` and `URLSearchParams`, with no Node.js built-ins. The CLI is the only part that uses Node.js.

## Related tools

- [workflow-lint](../workflow-lint): flags webhook triggers that never verify signatures (rule WL008), plus other workflow risks.
- [permission-planner](../permission-planner): minimum OAuth scopes and approval policy for agent actions.

---

Built by [TeamShift](https://teamshift.io/open-source/agent-toolkit?utm_source=github&utm_medium=readme) — AI workers for small-business operations.
