import { normalizeHeaders, type HeaderBag, type Provider } from "./verify.js";

export interface Detection {
  provider: Provider;
  /** Header that identified the provider. */
  header: string;
}

const RULES: ReadonlyArray<[Provider, string]> = [
  ["stripe", "stripe-signature"],
  ["github", "x-hub-signature-256"],
  ["github", "x-github-event"],
  ["github", "x-hub-signature"],
  ["shopify", "x-shopify-hmac-sha256"],
  ["shopify", "x-shopify-topic"],
  ["slack", "x-slack-signature"],
  ["twilio", "x-twilio-signature"],
];

/** Guess the sending provider from request headers. Returns null when nothing matches. */
export function detectProvider(headers: HeaderBag): Detection | null {
  const h = normalizeHeaders(headers);
  for (const [provider, header] of RULES) if (h[header] !== undefined) return { provider, header };
  const generic = Object.keys(h).find((k) => /signature|hmac/.test(k));
  return generic ? { provider: "generic", header: generic } : null;
}

export interface Explanation {
  provider: Provider;
  eventType?: string;
  eventId?: string;
  /** One-line human summary. */
  summary: string;
  fields: Array<{ label: string; value: string }>;
  /** Provider-specific advice, e.g. "respond with the challenge". */
  hints: string[];
}

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | undefined => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : undefined);
const s = (v: unknown): string | undefined => (typeof v === "string" && v ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : undefined);

/** Mask phone numbers and emails so explanations are safe to paste into tickets. */
export function mask(value: string): string {
  if (value.includes("@")) {
    const [user = "", domain = ""] = value.split("@");
    return `${user.slice(0, 1)}***@${domain}`;
  }
  if (/^\+?\d{7,}$/.test(value)) return `${value.slice(0, value.length - 7)}***${value.slice(-4)}`;
  return value;
}

function safeJson(text: string | null | undefined): Obj | undefined {
  if (!text) return undefined;
  try {
    return obj(JSON.parse(text));
  } catch {
    return undefined;
  }
}

function parsePayload(body: string): { json?: Obj; form?: URLSearchParams } {
  const t = body.trim();
  if (t.startsWith("{")) {
    try {
      return { json: JSON.parse(t) as Obj };
    } catch {
      return {};
    }
  }
  if (/^[\w.%-]+=/.test(t)) return { form: new URLSearchParams(t) };
  return {};
}

const ZERO_DECIMAL = new Set(["bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf"]);
function money(amount: unknown, currency: unknown): string | undefined {
  if (typeof amount !== "number" || typeof currency !== "string") return undefined;
  const c = currency.toLowerCase();
  return ZERO_DECIMAL.has(c) ? `${amount} ${c.toUpperCase()}` : `${(amount / 100).toFixed(2)} ${c.toUpperCase()}`;
}

function push(fields: Explanation["fields"], label: string, value: string | undefined): void {
  if (value !== undefined && value !== "") fields.push({ label, value });
}

function explainStripe(json: Obj | undefined): Explanation {
  const fields: Explanation["fields"] = [];
  const hints: string[] = [];
  if (!json) return { provider: "stripe", summary: "Stripe request with a non-JSON body.", fields, hints };
  const type = s(json["type"]);
  const id = s(json["id"]);
  const o = obj(obj(json["data"])?.["object"]) ?? {};
  const created = typeof json["created"] === "number" ? new Date((json["created"] as number) * 1000).toISOString() : undefined;
  const amount = money(o["amount"] ?? o["amount_total"] ?? o["amount_due"], o["currency"]);
  push(fields, "event", type);
  push(fields, "event id", id);
  push(fields, "mode", json["livemode"] === true ? "live" : json["livemode"] === false ? "test" : undefined);
  push(fields, "created", created);
  push(fields, "api version", s(json["api_version"]));
  push(fields, "object", o["object"] ? `${s(o["object"])} ${s(o["id"]) ?? ""}`.trim() : undefined);
  push(fields, "amount", amount);
  push(fields, "status", s(o["status"]));
  push(fields, "customer", s(o["customer"]));
  hints.push("Respond 2xx quickly and process asynchronously; Stripe retries non-2xx responses for up to 3 days in live mode.");
  if (id) hints.push(`Deduplicate on the event id (${id}); Stripe can deliver the same event more than once.`);
  const parts = [type ? `Stripe ${type}` : "Stripe event", id ? `(${id})` : "", o["object"] ? `for ${s(o["object"])} ${s(o["id"]) ?? ""}`.trim() : "", amount ? `— ${amount}` : "", s(o["status"]) ? `status ${s(o["status"])}` : "", json["livemode"] === false ? "[test mode]" : ""];
  return { provider: "stripe", eventType: type, eventId: id, summary: parts.filter(Boolean).join(" "), fields, hints };
}

function explainGithub(json: Obj | undefined, h: Record<string, string>): Explanation {
  const fields: Explanation["fields"] = [];
  const hints: string[] = [];
  const event = h["x-github-event"];
  const delivery = h["x-github-delivery"];
  const action = s(json?.["action"]);
  const repo = s(obj(json?.["repository"])?.["full_name"]);
  const sender = s(obj(json?.["sender"])?.["login"]);
  const pr = obj(json?.["pull_request"]);
  const issue = obj(json?.["issue"]);
  push(fields, "event", event);
  push(fields, "action", action);
  push(fields, "delivery id", delivery);
  push(fields, "repository", repo);
  push(fields, "sender", sender);
  push(fields, "ref", s(json?.["ref"]));
  push(fields, "pull request", pr ? `#${s(pr["number"])} ${s(pr["title"]) ?? ""}`.trim() : undefined);
  push(fields, "issue", issue ? `#${s(issue["number"])} ${s(issue["title"]) ?? ""}`.trim() : undefined);
  push(fields, "hook id", h["x-github-hook-id"] ?? s(json?.["hook_id"]));
  if (event === "ping") hints.push("Ping event: GitHub sends this when the webhook is created. Return 2xx.");
  hints.push("GitHub expects a 2xx response within 10 seconds; queue slow work.");
  const type = event ? (action ? `${event}.${action}` : event) : undefined;
  const summary = `GitHub ${type ?? "webhook"}${repo ? ` on ${repo}` : ""}${sender ? ` by ${sender}` : ""}${delivery ? ` (delivery ${delivery})` : ""}`;
  return { provider: "github", eventType: type, eventId: delivery, summary, fields, hints };
}

function explainShopify(json: Obj | undefined, h: Record<string, string>): Explanation {
  const fields: Explanation["fields"] = [];
  const topic = h["x-shopify-topic"];
  const shop = h["x-shopify-shop-domain"];
  const webhookId = h["x-shopify-webhook-id"] ?? h["x-shopify-event-id"];
  push(fields, "topic", topic);
  push(fields, "shop", shop);
  push(fields, "webhook id", webhookId);
  push(fields, "api version", h["x-shopify-api-version"]);
  push(fields, "resource id", s(json?.["admin_graphql_api_id"]) ?? s(json?.["id"]));
  push(fields, "name", s(json?.["name"]));
  push(fields, "total", json?.["total_price"] !== undefined ? `${s(json["total_price"])} ${s(json["currency"]) ?? ""}`.trim() : undefined);
  push(fields, "financial status", s(json?.["financial_status"]));
  const hints = ["Shopify signs the raw body with your app's client secret (base64 HMAC-SHA256).", "Deduplicate on X-Shopify-Webhook-Id; deliveries can repeat."];
  const summary = `Shopify ${topic ?? "webhook"}${shop ? ` from ${shop}` : ""}${s(json?.["name"]) ? ` — ${s(json?.["name"])}` : ""}`;
  return { provider: "shopify", eventType: topic, eventId: webhookId, summary, fields, hints };
}

function explainSlack(json: Obj | undefined, form: URLSearchParams | undefined): Explanation {
  const fields: Explanation["fields"] = [];
  const hints: string[] = [];
  if (form) {
    const payload = form.get("payload");
    if (payload) {
      let p: Obj | undefined;
      try {
        p = JSON.parse(payload) as Obj;
      } catch {
        p = undefined;
      }
      const type = s(p?.["type"]);
      push(fields, "interaction", type);
      push(fields, "team", s(obj(p?.["team"])?.["id"]));
      push(fields, "user", s(obj(p?.["user"])?.["id"]));
      hints.push("Interactive payloads must be acknowledged with HTTP 200 within 3 seconds.");
      return { provider: "slack", eventType: type, summary: `Slack interaction ${type ?? ""}`.trim(), fields, hints };
    }
    const command = form.get("command") ?? undefined;
    push(fields, "command", command);
    push(fields, "text", form.get("text") ?? undefined);
    push(fields, "team", form.get("team_domain") ?? form.get("team_id") ?? undefined);
    push(fields, "channel", form.get("channel_name") ?? undefined);
    push(fields, "user", form.get("user_name") ?? form.get("user_id") ?? undefined);
    hints.push("Slash commands must be acknowledged within 3 seconds; use response_url for slower replies.");
    return { provider: "slack", eventType: command ? `slash_command ${command}` : "form", summary: `Slack slash command ${command ?? ""}`.trim(), fields, hints };
  }
  const type = s(json?.["type"]);
  if (type === "url_verification") {
    hints.push("URL verification: respond 200 with the `challenge` value (plain text or JSON {\"challenge\": ...}).");
    return { provider: "slack", eventType: type, summary: "Slack Events API URL verification handshake", fields: [{ label: "type", value: type }], hints };
  }
  const event = obj(json?.["event"]);
  const eventType = s(event?.["type"]);
  const eventId = s(json?.["event_id"]);
  push(fields, "type", type);
  push(fields, "event", eventType);
  push(fields, "event id", eventId);
  push(fields, "team", s(json?.["team_id"]));
  push(fields, "channel", s(event?.["channel"]));
  push(fields, "user", s(event?.["user"]));
  hints.push("Events API requests must be acknowledged within 3 seconds or Slack retries (X-Slack-Retry-Num).");
  return { provider: "slack", eventType: eventType ?? type, eventId, summary: `Slack ${eventType ?? type ?? "event"}${eventId ? ` (${eventId})` : ""}`, fields, hints };
}

function explainTwilio(form: URLSearchParams | undefined, json: Obj | undefined): Explanation {
  const fields: Explanation["fields"] = [];
  const get = (k: string): string | undefined => form?.get(k) ?? s(json?.[k]);
  const messageSid = get("MessageSid") ?? get("SmsSid");
  const callSid = get("CallSid");
  const status = get("MessageStatus") ?? get("SmsStatus") ?? get("CallStatus");
  const from = get("From");
  const to = get("To");
  push(fields, "message sid", messageSid);
  push(fields, "call sid", callSid);
  push(fields, "status", status);
  push(fields, "from", from ? mask(from) : undefined);
  push(fields, "to", to ? mask(to) : undefined);
  push(fields, "body", get("Body"));
  push(fields, "account", get("AccountSid"));
  let eventType = "webhook";
  if (callSid) eventType = get("CallStatus") ? `call.${get("CallStatus")}` : "call";
  else if (messageSid) eventType = get("Body") !== undefined && (status === "received" || !get("MessageStatus")) ? "message.inbound" : `message.${status ?? "status"}`;
  const hints = ["Twilio signs the exact public URL it called; behind a proxy, reconstruct the original https URL (including query string)."];
  const summary = `Twilio ${eventType}${messageSid ?? callSid ? ` (${messageSid ?? callSid})` : ""}${from ? ` from ${mask(from)}` : ""}`;
  return { provider: "twilio", eventType, eventId: messageSid ?? callSid, summary, fields, hints };
}

function explainGeneric(json: Obj | undefined, form: URLSearchParams | undefined): Explanation {
  const fields: Explanation["fields"] = [];
  const src = json ?? (form ? Object.fromEntries(form.entries()) : undefined);
  const type = s(src?.["type"]) ?? s(src?.["event"]) ?? s(src?.["event_type"]) ?? s(src?.["topic"]) ?? s(src?.["action"]);
  const id = s(src?.["id"]) ?? s(src?.["event_id"]) ?? s(src?.["eventId"]);
  push(fields, "type", type);
  push(fields, "id", id);
  if (src) push(fields, "top-level keys", Object.keys(src).slice(0, 12).join(", "));
  return { provider: "generic", eventType: type, eventId: id, summary: `Webhook${type ? ` ${type}` : ""}${id ? ` (${id})` : ""}`, fields, hints: [] };
}

/** Summarize a webhook payload: event type, id and key fields. Personal data (emails, phone numbers) is masked. */
export function explain(provider: Provider, body: string, headers: HeaderBag = {}): Explanation {
  const h = normalizeHeaders(headers);
  const { json, form } = parsePayload(body);
  switch (provider) {
    case "stripe":
      return explainStripe(json);
    case "github":
      return explainGithub(json ?? safeJson(form?.get("payload")), h);
    case "shopify":
      return explainShopify(json, h);
    case "slack":
      return explainSlack(json, form);
    case "twilio":
      return explainTwilio(form, json);
    case "generic":
      return explainGeneric(json, form);
  }
}
