#!/usr/bin/env node
import { createServer, type IncomingMessage } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  detectProvider,
  diagnose,
  explain,
  PROVIDERS,
  SIGNATURE_HEADERS,
  sign,
  type DiagnoseResult,
  type Explanation,
  type Provider,
} from "./index.js";

const VERSION = "0.1.0";

const HELP = `webhook-inspect ${VERSION} — verify, explain, capture and replay webhooks

Usage:
  webhook-inspect verify  --provider <p> --secret <s> --header '<value | Name: value>' [--header ...]
                          (--body-file <f> | --body <s>) [--url <twilio-url>] [--timestamp <slack-ts>] [--json]
  webhook-inspect listen  [--port 8787] [--host 127.0.0.1] [--secret <s>] [--provider auto] [--dir .webhook-inspect]
                          [--public-url https://abc.example]   (base URL Twilio calls, for signature checks)
  webhook-inspect replay  <saved.json> --to <url> [--resign --secret <s>]

Providers: ${PROVIDERS.join(", ")}  (auto-detected from headers when --provider is omitted)
The secret can also come from the WEBHOOK_SECRET environment variable.
Try it in your browser: https://teamshift.io/tools/webhook-inspect`;

const C = process.stdout.isTTY && !process.env["NO_COLOR"];
const paint = (code: number, s: string): string => (C ? `\u001b[${code}m${s}\u001b[0m` : s);
const green = (s: string): string => paint(32, s);
const red = (s: string): string => paint(31, s);
const dim = (s: string): string => paint(2, s);
const bold = (s: string): string => paint(1, s);

function isProvider(p: string | undefined): p is Provider {
  return p !== undefined && (PROVIDERS as readonly string[]).includes(p);
}

function renderVerification(d: DiagnoseResult): string[] {
  const lines: string[] = [];
  if (d.ok) {
    lines.push(`  signature  ${green("✓ verified")} ${dim(`(${d.result.provider}, ${d.result.header ?? ""})`)}`);
    return lines;
  }
  lines.push(`  signature  ${red(`✗ ${d.result.code ?? "failed"}`)}  ${d.result.reason ?? ""}`);
  for (const x of d.diagnoses) {
    lines.push(`    ${x.level === "confirmed" ? bold("confirmed") : x.level}: ${x.message}`);
    lines.push(`      ${dim(`→ ${x.hint}`)}`);
  }
  return lines;
}

function renderExplanation(e: Explanation): string[] {
  const lines = [`  event      ${bold(e.summary)}`];
  for (const f of e.fields) lines.push(`    ${f.label.padEnd(16)} ${f.value}`);
  for (const h of e.hints) lines.push(`    ${dim(`hint: ${h}`)}`);
  return lines;
}

/** Parse repeated --header flags: "Name: value" pairs, or a bare value for the provider's signature header. */
function parseHeaderFlags(values: string[], provider: Provider | undefined, genericHeader: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const raw of values) {
    const m = /^([A-Za-z0-9-]+):\s?(.*)$/.exec(raw);
    if (m && !/^t=\d/.test(raw) && !/^(sha256|sha1|v0)=/.test(raw)) {
      headers[(m[1] as string).toLowerCase()] = m[2] as string;
    } else {
      if (!provider) throw new Error(`Bare --header value "${raw.slice(0, 20)}…" needs --provider so I know which header it is.`);
      const name = provider === "generic" ? (genericHeader ?? "x-signature") : SIGNATURE_HEADERS[provider];
      headers[name] = raw;
    }
  }
  return headers;
}

async function cmdVerify(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      provider: { type: "string" },
      secret: { type: "string" },
      header: { type: "string", multiple: true },
      "signature-header": { type: "string" },
      timestamp: { type: "string" },
      "body-file": { type: "string" },
      body: { type: "string" },
      url: { type: "string" },
      tolerance: { type: "string" },
      json: { type: "boolean", default: false },
    },
  });
  const flagProvider = values.provider;
  if (flagProvider !== undefined && !isProvider(flagProvider)) throw new Error(`Unknown provider "${flagProvider}". Use one of: ${PROVIDERS.join(", ")}.`);
  const headers = parseHeaderFlags(values.header ?? [], flagProvider, values["signature-header"]);
  if (values.timestamp) headers["x-slack-request-timestamp"] = values.timestamp;
  const provider: Provider | undefined = flagProvider ?? detectProvider(headers)?.provider;
  if (!provider) throw new Error("Could not detect the provider from the headers; pass --provider.");
  let body: string;
  if (values["body-file"]) body = await readFile(values["body-file"], "utf8");
  else if (values.body !== undefined) body = values.body;
  else throw new Error("Pass the raw body with --body-file <file> or --body '<raw>'.");
  const secret = values.secret ?? process.env["WEBHOOK_SECRET"] ?? "";
  const toleranceSec = values.tolerance === undefined ? undefined : Number(values.tolerance);
  if (toleranceSec !== undefined && !(Number.isFinite(toleranceSec) && toleranceSec >= 0)) {
    throw new Error(`--tolerance must be a non-negative number of seconds, got "${values.tolerance}".`);
  }
  const result = await diagnose({
    provider,
    secret,
    headers,
    body,
    url: values.url,
    toleranceSec,
    generic: values["signature-header"] ? { header: values["signature-header"] } : undefined,
  });
  const explanation = explain(provider, body, headers);
  if (values.json) {
    console.log(JSON.stringify({ ...result, explanation }, null, 2));
  } else {
    console.log([...renderVerification(result), ...renderExplanation(explanation)].join("\n"));
  }
  return result.ok ? 0 : 1;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function cmdListen(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      port: { type: "string", default: "8787" },
      host: { type: "string", default: "127.0.0.1" },
      secret: { type: "string" },
      provider: { type: "string", default: "auto" },
      dir: { type: "string", default: ".webhook-inspect" },
      "public-url": { type: "string" },
    },
  });
  const forced = values.provider === "auto" ? undefined : values.provider;
  if (forced !== undefined && !isProvider(forced)) throw new Error(`Unknown provider "${forced}".`);
  const secret = values.secret ?? process.env["WEBHOOK_SECRET"];
  const dir = values.dir ?? ".webhook-inspect";
  await mkdir(dir, { recursive: true });
  let count = 0;

  const server = createServer((req, res) => {
    void (async () => {
      const raw = await readBody(req);
      const body = raw.toString("utf8");
      const lossless = Buffer.from(body, "utf8").equals(raw);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
      const provider: Provider = forced ?? detectProvider(headers)?.provider ?? "generic";
      const publicUrl = values["public-url"] ? new URL(req.url ?? "/", values["public-url"]).toString() : `http://${headers["host"] ?? "localhost"}${req.url ?? "/"}`;
      const verification = secret ? await diagnose({ provider, secret, headers, body, url: publicUrl }) : undefined;
      const explanation = explain(provider, body, headers);
      const receivedAt = new Date().toISOString();
      count++;
      const file = join(dir, `${receivedAt.replace(/[:.]/g, "-")}-${String(count).padStart(3, "0")}-${provider}.json`);
      const record = {
        receivedAt,
        method: req.method ?? "POST",
        path: req.url ?? "/",
        publicUrl,
        provider,
        headers,
        body,
        ...(lossless ? {} : { bodyBase64: raw.toString("base64") }),
        verification,
        explanation,
      };
      await writeFile(file, JSON.stringify(record, null, 2));

      const lines = [
        "",
        bold(`── #${count} ${record.method} ${record.path}  ${receivedAt}  ${provider} ${"─".repeat(8)}`),
        ...Object.entries(headers).map(([k, v]) => `  ${dim(k.padEnd(28))} ${v.length > 90 ? `${v.slice(0, 87)}...` : v}`),
        `  body       ${raw.length} bytes${lossless ? "" : " (binary, saved as base64)"}`,
        ...(verification ? renderVerification(verification) : [`  signature  ${dim("not checked (pass --secret to verify)")}`]),
        ...renderExplanation(explanation),
        `  saved      ${file}`,
      ];
      console.log(lines.join("\n"));

      // Slack's Events API URL verification needs the challenge echoed back.
      if (provider === "slack" && explanation.eventType === "url_verification") {
        const challenge = (JSON.parse(body) as { challenge?: string }).challenge ?? "";
        res.writeHead(200, { "content-type": "text/plain" }).end(challenge);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ received: true, file }));
    })().catch((err: unknown) => {
      console.error(red(`error handling request: ${err instanceof Error ? err.message : String(err)}`));
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  const port = Number(values.port);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, values.host, () => resolve());
  });
  console.log(`webhook-inspect listening on http://${values.host}:${port}  (provider: ${forced ?? "auto"}, secret: ${secret ? "set" : "not set"}, saving to ${dir}/)`);
  console.log(dim("Expose it with a tunnel (e.g. `cloudflared tunnel --url http://localhost:" + port + "`) or `stripe listen --forward-to localhost:" + port + "`. Ctrl+C to stop."));
  await new Promise<void>((resolve) => {
    process.once("SIGINT", () => server.close(() => resolve()));
  });
  return 0;
}

const DROP_ON_REPLAY = new Set(["host", "content-length", "connection", "transfer-encoding", "accept-encoding", "keep-alive"]);

async function cmdReplay(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      to: { type: "string" },
      resign: { type: "boolean", default: false },
      secret: { type: "string" },
      provider: { type: "string" },
    },
  });
  const file = positionals[0];
  if (!file || !values.to) throw new Error("Usage: webhook-inspect replay <saved.json> --to <url> [--resign --secret <s>]");
  const record = JSON.parse(await readFile(file, "utf8")) as {
    method?: string;
    headers: Record<string, string>;
    body: string;
    bodyBase64?: string;
    provider?: string;
  };
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(record.headers)) if (!DROP_ON_REPLAY.has(k.toLowerCase())) headers[k.toLowerCase()] = v;
  const bytes = record.bodyBase64 ? Buffer.from(record.bodyBase64, "base64") : undefined;
  const body: string | Blob = bytes ? new Blob([bytes]) : record.body;
  if (values.resign) {
    const provider = values.provider ?? record.provider;
    const secret = values.secret ?? process.env["WEBHOOK_SECRET"];
    if (!isProvider(provider)) throw new Error("--resign needs a known provider (from the saved file or --provider).");
    if (!secret) throw new Error("--resign needs --secret (or WEBHOOK_SECRET).");
    const signed = await sign({ provider, secret, body: bytes ? bytes.toString("utf8") : record.body, url: values.to, contentType: headers["content-type"] });
    Object.assign(headers, signed);
    console.log(dim(`re-signed as ${provider} with a fresh timestamp`));
  }
  const method = (record.method ?? "POST").toUpperCase();
  const res = await fetch(values.to, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body });
  const text = await res.text();
  const ok = res.status >= 200 && res.status < 300;
  console.log(`${ok ? green(`✓ ${res.status}`) : red(`✗ ${res.status}`)} ${res.statusText}  ← ${values.to}`);
  if (text) console.log(dim(text.length > 500 ? `${text.slice(0, 500)}…` : text));
  return ok ? 0 : 1;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "verify":
      return cmdVerify(rest);
    case "listen":
      return cmdListen(rest);
    case "replay":
      return cmdReplay(rest);
    case "--version":
    case "-v":
      console.log(VERSION);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return cmd === undefined ? 2 : 0;
    default:
      console.error(`Unknown command "${cmd}".\n\n${HELP}`);
      return 2;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(red(`webhook-inspect: ${err instanceof Error ? err.message : String(err)}`));
    process.exitCode = 2;
  },
);
