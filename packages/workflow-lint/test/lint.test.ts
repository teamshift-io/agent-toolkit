import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findSecrets, formatJson, formatPretty, formatSarif, lint, RULE_LIST, WorkflowParseError } from "../src/index.js";

const fixture = (name: string): string => readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), "utf8");
const ids = (text: string, filename = "w.yaml"): string[] => lint(text, { filename }).findings.map((f) => f.ruleId);

/** Minimal generic spec builder for focused rule tests. */
const spec = (steps: string, extra = ""): string => `name: t\n${extra}steps:\n${steps}`;

describe("fixtures", () => {
  it("generic-good.yaml is clean", () => {
    const r = lint(fixture("generic-good.yaml"), { filename: "generic-good.yaml" });
    expect(r.findings).toEqual([]);
    expect(r.format).toBe("generic");
  });

  it("n8n-good.json is clean", () => {
    const r = lint(fixture("n8n-good.json"), { filename: "n8n-good.json" });
    expect(r.findings).toEqual([]);
    expect(r.format).toBe("n8n");
  });

  it("generic-bad.yaml triggers every rule", () => {
    const found = new Set(ids(fixture("generic-bad.yaml")));
    for (const rule of RULE_LIST) expect(found, rule.id).toContain(rule.id);
  });

  it("n8n-bad.json triggers every rule", () => {
    const found = new Set(ids(fixture("n8n-bad.json"), "n8n-bad.json"));
    for (const rule of RULE_LIST) expect(found, rule.id).toContain(rule.id);
  });

  it("locates findings on a source line", () => {
    const r = lint(fixture("n8n-bad.json"), { filename: "n8n-bad.json" });
    const email = r.findings.find((f) => f.stepId === "Email Customer");
    expect(email?.line).toBeGreaterThan(1);
  });
});

describe("WL001 missing-error-handling", () => {
  it("flags side-effect steps with no onError", () => {
    expect(ids(spec("  - { id: a, action: crm.update, completionCheck: x }"))).toContain("WL001");
  });
  it("flags swallowed errors", () => {
    const r = lint(spec("  - { id: a, action: crm.update, onError: continue, completionCheck: x }"));
    expect(r.findings.find((f) => f.ruleId === "WL001")?.message).toMatch(/silently/);
  });
  it("accepts explicit handling and ignores read-only steps", () => {
    expect(ids(spec("  - { id: a, action: crm.update, onError: alert, completionCheck: x }"))).not.toContain("WL001");
    expect(ids(spec("  - { id: a, action: crm.get }"))).not.toContain("WL001");
  });
  it("n8n: workflow error workflow counts as handling; continueOnFail does not", () => {
    const wf = (node: object, settings: object = {}): string =>
      JSON.stringify({ nodes: [{ name: "S", type: "n8n-nodes-base.slack", parameters: {}, ...node }], connections: {}, settings });
    expect(ids(wf({}), "x.json")).toContain("WL001");
    expect(ids(wf({}, { errorWorkflow: "e1" }), "x.json")).not.toContain("WL001");
    expect(ids(wf({ continueOnFail: true }), "x.json")).toContain("WL001");
    expect(ids(wf({ onError: "continueErrorOutput" }), "x.json")).not.toContain("WL001");
  });
});

describe("WL002 unsafe-retry", () => {
  it("flags retried writes without an idempotency key", () => {
    expect(ids(spec("  - { id: a, action: crm.create, onError: stop, retry: 3 }"))).toContain("WL002");
  });
  it("accepts an idempotency key, single attempts and read retries", () => {
    expect(ids(spec("  - { id: a, action: crm.create, onError: stop, retry: 3, idempotencyKey: k }"))).not.toContain("WL002");
    expect(ids(spec("  - { id: a, action: crm.create, onError: stop, retry: 1 }"))).not.toContain("WL002");
    expect(ids(spec("  - { id: a, action: crm.get, retry: 5 }"))).not.toContain("WL002");
  });
  it("n8n: Idempotency-Key header satisfies the rule", () => {
    const wf = (headers: object[]): string =>
      JSON.stringify({
        nodes: [
          {
            name: "Post",
            type: "n8n-nodes-base.httpRequest",
            retryOnFail: true,
            onError: "continueErrorOutput",
            parameters: { method: "POST", url: "https://api.crm.example/x", headerParameters: { parameters: headers }, options: { timeout: 5000 } },
          },
        ],
        connections: {},
      });
    expect(ids(wf([]), "x.json")).toContain("WL002");
    expect(ids(wf([{ name: "Idempotency-Key", value: "={{ $json.id }}" }]), "x.json")).not.toContain("WL002");
  });
});

describe("WL003 missing-timeout", () => {
  it("flags http, llm and open-ended waits without timeoutSec", () => {
    expect(ids(spec("  - { id: a, action: http.get }"))).toContain("WL003");
    expect(ids(spec("  - { id: a, action: llm.generate }"))).toContain("WL003");
    expect(ids(spec("  - { id: a, action: wait.for_reply }"))).toContain("WL003");
  });
  it("accepts timeouts and fixed-duration delays", () => {
    expect(ids(spec("  - { id: a, action: http.get, timeoutSec: 10 }"))).not.toContain("WL003");
    expect(ids(spec("  - { id: a, action: wait.delay, durationSec: 60 }"))).not.toContain("WL003");
  });
  it("n8n: Wait-for-webhook without Limit Wait Time is flagged", () => {
    const wf = (params: object): string =>
      JSON.stringify({ nodes: [{ name: "W", type: "n8n-nodes-base.wait", parameters: params }], connections: {} });
    expect(ids(wf({ resume: "webhook" }), "x.json")).toContain("WL003");
    expect(ids(wf({ resume: "webhook", limitWaitTime: true }), "x.json")).not.toContain("WL003");
    expect(ids(wf({ amount: 5 }), "x.json")).not.toContain("WL003");
  });
});

describe("WL004 unapproved-high-risk-action", () => {
  it("flags money, delete and external sends without approval", () => {
    expect(ids(spec("  - { id: a, action: stripe.refund, onError: stop, timeoutSec: 5 }"))).toContain("WL004");
    expect(ids(spec("  - { id: a, action: crm.delete, onError: stop }"))).toContain("WL004");
    expect(ids(spec("  - { id: a, action: email.send, onError: stop, timeoutSec: 5 }"))).toContain("WL004");
  });
  it("does not require approval for internal messages", () => {
    expect(ids(spec("  - { id: a, action: slack.post, onError: stop, timeoutSec: 5 }"))).not.toContain("WL004");
    expect(ids(spec("  - { id: a, action: email.send, audience: internal, onError: stop, timeoutSec: 5 }"))).not.toContain("WL004");
  });
  it("accepts step-level approval or a preceding approval step", () => {
    expect(ids(spec("  - { id: a, action: stripe.refund, approval: true, onError: stop }"))).not.toContain("WL004");
    expect(ids(spec("  - { id: ok, action: approval.request }\n  - { id: a, action: stripe.refund, onError: stop }"))).not.toContain("WL004");
    expect(ids(spec("  - { id: a, action: stripe.refund, approval: { required: false }, onError: stop }"))).toContain("WL004");
  });
});

describe("WL005 no-completion-check", () => {
  it("flags side-effect workflows without a completion check", () => {
    expect(ids(spec("  - { id: a, action: crm.update, onError: stop }"))).toContain("WL005");
  });
  it("accepts workflow-level, step-level or verify steps", () => {
    expect(ids(spec("  - { id: a, action: crm.update, onError: stop }", "completionCheck: row exists\n"))).not.toContain("WL005");
    expect(ids(spec("  - { id: a, action: crm.update, onError: stop }\n  - { id: v, action: verify.row }"))).not.toContain("WL005");
  });
  it("does not apply to read-only workflows", () => {
    expect(ids(spec("  - { id: a, action: crm.get }"))).not.toContain("WL005");
  });
});

describe("WL006 hardcoded-secret", () => {
  // Built at runtime so this repository never contains a string that looks like a live key.
  const stripeKey = ["sk", "live", "A1b2C3d4E5f6G7h8I9j0K1l2"].join("_");
  const awsKey = "AKIA" + "ABCDEFGHIJKLMNOP";
  const slack = ["xoxb", "1234567890", "abcdefABCDEF"].join("-");
  it.each([
    ["Stripe", stripeKey],
    ["AWS", awsKey],
    ["Slack", slack],
    ["private key", "-----BEGIN RSA PRIVATE KEY-----"],
  ])("detects %s credentials", (_name, secret) => {
    expect(findSecrets({ header: `x ${secret} y` }, "p").length).toBe(1);
  });
  it("detects literal values in secret-named keys", () => {
    expect(ids(spec("  - { id: a, action: http.get, timeoutSec: 5, params: { api_key: abcdef0123456789xyz } }"))).toContain("WL006");
  });
  it("ignores references, expressions and env lookups", () => {
    for (const v of ['"{{ $env.KEY }}"', '"=Bearer {{ $json.t }}"', '"${STRIPE_KEY}"', '"<your-key>"']) {
      expect(ids(spec(`  - { id: a, action: http.get, timeoutSec: 5, params: { apiKey: ${v} } }`))).not.toContain("WL006");
    }
  });
  it("redacts the secret in the message", () => {
    const text = spec(`  - { id: a, action: http.get, timeoutSec: 5, params: { auth: "${stripeKey}" } }`);
    const f = lint(text).findings.find((x) => x.ruleId === "WL006");
    expect(f?.message).not.toContain(stripeKey);
  });
  it("scans workflow-level env", () => {
    expect(ids(spec("  - { id: a, action: crm.get }", "env:\n  SLACK_TOKEN: abcdefghijklmnop1234\n"))).toContain("WL006");
  });
});

describe("WL007 unbounded-loop", () => {
  it("flags loops without a limit", () => {
    expect(ids(spec("  - { id: a, action: loop.over_contacts }"))).toContain("WL007");
    expect(ids(spec("  - { id: a, action: http.get, timeoutSec: 5, paginate: { cursor: next } }"))).toContain("WL007");
  });
  it("accepts limits", () => {
    expect(ids(spec("  - { id: a, action: loop.over_contacts, loop: { limit: 500 } }"))).not.toContain("WL007");
    expect(ids(spec("  - { id: a, action: http.get, timeoutSec: 5, paginate: { maxPages: 10 } }"))).not.toContain("WL007");
  });
  it("n8n: a self-wired cycle without Split In Batches is flagged", () => {
    const wf = JSON.stringify({
      nodes: [
        { name: "Poll", type: "n8n-nodes-base.httpRequest", parameters: { url: "https://x.example", options: { timeout: 1000 } } },
        { name: "Done?", type: "n8n-nodes-base.if", parameters: {} },
      ],
      connections: {
        Poll: { main: [[{ node: "Done?", type: "main", index: 0 }]] },
        "Done?": { main: [[], [{ node: "Poll", type: "main", index: 0 }]] },
      },
    });
    const f = lint(wf, { filename: "x.json" }).findings.find((x) => x.ruleId === "WL007");
    expect(f?.message).toMatch(/cycle/);
  });
});

describe("WL008 unverified-webhook", () => {
  it("flags webhook triggers without signature verification", () => {
    expect(ids(spec("  - { id: a, action: crm.get }", "trigger: { type: webhook }\n"))).toContain("WL008");
    expect(ids(spec("  - { id: a, action: crm.get }", "trigger: { type: webhook, verifySignature: false }\n"))).toContain("WL008");
  });
  it("accepts verification and ignores non-webhook triggers", () => {
    expect(ids(spec("  - { id: a, action: crm.get }", "trigger: { type: webhook, verifySignature: true }\n"))).not.toContain("WL008");
    expect(ids(spec("  - { id: a, action: crm.get }", "trigger: { type: schedule }\n"))).not.toContain("WL008");
  });
  it("n8n: Webhook authentication or a downstream HMAC node satisfies the rule", () => {
    const hook = (params: object, extra: object[] = [], connections: object = {}): string =>
      JSON.stringify({ nodes: [{ name: "Hook", type: "n8n-nodes-base.webhook", parameters: params }, ...extra], connections });
    expect(ids(hook({}), "x.json")).toContain("WL008");
    expect(ids(hook({ authentication: "headerAuth" }), "x.json")).not.toContain("WL008");
    const crypto = [{ name: "HMAC", type: "n8n-nodes-base.crypto", parameters: { action: "hmac" } }];
    expect(ids(hook({}, crypto, { Hook: { main: [[{ node: "HMAC", type: "main", index: 0 }]] } }), "x.json")).not.toContain("WL008");
  });
});

describe("WL009 pii-to-llm-without-note", () => {
  it("flags PII references flowing into LLM steps", () => {
    const r = lint(spec('  - { id: a, action: llm.generate, timeoutSec: 5, params: { prompt: "Reply to {{ contact.phoneNumber }}" } }'));
    expect(r.findings.find((f) => f.ruleId === "WL009")?.message).toMatch(/phoneNumber/);
  });
  it("accepts a piiNote and ignores non-PII inputs", () => {
    expect(ids(spec('  - { id: a, action: llm.generate, timeoutSec: 5, piiNote: redacted upstream, params: { p: "{{ c.email }}" } }'))).not.toContain("WL009");
    expect(ids(spec('  - { id: a, action: llm.generate, timeoutSec: 5, params: { p: "Write an email about {{ order.total }}" } }'))).not.toContain("WL009");
  });
  it("supports an explicit pii list", () => {
    expect(ids(spec("  - { id: a, action: llm.classify, timeoutSec: 5, pii: [address] }"))).toContain("WL009");
  });
});

describe("parsing, options and output", () => {
  it("rejects unknown formats with a clear error", () => {
    expect(() => lint("{\"foo\": 1}")).toThrow(WorkflowParseError);
    expect(() => lint("")).toThrow(/empty/);
  });
  it("honors --ignore by id or name and lint.ignore in the spec", () => {
    const text = spec("  - { id: a, action: crm.update, onError: stop }");
    expect(ids(text)).toContain("WL005");
    expect(lint(text, { ignore: ["WL005"] }).findings).toEqual([]);
    expect(lint(text, { ignore: ["no-completion-check"] }).findings).toEqual([]);
    expect(lint(`lint: { ignore: [WL005] }\n${text}`).findings).toEqual([]);
  });
  it("produces valid SARIF and JSON", () => {
    const r = lint(fixture("generic-bad.yaml"), { filename: "generic-bad.yaml" });
    const sarif = JSON.parse(formatSarif([r]));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(RULE_LIST.length);
    expect(sarif.runs[0].results.length).toBe(r.findings.length);
    expect(JSON.parse(formatJson([r])).summary.errors).toBe(r.summary.errors);
  });
  it("pretty output summarizes problems without ANSI when color is off", () => {
    const out = formatPretty([lint(fixture("generic-bad.yaml"), { filename: "generic-bad.yaml" })]);
    expect(out).toMatch(/problems \(\d+ errors, \d+ warnings\)/);
    expect(out).not.toContain("\u001b[");
  });
  it("every rule has docs, fix and a unique id", () => {
    expect(new Set(RULE_LIST.map((r) => r.id)).size).toBe(RULE_LIST.length);
    for (const r of RULE_LIST) {
      expect(r.docs).toContain(`#${r.id.toLowerCase()}-${r.name}`);
      expect(r.fix.length).toBeGreaterThan(10);
    }
  });
});

describe("review hardening", () => {
  it("treats writes on money resources as money (WL004)", () => {
    for (const a of ["stripe.refunds.create", "stripe.payment_intents.create", "stripe.payouts.create"]) {
      expect(ids(spec(`  - { id: a, action: ${a}, onError: stop, timeoutSec: 5 }`)), a).toContain("WL004");
    }
    expect(ids(spec("  - { id: a, action: stripe.customers.create, onError: stop, timeoutSec: 5 }"))).not.toContain("WL004");
    expect(ids(spec("  - { id: a, action: drive.trash, onError: stop }"))).toContain("WL004");
  });
  it("onError none/false/off is not handling; continue variants are swallowing; objects are handling", () => {
    for (const v of ["none", "false", "off"]) {
      const f = lint(spec(`  - { id: a, action: crm.update, onError: ${v}, completionCheck: x }`)).findings.find((x) => x.ruleId === "WL001");
      expect(f?.message, v).toMatch(/no error handling/);
    }
    expect(lint(spec("  - { id: a, action: crm.update, onError: continueOnFail, completionCheck: x }")).findings[0]?.message).toMatch(/silently/);
    expect(ids(spec("  - { id: a, action: crm.update, onError: { fallback: b }, completionCheck: x }"))).not.toContain("WL001");
  });
  it("recognizes retry: true, retries and maxRetries (WL002)", () => {
    for (const r of ["retry: true", "retries: 2", "maxRetries: 3", "retry: { max: 4 }"]) {
      expect(ids(spec(`  - { id: a, action: crm.create, onError: stop, ${r}, completionCheck: x }`)), r).toContain("WL002");
    }
  });
  it("requires a timeout on generic approval steps (WL003)", () => {
    expect(ids(spec("  - { id: a, action: approval.request }"))).toContain("WL003");
  });
  it("an empty or false completionCheck does not count (WL005)", () => {
    expect(ids(spec("  - { id: a, action: crm.update, onError: stop }", "completionCheck:\n"))).toContain("WL005");
    expect(ids(spec("  - { id: a, action: crm.update, onError: stop, completionCheck: false }"))).toContain("WL005");
  });
  it("finds secret_key/access_key literals and Basic auth (WL006)", () => {
    expect(findSecrets({ aws_secret_access_key: "abcdefghijklmnop1234" }, "p")).toHaveLength(1);
    expect(findSecrets({ secretKey: "abcdefghijklmnop1234" }, "p")).toHaveLength(1);
    expect(findSecrets({ Authorization: "Basic dXNlcjpwYXNzd29yZDEyMzQ1Njc4" }, "p")).toHaveLength(1);
    expect(findSecrets({ Authorization: "Basic {{ $env.CREDS }}" }, "p")).toHaveLength(0);
  });
  it("n8n: a Set/NoOp or a side-effect 'confirmation' node is not a completion check (WL005)", () => {
    const wf = (second: { name?: string; [k: string]: unknown }): string =>
      JSON.stringify({
        nodes: [
          { name: "Update", type: "n8n-nodes-base.hubspot", parameters: { operation: "update" }, onError: "continueErrorOutput" },
          { name: "Next", ...second },
        ],
        connections: { Update: { main: [[{ node: second.name ?? "Next", type: "main", index: 0 }]] } },
      });
    expect(ids(wf({ type: "n8n-nodes-base.set", parameters: {} }), "x.json")).toContain("WL005");
    expect(ids(wf({ name: "Send confirmation", type: "n8n-nodes-base.slack", parameters: {}, onError: "continueErrorOutput" }), "x.json")).toContain("WL005");
    expect(ids(wf({ type: "n8n-nodes-base.hubspot", parameters: { operation: "get" } }), "x.json")).not.toContain("WL005");
  });
});
