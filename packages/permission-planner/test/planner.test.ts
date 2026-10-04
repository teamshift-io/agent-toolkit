import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CATALOG, PROVIDERS, findAction, formatCatalogMarkdown, formatPlanMarkdown, parseActions, plan, suggest } from "../src/index.js";

const fixture = (name: string): string => readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), "utf8");

describe("catalog integrity", () => {
  it("has unique action ids", () => {
    expect(new Set(CATALOG.map((e) => e.action)).size).toBe(CATALOG.length);
  });
  it("every entry has an official https source and at least one scope", () => {
    for (const e of CATALOG) {
      expect(e.source, e.action).toMatch(
        /^https:\/\/(developers\.google\.com|learn\.microsoft\.com|docs\.slack\.dev|developers\.hubspot\.com|developer\.intuit\.com|docs\.stripe\.com|shopify\.dev)\//,
      );
      expect(e.scopes.length, e.action).toBeGreaterThan(0);
    }
  });
  it("every entry is either verified (with date) or explicitly unverified, never both", () => {
    for (const e of CATALOG) {
      expect(Boolean(e.verifiedOn) !== (e.status === "unverified"), e.action).toBe(true);
      if (e.verifiedOn) expect(e.verifiedOn).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
  it("action ids are prefixed consistently per provider", () => {
    const prefixes: Record<string, RegExp> = {
      google: /^(gmail|gcal|gdrive|gsheets)\./,
      microsoft: /^(outlook|onedrive|teams|graph)\./,
      slack: /^slack\./,
      hubspot: /^hubspot\./,
      quickbooks: /^qbo\./,
      stripe: /^stripe\./,
      shopify: /^shopify\./,
    };
    for (const e of CATALOG) expect(e.action, e.action).toMatch(prefixes[e.provider] as RegExp);
  });
  it("Google scopes are full URLs; the coverage map only references known scopes", () => {
    const all = new Set(CATALOG.flatMap((e) => e.scopes));
    for (const e of CATALOG.filter((x) => x.provider === "google")) for (const s of e.scopes) expect(s).toMatch(/^https:\/\//);
    for (const p of Object.values(PROVIDERS)) {
      for (const [broad, narrow] of Object.entries(p.covers ?? {})) {
        // The full calendar scope is a documented broader scope that no catalog action needs.
        expect(all.has(broad) || broad === "https://www.googleapis.com/auth/calendar", broad).toBe(true);
        // Stripe "X: Write implies X: Read" pairs may name Read levels no action needs yet.
        if (p.id !== "stripe") for (const n of narrow) expect(all.has(n), n).toBe(true);
      }
    }
  });
  it("covers all seven providers", () => {
    expect(new Set(CATALOG.map((e) => e.provider))).toEqual(new Set(Object.keys(PROVIDERS)));
  });
});

describe("findAction()", () => {
  it.each([
    ["gmail.send", "gmail.send"],
    ["google:gmail.send", "gmail.send"],
    ["slack:post_message", "slack.post_message"],
    ["Slack: post message", "slack.post_message"],
    ["stripe:refund", "stripe.refund"],
    ["qbo:send_invoice", "qbo.send_invoice"],
    ["quickbooks:qbo.send_invoice", "qbo.send_invoice"],
  ])("resolves %s", (input, id) => {
    expect(findAction(input)?.action).toBe(id);
  });
  it("does not cross providers", () => {
    expect(findAction("slack:gmail.send")).toBeUndefined();
  });
  it("suggests close matches", () => {
    expect(suggest("gmail.sendmail")).toContain("gmail.send");
  });
});

describe("plan()", () => {
  it("dedupes scopes and drops ones covered by a broader required scope", () => {
    const p = plan(["gmail.send", "gmail.draft"]);
    const google = p.providers.find((x) => x.provider === "google");
    expect(google?.scopes.map((s) => s.scope)).toEqual(["https://www.googleapis.com/auth/gmail.compose"]);
    expect(google?.scopes[0]?.covers).toEqual(["https://www.googleapis.com/auth/gmail.send"]);
    expect(google?.scopes[0]?.neededBy.sort()).toEqual(["gmail.draft", "gmail.send"]);
  });
  it("Stripe Write drops the matching Read", () => {
    const p = plan(["stripe.read_customers", "stripe.write_customers"]);
    expect(p.providers[0]?.scopes.map((s) => s.scope)).toEqual(["Customers: Write"]);
  });
  it("keeps HubSpot read and write separately (write does not imply read)", () => {
    const p = plan(["hubspot.read_contacts", "hubspot.write_contacts"]);
    expect(p.providers[0]?.scopes.map((s) => s.scope).sort()).toEqual(["crm.objects.contacts.read", "crm.objects.contacts.write"]);
  });
  it("maps tiers to approval policies", () => {
    const p = plan(["gmail.read", "slack.post_message", "gmail.send", "stripe.refund", "hubspot.delete_contacts"]);
    const byTier = Object.fromEntries(p.approvals.map((a) => [a.tier, a.policy]));
    expect(byTier).toEqual({
      read: "auto",
      "write-internal": "auto-with-audit",
      "send-external": "approval-until-track-record",
      money: "always-approve",
      destructive: "always-approve",
    });
    expect(p.highestTier).toBe("destructive");
  });
  it("lists unknown actions explicitly and never invents scopes for them", () => {
    const p = plan(["gmail.send", "quickbooks:issue_credit_memo"]);
    expect(p.unknown).toHaveLength(1);
    expect(p.unknown[0]?.message).toMatch(/do not fall back to admin/);
    expect(p.providers.flatMap((x) => x.scopes.map((s) => s.scope))).toEqual(["https://www.googleapis.com/auth/gmail.send"]);
  });
  it("flags unverified mappings, restricted scopes and the QuickBooks all-or-nothing scope", () => {
    const p = plan(["stripe.refund", "gmail.read", "qbo.read_accounting"]);
    expect(p.warnings.some((w) => w.includes("stripe.refund") && w.includes("unverified"))).toBe(true);
    expect(p.warnings.some((w) => w.includes("restricted"))).toBe(true);
    expect(p.warnings.some((w) => w.includes("all-or-nothing"))).toBe(true);
  });
  it("warns about broader or unnecessary scopes the app currently requests", () => {
    const p = plan(["gmail.send"], { currentScopes: ["https://mail.google.com/", "chat:write"] });
    expect(p.warnings).toContain(
      "Currently requested https://mail.google.com/ is broader than needed; https://www.googleapis.com/auth/gmail.send is enough.",
    );
    expect(p.warnings).toContain("Currently requested chat:write is not needed by any planned action. Remove it.");
  });
  it("ignores duplicate actions", () => {
    expect(plan(["gmail.send", "google:gmail.send"]).actions).toHaveLength(1);
  });
});

describe("parseActions() and formatting", () => {
  it("parses the fixture with objects, provider:action strings and currentScopes", () => {
    const parsed = parseActions(fixture("ar-agent.yaml"));
    expect(parsed.actions).toHaveLength(9);
    expect(parsed.actions[0]).toEqual({ input: "gmail.read", why: "Find customer replies about open invoices" });
    expect(parsed.currentScopes).toEqual(["https://mail.google.com/"]);
    const p = plan(parsed.actions, { currentScopes: parsed.currentScopes });
    expect(p.unknown.map((u) => u.input)).toEqual(["quickbooks:issue_credit_memo"]);
  });
  it("parses comma lists and plain YAML lists", () => {
    expect(parseActions("gmail.send,slack.post_message").actions).toHaveLength(2);
    expect(parseActions("- gmail.send\n- { action: refund, provider: stripe }").actions.map((a) => a.input)).toEqual(["gmail.send", "stripe:refund"]);
    expect(() => parseActions("{}")).toThrow(/No actions/);
  });
  it("never silently drops malformed items", () => {
    const parsed = parseActions(['- "Slack: post message"', "- Slack: post message", "- { provider: slack }"].join("\n"));
    expect(parsed.actions.map((a) => a.input)).toEqual(["Slack: post message", "Slack:post message", '{"provider":"slack"}']);
    const p = plan(parsed.actions);
    expect(p.actions.map((a) => a.action)).toEqual(["slack.post_message"]);
    expect(p.unknown.map((u) => u.input)).toEqual(['{"provider":"slack"}']);
  });
  it("renders markdown with every section", () => {
    const md = formatPlanMarkdown(plan(["gmail.send", "stripe.refund", "nope.nope"]));
    for (const h of ["# Permission plan", "## Actions", "## Approval policy", "## Warnings", "## Unknown actions"]) expect(md).toContain(h);
    expect(formatCatalogMarkdown(CATALOG).split("\n")).toHaveLength(CATALOG.length + 2);
  });
});
