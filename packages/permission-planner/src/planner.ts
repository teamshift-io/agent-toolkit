import { parse as parseYaml } from "yaml";
import { CATALOG, PROVIDERS, type CatalogEntry, type ProviderId, type RiskTier } from "./data/catalog.js";

export const TIER_ORDER: readonly RiskTier[] = ["read", "write-internal", "send-external", "money", "destructive"];

export interface ApprovalPolicy {
  tier: RiskTier;
  policy: "auto" | "auto-with-audit" | "approval-until-track-record" | "always-approve";
  summary: string;
}

export const APPROVAL_POLICIES: Record<RiskTier, ApprovalPolicy> = {
  read: { tier: "read", policy: "auto", summary: "No approval. Log what was accessed." },
  "write-internal": {
    tier: "write-internal",
    policy: "auto-with-audit",
    summary: "Run automatically with an audit log and an easy undo; spot-check a sample weekly.",
  },
  "send-external": {
    tier: "send-external",
    policy: "approval-until-track-record",
    summary: "Human approves each send until the agent has a clean track record (e.g. 25 consecutive approvals with no edits), then switch to spot checks. Keep approval for new templates and new recipient types.",
  },
  money: { tier: "money", policy: "always-approve", summary: "Always require explicit human approval, with amount and counterparty shown. Never auto-approve." },
  destructive: { tier: "destructive", policy: "always-approve", summary: "Always require explicit human approval. Prefer soft-delete/archive where the provider offers it." },
};

export interface ActionRequest {
  /** Raw input, e.g. `gmail.send` or `google:gmail.send`. */
  input: string;
  /** Free-text reason (optional, echoed in reports). */
  why?: string;
}

export interface PlannedAction {
  input: string;
  action: string;
  provider: ProviderId;
  label: string;
  tier: RiskTier;
  scopes: string[];
  sensitivity?: string;
  approval: ApprovalPolicy["policy"];
  verified: boolean;
  source: string;
  notes?: string;
  why?: string;
}

export interface PlannedScope {
  scope: string;
  sensitivity?: string;
  neededBy: string[];
  /** Narrower scopes dropped because this one already grants them. */
  covers: string[];
}

export interface ProviderPlan {
  provider: ProviderId;
  name: string;
  scopeKind: string;
  scopes: PlannedScope[];
  notes: string[];
}

export interface UnknownAction {
  input: string;
  suggestions: string[];
  message: string;
}

export interface Plan {
  actions: PlannedAction[];
  providers: ProviderPlan[];
  approvals: Array<ApprovalPolicy & { actions: string[] }>;
  warnings: string[];
  unknown: UnknownAction[];
  highestTier?: RiskTier;
}

export interface PlanOptions {
  /** Scopes the app currently requests, per provider or flat. Extra/broader ones produce warnings. */
  currentScopes?: string[];
  catalog?: readonly CatalogEntry[];
}

const PROVIDER_ALIASES: Record<string, ProviderId> = {
  google: "google",
  gmail: "google",
  gcal: "google",
  gdrive: "google",
  gsheets: "google",
  workspace: "google",
  microsoft: "microsoft",
  ms: "microsoft",
  graph: "microsoft",
  outlook: "microsoft",
  onedrive: "microsoft",
  teams: "microsoft",
  m365: "microsoft",
  slack: "slack",
  hubspot: "hubspot",
  quickbooks: "quickbooks",
  qbo: "quickbooks",
  intuit: "quickbooks",
  stripe: "stripe",
  shopify: "shopify",
};

export function resolveProvider(name: string): ProviderId | undefined {
  return PROVIDER_ALIASES[name.trim().toLowerCase()];
}

/** Find a catalog entry for `gmail.send`, `google:gmail.send`, `slack:post_message`, `Slack: post message`, ... */
export function findAction(input: string, catalog: readonly CatalogEntry[] = CATALOG): CatalogEntry | undefined {
  const raw = input.trim().toLowerCase().replace(/\s+/g, "_");
  const byId = catalog.find((e) => e.action === raw);
  if (byId) return byId;
  const m = /^([a-z0-9]+):_?(.+)$/.exec(raw);
  if (!m) return undefined;
  const [, prov = "", rest = ""] = m;
  const provider = resolveProvider(prov);
  const candidates = [rest, `${prov}.${rest}`];
  return catalog.find((e) => (provider === undefined || e.provider === provider) && candidates.includes(e.action));
}

function distance(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0] as number;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j] as number;
      dp[j] = Math.min((dp[j] as number) + 1, (dp[j - 1] as number) + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length] as number;
}

export function suggest(input: string, catalog: readonly CatalogEntry[] = CATALOG): string[] {
  const prefix = /^([a-z0-9]+):/.exec(input.trim().toLowerCase())?.[1];
  const provider = prefix ? resolveProvider(prefix) : undefined;
  const pool = provider ? catalog.filter((e) => e.provider === provider) : catalog;
  const q = input.trim().toLowerCase().replace(/^[a-z0-9]+:/, "").replace(/\s+/g, "_");
  const words = q.split(/[._:-]/).filter((w) => w.length > 2);
  return pool
    .map((e) => {
      const overlap = words.filter((w) => e.action.includes(w)).length;
      return { id: e.action, score: distance(q, e.action) - overlap * 4 };
    })
    .sort((a, b) => a.score - b.score)
    .slice(0, 3)
    .map((x) => x.id);
}

/** Accepts a YAML/JSON document: a list of strings/objects, or `{ actions: [...], currentScopes?: [...] }`. */
export function parseActions(text: string): { actions: ActionRequest[]; currentScopes?: string[] } {
  const doc: unknown = parseYaml(text);
  const toReq = (item: unknown): ActionRequest | undefined => {
    if (typeof item === "string") return { input: item };
    if (typeof item === "number" || typeof item === "boolean") return { input: String(item) };
    if (item && typeof item === "object") {
      const o = item as Record<string, unknown>;
      const action = typeof o["action"] === "string" ? o["action"] : undefined;
      const provider = typeof o["provider"] === "string" ? o["provider"] : undefined;
      if (!action) {
        // `- Slack: post message` parses as { Slack: "post message" }; anything else unrecognized is reported, never dropped.
        const entries = Object.entries(o);
        const only = entries.length === 1 ? entries[0] : undefined;
        if (only && typeof only[1] === "string" && !["provider", "why"].includes(only[0])) return { input: `${only[0]}:${only[1]}` };
        return { input: JSON.stringify(item) };
      }
      return { input: provider && !action.includes(":") && !findAction(action) ? `${provider}:${action}` : action, why: typeof o["why"] === "string" ? o["why"] : undefined };
    }
    return undefined;
  };
  let list: unknown[] = [];
  let currentScopes: string[] | undefined;
  if (Array.isArray(doc)) list = doc;
  else if (doc && typeof doc === "object") {
    const o = doc as Record<string, unknown>;
    if (Array.isArray(o["actions"])) list = o["actions"] as unknown[];
    if (Array.isArray(o["currentScopes"])) currentScopes = (o["currentScopes"] as unknown[]).filter((s): s is string => typeof s === "string");
  } else if (typeof doc === "string") list = doc.split(/[,\s]+/).filter(Boolean);
  const actions = list.map(toReq).filter((x): x is ActionRequest => !!x);
  if (actions.length === 0) throw new Error("No actions found. Provide a list like `- gmail.send` or `actions: [gmail.send, slack:post_message]`.");
  return { actions, currentScopes };
}

const maxTier = (tiers: RiskTier[]): RiskTier | undefined =>
  tiers.reduce<RiskTier | undefined>((m, t) => (m === undefined || TIER_ORDER.indexOf(t) > TIER_ORDER.indexOf(m) ? t : m), undefined);

/** Turn intended agent actions into minimum scopes, risk tiers and an approval policy. Pure and browser-safe. */
export function plan(requests: Array<string | ActionRequest>, options: PlanOptions = {}): Plan {
  const catalog = options.catalog ?? CATALOG;
  const reqs = requests.map((r) => (typeof r === "string" ? { input: r } : r));
  const actions: PlannedAction[] = [];
  const unknown: UnknownAction[] = [];
  const seen = new Set<string>();

  for (const r of reqs) {
    const e = findAction(r.input, catalog);
    if (!e) {
      unknown.push({
        input: r.input,
        suggestions: suggest(r.input, catalog),
        message:
          "Not in the catalog. Look up the minimum scope in the provider's docs; do not fall back to admin or full-access scopes just because the minimum is undocumented here.",
      });
      continue;
    }
    if (seen.has(e.action)) continue;
    seen.add(e.action);
    actions.push({
      input: r.input,
      action: e.action,
      provider: e.provider,
      label: e.label,
      tier: e.tier,
      scopes: e.scopes,
      sensitivity: e.sensitivity,
      approval: APPROVAL_POLICIES[e.tier].policy,
      verified: e.verifiedOn !== undefined && e.status !== "unverified",
      source: e.source,
      notes: e.notes,
      why: r.why,
    });
  }

  const providers: ProviderPlan[] = [];
  const warnings: string[] = [];
  const byProvider = new Map<ProviderId, PlannedAction[]>();
  for (const a of actions) byProvider.set(a.provider, [...(byProvider.get(a.provider) ?? []), a]);

  for (const [pid, acts] of byProvider) {
    const info = PROVIDERS[pid];
    const covers = info.covers ?? {};
    const needed = new Map<string, PlannedScope>();
    for (const a of acts) {
      for (const s of a.scopes) {
        const existing = needed.get(s);
        if (existing) existing.neededBy.push(a.action);
        else needed.set(s, { scope: s, sensitivity: a.sensitivity, neededBy: [a.action], covers: [] });
      }
    }
    // Drop scopes already granted by a broader scope that is required anyway.
    for (const [broad, narrower] of Object.entries(covers)) {
      const keeper = needed.get(broad);
      if (!keeper) continue;
      for (const n of narrower) {
        const dropped = needed.get(n);
        if (!dropped) continue;
        keeper.covers.push(n);
        keeper.neededBy.push(...dropped.neededBy.filter((x) => !keeper.neededBy.includes(x)));
        needed.delete(n);
      }
    }
    providers.push({ provider: pid, name: info.name, scopeKind: info.scopeKind, scopes: [...needed.values()], notes: info.notes ?? [] });

    for (const s of needed.values()) {
      if (s.sensitivity === "restricted") warnings.push(`${s.scope} is a Google restricted scope (needed by ${s.neededBy.join(", ")}). Check whether a narrower action covers the use case.`);
      if (s.covers.length > 0) warnings.push(`${s.scope} is broader than ${s.covers.join(", ")}; it was kept because ${s.neededBy.join(", ")} need(s) it.`);
    }
    if (pid === "quickbooks") warnings.push("QuickBooks: com.intuit.quickbooks.accounting is all-or-nothing read/write. Enforce read-only and approval rules inside the agent.");
  }

  for (const a of actions) if (!a.verified) warnings.push(`${a.action}: scope mapping is unverified. Confirm it against ${a.source} before shipping.`);

  if (options.currentScopes?.length) {
    const required = new Set(providers.flatMap((p) => p.scopes.map((s) => s.scope)));
    const allCovers = Object.values(PROVIDERS).flatMap((p) => Object.entries(p.covers ?? {}));
    for (const cur of options.currentScopes) {
      if (required.has(cur)) continue;
      const broaderThan = allCovers.find(([broad, narrower]) => broad === cur && narrower.some((n) => required.has(n)));
      const enough = broaderThan?.[1].filter((n) => required.has(n)) ?? [];
      warnings.push(
        broaderThan
          ? `Currently requested ${cur} is broader than needed; ${enough.join(" + ")} ${enough.length > 1 ? "are" : "is"} enough.`
          : `Currently requested ${cur} is not needed by any planned action. Remove it.`,
      );
    }
  }

  const approvals = TIER_ORDER.map((tier) => ({ ...APPROVAL_POLICIES[tier], actions: actions.filter((a) => a.tier === tier).map((a) => a.action) })).filter(
    (x) => x.actions.length > 0,
  );

  return { actions, providers, approvals, warnings, unknown, highestTier: maxTier(actions.map((a) => a.tier)) };
}
