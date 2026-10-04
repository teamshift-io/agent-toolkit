import { PII_NOTE, piiIdentifiers, piiRefsIn } from "./pii.js";
import type { NormalizedStep, NormalizedWorkflow, SideEffect, StepKind } from "./types.js";

type Obj = Record<string, unknown>;

const SIDE_EFFECTS: readonly SideEffect[] = ["none", "write", "send", "money", "delete"];

const KIND_BY_PREFIX: Record<string, StepKind> = {
  trigger: "trigger",
  webhook: "trigger",
  schedule: "trigger",
  http: "http",
  api: "http",
  rest: "http",
  graphql: "http",
  email: "email",
  mail: "email",
  gmail: "email",
  outlook: "email",
  sms: "email",
  slack: "message",
  teams: "message",
  chat: "message",
  message: "message",
  llm: "llm",
  ai: "llm",
  agent: "llm",
  openai: "llm",
  anthropic: "llm",
  gemini: "llm",
  wait: "wait",
  delay: "wait",
  sleep: "wait",
  loop: "loop",
  foreach: "loop",
  paginate: "loop",
  code: "code",
  script: "code",
  transform: "code",
  payment: "payment",
  stripe: "payment",
  invoice: "payment",
  refund: "payment",
  db: "data",
  sheet: "data",
  sheets: "data",
  crm: "data",
  file: "data",
  if: "control",
  switch: "control",
  branch: "control",
  approval: "approval",
  human: "approval",
  review: "approval",
  verify: "verify",
  check: "verify",
  assert: "verify",
};

const KINDS = new Set<StepKind>([
  "trigger", "http", "email", "message", "llm", "wait", "loop", "code", "payment", "data", "control", "approval", "verify", "other",
]);

function asObj(v: unknown): Obj | undefined {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function inferKind(action: string): StepKind {
  const prefix = action.toLowerCase().split(/[.:/]/)[0] ?? "";
  return KIND_BY_PREFIX[prefix] ?? "other";
}

const MONEY_WORD = /^(charges?|refunds?|pay|payments?|payment_intents?|payouts?|transfers?|captures?|purchases?|withdraw|withdrawals?)$/;

export function inferSideEffect(action: string): SideEffect {
  const segments = action.toLowerCase().split(/[.:/]/);
  const verb = segments.pop() ?? "";
  if (/^(charge|refund|pay|payout|transfer|capture|purchase|withdraw)/.test(verb)) return "money";
  if (/^(delete|remove|purge|destroy|cancel|void|trash|drop|truncate|erase|revoke|terminate|archive_permanently)/.test(verb)) return "delete";
  // `stripe.refunds.create`, `stripe.payment_intents.create`: a write on a money resource moves money.
  if (/^(create|confirm|post|send|execute|submit)/.test(verb) && segments.slice(1).some((seg) => MONEY_WORD.test(seg))) return "money";
  if (/^(send|reply|post|notify|publish|forward|sms|email|call)/.test(verb)) return "send";
  if (/^(create|update|upsert|write|append|insert|set|add|patch|put|move|label|tag)/.test(verb)) return "write";
  return "none";
}

/** A completion check counts only when it says something (`null`, `false`, `""` and `{}` do not). */
function declared(v: unknown): boolean {
  if (v === undefined || v === null || v === false) return false;
  if (typeof v === "string") return v.trim().length > 0;
  if (typeof v === "object") return Object.keys(v as object).length > 0;
  return true;
}

function parseOnError(v: unknown): NormalizedStep["errorHandling"] {
  if (v === undefined || v === null || v === false) return "none";
  if (typeof v === "object") return Object.keys(v as object).length > 0 ? "handled" : "none";
  const s = String(v).trim().toLowerCase();
  if (!s || /^(none|false|off|no|null)$/.test(s)) return "none";
  if (/^(continue|ignore|skip|swallow)/.test(s) || /continueonfail|continue_on_error/.test(s)) return "swallowed";
  return "handled";
}

/** Max attempts from `retry: 3`, `retry: true`, `retry: { maxAttempts | attempts | max | count }`, `retries`, `maxRetries`. */
function parseRetry(o: Obj): number | undefined {
  const r = o["retry"];
  if (r === true) return 3;
  const fromObj = asObj(r);
  const n =
    num(r) ??
    num(fromObj?.["maxAttempts"]) ??
    num(fromObj?.["attempts"]) ??
    num(fromObj?.["max"]) ??
    num(fromObj?.["count"]) ??
    (num(o["retries"]) !== undefined ? (num(o["retries"]) as number) + 1 : undefined) ??
    (num(o["maxRetries"]) !== undefined ? (num(o["maxRetries"]) as number) + 1 : undefined);
  if (n === undefined && fromObj && Object.keys(fromObj).length > 0) return 3;
  return n;
}

function approvalGiven(v: unknown): boolean {
  if (v === true) return true;
  if (typeof v === "string") return v.trim().length > 0 && !/^(none|false|no)$/i.test(v.trim());
  const o = asObj(v);
  if (o) return o["required"] !== false;
  return false;
}

function loopLimit(o: Obj | undefined): number | undefined {
  if (!o) return undefined;
  for (const k of ["limit", "maxIterations", "maxPages", "maxItems", "max"]) {
    const n = num(o[k]);
    if (n !== undefined && n > 0) return n;
  }
  return undefined;
}

function parseStep(raw: unknown, index: number, approvedSoFar: boolean): NormalizedStep {
  const o = asObj(raw) ?? {};
  const action = str(o["action"]) ?? str(o["type"]) ?? "unknown";
  const id = str(o["id"]) ?? str(o["name"]) ?? `step-${index + 1}`;
  const explicitKind = str(o["kind"]) as StepKind | undefined;
  const kind: StepKind = explicitKind && KINDS.has(explicitKind) ? explicitKind : inferKind(action);
  const declaredEffect = str(o["sideEffect"]) as SideEffect | undefined;
  const sideEffect: SideEffect = declaredEffect && SIDE_EFFECTS.includes(declaredEffect) ? declaredEffect : inferSideEffect(action);
  const audience = str(o["audience"])?.toLowerCase();
  const external =
    typeof o["external"] === "boolean"
      ? (o["external"] as boolean)
      : audience
        ? audience === "external"
        : sideEffect === "send" && kind !== "message";

  const errorHandling = parseOnError(o["onError"]);

  const retryMaxAttempts = parseRetry(o);

  const loopObj = asObj(o["loop"]) ?? asObj(o["paginate"]) ?? asObj(o["pagination"]);
  const isLoop = kind === "loop" || loopObj !== undefined;
  const limit = loopLimit(loopObj) ?? loopLimit(o);

  const durationSec = num(o["durationSec"]);
  const needsTimeout =
    ["http", "llm", "payment", "email", "message", "approval"].includes(kind) ||
    (kind === "wait" && durationSec === undefined) ||
    (kind === "data" && str(o["system"]) !== undefined);

  const params = o["params"] ?? o["inputs"] ?? o["with"] ?? {};
  const declaredPii = Array.isArray(o["pii"]) ? (o["pii"] as unknown[]).filter((x): x is string => typeof x === "string") : [];
  const inputKeys = Object.keys(asObj(o["inputs"]) ?? {}).flatMap(piiIdentifiers);
  const isLLM = kind === "llm";
  const piiNote = str(o["piiNote"]) !== undefined || str(o["dataHandling"]) !== undefined || PII_NOTE.test(str(o["notes"]) ?? "");

  const trigger = kind === "trigger";
  const isWebhook = trigger && /webhook/i.test(action);

  return {
    id,
    name: str(o["name"]) ?? id,
    action,
    system: str(o["system"]),
    kind,
    sideEffect,
    external,
    needsTimeout,
    timeoutSec: num(o["timeoutSec"]),
    errorHandling,
    retryMaxAttempts,
    idempotencyKey: str(o["idempotencyKey"]),
    approved: approvedSoFar || approvalGiven(o["approval"]),
    loop: isLoop ? { bounded: limit !== undefined, detail: limit !== undefined ? `limit ${limit}` : "no limit / maxPages / maxIterations" } : undefined,
    isLLM,
    piiRefs: isLLM ? [...new Set([...declaredPii, ...inputKeys, ...piiRefsIn(params)])] : [],
    piiNote,
    webhook: isWebhook
      ? { verified: o["verifySignature"] === true || /^(hmac|signature)$/i.test(str(o["auth"]) ?? ""), detail: "step" }
      : undefined,
    hasCompletionCheck: declared(o["completionCheck"]) || kind === "verify",
    params,
    path: `steps[${index}]`,
  };
}

function triggerStep(raw: unknown): NormalizedStep | undefined {
  const o = asObj(raw);
  const type = typeof raw === "string" ? raw : str(o?.["type"]);
  if (!type) return undefined;
  const isWebhook = /webhook/i.test(type);
  return {
    id: "trigger",
    name: `trigger (${type})`,
    action: `trigger.${type}`,
    kind: "trigger",
    sideEffect: "none",
    external: false,
    needsTimeout: false,
    errorHandling: "handled",
    approved: false,
    isLLM: false,
    piiRefs: [],
    piiNote: false,
    webhook: isWebhook
      ? {
          verified: o?.["verifySignature"] === true || /^(hmac|signature)$/i.test(str(o?.["auth"]) ?? ""),
          detail: str(o?.["auth"]) ?? (o?.["verifySignature"] === false ? "verifySignature: false" : "no verifySignature / auth"),
        }
      : undefined,
    hasCompletionCheck: false,
    params: o ?? {},
    path: "trigger",
  };
}

export function looksGeneric(doc: unknown): boolean {
  const o = asObj(doc);
  return !!o && Array.isArray(o["steps"]);
}

export function normalizeGeneric(doc: unknown): NormalizedWorkflow {
  const o = asObj(doc) ?? {};
  const rawSteps = Array.isArray(o["steps"]) ? (o["steps"] as unknown[]) : [];
  const steps: NormalizedStep[] = [];
  const trig = triggerStep(o["trigger"]);
  if (trig) steps.push(trig);
  let approvedSoFar = false;
  rawSteps.forEach((raw, i) => {
    const step = parseStep(raw, i, approvedSoFar);
    // A dedicated approval step gates everything after it.
    if (step.kind === "approval") approvedSoFar = true;
    steps.push(step);
  });
  const lint = asObj(o["lint"]);
  const ignore = Array.isArray(lint?.["ignore"]) ? (lint?.["ignore"] as unknown[]).filter((x): x is string => typeof x === "string") : [];
  return {
    name: str(o["name"]) ?? "workflow",
    format: "generic",
    steps,
    hasCompletionCheck: declared(o["completionCheck"]) || steps.some((s) => s.hasCompletionCheck),
    extraParams: [{ path: "env", value: o["env"] ?? {} }, { path: "variables", value: o["variables"] ?? {} }],
    unboundedCycles: [],
    ignore,
  };
}
