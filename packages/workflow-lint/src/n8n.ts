import { inferSideEffect } from "./generic.js";
import { PII_NOTE, piiRefsIn } from "./pii.js";
import type { NormalizedStep, NormalizedWorkflow, SideEffect, StepKind } from "./types.js";

type Obj = Record<string, unknown>;

interface N8nNode {
  id?: string;
  name: string;
  type: string;
  parameters: Obj;
  disabled?: boolean;
  continueOnFail?: boolean;
  onError?: string;
  retryOnFail?: boolean;
  maxTries?: number;
  notes?: string;
}

function asObj(v: unknown): Obj | undefined {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : undefined;
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v : undefined;
}

export function looksN8n(doc: unknown): boolean {
  const o = asObj(doc);
  return !!o && Array.isArray(o["nodes"]) && asObj(o["connections"]) !== undefined;
}

const short = (type: string): string => type.split(".").pop() ?? type;

const LLM_TYPES = /^(agent|openAi|chainLlm|chainSummarization|chainRetrievalQa|informationExtractor|textClassifier|sentimentAnalysis|anthropic|googleGemini|mistralAi|ollama|lmChat.*|lmOpenAi|lmCohere)$/;

interface Classified {
  kind: StepKind;
  sideEffect: SideEffect;
  external: boolean;
  needsTimeout: boolean;
  timeoutSec?: number;
  idempotencyKey?: string;
  loop?: { bounded: boolean; detail: string };
  approval: boolean;
  verifier: boolean;
}

function headerList(p: Obj): Array<{ name: string; value: string }> {
  const list = asObj(p["headerParameters"])?.["parameters"];
  if (!Array.isArray(list)) return [];
  return list
    .map((h) => asObj(h))
    .filter((h): h is Obj => !!h)
    .map((h) => ({ name: String(h["name"] ?? ""), value: String(h["value"] ?? "") }));
}

function classifyHttp(p: Obj): Classified {
  const method = (str(p["method"]) ?? "GET").toUpperCase();
  const url = str(p["url"]) ?? "";
  const options = asObj(p["options"]) ?? {};
  let sideEffect: SideEffect = method === "GET" || method === "HEAD" ? "none" : method === "DELETE" ? "delete" : "write";
  let external = false;
  if (sideEffect === "write" && /stripe\.com|paypal\.com|squareup\.com|braintreegateway|adyen/i.test(url) && /(charge|payment|refund|payout|transfer|capture|invoices\/.+\/pay)/i.test(url)) {
    sideEffect = "money";
  } else if (sideEffect === "write" && /sendgrid\.com|api\.twilio\.com|mailgun|postmarkapp|api\.resend\.com|sparkpost|mandrillapp|graph\.microsoft\.com\/.*sendMail|gmail\.googleapis\.com\/.*send/i.test(url)) {
    sideEffect = "send";
    external = true;
  } else if (sideEffect === "write" && /hooks\.slack\.com|slack\.com\/api\/chat\.postMessage/i.test(url)) {
    sideEffect = "send";
  }
  const timeoutMs = typeof options["timeout"] === "number" ? (options["timeout"] as number) : undefined;
  const idem =
    headerList(p).find((h) => /^idempotency[-_]key$/i.test(h.name))?.value ??
    (/idempotency[-_]key/i.test(String(p["jsonHeaders"] ?? "")) ? "jsonHeaders" : undefined);
  const pagOuter = asObj(options["pagination"]);
  const pag = asObj(pagOuter?.["pagination"]) ?? pagOuter;
  let loop: Classified["loop"];
  if (pag) {
    const max = typeof pag["maxRequests"] === "number" ? (pag["maxRequests"] as number) : undefined;
    const bounded = pag["limitPagesFetched"] === true && (max === undefined || max > 0);
    loop = { bounded, detail: bounded ? `maxRequests ${max ?? 100}` : "pagination without limitPagesFetched/maxRequests" };
  }
  return {
    kind: "http",
    sideEffect,
    external,
    needsTimeout: true,
    timeoutSec: timeoutMs !== undefined ? timeoutMs / 1000 : undefined,
    idempotencyKey: idem,
    loop,
    approval: false,
    verifier: false,
  };
}

const base = (kind: StepKind, sideEffect: SideEffect, external = false): Classified => ({
  kind,
  sideEffect,
  external,
  needsTimeout: false,
  approval: false,
  verifier: false,
});

function classify(node: N8nNode): Classified {
  const t = short(node.type);
  const p = node.parameters;
  const op = str(p["operation"]);
  const resource = str(p["resource"]);
  if (op === "sendAndWait") return { ...base("approval", "none"), approval: true };

  if (t === "httpRequest") return classifyHttp(p);
  if (node.type.includes("langchain") ? LLM_TYPES.test(t) : t === "openAi") return base("llm", "none");

  switch (t) {
    case "webhook":
      return base("trigger", "none");
    case "wait": {
      const resume = str(p["resume"]) ?? "timeInterval";
      if (resume === "webhook" || resume === "form") {
        const limited = p["limitWaitTime"] === true;
        return { ...base("approval", "none"), approval: true, needsTimeout: true, timeoutSec: limited ? 1 : undefined };
      }
      return base("wait", "none");
    }
    case "form":
      return { ...base("approval", "none"), approval: true };
    case "splitInBatches":
      return { ...base("loop", "none"), loop: { bounded: true, detail: "Split In Batches (bounded by input items)" } };
    case "if":
    case "switch":
    case "filter":
      return base("control", "none");
    case "code":
    case "function":
    case "functionItem": {
      const code = String(p["jsCode"] ?? p["functionCode"] ?? p["pythonCode"] ?? "");
      return { ...base("code", "none"), verifier: /createHmac|timingSafeEqual|constructEvent|verifySignature|crypto\.subtle/.test(code) };
    }
    case "crypto":
      return { ...base("code", "none"), verifier: (str(p["action"]) ?? "") === "hmac" };
    case "emailSend":
      return base("email", "send", true);
    case "gmail":
    case "microsoftOutlook": {
      const o = op ?? (resource === undefined || resource === "message" ? "send" : "get");
      if (/^(send|reply|forward)/i.test(o)) return base("email", "send", true);
      if (/delete/i.test(o)) return base("email", "delete");
      return base("email", inferSideEffect(o));
    }
    case "slack":
    case "microsoftTeams":
    case "discord":
    case "mattermost": {
      const o = op ?? "post";
      if (/delete/i.test(o)) return base("message", "delete");
      if (/^(post|send|create)/i.test(o) && (resource === undefined || resource === "message" || resource === "chatMessage")) return base("message", "send", false);
      return base("message", inferSideEffect(o));
    }
    case "twilio":
    case "telegram":
    case "whatsApp":
    case "vonage":
    case "messageBird": {
      const o = op ?? "send";
      return /^send/i.test(o) ? base("message", "send", true) : base("message", inferSideEffect(o));
    }
    case "stripe":
    case "payPal":
    case "quickbooks":
    case "xero":
    case "chargebee":
    case "square": {
      const o = op ?? "get";
      const r = (resource ?? "").toLowerCase();
      if (/delete|void/i.test(o)) return base("payment", "delete");
      if (/^send/i.test(o)) return base("payment", "send", true);
      if (/^create/i.test(o) && /charge|payment|payout|refund|bill|transfer/.test(r)) return base("payment", "money");
      return base("payment", inferSideEffect(o));
    }
    default: {
      if (/trigger$/i.test(t) || t === "start") return base("trigger", "none");
      return base("data", op ? inferSideEffect(op) : "none");
    }
  }
}

/** Build `name -> successors` from n8n `connections` (main outputs and error outputs). */
function buildGraph(connections: Obj, nodeNames: Set<string>): Map<string, Set<string>> {
  const g = new Map<string, Set<string>>();
  for (const name of nodeNames) g.set(name, new Set());
  for (const [src, outputs] of Object.entries(connections)) {
    const main = asObj(outputs)?.["main"];
    if (!Array.isArray(main) || !nodeNames.has(src)) continue;
    for (const branch of main) {
      if (!Array.isArray(branch)) continue;
      for (const edge of branch) {
        const target = str(asObj(edge)?.["node"]);
        if (target && nodeNames.has(target)) g.get(src)?.add(target);
      }
    }
  }
  return g;
}

function reachable(g: Map<string, Set<string>>, start: string): Set<string> {
  const seen = new Set<string>();
  const stack = [...(g.get(start) ?? [])];
  while (stack.length) {
    const n = stack.pop() as string;
    if (seen.has(n)) continue;
    seen.add(n);
    for (const m of g.get(n) ?? []) stack.push(m);
  }
  return seen;
}

/** Tarjan's strongly connected components; returns cycles (SCCs with >1 node or a self-loop). */
function cycles(g: Map<string, Set<string>>): string[][] {
  let index = 0;
  const idx = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const out: string[][] = [];
  const strong = (v: string): void => {
    idx.set(v, index);
    low.set(v, index);
    index++;
    stack.push(v);
    onStack.add(v);
    for (const w of g.get(v) ?? []) {
      if (!idx.has(w)) {
        strong(w);
        low.set(v, Math.min(low.get(v) as number, low.get(w) as number));
      } else if (onStack.has(w)) {
        low.set(v, Math.min(low.get(v) as number, idx.get(w) as number));
      }
    }
    if (low.get(v) === idx.get(v)) {
      const comp: string[] = [];
      let w: string;
      do {
        w = stack.pop() as string;
        onStack.delete(w);
        comp.push(w);
      } while (w !== v);
      if (comp.length > 1 || g.get(v)?.has(v)) out.push(comp.reverse());
    }
  };
  for (const v of g.keys()) if (!idx.has(v)) strong(v);
  return out;
}

export function normalizeN8n(doc: unknown): NormalizedWorkflow {
  const o = asObj(doc) ?? {};
  const nodes: N8nNode[] = (o["nodes"] as unknown[])
    .map((n) => asObj(n))
    .filter((n): n is Obj => !!n && typeof n["name"] === "string" && typeof n["type"] === "string")
    .map((n) => ({ ...(n as unknown as N8nNode), parameters: asObj(n["parameters"]) ?? {} }))
    .filter((n) => n.disabled !== true);
  const names = new Set(nodes.map((n) => n.name));
  const graph = buildGraph(asObj(o["connections"]) ?? {}, names);
  const settings = asObj(o["settings"]) ?? {};
  const hasErrorWorkflow = str(settings["errorWorkflow"]) !== undefined;

  const classified = new Map(nodes.map((n) => [n.name, classify(n)]));
  const descendants = new Map(nodes.map((n) => [n.name, reachable(graph, n.name)]));
  const ancestorsOf = (name: string): string[] => nodes.filter((n) => descendants.get(n.name)?.has(name)).map((n) => n.name);

  const steps: NormalizedStep[] = nodes.map((node) => {
    const c = classified.get(node.name) as Classified;
    const t = short(node.type);
    const onError = node.onError;
    const errorHandling: NormalizedStep["errorHandling"] =
      onError === "continueErrorOutput"
        ? "handled"
        : node.continueOnFail === true || onError === "continueRegularOutput"
          ? "swallowed"
          : hasErrorWorkflow
            ? "handled"
            : "none";
    const approved = c.approval || ancestorsOf(node.name).some((a) => classified.get(a)?.approval);
    let webhook: NormalizedStep["webhook"];
    if (t === "webhook") {
      const auth = str(node.parameters["authentication"]) ?? "none";
      const downstreamVerifier = [...(descendants.get(node.name) ?? [])].find((d) => classified.get(d)?.verifier);
      webhook =
        auth !== "none"
          ? { verified: true, detail: `authentication: ${auth}` }
          : downstreamVerifier
            ? { verified: true, detail: `verified by "${downstreamVerifier}"` }
            : { verified: false, detail: "authentication: none and no HMAC/Crypto verification node downstream" };
    }
    const isLLM = c.kind === "llm";
    return {
      id: node.name,
      name: node.name,
      action: node.type,
      kind: c.kind,
      sideEffect: c.sideEffect,
      external: c.external,
      needsTimeout: c.needsTimeout,
      timeoutSec: c.timeoutSec,
      errorHandling,
      retryMaxAttempts: node.retryOnFail === true ? (typeof node.maxTries === "number" ? node.maxTries : 3) : undefined,
      idempotencyKey: c.idempotencyKey,
      approved,
      loop: c.loop,
      isLLM,
      piiRefs: isLLM ? piiRefsIn(node.parameters) : [],
      piiNote: PII_NOTE.test(node.notes ?? ""),
      webhook,
      hasCompletionCheck: false,
      params: node.parameters,
      path: `nodes[${JSON.stringify(node.name)}]`,
    };
  });

  // Completion check heuristic: after a side-effect node, the workflow reads back / branches on the result,
  // or a node is explicitly named as a verification step.
  const sideEffectNodes = steps.filter((s) => s.sideEffect !== "none");
  // A read-back is a GET request or an explicit read operation (get/getAll/search/...); Set/NoOp/IF nodes alone don't verify anything.
  const nodeByName = new Map(nodes.map((n) => [n.name, n]));
  const isReadBack = (name: string): boolean => {
    const node = nodeByName.get(name);
    const c = classified.get(name);
    if (!node || !c || c.sideEffect !== "none") return false;
    if (c.kind === "http") return true;
    const op = str(node.parameters["operation"]);
    return op !== undefined && /^(get|getAll|read|search|lookup|list|find|fetch)/i.test(op);
  };
  const hasCompletionCheck = sideEffectNodes.some((s) =>
    [...(descendants.get(s.id) ?? [])].some((d) => {
      const namedCheck = /verif|confirm|assert|reconcil|check/i.test(d) && !/signature/i.test(d) && classified.get(d)?.sideEffect === "none";
      return isReadBack(d) || namedCheck;
    }),
  );

  const unbounded = cycles(graph).filter((comp) => !comp.some((n) => short(nodes.find((x) => x.name === n)?.type ?? "") === "splitInBatches"));

  return {
    name: str(o["name"]) ?? "n8n workflow",
    format: "n8n",
    steps,
    hasCompletionCheck,
    extraParams: [{ path: "settings", value: settings }],
    unboundedCycles: unbounded,
    ignore: [],
  };
}
