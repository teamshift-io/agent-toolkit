import { findSecrets } from "./secrets.js";
import type { Finding, NormalizedStep, NormalizedWorkflow, RuleMeta } from "./types.js";

const DOCS = "https://github.com/teamshift-io/agent-toolkit/tree/main/packages/workflow-lint#";

function meta(id: string, name: string, severity: RuleMeta["severity"], description: string, fix: string): RuleMeta {
  return { id, name, severity, description, fix, docs: `${DOCS}${id.toLowerCase()}-${name}` };
}

export const RULES = {
  missingErrorHandling: meta(
    "WL001",
    "missing-error-handling",
    "error",
    "A step with a side effect (write/send/money/delete) has no error handling, or silently swallows errors.",
    "Declare `onError` (stop + alert, fallback step, or error branch). In n8n set 'On Error: Continue (using error output)' and wire the error output, or set a workflow Error Workflow.",
  ),
  unsafeRetry: meta(
    "WL002",
    "unsafe-retry",
    "error",
    "A non-idempotent side-effect step is retried without an idempotency key, so a timeout-then-retry can double-send or double-charge.",
    "Add an `idempotencyKey` (e.g. `{{invoice.id}}-reminder-1`), send an `Idempotency-Key` header, or disable retries for this step.",
  ),
  missingTimeout: meta(
    "WL003",
    "missing-timeout",
    "warning",
    "An external call or wait has no timeout, so a hung provider or a never-answered approval stalls the run forever.",
    "Set `timeoutSec` (generic) or the HTTP Request 'Timeout' option / Wait node 'Limit Wait Time' (n8n).",
  ),
  unapprovedHighRisk: meta(
    "WL004",
    "unapproved-high-risk-action",
    "error",
    "A step that moves money, deletes data, or sends to people outside the business runs without a human approval gate.",
    "Add `approval: { required: true, by: <role> }` or an approval step before it. In n8n, put a 'Send and Wait for Response' / Wait (On Webhook or Form) node upstream.",
  ),
  noCompletionCheck: meta(
    "WL005",
    "no-completion-check",
    "warning",
    "The workflow has side effects but never verifies the end state, so it can report success when nothing actually happened.",
    "Add a workflow-level `completionCheck` (or a `verify.*` step) that reads back the result, e.g. 'invoice status is sent' or 'row exists'. In n8n, read the record back and branch on it with an IF node.",
  ),
  hardcodedSecret: meta(
    "WL006",
    "hardcoded-secret",
    "error",
    "A credential (API key, token, signing secret, private key) is hardcoded in the workflow definition.",
    "Move the value to a credential store or environment variable and reference it (`{{ $env.NAME }}`, n8n Credentials). Rotate the exposed key.",
  ),
  unboundedLoop: meta(
    "WL007",
    "unbounded-loop",
    "warning",
    "A loop, pagination, or execution cycle has no upper bound, so bad data or a provider bug can run it forever (and run up API bills).",
    "Set `loop.limit` / `maxPages` / `maxIterations`. In n8n enable 'Limit Pages Fetched' with 'Max Pages', or use Loop Over Items (Split In Batches) instead of wiring a node back to itself.",
  ),
  unverifiedWebhook: meta(
    "WL008",
    "unverified-webhook",
    "error",
    "A webhook trigger accepts requests without verifying a signature or authenticating the caller, so anyone who finds the URL can start the workflow.",
    "Verify the provider's HMAC signature (`trigger.verifySignature: true`) or require auth. In n8n set Webhook 'Authentication', or verify the signature in a Crypto/Code node right after the trigger.",
  ),
  piiToLlm: meta(
    "WL009",
    "pii-to-llm-without-note",
    "warning",
    "Personal data (emails, phone numbers, names, addresses) flows into an LLM step and nobody documented how it is handled.",
    "Minimize or redact the fields, and add a `piiNote` (generic) or a node Note (n8n) stating why the data is needed, the provider, and retention.",
  ),
} as const satisfies Record<string, RuleMeta>;

export const RULE_LIST: RuleMeta[] = Object.values(RULES);

const HIGH_RISK = new Set(["money", "delete"]);

function finding(rule: RuleMeta, step: NormalizedStep | undefined, message: string, path?: string): Finding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    message,
    fix: rule.fix,
    docs: rule.docs,
    stepId: step?.id,
    path: path ?? step?.path ?? "$",
  };
}

const label = (s: NormalizedStep): string => `"${s.name}"`;
const NOUN = { none: "step", write: "write", send: "send", money: "payment", delete: "delete" } as const;

export function runRules(wf: NormalizedWorkflow): Finding[] {
  const out: Finding[] = [];
  const sideEffectSteps = wf.steps.filter((s) => s.sideEffect !== "none");

  for (const s of wf.steps) {
    if (s.sideEffect !== "none") {
      if (s.errorHandling === "none") {
        out.push(finding(RULES.missingErrorHandling, s, `Step ${label(s)} (${s.sideEffect}) has no error handling; a failure will stop the run with no alert or fallback.`));
      } else if (s.errorHandling === "swallowed") {
        out.push(finding(RULES.missingErrorHandling, s, `Step ${label(s)} (${s.sideEffect}) continues on error, so a failed ${NOUN[s.sideEffect]} is silently treated as success.`));
      }
      if ((s.retryMaxAttempts ?? 1) > 1 && !s.idempotencyKey) {
        out.push(finding(RULES.unsafeRetry, s, `Step ${label(s)} retries up to ${s.retryMaxAttempts} times but has no idempotency key; a retry after a timeout can repeat the ${NOUN[s.sideEffect]}.`));
      }
      const needsApproval = HIGH_RISK.has(s.sideEffect) || (s.sideEffect === "send" && s.external);
      if (needsApproval && !s.approved) {
        const what = s.sideEffect === "money" ? "moves money" : s.sideEffect === "delete" ? "deletes data" : "sends to external recipients";
        out.push(finding(RULES.unapprovedHighRisk, s, `Step ${label(s)} ${what} without a human approval gate.`));
      }
    }
    if (s.needsTimeout && s.timeoutSec === undefined) {
      const what = s.kind === "approval" ? "waits for a human response" : s.kind === "wait" ? "waits for an event" : "calls an external system";
      out.push(finding(RULES.missingTimeout, s, `Step ${label(s)} ${what} with no timeout.`));
    }
    if (s.loop && !s.loop.bounded) {
      out.push(finding(RULES.unboundedLoop, s, `Step ${label(s)} loops/paginates with no upper bound (${s.loop.detail}).`));
    }
    if (s.webhook && !s.webhook.verified) {
      out.push(finding(RULES.unverifiedWebhook, s, `Webhook trigger ${label(s)} does not verify a signature (${s.webhook.detail}).`));
    }
    if (s.isLLM && s.piiRefs.length > 0 && !s.piiNote) {
      out.push(finding(RULES.piiToLlm, s, `LLM step ${label(s)} receives personal data (${s.piiRefs.slice(0, 5).join(", ")}) with no PII handling note.`));
    }
    for (const hit of findSecrets(s.params, `${s.path}.params`)) {
      out.push(finding(RULES.hardcodedSecret, s, `Step ${label(s)} contains a hardcoded ${hit.kind}: ${hit.preview}.`, hit.path));
    }
  }

  for (const extra of wf.extraParams) {
    for (const hit of findSecrets(extra.value, extra.path)) {
      out.push(finding(RULES.hardcodedSecret, undefined, `Workflow ${extra.path} contains a hardcoded ${hit.kind}: ${hit.preview}.`, hit.path));
    }
  }

  for (const cycle of wf.unboundedCycles) {
    const first = wf.steps.find((s) => s.id === cycle[0]);
    out.push(finding(RULES.unboundedLoop, first, `Execution cycle ${cycle.map((c) => `"${c}"`).join(" → ")} → "${cycle[0]}" has no loop limit.`));
  }

  if (sideEffectSteps.length > 0 && !wf.hasCompletionCheck) {
    out.push(
      finding(
        RULES.noCompletionCheck,
        undefined,
        `Workflow "${wf.name}" has ${sideEffectSteps.length} side-effect step(s) but no completion check; it can "succeed" without verifying the end state.`,
        wf.format === "generic" ? "completionCheck" : "$",
      ),
    );
  }

  return out;
}
