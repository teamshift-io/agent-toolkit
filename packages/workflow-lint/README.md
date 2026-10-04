# @teamshift-io/workflow-lint

**workflow-lint is an open-source preflight linter that catches missing error handling, unsafe retries, unapproved money actions and hardcoded secrets in AI-agent and automation workflows before they run.**

It reads [n8n](https://n8n.io) workflow exports and a small, tool-agnostic YAML/JSON workflow spec, applies nine rules drawn from real automation failures (double-sent emails, double charges, runs that "succeeded" while doing nothing), and prints a terminal report, JSON, or SARIF for CI. The core is pure TypeScript with no Node.js built-ins, so the same engine runs in the browser.

**Try it in your browser:** [teamshift.io/tools/workflow-lint](https://teamshift.io/tools/workflow-lint), no login, and nothing leaves the page.

## Quickstart

```bash
npx @teamshift-io/workflow-lint my-workflow.json          # n8n export
npx @teamshift-io/workflow-lint agent.workflow.yaml       # generic spec
npx @teamshift-io/workflow-lint flows/*.json --format sarif > workflow-lint.sarif
```

Exit code `0` = no errors, `1` = at least one error-severity finding, `2` = unreadable input or a usage error.

## Example output

Running it on the n8n fixture [`test/fixtures/n8n-bad.json`](test/fixtures/n8n-bad.json) prints the following (fix/docs lines trimmed):

```text
test/fixtures/n8n-bad.json  (n8n, 7 steps, workflow "New order follow-up")
  error    WL008 unverified-webhook  line 7
           Webhook trigger "Order Webhook" does not verify a signature (authentication: none and no HMAC/Crypto verification node downstream).
  error    WL006 hardcoded-secret  line 20
           Step "Fetch Orders" contains a hardcoded Bearer token: FAKE…89 (34 chars).
  error    WL001 missing-error-handling  line 55
           Step "Email Customer" (send) has no error handling; a failure will stop the run with no alert or fallback.
  error    WL002 unsafe-retry  line 55
           Step "Email Customer" retries up to 3 times but has no idempotency key; a retry after a timeout can repeat the send.
  error    WL004 unapproved-high-risk-action  line 55
           Step "Email Customer" sends to external recipients without a human approval gate.
  error    WL001 missing-error-handling  line 65
           Step "Charge Deposit" (money) continues on error, so a failed payment is silently treated as success.
  error    WL004 unapproved-high-risk-action  line 65
           Step "Charge Deposit" moves money without a human approval gate.
  warning  WL005 no-completion-check  $
           Workflow "New order follow-up" has 2 side-effect step(s) but no completion check; it can "succeed" without verifying the end state.
  warning  WL003 missing-timeout  line 20
           Step "Fetch Orders" calls an external system with no timeout.
  warning  WL007 unbounded-loop  line 20
           Step "Fetch Orders" loops/paginates with no upper bound (pagination without limitPagesFetched/maxRequests).
  warning  WL007 unbounded-loop  line 28
           Execution cycle "Poll Export" → "Export Ready?" → "Poll Export" has no loop limit.
  warning  WL009 pii-to-llm-without-note  line 47
           LLM step "Draft Thank-You" receives personal data (first_name, last_name, email, phone) with no PII handling note.

✖ 12 problems (7 errors, 5 warnings)
```

The fixed version, [`test/fixtures/n8n-good.json`](test/fixtures/n8n-good.json), reports `✓ 0 problems`.

## Rules

| ID | Name | Severity | Catches |
|---|---|---|---|
| [WL001](#wl001-missing-error-handling) | missing-error-handling | error | Side-effect step with no error path, or one that silently continues on error |
| [WL002](#wl002-unsafe-retry) | unsafe-retry | error | Retried write/send/payment with no idempotency key |
| [WL003](#wl003-missing-timeout) | missing-timeout | warning | External call or wait with no timeout |
| [WL004](#wl004-unapproved-high-risk-action) | unapproved-high-risk-action | error | Money, delete, or external send with no human approval gate |
| [WL005](#wl005-no-completion-check) | no-completion-check | warning | Workflow never verifies the end state |
| [WL006](#wl006-hardcoded-secret) | hardcoded-secret | error | API keys, tokens, signing secrets, private keys in parameters |
| [WL007](#wl007-unbounded-loop) | unbounded-loop | warning | Loops, pagination or execution cycles without a limit |
| [WL008](#wl008-unverified-webhook) | unverified-webhook | error | Webhook trigger that does not verify a signature or authenticate |
| [WL009](#wl009-pii-to-llm-without-note) | pii-to-llm-without-note | warning | Personal data sent to an LLM step without a documented handling note |

### WL001 missing-error-handling

A step that writes, sends, moves money or deletes must say what happens when it fails. **Generic:** set `onError` (`stop`, `alert`, `fallback:<step>`, ...). `onError: continue` / `ignore` is reported as swallowing errors. **n8n:** node setting *On Error → Continue (using error output)* with the error output wired up, or a workflow-level *Error Workflow*. `continueOnFail` / *Continue (regular output)* on a side-effect node is reported.

### WL002 unsafe-retry

Retries plus a non-idempotent side effect means a timeout followed by a retry can send twice or charge twice. Add an `idempotencyKey` (generic), or send an `Idempotency-Key` header from the n8n HTTP Request node. You can also turn retries off for that step.

### WL003 missing-timeout

HTTP/API calls, LLM calls, payments, messaging steps, approval steps and open-ended waits need `timeoutSec`. In n8n, this rule checks the HTTP Request *Timeout* option and the Wait node's *Limit Wait Time* when it resumes on a webhook or form (a human approval that nobody answers blocks the run forever).

### WL004 unapproved-high-risk-action

Steps with `sideEffect: money` or `delete`, or `send` to external recipients, need human approval. **Generic:** `approval: { required: true, by: <role> }` on the step, or an earlier `approval.*` step. **n8n:** an upstream *Send and Wait for Response* operation (Gmail, Slack, ...), a Form node, or a Wait node that resumes on a webhook or form. Messages to internal chat (Slack, Teams) don't require approval unless marked `audience: external`.

### WL005 no-completion-check

An automation that sends, writes or charges should confirm the result instead of assuming success. **Generic:** a workflow-level `completionCheck`, a step-level `completionCheck`, or a `verify.*` step. **n8n (heuristic):** downstream of a side-effect node there is a read-back (an HTTP GET, or a `get`/`getAll`/`search`/`read` operation), or a side-effect-free node named like *Verify…*, *Confirm…*, *Check…*. Set/NoOp/IF nodes on their own don't count.

### WL006 hardcoded-secret

Scans every parameter for Stripe, OpenAI, Anthropic, AWS, GitHub, Slack, Google, Shopify, Twilio, SendGrid and HubSpot key shapes, plus private key blocks, JWTs, literal Bearer and Basic credentials, and literal values under keys named `apiKey`, `secretKey`, `accessKey`, `token`, `secret`, `password` or `authorization`. Expressions (`{{ $env.X }}`, `={{ ... }}`, `${VAR}`) are ignored. Matches are redacted in the output.

### WL007 unbounded-loop

**Generic:** `loop.*` steps or `paginate:` blocks need `limit`, `maxPages`, `maxIterations` or `maxItems`. **n8n:** HTTP Request pagination without *Limit Pages Fetched*, and any connection cycle that doesn't pass through *Loop Over Items (Split In Batches)*.

### WL008 unverified-webhook

**Generic:** `trigger: { type: webhook, verifySignature: true }` (or `auth: hmac`). **n8n:** Webhook node *Authentication* set to Basic, Header or JWT, or a Crypto (HMAC) or Code node downstream that verifies the signature (`createHmac`, `timingSafeEqual`, `constructEvent`, ...). To check the signature itself, use [webhook-inspect](../webhook-inspect).

### WL009 pii-to-llm-without-note

Flags LLM/agent steps whose inputs reference emails, phone numbers, names, addresses, dates of birth, card numbers and similar fields. The check looks inside `{{ }}` expressions, generic `inputs` keys and explicit `pii: [...]` lists. Fix it by minimizing the fields and adding `piiNote:` (generic), or by adding a node *Note* in n8n that mentions PII, privacy, redaction or retention.

## The generic workflow spec

Use it for agents and automations built with code, Make, Zapier, Temporal, LangGraph or anything else: describe the steps, and workflow-lint checks the safety properties.

```yaml
name: Overdue invoice chaser
trigger:
  type: webhook            # webhook | schedule | manual | event
  verifySignature: true    # webhook only
completionCheck:           # how the workflow proves it worked
  description: Every reminded invoice has reminder_sent_at set.
lint:
  ignore: [WL009]          # optional per-file rule suppression
steps:
  - id: send-reminder      # required, unique
    action: email.send     # <system-or-kind>.<verb>; kind and sideEffect are inferred from it
    system: gmail
    sideEffect: send       # none | write | send | money | delete
    audience: external     # external | internal (for send; email defaults to external, chat to internal)
    onError: alert         # stop | alert | retry | fallback:<id> | continue (= swallowed)
    retry: { maxAttempts: 3 }
    timeoutSec: 30
    idempotencyKey: "{{ invoice.id }}-reminder-1"
    approval: { required: true, by: office-manager }
    completionCheck: Gmail returns a message id
    inputs: { to: "{{ invoice.customer.email }}" }
    piiNote: Customer email is required to send the reminder.
```

| Field | Meaning |
|---|---|
| `action` | `<prefix>.<verb>`. Prefixes such as `http`, `email`, `slack`, `llm`, `wait`, `loop`, `stripe`, `crm`, `approval`, `verify` set the step kind. Verbs such as `send`, `charge`, `refund`, `delete`, `create` and `update` set the default `sideEffect` |
| `sideEffect` | Explicit side effect; overrides inference |
| `onError`, `retry`, `timeoutSec`, `idempotencyKey`, `approval`, `completionCheck` | Inputs to the rules above |
| `loop` / `paginate` | `{ limit \| maxPages \| maxIterations \| maxItems }` |
| `durationSec` | Fixed delay for `wait.*` steps (no timeout needed) |
| `pii`, `piiNote` | Declared personal-data fields and the handling note |
| `params` / `inputs` | Scanned for secrets and PII references |

## Library use

```ts
import { lint, formatPretty } from "@teamshift-io/workflow-lint";

const result = lint(workflowText, { filename: "flow.json", ignore: ["WL005"] });
if (result.summary.errors > 0) console.log(formatPretty([result]));
```

`lint()` is synchronous and pure. It takes JSON or YAML text and returns `{ findings, summary, format, stepCount }`. `formatSarif()` produces SARIF 2.1.0 for GitHub code scanning and other CI tools.

## FAQ

### How do I lint an n8n workflow before activating it?

Export it (*Workflow → Download*, or copy all nodes) and run `npx @teamshift-io/workflow-lint workflow.json`. Pasted node selections work too, because workflow-lint only needs `nodes` and `connections`.

### How do I stop an AI agent from sending duplicate emails or double-charging when it retries?

Give every side-effect step an idempotency key derived from the business object, for example `{{invoice.id}}-reminder-2`, and pass it to the provider: an `Idempotency-Key` header for Stripe, or a dedupe check before sending email. WL002 flags every retried side effect that lacks one.

### Which automation steps should require human approval?

Anything that moves money, deletes data, or sends to customers, vendors or the public, at least until the automation has a track record. WL004 enforces this. To work out the matching OAuth scopes and approval policy, see [permission-planner](../permission-planner).

### How do I find hardcoded API keys in n8n or Zapier exports?

Run workflow-lint on the export. WL006 recognizes common provider key formats and literal values under secret-named fields, and it redacts the value in its output. Move the key to n8n Credentials or an environment variable, then rotate it.

### What is a completion check in an automation workflow?

A step that reads back the end state, such as "the invoice status is now `sent`" or "the row exists", instead of trusting that each API call returned 200. Without one, a workflow can report success after doing nothing. WL005 flags workflows with side effects and no completion check.

### Can I use workflow-lint in CI?

Yes. Use `--format sarif` for GitHub code scanning and similar tools, or `--format json` for custom gates. The exit code is non-zero when there are error-severity findings.

### Does workflow-lint send my workflow anywhere?

No. The CLI is local, and the [browser version](https://teamshift.io/tools/workflow-lint) runs the same pure core client-side.

## Related tools

- [webhook-inspect](../webhook-inspect): verify and debug webhook signatures.
- [permission-planner](../permission-planner): minimum OAuth scopes and approval policy for agent actions.

---

Built by [TeamShift](https://teamshift.io/open-source/agent-toolkit?utm_source=github&utm_medium=readme) — AI workers for small-business operations.
