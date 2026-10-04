# agent-toolkit

**agent-toolkit is TeamShift's free, open-source collection of small developer tools for people building AI agents and business automations. It lints workflows before they run, verifies and debugs webhook signatures, and plans least-privilege OAuth scopes with human-approval policies.**

Each tool has three parts:

- A **pure, browser-safe TypeScript core** with no Node.js built-ins. The same cores power free, no-login pages at [teamshift.io/tools](https://teamshift.io/tools).
- A **CLI** you can run with `npx`.
- A **test suite**.

Runtime dependencies are minimal: only `yaml`, used by the two tools that read YAML. Everything is Apache-2.0.

## Tools

| Tool | What it does | Try it |
|---|---|---|
| [`@teamshift-io/workflow-lint`](packages/workflow-lint) | Preflight linter for n8n exports and a generic YAML/JSON workflow spec. Catches missing error handling, unsafe retries, unapproved money/delete/send steps, missing timeouts, hardcoded secrets, unbounded loops, unverified webhooks, and PII sent to LLMs. Outputs to the terminal, JSON or SARIF. | [teamshift.io/tools/workflow-lint](https://teamshift.io/tools/workflow-lint) |
| [`@teamshift-io/webhook-inspect`](packages/webhook-inspect) | Verifies Stripe, GitHub, Shopify, Slack, Twilio and generic HMAC signatures with WebCrypto, explains each event, and diagnoses *why* a signature fails. Includes a local capture server and a replay command. | [teamshift.io/tools/webhook-inspect](https://teamshift.io/tools/webhook-inspect) |
| [`@teamshift-io/permission-planner`](packages/permission-planner) | Turns intended agent actions into minimum OAuth scopes and API permissions (Google, Microsoft Graph, Slack, HubSpot, QuickBooks, Stripe, Shopify), a risk tier and an approval policy. Every scope links to official docs. | [teamshift.io/tools/permission-planner](https://teamshift.io/tools/permission-planner) |

## Quickstart

```bash
npx @teamshift-io/workflow-lint my-n8n-workflow.json
npx @teamshift-io/webhook-inspect verify --provider stripe --secret whsec_... --header 't=...,v1=...' --body-file body.json
npx @teamshift-io/permission-planner plan --actions gmail.send,hubspot.write_deals,stripe.refund
```

## Why these three

AI agents and automations tend to fail in the same few places:

1. **The workflow itself.** It retries a payment without an idempotency key, emails customers without approval, or "succeeds" without checking anything happened. workflow-lint catches these before the first run.
2. **The inbound edge.** Webhooks fail signature checks for reasons that are hard to see: re-serialized bodies, the wrong secret, clock skew, proxies rewriting URLs. webhook-inspect shows you which one it is.
3. **The permission boundary.** Agents get far broader OAuth scopes than they need, and nobody decides which actions need a human. permission-planner produces the minimum scopes and an approval policy, with sources.

## Development

Requirements: Node.js 20+ and pnpm 11 (via Corepack).

```bash
corepack pnpm@11.2.2 install
corepack pnpm@11.2.2 build
corepack pnpm@11.2.2 test
corepack pnpm@11.2.2 typecheck
```

Layout: `packages/<tool>/src/index.ts` is the browser-safe core, `src/cli.ts` is the Node.js CLI, and `test/` holds vitest suites and fixtures.

## Contributing

New rules, providers and catalog entries are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. In short, every rule needs a good and a bad fixture, and every permission-catalog entry needs an official `source` URL. If you can't verify an entry, mark it `status: "unverified"`. Please also read the [Code of Conduct](CODE_OF_CONDUCT.md), and report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Citation

If you reference this toolkit in research or documentation, see [CITATION.cff](CITATION.cff). A machine-readable summary for LLMs is in [llms.txt](llms.txt).

## License

[Apache-2.0](LICENSE)

---

Built by [TeamShift](https://teamshift.io/open-source/agent-toolkit?utm_source=github&utm_medium=readme) — AI workers for small-business operations.
