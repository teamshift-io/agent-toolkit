# @teamshift/permission-planner

**permission-planner is an open-source tool that turns a list of intended AI-agent actions into the minimum OAuth scopes and API permissions, a risk tier, and a recommended human-approval policy, with every scope traced to the provider's official documentation.**

It ships a curated catalog of 89 agent actions across Google Workspace (Gmail, Calendar, Drive, Sheets), Microsoft Graph, Slack, HubSpot, QuickBooks Online, Stripe restricted keys and the Shopify Admin API. Each entry records the provider's own sensitivity classification where one is published, a `source` link, and either a verification date or an explicit **unverified** flag. If an action isn't in the catalog, the planner lists it as unknown and suggests nothing broader. It never recommends admin or full-access scopes just because the minimum isn't documented.

**Try it in your browser:** [teamshift.io/tools/permission-planner](https://teamshift.io/tools/permission-planner)

## Quickstart

```bash
npx @teamshift/permission-planner plan actions.yaml            # Markdown report
npx @teamshift/permission-planner plan actions.yaml --format json
npx @teamshift/permission-planner plan --actions gmail.send,slack.post_message,stripe.refund
npx @teamshift/permission-planner list --provider google        # browse the catalog with sources
```

`actions.yaml` is a list of action ids or `provider:action` strings, optionally with the scopes your app requests today:

```yaml
actions:
  - action: gmail.read
    why: Find customer replies about open invoices
  - gmail.send
  - google:gsheets.write
  - qbo.read_accounting
  - qbo.send_invoice
  - stripe:refund
  - slack.post_message
  - hubspot.write_deals
  - quickbooks:issue_credit_memo   # not in the catalog, reported as unknown
currentScopes:
  - https://mail.google.com/
```

Exit code `0` = every action is known, `1` = some actions are unknown, `2` = usage error.

## Example output

From [`test/fixtures/ar-agent.yaml`](test/fixtures/ar-agent.yaml) (trimmed):

```text
# Permission plan

Highest risk tier: **money** · 8 action(s) · 5 provider(s) · 1 unknown

## Google Workspace (Gmail, Calendar, Drive, Sheets)

| OAuth 2.0 scope | provider classification | needed by |
|---|---|---|
| `https://www.googleapis.com/auth/gmail.readonly` | restricted | gmail.read |
| `https://www.googleapis.com/auth/gmail.send` | sensitive | gmail.send |
| `https://www.googleapis.com/auth/spreadsheets` | sensitive | gsheets.write |

## QuickBooks Online

| OAuth scope | provider classification | needed by |
|---|---|---|
| `com.intuit.quickbooks.accounting` | — | qbo.read_accounting, qbo.send_invoice |

> QuickBooks has no read-only accounting scope: com.intuit.quickbooks.accounting grants read AND write to all accounting data. Enforce read-only or approval rules inside the agent.

## Approval policy

- **read** (auto): No approval. Log what was accessed. — gmail.read, qbo.read_accounting
- **write-internal** (auto-with-audit): Run automatically with an audit log and an easy undo; spot-check a sample weekly. — gsheets.write, slack.post_message, hubspot.write_deals
- **send-external** (approval-until-track-record): Human approves each send until the agent has a clean track record (e.g. 25 consecutive approvals with no edits), then switch to spot checks. — gmail.send, qbo.send_invoice
- **money** (always-approve): Always require explicit human approval, with amount and counterparty shown. Never auto-approve. — stripe.refund

## Warnings

- https://www.googleapis.com/auth/gmail.readonly is a Google restricted scope (needed by gmail.read). Check whether a narrower action covers the use case.
- stripe.refund: scope mapping is unverified. Confirm it against https://docs.stripe.com/stripe-apps/reference/permissions before shipping.
- Currently requested https://mail.google.com/ is broader than needed; https://www.googleapis.com/auth/gmail.readonly + https://www.googleapis.com/auth/gmail.send are enough.

## Unknown actions

- `quickbooks:issue_credit_memo`: Not in the catalog. Look up the minimum scope in the provider's docs; do not fall back to admin or full-access scopes just because the minimum is undocumented here. Did you mean: qbo.record_payment, qbo.create_invoice, qbo.charge_card?
```

## Risk tiers and approval policy

| Tier | Examples | Recommended policy |
|---|---|---|
| `read` | read email, list deals | Automatic; log access |
| `write-internal` | update CRM, append a sheet row, post in internal Slack | Automatic with audit log and undo; weekly spot checks |
| `send-external` | email a customer, send an invoice, invite external attendees | Human approval until the agent has a clean track record, then spot checks |
| `money` | refund, charge, payout, record a payment | Always human approval |
| `destructive` | delete contacts, trash email, delete files | Always human approval; prefer soft delete |

## Catalog coverage

| Provider | Actions | Verified against docs on 2026-10-03 | Source |
|---|---|---|---|
| Google (Gmail, Calendar, Drive, Sheets) | 19 | 19 | [Gmail](https://developers.google.com/workspace/gmail/api/auth/scopes), [Calendar](https://developers.google.com/workspace/calendar/api/auth), [Drive](https://developers.google.com/workspace/drive/api/guides/api-specific-auth), [Sheets](https://developers.google.com/workspace/sheets/api/scopes) |
| Microsoft Graph (delegated) | 15 | 15 | [Permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference) |
| Slack (bot scopes) | 12 | 12 | [Scopes](https://docs.slack.dev/reference/scopes) |
| HubSpot | 12 | 12 | [Scopes](https://developers.hubspot.com/docs/apps/legacy-apps/authentication/scopes) |
| QuickBooks Online | 6 | 6 | [Scopes](https://developer.intuit.com/app/developer/qbo/docs/learn/scopes) |
| Stripe (restricted keys) | 13 | 0 (unverified) | [Restricted keys](https://docs.stripe.com/keys/restricted-api-keys), [permission groups](https://docs.stripe.com/stripe-apps/reference/permissions) |
| Shopify Admin API | 12 | 11 | [Access scopes](https://shopify.dev/docs/api/usage/access-scopes) |

Why some entries are unverified:

- **Stripe:** the restricted-key page documents the None/Read/Write levels, but not the resource labels. The labels used here ("Charges and Refunds", "Payment Intents", ...) come from Stripe's published permission groups.
- **`shopify.refund_order`:** the `refundCreate` docs say it needs "orders" access, and `write_orders` is inferred from that.

Run `permission-planner list` for the full table with links.

Deduplication uses only documented coverage. For example, `gmail.compose` includes sending, so `gmail.send` is dropped when both are needed. Stripe `Write` implies `Read`. HubSpot `.write` does **not** imply `.read`, so both are kept.

## Library use

```ts
import { plan, formatPlanMarkdown, CATALOG } from "@teamshift/permission-planner";

const result = plan(["gmail.send", "hubspot.write_deals", "stripe.refund"], { currentScopes: ["https://mail.google.com/"] });
result.providers;   // minimum scopes per provider, with neededBy
result.approvals;   // policy per risk tier
result.unknown;     // actions with no catalog entry, listed explicitly
```

## FAQ

### What Gmail scope do I need to send email from an AI agent?

`https://www.googleapis.com/auth/gmail.send`. It is send-only (it cannot read the mailbox) and Google classifies it as *sensitive*, not restricted. Avoid `https://mail.google.com/`, which is full mailbox access, and `gmail.modify`, which also reads. Both are restricted scopes and trigger stricter Google verification.

### What is the minimum Gmail scope to read email?

`https://www.googleapis.com/auth/gmail.readonly` (restricted). If headers and labels are enough, `gmail.metadata` avoids reading bodies, though it is also restricted.

### What is the difference between Google sensitive and restricted scopes?

Google labels scopes non-sensitive, sensitive or restricted. Sensitive scopes need OAuth app verification before external users can grant them. Restricted scopes, which cover most Gmail read access and full Drive access, need verification and can also require a third-party security assessment. permission-planner shows the classification next to each Google scope.

### Which Microsoft Graph permission lets an agent send email?

`Mail.Send` (delegated). It doesn't include reading mail, which is `Mail.Read`. As a delegated permission it doesn't need admin consent. The application-permission version applies to every mailbox in the tenant and does.

### Does QuickBooks Online have a read-only scope?

No. `com.intuit.quickbooks.accounting` grants read and write access to all accounting data, so enforce read-only behavior and approvals inside your agent.

### Which Slack scope does a bot need to post messages?

`chat:write` for channels the bot is a member of, plus `chat:write.public` to post in public channels without joining. `chat:write` also lets the bot edit and delete its own messages.

### What Stripe restricted key permissions does an agent need to issue refunds?

Write access to "Charges and Refunds". Stripe groups refunds with charges. Use a restricted key (`rk_…`), never the secret key. This catalog marks the Stripe labels **unverified**, so confirm them in the Dashboard when you create the key.

### Which actions should an AI agent never do without human approval?

Moving money (charges, refunds, payouts, recording payments) and destructive actions (deleting records, files or email) should always need explicit approval. External sends should need approval until the agent has a track record. [workflow-lint](../workflow-lint) enforces the same policy on workflow definitions (rule WL004).

### What if my action isn't in the catalog?

The planner lists it under **Unknown actions**, suggests close matches from the same provider, and never substitutes a broad scope. To add the entry, open a PR with the official `source` URL (see [CONTRIBUTING.md](../../CONTRIBUTING.md)).

## Related tools

- [workflow-lint](../workflow-lint): preflight checks for agent and automation workflows.
- [webhook-inspect](../webhook-inspect): verify and debug webhook signatures.

---

Built by [TeamShift](https://teamshift.io/open-source/agent-toolkit?utm_source=github&utm_medium=readme) — AI workers for small-business operations.
