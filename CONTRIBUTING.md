# Contributing to agent-toolkit

Thanks for helping. These tools are small on purpose: prefer one sharp, well-tested change over a broad one.

## Setup

```bash
corepack pnpm@11.2.2 install
corepack pnpm@11.2.2 build
corepack pnpm@11.2.2 test
corepack pnpm@11.2.2 typecheck
```

All four must pass before you open a PR. Run a single package with `corepack pnpm@11.2.2 --filter @teamshift/workflow-lint test`.

## Ground rules

- **Cores stay browser-safe.** Nothing under `packages/*/src/` except `cli.ts` may import `node:*` modules or Node-only globals such as `Buffer` or `process`. The cores also power in-browser tools at teamshift.io/tools. Check with `grep -rn "from \"node:" packages/*/src --include=*.ts | grep -v cli.ts`, which should print nothing.
- **Minimal dependencies.** Ask in an issue before adding a runtime dependency.
- **Fictional data only.** Fixtures use `.example` domains and 555-01xx phone numbers. Never commit real customer data or anything shaped like a real live key. Tests that need key-shaped strings build them at runtime (see `workflow-lint/test/lint.test.ts`).
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.

## Adding a workflow-lint rule

1. Add the rule metadata to `RULES` in `packages/workflow-lint/src/rules.ts`: the next `WLxxx` id, a kebab-case name, severity, description and fix. The docs anchor is generated from the id and name.
2. Implement the check in `runRules()`. If the rule needs new information about steps, add a field to `NormalizedStep` in `src/types.ts` and populate it in **both** `src/generic.ts` and `src/n8n.ts`, or document why one format doesn't apply.
3. Add tests to `test/lint.test.ts`: at least one case that triggers the rule and one near-miss that must not.
4. Update the fixtures. `test/fixtures/*-bad.*` must trigger every rule, and `test/fixtures/*-good.*` must stay clean. The fixture tests enforce both.
5. Document the rule in `packages/workflow-lint/README.md`: add a row to the rules table and a `### WLxxx rule-name` section, whose heading becomes the docs anchor.

## Adding a webhook-inspect provider

1. Add the provider id to `Provider`/`PROVIDERS` and its signature header to `SIGNATURE_HEADERS` in `src/verify.ts`.
2. Implement `verify<Provider>()` and a `sign()` branch. Use only `src/crypto.ts` (WebCrypto) helpers and constant-time comparison.
3. Add detection to `RULES` in `src/explain.ts` and an `explain<Provider>()` that returns event type, id and key fields. Mask personal data with `mask()`.
4. Add provider-specific checks to `diagnose()` if the provider has a common failure mode.
5. Tests must sign with an **independent implementation** (`node:crypto` in the test file), then verify the result and cover tampered-body, wrong-secret and header cases.
6. Link the provider's official signature documentation in your PR description and add a row to the README providers table.

## Adding or correcting a permission-planner catalog entry

Catalog entries live in `packages/permission-planner/src/data/catalog.ts`.

Required for every entry:

- `source`: the URL of the provider's **official** documentation page where the scope is listed. Blogs, Stack Overflow and AI answers don't count.
- `scopes`: the exact strings as documented. Never guess a scope name.
- `tier`: one of `read`, `write-internal`, `send-external`, `money`, `destructive`. Pick the higher tier when in doubt.
- Either `verifiedOn: "YYYY-MM-DD"`, if you personally read the exact scope string on the `source` page that day, **or** `status: "unverified"`. Never both.
- `sensitivity`: only when the provider publishes a classification (for example Google's non-sensitive / sensitive / restricted).

If a broader scope documentably includes a narrower one, add it to that provider's `covers` map so the planner can dedupe. Only add relationships the provider's docs state.

For corrections, open a "Catalog correction" issue or PR with the official link and a quote of the relevant line.

## Pull requests

- Reference an issue (`Fixes #123`) when one exists.
- Include the commands you ran and their results.
- Keep README examples real: paste actual CLI output, trimmed if long.
