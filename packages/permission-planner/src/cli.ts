#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { CATALOG, formatCatalogMarkdown, formatPlanMarkdown, parseActions, plan, resolveProvider } from "./index.js";

const VERSION = "0.1.0";

const HELP = `permission-planner ${VERSION} — minimum OAuth scopes, risk tiers and approval policy for AI-agent actions

Usage:
  permission-planner plan <actions.yaml|json> [--format md|json] [--current <scope,scope>]
  permission-planner plan --actions gmail.send,slack.post_message [--format md|json]
  permission-planner list [--provider google|microsoft|slack|hubspot|quickbooks|stripe|shopify] [--format md|json]

actions file: a YAML/JSON list (\`- gmail.send\`, \`- google:gmail.send\`, \`- { action: refund, provider: stripe, why: ... }\`)
or an object with \`actions:\` and optional \`currentScopes:\`.
Exit codes: 0 = all actions known, 1 = some actions unknown, 2 = usage error.
Try it in your browser: https://teamshift.io/tools/permission-planner`;

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === undefined || cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return cmd === undefined ? 2 : 0;
  }
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return 0;
  }
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      format: { type: "string", short: "f", default: "md" },
      provider: { type: "string", short: "p" },
      actions: { type: "string", short: "a" },
      current: { type: "string" },
    },
  });
  const format = values.format ?? "md";
  if (format !== "md" && format !== "json") throw new Error(`Unknown --format "${format}". Use md or json.`);

  if (cmd === "list") {
    let entries = CATALOG;
    if (values.provider) {
      const p = resolveProvider(values.provider);
      if (!p) throw new Error(`Unknown provider "${values.provider}".`);
      entries = CATALOG.filter((e) => e.provider === p);
    }
    console.log(format === "json" ? JSON.stringify(entries, null, 2) : formatCatalogMarkdown(entries));
    return 0;
  }

  if (cmd === "plan") {
    let parsed: ReturnType<typeof parseActions>;
    if (values.actions) parsed = parseActions(values.actions);
    else if (positionals[0]) parsed = parseActions(await readFile(positionals[0], "utf8"));
    else throw new Error("plan needs an actions file or --actions a,b,c");
    const current = values.current ? values.current.split(",").map((s) => s.trim()).filter(Boolean) : parsed.currentScopes;
    const result = plan(parsed.actions, { currentScopes: current });
    console.log(format === "json" ? JSON.stringify(result, null, 2) : formatPlanMarkdown(result));
    return result.unknown.length > 0 ? 1 : 0;
  }

  console.error(`Unknown command "${cmd}".\n\n${HELP}`);
  return 2;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(`permission-planner: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  },
);
