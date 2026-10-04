#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { formatJson, formatPretty, formatSarif, lint, RULE_LIST, VERSION } from "./index.js";
import type { LintResult } from "./index.js";

const HELP = `workflow-lint ${VERSION} — preflight linter for AI-agent and automation workflows

Usage:
  workflow-lint <file...> [--format pretty|json|sarif] [--ignore WL005,WL009] [--no-color]
  workflow-lint --list-rules

Inputs: n8n workflow export JSON, or a workflow-lint spec (YAML/JSON with a "steps" array).
Exit codes: 0 = no errors, 1 = at least one error-severity finding, 2 = usage or parse failure.
Docs: https://github.com/teamshift-io/agent-toolkit/tree/main/packages/workflow-lint
Try it in your browser: https://teamshift.io/tools/workflow-lint`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      format: { type: "string", short: "f", default: "pretty" },
      ignore: { type: "string", multiple: true },
      "no-color": { type: "boolean", default: false },
      "list-rules": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
  });

  if (values.help) {
    console.log(HELP);
    return 0;
  }
  if (values.version) {
    console.log(VERSION);
    return 0;
  }
  if (values["list-rules"]) {
    for (const r of RULE_LIST) console.log(`${r.id}  ${r.severity.padEnd(7)}  ${r.name.padEnd(28)}  ${r.description}`);
    return 0;
  }
  if (positionals.length === 0) {
    console.error(HELP);
    return 2;
  }
  const format = values.format ?? "pretty";
  if (!["pretty", "json", "sarif"].includes(format)) {
    console.error(`Unknown --format "${format}". Use pretty, json or sarif.`);
    return 2;
  }
  const ignore = (values.ignore ?? []).flatMap((v) => v.split(",")).map((v) => v.trim()).filter(Boolean);

  const results: LintResult[] = [];
  for (const file of positionals) {
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch (err) {
      console.error(`workflow-lint: cannot read ${file}: ${(err as Error).message}`);
      return 2;
    }
    try {
      results.push(lint(text, { filename: file, ignore }));
    } catch (err) {
      console.error(`workflow-lint: ${file}: ${(err as Error).message}`);
      return 2;
    }
  }

  const color = !values["no-color"] && process.stdout.isTTY === true && !process.env["NO_COLOR"];
  const output = format === "json" ? formatJson(results) : format === "sarif" ? formatSarif(results) : formatPretty(results, { color });
  console.log(output);
  return results.some((r) => r.summary.errors > 0) ? 1 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(err instanceof Error ? err.stack ?? err.message : String(err));
    process.exitCode = 2;
  },
);
