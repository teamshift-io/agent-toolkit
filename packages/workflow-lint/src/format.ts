import { RULE_LIST } from "./rules.js";
import type { LintResult, Severity } from "./types.js";

export const VERSION = "0.1.0";

const ANSI = { red: "\u001b[31m", yellow: "\u001b[33m", blue: "\u001b[34m", dim: "\u001b[2m", bold: "\u001b[1m", green: "\u001b[32m", reset: "\u001b[0m" };

export function formatPretty(results: LintResult[], opts: { color?: boolean } = {}): string {
  const c = (code: keyof typeof ANSI, s: string): string => (opts.color ? `${ANSI[code]}${s}${ANSI.reset}` : s);
  const sev: Record<Severity, string> = { error: c("red", "error  "), warning: c("yellow", "warning"), info: c("blue", "info   ") };
  const out: string[] = [];
  let errors = 0;
  let warnings = 0;
  for (const r of results) {
    errors += r.summary.errors;
    warnings += r.summary.warnings;
    out.push(c("bold", `${r.file ?? r.workflow}`) + c("dim", `  (${r.format}, ${r.stepCount} steps, workflow "${r.workflow}")`));
    if (r.findings.length === 0) {
      out.push(`  ${c("green", "✓ no problems found")}`);
    }
    for (const f of r.findings) {
      const loc = f.line ? `line ${f.line}` : f.path;
      out.push(`  ${sev[f.severity]}  ${c("bold", f.ruleId)} ${f.ruleName}  ${c("dim", loc)}`);
      out.push(`           ${f.message}`);
      out.push(`           ${c("dim", `fix: ${f.fix}`)}`);
      out.push(`           ${c("dim", f.docs)}`);
    }
    out.push("");
  }
  const total = errors + warnings;
  const line = `${total} problem${total === 1 ? "" : "s"} (${errors} error${errors === 1 ? "" : "s"}, ${warnings} warning${warnings === 1 ? "" : "s"})`;
  out.push(errors > 0 ? c("red", c("bold", `✖ ${line}`)) : total > 0 ? c("yellow", `⚠ ${line}`) : c("green", "✓ 0 problems"));
  return out.join("\n");
}

export function formatJson(results: LintResult[]): string {
  return JSON.stringify(results.length === 1 ? results[0] : results, null, 2);
}

const SARIF_LEVEL: Record<Severity, string> = { error: "error", warning: "warning", info: "note" };

/** SARIF 2.1.0 log, consumable by GitHub code scanning and most CI tools. */
export function formatSarif(results: LintResult[]): string {
  const log = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "workflow-lint",
            version: VERSION,
            informationUri: "https://teamshift.io/tools/workflow-lint",
            rules: RULE_LIST.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.description },
              help: { text: r.fix },
              helpUri: r.docs,
              defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
            })),
          },
        },
        results: results.flatMap((r) =>
          r.findings.map((f) => ({
            ruleId: f.ruleId,
            level: SARIF_LEVEL[f.severity],
            message: { text: `${f.message} Fix: ${f.fix}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: (r.file ?? "workflow").replace(/\\/g, "/") },
                  ...(f.line ? { region: { startLine: f.line } } : {}),
                },
                logicalLocations: [{ fullyQualifiedName: f.path }],
              },
            ],
          })),
        ),
      },
    ],
  };
  return JSON.stringify(log, null, 2);
}
