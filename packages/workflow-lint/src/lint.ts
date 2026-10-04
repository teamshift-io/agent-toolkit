import { parse as parseYaml } from "yaml";
import { looksGeneric, normalizeGeneric } from "./generic.js";
import { looksN8n, normalizeN8n } from "./n8n.js";
import { RULE_LIST, runRules } from "./rules.js";
import type { Finding, LintOptions, LintResult, NormalizedWorkflow, Severity } from "./types.js";

export class WorkflowParseError extends Error {
  override name = "WorkflowParseError";
}

/** Parse JSON or YAML text. JSON is tried first because every JSON document is also YAML. */
export function parseDocument(text: string, filename?: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) throw new WorkflowParseError("Input is empty.");
  const preferJson = filename ? /\.json$/i.test(filename) : trimmed.startsWith("{") || trimmed.startsWith("[");
  if (preferJson) {
    try {
      return JSON.parse(trimmed);
    } catch (err) {
      if (filename && /\.json$/i.test(filename)) throw new WorkflowParseError(`Invalid JSON: ${(err as Error).message}`);
    }
  }
  try {
    return parseYaml(text);
  } catch (err) {
    throw new WorkflowParseError(`Invalid YAML/JSON: ${(err as Error).message}`);
  }
}

/** Detect the input format and convert it to the internal model the rules run on. */
export function normalize(doc: unknown): NormalizedWorkflow {
  // n8n "copy nodes" clipboard JSON and full exports both have nodes + connections.
  if (looksN8n(doc)) return normalizeN8n(doc);
  if (looksGeneric(doc)) return normalizeGeneric(doc);
  throw new WorkflowParseError(
    "Unrecognized workflow format. Expected an n8n export (`nodes` + `connections`) or a workflow-lint spec with a `steps` array.",
  );
}

function locate(lines: string[], f: Finding): number | undefined {
  if (!f.stepId) return undefined;
  const needles = [`"${f.stepId}"`, `'${f.stepId}'`, ` ${f.stepId}`];
  const i = lines.findIndex((l) => /\b(id|name)\b/.test(l) && needles.some((n) => l.includes(n)));
  return i >= 0 ? i + 1 : undefined;
}

const ORDER: Record<Severity, number> = { error: 0, warning: 1, info: 2 };

/** Lint already-parsed workflow text (JSON or YAML). Pure and browser-safe. */
export function lint(text: string, options: LintOptions = {}): LintResult {
  const wf = normalize(parseDocument(text, options.filename));
  const ignore = new Set([...(options.ignore ?? []), ...wf.ignore].map((x) => x.toLowerCase()));
  const lines = text.split(/\r?\n/);
  const findings = runRules(wf)
    .filter((f) => !ignore.has(f.ruleId.toLowerCase()) && !ignore.has(f.ruleName.toLowerCase()))
    .map((f) => ({ ...f, line: locate(lines, f) }))
    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || (a.line ?? 0) - (b.line ?? 0) || a.ruleId.localeCompare(b.ruleId));
  const count = (s: Severity): number => findings.filter((f) => f.severity === s).length;
  return {
    workflow: wf.name,
    format: wf.format,
    file: options.filename,
    stepCount: wf.steps.length,
    findings,
    summary: { errors: count("error"), warnings: count("warning"), infos: count("info") },
  };
}

export { RULE_LIST };
