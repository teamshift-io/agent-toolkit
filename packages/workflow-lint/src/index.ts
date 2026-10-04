/**
 * @teamshift/workflow-lint — browser-safe core. No Node.js built-ins are imported here.
 */
export { lint, normalize, parseDocument, WorkflowParseError, RULE_LIST } from "./lint.js";
export { RULES } from "./rules.js";
export { formatPretty, formatJson, formatSarif, VERSION } from "./format.js";
export { findSecrets, SECRET_PATTERNS } from "./secrets.js";
export type {
  Finding,
  LintOptions,
  LintResult,
  NormalizedStep,
  NormalizedWorkflow,
  RuleMeta,
  Severity,
  SideEffect,
  SourceFormat,
  StepKind,
} from "./types.js";
