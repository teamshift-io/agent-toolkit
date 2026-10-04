export type Severity = "error" | "warning" | "info";

/** What a step does to the outside world. Ordered from harmless to irreversible. */
export type SideEffect = "none" | "write" | "send" | "money" | "delete";

export type StepKind =
  | "trigger"
  | "http"
  | "email"
  | "message"
  | "llm"
  | "wait"
  | "loop"
  | "code"
  | "payment"
  | "data"
  | "control"
  | "approval"
  | "verify"
  | "other";

export type SourceFormat = "generic" | "n8n";

export interface NormalizedStep {
  /** Stable identifier (generic `id`, n8n node name). */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Raw action / node type. */
  action: string;
  system?: string;
  kind: StepKind;
  sideEffect: SideEffect;
  /** True when the side effect reaches people or systems outside the business (customers, vendors). */
  external: boolean;
  /** True when the step calls a remote system or waits on something (timeout applies). */
  needsTimeout: boolean;
  timeoutSec?: number;
  /** "handled" = explicit error path; "swallowed" = errors silently ignored; "none" = nothing declared. */
  errorHandling: "handled" | "swallowed" | "none";
  retryMaxAttempts?: number;
  idempotencyKey?: string;
  /** True when this step itself is gated by, or preceded by, a human approval. */
  approved: boolean;
  /** For loop / pagination steps. undefined = not a loop. */
  loop?: { bounded: boolean; detail: string };
  isLLM: boolean;
  /** Fields or expressions that look like personal data flowing into this step. */
  piiRefs: string[];
  /** True when the author documented PII handling for this step. */
  piiNote: boolean;
  webhook?: { verified: boolean; detail: string };
  hasCompletionCheck: boolean;
  /** Parameters scanned for secrets. */
  params: unknown;
  /** JSON-ish path used in reports, e.g. `steps[2]` or `nodes["Send invoice"]`. */
  path: string;
}

export interface NormalizedWorkflow {
  name: string;
  format: SourceFormat;
  steps: NormalizedStep[];
  /** True when the workflow declares (or contains) a check that verifies the end state. */
  hasCompletionCheck: boolean;
  /** Extra values scanned for secrets that are not tied to a step (e.g. workflow-level settings). */
  extraParams: Array<{ path: string; value: unknown }>;
  /** Steps that form an execution cycle without a bounded loop construct. */
  unboundedCycles: string[][];
  ignore: string[];
}

export interface RuleMeta {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  fix: string;
  docs: string;
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  message: string;
  fix: string;
  docs: string;
  stepId?: string;
  path: string;
  /** 1-based line in the source text, when it could be located. */
  line?: number;
}

export interface LintResult {
  workflow: string;
  format: SourceFormat;
  file?: string;
  stepCount: number;
  findings: Finding[];
  summary: { errors: number; warnings: number; infos: number };
}

export interface LintOptions {
  /** File name used in reports and to pick the parser (.yaml/.yml vs .json). */
  filename?: string;
  /** Rule ids or names to skip. */
  ignore?: string[];
}
