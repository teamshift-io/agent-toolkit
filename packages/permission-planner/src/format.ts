import type { CatalogEntry } from "./data/catalog.js";
import type { Plan } from "./planner.js";

const cell = (s: string): string => s.replace(/\|/g, "\\|");

export function formatPlanMarkdown(p: Plan): string {
  const out: string[] = ["# Permission plan", ""];
  if (p.highestTier) out.push(`Highest risk tier: **${p.highestTier}** · ${p.actions.length} action(s) · ${p.providers.length} provider(s)${p.unknown.length ? ` · ${p.unknown.length} unknown` : ""}`, "");

  for (const prov of p.providers) {
    out.push(`## ${prov.name}`, "", `| ${prov.scopeKind} | provider classification | needed by |`, "|---|---|---|");
    for (const s of prov.scopes) out.push(`| \`${cell(s.scope)}\` | ${s.sensitivity ?? "—"} | ${s.neededBy.join(", ")} |`);
    for (const n of prov.notes) out.push("", `> ${n}`);
    out.push("");
  }

  out.push("## Actions", "", "| action | tier | approval | scopes | verified |", "|---|---|---|---|---|");
  for (const a of p.actions) {
    out.push(`| ${a.action} — ${cell(a.label)} | ${a.tier} | ${a.approval} | ${a.scopes.map((s) => `\`${cell(s)}\``).join(" + ")} | ${a.verified ? "yes" : "**unverified**"} |`);
  }
  out.push("");

  out.push("## Approval policy", "");
  for (const ap of p.approvals) out.push(`- **${ap.tier}** (${ap.policy}): ${ap.summary} — ${ap.actions.join(", ")}`);
  out.push("");

  if (p.warnings.length) {
    out.push("## Warnings", "");
    for (const w of p.warnings) out.push(`- ${w}`);
    out.push("");
  }
  if (p.unknown.length) {
    out.push("## Unknown actions", "");
    for (const u of p.unknown) out.push(`- \`${u.input}\`: ${u.message}${u.suggestions.length ? ` Did you mean: ${u.suggestions.join(", ")}?` : ""}`);
    out.push("");
  }
  out.push("Sources: every scope links to the provider's official documentation in `permission-planner list`.");
  return out.join("\n");
}

export function formatCatalogMarkdown(entries: readonly CatalogEntry[]): string {
  const out = ["| action | provider | scopes | classification | tier | status | source |", "|---|---|---|---|---|---|---|"];
  for (const e of entries) {
    const status = e.verifiedOn && e.status !== "unverified" ? `verified ${e.verifiedOn}` : "unverified";
    out.push(`| ${e.action} | ${e.provider} | ${e.scopes.map((s) => `\`${cell(s)}\``).join(" + ")} | ${e.sensitivity ?? "—"} | ${e.tier} | ${status} | [docs](${e.source}) |`);
  }
  return out.join("\n");
}
