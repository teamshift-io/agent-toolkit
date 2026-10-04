/**
 * @teamshift/permission-planner — browser-safe core. No Node.js built-ins are imported here.
 */
export { CATALOG, PROVIDERS } from "./data/catalog.js";
export type { CatalogEntry, ProviderId, ProviderInfo, RiskTier } from "./data/catalog.js";
export { plan, parseActions, findAction, suggest, resolveProvider, APPROVAL_POLICIES, TIER_ORDER } from "./planner.js";
export type { ActionRequest, ApprovalPolicy, Plan, PlanOptions, PlannedAction, PlannedScope, ProviderPlan, UnknownAction } from "./planner.js";
export { formatPlanMarkdown, formatCatalogMarkdown } from "./format.js";
