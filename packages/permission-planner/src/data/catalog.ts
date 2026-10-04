/**
 * Curated map of agent actions -> minimum OAuth scopes / API permissions.
 *
 * Rules for this file (see CONTRIBUTING.md):
 * - Every entry has a `source` URL pointing at the provider's official documentation.
 * - `verifiedOn` is set only when a maintainer read the exact scope string on that page.
 *   Otherwise the entry carries `status: "unverified"` and the planner says so.
 * - Never guess a scope name. Prefer fewer, correct entries.
 */

export type RiskTier = "read" | "write-internal" | "send-external" | "money" | "destructive";
export type ProviderId = "google" | "microsoft" | "slack" | "hubspot" | "quickbooks" | "stripe" | "shopify";

export interface CatalogEntry {
  provider: ProviderId;
  /** Globally unique action id, e.g. `gmail.send`. */
  action: string;
  label: string;
  /** Minimum scopes/permissions; all are required. */
  scopes: string[];
  /** Provider's own classification, when documented (e.g. Google "restricted"). */
  sensitivity?: string;
  tier: RiskTier;
  /** Official documentation page the scope was checked against. */
  source: string;
  verifiedOn?: string;
  status?: "unverified";
  notes?: string;
}

export interface ProviderInfo {
  id: ProviderId;
  name: string;
  /** What a "scope" is called for this provider. */
  scopeKind: string;
  docs: string;
  /** Provider-wide caveats shown in every plan that touches it. */
  notes?: string[];
  /** Documented "broader scope X also grants narrower scope Y" relationships, used to dedupe. */
  covers?: Record<string, string[]>;
}

const VERIFIED = "2026-10-03";

const GMAIL = "https://developers.google.com/workspace/gmail/api/auth/scopes";
const GCAL = "https://developers.google.com/workspace/calendar/api/auth";
const GDRIVE = "https://developers.google.com/workspace/drive/api/guides/api-specific-auth";
const GSHEETS = "https://developers.google.com/workspace/sheets/api/scopes";
const GRAPH = "https://learn.microsoft.com/en-us/graph/permissions-reference";
const SLACK = "https://docs.slack.dev/reference/scopes";
const HUBSPOT = "https://developers.hubspot.com/docs/apps/legacy-apps/authentication/scopes";
const QBO = "https://developer.intuit.com/app/developer/qbo/docs/learn/scopes";
const STRIPE = "https://docs.stripe.com/keys/restricted-api-keys";
const STRIPE_PERMS = "https://docs.stripe.com/stripe-apps/reference/permissions";
const SHOPIFY = "https://shopify.dev/docs/api/usage/access-scopes";

const g = (s: string): string => `https://www.googleapis.com/auth/${s}`;

export const PROVIDERS: Record<ProviderId, ProviderInfo> = {
  google: {
    id: "google",
    name: "Google Workspace (Gmail, Calendar, Drive, Sheets)",
    scopeKind: "OAuth 2.0 scope",
    docs: "https://developers.google.com/identity/protocols/oauth2/scopes",
    notes: [
      "Restricted scopes require Google OAuth app verification and can require a third-party security assessment for apps used outside your own Workspace organization.",
      "Sensitive scopes require OAuth app verification before external users can grant them.",
    ],
    covers: {
      "https://mail.google.com/": [g("gmail.readonly"), g("gmail.metadata"), g("gmail.compose"), g("gmail.send"), g("gmail.modify"), g("gmail.labels")],
      [g("gmail.modify")]: [g("gmail.readonly"), g("gmail.compose"), g("gmail.send")],
      [g("gmail.compose")]: [g("gmail.send")],
      [g("calendar")]: [g("calendar.readonly"), g("calendar.events"), g("calendar.events.readonly")],
      [g("calendar.events")]: [g("calendar.events.readonly")],
      [g("drive")]: [g("drive.readonly"), g("drive.file")],
      [g("spreadsheets")]: [g("spreadsheets.readonly")],
    },
  },
  microsoft: {
    id: "microsoft",
    name: "Microsoft Graph (Outlook, Calendar, OneDrive, Teams)",
    scopeKind: "delegated permission",
    docs: GRAPH,
    notes: [
      "Listed permissions are delegated (the agent acts as the signed-in user); none of them needs admin consent as a delegated permission.",
      "The Application-permission versions of Mail.*, Calendars.*, Contacts.* and Files.ReadWrite.All require admin consent and apply to every mailbox/drive in the tenant. Avoid them for single-user agents.",
    ],
    covers: {
      "Mail.ReadWrite": ["Mail.Read", "Mail.ReadBasic"],
      "Mail.Read": ["Mail.ReadBasic"],
      "Calendars.ReadWrite": ["Calendars.Read"],
      "Files.ReadWrite.All": ["Files.ReadWrite", "Files.Read"],
      "Files.ReadWrite": ["Files.Read"],
      "Contacts.ReadWrite": ["Contacts.Read"],
    },
  },
  slack: {
    id: "slack",
    name: "Slack",
    scopeKind: "bot token scope",
    docs: SLACK,
    notes: ["Scopes listed are bot-token scopes. Messages in Slack Connect channels reach people outside your organization; treat those posts as send-external."],
  },
  hubspot: {
    id: "hubspot",
    name: "HubSpot CRM",
    scopeKind: "OAuth scope",
    docs: HUBSPOT,
    notes: ["HubSpot `.write` scopes do not imply `.read`; request both when the agent reads and writes the same object.", "Deleting records uses the object's `.write` scope; there is no separate delete scope, so enforce delete approval in the agent."],
  },
  quickbooks: {
    id: "quickbooks",
    name: "QuickBooks Online",
    scopeKind: "OAuth scope",
    docs: QBO,
    notes: [
      "QuickBooks has no read-only accounting scope: com.intuit.quickbooks.accounting grants read AND write to all accounting data. Enforce read-only or approval rules inside the agent.",
    ],
  },
  stripe: {
    id: "stripe",
    name: "Stripe (restricted API key)",
    scopeKind: "restricted key permission",
    docs: STRIPE,
    notes: [
      "Use a restricted key (rk_...), never the secret key (sk_...). Each resource is None / Read / Write; Write implies Read.",
      "Resource names follow Stripe's published permission groups; confirm the exact label in Dashboard → Developers → API keys → Create restricted key.",
    ],
    covers: {
      "Customers: Write": ["Customers: Read"],
      "Charges and Refunds: Write": ["Charges and Refunds: Read"],
      "Payment Intents: Write": ["Payment Intents: Read"],
      "Invoices: Write": ["Invoices: Read"],
      "Checkout Sessions: Write": ["Checkout Sessions: Read"],
      "Products: Write": ["Products: Read"],
      "Prices: Write": ["Prices: Read"],
      "Payouts: Write": ["Payouts: Read"],
    },
  },
  shopify: {
    id: "shopify",
    name: "Shopify Admin API",
    scopeKind: "access scope",
    docs: SHOPIFY,
    notes: [
      "read_orders/write_orders cover orders from the last 60 days; older orders need read_all_orders, which requires Shopify approval.",
      "Customer names, emails, phones and addresses are protected customer data: apps get none by default and must request access separately.",
    ],
  },
};

type E = Omit<CatalogEntry, "provider">;
const google = (e: E): CatalogEntry => ({ provider: "google", ...e });
const ms = (e: E): CatalogEntry => ({ provider: "microsoft", ...e });
const slack = (e: E): CatalogEntry => ({ provider: "slack", ...e });
const hubspot = (e: E): CatalogEntry => ({ provider: "hubspot", ...e });
const qbo = (e: E): CatalogEntry => ({ provider: "quickbooks", ...e });
const stripe = (e: E): CatalogEntry => ({ provider: "stripe", ...e });
const shopify = (e: E): CatalogEntry => ({ provider: "shopify", ...e });

const GRAPH_NOTE = "Delegated permission; admin consent not required for delegated use.";

export const CATALOG: readonly CatalogEntry[] = [
  // ---------------- Google: Gmail ----------------
  google({ action: "gmail.read", label: "Read email messages and threads", scopes: [g("gmail.readonly")], sensitivity: "restricted", tier: "read", source: GMAIL, verifiedOn: VERIFIED }),
  google({ action: "gmail.read_metadata", label: "Read message headers and labels (no bodies)", scopes: [g("gmail.metadata")], sensitivity: "restricted", tier: "read", source: GMAIL, verifiedOn: VERIFIED }),
  google({ action: "gmail.send", label: "Send email", scopes: [g("gmail.send")], sensitivity: "sensitive", tier: "send-external", source: GMAIL, verifiedOn: VERIFIED, notes: "Send-only; cannot read the mailbox. The narrowest way to let an agent send." }),
  google({ action: "gmail.draft", label: "Create and edit drafts", scopes: [g("gmail.compose")], sensitivity: "restricted", tier: "write-internal", source: GMAIL, verifiedOn: VERIFIED, notes: "gmail.compose also permits sending. If the agent must never send, enforce that in code; Google has no drafts-only scope." }),
  google({ action: "gmail.manage_labels", label: "Create, rename and delete labels", scopes: [g("gmail.labels")], sensitivity: "non-sensitive", tier: "write-internal", source: GMAIL, verifiedOn: VERIFIED }),
  google({ action: "gmail.organize", label: "Apply labels, archive, mark read/unread", scopes: [g("gmail.modify")], sensitivity: "restricted", tier: "write-internal", source: GMAIL, verifiedOn: VERIFIED, notes: "gmail.modify also grants reading, composing and sending email." }),
  google({ action: "gmail.trash", label: "Move messages to trash", scopes: [g("gmail.modify")], sensitivity: "restricted", tier: "destructive", source: GMAIL, verifiedOn: VERIFIED, notes: "Trash is recoverable for 30 days. gmail.modify cannot permanently delete." }),
  google({ action: "gmail.delete_permanently", label: "Permanently delete messages (bypass trash)", scopes: ["https://mail.google.com/"], sensitivity: "restricted", tier: "destructive", source: GMAIL, verifiedOn: VERIFIED, notes: "Full mailbox access. Google documents this as the only scope for immediate permanent deletion; prefer trash." }),

  // ---------------- Google: Calendar ----------------
  google({ action: "gcal.read_events", label: "Read calendar events", scopes: [g("calendar.events.readonly")], tier: "read", source: GCAL, verifiedOn: VERIFIED }),
  google({ action: "gcal.read_calendars", label: "Read calendars and their settings", scopes: [g("calendar.readonly")], tier: "read", source: GCAL, verifiedOn: VERIFIED }),
  google({ action: "gcal.write_events", label: "Create and update events (no external guests)", scopes: [g("calendar.events")], tier: "write-internal", source: GCAL, verifiedOn: VERIFIED }),
  google({ action: "gcal.invite_attendees", label: "Create events that invite external attendees", scopes: [g("calendar.events")], tier: "send-external", source: GCAL, verifiedOn: VERIFIED, notes: "Same scope as gcal.write_events, but invitations email people outside the business." }),
  google({ action: "gcal.delete_events", label: "Delete events", scopes: [g("calendar.events")], tier: "destructive", source: GCAL, verifiedOn: VERIFIED }),

  // ---------------- Google: Drive ----------------
  google({ action: "gdrive.app_files", label: "Create files and edit files the user opened with the app", scopes: [g("drive.file")], sensitivity: "non-sensitive", tier: "write-internal", source: GDRIVE, verifiedOn: VERIFIED, notes: "Google's recommended scope. Pair with the Google Picker to let users choose existing files." }),
  google({ action: "gdrive.read_all", label: "Read all files in the user's Drive", scopes: [g("drive.readonly")], sensitivity: "restricted", tier: "read", source: GDRIVE, verifiedOn: VERIFIED, notes: "Consider drive.file + Picker instead; it is non-sensitive." }),
  google({ action: "gdrive.edit_all", label: "Edit any file in the user's Drive", scopes: [g("drive")], sensitivity: "restricted", tier: "write-internal", source: GDRIVE, verifiedOn: VERIFIED }),
  google({ action: "gdrive.delete_any", label: "Delete any file in the user's Drive", scopes: [g("drive")], sensitivity: "restricted", tier: "destructive", source: GDRIVE, verifiedOn: VERIFIED }),

  // ---------------- Google: Sheets ----------------
  google({ action: "gsheets.read", label: "Read spreadsheets", scopes: [g("spreadsheets.readonly")], sensitivity: "sensitive", tier: "read", source: GSHEETS, verifiedOn: VERIFIED, notes: "If the agent only touches sheets it created or the user picked, drive.file (non-sensitive) is narrower." }),
  google({ action: "gsheets.write", label: "Edit spreadsheets (append rows, update cells)", scopes: [g("spreadsheets")], sensitivity: "sensitive", tier: "write-internal", source: GSHEETS, verifiedOn: VERIFIED, notes: "If the agent only touches sheets it created or the user picked, drive.file (non-sensitive) is narrower." }),

  // ---------------- Microsoft Graph ----------------
  ms({ action: "outlook.read_mail_basic", label: "Read mail headers/metadata without bodies or attachments", scopes: ["Mail.ReadBasic"], tier: "read", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "outlook.read_mail", label: "Read mail", scopes: ["Mail.Read"], tier: "read", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "outlook.send_mail", label: "Send mail as the user", scopes: ["Mail.Send"], tier: "send-external", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "outlook.draft", label: "Create drafts, move and flag messages", scopes: ["Mail.ReadWrite"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: `${GRAPH_NOTE} Mail.ReadWrite does not include sending (that is Mail.Send).` }),
  ms({ action: "outlook.delete_mail", label: "Delete messages", scopes: ["Mail.ReadWrite"], tier: "destructive", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "outlook.read_calendar", label: "Read calendars and events", scopes: ["Calendars.Read"], tier: "read", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "outlook.write_calendar", label: "Create, update and delete events", scopes: ["Calendars.ReadWrite"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: `${GRAPH_NOTE} Inviting external attendees emails them; gate those with approval.` }),
  ms({ action: "outlook.read_contacts", label: "Read contacts", scopes: ["Contacts.Read"], tier: "read", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "outlook.write_contacts", label: "Create and update contacts", scopes: ["Contacts.ReadWrite"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "onedrive.read_files", label: "Read the user's files", scopes: ["Files.Read"], tier: "read", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "onedrive.write_files", label: "Create, edit and delete the user's files", scopes: ["Files.ReadWrite"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "onedrive.write_shared_files", label: "Edit all files the user can access (including shared)", scopes: ["Files.ReadWrite.All"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: `${GRAPH_NOTE} Much broader than Files.ReadWrite.` }),
  ms({ action: "teams.send_chat", label: "Send Teams chat messages", scopes: ["ChatMessage.Send"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: `${GRAPH_NOTE} Chats with external/guest users reach outside the business.` }),
  ms({ action: "teams.send_channel", label: "Post Teams channel messages", scopes: ["ChannelMessage.Send"], tier: "write-internal", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),
  ms({ action: "graph.read_profile", label: "Sign in and read the user's profile", scopes: ["User.Read"], tier: "read", source: GRAPH, verifiedOn: VERIFIED, notes: GRAPH_NOTE }),

  // ---------------- Slack ----------------
  slack({ action: "slack.post_message", label: "Post messages in channels the bot is in", scopes: ["chat:write"], tier: "write-internal", source: SLACK, verifiedOn: VERIFIED, notes: "chat:write also lets the bot edit and delete its own messages." }),
  slack({ action: "slack.post_any_public_channel", label: "Post in public channels without joining", scopes: ["chat:write", "chat:write.public"], tier: "write-internal", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.delete_own_message", label: "Delete messages the bot posted", scopes: ["chat:write"], tier: "destructive", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.list_channels", label: "List public channels", scopes: ["channels:read"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.read_public_history", label: "Read messages in public channels", scopes: ["channels:history"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.read_private_history", label: "Read messages in private channels the bot is in", scopes: ["groups:history"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.read_dms", label: "Read direct messages with the bot", scopes: ["im:history"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.read_users", label: "Read workspace members", scopes: ["users:read"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.read_user_emails", label: "Read members' email addresses", scopes: ["users:read", "users:read.email"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.read_files", label: "Read files the bot can access", scopes: ["files:read"], tier: "read", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.upload_file", label: "Upload, edit and delete files", scopes: ["files:write"], tier: "write-internal", source: SLACK, verifiedOn: VERIFIED }),
  slack({ action: "slack.add_reaction", label: "Add and remove emoji reactions", scopes: ["reactions:write"], tier: "write-internal", source: SLACK, verifiedOn: VERIFIED }),

  // ---------------- HubSpot ----------------
  hubspot({ action: "hubspot.read_contacts", label: "Read contacts", scopes: ["crm.objects.contacts.read"], tier: "read", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.write_contacts", label: "Create and update contacts", scopes: ["crm.objects.contacts.write"], tier: "write-internal", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.delete_contacts", label: "Delete contacts", scopes: ["crm.objects.contacts.write"], tier: "destructive", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.read_companies", label: "Read companies", scopes: ["crm.objects.companies.read"], tier: "read", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.write_companies", label: "Create and update companies", scopes: ["crm.objects.companies.write"], tier: "write-internal", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.delete_companies", label: "Delete companies", scopes: ["crm.objects.companies.write"], tier: "destructive", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.read_deals", label: "Read deals", scopes: ["crm.objects.deals.read"], tier: "read", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.write_deals", label: "Create and update deals", scopes: ["crm.objects.deals.write"], tier: "write-internal", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.delete_deals", label: "Delete deals", scopes: ["crm.objects.deals.write"], tier: "destructive", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.read_tickets", label: "Read tickets", scopes: ["tickets"], tier: "read", source: HUBSPOT, verifiedOn: VERIFIED, notes: "`tickets` is a single scope covering read and write." }),
  hubspot({ action: "hubspot.write_tickets", label: "Create and update tickets", scopes: ["tickets"], tier: "write-internal", source: HUBSPOT, verifiedOn: VERIFIED }),
  hubspot({ action: "hubspot.read_owners", label: "Read record owners (users)", scopes: ["crm.objects.owners.read"], tier: "read", source: HUBSPOT, verifiedOn: VERIFIED }),

  // ---------------- QuickBooks Online ----------------
  qbo({ action: "qbo.read_accounting", label: "Read customers, invoices, bills and reports", scopes: ["com.intuit.quickbooks.accounting"], tier: "read", source: QBO, verifiedOn: VERIFIED, notes: "No read-only scope exists; this scope also allows writes." }),
  qbo({ action: "qbo.create_invoice", label: "Create or update invoices (not sent)", scopes: ["com.intuit.quickbooks.accounting"], tier: "write-internal", source: QBO, verifiedOn: VERIFIED }),
  qbo({ action: "qbo.send_invoice", label: "Email an invoice to a customer", scopes: ["com.intuit.quickbooks.accounting"], tier: "send-external", source: QBO, verifiedOn: VERIFIED }),
  qbo({ action: "qbo.record_payment", label: "Record a customer payment or bill payment", scopes: ["com.intuit.quickbooks.accounting"], tier: "money", source: QBO, verifiedOn: VERIFIED, notes: "Changes the books (A/R, A/P, bank balances) even though no money moves." }),
  qbo({ action: "qbo.delete_transaction", label: "Delete or void transactions", scopes: ["com.intuit.quickbooks.accounting"], tier: "destructive", source: QBO, verifiedOn: VERIFIED }),
  qbo({ action: "qbo.charge_card", label: "Charge a card via QuickBooks Payments", scopes: ["com.intuit.quickbooks.payment"], tier: "money", source: QBO, verifiedOn: VERIFIED, notes: "QuickBooks Payments scope is US-only." }),

  // ---------------- Stripe (restricted key permissions) ----------------
  stripe({ action: "stripe.read_customers", label: "Read customers", scopes: ["Customers: Read"], tier: "read", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.write_customers", label: "Create and update customers", scopes: ["Customers: Write"], tier: "write-internal", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.delete_customers", label: "Delete customers", scopes: ["Customers: Write"], tier: "destructive", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.read_charges", label: "Read charges and refunds", scopes: ["Charges and Refunds: Read"], tier: "read", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.refund", label: "Create refunds", scopes: ["Charges and Refunds: Write"], tier: "money", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.create_payment_intent", label: "Create and confirm PaymentIntents (charge customers)", scopes: ["Payment Intents: Write"], tier: "money", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.create_invoice", label: "Create draft invoices", scopes: ["Invoices: Write"], tier: "write-internal", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.send_invoice", label: "Finalize and send invoices to customers", scopes: ["Invoices: Write"], tier: "send-external", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.create_checkout_session", label: "Create Checkout Sessions (payment links for customers)", scopes: ["Checkout Sessions: Write"], tier: "write-internal", source: STRIPE_PERMS, status: "unverified", notes: "No money moves until the customer pays." }),
  stripe({ action: "stripe.write_products", label: "Create and update products", scopes: ["Products: Write"], tier: "write-internal", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.write_prices", label: "Create and update prices", scopes: ["Prices: Write"], tier: "write-internal", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.read_balance", label: "Read account balance", scopes: ["Balance: Read"], tier: "read", source: STRIPE_PERMS, status: "unverified" }),
  stripe({ action: "stripe.create_payout", label: "Create payouts to the bank account", scopes: ["Payouts: Write"], tier: "money", source: STRIPE_PERMS, status: "unverified" }),

  // ---------------- Shopify Admin API ----------------
  shopify({ action: "shopify.read_products", label: "Read products", scopes: ["read_products"], tier: "read", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.write_products", label: "Create and update products", scopes: ["write_products"], tier: "write-internal", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.read_orders", label: "Read orders (last 60 days)", scopes: ["read_orders"], tier: "read", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.read_all_orders", label: "Read orders older than 60 days", scopes: ["read_orders", "read_all_orders"], tier: "read", source: SHOPIFY, verifiedOn: VERIFIED, notes: "read_all_orders requires Shopify approval." }),
  shopify({ action: "shopify.write_orders", label: "Edit orders", scopes: ["write_orders"], tier: "write-internal", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.refund_order", label: "Refund an order", scopes: ["write_orders"], tier: "money", source: "https://shopify.dev/docs/api/admin-graphql/latest/mutations/refundCreate", status: "unverified", notes: "refundCreate docs say it requires `orders` access; write_orders is the inferred scope." }),
  shopify({ action: "shopify.read_customers", label: "Read customers", scopes: ["read_customers"], tier: "read", source: SHOPIFY, verifiedOn: VERIFIED, notes: "Protected customer data access must be requested separately." }),
  shopify({ action: "shopify.write_customers", label: "Create and update customers", scopes: ["write_customers"], tier: "write-internal", source: SHOPIFY, verifiedOn: VERIFIED, notes: "Protected customer data access must be requested separately." }),
  shopify({ action: "shopify.read_inventory", label: "Read inventory levels", scopes: ["read_inventory"], tier: "read", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.write_inventory", label: "Adjust inventory levels", scopes: ["write_inventory"], tier: "write-internal", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.read_draft_orders", label: "Read draft orders", scopes: ["read_draft_orders"], tier: "read", source: SHOPIFY, verifiedOn: VERIFIED }),
  shopify({ action: "shopify.write_draft_orders", label: "Create and update draft orders", scopes: ["write_draft_orders"], tier: "write-internal", source: SHOPIFY, verifiedOn: VERIFIED }),
];
