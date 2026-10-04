const SINGLE = new Set(["email", "phone", "mobile", "ssn", "dob", "address", "street", "zip", "zipcode", "postal", "postcode", "passport", "iban", "birthday", "birthdate"]);
const PAIRS: ReadonlyArray<[string, string]> = [
  ["first", "name"],
  ["last", "name"],
  ["full", "name"],
  ["customer", "name"],
  ["card", "number"],
  ["credit", "card"],
  ["date", "birth"],
  ["social", "security"],
  ["tax", "id"],
  ["license", "number"],
];

function tokens(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

/** Return identifiers that look like personal data (email, phone, names, addresses, ...). */
export function piiIdentifiers(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(/[A-Za-z_][A-Za-z0-9_]*/g)) {
    const id = m[0];
    const t = tokens(id);
    const set = new Set(t);
    if (t.some((x) => SINGLE.has(x)) || PAIRS.some(([a, b]) => set.has(a) && set.has(b))) found.add(id);
  }
  return [...found];
}

/** Extract template expressions (`{{ ... }}`) from every string inside a value. */
export function expressions(value: unknown): string[] {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === "string") {
      for (const m of v.matchAll(/\{\{([\s\S]*?)\}\}/g)) out.push(m[1] ?? "");
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(value);
  return out;
}

export function piiRefsIn(value: unknown): string[] {
  return [...new Set(expressions(value).flatMap(piiIdentifiers))];
}

export const PII_NOTE = /\b(pii|personal data|privacy|redact|anonymi[sz]|pseudonymi[sz]|gdpr|ccpa|hipaa|dpa|data processing|consent)\b/i;
