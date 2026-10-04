/** Patterns for common credential shapes. Kept specific to avoid noisy false positives. */
export const SECRET_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
  { name: "Stripe secret/restricted key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { name: "Stripe webhook signing secret", re: /\bwhsec_[A-Za-z0-9+/=]{16,}/ },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "OpenAI API key", re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { name: "AWS access key id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/ },
  { name: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/ },
  { name: "Slack incoming webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Shopify access token", re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/ },
  { name: "Twilio API key", re: /\bSK[0-9a-fA-F]{32}\b/ },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { name: "HubSpot private app token", re: /\bpat-(?:na|eu)\d-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "Basic auth credentials", re: /\bBasic\s+(?![{$=<])[A-Za-z0-9+/]{16,}={0,2}/ },
  { name: "Bearer token", re: /\bBearer\s+(?![{$=<])[A-Za-z0-9._~+/-]{24,}=*/ },
];

const SECRETY_KEY = /(?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?key|secret[_-]?access[_-]?key|token|password|passwd|authorization|private[_-]?key|client[_-]?secret)$/i;

/** Values that are references, not literals: n8n expressions, template vars, env lookups. */
function isReference(value: string): boolean {
  const v = value.trim();
  return (
    v.startsWith("=") ||
    v.includes("{{") ||
    v.includes("${") ||
    /\$env|process\.env|\$secrets|\$vars|\$credentials/i.test(v) ||
    /^<[^>]+>$/.test(v) ||
    /^(?:changeme|xxx+|\*+|redacted|your[_-].*)$/i.test(v)
  );
}

export function redact(secret: string): string {
  if (secret.length <= 8) return "****";
  return `${secret.slice(0, 4)}…${secret.slice(-2)} (${secret.length} chars)`;
}

export interface SecretHit {
  path: string;
  kind: string;
  preview: string;
}

/** Recursively scan a value for hardcoded credentials. */
export function findSecrets(value: unknown, basePath: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const walk = (v: unknown, path: string, key: string | undefined): void => {
    if (typeof v === "string") {
      for (const p of SECRET_PATTERNS) {
        const m = p.re.exec(v);
        if (m) {
          // A Bearer header built from an expression is fine; the regex already excludes `{{`, `$`, `=`.
          hits.push({ path, kind: p.name, preview: redact(m[0].replace(/^(?:Bearer|Basic)\s+/, "")) });
          return;
        }
      }
      if (key && SECRETY_KEY.test(key) && v.length >= 12 && !/\s/.test(v.trim()) && !isReference(v)) {
        hits.push({ path, kind: `literal value in "${key}"`, preview: redact(v.trim()) });
      }
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(item, `${path}[${i}]`, key));
      return;
    }
    if (v && typeof v === "object") {
      const obj = v as Record<string, unknown>;
      // n8n header/query parameter lists: { name: "Authorization", value: "Bearer ..." }
      const pairName = typeof obj["name"] === "string" ? (obj["name"] as string) : undefined;
      for (const [k, child] of Object.entries(obj)) {
        const effectiveKey = k === "value" && pairName ? pairName.replace(/[\s-]/g, "_") : k;
        walk(child, `${path}.${k}`, effectiveKey);
      }
    }
  };
  walk(value, basePath, undefined);
  return hits;
}
