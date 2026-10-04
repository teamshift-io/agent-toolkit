/** WebCrypto helpers. Works in browsers, Deno, Bun, Cloudflare Workers and Node.js >= 20. */

export type HashAlg = "SHA-1" | "SHA-256" | "SHA-512";
export type Encoding = "hex" | "base64";

const enc = new TextEncoder();

function subtle(): (typeof globalThis.crypto)["subtle"] {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("WebCrypto (globalThis.crypto.subtle) is not available in this runtime.");
  return s;
}

export function toBytes(data: string | Uint8Array): Uint8Array {
  return typeof data === "string" ? enc.encode(data) : data;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64(b64: string): Uint8Array | undefined {
  try {
    const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return undefined;
  }
}

export function fromHex(hex: string): Uint8Array | undefined {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex)) return undefined;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function encode(bytes: Uint8Array, encoding: Encoding): string {
  return encoding === "hex" ? toHex(bytes) : toBase64(bytes);
}

// TS 5.7+ types Uint8Array generically; WebCrypto wants an ArrayBuffer-backed view.
const buf = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer;

export async function hmac(alg: HashAlg, key: string | Uint8Array, data: string | Uint8Array, encoding: Encoding): Promise<string> {
  const k = await subtle().importKey("raw", buf(toBytes(key)), { name: "HMAC", hash: alg }, false, ["sign"]);
  const sig = await subtle().sign("HMAC", k, buf(toBytes(data)));
  return encode(new Uint8Array(sig), encoding);
}

export async function digest(alg: HashAlg, data: string | Uint8Array, encoding: Encoding): Promise<string> {
  const d = await subtle().digest(alg, buf(toBytes(data)));
  return encode(new Uint8Array(d), encoding);
}

/** Constant-time string comparison (length is not secret). */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
