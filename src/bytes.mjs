// SPDX-License-Identifier: MIT
// Byte helpers shared by the browser page and the CLI. WebCrypto only (browsers, Node >= 20).

const subtle = () => {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Error("webcrypto_unavailable");
  return s;
};

export const utf8 = (text) => new TextEncoder().encode(text);
export const fromUtf8 = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex) {
  if (typeof hex !== "string" || !/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error("hex_invalid");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(text) {
  if (typeof text !== "string" || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error("base64_invalid");
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

/** A fresh ArrayBuffer holding exactly these bytes (WebCrypto and pkijs want ArrayBuffers). */
export function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle().digest("SHA-256", toArrayBuffer(bytes)));
}

export async function sha256Hex(bytes) {
  return toHex(await sha256(bytes));
}

/** PEM (one or more blocks) or raw DER -> list of DER byte arrays. */
export function pemOrDer(bytes) {
  let text = null;
  try { text = fromUtf8(bytes); } catch { /* binary */ }
  if (text && text.includes("-----BEGIN")) {
    const blocks = [...text.matchAll(/-----BEGIN [A-Z0-9 ]+-----([\s\S]*?)-----END [A-Z0-9 ]+-----/g)];
    if (blocks.length === 0) throw new Error("pem_invalid");
    return blocks.map((m) => fromBase64(m[1].replace(/\s+/g, "")));
  }
  return [bytes];
}
