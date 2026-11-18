// SPDX-License-Identifier: MIT
/**
 * crAcken Prove checkpoint (signed note) and leaf format v1.
 *
 * Note text (C2SP tlog-checkpoint + signed-note form, spec text from transparency-dev/formats and C2SP):
 *   <origin>\n<tree size>\n<base64 root>\nrecorded_at <UTC ms ISO>\n\n— <key name> <base64(4-byte key hash || Ed25519 sig)>\n
 * The signature covers the body up to and including its last \n. Key hash = first 4 bytes of
 * SHA-256(name || 0x0A || 0x01 || 32-byte public key). Verifier key text: name+<key hash hex>+base64(0x01 || public key).
 * Leaf data (UTF-8): "cracken:prove-leaf:v1\n<organisation uuid>\n<seq>\n<head hash hex>"; leaf hash = SHA-256(0x00 || data).
 */
import { bytesEqual, concat, fromBase64, sha256, toArrayBuffer, toHex, utf8 } from "./bytes.mjs";
import { hashLeaf } from "./merkle.mjs";

const EM_DASH_PREFIX = "— ";
const ED25519_TYPE = 0x01;

export function leafData(organizationId, headSeq, headHashHex) {
  return utf8(`cracken:prove-leaf:v1\n${organizationId}\n${headSeq}\n${headHashHex}`);
}
export function leafHash(organizationId, headSeq, headHashHex) {
  return hashLeaf(leafData(organizationId, headSeq, headHashHex));
}

export async function keyHashOf(name, publicKey) {
  return (await sha256(concat(utf8(name), Uint8Array.of(0x0a, ED25519_TYPE), publicKey))).slice(0, 4);
}

/** Parse "name+hash+base64(0x01||pk)"; checks that the stated key hash matches. */
export async function parseVerifierKey(text) {
  const parts = /^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})$/.exec(String(text).trim());
  if (!parts) throw new Error("verifier_key_invalid");
  parts.shift();
  const raw = fromBase64(parts[2]);
  if (raw.length !== 33 || raw[0] !== ED25519_TYPE) throw new Error("verifier_key_invalid");
  const publicKey = raw.slice(1);
  if (toHex(await keyHashOf(parts[0], publicKey)) !== parts[1]) throw new Error("verifier_key_hash_mismatch");
  return { name: parts[0], publicKey };
}

/** Split and parse a note without checking any signature. */
export function parseNote(note) {
  if (typeof note !== "string" || !note.endsWith("\n")) throw new Error("checkpoint_note_invalid");
  const split = note.indexOf("\n\n");
  if (split < 0) throw new Error("checkpoint_note_invalid");
  const body = note.slice(0, split + 1);
  const sigLines = note.slice(split + 2, -1).split("\n");
  const [origin, size, root, ...extensions] = body.slice(0, -1).split("\n");
  if (!origin || !/^(?:0|[1-9]\d{0,15})$/.test(size ?? "") || !root) throw new Error("checkpoint_note_invalid");
  const rootHash = fromBase64(root);
  if (rootHash.length !== 32) throw new Error("checkpoint_note_invalid");
  const recorded = extensions.find((l) => l.startsWith("recorded_at "));
  const recordedAt = recorded ? recorded.slice("recorded_at ".length) : null;
  if (recordedAt !== null && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(recordedAt)) throw new Error("checkpoint_note_invalid");
  const signatures = sigLines.map((line) => {
    if (!line.startsWith(EM_DASH_PREFIX)) throw new Error("checkpoint_note_invalid");
    const rest = line.slice(EM_DASH_PREFIX.length);
    const space = rest.lastIndexOf(" ");
    if (space <= 0) throw new Error("checkpoint_note_invalid");
    return { name: rest.slice(0, space), blob: fromBase64(rest.slice(space + 1)) };
  });
  if (signatures.length === 0) throw new Error("checkpoint_note_invalid");
  return { body, origin, size: Number(size), rootHash, recordedAt, signatures };
}

/** Ed25519 signature check of `key` over the note body. Returns "valid", or throws a code. */
export async function verifyNoteSignature(parsed, key) {
  const sig = parsed.signatures.find((s) => s.name === key.name);
  if (!sig) throw new Error("checkpoint_signature_missing");
  if (sig.blob.length !== 68 || !bytesEqual(sig.blob.slice(0, 4), await keyHashOf(key.name, key.publicKey))) {
    throw new Error("checkpoint_signature_invalid");
  }
  let cryptoKey;
  try {
    cryptoKey = await globalThis.crypto.subtle.importKey("raw", toArrayBuffer(key.publicKey), { name: "Ed25519" }, false, ["verify"]);
  } catch {
    throw new Error("ed25519_unsupported_in_this_runtime");
  }
  const ok = await globalThis.crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, toArrayBuffer(sig.blob.slice(4)), toArrayBuffer(utf8(parsed.body)));
  if (!ok) throw new Error("checkpoint_signature_invalid");
  return "valid";
}
