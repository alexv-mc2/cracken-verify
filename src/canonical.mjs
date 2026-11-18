// SPDX-License-Identifier: MIT
/**
 * crAcken org-event-log format v1: canonical JSON and row hash.
 *
 * Independent JavaScript port of the crAcken reference verifier (sbom-to-cra
 * src/lib/org-event-log/canonical.ts, rule text docs/architecture/org-event-log-format-v1.md).
 * That reference adapted the shared writer/verifier envelope pattern of tauvin/auditrum,
 * auditrum/hash_chain.py (https://github.com/tauvin/auditrum), MIT License, Copyright (c) 2024.
 *
 * row_hash = SHA-256( "cracken:org-event-log:v1\n" || C(envelope) ), UTF-8.
 * C: no whitespace; object keys ^[a-z][a-z0-9_]{0,62}$ sorted bytewise; integers only
 * (|n| <= 2^53 - 1); strings as JSON.stringify; depth <= 16 from the root.
 */
import { sha256Hex, utf8 } from "./bytes.mjs";

export const ORG_EVENT_HASH_PREFIX = "cracken:org-event-log:v1\n";
export const GENESIS_PREV_HASH = "0".repeat(64);
export const ENVELOPE_KEYS = Object.freeze([
  "actor_id", "actor_type", "event_type", "format_version", "occurred_at_us", "organization_id", "payload",
  "prev_hash", "recorded_at_us", "seq", "source_id", "source_table", "subject_id", "subject_type",
]);
const KEY_RE = /^[a-z][a-z0-9_]{0,62}$/;

function jsonString(value) {
  // PostgreSQL text/jsonb cannot hold NUL or unpaired UTF-16 surrogates.
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit === 0) throw new Error("org_event_canonical_string_invalid");
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("org_event_canonical_string_invalid");
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("org_event_canonical_string_invalid");
    }
  }
  return JSON.stringify(value);
}

/** Canonical encoding C(value); throws a code for anything v1 cannot represent. */
export function canonicalJson(value, depth = 0) {
  if (depth > 16) throw new Error("org_event_canonical_too_deep");
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return jsonString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("org_event_canonical_number_not_safe_integer");
    return String(value); // -0 -> "0", as PostgreSQL jsonb normalises it
  }
  if (Array.isArray(value)) {
    const entries = [];
    for (let i = 0; i < value.length; i += 1) {
      if (!(i in value)) throw new Error("org_event_canonical_value_invalid");
      entries.push(canonicalJson(value[i], depth + 1));
    }
    return `[${entries.join(",")}]`;
  }
  if (typeof value !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new Error("org_event_canonical_value_invalid");
  }
  const keys = Object.keys(value).sort(); // ASCII-only keys: UTF-16 order = byte order
  for (const key of keys) if (!KEY_RE.test(key)) throw new Error("org_event_canonical_key_invalid");
  return `{${keys.map((key) => `${jsonString(key)}:${canonicalJson(value[key], depth + 1)}`).join(",")}}`;
}

export async function canonicalHash(value) {
  return sha256Hex(utf8(ORG_EVENT_HASH_PREFIX + canonicalJson(value)));
}

/** The hashed envelope: exactly the 14 v1 columns (owner_id and created_at are never hashed). */
export function orgEventEnvelope(row) {
  const out = {};
  for (const key of ENVELOPE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(row, key)) throw new Error(`org_event_field_missing:${key}`);
    out[key] = row[key];
  }
  return out;
}

export async function orgEventRowHash(row) {
  if (row.format_version !== 1) throw new Error("org_event_format_version_unknown");
  return canonicalHash(orgEventEnvelope(row));
}
