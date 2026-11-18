// Vectors from sbom-to-cra docs/architecture/org-event-log-format-v1.md (synthetic values only).
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalHash, canonicalJson, GENESIS_PREV_HASH, orgEventRowHash } from "../src/canonical.mjs";

const VECTORS = [
  ["empty_object", {}, "{}", "4d3f100e3b3d767fdee54fd7b0c401c31b284dd6c8924e923b8fc1f8e15938aa"],
  ["key_order_and_scalars", { b: true, a: null, c: false, a_b: 0, a0: -42 }, '{"a":null,"a0":-42,"a_b":0,"b":true,"c":false}',
    "a2be6f2b6b8684d8cd63df86e18a0773dfe4003e7026c1fd6329ecfc3e250860"],
  ["nested_array_order_kept", { z: [3, 1, 2], y: { k: [{ b: 1, a: 2 }] } }, '{"y":{"k":[{"a":2,"b":1}]},"z":[3,1,2]}',
    "5cb0675bac462deb94a1aef35efcb003a6864f60d8173677dcf82ac3414048d6"],
  ["string_escapes", { s: "quote\" backslash\\ slash/ tab\t nl\n cr\r bs\b ff\f us\u001f del\u007f" }, null,
    "bfc8bb0e5069bb976c08af1559be45b21b568037fa9cab2fe7a780c98d78e257"],
  ["unicode_literal", { s: "Grüße — 漢字 😀" }, '{"s":"Grüße — 漢字 😀"}', "67149ec48f9e838b9c7a4b5f0724c95fd99d9a100745afd76377075205742b5d"],
  ["safe_integer_bounds", { max: 9007199254740991, min: -9007199254740991 }, '{"max":9007199254740991,"min":-9007199254740991}',
    "53a22fa16e63f3e93b4aa07677f7dcc42c53c23689613a4c2c3fdcce76830fbb"],
  ["exponent_normalised", JSON.parse('{"n":1e2}'), '{"n":100}', "39d162fd60399d5a434c179cbfa6bbfa93dc2a40e68f7078089321495d1b6957"],
];

test("canonical encoding and hash vectors", async () => {
  for (const [name, input, encoded, hash] of VECTORS) {
    if (encoded !== null) assert.equal(canonicalJson(input), encoded, name);
    assert.equal(await canonicalHash(input), hash, name);
  }
});

test("rejections", () => {
  for (const v of [{ A: 1 }, { "a-b": 1 }]) assert.throws(() => canonicalJson(v), /org_event_canonical_key_invalid/);
  for (const v of [{ n: 1.5 }, { n: 25.5 }, { n: 9007199254740992 }]) assert.throws(() => canonicalJson(v), /not_safe_integer/);
  assert.throws(() => canonicalJson({ s: "a\u0000" }), /string_invalid/);
  assert.throws(() => canonicalJson({ s: "\ud800x" }), /string_invalid/);
  let deep = 1; for (let i = 0; i < 17; i++) deep = [deep];
  assert.throws(() => canonicalJson(deep), /too_deep/);
});

const ROW1 = {
  actor_id: "11111111-1111-4111-8111-111111111111", actor_type: "user", event_type: "reporting_case.note_added", format_version: 1,
  occurred_at_us: 1793534400000000, organization_id: "22222222-2222-4222-8222-222222222222",
  payload: { actor_basis: "session", case_seq: 3, journal_entry_hash: "ab".repeat(32), journal_hash_version: 1, journal_source: "rpc" },
  prev_hash: GENESIS_PREV_HASH, recorded_at_us: 1793534400123456, seq: 1, source_id: "33333333-3333-4333-8333-333333333333",
  source_table: "reporting_case_events", subject_id: "44444444-4444-4444-8444-444444444444", subject_type: "reporting_case",
};

test("envelope vectors ROW1 and ROW2", async () => {
  const h1 = await orgEventRowHash(ROW1);
  assert.equal(h1, "6fc8afab79c3ba3aafc548dd22e976c5ed49655b1af24fc7f8348f1353179cd2");
  const row2 = { ...ROW1, seq: 2, prev_hash: h1, source_id: "55555555-5555-4555-8555-555555555555", recorded_at_us: 1793534400223456 };
  assert.equal(await orgEventRowHash(row2), "5ac9e77daa01b9f6fbf3c9e030b760810eb69575d31dfd9d26eeea1acf18c592");
  // Extra read-side columns are not hashed; unknown format versions are refused.
  assert.equal(await orgEventRowHash({ ...ROW1, owner_id: "x", created_at: "y" }), h1);
  await assert.rejects(orgEventRowHash({ ...ROW1, format_version: 2 }), /format_version_unknown/);
});
