import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { utf8 } from "../src/bytes.mjs";
import { esploraHeaders } from "../src/ots.mjs";
import { PATHS, verifyBundle } from "../src/verify.mjs";
import { buildBundle, makeManifest, zip } from "./fixtures.mjs";

const b = await buildBundle();
const failed = (r) => r.checks.filter((c) => c.status === "fail").map((c) => c.id);

/** Deterministic positions: first, middle, last and 12 pseudo-random bytes (every byte with CRACKEN_VERIFY_EXHAUSTIVE=1). */
function positions(length, seed) {
  if (process.env.CRACKEN_VERIFY_EXHAUSTIVE === "1") return Array.from({ length }, (_, i) => i);
  const out = new Set([0, Math.floor(length / 2), length - 1]);
  let x = seed;
  while (out.size < Math.min(length, 15)) { x = (x * 1103515245 + 12345) & 0x7fffffff; out.add(x % length); }
  return [...out];
}
function withChange(files, path, pos) {
  const copy = new Map(files);
  const bytes = new Uint8Array(files.get(path));
  bytes[pos] ^= 0x01;
  copy.set(path, bytes);
  return copy;
}

test("the valid synthetic bundle passes with the auditor's inputs", async () => {
  const r = await verifyBundle(b.zip, b.options);
  assert.equal(r.result, "PASS", JSON.stringify(failed(r)));
  assert.ok(r.checks.every((c) => c.status === "pass"));
  assert.match(r.summary.conclusion, /All 6 events up to seq 6 existed no later than 2026-11-01T13:00:05.000Z/);
});

test("one changed byte in any file of the bundle is detected", async () => {
  let cases = 0;
  for (const path of b.files.keys()) {
    for (const pos of positions(b.files.get(path).length, path.length * 7919)) {
      const r = await verifyBundle(zip(withChange(b.files, path, pos)), b.options);
      assert.equal(r.result, "FAIL", `${path} byte ${pos} not detected`);
      cases++;
    }
  }
  assert.ok(cases >= 8 * 15);
});

test("a changed byte is still detected when the manifest is rewritten to match (anchored files)", async () => {
  for (const path of [PATHS.events, PATHS.checkpoint]) {
    for (const pos of positions(b.files.get(path).length, 31337)) {
      const files = withChange(b.files, path, pos);
      files.set(PATHS.manifest, await makeManifest(files, b.fields));
      const r = await verifyBundle(zip(files), b.options);
      assert.equal(r.result, "FAIL", `${path} byte ${pos} with rewritten manifest not detected`);
      assert.ok(!failed(r).includes("manifest.files"), "manifest itself is consistent");
    }
  }
  // A rewritten event with a recomputed chain no longer reaches the anchored root.
  const rows = b.rows.map((r) => ({ ...r }));
  rows[2].payload = { ...rows[2].payload, case_seq: 99 };
  const { canonicalJson, orgEventRowHash } = await import("../src/canonical.mjs");
  let prev = "0".repeat(64);
  for (const row of rows) { row.prev_hash = prev; delete row.row_hash; row.row_hash = await orgEventRowHash(row); prev = row.row_hash; }
  const files = new Map(b.files);
  files.set(PATHS.events, utf8(rows.map((r) => canonicalJson(r) + "\n").join("")));
  files.set(PATHS.manifest, await makeManifest(files, { ...b.fields, head_hash: prev }));
  const r = await verifyBundle(zip(files), b.options);
  assert.equal(r.result, "FAIL");
  assert.ok(failed(r).includes("checkpoint.binding"));
});

test("missing, extra and unlisted files, and a broken zip, fail", async () => {
  const missing = new Map(b.files); missing.delete(PATHS.ots);
  assert.equal((await verifyBundle(zip(missing), b.options)).result, "FAIL");
  const extra = new Map(b.files); extra.set("extra.txt", utf8("x"));
  assert.equal((await verifyBundle(zip(extra), b.options)).result, "FAIL");
  assert.equal((await verifyBundle(b.zip.slice(0, b.zip.length - 30), b.options)).result, "FAIL");
});

test("without anchors' auditor inputs the result is not PASS; pending OTS is a warning", async () => {
  const r = await verifyBundle(b.zip, {});
  assert.equal(r.result, "FAIL"); // synthetic TSA is not the pinned FreeTSA root
  const noTsa = new Map(b.files); noTsa.delete(PATHS.rfc3161);
  noTsa.set(PATHS.manifest, await makeManifest(noTsa, b.fields));
  const r2 = await verifyBundle(zip(noTsa), { headers: new Map() });
  assert.equal(r2.result, "INCOMPLETE");
  const pending = await buildBundle({ otsPending: true });
  const r3 = await verifyBundle(pending.zip, pending.options);
  assert.equal(r3.result, "PASS");
  assert.equal(r3.checks.find((c) => c.id === "anchor.ots").status, "warn");
  // Opt-in fetch path with a fake transport: no network in tests.
  const fetchHeader = esploraHeaders(async () => ({ ok: false, status: 503, text: async () => "" }));
  const r4 = await verifyBundle(b.zip, { ...b.options, headers: new Map(), fetchHeader });
  assert.equal(r4.checks.find((c) => c.id === "anchor.ots").status, "fail");
});

test("committed sample bundle and the CLI", () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const args = ["cli.mjs", "test/vectors/sample-bundle.zip", "--tsa-ca", "test/vectors/sample-tsa-root.pem",
    "--key", "@test/vectors/sample-verifier-key.txt", "--headers", "test/vectors/sample-block-headers.txt"];
  const out = execFileSync(process.execPath, args, { cwd: root, encoding: "utf8" });
  assert.match(out, /Result: PASS/);
  const bad = spawnSync(process.execPath, ["cli.mjs", "test/vectors/sample-bundle.zip"], { cwd: root, encoding: "utf8" });
  assert.equal(bad.status, 1); // synthetic TSA is not trusted by default
  assert.equal(spawnSync(process.execPath, ["cli.mjs"], { cwd: root }).status, 2);
  assert.ok(readFileSync(new URL("./vectors/sample-bundle.zip", import.meta.url)).length > 1000);
});

test("known keys: the published key format is accepted; a known key that did not sign is not used", async () => {
  const { KNOWN_KEYS } = await import("../src/known-keys.mjs");
  const { parseVerifierKey } = await import("../src/checkpoint.mjs");
  for (const k of KNOWN_KEYS) assert.equal((await parseVerifierKey(k.verifier_key)).publicKey.length, 32);
  // Synthetic note is signed by the throw-away test key, so the default list does not match and the bundle key is used (warn).
  const r = await verifyBundle(b.zip, { ...b.options, verifierKey: undefined });
  assert.equal(r.checks.find((c) => c.id === "checkpoint.signature").status, "warn");
  // Listing the throw-away key as known makes it a pass without --key.
  const r2 = await verifyBundle(b.zip, { ...b.options, verifierKey: undefined, knownKeys: [{ verifier_key: b.key.verifierKey }] });
  assert.equal(r2.checks.find((c) => c.id === "checkpoint.signature").status, "pass");
});

test("checkpoint earlier than T: accepted when every event precedes the checkpoint, refused otherwise", async () => {
  // Last synthetic event is recorded at 12:06:00.123456; the checkpoint at 13:00; T = 14:00 (nothing recorded in between).
  const later = await buildBundle({ asOfUs: Date.parse("2026-11-01T14:00:00Z") * 1000 });
  const r = await verifyBundle(later.zip, later.options);
  assert.equal(r.result, "PASS", JSON.stringify(failed(r)));
  assert.match(r.checks.find((c) => c.id === "checkpoint.binding").detail, /not covered by this bundle/);
  assert.deepEqual(r.summary.uncovered_window, { from: "2026-11-01T13:00:00.000Z", to: "2026-11-01T14:00:00Z" });
  // Same millisecond as the last event (µs beyond the note's ms precision) still counts as before the checkpoint.
  const sameMs = await buildBundle({ recordedAt: "2026-11-01T12:06:00.123Z", asOfUs: Date.parse("2026-11-01T14:00:00Z") * 1000 });
  assert.equal((await verifyBundle(sameMs.zip, sameMs.options)).result, "PASS");
  // Events recorded after the checkpoint time are in the bundle: refused, with T before or after the checkpoint.
  for (const asOfUs of [Date.parse("2026-11-01T14:00:00Z") * 1000, Date.parse("2026-11-01T12:02:00Z") * 1000]) {
    const bad = await buildBundle({ recordedAt: "2026-11-01T12:03:00.000Z", asOfUs });
    const rb = await verifyBundle(bad.zip, bad.options);
    assert.equal(rb.result, "FAIL");
    assert.match(rb.checks.find((c) => c.id === "checkpoint.binding").detail, /event recorded after the checkpoint time/);
  }
  // The default case (checkpoint after T) has no uncovered window.
  assert.equal((await verifyBundle(b.zip, b.options)).summary.uncovered_window, undefined);
});
