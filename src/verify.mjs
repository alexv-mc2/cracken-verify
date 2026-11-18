// SPDX-License-Identifier: MIT
/**
 * crAcken Prove auditor bundle v1: the whole check, shared by verify.html and cli.mjs.
 * Format: docs/bundle-format-v1.md. Every step returns a check line; the run never stops at the first failure.
 */
import { fromHex, fromUtf8, sha256Hex, toHex } from "./bytes.mjs";
import { canonicalJson, ENVELOPE_KEYS, GENESIS_PREV_HASH, orgEventRowHash } from "./canonical.mjs";
import { leafHash, parseNote, parseVerifierKey, verifyNoteSignature } from "./checkpoint.mjs";
import { rootFromInclusionProof } from "./merkle.mjs";
import { KNOWN_KEYS } from "./known-keys.mjs";
import { verifyOts } from "./ots.mjs";
import { verifyTimeStamp } from "./rfc3161.mjs";
import { readZip } from "./zip.mjs";

export const BUNDLE_FORMAT = "cracken-prove-bundle/v1";
export const CHECKPOINT_FORMAT = "cracken-prove-checkpoint/v1";
export const PATHS = Object.freeze({
  manifest: "manifest.json", events: "events.jsonl", checkpoint: "checkpoint.json", reconstruction: "reconstruction.json",
  rfc3161: "anchors/rfc3161.tsr", ots: "anchors/opentimestamps.ots", key: "cracken-public-key.txt",
});
const REQUIRED = [PATHS.events, PATHS.checkpoint, PATHS.reconstruction];
const MANIFEST_KEYS = ["as_of_us", "checkpoint_root", "checkpoint_tree_size", "files", "format", "head_hash", "head_seq", "organization_id"];
const CHECKPOINT_KEYS = ["format", "inclusion_proof", "leaf", "leaf_index", "note", "root_hash", "tree_size"];
const LEAF_KEYS = ["head_hash", "head_seq", "organization_id"];
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PATH_RE = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;

const usToIso = (us) => new Date(Math.floor(us / 1000)).toISOString().replace(".000Z", "Z") + (us % 1000 ? ` (+${us % 1000} µs)` : "");
const msg = (e) => (e && e.message) || String(e);
function sameKeys(obj, keys) {
  return obj !== null && typeof obj === "object" && !Array.isArray(obj) && Object.keys(obj).sort().join(",") === [...keys].sort().join(",");
}
/** Parse JSON and require the file bytes to be exactly the canonical encoding (no other byte form accepted). */
function parseCanonical(bytes, code) {
  let text;
  let value;
  try { text = fromUtf8(bytes); value = JSON.parse(text); } catch { throw new Error(`${code}_not_json`); }
  let canon;
  try { canon = canonicalJson(value); } catch (e) { throw new Error(`${code}_not_canonical: ${msg(e)}`); }
  if (canon !== text) throw new Error(`${code}_not_canonical`);
  return value;
}

/**
 * @param {Uint8Array} zipBytes
 * @param {{ trustedCaDers?: Uint8Array[], trustedRootSha256?: string[], verifierKey?: string,
 *   headers?: Map<number, Uint8Array>, fetchHeader?: (h:number)=>Promise<Uint8Array> }} [options]
 */
export async function verifyBundle(zipBytes, options = {}) {
  const checks = [];
  const add = (id, status, title, detail = "") => checks.push({ id, status, title, detail });
  const summary = {};
  const done = (result) => ({ result, summary, checks });

  // 0. Zip.
  let files;
  try { files = readZip(zipBytes); } catch (e) { add("zip", "fail", "Read the zip", msg(e)); return done("FAIL"); }
  add("zip", "pass", "Read the zip", `${files.size} files`);

  // 1. Manifest: every file hashed, nothing unlisted, nothing missing.
  let manifest = null;
  try {
    if (!files.has(PATHS.manifest)) throw new Error("manifest_missing");
    manifest = parseCanonical(files.get(PATHS.manifest), "manifest");
    if (!sameKeys(manifest, MANIFEST_KEYS)) throw new Error("manifest_keys_invalid");
    if (manifest.format !== BUNDLE_FORMAT) throw new Error(`manifest_format_unknown: ${manifest.format}`);
    if (!UUID.test(manifest.organization_id) || !HEX64.test(manifest.head_hash) || !HEX64.test(manifest.checkpoint_root)
      || !(manifest.head_seq >= 1) || !(manifest.checkpoint_tree_size >= 1) || !(manifest.as_of_us >= 0) || !Array.isArray(manifest.files)) {
      throw new Error("manifest_fields_invalid");
    }
    add("manifest.format", "pass", "Manifest is canonical JSON of format v1", BUNDLE_FORMAT);
  } catch (e) {
    add("manifest.format", "fail", "Manifest is canonical JSON of format v1", msg(e));
    manifest = null;
  }
  if (manifest) {
    const problems = [];
    const listed = new Set();
    let previous = "";
    for (const entry of manifest.files) {
      if (!sameKeys(entry, ["path", "sha256", "size_bytes"]) || !PATH_RE.test(entry.path) || !HEX64.test(entry.sha256)) { problems.push("bad entry"); continue; }
      if (entry.path <= previous) problems.push(`not sorted or duplicate: ${entry.path}`);
      previous = entry.path;
      listed.add(entry.path);
      if (entry.path === PATHS.manifest) { problems.push("manifest lists itself"); continue; }
      const bytes = files.get(entry.path);
      if (!bytes) { problems.push(`missing: ${entry.path}`); continue; }
      if (bytes.length !== entry.size_bytes) problems.push(`size differs: ${entry.path}`);
      if ((await sha256Hex(bytes)) !== entry.sha256) problems.push(`SHA-256 differs: ${entry.path}`);
    }
    for (const path of files.keys()) if (path !== PATHS.manifest && !listed.has(path)) problems.push(`not listed: ${path}`);
    for (const path of REQUIRED) if (!listed.has(path)) problems.push(`required file not listed: ${path}`);
    add("manifest.files", problems.length ? "fail" : "pass", "Every file matches its SHA-256 in the manifest",
      problems.length ? problems.join("; ") : `${manifest.files.length} files`);
  }

  // 2. Event chain: recompute every row_hash and the prev_hash links from seq 1.
  let head = null;
  try {
    const bytes = files.get(PATHS.events);
    if (!bytes) throw new Error("events_missing");
    const text = fromUtf8(bytes);
    if (!text.endsWith("\n")) throw new Error("events_last_line_not_terminated");
    const lines = text.slice(0, -1).split("\n");
    let prev = GENESIS_PREV_HASH;
    let org = null;
    let first = null;
    let last = null;
    for (let i = 0; i < lines.length; i++) {
      const where = `line ${i + 1}`;
      let row;
      try { row = JSON.parse(lines[i]); } catch { throw new Error(`events_${where}_not_json`); }
      if (!sameKeys(row, [...ENVELOPE_KEYS, "row_hash"])) throw new Error(`events_${where}_keys_invalid`);
      let canon;
      try { canon = canonicalJson(row); } catch (e) { throw new Error(`events_${where}_${msg(e)}`); }
      if (canon !== lines[i]) throw new Error(`events_${where}_not_canonical`);
      if (row.seq !== i + 1) throw new Error(`events_${where}_seq_gap (seq ${row.seq}, expected ${i + 1})`);
      if (org === null) org = row.organization_id;
      if (row.organization_id !== org) throw new Error(`events_${where}_other_organisation`);
      if (row.prev_hash !== prev) throw new Error(`events_seq_${row.seq}_prev_hash_mismatch`);
      const computed = await orgEventRowHash(row);
      if (computed !== row.row_hash) throw new Error(`events_seq_${row.seq}_row_hash_mismatch`);
      prev = row.row_hash;
      first ??= row;
      last = row;
    }
    if (!last) throw new Error("events_empty");
    head = { organization_id: org, seq: last.seq, hash: last.row_hash, firstRecordedUs: first.recorded_at_us, lastRecordedUs: last.recorded_at_us, rows: lines.length };
    summary.organization_id = org;
    summary.events = lines.length;
    summary.head = { seq: last.seq, hash: last.row_hash };
    add("events.chain", "pass", "Every event's row_hash and prev_hash link recomputes (from seq 1)",
      `${lines.length} events, seq 1..${last.seq}, head ${last.row_hash}`);
    if (manifest) {
      const bad = [];
      if (manifest.organization_id !== org) bad.push("organisation");
      if (manifest.head_seq !== last.seq) bad.push("head_seq");
      if (manifest.head_hash !== last.row_hash) bad.push("head_hash");
      add("events.manifest", bad.length ? "fail" : "pass", "Chain head equals the manifest", bad.length ? `differs: ${bad.join(", ")}` : "");
    }
  } catch (e) {
    add("events.chain", "fail", "Every event's row_hash and prev_hash link recomputes (from seq 1)", msg(e));
  }

  // 3. Checkpoint: note, leaf, RFC 6962 inclusion path to the signed root.
  let checkpoint = null;
  let root = null;
  let recordedAtMs = null;
  try {
    const bytes = files.get(PATHS.checkpoint);
    if (!bytes) throw new Error("checkpoint_missing");
    checkpoint = parseCanonical(bytes, "checkpoint");
    if (!sameKeys(checkpoint, CHECKPOINT_KEYS) || checkpoint.format !== CHECKPOINT_FORMAT || !sameKeys(checkpoint.leaf, LEAF_KEYS)
      || !HEX64.test(checkpoint.root_hash) || !Array.isArray(checkpoint.inclusion_proof) || !checkpoint.inclusion_proof.every((h) => HEX64.test(h))) {
      throw new Error("checkpoint_fields_invalid");
    }
    const note = parseNote(checkpoint.note);
    if (note.size !== checkpoint.tree_size || toHex(note.rootHash) !== checkpoint.root_hash) throw new Error("checkpoint_note_differs_from_fields");
    if (!note.recordedAt) throw new Error("checkpoint_note_without_recorded_at");
    root = fromHex(checkpoint.root_hash);
    recordedAtMs = Date.parse(note.recordedAt);
    summary.checkpoint = { origin: note.origin, tree_size: note.size, root: checkpoint.root_hash, recorded_at: note.recordedAt };
    add("checkpoint.note", "pass", "Checkpoint note parses and matches its fields", `${note.origin}, size ${note.size}, recorded_at ${note.recordedAt}`);

    const leaf = checkpoint.leaf;
    const lh = await leafHash(leaf.organization_id, leaf.head_seq, leaf.head_hash);
    const computedRoot = await rootFromInclusionProof(checkpoint.leaf_index, checkpoint.tree_size, lh, checkpoint.inclusion_proof.map(fromHex));
    if (toHex(computedRoot) !== checkpoint.root_hash) throw new Error("checkpoint_inclusion_root_mismatch");
    add("checkpoint.inclusion", "pass", "RFC 6962 inclusion path leads from the organisation head to the root",
      `leaf ${checkpoint.leaf_index} of ${checkpoint.tree_size}, ${checkpoint.inclusion_proof.length} hashes`);
    const bad = [];
    if (head && (leaf.organization_id !== head.organization_id || leaf.head_seq !== head.seq || leaf.head_hash !== head.hash)) bad.push("leaf is not the chain head");
    if (manifest && (manifest.checkpoint_root !== checkpoint.root_hash || manifest.checkpoint_tree_size !== checkpoint.tree_size)) bad.push("manifest root/size differ");
    if (manifest && manifest.as_of_us > recordedAtMs * 1000) bad.push("checkpoint is earlier than the as-of time");
    add("checkpoint.binding", bad.length ? "fail" : "pass", "Checkpoint leaf is this chain's head; manifest and as-of agree", bad.join("; "));

    // Signature: convenience only (the anchors are the evidence).
    const sigTitle = "crAcken Ed25519 signature on the checkpoint";
    // Key choice: the auditor's key; else a key known to this release whose name signed the note; else the bundle's own key (weak).
    const known = (options.knownKeys ?? KNOWN_KEYS).map((k) => k.verifier_key)
      .find((v) => note.signatures.some((s) => v.startsWith(`${s.name}+`)));
    const keyText = options.verifierKey || known || (files.has(PATHS.key) ? fromUtf8(files.get(PATHS.key)) : null);
    const keySource = options.verifierKey ? "auditor-supplied key" : known ? "key listed in this verifier (src/known-keys.mjs; compare with cracken.tech)"
      : "key from the bundle (not independent; compare with cracken.tech)";
    const trustedKey = Boolean(options.verifierKey || known);
    if (!keyText) add("checkpoint.signature", "skip", sigTitle, "no verifier key supplied");
    else {
      try {
        const key = await parseVerifierKey(keyText);
        await verifyNoteSignature(note, key);
        add("checkpoint.signature", trustedKey ? "pass" : "warn", sigTitle, `${key.name}: valid (${keySource})`);
      } catch (e) {
        add("checkpoint.signature", msg(e) === "ed25519_unsupported_in_this_runtime" ? "skip" : "fail", sigTitle, msg(e));
      }
    }
  } catch (e) {
    add("checkpoint", "fail", "Checkpoint and inclusion path", msg(e));
    root = null;
  }

  // 4. reconstruction.json: same as-of time as the manifest (its bytes are bound by the manifest only).
  try {
    const bytes = files.get(PATHS.reconstruction);
    if (!bytes) throw new Error("reconstruction_missing");
    const rec = JSON.parse(fromUtf8(bytes));
    if (!rec || typeof rec !== "object" || !Number.isSafeInteger(rec.as_of_us)) throw new Error("reconstruction_as_of_missing");
    if (manifest && rec.as_of_us !== manifest.as_of_us) throw new Error("reconstruction_as_of_differs_from_manifest");
    if (manifest && rec.organization_id !== undefined && rec.organization_id !== manifest.organization_id) throw new Error("reconstruction_organisation_differs");
    summary.as_of = usToIso(rec.as_of_us);
    add("reconstruction", "pass", "Reconstruction is for the manifest's organisation and as-of time", summary.as_of);
  } catch (e) {
    add("reconstruction", "fail", "Reconstruction is for the manifest's organisation and as-of time", msg(e));
  }

  // 5. Anchors over the root.
  const anchorTimes = [];
  if (!root) add("anchors", "skip", "External anchors", "no valid checkpoint root to check against");
  else {
    if (files.has(PATHS.rfc3161)) {
      try {
        const r = await verifyTimeStamp(files.get(PATHS.rfc3161), { root, trustedCaDers: options.trustedCaDers, trustedRootSha256: options.trustedRootSha256 });
        anchorTimes.push({ kind: "RFC 3161", time: r.genTime });
        summary.rfc3161 = { gen_time: r.genTime.toISOString(), tsa: r.tsaName, serial: r.serial };
        add("anchor.rfc3161", "pass", "RFC 3161 time-stamp token over the root",
          `${r.tsaName}, genTime ${r.genTime.toISOString()}, serial ${r.serial}; trusted by ${r.trustedBy}; revocation not checked`);
      } catch (e) { add("anchor.rfc3161", "fail", "RFC 3161 time-stamp token over the root", msg(e)); }
    } else add("anchor.rfc3161", "skip", "RFC 3161 time-stamp token over the root", `${PATHS.rfc3161} not in the bundle`);

    if (files.has(PATHS.ots)) {
      try {
        const r = await verifyOts(files.get(PATHS.ots), root, { headers: options.headers, fetchHeader: options.fetchHeader });
        if (r.status === "verified") {
          anchorTimes.push({ kind: "Bitcoin (OpenTimestamps)", time: r.blockTime });
          summary.opentimestamps = { height: r.height, block_time: r.blockTime.toISOString(), block_hash: r.blockHash };
          add("anchor.ots", "pass", "OpenTimestamps proof over the root", `Bitcoin block ${r.height} (${r.blockHash}), block time ${r.blockTime.toISOString()} (±2 h)`);
        } else if (r.status === "pending") {
          add("anchor.ots", "warn", "OpenTimestamps proof over the root", `not yet in a Bitcoin block (pending at ${r.calendars.join(", ") || "no calendar"}); ask crAcken for the upgraded bundle`);
        } else {
          add("anchor.ots", "skip", "OpenTimestamps proof over the root", `supply the block header for height ${r.heights.join(", ")} (own node) or allow fetching headers`);
        }
      } catch (e) { add("anchor.ots", "fail", "OpenTimestamps proof over the root", msg(e)); }
    } else add("anchor.ots", "skip", "OpenTimestamps proof over the root", `${PATHS.ots} not in the bundle`);
  }

  const failed = checks.some((c) => c.status === "fail");
  if (!failed && anchorTimes.length) {
    const earliest = anchorTimes.reduce((a, b) => (b.time < a.time ? b : a));
    summary.no_later_than = earliest.time.toISOString();
    summary.conclusion = `All ${head ? head.rows : "?"} events up to seq ${head ? head.seq : "?"} existed no later than ${earliest.time.toISOString()} (${earliest.kind}).`;
  }
  return done(failed ? "FAIL" : anchorTimes.length ? "PASS" : "INCOMPLETE");
}

