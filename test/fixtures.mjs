// SPDX-License-Identifier: MIT
/**
 * SYNTHETIC test bundle generator. Every value here is invented: organisation and actor UUIDs are made-up
 * patterns, the TSA is a throw-away test CA created on the fly, the Bitcoin block header is fabricated so its
 * Merkle root equals the stamped commitment. No data of any real organisation, TSA or Bitcoin block.
 */
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { zipSync } from "fflate";
import { DetachedTimestampFile, OpAppend, OpPrepend, OpSHA256, makeBitcoin, makePending } from "@otskit/core";
import { concat, sha256, sha256Hex, toArrayBuffer, toBase64, toHex, utf8 } from "../src/bytes.mjs";
import { canonicalJson, GENESIS_PREV_HASH, orgEventRowHash } from "../src/canonical.mjs";
import { keyHashOf, leafHash } from "../src/checkpoint.mjs";
import { BUNDLE_FORMAT, CHECKPOINT_FORMAT, PATHS } from "../src/verify.mjs";
import { inclusionProof, subtreeRoot } from "./merkle-gen.mjs";

export const ORG = "c0ec0000-0000-4000-8000-000000000001";
const ACTOR = "a0000000-0000-4000-8000-00000000000a";
const T0 = 1793534400000000; // 2026-11-01T12:00:00Z in µs
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
export const OTS_HEIGHT = 900123;
const KEY_NAME = "test.invalid/prove-key-synthetic";

pkijs.setEngine("webcrypto", new pkijs.CryptoEngine({ name: "webcrypto", crypto: globalThis.crypto }));
const uuid = (n) => `e0000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

/** Synthetic org_event_log rows, seq 1..n, with real v1 hashes. */
export async function makeEvents(n = 6) {
  const rows = [];
  let prev = GENESIS_PREV_HASH;
  for (let seq = 1; seq <= n; seq++) {
    const cutover = seq === 1;
    const row = {
      actor_id: cutover ? null : ACTOR,
      actor_type: cutover ? "system" : "user",
      event_type: cutover ? "org_event_log.cutover" : seq % 2 ? "vex_statement.proposed" : "reporting_case.note_added",
      format_version: 1,
      occurred_at_us: T0 + seq * 60_000_000,
      organization_id: ORG,
      payload: cutover
        ? { migration: "20261101003100", journal_rows: 0, journal_last_seq: 0, journal_digest_v1: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
        : seq % 2
          ? { finding_id: uuid(100 + seq), release_id: uuid(200), statement_version: 1, vex_status: "not_affected", justification: "vulnerable_code_not_present", statement_sha256: "cd".repeat(32), hash_alg: "sha256_jsonb_text_v1" }
          : { actor_basis: "session", case_seq: seq, journal_entry_hash: "ab".repeat(32), journal_hash_version: 1, journal_source: "rpc" },
      prev_hash: prev,
      recorded_at_us: T0 + seq * 60_000_000 + 123_456,
      seq,
      source_id: cutover ? ORG : uuid(seq),
      source_table: cutover ? "org_event_log_cutover" : seq % 2 ? "vex_statements" : "reporting_case_events",
      subject_id: cutover ? ORG : uuid(300 + seq),
      subject_type: cutover ? "organization" : seq % 2 ? "vex_statement" : "reporting_case",
    };
    row.row_hash = await orgEventRowHash(row);
    prev = row.row_hash;
    rows.push(row);
  }
  return rows;
}

async function makeCert({ cn, issuerCn, serial, publicKey, signKey, ca }) {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: serial });
  const name = (v) => [new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1js.Utf8String({ value: v }) })];
  cert.issuer.typesAndValues = name(issuerCn);
  cert.subject.typesAndValues = name(cn);
  cert.notBefore.value = new Date("2026-01-01T00:00:00Z");
  cert.notAfter.value = new Date("2046-01-01T00:00:00Z");
  const bc = new pkijs.BasicConstraints({ cA: ca });
  const ku = new asn1js.BitString({ valueHex: Uint8Array.of(ca ? 0x06 : 0x80).buffer, unusedBits: ca ? 1 : 7 });
  cert.extensions = [
    new pkijs.Extension({ extnID: "2.5.29.19", critical: true, extnValue: bc.toSchema().toBER(false), parsedValue: bc }),
    new pkijs.Extension({ extnID: "2.5.29.15", critical: true, extnValue: ku.toBER(false) }),
  ];
  if (!ca) {
    const eku = new pkijs.ExtKeyUsage({ keyPurposes: ["1.3.6.1.5.5.7.3.8"] });
    cert.extensions.push(new pkijs.Extension({ extnID: "2.5.29.37", critical: true, extnValue: eku.toSchema().toBER(false), parsedValue: eku }));
  }
  await cert.subjectPublicKeyInfo.importKey(publicKey);
  await cert.sign(signKey, "SHA-256");
  return cert;
}

/** Throw-away test TSA: root CA + TSA certificate (ECDSA P-256). */
export async function makeTestTsa() {
  const alg = { name: "ECDSA", namedCurve: "P-256" };
  const rootKeys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const tsaKeys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const root = await makeCert({ cn: "Synthetic Test Root CA (not a real TSA)", issuerCn: "Synthetic Test Root CA (not a real TSA)", serial: 1, publicKey: rootKeys.publicKey, signKey: rootKeys.privateKey, ca: true });
  const tsa = await makeCert({ cn: "Synthetic Test TSA (not a real TSA)", issuerCn: "Synthetic Test Root CA (not a real TSA)", serial: 2, publicKey: tsaKeys.publicKey, signKey: rootKeys.privateKey, ca: false });
  return { root, tsa, tsaKey: tsaKeys.privateKey, rootDer: new Uint8Array(root.toSchema().toBER(false)) };
}

/** TimeStampToken (ContentInfo DER) over a 32-byte digest. */
export async function makeToken(tsa, digest, genTime, { includeRoot = true } = {}) {
  const tst = new pkijs.TSTInfo({
    version: 1,
    policy: "1.3.6.1.4.1.99999.1",
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256, algorithmParams: new asn1js.Null() }),
      hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(digest) }),
    }),
    serialNumber: new asn1js.Integer({ value: 4242 }),
    genTime,
  });
  const tstDer = new Uint8Array(tst.toSchema().toBER(false));
  const signed = new pkijs.SignedData({
    version: 3,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_TST_INFO, eContent: new asn1js.OctetString({ valueHex: toArrayBuffer(tstDer) }) }),
    signerInfos: [new pkijs.SignerInfo({
      version: 1,
      sid: new pkijs.IssuerAndSerialNumber({ issuer: tsa.tsa.issuer, serialNumber: tsa.tsa.serialNumber }),
      signedAttrs: new pkijs.SignedAndUnsignedAttributes({ type: 0, attributes: [
        new pkijs.Attribute({ type: "1.2.840.113549.1.9.3", values: [new asn1js.ObjectIdentifier({ value: OID_TST_INFO })] }),
        new pkijs.Attribute({ type: "1.2.840.113549.1.9.4", values: [new asn1js.OctetString({ valueHex: toArrayBuffer(await sha256(tstDer)) })] }),
      ] }),
    })],
    certificates: includeRoot ? [tsa.tsa, tsa.root] : [tsa.tsa],
  });
  await signed.sign(tsa.tsaKey, 0, "SHA-256");
  const info = new pkijs.ContentInfo({ contentType: OID_SIGNED_DATA, content: signed.toSchema(true) });
  return new Uint8Array(info.toSchema().toBER(false));
}

/** .ots over `digest` with one fabricated Bitcoin attestation, plus the fabricated 80-byte header. */
export function makeOts(digest, { pending = false } = {}) {
  const file = DetachedTimestampFile.fromHash(new OpSHA256(), digest);
  const tip = file.timestamp.add(new OpAppend(utf8("synthetic-nonce-1"))).add(new OpSHA256())
    .add(new OpPrepend(new Uint8Array(32).fill(7))).add(new OpSHA256());
  if (pending) {
    tip.addAttestation(makePending("https://alice.btc.calendar.opentimestamps.org"));
    return { ots: file.serializeToBytes(), header: null };
  }
  tip.addAttestation(makeBitcoin(OTS_HEIGHT));
  const header = new Uint8Array(80);
  header.set([0x00, 0x00, 0x00, 0x20], 0);
  header.set(tip.msg, 36); // Merkle root field (internal byte order) = the commitment
  new DataView(header.buffer).setUint32(68, 1793541600, true); // block time 2026-11-01T14:00:00Z
  return { ots: file.serializeToBytes(), header };
}

export async function makeKey() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const keyHash = await keyHashOf(KEY_NAME, publicKey);
  const verifierKey = `${KEY_NAME}+${toHex(keyHash)}+${toBase64(Uint8Array.of(1, ...publicKey))}`;
  return { name: KEY_NAME, publicKey, keyHash, privateKey: pair.privateKey, verifierKey };
}

/** Canonical manifest over every file except itself. */
export async function makeManifest(files, fields) {
  const entries = [];
  for (const path of [...files.keys()].filter((p) => p !== PATHS.manifest).sort()) {
    entries.push({ path, sha256: await sha256Hex(files.get(path)), size_bytes: files.get(path).length });
  }
  return utf8(canonicalJson({ format: BUNDLE_FORMAT, ...fields, files: entries }));
}

export function zip(files) {
  const input = {};
  for (const [path, bytes] of files) input[path] = [bytes, { level: 6, mtime: new Date("2026-11-18T00:00:00Z") }];
  return zipSync(input);
}

/** Full synthetic bundle; returns the zip, the file map, the manifest fields and auditor options. */
export async function buildBundle({ events = 6, leaves = 7, leafIndex = 4, otsPending = false, withKeyFile = true } = {}) {
  const rows = await makeEvents(events);
  const head = rows[rows.length - 1];
  const leafList = [];
  for (let i = 0; i < leaves; i++) {
    leafList.push(i === leafIndex ? await leafHash(ORG, head.seq, head.row_hash)
      : await leafHash(`c0ec0000-0000-4000-8000-${String(100 + i).padStart(12, "0")}`, i + 1, (await sha256Hex(utf8(`synthetic-${i}`)))));
  }
  const root = await subtreeRoot(leafList);
  const proof = await inclusionProof(leafIndex, leafList);
  const recordedAt = "2026-11-01T13:00:00.000Z";
  const key = await makeKey();
  const body = `cracken.tech/prove/v1\n${leaves}\n${toBase64(root)}\nrecorded_at ${recordedAt}\n`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, utf8(body)));
  const note = `${body}\n— ${key.name} ${toBase64(concat(key.keyHash, sig))}\n`;
  const asOfUs = head.recorded_at_us - 30_000_000;
  const tsa = await makeTestTsa();
  const token = await makeToken(tsa, root, new Date("2026-11-01T13:00:05Z"));
  const { ots, header } = makeOts(root, { pending: otsPending });

  const files = new Map();
  files.set(PATHS.events, utf8(rows.map((r) => canonicalJson(r) + "\n").join("")));
  files.set(PATHS.checkpoint, utf8(canonicalJson({
    format: CHECKPOINT_FORMAT, note, tree_size: leaves, root_hash: toHex(root), leaf_index: leafIndex,
    leaf: { organization_id: ORG, head_seq: head.seq, head_hash: head.row_hash }, inclusion_proof: proof.map(toHex),
  })));
  files.set(PATHS.reconstruction, utf8(JSON.stringify({ format: "cracken-prove-reconstruction/v1", organization_id: ORG, as_of_us: asOfUs,
    note: "SYNTHETIC test reconstruction; invented data only.", findings: [], vex_statements: [], reporting_cases: [] }, null, 2)));
  files.set(PATHS.rfc3161, token);
  files.set(PATHS.ots, ots);
  if (withKeyFile) files.set(PATHS.key, utf8(key.verifierKey + "\n"));
  files.set("README.txt", utf8("SYNTHETIC crAcken Prove test bundle. Invented data only; not evidence of anything.\n"));
  const fields = { organization_id: ORG, as_of_us: asOfUs, head_seq: head.seq, head_hash: head.row_hash, checkpoint_tree_size: leaves, checkpoint_root: toHex(root) };
  files.set(PATHS.manifest, await makeManifest(files, fields));
  const headers = new Map(header ? [[OTS_HEIGHT, header]] : []);
  return { zip: zip(files), files, fields, rows, root, tsa, key,
    options: { trustedCaDers: [tsa.rootDer], verifierKey: key.verifierKey, headers }, header };
}
