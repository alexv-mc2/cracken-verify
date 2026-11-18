import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fromHex, sha256, toHex } from "../src/bytes.mjs";
import { esploraHeaders, parseHeaders, verifyOts } from "../src/ots.mjs";
import { verifyTimeStamp } from "../src/rfc3161.mjs";
import { makeOts, makeTestTsa, makeToken, OTS_HEIGHT } from "./fixtures.mjs";

const root = fromHex("5a".repeat(32));

test("RFC 3161: synthetic token verifies only for its root and the auditor's CA", async () => {
  const tsa = await makeTestTsa();
  const token = await makeToken(tsa, root, new Date("2026-11-01T13:00:05Z"));
  const ok = await verifyTimeStamp(token, { root, trustedCaDers: [tsa.rootDer] });
  assert.equal(ok.genTime.toISOString(), "2026-11-01T13:00:05.000Z");
  await assert.rejects(verifyTimeStamp(token, { root: fromHex("5b".repeat(32)), trustedCaDers: [tsa.rootDer] }), /imprint_mismatch/);
  await assert.rejects(verifyTimeStamp(token, { root }), /root_not_trusted/); // default FreeTSA pin
  const other = await makeTestTsa();
  await assert.rejects(verifyTimeStamp(token, { root, trustedCaDers: [other.rootDer] }), /chain_invalid|signature_invalid/);
  // A token without the root certificate still verifies against the auditor's CA file.
  const bare = await makeToken(tsa, root, new Date("2026-11-01T13:00:05Z"), { includeRoot: false });
  assert.ok(await verifyTimeStamp(bare, { root, trustedCaDers: [tsa.rootDer] }));
  // Outside the certificate validity the chain fails.
  const late = await makeToken(tsa, root, new Date("2047-01-01T00:00:00Z"));
  await assert.rejects(verifyTimeStamp(late, { root, trustedCaDers: [tsa.rootDer] }), /chain_invalid/);
});

test("RFC 3161: a real FreeTSA response over a random digest verifies with the pinned root", async () => {
  // Captured 2026-11-10 by the crAcken worker tests for a random 32-byte digest (no organisation data).
  const der = new Uint8Array(readFileSync(new URL("./vectors/freetsa-random-digest.tsr", import.meta.url)));
  const digest = fromHex("79dc0ff6af72e3e3fec72288aa707cea3a021bd8cf391914ce067fb0d22b4d5d");
  const r = await verifyTimeStamp(der, { root: digest });
  assert.equal(r.tsaName, "www.freetsa.org");
  assert.ok(r.genTime.toISOString().startsWith("2026-11-10"));
  const flipped = new Uint8Array(der); flipped[300] ^= 1;
  await assert.rejects(verifyTimeStamp(flipped, { root: digest }));
});

test("OpenTimestamps: verified with the header, pending, missing header, wrong header, wrong digest", async () => {
  const { ots, header } = makeOts(root);
  const r = await verifyOts(ots, root, { headers: new Map([[OTS_HEIGHT, header]]) });
  assert.equal(r.status, "verified");
  assert.equal(r.height, OTS_HEIGHT);
  assert.equal(r.blockTime.toISOString(), "2026-11-01T14:00:00.000Z");
  assert.deepEqual(await verifyOts(ots, root, {}), { status: "needs_header", heights: [OTS_HEIGHT] });
  const bad = new Uint8Array(header); bad[40] ^= 1;
  await assert.rejects(verifyOts(ots, root, { headers: new Map([[OTS_HEIGHT, bad]]) }), /attestation_mismatch/);
  await assert.rejects(verifyOts(ots, fromHex("00".repeat(32)), {}), /digest_mismatch/);
  const pending = makeOts(root, { pending: true });
  const p = await verifyOts(pending.ots, root, {});
  assert.equal(p.status, "pending");
  assert.deepEqual(p.calendars, ["https://alice.btc.calendar.opentimestamps.org"]);
  const truncated = ots.slice(0, ots.length - 3);
  await assert.rejects(verifyOts(truncated, root, {}), /ots_parse_failed/);
});

test("header input parsing and the opt-in two-explorer fetch", async () => {
  const { ots, header } = makeOts(root);
  assert.equal(parseHeaders(`${OTS_HEIGHT}:${toHex(header)}\n`).get(OTS_HEIGHT).length, 80);
  assert.throws(() => parseHeaders("12:abcd"), /block_header_input_invalid/);
  const hash = toHex((await sha256(await sha256(header))).reverse());
  const calls = [];
  const fake = (headerHex) => async (url) => {
    calls.push(url);
    const body = url.endsWith("/header") ? headerHex : url.includes("/block-height/") ? hash : "";
    return { ok: true, status: 200, text: async () => body };
  };
  const r = await verifyOts(ots, root, { fetchHeader: esploraHeaders(fake(toHex(header))) });
  assert.equal(r.status, "verified");
  assert.equal(calls.length, 4); // two explorers, two requests each
  const wrong = new Uint8Array(header); wrong[0] ^= 1;
  await assert.rejects(verifyOts(ots, root, { fetchHeader: esploraHeaders(fake(toHex(wrong))) }), /self_check_failed/);
});
