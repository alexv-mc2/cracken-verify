// SPDX-License-Identifier: MIT
/**
 * OpenTimestamps proof check on @otskit/core 0.2.0 (MIT, bundled; see NOTICE). Ideas only, no code, from the
 * LGPL-3.0 javascript-opentimestamps project. The stamped message is the 32-byte checkpoint root.
 *
 * Offline by default: every Bitcoin attestation needs the raw 80-byte block header at its height, supplied by
 * the auditor (from an own node: `bitcoin-cli getblockheader $(bitcoin-cli getblockhash H) false`). Only on an
 * explicit opt-in are headers fetched from two independent Esplora explorers; each header must hash to the
 * block hash its explorer named and both must agree byte for byte.
 */
import { DetachedTimestampFile, VerificationError, verifyBitcoinAttestation } from "@otskit/core";
import { bytesEqual, fromHex, sha256, toHex } from "./bytes.mjs";

export const DEFAULT_EXPLORERS = [
  { name: "blockstream.info", baseUrl: "https://blockstream.info/api" },
  { name: "mempool.space", baseUrl: "https://mempool.space/api" },
];

async function blockHashOf(header) {
  return toHex((await sha256(await sha256(header))).reverse());
}

/** Parse "height:headerhex" lines (or a JSON object {height: hex}) into a Map<number, Uint8Array>. */
export function parseHeaders(text) {
  const map = new Map();
  const trimmed = String(text || "").trim();
  if (!trimmed) return map;
  const entries = trimmed.startsWith("{") ? Object.entries(JSON.parse(trimmed))
    : trimmed.split(/\r?\n/).filter((l) => l.trim()).map((l) => l.split(/[:\s]+/).filter(Boolean));
  for (const [h, hex] of entries) {
    if (!/^\d{1,9}$/.test(String(h)) || !/^[0-9a-fA-F]{160}$/.test(String(hex))) throw new Error("block_header_input_invalid");
    map.set(Number(h), fromHex(String(hex).toLowerCase()));
  }
  return map;
}

/** Header source over two Esplora explorers (network). */
export function esploraHeaders(fetchImpl = globalThis.fetch, explorers = DEFAULT_EXPLORERS) {
  const get = async (base, path) => {
    const res = await fetchImpl(`${base}${path}`);
    if (!res.ok) throw new Error(`explorer_http_${res.status}`);
    const text = (await res.text()).trim();
    if (text.length > 1024) throw new Error("explorer_response_too_large");
    return text.toLowerCase();
  };
  return async (height) => {
    const answers = [];
    for (const ex of explorers) {
      const hash = await get(ex.baseUrl, `/block-height/${height}`);
      const hex = await get(ex.baseUrl, `/block/${hash}/header`);
      if (!/^[0-9a-f]{64}$/.test(hash) || !/^[0-9a-f]{160}$/.test(hex)) throw new Error("explorer_answer_invalid");
      const header = fromHex(hex);
      if ((await blockHashOf(header)) !== hash) throw new Error("explorer_header_self_check_failed");
      answers.push(header);
    }
    if (answers.some((a) => !bytesEqual(a, answers[0]))) throw new Error("explorers_disagree");
    return answers[0];
  };
}

/**
 * @param {Uint8Array} otsBytes
 * @param {Uint8Array} root expected file digest (checkpoint root)
 * @param {{ headers?: Map<number, Uint8Array>, fetchHeader?: (height:number)=>Promise<Uint8Array> }} options
 * @returns {Promise<{status:"verified", height:number, blockTime:Date, blockHash:string}
 *   | {status:"pending", calendars:string[]} | {status:"needs_header", heights:number[]}>}
 */
export async function verifyOts(otsBytes, root, options = {}) {
  let file;
  try { file = DetachedTimestampFile.deserialize(otsBytes); } catch (e) { throw new Error(`ots_parse_failed: ${e.message}`); }
  if (file.fileHashOp.tagName !== "sha256") throw new Error("ots_file_hash_not_sha256");
  if (!bytesEqual(file.fileDigest(), root)) throw new Error("ots_digest_mismatch");
  const all = file.timestamp.allAttestations();
  const bitcoin = all.filter(({ attestation }) => attestation.kind === "bitcoin");
  if (bitcoin.length === 0) {
    return { status: "pending", calendars: all.filter(({ attestation }) => attestation.kind === "pending").map(({ attestation }) => attestation.uri) };
  }
  const missing = [];
  let best = null;
  for (const { msg, attestation } of bitcoin) {
    let header = options.headers ? options.headers.get(attestation.height) : undefined;
    if (!header && options.fetchHeader) header = await options.fetchHeader(attestation.height);
    if (!header) { missing.push(attestation.height); continue; }
    let time;
    try { time = verifyBitcoinAttestation(msg, attestation, header, attestation.height); } catch (e) {
      if (e instanceof VerificationError) throw new Error(`ots_attestation_mismatch_at_height_${attestation.height}`);
      throw e;
    }
    const result = { status: "verified", height: attestation.height, blockTime: new Date(time * 1000), blockHash: await blockHashOf(header) };
    if (!best || result.blockTime < best.blockTime) best = result;
  }
  return best ?? { status: "needs_header", heights: missing };
}
