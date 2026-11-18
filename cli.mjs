#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// cracken-verify CLI: same core as verify.html. Offline unless --fetch-headers is given.
import { readFileSync } from "node:fs";
import { pemOrDer } from "./src/bytes.mjs";
import { esploraHeaders, parseHeaders } from "./src/ots.mjs";
import { verifyBundle } from "./src/verify.mjs";

const USAGE = `usage: cracken-verify <bundle.zip> [options]

  --tsa-ca <file>        TSA root/CA certificate (PEM or DER) you downloaded yourself; repeatable.
                         Default: the pinned SHA-256 fingerprint of the FreeTSA root certificate.
  --key <text|@file>     crAcken checkpoint verifier key (name+hash+base64) from cracken.tech.
  --header <H:hex>       Raw 80-byte Bitcoin block header (hex) at height H, from your own node; repeatable.
  --headers <file>       File with "H:hex" lines or a JSON object {"H": "hex"}.
  --fetch-headers        Allow network: fetch missing block headers from blockstream.info AND mempool.space
                         (both must agree). Without it the CLI makes no network request.
  --json                 Print the full report as JSON.

exit code: 0 PASS, 1 FAIL, 3 INCOMPLETE (no external anchor could be verified), 2 usage error`;

function parseArgs(argv) {
  const opts = { cas: [], headerLines: [], key: null, fetch: false, json: false, zip: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--tsa-ca") opts.cas.push(next());
    else if (a === "--key") opts.key = next();
    else if (a === "--header") opts.headerLines.push(next());
    else if (a === "--headers") opts.headerLines.push(readFileSync(next(), "utf8"));
    else if (a === "--fetch-headers") opts.fetch = true;
    else if (a === "--json") opts.json = true;
    else if (a === "-h" || a === "--help") { console.log(USAGE); process.exit(0); }
    else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    else if (!opts.zip) opts.zip = a;
    else throw new Error("only one bundle at a time");
  }
  if (!opts.zip) throw new Error("bundle path missing");
  return opts;
}

let opts;
try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\n\n${USAGE}`); process.exit(2); }

const headers = new Map();
for (const block of opts.headerLines) for (const [h, v] of parseHeaders(block)) headers.set(h, v);
const options = {
  trustedCaDers: opts.cas.flatMap((f) => pemOrDer(new Uint8Array(readFileSync(f)))),
  verifierKey: opts.key ? (opts.key.startsWith("@") ? readFileSync(opts.key.slice(1), "utf8").trim() : opts.key) : undefined,
  headers,
  fetchHeader: opts.fetch ? esploraHeaders() : undefined,
};
const report = await verifyBundle(new Uint8Array(readFileSync(opts.zip)), options);
if (opts.json) console.log(JSON.stringify(report, null, 2));
else {
  const mark = { pass: "PASS", fail: "FAIL", warn: "WARN", skip: "SKIP", info: "INFO" };
  for (const c of report.checks) console.log(`[${mark[c.status]}] ${c.title}${c.detail ? `\n       ${c.detail}` : ""}`);
  console.log(`\nResult: ${report.result}`);
  if (report.summary.conclusion) console.log(report.summary.conclusion);
}
process.exit(report.result === "PASS" ? 0 : report.result === "FAIL" ? 1 : 3);
