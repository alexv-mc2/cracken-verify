// SPDX-License-Identifier: MIT
// Writes the committed SYNTHETIC sample bundle (test/vectors/). Invented data only. Run: npm run vectors
import { mkdirSync, writeFileSync } from "node:fs";
import { toBase64, toHex } from "../src/bytes.mjs";
import { buildBundle, OTS_HEIGHT } from "./fixtures.mjs";

const dir = new URL("./vectors/", import.meta.url);
mkdirSync(dir, { recursive: true });
const b = await buildBundle();
const pem = `-----BEGIN CERTIFICATE-----\n${toBase64(b.tsa.rootDer).match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
writeFileSync(new URL("sample-bundle.zip", dir), b.zip);
writeFileSync(new URL("sample-tsa-root.pem", dir), pem);
writeFileSync(new URL("sample-verifier-key.txt", dir), b.key.verifierKey + "\n");
writeFileSync(new URL("sample-block-headers.txt", dir), `${OTS_HEIGHT}:${toHex(b.header)}\n`);
console.log("wrote test/vectors/sample-*");
