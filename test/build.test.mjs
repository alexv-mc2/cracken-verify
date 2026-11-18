// The browser bundle (same esbuild settings as build.mjs) verifies the committed sample; verify.html is current.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { build } from "esbuild";
import { pemOrDer } from "../src/bytes.mjs";
import { parseHeaders } from "../src/ots.mjs";

const v = (p) => new URL(`./vectors/${p}`, import.meta.url);

test("browser-platform bundle of the core verifies the sample bundle", async () => {
  const out = await build({ entryPoints: ["src/verify.mjs"], bundle: true, format: "esm", platform: "browser", target: "es2020", write: false });
  const mod = await import(`data:text/javascript;base64,${Buffer.from(out.outputFiles[0].text).toString("base64")}`);
  const report = await mod.verifyBundle(new Uint8Array(readFileSync(v("sample-bundle.zip"))), {
    trustedCaDers: pemOrDer(new Uint8Array(readFileSync(v("sample-tsa-root.pem")))),
    verifierKey: readFileSync(v("sample-verifier-key.txt"), "utf8").trim(),
    headers: parseHeaders(readFileSync(v("sample-block-headers.txt"), "utf8")),
  });
  assert.equal(report.result, "PASS");
});

test("verify.html is built, self-contained and matches its .sha256 file", () => {
  if (!existsSync("verify.html")) return; // fresh clone before `npm run build`
  const html = readFileSync("verify.html", "utf8");
  assert.ok(!/<script[^>]+src=/i.test(html), "no external scripts");
  assert.ok(!/<link[^>]+href=/i.test(html), "no external stylesheets");
  assert.match(html, /id="third-party-licences"/);
  const sha = createHash("sha256").update(html).digest("hex");
  assert.equal(readFileSync("verify.html.sha256", "utf8").split(/\s+/)[0], sha);
  const script = html.slice(html.lastIndexOf("<script>") + 8, html.lastIndexOf("</script>"));
  assert.doesNotThrow(() => new Function(script), "inline script parses");
});
