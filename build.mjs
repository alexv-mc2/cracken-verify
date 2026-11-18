// SPDX-License-Identifier: MIT
// Builds verify.html: one self-contained file (core + pkijs/asn1js/@otskit/core/fflate inlined, licences embedded).
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const BUNDLED = ["pkijs", "asn1js", "bytestreamjs", "@peculiar/utils", "@noble/hashes", "@otskit/core", "fflate"];
const result = await build({
  entryPoints: ["src/web.mjs"], bundle: true, format: "iife", platform: "browser", target: "es2020",
  minify: true, legalComments: "none", write: false, charset: "utf8",
});
const js = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script").replace(/<!--/g, "<\\!--");

let licences = readFileSync("NOTICE", "utf8") + "\n\n==== cracken-verify (MIT) ====\n" + readFileSync("LICENSE", "utf8")
  + "\n\n==== src/merkle.mjs (Apache-2.0, from sigstore-js) ====\n" + readFileSync("LICENSES/Apache-2.0.txt", "utf8");
for (const pkg of BUNDLED) {
  const meta = JSON.parse(readFileSync(`node_modules/${pkg}/package.json`, "utf8"));
  licences += `\n\n==== ${pkg} ${meta.version} (${meta.license}) ====\n` + readFileSync(`node_modules/${pkg}/LICENSE`, "utf8");
}
if (/<\/script/i.test(licences)) throw new Error("licence text contains a closing script tag");

const template = readFileSync("verify.template.html", "utf8");
const html = template
  .replace("<!--LICENCES-->", () => `<script type="text/plain" id="third-party-licences">\n${licences}\n</script>`)
  .replace("/*SCRIPT*/", () => js);
writeFileSync("verify.html", html);
const sha = createHash("sha256").update(html).digest("hex");
writeFileSync("verify.html.sha256", `${sha}  verify.html\n`);
console.log(`verify.html ${html.length} bytes, sha256 ${sha}`);
