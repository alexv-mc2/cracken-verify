// SPDX-License-Identifier: MIT
// verify.html glue: read the inputs, run the shared core, render the checks. No network unless the box is ticked.
import { pemOrDer } from "./bytes.mjs";
import { esploraHeaders, parseHeaders } from "./ots.mjs";
import { verifyBundle } from "./verify.mjs";

const $ = (id) => document.getElementById(id);
const readFile = (input) => (input.files && input.files[0] ? input.files[0].arrayBuffer().then((b) => new Uint8Array(b)) : Promise.resolve(null));
const LABEL = { pass: "Pass", fail: "Fail", warn: "Note", skip: "Not checked", info: "Info" };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.append(c);
  return node;
}

async function run(event) {
  event.preventDefault();
  const out = $("result");
  out.replaceChildren(el("p", { class: "muted" }, "Checking…"));
  try {
    const zip = await readFile($("bundle"));
    if (!zip) throw new Error("Choose the bundle zip first.");
    const caBytes = [];
    for (const f of $("tsa-ca").files) caBytes.push(...pemOrDer(new Uint8Array(await f.arrayBuffer())));
    const options = {
      trustedCaDers: caBytes,
      verifierKey: $("key").value.trim() || undefined,
      headers: parseHeaders($("headers").value),
      fetchHeader: $("fetch").checked ? esploraHeaders() : undefined,
    };
    const report = await verifyBundle(zip, options);
    const list = el("ol", { class: "checks" });
    for (const c of report.checks) {
      list.append(el("li", { class: c.status }, el("span", { class: "badge" }, LABEL[c.status]), el("span", { class: "title" }, c.title),
        ...(c.detail ? [el("code", { class: "detail" }, c.detail)] : [])));
    }
    const verdict = el("p", { class: `verdict ${report.result.toLowerCase()}`, role: "status" }, `Result: ${report.result}`);
    const conclusion = report.summary.conclusion ? [el("p", { class: "conclusion" }, report.summary.conclusion)] : [];
    const json = el("details", {}, el("summary", {}, "Full report (JSON)"), el("pre", {}, JSON.stringify(report, null, 2)));
    out.replaceChildren(verdict, ...conclusion, list, json);
  } catch (e) {
    out.replaceChildren(el("p", { class: "verdict fail", role: "status" }, `Error: ${e.message || e}`));
  }
}

$("form").addEventListener("submit", run);
const lic = document.getElementById("third-party-licences");
if (lic) $("licences").textContent = lic.textContent.trim();
