// SPDX-License-Identifier: MIT
// Read a bundle zip into { path -> bytes } with fflate (MIT, bundled). Refuses unsafe or duplicate names.
import { unzipSync } from "fflate";

export const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

export function readZip(zipBytes) {
  const seen = new Set();
  let total = 0;
  let entries;
  try {
    entries = unzipSync(zipBytes, {
      filter(file) {
        if (seen.has(file.name)) throw new Error(`zip_duplicate_entry:${file.name}`);
        seen.add(file.name);
        total += file.originalSize;
        if (total > MAX_TOTAL_BYTES) throw new Error("zip_too_large");
        return true;
      },
    });
  } catch (e) {
    throw new Error(String(e.message || e).startsWith("zip_") ? e.message : `zip_unreadable: ${e.message || e}`);
  }
  const files = new Map();
  for (const [name, bytes] of Object.entries(entries)) {
    if (name.endsWith("/")) { if (bytes.length) throw new Error(`zip_directory_with_data:${name}`); continue; }
    if (name.startsWith("/") || name.includes("\\") || name.split("/").some((p) => p === ".." || p === "." || p === "")) {
      throw new Error(`zip_path_unsafe:${name}`);
    }
    files.set(name, bytes);
  }
  return files;
}
