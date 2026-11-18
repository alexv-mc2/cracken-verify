// SPDX-License-Identifier: MIT
// Test-only RFC 6962 tree builder (MTH and PATH of RFC 6962 section 2.1), used to make synthetic proofs.
import { hashChildren } from "../src/merkle.mjs";

const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
export async function subtreeRoot(leaves, lo = 0, hi = leaves.length) {
  if (hi - lo === 1) return leaves[lo];
  const k = split(hi - lo);
  return hashChildren(await subtreeRoot(leaves, lo, lo + k), await subtreeRoot(leaves, lo + k, hi));
}
export async function inclusionProof(index, leaves, lo = 0, hi = leaves.length) {
  if (hi - lo === 1) return [];
  const k = split(hi - lo);
  return index < k
    ? [...await inclusionProof(index, leaves, lo, lo + k), await subtreeRoot(leaves, lo + k, hi)]
    : [...await inclusionProof(index - k, leaves, lo + k, hi), await subtreeRoot(leaves, lo, lo + k)];
}
