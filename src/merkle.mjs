/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// SPDX-License-Identifier: Apache-2.0
//
// RFC 6962 Merkle inclusion proof verification.
// Ported from sigstore-js packages/verify/src/tlog/merkle.ts
// (https://github.com/sigstore/sigstore-js, Apache-2.0); see NOTICE and LICENSES/Apache-2.0.txt.
// Modifications by crAcken (2026): plain JavaScript; Node Buffer and @sigstore/core crypto replaced by
// Uint8Array + WebCrypto SHA-256 (async); the Rekor entry/checkpoint types replaced by explicit
// (index, size, leafHash, proof, root) arguments; leaf hashing exported for the crAcken leaf format;
// errors are plain Error codes; the sigstore decomposition (decompInclProof, chainInner,
// chainBorderRight, innerProofSize, onesCount, bitLength) is kept as written.
import { bytesEqual, concat, sha256 } from "./bytes.mjs";

const RFC6962_LEAF_HASH_PREFIX = Uint8Array.of(0x00);
const RFC6962_NODE_HASH_PREFIX = Uint8Array.of(0x01);

/** Root implied by an inclusion proof; throws on a malformed proof (index, size or hash count). */
export async function rootFromInclusionProof(index, size, leafHash, hashes) {
  let logIndex;
  let treeSize;
  try {
    logIndex = BigInt(index);
    treeSize = BigInt(size);
  } catch {
    throw new Error("merkle_index_invalid");
  }
  if (logIndex < 0n || logIndex >= treeSize) throw new Error("merkle_index_out_of_range");
  if (leafHash.length !== 32 || hashes.some((h) => h.length !== 32)) throw new Error("merkle_hash_length_invalid");

  // Figure out which subset of hashes corresponds to the inner and border nodes
  const { inner, border } = decompInclProof(logIndex, treeSize);
  if (hashes.length !== inner + border) throw new Error("merkle_hash_count_invalid");

  const innerHashes = hashes.slice(0, inner);
  const borderHashes = hashes.slice(inner);
  return chainBorderRight(await chainInner(leafHash, innerHashes, logIndex), borderHashes);
}

/** True when the proof leads from leafHash at index in a tree of size to root. */
export async function verifyInclusion(index, size, leafHash, hashes, root) {
  try {
    return bytesEqual(await rootFromInclusionProof(index, size, leafHash, hashes), root);
  } catch {
    return false;
  }
}

// Breaks down inclusion proof for a leaf at the specified index in a tree of
// the specified size. The split point is where paths to the index leaf and
// the (size - 1) leaf diverge. Returns lengths of the bottom and upper proof
// parts.
function decompInclProof(index, size) {
  const inner = innerProofSize(index, size);
  const border = onesCount(index >> BigInt(inner));
  return { inner, border };
}

// Computes a subtree hash for a node on or below the tree's right border.
// Assumes the provided proof hashes are ordered from lower to higher levels
// and seed is the initial hash of the node specified by the index.
async function chainInner(seed, hashes, index) {
  let acc = seed;
  for (let i = 0; i < hashes.length; i++) {
    acc = (index >> BigInt(i)) & 1n ? await hashChildren(hashes[i], acc) : await hashChildren(acc, hashes[i]);
  }
  return acc;
}

// Computes a subtree hash for nodes along the tree's right border.
async function chainBorderRight(seed, hashes) {
  let acc = seed;
  for (const h of hashes) acc = await hashChildren(h, acc);
  return acc;
}

function innerProofSize(index, size) {
  return bitLength(index ^ (size - 1n));
}

// Counts the number of ones in the binary representation of the given number.
function onesCount(num) {
  return num.toString(2).split("1").length - 1;
}

// Returns the number of bits necessary to represent an integer in binary.
function bitLength(n) {
  return n === 0n ? 0 : n.toString(2).length;
}

// Hashing logic according to RFC6962.
// https://datatracker.ietf.org/doc/html/rfc6962#section-2
export function hashChildren(left, right) {
  return sha256(concat(RFC6962_NODE_HASH_PREFIX, left, right));
}

export function hashLeaf(leaf) {
  return sha256(concat(RFC6962_LEAF_HASH_PREFIX, leaf));
}
