// RFC 6962 vectors: transparency-dev/merkle (Apache-2.0) testonly/constants.go and proof/verify_test.go,
// as used by sbom-to-cra deploy/extended-worker/prove-merkle_test.ts.
import assert from "node:assert/strict";
import { test } from "node:test";
import { fromHex, toHex, utf8 } from "../src/bytes.mjs";
import { leafHash } from "../src/checkpoint.mjs";
import { hashLeaf, rootFromInclusionProof, verifyInclusion } from "../src/merkle.mjs";
import { inclusionProof, subtreeRoot } from "./merkle-gen.mjs";

const LEAF_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
const ROOTS = [
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];
const INCLUSION = [
  [0, 1, []],
  [0, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]],
  [5, 8, ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]],
  [2, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]],
];
const refLeaves = () => Promise.all(LEAF_INPUTS.map((h) => hashLeaf(fromHex(h))));

test("published inclusion vectors verify", async () => {
  const leaves = await refLeaves();
  for (let n = 1; n <= 8; n++) assert.equal(toHex(await subtreeRoot(leaves.slice(0, n))), ROOTS[n - 1]);
  for (const [index, size, proof] of INCLUSION) {
    assert.ok(await verifyInclusion(index, size, leaves[index], proof.map(fromHex), fromHex(ROOTS[size - 1])), `${index}/${size}`);
  }
});

test("crAcken leaf vector", async () => {
  assert.equal(toHex(await leafHash("c0ec0000-0000-4000-8000-000000000001", 7, "ab".repeat(32))),
    "0bab25c67eee6f3362949c10f16858583df567058e45597b6373d42b31b067f7");
});

test("every inclusion proof of trees up to 33 leaves verifies; tampering is rejected", async () => {
  const all = await Promise.all(Array.from({ length: 33 }, (_, i) => hashLeaf(utf8(`leaf-${i}`))));
  for (let n = 1; n <= 33; n++) {
    const tree = all.slice(0, n);
    const root = await subtreeRoot(tree);
    for (let i = 0; i < n; i++) {
      const proof = await inclusionProof(i, tree);
      assert.equal(toHex(await rootFromInclusionProof(i, n, tree[i], proof)), toHex(root));
      assert.ok(!await verifyInclusion(i, n, await hashLeaf(Uint8Array.of(9)), proof, root), "wrong leaf");
      if (proof.length) {
        const bad = proof.map((h) => new Uint8Array(h)); bad[bad.length - 1][0] ^= 1;
        assert.ok(!await verifyInclusion(i, n, tree[i], bad, root), "flipped proof bit");
        assert.ok(!await verifyInclusion(i, n, tree[i], proof.slice(1), root), "short proof");
      }
      assert.ok(!await verifyInclusion(i, n, tree[i], [...proof, tree[0]], root), "long proof");
    }
  }
});

test("bad index or size is refused", async () => {
  const tree = await Promise.all([1, 2, 3, 4].map((i) => hashLeaf(Uint8Array.of(i))));
  const root = await subtreeRoot(tree);
  const proof = await inclusionProof(1, tree);
  assert.ok(!await verifyInclusion(4, 4, tree[1], proof, root));
  assert.ok(!await verifyInclusion(-1, 4, tree[1], proof, root));
  assert.ok(!await verifyInclusion(2, 4, tree[1], proof, root));
  assert.ok(!await verifyInclusion(1, 5, tree[1], proof, root));
  await assert.rejects(rootFromInclusionProof(1, 4, tree[1], [new Uint8Array(31), proof[1]]), /hash_length/);
});
