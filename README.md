# cracken-verify

Offline verifier for crAcken **Prove** auditor bundles. One self-contained page (`verify.html`) and a
small Node CLI (`cli.mjs`) share one core (`src/`). MIT licence; see NOTICE for the Apache-2.0 and
BSD-3-Clause parts.

A Prove bundle is a zip that crAcken exports for one organisation and one date T. It lets an auditor
check, without trusting crAcken, that the organisation's recorded events existed no later than a time
fixed by an independent public log: an RFC 3161 time-stamp authority (FreeTSA) and the Bitcoin
blockchain (OpenTimestamps).

## Use it

**In a browser, offline:** download `verify.html` from a release, compare its SHA-256 with
`verify.html.sha256` (and with the hash crAcken lists in the bundle README), open it from disk, choose
the zip. Nothing leaves the page unless you tick "fetch block headers".

**On the command line** (Node ≥ 20):

```sh
git clone <this repository> && cd cracken-verify && npm ci
node cli.mjs bundle.zip \
  --tsa-ca freetsa-cacert.pem \
  --key 'cracken.tech/prove-key-2026-11+30eb8ebf+AaTJP1WXQ8VIzvODrd4TXZQlR4nO+RBndZ+7eVvumLh0' \
  --header 900123:<80-byte header hex from your own node>
```

`--fetch-headers` allows the CLI to fetch missing Bitcoin block headers from blockstream.info **and**
mempool.space (each header must hash to the block hash its explorer named; both must agree). Exit code
0 = PASS, 1 = FAIL, 3 = INCOMPLETE (integrity checked, but no external anchor could be verified),
2 = usage error. `--json` prints the full report.

Try it on the synthetic sample:

```sh
node cli.mjs test/vectors/sample-bundle.zip --tsa-ca test/vectors/sample-tsa-root.pem \
  --key @test/vectors/sample-verifier-key.txt --headers test/vectors/sample-block-headers.txt
```

## What is verified

1. **Manifest.** Every file in the zip has the SHA-256 and size listed in `manifest.json`; nothing is
   missing or unlisted; the manifest is byte-exact canonical JSON and each of its fields is cross-checked.
2. **Hash chain.** Every event in `events.jsonl` recomputes to its `row_hash` under crAcken
   org-event-log format v1, and each `prev_hash` is the previous `row_hash`, from seq 1 (genesis = 32
   zero bytes) to the head. Changing, inserting or removing any event breaks this or the next step.
3. **Merkle inclusion.** The organisation's head (seq + hash) is a leaf of the checkpoint tree: the
   RFC 6962 audit path in `checkpoint.json` leads to the checkpoint root, and the signed note states
   the same root and size.
4. **RFC 3161 anchor.** `anchors/rfc3161.tsr` is a time-stamp token whose message imprint is the
   checkpoint root (SHA-256), with a valid CMS signature by a certificate with the timeStamping key
   usage, chaining at genTime to a root you trust. Gives T_A: the root existed no later than T_A.
5. **OpenTimestamps anchor.** `anchors/opentimestamps.ots` commits to the checkpoint root; replaying its
   operations gives the Merkle root of a Bitcoin block header at the attested height. Gives T_B (block
   time, ±2 h). A proof that is not yet in a block is reported as pending, not as a failure.
6. **Conclusion.** All events up to the head existed no later than min(T_A, T_B). Any later change
   breaks the chain, the path or the anchor.

The crAcken Ed25519 signature on the checkpoint is shown when a key is available (from `--key`, from
`src/known-keys.mjs`, or — marked as not independent — from the bundle). It is a convenience; the
anchors are the evidence.

## What you still trust

- **The TSA root certificate.** Download it yourself (FreeTSA: `https://freetsa.org/files/cacert.pem`
  and `tsa.crt`), not from the bundle. Without `--tsa-ca` the verifier accepts only a token whose chain
  contains the FreeTSA root with SHA-256 fingerprint
  `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc` (pinned in `src/rfc3161.mjs`).
  Certificate revocation is not checked offline.
- **The Bitcoin block header.** Best from your own node (a pruned node is enough). Fetched headers trust
  the two explorers.
- **This code.** It is small; read `src/`. `verify.html` is rebuilt from source in CI and must be
  byte-identical (`npm ci && npm run build && git diff --exit-code`).
- **Not proven:** that crAcken recorded every event that happened (only that what was recorded was not
  changed after the checkpoint), anything before the first anchored checkpoint, and the content of
  `reconstruction.json` beyond its hash (it is crAcken's reading of the anchored events). This is not a
  qualified (eIDAS) time stamp.

## Check it with other tools

The checkpoint root is `root_hash` in `checkpoint.json` (hex).

```sh
# RFC 3161, with OpenSSL (token only: -token_in; drop it for a full response)
openssl ts -verify -digest <root_hex> -token_in -in anchors/rfc3161.tsr \
  -CAfile cacert.pem -untrusted tsa.crt
openssl ts -reply -token_in -in anchors/rfc3161.tsr -text        # show genTime and imprint

# OpenTimestamps, with the reference client (LGPL-3.0, separate tool) and your own Bitcoin node
ots info anchors/opentimestamps.ots
ots verify -d <root_hex> anchors/opentimestamps.ots

# File hashes against the manifest
shasum -a 256 events.jsonl checkpoint.json reconstruction.json anchors/*

# A block header from your own node
bitcoin-cli getblockheader "$(bitcoin-cli getblockhash 900123)" false
```

## crAcken checkpoint keys

Verifier keys use the signed-note form `name+<key hash hex>+base64(0x01 ‖ Ed25519 public key)`.
Keys known to this release are listed in `src/known-keys.mjs`:

| Key name | Verifier key | Since |
|---|---|---|
| `cracken.tech/prove-key-2026-11` | `cracken.tech/prove-key-2026-11+30eb8ebf+AaTJP1WXQ8VIzvODrd4TXZQlR4nO+RBndZ+7eVvumLh0` | 2026-11-18 |

Compare with the list on cracken.tech. Key rotations are added, never replaced.

## Bundle format

See `docs/bundle-format-v1.md`.

## Development

```sh
npm ci
npm test                              # node --test, a few seconds
CRACKEN_VERIFY_EXHAUSTIVE=1 node --test test/bundle.test.mjs   # flip every byte of every file (~1 min)
npm run build                         # verify.html + verify.html.sha256
npm run vectors                       # regenerate test/vectors/sample-* (new random test keys)
```

All test data is synthetic: invented organisation and actor IDs, a throw-away test TSA, a throw-away
Ed25519 key and a fabricated Bitcoin block header. The one exception is
`test/vectors/freetsa-random-digest.tsr`, a real FreeTSA response for a random digest, used to test the
pinned FreeTSA root; it contains no organisation data.

## Licence

MIT (LICENSE). `src/merkle.mjs` is Apache-2.0 (from sigstore-js). Bundled pkijs, asn1js and bytestreamjs
are BSD-3-Clause; @otskit/core, fflate, @noble/hashes and @peculiar/utils are MIT. Details in NOTICE;
full texts are embedded in `verify.html`.
