# crAcken Prove auditor bundle, format v1

What `cracken-verify` expects inside the zip. The crAcken exporter (sbom-to-cra, Prove P5) must produce
exactly this; anything else is reported as a failure. The test generator `test/fixtures.mjs` is a
reference producer (synthetic data only) and `test/vectors/sample-bundle.zip` is a reference output.

## Files

| Path | Required | Content |
|---|---|---|
| `manifest.json` | yes | Canonical JSON (rules below), lists every other file |
| `events.jsonl` | yes | The organisation's `org_event_log` rows, seq 1 to the head at the checkpoint |
| `checkpoint.json` | yes | Checkpoint note, the organisation's leaf and its RFC 6962 inclusion path |
| `reconstruction.json` | yes | crAcken's reconstruction at the as-of time (JSON object; free form apart from the keys below) |
| `anchors/rfc3161.tsr` | no | RFC 3161 TimeStampToken (DER ContentInfo) or full TimeStampResp over the checkpoint root |
| `anchors/opentimestamps.ots` | no | OpenTimestamps detached proof over the checkpoint root (SHA-256 file digest = root) |
| `cracken-public-key.txt` | no | Signed-note verifier key, one line (convenience; an auditor uses the key from cracken.tech) |
| anything else (`README.txt`, `reconstruction.pdf`, `verify/verify.html`, …) | no | Must be listed in the manifest |

Paths: ASCII `[A-Za-z0-9._-]` segments separated by `/`; no directories with data, no duplicates. A file
in the zip that the manifest does not list, or a listed file that is missing, fails the check.

## Canonical JSON

`manifest.json`, every line of `events.jsonl` and `checkpoint.json` are byte-exact canonical JSON as
defined by crAcken org-event-log format v1 (`docs/architecture/org-event-log-format-v1.md` in
sbom-to-cra): UTF-8, no whitespace, keys `^[a-z][a-z0-9_]{0,62}$` sorted bytewise, integers only
(|n| ≤ 2^53 − 1), strings as `JSON.stringify`, no trailing newline in the `.json` files.
`reconstruction.json` is ordinary JSON (any formatting).

## manifest.json

```json
{"as_of_us":1793534730123456,"checkpoint_root":"<64 hex>","checkpoint_tree_size":7,
 "files":[{"path":"anchors/opentimestamps.ots","sha256":"<64 hex>","size_bytes":411}, ...],
 "format":"cracken-prove-bundle/v1","head_hash":"<64 hex>","head_seq":6,"organization_id":"<uuid>"}
```

Exactly these keys. `files` sorted by `path`, every file except `manifest.json` itself. `as_of_us` is the
requested time T in microseconds since the Unix epoch. Every field is cross-checked: `organization_id`,
`head_seq`, `head_hash` against the last event and the checkpoint leaf; `checkpoint_root` and
`checkpoint_tree_size` against `checkpoint.json`; `as_of_us` against `reconstruction.json` (and, when it is later
than the checkpoint, it is reported as an uncovered window).

## events.jsonl

One row per line, each line terminated by `\n`, seq 1, 2, 3, … without gaps, all of one organisation.
Each line is the canonical JSON of the 14 envelope keys (`actor_id, actor_type, event_type,
format_version, occurred_at_us, organization_id, payload, prev_hash, recorded_at_us, seq, source_id,
source_table, subject_id, subject_type`) plus `row_hash`; nothing else (no `owner_id`, no `created_at`).
Hashes are lower-case hex without `\x`. Row 1 has `prev_hash` = 64 zeros; row n has `prev_hash` =
`row_hash` of row n − 1; `row_hash = SHA-256("cracken:org-event-log:v1\n" ‖ C(envelope))`.

## checkpoint.json

```json
{"format":"cracken-prove-checkpoint/v1","inclusion_proof":["<64 hex>", ...],
 "leaf":{"head_hash":"<64 hex>","head_seq":6,"organization_id":"<uuid>"},"leaf_index":4,
 "note":"cracken.tech/prove/v1\n7\n<base64 root>\nrecorded_at 2026-11-01T13:00:00.000Z\n\n— <key name> <base64 sig>\n",
 "root_hash":"<64 hex>","tree_size":7}
```

- `note`: the stored signed note, byte for byte (`chain_checkpoints.note`). Its size and root must equal
  `tree_size` and `root_hash`; it must carry `recorded_at`. Every event in the bundle must have
  `recorded_at_us` ≤ the checkpoint time (`recorded_at` in ms + 999 µs, because the note has ms precision).
- `leaf`: the organisation's leaf in that checkpoint; it must be the last event (seq and `row_hash`).
  Leaf hash = `SHA-256(0x00 ‖ "cracken:prove-leaf:v1\n<org>\n<seq>\n<head hash>")`.
- `inclusion_proof`: RFC 6962 audit path from `leaf_index` in a tree of `tree_size`, lowest level first.

The export is cut at the first checkpoint at or after T: events after T up to that checkpoint's head
are included (they are needed to reach the anchored root); the reconstruction uses only events with
`recorded_at_us ≤ as_of_us`.

If no checkpoint after T exists yet, the export may use the latest checkpoint before T, but only when
the organisation recorded nothing after that checkpoint: the bundle then ends at the checkpoint, every
event in it precedes the checkpoint time (and so precedes T). The verifier accepts this, reports the
window from the checkpoint time to T as "not covered by this bundle" (`summary.uncovered_window`), and
fails any bundle that contains an event recorded after the checkpoint time, whether T is before or
after the checkpoint.

## reconstruction.json

A JSON object with at least `as_of_us` (equal to the manifest) and, if present, `organization_id`
(equal to the manifest). The rest is defined by the exporter. Its bytes are bound by the manifest only,
not by the anchors: it is crAcken's reading of the anchored events, which the auditor can recompute.
