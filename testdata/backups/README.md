# Old-format backup fixtures

Backups written by **published** iwcore versions, one per on-disk format era.
`tests/compat_tests.rs` restores every one with the current code and checks
that nothing changed.

| Folder | iwcore | Why this version |
|---|---|---|
| `v0.1.3` | 0.1.3 | v5 scheme (AES-CBC), old `nswb-` backup prefix |
| `v0.1.27` | 0.1.27 | last v5 release, `iwb-` prefix, all 0.1.x field types |
| `v0.2.0` | 0.2.0 | first v6 scheme (XChaCha20-Poly1305 + Argon2id) |
| `v0.2.9` | 0.2.9 | after the migration hardening |
| `v0.3.0` | 0.3.0 | AutoFill module added, no format change |
| `v0.4.0` | 0.4.0 | last release before passkeys; also an AutoFill index and journal in format v1 |

Each folder holds:

- the backup zip exactly as that version wrote it;
- `manifest.json`: the password and every label, item and field read back
  through that version's API right before the backup, plus the id of one item
  that was moved to the trash. For `v0.4.0`, also the AutoFill keys and the
  staged journal record;
- `v0.4.0` only: `autofill-index-v1.bin` and `autofill-journal-v1.bin`, and
  `golden/`: the CSV, JSON and XML exports iwcore 0.4.0 produced for this
  vault, with the export time (and JSON's date-derived `expired` / `expiring`
  flags) normalised. Written once with `IWCORE_WRITE_GOLDEN=1`.

Every value in these files is synthetic test data.

## How they were generated

`generator.rs.txt` is the program, run once per version (2026-10-31) from a
scratch Cargo project with `iwcore = "=<version>"` and `serde_json = "1"`
(and a feature `autofill = []`, enabled for 0.4.0 only):

```sh
cargo run --release [--features autofill] -- <version> <out-dir>
```

Fixtures are never regenerated in place: a new format era gets a new folder.
