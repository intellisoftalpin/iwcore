# Changelog

## 0.7.1

### Added

- **`PendingRecord::create_only`.** A provider marks a login it could not
  attribute to the site it names (for example an app that only claims a web
  domain). The drain never replaces a stored login with such a record: an exact
  duplicate is skipped, anything else becomes a new entry, also when the record
  is an update naming an item. `PendingRecord::from_login_json` reads an
  optional boolean `create_only` member. The member is written to the journal
  only when set, so ordinary records are byte for byte as before.

## 0.7.0

### Breaking changes

- `autofill::PendingRecord` no longer implements `Serialize` or `Deserialize`.
  Logins written by a provider are read with `PendingRecord::from_login_json`
  or through the new `autofill::PendingLogin` (`From<PendingLogin>`). The
  journal bytes are unchanged.
- `DrainSummary` gains `already_applied` and `unparsed_bytes`;
  `journal::DrainRead` gains `unparsed_bytes`.
- `crypto::prepare_key` / `crypto::legacy::prepare_key` return
  `Zeroizing<[u8; 32]>`; `LegacyKeyChain::decrypt` returns
  `Zeroizing<String>`.

### Hardening

- **Format upgrade compacts the database.** Every wallet connection uses
  `secure_delete`; the v5 to v6 upgrade runs `VACUUM` and a truncating WAL
  checkpoint after it commits, and a vault upgraded by an older version is
  compacted once at its next unlock. `retire_pre_v6_snapshot` now needs a
  backup of the same vault taken after that compaction.
- **`Wallet::discard_quarantined`** deletes records that could not be
  recovered during the upgrade and compacts the file.
- **Backups from outside.** Wallet tables with generated or hidden columns are
  refused, and the read-only connection sets SQLite length, expression depth,
  argument and column limits. Checking a backup password uses tighter Argon2
  bounds than the live vault (memory <= 256 MiB, time <= 12, lanes <= 4), and
  a legacy encryption count above 10,000 is refused.
- **Restore** opens the backup's database as untrusted and refuses triggers,
  views, virtual tables, generated columns and expression or partial indexes
  before anything is replaced.
- **AutoFill journal.** The vault remembers which records it has applied, so a
  record is never applied twice; records are applied in creation order. The
  drain reports bytes it could not read.
- **Link hosts** end at a backslash, as in browsers.
- **CXF import** keeps only http and https web addresses as links; others are
  listed in `preview.skipped`.
- **Legacy key material** and decrypted legacy values are wiped after use.
- **File modes.** On Unix, new wallet and backup folders are 0700 and the
  database and backup files 0600.
- **Fuzzing** has a per-input time limit; the backup target also checks the
  password and starts from real wallet seeds.

## 0.6.0

### Hardening

- **AutoFill index leaves no key copies behind.** Building the index grew its
  JSON and padding buffers while writing, and every grow released a block that
  still held passkey records in plain text. Both buffers are now sized before
  anything is written. `tests/wipe_on_drop.rs` scans every block released
  during the build, and during the drop of a passkey record, for the secret.
- **Backups from outside.** The database inside a backup is checked before any
  query (SQLite header, `quick_check`, wallet tables must be real tables) and
  opened read-only with defensive mode, `trusted_schema` off, `query_only` on
  and a work budget. `inspect_backup_in`, `is_backup_compatible_in` and
  `check_backup_password_in` use it; the password check no longer goes
  through `Wallet::open`, so nothing is migrated or written.
- **Restore.** The SQLite header is checked before a temp file is created; the
  restored database is capped at 256 MiB (was 2 GiB) and, above 1 MiB, at 1000
  times its compressed size. The previous database's `-wal`, `-shm` and
  `-journal` files are moved aside and only deleted once the new file is in
  place (moved back on failure); the folder is synced on Unix.
- **Stored KDF settings** are checked before any key derivation: v6 scheme and
  argon2id only, memory <= 1 GiB, time cost 1..=100, parallelism 1..=16.
- **Pre-v6 snapshot.** The snapshot written by the v5 to v6 upgrade is no
  longer kept forever: `Wallet::retire_pre_v6_snapshot(backup_folder)` deletes
  it once the vault is v6, unlocked, and the folder holds a v6 backup.
- **AutoFill journal.** Format 2 closes every record with an HMAC-SHA256 tag
  under a new symmetric journal auth key held only by the app and its
  provider; the drain applies only records that verify and counts the rest.
  Format-1 records are applied only through an explicit recovery path.
  A drained passkey for an account that already has one no longer replaces
  it: it is reported for confirmation (`Wallet::confirm_passkey_replacement`).
- **AutoFill framing** uses checked arithmetic and bounds-checked slices on
  every pointer width; a CI job runs the tests on i686 (32-bit `usize`).
- **Passkey attach.** A drained passkey joins an existing login only by exact
  host or the same registrable domain under the full Public Suffix List.
- **Key material in memory.** `derive_kek`, `unwrap_dek` and the exports return
  zeroizing buffers; no plain copies of the data key; `LegacyKeyChain` wipes
  its keys; `IWItem` `Debug` redacts the name. Passkey private keys are no
  longer reachable through public fields: the AutoFill index and journal hold
  them opaquely, the stored record serialiser is crate-internal, and parsed or
  serialised copies are wiped. `Wallet::export_cxf` writes straight into one
  exact-size zeroizing buffer without an intermediate JSON tree.
- **Client data.** `passkey::json::client_data` decides what is signed: for an
  `android:apk-key-hash:` origin a caller-supplied clientDataHash is refused
  and clientDataJSON is always built by the core.
- **CXF import** reads the payload with streaming readers (no JSON tree), with
  a 16 MiB payload limit (was 64 MiB) and new limits on collections, list
  entries, fields per import and listed skips. A passkey credential id is never
  stored twice, and an existing passkey for the same account is never
  replaced by an import (skipped with a reason). Date arithmetic is checked.
- **Legacy decrypt** refuses malformed plaintexts with an error instead of
  panicking, and legacy key derivation terminates for an empty password.
- `crypto/`, `backup/`, `autofill/` and `cxf/` deny `unwrap`, `expect`, `panic`
  and indexing outside tests (plus `arithmetic_side_effects` where applied).

### Features

- `autofill::passkeys`: `HeldPasskeys` (index plus staged journal passkeys),
  `sign_from_index`, `SignRequest`, `SignedAssertion`, `PasskeyCandidate`: a
  provider lists and signs without decoding a passkey record.
- Password AutoFill verification helpers in `passkey::origin` (pure, no
  network): `registrable_domain`, `login_assetlinks_url`,
  `app_allowed_for_domain`, `web_domain_matches_url`.

### API (breaking)

- `AutofillKeys` gains `journal_auth_key`. `journal::seal_record` takes the
  auth key; `journal::FORMAT_VERSION` is 2 (new `LEGACY_FORMAT_VERSION`,
  `TAG_LEN`, `MAC_CONTEXT`). `journal::open_with_journal_key` is replaced by
  `open_for_drain(journal, &DrainKeys) -> DrainRead`.
- `Wallet::drain_autofill_journal` takes `&DrainKeys`. `DrainSummary`:
  `passkeys_replaced` removed; `pending_replacements` and `unauthenticated`
  added. New `PasskeyReplacement`, `Wallet::confirm_passkey_replacement`.
- `PendingRecord.passkey` is private; new `PendingRecord::new_login`,
  `::new_passkey`, `::staged_passkey`, and `Registration::pending_record`.
- `PasskeyIndexEntry` fields are private (`new`, `record()`, `summary()`); its
  Serialize/Deserialize derives are removed (wire format unchanged).
  `IndexContents` no longer derives `PartialEq`/`Eq`.
- `PasskeyRecord::to_field_value` is crate-internal.
- `crypto::encrypt`/`decrypt` and `crypto::legacy::encrypt`/`decrypt` are no
  longer public; legacy data is read through `legacy::LegacyKeyChain`.
- `kdf::derive_kek` and `dek::unwrap_dek` return `Zeroizing<[u8; 32]>`;
  `export_pdf`/`csv`/`json`/`xml` return `Zeroizing<Vec<u8>>`.
- New `KdfParams::check_stored`, `KDF_MAX_*`; new `Wallet::has_pre_v6_snapshot`,
  `Wallet::retire_pre_v6_snapshot`; new `origin::ANDROID_ORIGIN_PREFIX`,
  `origin::is_android_origin`; `cxf` limit constants.

### Tests

- Fuzz targets added: `restore_inspect`, `autofill_index`, `legacy_decrypt`,
  `origin_check`, `cxf_import_apply`; the CXF targets run with seeds and a
  1 MiB input size in the release gate.

### Dependencies

- `serde_json` gains the `raw_value` feature.

## 0.5.2

### Features

- **Passkeys** (new module `passkey`): IntelliWallet as a WebAuthn
  authenticator, platform neutral, for the iOS and Android providers.
  - A passkey is stored as a `PKEY` field on a login item (new system label,
    value type `pass`, so apps older than passkey support mask it). The value is
    a CXF-shaped JSON record; unknown fields survive round trips.
  - `sign::register` / `sign::assert`: ES256 only, attestation `none` with the
    IntelliWallet AAGUID `a2117fe2-e236-40fa-9481-ca437bd8b94e`, sign counter 0,
    flags UP, BE, BS always and UV only when the user was verified; keys,
    credential ids and PRF secrets from the OS random generator; deterministic
    DER signatures; `excludeCredentials` honoured.
  - `prf`: the WebAuthn PRF extension (`hmac-secret`), from raw inputs or
    pre-hashed salts. Every new passkey gets PRF secrets; imported ones keep
    theirs. The output is frozen by golden vectors.
  - `json`: Android's WebAuthn creation / request JSON (untrusted, bounded and
    validated), `clientDataJSON`, and the `PublicKeyCredential` response JSON.
  - `origin`: rpId against a browser origin with the full Public Suffix List,
    `android:apk-key-hash:` origins, `assetlinks.json` (`get_login_creds` only).
  - `Wallet::list_passkeys`, `Wallet::passkey_summary`.
  - `testdata/passkey-vectors.json`: every byte pinned, for the Swift
    implementation too. Verified externally against Yubico's `fido2` server.
- **AutoFill**: index format 2 carries passkeys (format 1 still opens); the
  journal accepts `PendingOp::CreatePasskey` records (binary framing unchanged,
  so every existing journal still reads); the drain applies staged passkeys
  (replace the same account's passkey with the old one kept in the trash,
  attach to the matching login, or a new item) and runs in one transaction.
- **CXF import and export** (new module `cxf`, FIDO Credential Exchange Format
  1.0): `Wallet::preview_cxf`, `Wallet::import_cxf` (automatic backup, one
  transaction, never modifies existing items, duplicate-free) and
  `Wallet::export_cxf` (whole vault or chosen folders, lossless). All 17 CXF
  credential types are mapped.
- `backup::inspect_backup_in`: a backup's date, entry count and passkey count,
  without its password.

### Security

- Dependencies upgraded; `cargo audit` goes from 10 vulnerabilities and 19
  warnings to none: `crypto-bigint` / `ctutils` timing fixes
  (RUSTSEC-2026-0387, -0385) for P-256, `zip` 9 with Deflate only (removes the
  zstd chain), `genpdf` (unmaintained, vulnerable `lopdf`) replaced by
  `printpdf`, yanked crates replaced.
- Restore streams the database with a 2 GiB cap (a crafted backup can no
  longer exhaust memory) and replaces it atomically (a failure no longer leaves
  a truncated database); stale `-wal` / `-shm` files are removed.
- `Debug` of `IWField`, `FieldValueUsage`, `IndexEntry`, `PendingRecord` and
  every new secret-holding type prints `[redacted]` instead of secrets.
- A passkey's private key and PRF secrets never leave through `get_fields`,
  `get_fields_by_item`, `get_deleted_fields`, `search` or the exports.
- Long-lived secrets (data key, KDF salts, AutoFill keys, passkey keys) come
  from the OS random generator directly (`crypto::rng`).
- CI: `cargo deny` and `cargo audit` jobs, required for a release.

### Fixes

- `Wallet::move_item` refuses to move an item into itself or a descendant,
  which detached that subtree.
- CSV and PDF exports no longer loop forever on a vault with a parent cycle.
- PDF export: a card taller than a page continues on the next page instead of
  being clipped; files are about five times smaller.

### API (breaking)

- `WalletError` gains `InvalidInput`, `NotSupported`, `PasskeyExcluded`.
- `autofill::PendingOp` gains `CreatePasskey`; `PendingRecord` gains `passkey`.
- `autofill::DrainSummary` gains `passkeys_added`, `passkeys_replaced`.
- `autofill::index::FORMAT_VERSION` is 2; new `build_with_passkeys`, `open_all`,
  `IndexContents`, `PasskeyIndexEntry`.
- `crypto::dek::generate_dek` returns `Result<Zeroizing<[u8; 32]>>`;
  `autofill::crypto::random_key` and `random_bytes` return `Result`.
- `add_field`, `update_field` and `copy_field` refuse the `PKEY` type;
  `copy_item` skips passkeys; for a `PKEY` field, the public field API returns a
  secret-free summary as the value.
- A backup compressed with anything but Deflate or Stored is refused.

### Tests

- Backups written by iwcore 0.1.3, 0.1.27, 0.2.0, 0.2.9, 0.3.0 and 0.4.0
  restore unchanged, field by field, and each then works with passkeys; CSV,
  JSON and XML exports are pinned to golden files.
- Property-based tests, fuzz targets (`fuzz/`, not published) for every
  untrusted parser, mutation testing on the new modules.

### Dependencies

- New: `base64` 0.23.1, `hmac` 0.13.0, `psl` 2.1.245, `printpdf` 0.12.8
  (default features off). Dev: `ciborium`, `coset`, `proptest`.
- Removed: `genpdf`.
- Apps should refresh their lockfile so the fixed `crypto-bigint` and `ctutils`
  are picked up (iwcore does not ship a lockfile).

## 0.4.0

### Features

- `Wallet::drain_autofill_journal` now reconciles staged records against the
  vault before importing them.

  A provider that cannot open the vault cannot know whether the login it just
  captured is new. The Android `AutofillService` is handed a password by the
  system with no authentication at all, so it cannot read the index at that
  moment and stages every capture as a `Create`. The drain is the only place
  with the whole vault open, so it is the place that decides:

  - a create naming a login the vault already holds, with the same password, is
    dropped;
  - a create naming a login the vault already holds, with a different password,
    becomes a password update on that item, with the previous value moved into
    `OLDP`;
  - anything else is imported into the `AutoFill` folder as before.

  "Already holds" means a `LINK` resolving to the same host or the same
  registrable domain, **and** the same identity value ignoring ASCII case.
  Looser match tiers are deliberately rejected: importing a duplicate is
  recoverable, overwriting the password of an entry that only loosely matched is
  not.

### Fixes

- Draining the same journal twice no longer imports the login twice. Records
  were deduplicated by `record_id` within a single journal only, so a crash
  between writing to the vault and deleting the journal produced a duplicate on
  the next drain, which the documentation already claimed could not happen.
  Reconciliation closes it.

### API

- `DrainSummary` gains `unchanged`, the count of records dropped because the
  vault already held them. Additive; existing fields are unchanged.
- `autofill::journal::count_records` counts the framed records in a journal
  without opening any of them. The provider needs the count to enforce the cap
  at save time, where on Android it holds no key it is willing to use.

No format change. The index layout, the journal framing, the key hierarchy and
everything the iOS extension reads or writes are byte-identical to 0.3.0.

## 0.3.0

### Features

- New `autofill` module: everything a platform autofill provider (the iOS
  AutoFill extension, and later the Android `AutofillService`) needs, without
  ever letting that provider open the vault.

  - `autofill::index` builds a sealed snapshot of the vault's login entries.
    Sealed as a single ChaCha20-Poly1305 blob with the plaintext header
    authenticated as AAD, and padded to a 4 KiB boundary so the file size does
    not disclose the entry count. Only entries that have a password, and only
    the identity, password and link fields: notes, seed phrases, card numbers,
    PINs and security answers are never copied.
  - `autofill::journal` carries logins created inside the provider until the app
    drains them. Records are dual-wrapped: to an app-only P-256 public key, and
    under the shared index key. The first guarantees the app can always drain,
    even after the index key is rotated or invalidated; the second lets the
    provider show a login it just created. Records are independently sealed and
    framed, so a torn write costs at most the last one.
  - `autofill::identity` classifies a login identity into exactly one of `MAIL`,
    `USER` or `ACNT`, and the index resolves the same three in that priority on
    the way out, so an entry round-trips unchanged.
  - `autofill::domain` normalizes free-text `LINK` values into comparable hosts
    and precomputes registrable domains against a curated public suffix list, so
    the provider needs no suffix list of its own. Includes a hand-rolled RFC 3492
    punycode encoder rather than a dependency on the full IDNA crate chain.
  - `Wallet::build_autofill_index` and `Wallet::drain_autofill_journal` tie it to
    the vault. The plaintext credential set never leaves Rust: callers pass keys
    in and get sealed bytes out.

- Drained logins become ordinary items with ordinary field types. No schema
  change, no new field type, no marker column, so older builds and the CLI read
  them without knowing autofill exists.

### Dependencies

- Added `p256`, `hkdf` and `sha2` for the journal's ECDH key wrapping. The
  construction (P-256 ECDH, HKDF-SHA256, ChaCha20-Poly1305 with a 96-bit nonce)
  is deliberately limited to what Apple's CryptoKit exposes natively, so the iOS
  extension needs no Rust and no third-party crypto of its own.

### Compatibility

- Purely additive. No change to the vault format, the schema, `open`, `unlock`
  or `change_password`.

## 0.2.4

### Bug fixes

- Fixed a legacy (v5) vault decryption bug: databases whose `email` column
  (the legacy AES re-encryption counter) is SQL `NULL` instead of `"0"` were
  silently treated as if it were `200`, deriving the wrong key and rejecting
  the correct password on backup import and on first unlock after upgrade.
  `NULL`/unparseable now falls back to `0`, matching the original app's
  behavior.

## 0.2.3

### Dependencies

- Moved `chacha20poly1305` off its release candidate onto the stable 0.11.0
  release.
- Bumped `zeroize` to 1.9.0, `rand` to 0.10.2, and `uuid` to 1.23.4.

## 0.2.2

### Documentation & maintenance

- Aligned the README and crate-level docs with the 0.2.x encryption scheme
  (XChaCha20-Poly1305 + Argon2id): corrected the description, added a Security
  section covering the authenticated-encryption model and the transparent,
  crash-safe migration, and refreshed the password-change and
  password-generation examples.
- Added links to IntelliWallet (the password manager built on this library) and
  its Google Play / App Store listings.
- Upgraded CI to current GitHub Actions majors (`actions/checkout@v5`,
  `codecov/codecov-action@v5`) to clear the Node.js 20 deprecation warnings.

## 0.2.0

### Security: new authenticated encryption scheme (v6)

The core encryption has been replaced. Item names and field values are now
protected with **XChaCha20-Poly1305** authenticated encryption over a random,
per-vault **Data Encryption Key (DEK)**, with the DEK wrapped by a key derived
from the master password using **Argon2id** (per-vault salt, parameters stored
in the database).

This replaces the previous scheme (zero-IV AES-256-CBC with an unsalted MD5
checksum) and fixes its core weaknesses:

- a real, memory-hard key derivation instead of using the password as the key;
- a unique random nonce per value (no more deterministic ciphertext);
- authenticated encryption that detects tampering;
- per-vault salt, so identical passwords no longer yield identical ciphertext.

### Transparent, crash-safe migration (v5 → v6)

Existing vaults upgrade automatically the first time they are unlocked:

- the upgrade runs in a single transaction and is **atomic** — an interruption
  or failure rolls back to a fully working previous-version vault, and the next
  unlock simply retries;
- a one-time snapshot of the original database is written next to it and
  **kept** as a recovery anchor;
- unreadable, long-dead soft-deleted history is purged during the upgrade;
- no readable data changes — users and the app see identical content before and
  after.

### Other changes

- **Faster password changes.** Changing the master password now re-wraps the DEK
  instead of re-encrypting the whole vault — effectively instant, and it leaves
  stored data untouched.
- **Database version is now 6.** Backups produced by 0.2.0 require 0.2.0 or
  later; older versions correctly reject them. 0.2.0 reads and migrates older
  backups on restore.
- **In-memory keys are zeroized** on lock and drop.
- **No public/FFI API changes** — callers need no code changes. Newly created
  vaults are born at v6.

### Dependencies

- Major upgrades across the board: `rusqlite` 0.40, `zip` 8, `rand` 0.10,
  `uuid` 1.23, `tempfile` 3.27.
- Crypto crates moved to stable releases (`aes`, `cbc`, `md-5`) and new crates
  added (`argon2`, `chacha20poly1305`, `zeroize`).

### Quality

- New migration test suite runs the full upgrade against real vault data,
  covering data preservation, rollback/recovery, idempotency, and backups in
  both directions.
- CI now enforces `cargo clippy --all-targets -- -D warnings`.
- Line coverage ~90%.

### Notes

- The Argon2id cost parameters are defined as constants and stored per vault, so
  they can be raised in a future version without breaking existing vaults.
  Validate the defaults on a low-end target device before release.
