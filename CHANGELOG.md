# Changelog

## 0.5.0

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
