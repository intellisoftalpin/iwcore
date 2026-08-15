# Changelog

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
