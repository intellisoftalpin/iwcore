# Changelog

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
