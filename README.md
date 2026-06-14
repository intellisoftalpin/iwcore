# iwcore

[![Crates.io](https://img.shields.io/crates/v/iwcore.svg)](https://crates.io/crates/iwcore)
[![Documentation](https://img.shields.io/docsrs/iwcore)](https://docs.rs/iwcore/latest/iwcore/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/intellisoftalpin/iwcore/actions/workflows/ci.yml/badge.svg)](https://github.com/intellisoftalpin/iwcore/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/intellisoftalpin/iwcore/branch/main/graph/badge.svg)](https://codecov.io/gh/intellisoftalpin/iwcore)

**IntelliWallet Core** (`iwcore`) is an open-source **Rust password manager library**: a small, embeddable engine for building secure password managers and digital vaults. It bundles authenticated encryption (**XChaCha20-Poly1305 + Argon2id**), encrypted SQLite storage, backups, search, and password generation behind a clean API.

It is the storage and cryptography engine behind **[IntelliWallet](https://intelliwallet.io/)**, a free cross-platform password manager available on [Google Play](https://play.google.com/store/apps/details?id=com.nyxbull.nswallet) and the [App Store](https://apps.apple.com/app/intelliwallet/id6744400972).

The core is **open by design**: anyone can audit exactly how IntelliWallet protects your data, and anyone can use `iwcore` to build their own client or an alternative to IntelliWallet.

## Contents

- [Features](#features)
- [Security](#security)
- [Open Source](#open-source)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#opening-an-existing-wallet)
- [Field Types](#field-types)
- [Supported Languages](#supported-languages)
- [License](#license)

## Features

- **Authenticated Encryption** - XChaCha20-Poly1305 (AEAD) over a per-vault Data Encryption Key, wrapped by an Argon2id-derived key; unique nonce per value and built-in tamper detection
- **SQLite Storage** - Reliable database storage with full ACID compliance
- **Hierarchical Organization** - Organize items in folders with drag-and-drop support
- **Custom Field Types** - 20 built-in field types (email, password, credit card, etc.) plus custom labels
- **Delete & Restore** - Soft-delete with full undo capability for items and fields
- **Backup & Restore** - ZIP-based backup with versioning, auto-cleanup, and integrity verification
- **Multi-language Support** - 11 languages included
- **Password Generator** - Random, pattern-based, and memorable password generation
- **Search** - Full-text search across item names and field values
- **Export** - Data export with PDF item model support
- **Database Maintenance** - Compact/optimize database by purging deleted records

## Security

iwcore protects item names and field values with modern authenticated encryption:

- **XChaCha20-Poly1305 (AEAD)** encrypts every value with a unique random nonce, so identical plaintext never yields identical ciphertext, and any tampering is detected on decryption.
- **Per-vault Data Encryption Key (DEK).** A random 256-bit DEK encrypts all data. The DEK is stored wrapped (encrypted) under a Key Encryption Key derived from the master password with **Argon2id** (memory-hard, per-vault random salt, parameters stored per vault). Password verification is simply "can we unwrap the DEK", so there is no separate verifier to attack.
- **Cheap password changes and future hardening.** Changing the master password (or raising the Argon2id cost in a future release) only re-wraps the DEK; stored data is never re-encrypted.
- **In-memory keys are zeroized** when the wallet is locked or dropped.
- **Newly created vaults are born with this scheme.**

## Open Source

We believe the security of a password manager should be **verifiable, not taken on trust**. That is why the core of IntelliWallet is open source:

- **Auditable.** Anyone can read exactly how vaults are encrypted, how keys are derived, and how data is stored. No black boxes around your passwords, security through transparency, not obscurity.
- **Reusable.** `iwcore` is a standalone, MIT-licensed library. You are free to use it to build your own password manager or an alternative client to IntelliWallet.
- **Improvable.** Anyone can propose enhancements, open a pull request, or fork the project. The library grows with its community.
- **Yours for the long run.** Because the storage format and cryptography are open, you can always recover and use your data independently, regardless of the future of the IntelliWallet app or [IntelliSoftAlpin eG](https://intellisoftalpin.com). Your vault outlives any single product or company.
- **Standard cryptography.** We rely on well-reviewed primitives from the Rust community (XChaCha20-Poly1305, Argon2id) rather than home-grown schemes.

Found a security issue? Responsible disclosure is appreciated, please open an issue or get in touch.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
iwcore = "0.2.2"
```

Or use cargo:

```bash
cargo add iwcore
```

## Quick Start

```rust
use iwcore::Wallet;
use std::path::Path;

// Create a new wallet
let mut wallet = Wallet::create(Path::new("./my_wallet"), "my_password", "en")?;

// Add an item
let item_id = wallet.add_item("My Email", "document", false, None)?;

// Add fields to the item
wallet.add_field(&item_id, "MAIL", "user@example.com", None)?;
wallet.add_field(&item_id, "PASS", "secret123", None)?;

// Search for items
let results = wallet.search("email")?;
for result in results {
    println!("Found: {}", result.item.name);
}

// Close the wallet
wallet.close();
```

## Opening an Existing Wallet

```rust
use iwcore::Wallet;
use std::path::Path;

let mut wallet = Wallet::open(Path::new("./my_wallet"))?;

// Unlock with password
if wallet.unlock("my_password")? {
    let items = wallet.get_items()?;
    for item in items {
        println!("{}: {}", item.item_id, item.name);
    }
}

wallet.close();
```

## Item & Field Management

```rust
// Create folders and items
let folder_id = wallet.add_item("Work", "folder", true, None)?;
let item_id = wallet.add_item("Server Login", "document", false, Some(&folder_id))?;

// Add, update, copy, move fields
let field_id = wallet.add_field(&item_id, "USER", "admin", None)?;
wallet.update_field(&field_id, "root", None)?;
wallet.copy_field(&item_id, &field_id, &other_item_id)?;
wallet.move_field(&item_id, &field_id, &other_item_id)?;

// Move and copy items
wallet.move_item(&item_id, &new_folder_id)?;
let copy_id = wallet.copy_item(&item_id)?;

// Soft-delete and restore
wallet.delete_item(&item_id)?;
let deleted = wallet.get_deleted_items()?;
wallet.undelete_item(&item_id)?;

wallet.delete_field(&item_id, &field_id)?;
let deleted_fields = wallet.get_deleted_fields()?;
wallet.undelete_field(&item_id, &field_id)?;

// Purge all soft-deleted records permanently
let (purged_items, purged_fields) = wallet.compact()?;
```

## Password Management

```rust
// Change wallet password (re-wraps the data key; stored data is untouched, effectively instant)
wallet.change_password("new_secure_password")?;

// Check password without unlocking
let valid = wallet.check_password("my_password")?;

// Lock/unlock session
wallet.lock();
assert!(!wallet.is_unlocked());
wallet.unlock("my_password")?;
```

## Password Generation

```rust
use iwcore::{
    generate_password, generate_clever_password, generate_memorable_password,
    PasswordOptions, MemorableOptions, MemorableCaps,
};

// Random password with options
let options = PasswordOptions {
    lowercase: true,
    uppercase: true,
    digits: true,
    special: true,
    length: 16,
};
let password = generate_password(&options);

// Pattern-based password (A=uppercase, a=lowercase, 0=digit, @=special)
let password = generate_clever_password("Aaaa0000@@");

// Memorable password, e.g. "Garden7-River4-Maple2-Stone9"
let memorable = generate_memorable_password(&MemorableOptions {
    num_words: 4,
    digits_per_word: 1,
    separator: "-".to_string(),
    prefix: String::new(),
    caps: MemorableCaps::First,
});
```

## Backup & Restore

```rust
use iwcore::{Wallet, BackupManager};
use std::path::Path;

let wallet = Wallet::open(Path::new("./my_wallet"))?;

// Create backup (automatically checkpoints WAL for data consistency)
let backup_mgr = BackupManager::new(Path::new("./backups"));
let backup_path = backup_mgr.create_backup(wallet.database()?, true)?;

// List and manage backups
let backups = backup_mgr.list_backups()?;
let latest = backup_mgr.get_latest_backup()?;

// Verify backup integrity
backup_mgr.verify_backup(&backup_path)?;

// Restore backup
backup_mgr.restore_backup(&backup_path, Path::new("./restored.dat"))?;

// Cleanup old backups
backup_mgr.cleanup_old_backups(5)?;
backup_mgr.cleanup_auto_backups(3, 30)?;
```

Backups carry the database version, so newer backups are correctly rejected by older
versions, while newer versions can read and migrate older backups on restore.

## Custom Labels

```rust
// Add a custom field type
wallet.add_label("CUST", "Custom Field", "text", "tag")?;

// Update label properties
wallet.update_label_name("CUST", "My Custom Field")?;
wallet.update_label_icon("CUST", "star")?;

// Delete custom label
wallet.delete_label("CUST")?;
```

## Field Types

iwcore supports 20 built-in field types:

| Code | Name | Value Type |
|------|------|------------|
| MAIL | Email | email |
| PASS | Password | password |
| NOTE | Note | text |
| LINK | Link | link |
| ACNT | Account | text |
| CARD | Card | text |
| NAME | Name | text |
| PHON | Phone | phone |
| PINC | PIN | text |
| USER | Username | text |
| OLDP | Old Password | password |
| DATE | Date | date |
| TIME | Time | time |
| EXPD | Expiry Date | date |
| SNUM | Serial Number | text |
| ADDR | Address | text |
| SQUE | Secret Question | text |
| SANS | Secret Answer | text |
| 2FAC | 2FA | text |
| SEED | Seed Phrase | text |

## Supported Languages

- English (en)
- German (de)
- Russian (ru)
- Ukrainian (uk)
- Polish (pl)
- Portuguese (pt)
- Belarusian (be)
- Bulgarian (bg)
- Hindi (hi)
- Catalan (ca)
- Spanish (es)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Links

- [IntelliWallet](https://intelliwallet.io/) - the password manager built on this library
- [IntelliWallet on Google Play](https://play.google.com/store/apps/details?id=com.nyxbull.nswallet)
- [IntelliWallet on the App Store](https://apps.apple.com/app/intelliwallet/id6744400972)
- [Documentation](https://docs.rs/iwcore)
- [Repository](https://github.com/intellisoftalpin/iwcore)
- [IntelliSoftAlpin eG](https://intellisoftalpin.com) - the company behind IntelliWallet
