# iwcore

[![Crates.io](https://img.shields.io/crates/v/iwcore.svg)](https://crates.io/crates/iwcore)
[![Documentation](https://img.shields.io/docsrs/iwcore)](https://docs.rs/iwcore/latest/iwcore/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/intellisoftalpin/iwcore/actions/workflows/ci.yml/badge.svg)](https://github.com/intellisoftalpin/iwcore/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/intellisoftalpin/iwcore/branch/main/graph/badge.svg)](https://codecov.io/gh/intellisoftalpin/iwcore)

**IntelliWallet Core** - A secure password manager library with AES-256 encryption.

## Features

- **AES-256-CBC Encryption** - Industry-standard encryption with PKCS7 padding
- **SQLite Storage** - Reliable database storage with full ACID compliance
- **Hierarchical Organization** - Organize items in folders with drag-and-drop support
- **Custom Field Types** - 20 built-in field types (email, password, credit card, etc.) plus custom labels
- **Delete & Restore** - Soft-delete with full undo capability for items and fields
- **Backup & Restore** - ZIP-based backup with versioning, auto-cleanup, and integrity verification
- **Multi-language Support** - 11 languages included
- **Password Generator** - Random and pattern-based password generation
- **Search** - Full-text search across item names and field values
- **Export** - Data export with PDF item model support
- **Database Maintenance** - Compact/optimize database by purging deleted records

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
iwcore = "0.1.11"
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
// Change wallet password (re-encrypts all data including deleted records)
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
use iwcore::{generate_password, generate_clever_password, PasswordOptions};

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

- [Homepage](https://intelliwallet.io)
- [Documentation](https://docs.rs/iwcore)
- [Repository](https://github.com/intellisoftalpin/iwcore)
