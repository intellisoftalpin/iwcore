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
- **Hierarchical Organization** - Organize items in folders
- **Custom Field Types** - 19 built-in field types (email, password, credit card, etc.)
- **Backup & Restore** - ZIP-based backup with versioning
- **Multi-language Support** - 11 languages included
- **Password Generator** - Random and pattern-based password generation

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
iwcore = "0.1"
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

// Create backup
let backup_mgr = BackupManager::new(Path::new("./backups"));
let backup_path = backup_mgr.create_backup(&wallet.database_path(), true)?;

// List backups
let backups = backup_mgr.list_backups()?;

// Restore backup
backup_mgr.restore_backup(&backup_path, Path::new("./restored.dat"))?;
```

## Field Types

iwcore supports 19 built-in field types:

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
