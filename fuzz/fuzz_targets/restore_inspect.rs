//! A backup file comes from outside (another device, a download, a share):
//! untrusted. Inspecting it, reading its version and checking compatibility
//! must return an error for any bytes, never panic or run for long.
//!
//! The first byte picks the shape: odd = the bytes are the whole backup file,
//! even = the bytes are the database inside an otherwise well-formed backup,
//! so the database checks are reached without the fuzzer first having to
//! build a valid zip.
#![no_main]
use std::io::Write;

use iwcore::backup::{inspect_backup_in, is_backup_compatible_in};
use libfuzzer_sys::fuzz_target;

fn zip_with_database(db: &[u8]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    if zip.start_file("nswallet.dat", options).is_err() || zip.write_all(db).is_err() {
        return Vec::new();
    }
    zip.finish().map(|c| c.into_inner()).unwrap_or_default()
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let bytes = if mode & 1 == 1 { rest.to_vec() } else { zip_with_database(rest) };

    let Ok(dir) = tempfile::TempDir::new() else { return };
    let backup = dir.path().join("iwb-20260101-120000-manual.zip");
    if std::fs::write(&backup, &bytes).is_err() {
        return;
    }
    let temp_base = dir.path().join("tmp");
    let _ = inspect_backup_in(&backup, &temp_base);
    let _ = is_backup_compatible_in(&backup, "6", &temp_base);
});
