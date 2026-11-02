//! Legacy (v5) blobs come from old vaults and old backups: untrusted. The
//! migration decrypts them with every candidate key; a malformed blob, or a
//! plaintext that only looks like a checksum, must be an error, never a panic.
#![no_main]
use iwcore::crypto::legacy::LegacyKeyChain;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte: iteration count (0, 200 and small odd counts cover every
    // candidate set); next byte: password length; then the password, then
    // the ciphertext.
    let Some((&count, rest)) = data.split_first() else { return };
    let count = match count {
        0..=9 => 0,
        10..=19 => 200,
        n => u32::from(n % 8),
    };
    let Some((&pw_len, rest)) = rest.split_first() else { return };
    let pw_len = usize::from(pw_len % 40).min(rest.len());
    let (pw, blob) = rest.split_at(pw_len);
    let password = String::from_utf8_lossy(pw);
    let mut chain = LegacyKeyChain::new(&password, count);
    let first = chain.decrypt(blob);
    // A second pass takes the remembered-candidate path and must agree.
    let second = chain.decrypt(blob);
    assert_eq!(first.is_ok(), second.is_ok());
    if let (Ok(a), Ok(b)) = (&first, &second) {
        assert_eq!(a, b);
    }
    let _ = chain.preferred_mode();
    // The same blob under a fixed known key set.
    let _ = LegacyKeyChain::new("Sun001!", 0).decrypt(blob);
});
