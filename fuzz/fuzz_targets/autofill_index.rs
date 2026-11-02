//! The AutoFill index is read by the provider from a shared container: its
//! header is parsed before any key is at hand (`peek_header`), and its body is
//! decoded after the AEAD opens. Both must survive any bytes.
//!
//! Every input is used twice:
//! - as a whole index file, for `peek_header` and `open_all`;
//! - as the plaintext body of an index sealed under a valid header and the
//!   right key, so the length prefix and JSON decoding (logins, passkeys) are
//!   reached, which random ciphertext never would. The first byte picks the
//!   format and whether the length prefix and padding are added for it.
#![no_main]
use iwcore::autofill::{crypto, index, IndexHeader};
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [7; 32];
const OTHER_KEY: [u8; 32] = [8; 32];

/// The on-disk header, as `index::build` writes it.
fn header_bytes(header: &IndexHeader) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(index::MAGIC);
    out.push(header.format_version);
    out.extend_from_slice(&header.generation.to_le_bytes());
    out.extend_from_slice(&header.built_at.to_le_bytes());
    out.push(u8::try_from(header.database_id.len()).unwrap());
    out.extend_from_slice(header.database_id.as_bytes());
    out
}

fn sealed_file(header: &IndexHeader, padded: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut file = header_bytes(header);
    let sealed = crypto::seal(key, padded, &file).unwrap();
    file.extend_from_slice(&sealed);
    file
}

fuzz_target!(|data: &[u8]| {
    // 1. The raw file. An index that opens has the header peek_header reports.
    let peeked = index::peek_header(data);
    if let Ok((header, _)) = index::open_all(data, &KEY) {
        assert_eq!(peeked.as_ref().ok(), Some(&header));
    }
    let _ = index::open(data, &KEY);

    // 2. The input as a body sealed under a valid header.
    let Some((&mode, body)) = data.split_first() else { return };
    let header = IndexHeader {
        format_version: 1 + (mode & 1),
        generation: u64::from(mode),
        built_at: -1,
        database_id: "fuzz".into(),
    };
    let padded = if mode & 2 != 0 {
        // Well-framed: length prefix, JSON, zero padding to the block size.
        let mut p = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
        p.extend_from_slice(body);
        p.resize(p.len().next_multiple_of(index::PAD_BLOCK), 0);
        p
    } else {
        body.to_vec()
    };
    let file = sealed_file(&header, &padded, &KEY);

    assert_eq!(index::peek_header(&file).unwrap(), header);
    assert!(index::open_all(&file, &OTHER_KEY).is_err(), "a wrong key never opens");
    let mut tampered = file.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
        assert!(index::open_all(&tampered, &KEY).is_err(), "a changed byte never opens");
    }

    let Ok((opened_header, contents)) = index::open_all(&file, &KEY) else { return };
    assert_eq!(opened_header, header);
    if header.format_version == 1 {
        assert!(contents.passkeys.is_empty(), "format 1 holds no passkeys");
    }
    for p in &contents.passkeys {
        let _ = p.summary();
        let _ = format!("{p:?}");
    }

    // 3. What opened writes back and reopens to the same contents.
    let rebuilt = index::build_with_passkeys(&contents.logins, &contents.passkeys, &KEY, &header);
    if let Ok(rebuilt) = rebuilt {
        let (h, again) = index::open_all(&rebuilt, &KEY).unwrap();
        assert_eq!(h, header);
        assert_eq!(again.logins, contents.logins);
        let summaries = |c: &index::IndexContents| c.passkeys.iter().map(|p| p.summary()).collect::<Vec<_>>();
        assert_eq!(summaries(&again), summaries(&contents));
    }
});
