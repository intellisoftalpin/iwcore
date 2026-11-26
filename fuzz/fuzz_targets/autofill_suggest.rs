//! The site being filled comes from a browser or an app, and stored links are
//! free text. Ranking must never panic, must list every login at most once,
//! and must keep its promises about what lands in which section.
#![no_main]
use iwcore::autofill::{domain, index, suggest, IndexEntry, Picks, Reason, Section};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut lines = text.split('\n');
    let query = lines.next().unwrap_or("");
    let picked = lines.next().filter(|p| !p.is_empty());
    let entries: Vec<IndexEntry> = lines
        .take(16)
        .enumerate()
        .map(|(i, line)| {
            let mut parts = line.split('|');
            let title = parts.next().unwrap_or("").to_string();
            let hosts: Vec<String> = parts.filter_map(domain::normalize_host).collect();
            let (registrable, names) = index::derived_keys(&hosts);
            IndexEntry {
                item_id: i.to_string(),
                title,
                identity_type: "USER".into(),
                username: "u".into(),
                password: "p".into(),
                totp_secret: None,
                hosts,
                registrable,
                names,
            }
        })
        .collect();

    let got = suggest(&entries, query, picked);
    let mut seen = std::collections::HashSet::new();
    for s in &got {
        assert!(seen.insert(s.entry), "a login is listed once");
        let e = &entries[s.entry];
        match s.reason {
            Reason::Picked => assert_eq!(Some(e.item_id.as_str()), picked),
            Reason::TitleName => assert!(e.hosts.is_empty() && s.host.is_none()),
            _ => assert!(s.host.as_ref().is_some_and(|h| e.hosts.contains(h))),
        }
        // A domain match is never weaker than the same-name section, and a
        // same-name match never shares the query's registrable domain.
        if s.section == Section::SameName {
            let q = domain::normalize_host(query).and_then(|h| domain::registrable_domain(&h));
            if let Some(h) = &s.host {
                assert!(q.is_none() || domain::registrable_domain(h) != q);
            }
        }
    }
    for pair in got.windows(2) {
        assert!(pair[0].section <= pair[1].section, "sorted by section");
    }

    let mut picks = Picks::new();
    let _ = picks.record(query, picked.unwrap_or("x"), 1);
    let sealed = picks.seal(&[1; 32], "db").unwrap();
    assert_eq!(Picks::open(&sealed, &[1; 32], "db"), picks);
    let _ = Picks::open(data, &[1; 32], "db");
});
