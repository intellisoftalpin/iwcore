//! Host normalization and registrable-domain computation for autofill matching.
//!
//! `LINK` field values are free text. Users paste full URLs, bare hosts, hosts
//! with ports, and occasionally junk. Everything in this module runs on the
//! **app** side while the index is built, and the results are stored in the
//! index precomputed, so the iOS AutoFill extension only ever does plain string
//! comparison and never needs a public suffix list of its own.
//!
//! # Why the registrable domain matters
//!
//! Matching on the bare last two labels is wrong for multi-label suffixes:
//! `login.example.co.uk` and `evil.co.uk` would both reduce to `co.uk` and
//! appear to match each other. For a password manager that is not a cosmetic
//! bug, so the registrable domain (eTLD+1) is computed against a suffix list
//! and a candidate that is itself a public suffix is rejected outright.
//!
//! # Limitation, stated plainly
//!
//! `PUBLIC_SUFFIXES` is a **curated subset** of the Mozilla Public Suffix
//! List, not the full list, chosen to keep a published library free of a large
//! generated data table. Hosts under a multi-label suffix that is not listed
//! fall back to last-two-labels, which can be too permissive. Exact-host
//! matching is unaffected and always correct, and no automatic filling ever
//! happens without an explicit user tap, so the blast radius of a missing
//! suffix is a suggestion ranked higher than it deserves, not a silent leak.

/// Match strength between a stored entry and the site being filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchTier {
    /// The stored host is a subdomain of the query host, or vice versa.
    HostSuffix,
    /// Both resolve to the same registrable domain (eTLD+1).
    RegistrableDomain,
    /// Byte-for-byte identical hosts.
    ExactHost,
}

/// URI schemes that never denote a web login target. A `LINK` field holding one
/// of these yields no host at all rather than a bogus one.
const REJECTED_SCHEMES: [&str; 8] = [
    "mailto", "javascript", "data", "tel", "sms", "file", "about", "blob",
];

/// Curated subset of the Mozilla Public Suffix List. MUST stay sorted:
/// lookups are a binary search. See the module docs for why this is a subset.
const PUBLIC_SUFFIXES: &[&str] = &[
    "ac.at", "ac.cn", "ac.il", "ac.in", "ac.jp", "ac.kr", "ac.nz", "ac.th",
    "ac.uk", "ac.za", "ad.jp", "appspot.com", "azurewebsites.net", "blogspot.com",
    "cloudfront.net", "co.id", "co.il", "co.in", "co.jp", "co.ke", "co.kr",
    "co.nz", "co.th", "co.tz", "co.ug", "co.uk", "co.za", "com.ar", "com.au",
    "com.bo", "com.br", "com.cn", "com.co", "com.cy", "com.ec", "com.eg",
    "com.es", "com.gh", "com.gr", "com.hk", "com.kw", "com.mt", "com.mx",
    "com.my", "com.ng", "com.pe", "com.ph", "com.pk", "com.pl", "com.pt",
    "com.py", "com.qa", "com.sa", "com.sg", "com.tr", "com.tw", "com.ua",
    "com.uy", "com.ve", "com.vn", "ed.jp", "edu.au", "edu.br", "edu.cn",
    "edu.es", "edu.hk", "edu.in", "edu.my", "edu.pl", "edu.pt", "edu.sg",
    "edu.tr", "edu.tw", "edu.vn", "firebaseapp.com", "firm.in", "gen.in",
    "github.dev", "github.io", "gitlab.io", "glitch.me", "go.jp", "go.kr",
    "go.th", "gob.es", "gov.au", "gov.br", "gov.cn", "gov.hk", "gov.il",
    "gov.in", "gov.my", "gov.pl", "gov.pt", "gov.sg", "gov.tr", "gov.tw",
    "gov.ua", "gov.uk", "govt.nz", "gr.jp", "gv.at", "herokuapp.com", "id.au",
    "in.th", "in.ua", "ind.in", "kiev.ua", "lg.jp", "ltd.uk", "me.uk", "my.id",
    "myshopify.com", "ne.jp", "ne.kr", "net.au", "net.br", "net.cn", "net.gr",
    "net.hk", "net.in", "net.my", "net.nz", "net.pk", "net.pl", "net.sg",
    "net.tr", "net.tw", "net.ua", "net.uk", "net.vn", "netlify.app", "nom.es",
    "or.at", "or.id", "or.jp", "or.kr", "org.au", "org.br", "org.cn", "org.es",
    "org.gr", "org.hk", "org.il", "org.in", "org.nz", "org.pk", "org.pl",
    "org.pt", "org.sg", "org.tw", "org.ua", "org.uk", "org.za", "pages.dev",
    "re.kr", "sch.uk", "vercel.app", "web.app", "web.id", "wordpress.com",
    "workers.dev",
];

/// True if `candidate` is a known multi-label public suffix.
pub fn is_public_suffix(candidate: &str) -> bool {
    PUBLIC_SUFFIXES.binary_search(&candidate).is_ok()
}

/// Normalize a raw `LINK` value into a comparable host.
///
/// Strips the scheme, path, query, fragment, userinfo and port; lowercases;
/// removes a trailing root dot and a leading `www.`; and converts non-ASCII
/// labels to punycode so a host typed in Cyrillic matches the `xn--` form iOS
/// supplies. Returns `None` for anything that does not yield a plausible host.
///
/// Never panics, whatever the input.
pub fn normalize_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Scheme. `://` is the common form; a bare `scheme:` prefix is how the
    // schemes we reject (mailto:, javascript:, ...) actually appear.
    let after_scheme = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            if is_rejected_scheme(scheme) {
                return None;
            }
            rest
        }
        None => {
            if let Some((scheme, _)) = trimmed.split_once(':')
                && is_rejected_scheme(scheme)
            {
                return None;
            }
            trimmed
        }
    };

    // Protocol-relative form (`//example.com/x`), which users do paste.
    let after_scheme = after_scheme.strip_prefix("//").unwrap_or(after_scheme);

    // Authority ends at the first path, query or fragment delimiter.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        return None;
    }

    // Userinfo: everything up to and including the last `@`.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);

    let host = strip_port(host_port)?;
    if host.is_empty() {
        return None;
    }

    let lowered = host.to_lowercase();
    let no_root_dot = lowered.trim_end_matches('.');
    if no_root_dot.is_empty() {
        return None;
    }

    let ascii = to_ascii_host(no_root_dot)?;
    let stripped = ascii.strip_prefix("www.").unwrap_or(&ascii);
    if stripped.is_empty() {
        return None;
    }

    is_plausible_host(stripped).then(|| stripped.to_string())
}

/// Compute the registrable domain (eTLD+1) of an already-normalized host.
///
/// Returns `None` for IP literals, single-label hosts, and any host that is
/// itself a public suffix, because none of those may be used as a matching key:
/// treating `co.uk` as a registrable domain would match every British site
/// against every other.
pub fn registrable_domain(host: &str) -> Option<String> {
    if host.is_empty() || is_ip_literal(host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }

    // Longest matching public suffix wins, so `s3.amazonaws.com`-style
    // three-label suffixes beat any two-label prefix of themselves.
    let best_suffix_labels = (0..labels.len())
        .find(|&start| labels.get(start..).is_some_and(|tail| is_public_suffix(&tail.join("."))))
        .map_or(0, |start| labels.len().saturating_sub(start));

    let take = if best_suffix_labels > 0 {
        best_suffix_labels.checked_add(1)?
    } else {
        2
    };
    let first = labels.len().checked_sub(take)?;
    let candidate = labels.get(first..)?.join(".");
    // Belt and braces for suffixes missing from the curated list.
    if is_public_suffix(&candidate) {
        return None;
    }
    Some(candidate)
}

/// Strength of the match between a stored host and the host being filled.
/// `None` means the two are unrelated and the entry must not be suggested by
/// domain at all.
pub fn match_tier(stored_host: &str, query_host: &str) -> Option<MatchTier> {
    if stored_host.is_empty() || query_host.is_empty() {
        return None;
    }
    if stored_host == query_host {
        return Some(MatchTier::ExactHost);
    }
    let stored_reg = registrable_domain(stored_host);
    let query_reg = registrable_domain(query_host);
    if let (Some(a), Some(b)) = (&stored_reg, &query_reg)
        && a == b
    {
        return Some(MatchTier::RegistrableDomain);
    }
    // A label-aligned suffix relationship, so `example.com` cannot match
    // `notexample.com`. Only meaningful when a registrable domain exists;
    // without one we would be comparing bare suffixes again.
    if stored_reg.is_some()
        && query_reg.is_some()
        && (is_subdomain_of(stored_host, query_host) || is_subdomain_of(query_host, stored_host))
    {
        return Some(MatchTier::HostSuffix);
    }
    None
}

fn is_subdomain_of(child: &str, parent: &str) -> bool {
    child
        .strip_suffix(parent)
        .is_some_and(|head| head.ends_with('.'))
}

fn is_rejected_scheme(scheme: &str) -> bool {
    let lowered = scheme.trim().to_ascii_lowercase();
    REJECTED_SCHEMES.contains(&lowered.as_str())
}

/// Remove a `:port` suffix, handling bracketed IPv6 literals. Returns `None`
/// when the authority is structurally broken (an unclosed bracket).
fn strip_port(host_port: &str) -> Option<&str> {
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) => {
            // Only a genuinely numeric tail is a port. A bare unbracketed IPv6
            // literal has several colons and no numeric-only tail, and is left
            // intact rather than truncated.
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                Some(host)
            } else {
                Some(host_port)
            }
        }
        None => Some(host_port),
    }
}

fn is_plausible_host(host: &str) -> bool {
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return false;
    }
    if host.starts_with('-') || host.ends_with('-') {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b':')
}

/// Registrable domain of a normalized host under the full Public Suffix List
/// (ICANN and private sections, `psl` crate), as WebAuthn scopes passkeys.
///
/// The curated list above is enough to rank logins, but a passkey is bound to
/// its rpId: two hosts under a hosting suffix the curated list does not carry
/// (`a.onrender.com`, `b.onrender.com`) belong to different owners. Returns
/// `None` for IP literals and for hosts that are themselves public suffixes.
pub(crate) fn psl_registrable_domain(host: &str) -> Option<&str> {
    if host.is_empty() || is_ip_literal(host) {
        return None;
    }
    psl::domain_str(host)
}

/// May a passkey for `rp_id` sit on a login stored for `stored_host`?
///
/// Yes when both normalize to the same host, or when both have the same
/// registrable domain under the full Public Suffix List.
pub(crate) fn passkey_matches_host(stored_host: &str, rp_id: &str) -> bool {
    let (Some(stored), Some(rp)) = (normalize_host(stored_host), normalize_host(rp_id)) else {
        return false;
    };
    if stored == rp {
        return true;
    }
    matches!(
        (psl_registrable_domain(&stored), psl_registrable_domain(&rp)),
        (Some(a), Some(b)) if a == b
    )
}

fn is_ip_literal(host: &str) -> bool {
    // IPv6 (already unbracketed by strip_port) always contains a colon.
    if host.contains(':') {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit()))
}

/// Convert a host to its ASCII (punycode) form, label by label. ASCII labels
/// pass through untouched, which is the overwhelming majority of real input.
fn to_ascii_host(host: &str) -> Option<String> {
    if host.is_ascii() {
        return Some(host.to_string());
    }
    let mut out = String::with_capacity(host.len());
    for (i, label) in host.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(label);
        } else {
            out.push_str("xn--");
            out.push_str(&punycode_encode(label)?);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492), encoding only.
//
// Deliberately hand-rolled rather than pulled in as a dependency: the full IDNA
// crate chain costs roughly twenty transitive crates in a published security
// library, and this is a deterministic string encoding with published test
// vectors. Note that UTS-46 mapping is NOT applied; input is lowercased by the
// caller and otherwise used as-is, which covers ordinary IDN hosts.
// ---------------------------------------------------------------------------

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

/// Largest `delta` `adapt` leaves unscaled, per RFC 3492 section 6.1.
const ADAPT_LIMIT: u32 = ((BASE - TMIN) * TMAX) / 2;
/// Digit alphabet, value 0 to 35.
const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Every step is checked arithmetic: an overflow (which RFC 3492 itself
/// treats as a failure) or any impossible state yields `None`, never a panic or
/// a wrapped value.
fn punycode_encode(label: &str) -> Option<String> {
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut output = String::new();

    for &c in &input {
        if c < INITIAL_N {
            output.push(char::from_u32(c)?);
        }
    }
    // Basic code points are ASCII, so bytes and chars agree.
    let basic_count = u32::try_from(output.len()).ok()?;
    let total = u32::try_from(input.len()).ok()?;
    let mut handled = basic_count;
    if basic_count > 0 {
        output.push('-');
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;

    while handled < total {
        let m = *input.iter().filter(|&&c| c >= n).min()?;
        delta = delta.checked_add(m.checked_sub(n)?.checked_mul(handled.checked_add(1)?)?)?;
        n = m;

        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    // TMIN when k <= bias, TMAX when k >= bias + TMAX, else k - bias.
                    let t = k.saturating_sub(bias).clamp(TMIN, TMAX);
                    if q < t {
                        break;
                    }
                    let span = BASE.checked_sub(t)?;
                    let rest = q.checked_sub(t)?;
                    output.push(digit_to_char(t.checked_add(rest.checked_rem(span)?)?)?);
                    q = rest.checked_div(span)?;
                    k = k.checked_add(BASE)?;
                }
                output.push(digit_to_char(q)?);
                let next = handled.checked_add(1)?;
                bias = adapt(delta, next, handled == basic_count)?;
                delta = 0;
                handled = next;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }

    Some(output)
}

fn adapt(delta: u32, numpoints: u32, first_time: bool) -> Option<u32> {
    let mut delta = delta.checked_div(if first_time { DAMP } else { 2 })?;
    delta = delta.checked_add(delta.checked_div(numpoints)?)?;
    let mut k: u32 = 0;
    while delta > ADAPT_LIMIT {
        delta = delta.checked_div(BASE - TMIN)?;
        k = k.checked_add(BASE)?;
    }
    let scaled = (BASE - TMIN + 1).checked_mul(delta)?.checked_div(delta.checked_add(SKEW)?)?;
    k.checked_add(scaled)
}

fn digit_to_char(d: u32) -> Option<char> {
    DIGITS.get(usize::try_from(d).ok()?).map(|&b| char::from(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_suffix_list_is_sorted_for_binary_search() {
        let mut sorted = PUBLIC_SUFFIXES.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            PUBLIC_SUFFIXES, sorted.as_slice(),
            "PUBLIC_SUFFIXES must stay sorted, binary_search depends on it"
        );
    }

    #[test]
    fn public_suffix_list_has_no_duplicates() {
        let mut seen = PUBLIC_SUFFIXES.to_vec();
        seen.dedup();
        assert_eq!(seen.len(), PUBLIC_SUFFIXES.len());
    }

    #[test]
    fn strips_scheme_path_query_fragment_and_port() {
        for raw in [
            "https://example.com",
            "http://example.com/login",
            "https://example.com:8443/login?next=1#form",
            "example.com/login",
            "example.com:8080",
            "//example.com/x",
            "  https://example.com/  ",
        ] {
            assert_eq!(normalize_host(raw).as_deref(), Some("example.com"), "{raw}");
        }
    }

    #[test]
    fn strips_userinfo_and_www_and_case_and_root_dot() {
        for raw in [
            "https://user:pass@www.Example.COM/",
            "WWW.EXAMPLE.COM",
            "example.com.",
            "https://user@example.com",
        ] {
            assert_eq!(normalize_host(raw).as_deref(), Some("example.com"), "{raw}");
        }
    }

    #[test]
    fn www_is_only_stripped_as_a_whole_label() {
        assert_eq!(normalize_host("wwwexample.com").as_deref(), Some("wwwexample.com"));
        assert_eq!(normalize_host("www2.example.com").as_deref(), Some("www2.example.com"));
    }

    #[test]
    fn rejects_non_web_schemes_and_junk() {
        for raw in [
            "mailto:a@example.com",
            "javascript:alert(1)",
            "data:text/html,x",
            "tel:+380670000000",
            "file:///etc/passwd",
            "about:blank",
            "",
            "   ",
            "https://",
            "/just/a/path",
            "?query=only",
        ] {
            assert_eq!(normalize_host(raw), None, "{raw:?} should not yield a host");
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        for raw in [
            "https://[unclosed",
            "::::",
            "..",
            "-example.com",
            "example.com-",
            "a..b",
            "\u{0}\u{1}",
            "https://:8080",
        ] {
            let _ = normalize_host(raw);
        }
    }

    #[test]
    fn punycode_matches_published_vectors() {
        // Canonical, widely published IDN examples.
        assert_eq!(punycode_encode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(punycode_encode("münchen").as_deref(), Some("mnchen-3ya"));
        assert_eq!(punycode_encode("рф").as_deref(), Some("p1ai"));
        assert_eq!(punycode_encode("пример").as_deref(), Some("e1afmkfd"));
    }

    /// RFC 3492 treats an overflowing `delta` as a failure. The encoder must
    /// report it as `None`, not wrap (release) or panic (debug).
    #[test]
    fn punycode_overflow_is_a_failure_not_a_wrap() {
        let huge = format!("{}\u{10FFFF}", "a".repeat(5000));
        assert_eq!(punycode_encode(&huge), None);
        assert_eq!(normalize_host(&format!("https://{huge}.com/")), None);
        // Long, but within range: still encodes.
        let fine = format!("{}é", "a".repeat(50));
        assert!(punycode_encode(&fine).is_some());
    }

    #[test]
    fn digits_map_to_the_rfc_alphabet_and_nothing_past_it() {
        assert_eq!(digit_to_char(0), Some('a'));
        assert_eq!(digit_to_char(25), Some('z'));
        assert_eq!(digit_to_char(26), Some('0'));
        assert_eq!(digit_to_char(35), Some('9'));
        assert_eq!(digit_to_char(36), None);
        assert_eq!(digit_to_char(u32::MAX), None);
    }

    #[test]
    fn idn_hosts_normalize_to_punycode() {
        assert_eq!(normalize_host("пример.рф").as_deref(), Some("xn--e1afmkfd.xn--p1ai"));
        assert_eq!(normalize_host("https://Bücher.de/x").as_deref(), Some("xn--bcher-kva.de"));
        // Mixed: only the non-ASCII label is encoded.
        assert_eq!(normalize_host("münchen.example.com").as_deref(), Some("xn--mnchen-3ya.example.com"));
    }

    #[test]
    fn registrable_domain_handles_plain_gtlds() {
        assert_eq!(registrable_domain("example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("login.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("a.b.c.example.org").as_deref(), Some("example.org"));
    }

    #[test]
    fn registrable_domain_respects_multi_label_suffixes() {
        assert_eq!(registrable_domain("example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("login.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("shop.example.com.ua").as_deref(), Some("example.com.ua"));
        assert_eq!(registrable_domain("user.github.io").as_deref(), Some("user.github.io"));
        assert_eq!(registrable_domain("blog.user.github.io").as_deref(), Some("user.github.io"));
    }

    #[test]
    fn bare_public_suffixes_have_no_registrable_domain() {
        // The whole point: `co.uk` must never become a matching key.
        for host in ["co.uk", "com.ua", "github.io", "blogspot.com"] {
            assert_eq!(registrable_domain(host), None, "{host}");
        }
    }

    #[test]
    fn ip_literals_and_single_labels_have_no_registrable_domain() {
        for host in ["192.168.1.1", "8.8.8.8", "localhost", "::1", "fe80::1"] {
            assert_eq!(registrable_domain(host), None, "{host}");
        }
    }

    #[test]
    fn ip_literals_normalize_but_stay_exact_match_only() {
        assert_eq!(normalize_host("http://192.168.1.1:8080/admin").as_deref(), Some("192.168.1.1"));
        assert_eq!(normalize_host("https://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(
            match_tier("192.168.1.1", "192.168.1.1"),
            Some(MatchTier::ExactHost)
        );
        assert_eq!(match_tier("192.168.1.1", "192.168.1.2"), None);
    }

    #[test]
    fn an_empty_host_never_matches() {
        assert_eq!(match_tier("", "example.com"), None);
        assert_eq!(match_tier("example.com", ""), None);
        assert_eq!(match_tier("", ""), None);
    }

    #[test]
    fn match_tiers_rank_as_documented() {
        assert_eq!(match_tier("example.com", "example.com"), Some(MatchTier::ExactHost));
        assert_eq!(
            match_tier("example.com", "login.example.com"),
            Some(MatchTier::RegistrableDomain)
        );
        assert_eq!(
            match_tier("example.co.uk", "login.example.co.uk"),
            Some(MatchTier::RegistrableDomain)
        );
        assert!(MatchTier::ExactHost > MatchTier::RegistrableDomain);
        assert!(MatchTier::RegistrableDomain > MatchTier::HostSuffix);
    }

    #[test]
    fn unrelated_hosts_under_a_shared_suffix_do_not_match() {
        // The regression this module exists to prevent.
        assert_eq!(match_tier("example.co.uk", "evil.co.uk"), None);
        assert_eq!(match_tier("mybank.com.ua", "phisher.com.ua"), None);
        assert_eq!(match_tier("alice.github.io", "mallory.github.io"), None);
        // And no accidental substring matching.
        assert_eq!(match_tier("example.com", "notexample.com"), None);
        assert_eq!(match_tier("example.com", "example.com.evil.net"), None);
    }

    #[test]
    fn passkeys_match_by_exact_host_or_the_full_public_suffix_list() {
        // Exact host, after normalization.
        assert!(passkey_matches_host("https://www.Example.com/login", "example.com"));
        assert!(passkey_matches_host("localhost", "localhost"));
        // Same registrable domain under the full list.
        assert!(passkey_matches_host("example.com", "login.example.com"));
        assert!(passkey_matches_host("app.example.co.uk", "example.co.uk"));
        // Hosting suffixes the curated list does not carry still separate owners.
        assert!(!is_public_suffix("onrender.com"), "the curated list lacks it; the full list is what matters");
        assert!(!passkey_matches_host("theirs.onrender.com", "ours.onrender.com"));
        assert!(!passkey_matches_host("alice.github.io", "mallory.github.io"));
        assert!(!passkey_matches_host("example.co.uk", "other.co.uk"));
        // A public suffix, an IP literal or junk never matches by domain.
        assert!(!passkey_matches_host("onrender.com", "ours.onrender.com"));
        assert!(!passkey_matches_host("10.0.0.1", "10.0.0.2"));
        assert!(!passkey_matches_host("", "example.com"));
        assert!(!passkey_matches_host("example.com", "javascript:alert(1)"));
        assert!(!passkey_matches_host("example.com", "notexample.com"));
    }

    #[test]
    fn psl_registrable_domain_refuses_suffixes_and_ip_literals() {
        assert_eq!(psl_registrable_domain("a.b.example.com"), Some("example.com"));
        assert_eq!(psl_registrable_domain("ours.onrender.com"), Some("ours.onrender.com"));
        assert_eq!(psl_registrable_domain("onrender.com"), None);
        assert_eq!(psl_registrable_domain("co.uk"), None);
        assert_eq!(psl_registrable_domain("192.168.1.1"), None);
        assert_eq!(psl_registrable_domain("::1"), None);
        assert_eq!(psl_registrable_domain(""), None);
    }
}
