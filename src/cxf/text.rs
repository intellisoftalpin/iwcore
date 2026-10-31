//! Text forms IntelliWallet stores, built from and parsed back into CXF values.
//!
//! - `2FAC`: a bare Base32 secret when the parameters are the defaults
//!   (SHA-1, 6 digits, 30 s), otherwise an `otpauth://totp/...` URI;
//! - `WIFI`: the `WIFI:T:<sec>;S:<ssid>;P:<pass>;H:<hidden>;;` URI the app's
//!   QR code support already reads and writes;
//! - SSH keys: PEM text.
//!
//! Every value taken from an import is also bounded and stripped of control
//! characters here.

use base64::Engine;

/// Longest single value kept from an import; notes may be longer.
pub(crate) const VALUE_MAX: usize = 64 * 1024;
pub(crate) const NOTE_MAX: usize = 1024 * 1024;
/// Longest title, folder or label name kept.
pub(crate) const NAME_MAX: usize = 1024;

/// Strip control characters (keeping newlines and tabs when `multiline`) and
/// cut to `max` bytes on a character boundary.
pub(crate) fn clean(text: &str, max: usize, multiline: bool) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    for c in text.chars() {
        let keep = !c.is_control() || (multiline && (c == '\n' || c == '\t'));
        if !keep {
            continue;
        }
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// A one-line name: control characters removed, whitespace collapsed at the
/// ends, at most [`NAME_MAX`] bytes.
pub(crate) fn name(text: &str) -> String {
    clean(text, NAME_MAX, false).trim().to_string()
}

/// TOTP parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Totp {
    pub secret: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Totp {
    fn is_default(&self) -> bool {
        self.algorithm == "SHA1" && self.digits == 6 && self.period == 30
    }
}

/// Normalise a Base32 secret: upper case, no spaces, no padding. `None` when it
/// is not Base32 at all.
pub(crate) fn base32_secret(secret: &str) -> Option<String> {
    let s: String = secret.chars().filter(|c| !c.is_whitespace() && *c != '=').collect::<String>().to_ascii_uppercase();
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))).then_some(s)
}

/// The `2FAC` value for these parameters.
pub(crate) fn totp_value(t: &Totp) -> String {
    if t.is_default() && t.issuer.is_none() && t.account.is_none() {
        return t.secret.clone();
    }
    let label = match (&t.issuer, &t.account) {
        (Some(i), Some(a)) => format!("{}:{}", pct(i), pct(a)),
        (Some(i), None) => pct(i),
        (None, Some(a)) => pct(a),
        (None, None) => String::new(),
    };
    let mut uri = format!("otpauth://totp/{label}?secret={}", t.secret);
    if let Some(i) = &t.issuer {
        uri.push_str(&format!("&issuer={}", pct(i)));
    }
    uri.push_str(&format!("&algorithm={}&digits={}&period={}", t.algorithm, t.digits, t.period));
    uri
}

/// Read a `2FAC` value back: a bare secret or an `otpauth://totp/` URI.
pub(crate) fn parse_totp(value: &str) -> Option<Totp> {
    let value = value.trim();
    let Some(rest) = value.strip_prefix("otpauth://totp/").or_else(|| value.strip_prefix("OTPAUTH://TOTP/")) else {
        return base32_secret(value).map(|secret| Totp {
            secret, algorithm: "SHA1".into(), digits: 6, period: 30, issuer: None, account: None,
        });
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = unpct(label);
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), Some(a.trim().to_string())),
        None if label.is_empty() => (None, None),
        None => (None, Some(label)),
    };
    let mut t = Totp { secret: String::new(), algorithm: "SHA1".into(), digits: 6, period: 30, issuer: label_issuer, account };
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = unpct(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => t.secret = base32_secret(&v)?,
            "issuer" if !v.is_empty() => t.issuer = Some(v),
            "algorithm" => t.algorithm = v.to_ascii_uppercase(),
            "digits" => t.digits = v.parse().ok()?,
            "period" => t.period = v.parse().ok()?,
            _ => {}
        }
    }
    (!t.secret.is_empty()).then_some(t)
}

/// Wi-Fi security as the `WIFI:` URI writes it.
pub(crate) fn wifi_value(ssid: &str, security: &str, passphrase: &str, hidden: bool) -> String {
    format!(
        "WIFI:T:{};S:{};P:{};H:{};;",
        security,
        wifi_escape(ssid),
        wifi_escape(passphrase),
        if hidden { "true" } else { "false" }
    )
}

/// `(ssid, security, passphrase, hidden)` from a `WIFI:` value; a value that is
/// not a `WIFI:` URI is taken as a bare passphrase.
pub(crate) fn parse_wifi(value: &str) -> (String, String, String, bool) {
    let Some(body) = value.strip_prefix("WIFI:") else {
        return (String::new(), "WPA".into(), value.to_string(), false);
    };
    let (mut ssid, mut sec, mut pass, mut hidden) = (String::new(), "WPA".to_string(), String::new(), false);
    for part in split_unescaped(body) {
        if let Some((k, v)) = part.split_once(':') {
            let v = wifi_unescape(v);
            match k {
                "S" => ssid = v,
                "T" => sec = v,
                "P" => pass = v,
                "H" => hidden = v.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
    }
    (ssid, sec, pass, hidden)
}

fn wifi_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn wifi_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split on `;` that is not escaped.
fn split_unescaped(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut esc = false;
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            cur.push(c);
            esc = true;
        } else if c == ';' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

/// PEM text of a DER private key (`-----BEGIN PRIVATE KEY-----`).
pub(crate) fn pem_private_key(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}

/// Percent-encode for an otpauth label or query value.
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unpct(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if b == b'+' { b' ' } else { b });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Last day of a `YYYY-MM` month as the vault's `YYYYMMDD` date.
pub(crate) fn year_month_to_last_day(ym: &str) -> Option<String> {
    let (y, m) = ym.trim().split_once('-')?;
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    let first_next = if m == 12 {
        chrono::NaiveDate::from_ymd_opt(y + 1, 1, 1)?
    } else {
        chrono::NaiveDate::from_ymd_opt(y, m + 1, 1)?
    };
    Some(first_next.pred_opt()?.format("%Y%m%d").to_string())
}

/// `YYYY-MM-DD` as `YYYYMMDD`; anything else unchanged.
pub(crate) fn iso_date_to_vault(date: &str) -> String {
    chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d")
        .map(|d| d.format("%Y%m%d").to_string())
        .unwrap_or_else(|_| date.to_string())
}

/// `YYYYMMDD` (or `YYYY-MM-DD`) as `YYYY-MM-DD`; `None` if neither.
pub(crate) fn vault_date_to_iso(date: &str) -> Option<String> {
    let d = date.trim();
    chrono::NaiveDate::parse_from_str(d, "%Y%m%d")
        .or_else(|_| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d"))
        .ok()
        .map(|d| d.format("%Y-%m-%d").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_strips_controls_and_bounds_length() {
        assert_eq!(clean("a\u{0}b\u{1b}[31mc\nd", 100, false), "ab[31mcd");
        assert_eq!(clean("a\nb\tc", 100, true), "a\nb\tc");
        assert_eq!(clean("ééé", 5, false), "éé", "cut on a character boundary");
        assert_eq!(name("  ../../etc  "), "../../etc", "kept as text, never a path");
        assert_eq!(name("%s%n{}"), "%s%n{}");
    }

    #[test]
    fn totp_round_trips() {
        let default = Totp { secret: "JBSWY3DPEHPK3PXP".into(), algorithm: "SHA1".into(), digits: 6, period: 30, issuer: None, account: None };
        assert_eq!(totp_value(&default), "JBSWY3DPEHPK3PXP");
        assert_eq!(parse_totp("jbsw y3dp ehpk 3pxp"), Some(default.clone()));
        let custom = Totp {
            secret: "JBSWY3DPEHPK3PXP".into(), algorithm: "SHA256".into(), digits: 8, period: 60,
            issuer: Some("ACME & Co".into()), account: Some("a:b@x.com".into()),
        };
        let uri = totp_value(&custom);
        assert!(uri.starts_with("otpauth://totp/ACME%20%26%20Co:a%3Ab%40x.com?secret="));
        let back = parse_totp(&uri).unwrap();
        assert_eq!(back.secret, custom.secret);
        assert_eq!((back.algorithm.as_str(), back.digits, back.period), ("SHA256", 8, 60));
        assert_eq!(back.issuer.as_deref(), Some("ACME & Co"));
        assert!(parse_totp("not base32!").is_none());
        assert!(parse_totp("otpauth://totp/x?secret=!!").is_none());
        assert!(parse_totp("otpauth://totp/x?digits=6").is_none());
    }

    #[test]
    fn wifi_round_trips_with_hostile_characters() {
        let ssid = r#"Café; "Guest", \net:1"#;
        let pass = r#"p;a,s:s"w\d"#;
        let v = wifi_value(ssid, "WPA", pass, true);
        assert_eq!(parse_wifi(&v), (ssid.to_string(), "WPA".to_string(), pass.to_string(), true));
        assert_eq!(parse_wifi("plain-pass"), (String::new(), "WPA".into(), "plain-pass".into(), false));
    }

    #[test]
    fn pem_round_trips() {
        let der: Vec<u8> = (0..200u8).collect();
        let pem = pem_private_key(&der);
        assert!(pem.lines().all(|l| l.len() <= 64));
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(body).unwrap(), der);
    }

    #[test]
    fn dates() {
        assert_eq!(year_month_to_last_day("2029-02").as_deref(), Some("20290228"));
        assert_eq!(year_month_to_last_day("2028-02").as_deref(), Some("20280229"));
        assert_eq!(year_month_to_last_day("2030-12").as_deref(), Some("20301231"));
        assert!(year_month_to_last_day("2030-13").is_none());
        assert!(year_month_to_last_day("garbage").is_none());
        assert_eq!(iso_date_to_vault("1990-05-17"), "19900517");
        assert_eq!(iso_date_to_vault("May 17"), "May 17");
        assert_eq!(vault_date_to_iso("19900517").as_deref(), Some("1990-05-17"));
        assert_eq!(vault_date_to_iso("1990-05-17").as_deref(), Some("1990-05-17"));
        assert!(vault_date_to_iso("soon").is_none());
    }

    #[test]
    fn percent_decoding_is_total() {
        for s in ["%", "%G1", "%%%", "a%2", "%E2%82%AC"] {
            let _ = unpct(s);
        }
        assert_eq!(unpct("%E2%82%AC"), "€");
    }
}
