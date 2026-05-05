//! DNS name parsing helpers.
//!
//! mDNS instance labels frequently contain characters that hickory's STD3 validator
//! rejects (spaces, `@`, etc.). `Name::from_utf8` is therefore too strict for our use
//! case. `lax_from_str` splits on `.` and feeds the labels in as raw bytes, which
//! bypasses STD3. Trailing dot is optional.

use hickory_proto::rr::Name;

use crate::error::{Error, Result};

/// Escape a single DNS label for inclusion in a dot-joined fqdn string.
///
/// Backslashes the literal `.` and `\` characters per RFC 1035 §5.1 so a label
/// containing a dot (e.g. `v1.0 Speaker`) does not collide with the label
/// separator when concatenated. Other characters (including non-ASCII UTF-8)
/// pass through unchanged for human-readable output.
pub(crate) fn escape_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        if c == '\\' || c == '.' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Parse a dot-separated fqdn into a `Name` without STD3 character validation.
pub(crate) fn lax_from_str(s: &str) -> Result<Name> {
    if s.contains('\0') {
        return Err(Error::InvalidServiceType(s.to_string()));
    }
    let trimmed = s.trim_end_matches('.');
    let label_count = trimmed.split('.').filter(|label| !label.is_empty()).count();
    if label_count == 0 {
        return Err(Error::InvalidServiceType(s.to_string()));
    }
    let mut labels = Vec::with_capacity(label_count);
    for label in trimmed.split('.').filter(|label| !label.is_empty()) {
        labels.push(label.as_bytes());
    }
    Name::from_labels(labels).map_err(|_| Error::InvalidServiceType(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_local_fqdn() {
        let n = lax_from_str("_airplay._tcp.local.").expect("parse");
        assert_eq!(n.to_string(), "_airplay._tcp.local.");
    }

    #[test]
    fn accepts_spaces_in_labels() {
        let n = lax_from_str("Living Room ATV._airplay._tcp.local.").expect("parse");
        // Spaces should appear as escapes in the canonical Name display.
        assert!(n.to_string().to_lowercase().contains("airplay"));
    }

    #[test]
    fn accepts_at_sign_in_labels() {
        let n = lax_from_str("AABBCCDDEEFF@Foo._raop._tcp.local.").expect("parse");
        drop(n); // smoke: it compiled and didn't error
    }

    #[test]
    fn rejects_empty_string() {
        assert!(lax_from_str("").is_err());
        assert!(lax_from_str(".").is_err());
    }

    #[test]
    fn escape_label_backslashes_dots_and_backslashes() {
        assert_eq!(escape_label("v1.0 Speaker"), "v1\\.0 Speaker");
        assert_eq!(escape_label("a\\b"), "a\\\\b");
        assert_eq!(
            escape_label("Shannon's MacBook Pro"),
            "Shannon's MacBook Pro"
        );
    }

    #[test]
    fn escape_label_empty_string_returns_empty() {
        assert_eq!(escape_label(""), "");
    }

    #[test]
    fn escape_label_only_dots_escapes_all() {
        assert_eq!(escape_label("..."), "\\.\\.\\.");
    }

    #[test]
    fn escape_label_only_backslashes_escapes_all() {
        assert_eq!(escape_label("\\\\"), "\\\\\\\\");
    }

    #[test]
    fn escape_label_control_chars_pass_through() {
        // Control characters (newline, tab) are not dots or backslashes;
        // they pass through unchanged.
        assert_eq!(escape_label("a\nb"), "a\nb");
        assert_eq!(escape_label("a\tb"), "a\tb");
    }

    #[test]
    fn escape_label_mixed_dots_and_backslashes() {
        // "a.b\\c" should become "a\.b\\c"
        assert_eq!(escape_label("a.b\\c"), "a\\.b\\\\c");
    }

    #[test]
    fn escape_label_unicode_passes_through_unchanged() {
        let input = "Shannon\u{2019}s \u{00e9}l\u{00e8}ve";
        assert_eq!(escape_label(input), input);
    }

    #[test]
    fn lax_from_str_rejects_null_byte() {
        assert!(lax_from_str("foo\0bar").is_err());
    }

    #[test]
    fn lax_from_str_rejects_only_dots() {
        assert!(lax_from_str("....").is_err());
    }
}
