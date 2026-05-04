//! Build script: parse `oui/oui.csv` and emit a sorted static table into `OUT_DIR/oui_table.rs`.

use std::fmt::Write as _;
use std::path::PathBuf;

/// True for zero-width / invisible Unicode code points that cause clippy warnings.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' // soft hyphen
        | '\u{034F}' // combining grapheme joiner
        | '\u{061C}' // arabic letter mark
        | '\u{115F}' // hangul choseong filler
        | '\u{1160}' // hangul jungseong filler
        | '\u{17B4}' // khmer vowel inherent aq
        | '\u{17B5}' // khmer vowel inherent aa
        | '\u{180B}'..='\u{180D}' // mongolian free variation selectors
        | '\u{180E}' // mongolian vowel separator
        | '\u{180F}' // mongolian free variation selector 15
        | '\u{200B}'..='\u{200F}' // zero-width space/non-joiner/joiner/ltr/rtl marks
        | '\u{202A}'..='\u{202E}' // directional formatting chars
        | '\u{2060}'..='\u{2064}' // word joiner / invisible operators
        | '\u{2066}'..='\u{206F}' // additional formatting chars
        | '\u{FEFF}' // zero-width no-break space / BOM
        | '\u{FFA0}' // halfwidth hangul filler
        | '\u{FFF0}'..='\u{FFF8}' // specials
        | '\u{1D173}'..='\u{1D17A}' // musical formatting
        | '\u{E0000}'..='\u{E007F}' // tags
    )
}

/// Parse one CSV line into fields, handling RFC-4180 quoted fields.
/// Commas inside double-quoted fields are treated as part of the field value.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    // Escaped double-quote inside a quoted field
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(field.clone());
            field.clear();
        } else {
            field.push(ch);
        }
    }
    fields.push(field);
    fields
}

fn main() {
    println!("cargo:rerun-if-changed=oui/oui.csv");

    let csv_path = PathBuf::from("oui/oui.csv");
    let raw = std::fs::read_to_string(&csv_path).expect("oui/oui.csv must exist");

    let mut entries: Vec<(u32, String)> = Vec::new();

    for line in raw.lines().skip(1) {
        let cols = parse_csv_line(line);

        let registry = cols.first().map_or("", |s| s.trim());
        let assignment = cols.get(1).map_or("", |s| s.trim());
        let org_name = cols.get(2).map_or("", |s| s.trim());

        if registry != "MA-L" {
            continue;
        }

        // Parse 6-hex-digit assignment (uppercase, no separators)
        let Ok(oui_int) = u32::from_str_radix(assignment, 16) else {
            continue;
        };

        // Remove invisible / control characters (zero-width spaces, etc.) that cause
        // clippy::invisible_characters and clippy::unicode_not_nfc on the generated file.
        // We only keep printable non-control code points.
        let name: String = org_name
            .chars()
            .filter(|c| !c.is_control() && !is_invisible(*c))
            .collect();

        if name.is_empty() {
            continue;
        }

        entries.push((oui_int, name));
    }

    entries.sort_by_key(|&(k, _)| k);
    entries.dedup_by_key(|(k, _)| *k);

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let out_path = PathBuf::from(out_dir).join("oui_table.rs");

    let mut buf = String::new();
    // Suppress lints that fire on machine-generated content.
    let _ = writeln!(buf, "#[allow(");
    let _ = writeln!(buf, "    clippy::unreadable_literal,");
    let _ = writeln!(buf, "    clippy::unicode_not_nfc,");
    let _ = writeln!(
        buf,
        "    reason = \"machine-generated OUI key table from IEEE CSV\""
    );
    let _ = writeln!(buf, ")]");
    let _ = writeln!(buf, "pub(crate) static OUI_TABLE: &[(u32, &str)] = &[");
    for (k, name) in &entries {
        // Escape any backslashes or double-quotes in the vendor name
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = writeln!(buf, "    ({k}_u32, \"{escaped}\"),");
    }
    let _ = writeln!(buf, "];");

    std::fs::write(&out_path, buf).expect("write oui_table.rs");
}
