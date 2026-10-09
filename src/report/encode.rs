//! Lossless byte encoding, display escaping, timestamps, and OID checks
//! (spec §§7, 16). No third-party encoding crates: Base64 and RFC 3339 are
//! implemented here so the report lane adds no dependencies.

use crate::report::model::{EncodedName, ObjectId, PathRecord};

/// Standard Base64 alphabet (RFC 4648 §4, `+/` with `=` padding).
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes with standard Base64 (with padding).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut n: u32 = 0;
        for (i, byte) in chunk.iter().enumerate() {
            n |= (*byte as u32) << (16 - 8 * i);
        }
        let pad = 3 - chunk.len();
        for i in 0..4 - pad {
            let sextet = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            out.push(B64_ALPHABET[sextet] as char);
        }
        for _ in 0..pad {
            out.push('=');
        }
    }
    out
}

/// Decode standard Base64. Returns `None` on any malformed input
/// (bad characters, bad padding, or non-canonical trailing bits are
/// accepted: validation only needs well-formedness, not canonicality).
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (chunk_index, chunk) in text.as_bytes().chunks(4).enumerate() {
        let mut n: u32 = 0;
        let mut pad = 0usize;
        for (i, byte) in chunk.iter().enumerate() {
            let sextet = match byte {
                b'A'..=b'Z' => (byte - b'A') as u32,
                b'a'..=b'z' => (byte - b'a' + 26) as u32,
                b'0'..=b'9' => (byte - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    // Padding is only legal in the last two positions,
                    // and only in the final quantum; excess padding or
                    // data after padding is malformed.
                    if i < 2 {
                        return None;
                    }
                    0
                }
                _ => return None,
            };
            if pad > 0 && *byte != b'=' {
                return None;
            }
            n |= sextet << (18 - 6 * i);
        }
        if pad > 2 {
            return None;
        }
        if pad > 0 && chunk_index + 1 != text.len() / 4 {
            return None;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad == 0 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Check standard Base64 syntax without allocating a decoded copy. This
/// mirrors [`base64_decode`] so staged-report validation can verify a large
/// encoded path while retaining only the current record.
pub fn base64_is_valid(text: &str) -> bool {
    if !text.len().is_multiple_of(4) {
        return false;
    }
    for (chunk_index, chunk) in text.as_bytes().chunks(4).enumerate() {
        let mut pad = 0usize;
        for (index, byte) in chunk.iter().enumerate() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                    if pad > 0 {
                        return false;
                    }
                }
                b'=' => {
                    pad += 1;
                    if index < 2 {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        if pad > 2 {
            return false;
        }
        if pad > 0 && chunk_index + 1 != text.len() / 4 {
            return false;
        }
    }
    true
}

/// Escape terminal control characters for safe `display` text. Printable
/// text passes through unchanged; `\n`, `\r`, `\t` use short escapes and
/// other control characters use `\u{...}`. Never lossy on the `value`
/// channel — only the presentation channel is transformed.
pub fn escape_display(text: &str) -> String {
    if !text.chars().any(|c| c.is_control()) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{{{:X}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Maximum bytes for one free-text report field (finding 6): error
/// messages, candidate reasons, and evidence/unknown-field lines stream
/// row by row, so one huge field would otherwise blow the streaming
/// memory bound. Lossless path/name channels (`value`) are NOT capped —
/// lossy replacement there is forbidden — only diagnostic prose.
pub const MAX_REPORT_FIELD_BYTES: usize = 64 * 1024;

/// Cap one free-text report field at [`MAX_REPORT_FIELD_BYTES`]: short
/// fields pass through untouched; longer ones are cut at a character
/// boundary with an explicit `…[+N bytes truncated]` marker, so the cut
/// is always visible and never silent.
pub fn cap_report_field(text: &str) -> String {
    if text.len() <= MAX_REPORT_FIELD_BYTES {
        return text.to_string();
    }
    let mut end = MAX_REPORT_FIELD_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = text.len() - end;
    format!("{}…[+{dropped} bytes truncated]", &text[..end])
}

/// Encode raw bytes as (`encoding`, `value`, `display`): exact Unicode when
/// the bytes are valid UTF-8, otherwise standard Base64 of the original
/// bytes. Lossy replacement is forbidden on `value`; `display` is escaped
/// presentation text only.
pub fn encode_bytes(raw: &[u8]) -> (String, String, String) {
    match std::str::from_utf8(raw) {
        Ok(text) => ("utf8".to_string(), text.to_string(), escape_display(text)),
        Err(_) => (
            "base64".to_string(),
            base64_encode(raw),
            escape_display(&String::from_utf8_lossy(raw)),
        ),
    }
}

/// Build a [`PathRecord`] from raw path bytes plus optional identity.
pub fn encode_path(
    id: String,
    raw: &[u8],
    volume_id: Option<String>,
    object_id: Option<String>,
    incarnation: Option<String>,
) -> PathRecord {
    let (encoding, value, display) = encode_bytes(raw);
    PathRecord {
        id,
        display,
        encoding,
        value,
        volume_id,
        object_id,
        incarnation,
    }
}

/// Build an [`EncodedName`] from raw bytes.
pub fn encode_name(raw: &[u8]) -> EncodedName {
    let (encoding, value, display) = encode_bytes(raw);
    EncodedName {
        display,
        encoding,
        value,
    }
}

/// Convert unix milliseconds to RFC 3339 UTC (`...T...Z`, millis precision).
/// Uses the proleptic Gregorian calendar; handles pre-1970 times.
pub fn ms_to_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000) as u32;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
    )
}

/// Current time as RFC 3339 UTC.
pub fn now_rfc3339() -> String {
    ms_to_rfc3339(crate::store::now_ms())
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's
/// `civil_from_days` with the 719468-day shift to 0000-03-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

/// Lightweight RFC 3339 shape check for validation: `YYYY-MM-DDTHH:MM:SSZ`
/// with an optional fractional part. Full calendar validation is out of
/// scope; emission always uses [`ms_to_rfc3339`].
pub fn is_rfc3339_shape(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.ends_with('Z') {
        return false;
    }
    let digit = |i: usize| bytes.get(i).is_some_and(|b| b.is_ascii_digit());
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !digit(i) {
            return false;
        }
    }
    bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.get(19).is_some_and(|b| *b == b'Z' || *b == b'.')
        && (bytes[19] != b'.' || {
            let frac = &text[20..text.len() - 1];
            !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Validate an [`ObjectId`]: nonempty even-length lowercase hex; `sha1`
/// requires 40 chars, `sha256` requires 64. Unknown algorithms only need
/// the generic shape. Returns the reason when invalid.
pub fn object_id_error(oid: &ObjectId) -> Option<String> {
    if oid.hex.is_empty() || !oid.hex.len().is_multiple_of(2) {
        return Some("hex must be a nonempty even-length string".to_string());
    }
    if !oid.hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("hex must contain only hexadecimal characters".to_string());
    }
    if oid.hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Some("hex must be lowercase".to_string());
    }
    match oid.algorithm.as_str() {
        "sha1" if oid.hex.len() != 40 => Some("sha1 hex must be 40 characters".to_string()),
        "sha256" if oid.hex.len() != 64 => Some("sha256 hex must be 64 characters".to_string()),
        _ => None,
    }
}

/// Interpret stored OID bytes as report hex. Catalog BLOBs hold either the
/// hex spelling or raw digest bytes; valid lowercase hex passes through,
/// uppercase hex is lowercased, anything else is hex-encoded so the report
/// never carries non-hex in `hex`.
pub fn oid_hex_from_bytes(raw: &[u8]) -> String {
    if !raw.is_empty() && raw.len().is_multiple_of(2) && raw.iter().all(|b| b.is_ascii_hexdigit()) {
        return raw.iter().map(|b| b.to_ascii_lowercase() as char).collect();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Guess the algorithm when the catalog stored an OID without one: 40 hex
/// chars is `sha1`, 64 is `sha256`, otherwise `unknown` (the schema only
/// constrains known algorithms, so `unknown` stays schema-valid and honest).
pub fn guess_oid_algorithm(hex: &str) -> &str {
    match hex.len() {
        40 => "sha1",
        64 => "sha256",
        _ => "unknown",
    }
}
