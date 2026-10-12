//! Canonical JSON and SHA-256 helpers shared by the proof runner.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Canonical JSON: recursively sorted object keys, compact separators, UTF-8,
/// shortest-roundtrip numbers. Matches
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
/// for the ASCII-only proof policy files.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("json string")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // serde_json without preserve_order stores objects in a BTreeMap,
            // so iteration is already key-sorted.
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("json key"));
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
    }
}

/// SHA-256 over the canonical JSON of `value` with the top-level `sha256`
/// key removed (self-hash convention used by proof/policy.json).
pub fn self_hash(value: &Value) -> Result<String, String> {
    let mut v = value.clone();
    match v.as_object_mut() {
        Some(m) => {
            m.remove("sha256");
        }
        None => return Err("document is not a JSON object".to_string()),
    }
    Ok(sha256_hex(canonical_json(&v).as_bytes()))
}

pub fn read_json(path: &Path) -> Result<Value, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("malformed JSON in {}: {e}", path.display()))
}

pub fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    let mut text = serde_json::to_string_pretty(value).expect("json serialize");
    text.push('\n');
    fs::write(path, text)
}
