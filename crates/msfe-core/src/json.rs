//! Minimal JSON value, serializer and parser (dependency-free).
//!
//! Enough to emit and consume the config/policy/stats payloads the CLI and
//! daemon exchange. Replaced by `serde_json` later if we take on a dependency.

use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    /// Pre-formatted number (e.g. a decimal string) emitted verbatim.
    Num(String),
    Str(String),
    Array(Vec<Json>),
    /// Insertion-ordered object.
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Num(s) => out.push_str(s),
            Json::Str(s) => write_escaped(out, s),
            Json::Array(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    it.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

impl std::fmt::Display for Json {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---- accessors ---------------------------------------------------------------

impl Json {
    /// Field of an object by key.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(f) => f.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
    /// Convenience: string field, or "".
    pub fn str_field(&self, key: &str) -> String {
        self.get(key)
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string()
    }
}

// ---- parser ------------------------------------------------------------------

impl Json {
    /// Parse a JSON document. Minimal but correct for objects, arrays, strings
    /// (with `\uXXXX`), numbers, booleans and null.
    pub fn parse(input: &str) -> Result<Json, String> {
        let mut p = Parser {
            b: input.as_bytes(),
            i: 0,
        };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing data at byte {}", p.i));
        }
        Ok(v)
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            other => Err(format!(
                "unexpected {:?} at {}",
                other.map(|c| c as char),
                self.i
            )),
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1; // {
        let mut fields = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected key string at {}", self.i));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.i));
            }
            self.i += 1;
            self.ws();
            let val = self.value()?;
            fields.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Object(fields));
                }
                other => return Err(format!("expected ',' or '}}' got {:?}", other)),
            }
        }
    }
    fn array(&mut self) -> Result<Json, String> {
        self.i += 1; // [
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Array(items));
                }
                other => return Err(format!("expected ',' or ']' got {:?}", other)),
            }
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut s = String::new();
        while let Some(c) = self.peek() {
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'b' => s.push('\u{8}'),
                        b'f' => s.push('\u{c}'),
                        b'u' => {
                            let hex = self.b.get(self.i..self.i + 4).ok_or("short \\u escape")?;
                            let code = u32::from_str_radix(
                                std::str::from_utf8(hex).map_err(|_| "bad \\u")?,
                                16,
                            )
                            .map_err(|_| "bad \\u hex")?;
                            self.i += 4;
                            s.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => {
                    // copy this UTF-8 byte-run; find char boundary
                    let start = self.i - 1;
                    while self.i < self.b.len() && self.b[self.i] != b'"' && self.b[self.i] != b'\\'
                    {
                        self.i += 1;
                    }
                    s.push_str(
                        std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad utf8")?,
                    );
                }
            }
        }
        Err("unterminated string".into())
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut is_float = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.i += 1;
            } else if matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                is_float = true;
                self.i += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number")?;
        if is_float {
            Ok(Json::Num(text.to_string()))
        } else {
            text.parse::<i64>()
                .map(Json::Int)
                .or_else(|_| Ok(Json::Num(text.to_string())))
        }
    }
    fn boolean(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Json::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Json::Bool(false))
        } else {
            Err("bad literal".into())
        }
    }
    fn null(&mut self) -> Result<Json, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Json::Null)
        } else {
            Err("bad literal".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_strings() {
        assert_eq!(Json::str("a\"b\\c\n").to_string(), r#""a\"b\\c\n""#);
    }

    #[test]
    fn objects_and_arrays() {
        let j = Json::Object(vec![
            ("k".into(), Json::Int(3)),
            (
                "list".into(),
                Json::Array(vec![Json::Bool(true), Json::Null]),
            ),
        ]);
        assert_eq!(j.to_string(), r#"{"k":3,"list":[true,null]}"#);
    }

    #[test]
    fn parse_roundtrip() {
        let src = r#"{"a":1,"b":"x\ny","c":[true,false,null,-3.5],"d":{"e":"f"}}"#;
        let v = Json::parse(src).unwrap();
        assert_eq!(v.get("a").unwrap().to_string(), "1");
        assert_eq!(v.get("b").unwrap().as_str(), Some("x\ny"));
        assert_eq!(v.get("c").unwrap().as_array().unwrap().len(), 4);
        assert_eq!(v.str_field("d"), ""); // d is an object, not a string
        assert_eq!(v.get("d").unwrap().str_field("e"), "f");
    }

    #[test]
    fn parse_unicode_escape_and_ws() {
        let v = Json::parse("  { \"k\" : \"\\u00e9\" } ").unwrap();
        assert_eq!(v.str_field("k"), "é");
    }

    #[test]
    fn parse_rejects_trailing() {
        assert!(Json::parse("{} x").is_err());
        assert!(Json::parse("[1,2").is_err());
    }
}
