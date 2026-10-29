//! Strict RFC 8259 parser with useful error positions.

use crate::value::{Map, Number, Value};
use crate::Error;

const MAX_DEPTH: usize = 256;

pub fn parse(input: &str) -> crate::Result<Value> {
    let mut p = Parser::new(input);
    p.skip_ws();
    let v = p.parse_value(0)?;
    p.skip_ws();
    if p.i != p.bytes.len() {
        return Err(p.err("trailing characters after JSON value"));
    }
    Ok(v)
}

pub fn parse_bytes(input: &[u8]) -> crate::Result<Value> {
    let text = core::str::from_utf8(input)
        .map_err(|e| Error::new(format!("json: input is not valid UTF-8: {e}")))?;
    parse(text)
}

/// Parse one value and return it plus the number of bytes consumed. Handy for
/// newline-delimited JSON and for SSE payloads with surrounding noise.
pub fn parse_prefix(input: &str) -> crate::Result<(Value, usize)> {
    let mut p = Parser::new(input);
    p.skip_ws();
    let v = p.parse_value(0)?;
    Ok((v, p.i))
}

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Parser {
            src,
            bytes: src.as_bytes(),
            i: 0,
        }
    }

    fn err(&self, msg: &str) -> Error {
        let lo = self.i.saturating_sub(24);
        let hi = (self.i + 24).min(self.bytes.len());
        let snippet = String::from_utf8_lossy(&self.bytes[lo..hi]).replace('\n', " ");
        Error::new(format!(
            "json: {msg} at byte {} (near {:?})",
            self.i, snippet
        ))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.i += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, b: u8) -> crate::Result<()> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", b as char)))
        }
    }

    fn parse_value(&mut self, depth: usize) -> crate::Result<Value> {
        if depth > MAX_DEPTH {
            return Err(self.err("maximum nesting depth exceeded"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => Ok(Value::Number(self.parse_number()?)),
            Some(c) => Err(self.err(&format!("unexpected character '{}'", c as char))),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn literal(&mut self, word: &str) -> crate::Result<()> {
        if self.src[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(self.err(&format!("expected {word}")))
        }
    }

    fn parse_array(&mut self, depth: usize) -> crate::Result<Value> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            out.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {
                    self.skip_ws();
                    continue;
                }
                Some(b']') => break,
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
        Ok(Value::Array(out))
    }

    fn parse_object(&mut self, depth: usize) -> crate::Result<Value> {
        self.expect(b'{')?;
        let mut map = Map::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected string key in object"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value(depth + 1)?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
        Ok(Value::Object(map))
    }

    fn parse_number(&mut self) -> crate::Result<Number> {
        let start = self.i;
        let mut is_float = false;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.err("leading zeros are not allowed"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("expected digit in number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            is_float = true;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit after decimal point"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            is_float = true;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit in exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let text = &self.src[start..self.i];
        if !is_float {
            if let Ok(v) = text.parse::<i64>() {
                return Ok(Number::Int(v));
            }
        }
        match text.parse::<f64>() {
            Ok(f) if f.is_finite() => Ok(Number::Float(f)),
            Ok(_) => Err(self.err("number out of range")),
            Err(_) => Err(self.err("invalid number")),
        }
    }

    fn parse_string(&mut self) -> crate::Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = match self.bump() {
                Some(b) => b,
                None => return Err(self.err("unterminated string")),
            };
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = match self.bump() {
                        Some(e) => e,
                        None => return Err(self.err("unterminated escape")),
                    };
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(self.err("lone high surrogate"));
                                }
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                match char::from_u32(c) {
                                    Some(ch) => out.push(ch),
                                    None => return Err(self.err("invalid surrogate pair")),
                                }
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err(self.err("lone low surrogate"));
                            } else {
                                match char::from_u32(cp) {
                                    Some(ch) => out.push(ch),
                                    None => return Err(self.err("invalid unicode escape")),
                                }
                            }
                        }
                        other => {
                            return Err(self.err(&format!("invalid escape '\\{}'", other as char)))
                        }
                    }
                }
                0x00..=0x1f => return Err(self.err("unescaped control character in string")),
                _ if b < 0x80 => out.push(b as char),
                _ => {
                    // Multi-byte UTF-8: re-read the full char.
                    self.i -= 1;
                    let ch = match self.src[self.i..].chars().next() {
                        Some(c) => c,
                        None => return Err(self.err("invalid UTF-8 in string")),
                    };
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> crate::Result<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = match self.bump() {
                Some(b) => b,
                None => return Err(self.err("truncated \\u escape")),
            };
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(self.err("invalid hex digit in \\u escape")),
            };
            v = (v << 4) | digit as u32;
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ser::to_string;

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Value::Null);
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(parse("false").unwrap(), Value::Bool(false));
        assert_eq!(parse("0").unwrap().as_i64(), Some(0));
        assert_eq!(parse("-42").unwrap().as_i64(), Some(-42));
        assert_eq!(parse("3.25").unwrap().as_f64(), Some(3.25));
        assert_eq!(parse("1e3").unwrap().as_f64(), Some(1000.0));
        assert_eq!(parse("-1.5E-2").unwrap().as_f64(), Some(-0.015));
        assert_eq!(
            parse("9223372036854775807").unwrap().as_i64(),
            Some(i64::MAX)
        );
        assert_eq!(
            parse("18446744073709551615").unwrap().as_f64(),
            Some(1.8446744073709552e19)
        );
    }

    #[test]
    fn parses_strings_with_escapes() {
        assert_eq!(parse(r#""a\nb""#).unwrap().as_str(), Some("a\nb"));
        assert_eq!(
            parse(r#""\u4f60\u597d""#).unwrap().as_str(),
            Some("\u{4f60}\u{597d}")
        );
        assert_eq!(
            parse(r#""\ud83d\ude00""#).unwrap().as_str(),
            Some("\u{1f600}")
        );
        assert_eq!(parse(r#""quote: \"""#).unwrap().as_str(), Some("quote: \""));
        assert!(parse(r#""\ud800""#).is_err());
        assert!(parse(r#""\udc00""#).is_err());
        assert!(parse(r#""a\u{1}b""#).is_err());
    }

    #[test]
    fn parses_nested_documents() {
        let text = r#"{"a":[1,2,{"b":true}],"c":{"d":null,"e":"x"}}"#;
        let v = parse(text).unwrap();
        assert_eq!(to_string(&v), text);
    }

    #[test]
    fn rejects_invalid_documents() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "+1",
            "1.",
            "1e",
            "tru",
            "\"unterminated",
            "{} garbage",
            "{\"a\" 1}",
            "{\"a\":1 \"b\":2}",
            "NaN",
            "Infinity",
            &format!("{}{}", "[".repeat(300), "]".repeat(300)),
        ] {
            assert!(parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn duplicate_keys_last_wins() {
        let v = parse(r#"{"a":1,"a":2}"#).unwrap();
        assert_eq!(v["a"].as_i64(), Some(2));
    }

    #[test]
    fn prefix_parsing_reports_consumed_bytes() {
        let (v, n) = parse_prefix("  {\"a\":1} trailing").unwrap();
        assert_eq!(v["a"].as_i64(), Some(1));
        assert_eq!(&"  {\"a\":1} trailing"[n..], " trailing");
    }

    #[test]
    fn errors_have_positions() {
        let e = parse("{\"a\": bad}").unwrap_err();
        assert!(e.to_string().contains("byte"), "{e}");
    }
}
