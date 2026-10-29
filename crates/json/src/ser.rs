//! JSON serialization.

use crate::value::Value;

pub fn to_string(value: &Value) -> String {
    let mut out = String::with_capacity(256);
    write_to(value, &mut out);
    out
}

pub fn to_string_pretty(value: &Value) -> String {
    let mut out = String::with_capacity(512);
    write_pretty(value, &mut out, 0);
    out
}

pub fn write_to(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_to(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_to(v, out);
            }
            out.push('}');
        }
    }
}

fn write_pretty(value: &Value, out: &mut String, depth: usize) {
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, depth + 1);
                write_pretty(item, out, depth + 1);
            }
            out.push('\n');
            push_indent(out, depth);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                push_indent(out, depth + 1);
                write_string(k, out);
                out.push_str(": ");
                write_pretty(v, out, depth + 1);
            }
            out.push('\n');
            push_indent(out, depth);
            out.push('}');
        }
        _ => write_to(value, out),
    }
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

pub fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Write an f64 in a form that is valid JSON and short.
pub fn write_f64(f: &mut core::fmt::Formatter<'_>, x: f64) -> core::fmt::Result {
    if !x.is_finite() {
        return f.write_str("null");
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            f.write_str("-0.0")
        } else {
            f.write_str("0")
        };
    }
    // Use exponent notation for very large/small magnitudes to avoid 300-digit
    // integer expansions; JSON accepts both forms.
    let abs = x.abs();
    if abs >= 1e21 || abs < 1e-6 {
        let s = format!("{x:e}");
        // Rust prints 1e300 as "1e300" and 1e-7 as "1e-7"; both valid JSON.
        f.write_str(&s)
    } else {
        let s = format!("{x}");
        f.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse, Number, Value};

    #[test]
    fn escapes_roundtrip() {
        let s = "quote\" back\\ slash\n tab\t ctrl\u{1} unicode \u{4f60}";
        let v = Value::String(s.to_string());
        let text = to_string(&v);
        assert!(text.starts_with('"'));
        assert_eq!(parse(&text).unwrap(), v);
    }

    #[test]
    fn numbers_are_valid() {
        for n in [0i64, 1, -1, i64::MAX, i64::MIN] {
            let v = Value::Number(Number::Int(n));
            assert_eq!(parse(&to_string(&v)).unwrap(), v);
        }
        for f in [0.5, -0.0, 1e300, 1e-300, 123456.789, 1.0 / 3.0] {
            let v = Value::Number(Number::Float(f));
            let text = to_string(&v);
            let back = parse(&text).unwrap();
            match back {
                Value::Number(Number::Float(b)) => assert_eq!(b, f, "text = {text}"),
                other => panic!("expected number, got {other:?} from {text}"),
            }
        }
    }

    #[test]
    fn pretty_is_parseable() {
        let v = parse(r#"{"a":[1,2,{"b":null}],"c":"x"}"#).unwrap();
        let pretty = to_string_pretty(&v);
        assert_reserialize_eq(&pretty, &v);
    }

    fn assert_reserialize_eq(text: &str, v: &Value) {
        assert_eq!(&parse(text).unwrap(), v);
    }
}
