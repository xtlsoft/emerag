//! Number formatting with Lua's semantics.
//!
//! Lua 5.4 formats floats with %.14g and prints integral floats without a
//! trailing ".0" (emerag-script has a single Number type, so this is the
//! documented behaviour for every number). Everything here is hand written:
//! the workspace may not depend on libc's printf.

/// Format an integral value without a decimal point, like Lua's integer
/// formatting. Non integral values use format_g with 14 significant digits.
pub(crate) fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        return "nan".to_string();
    }
    if n.is_infinite() {
        return if n > 0.0 {
            "inf".to_string()
        } else {
            "-inf".to_string()
        };
    }
    if n == 0.0 {
        return if n.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }
    if n.fract() == 0.0 && n.abs() < 1e16 {
        // f64 integral values below 2^53 are exact; use the shortest exact form.
        return format!("{:.0}", n);
    }
    format_g(n, 14, false, false)
}

/// C-style %g: prec significant digits, trailing zeros removed unless alt is
/// set, switching to exponent form when the exponent is < -4 or >= precision.
pub(crate) fn format_g(x: f64, prec: usize, upper: bool, alt: bool) -> String {
    if x.is_nan() {
        return if upper {
            "NAN".to_string()
        } else {
            "nan".to_string()
        };
    }
    if x.is_infinite() {
        let body = if upper { "INF" } else { "inf" };
        return if x < 0.0 {
            format!("-{body}")
        } else {
            body.to_string()
        };
    }
    let p = if prec == 0 { 1 } else { prec };
    let neg = x.is_sign_negative();
    let ax = x.abs();
    let mut out = String::new();
    if ax == 0.0 {
        out.push('0');
        if alt {
            out.push('.');
            for _ in 1..p {
                out.push('0');
            }
        }
        return finish(neg, out);
    }
    // Round to p significant digits using Rust's exponent formatting.
    let sci = format!("{:.*e}", p - 1, ax);
    let (mant, exp_s) = match sci.split_once('e') {
        Some(v) => v,
        None => (sci.as_str(), "0"),
    };
    let exp: i32 = exp_s.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let bytes = digits.as_bytes();
    if exp < -4 || exp >= p as i32 {
        out.push(bytes.first().copied().unwrap_or(b'0') as char);
        let frac_raw = if bytes.len() > 1 { &digits[1..] } else { "" };
        let frac = if alt {
            frac_raw.to_string()
        } else {
            frac_raw.trim_end_matches('0').to_string()
        };
        if !frac.is_empty() {
            out.push('.');
            out.push_str(&frac);
        }
        out.push(if upper { 'E' } else { 'e' });
        out.push(if exp < 0 { '-' } else { '+' });
        let a = exp.unsigned_abs();
        if a < 10 {
            out.push('0');
        }
        out.push_str(&a.to_string());
    } else if exp >= 0 {
        let ip_len = (exp + 1) as usize;
        let (ip, fp_raw) = if bytes.len() > ip_len {
            (&digits[..ip_len], &digits[ip_len..])
        } else {
            (&digits[..], "")
        };
        out.push_str(ip);
        let fp = if alt {
            fp_raw.to_string()
        } else {
            fp_raw.trim_end_matches('0').to_string()
        };
        if !fp.is_empty() {
            out.push('.');
            out.push_str(&fp);
        } else if alt {
            out.push('.');
        }
    } else {
        out.push_str("0.");
        for _ in 0..(-exp - 1) {
            out.push('0');
        }
        let fp = if alt {
            digits.clone()
        } else {
            digits.trim_end_matches('0').to_string()
        };
        out.push_str(&fp);
    }
    finish(neg, out)
}

/// C-style %f: fixed point with prec digits after the decimal point.
pub(crate) fn format_fixed(x: f64, prec: usize) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x < 0.0 {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    let neg = x.is_sign_negative();
    let body = format!("{:.*}", prec, x.abs());
    finish(neg, body)
}

/// C-style %e: scientific notation with prec fractional digits and an
/// exponent of at least two digits (Lua/printf compatible).
pub(crate) fn format_exp(x: f64, prec: usize, upper: bool) -> String {
    if x.is_nan() {
        return if upper {
            "NAN".to_string()
        } else {
            "nan".to_string()
        };
    }
    if x.is_infinite() {
        let body = if upper { "INF" } else { "inf" };
        return if x < 0.0 {
            format!("-{body}")
        } else {
            body.to_string()
        };
    }
    let neg = x.is_sign_negative();
    let sci = format!("{:.*e}", prec, x.abs());
    let (mant, exp_s) = match sci.split_once('e') {
        Some(v) => v,
        None => (sci.as_str(), "0"),
    };
    let exp: i32 = exp_s.parse().unwrap_or(0);
    let mut out = String::with_capacity(mant.len() + 6);
    out.push_str(mant);
    out.push(if upper { 'E' } else { 'e' });
    out.push(if exp < 0 { '-' } else { '+' });
    let a = exp.unsigned_abs();
    if a < 10 {
        out.push('0');
    }
    out.push_str(&a.to_string());
    finish(neg, out)
}

fn finish(neg: bool, body: String) -> String {
    // A negative zero keeps its sign only when the body is non-zero, like printf.
    if neg && body.bytes().any(|b| b.is_ascii_digit() && b != b'0') {
        let mut s = String::with_capacity(body.len() + 1);
        s.push('-');
        s.push_str(&body);
        s
    } else {
        body
    }
}

/// Append a C-escaped quoted string (Lua's %q).
pub(crate) fn quote_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 32 || c as u32 == 127 => {
                out.push_str(&format!("\\{:03}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse a Lua number string: optional sign, decimal or 0x hexadecimal with
/// optional binary exponent. Rejects the things Lua's tonumber rejects (inf,
/// nan, trailing garbage).
pub(crate) fn parse_number(text: &str) -> Option<f64> {
    let s = text.trim();
    if s.is_empty() {
        return None;
    }
    let (neg, body) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    let first = *body.as_bytes().first()?;
    if !(first.is_ascii_digit() || first == b'.') {
        return None;
    }
    if body == "." {
        return None;
    }
    let value = if body.len() > 2 && (body.starts_with("0x") || body.starts_with("0X")) {
        parse_hex_float(body)?
    } else {
        body.parse::<f64>().ok()?
    };
    Some(if neg { -value } else { value })
}

/// Parse 0x... (optionally with a hexadecimal fraction and a p exponent).
pub(crate) fn parse_hex_float(text: &str) -> Option<f64> {
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    let (mant, exp_part) = match body.find(['p', 'P']) {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let mut value = 0.0f64;
    let mut frac = 0.0f64;
    let mut scale = 1.0f64;
    let mut seen_dot = false;
    let mut digits = 0;
    for ch in mant.bytes() {
        if ch == b'.' {
            if seen_dot {
                return None;
            }
            seen_dot = true;
            continue;
        }
        let d = (ch as char).to_digit(16)? as f64;
        digits += 1;
        if seen_dot {
            scale /= 16.0;
            frac += d * scale;
        } else {
            value = value * 16.0 + d;
        }
    }
    if digits == 0 {
        return None;
    }
    let mut v = value + frac;
    if let Some(e) = exp_part {
        if e.is_empty() {
            return None;
        }
        let exp: i32 = e.parse().ok()?;
        v *= 2f64.powi(exp);
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_print_without_dot() {
        assert_eq!(number_to_string(1.0), "1");
        assert_eq!(number_to_string(-7.0), "-7");
        assert_eq!(number_to_string(1024.0), "1024");
        assert_eq!(number_to_string(0.0), "0");
    }

    #[test]
    fn floats_use_fourteen_digits() {
        assert_eq!(number_to_string(0.5), "0.5");
        assert_eq!(number_to_string(1.0 / 3.0), "0.33333333333333");
        assert_eq!(number_to_string(2.5), "2.5");
        assert_eq!(number_to_string(1e300), "1e+300");
        assert_eq!(number_to_string(-1.5e-7), "-1.5e-07");
        assert_eq!(number_to_string(f64::NAN), "nan");
        assert_eq!(number_to_string(f64::INFINITY), "inf");
        assert_eq!(number_to_string(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn g_format_matches_printf_examples() {
        assert_eq!(format_g(1234.5678, 6, false, false), "1234.57");
        assert_eq!(format_g(0.0001234, 6, false, false), "0.0001234");
        assert_eq!(format_g(0.00001234, 6, false, false), "1.234e-05");
        assert_eq!(format_g(100.0, 6, false, false), "100");
        assert_eq!(format_g(1.0, 6, false, false), "1");
        assert_eq!(format_g(123456789.0, 6, false, false), "1.23457e+08");
        assert_eq!(format_g(1.0, 6, false, true), "1.00000");
    }

    #[test]
    fn f_and_e_formatting() {
        assert_eq!(format_fixed(1.5, 3), "1.500");
        assert_eq!(format_fixed(-0.0, 2), "0.00");
        assert_eq!(format_exp(12345.678, 2, false), "1.23e+04");
        assert_eq!(format_exp(1.0, 0, true), "1E+00");
        assert_eq!(format_exp(0.5, 1, false), "5.0e-01");
    }

    #[test]
    fn quoting() {
        let mut s = String::new();
        quote_string("a\"b\\c\nd", &mut s);
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\"");
    }
}
