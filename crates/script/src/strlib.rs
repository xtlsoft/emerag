//! The string library, including Lua patterns and string.format.

use std::cell::RefCell;
use std::rc::Rc;

use crate::error::IResult;
use crate::interp::Interp;
use crate::numfmt;
use crate::pattern::{self, CapValue, Match};
use crate::value::{Function, NativeFn, Value};

pub(crate) const FUNCS: &[(&str, NativeFn)] = &[
    ("len", str_len),
    ("sub", str_sub),
    ("byte", str_byte),
    ("char", str_char),
    ("rep", str_rep),
    ("reverse", str_reverse),
    ("upper", str_upper),
    ("lower", str_lower),
    ("format", str_format),
    ("find", str_find),
    ("match", str_match),
    ("gmatch", str_gmatch),
    ("gsub", str_gsub),
];

/// State for one string.gmatch iterator.
pub(crate) struct GmatchState {
    pub src: Vec<u8>,
    pub pat: Vec<u8>,
    pub pos: usize,
    /// End of the previous match; an empty match there is skipped (Lua 5.4).
    pub last: Option<usize>,
}

// ---- index helpers (mirroring Lua's posrelatI/getendpos) ---------------

fn posrelat_start(pos: i64, len: usize) -> usize {
    let len = len as i64;
    if pos > 0 {
        pos as usize
    } else if pos == 0 {
        1
    } else if pos < -len {
        1
    } else {
        (len + pos + 1) as usize
    }
}

fn posrelat_end(pos: i64, len: usize) -> usize {
    let len = len as i64;
    if pos > len {
        len as usize
    } else if pos >= 0 {
        pos as usize
    } else if pos < -len {
        0
    } else {
        (len + pos + 1) as usize
    }
}

fn slice_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---- basic operations --------------------------------------------------

fn str_len(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "len")?;
    Ok(vec![Value::Number(s.len() as f64)])
}

fn str_sub(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "sub")?;
    let len = s.len();
    let i = interp.arg_int(&args, 1, "sub")?;
    let j = match args.get(2) {
        None | Some(Value::Nil) => -1,
        Some(_) => interp.arg_int(&args, 2, "sub")?,
    };
    let start = posrelat_start(i, len);
    let end = posrelat_end(j, len);
    if start > end {
        return Ok(vec![Value::Str(String::new())]);
    }
    let bytes = &s.as_bytes()[start - 1..end];
    Ok(vec![interp.new_string(slice_lossy(bytes))?])
}

fn str_byte(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "byte")?;
    let len = s.len();
    let i = match args.get(1) {
        None | Some(Value::Nil) => 1,
        Some(_) => interp.arg_int(&args, 1, "byte")?,
    };
    let j = match args.get(2) {
        None | Some(Value::Nil) => i,
        Some(_) => interp.arg_int(&args, 2, "byte")?,
    };
    let start = posrelat_start(i, len);
    let end = posrelat_end(j, len);
    let mut out = Vec::new();
    if start <= end {
        for b in &s.as_bytes()[start - 1..end] {
            out.push(Value::Number(*b as f64));
        }
    }
    Ok(out)
}

fn str_char(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let mut out: Vec<u8> = Vec::with_capacity(args.len());
    for (i, _) in args.iter().enumerate() {
        let n = interp.arg_int(&args, i, "char")?;
        if !(0..=255).contains(&n) {
            return Err(interp.rt(format!(
                "bad argument #{} to 'char' (value out of range)",
                i + 1
            )));
        }
        out.push(n as u8);
    }
    let text = String::from_utf8(out).map_err(|_| interp.rt("'char' result is not valid UTF-8"))?;
    Ok(vec![interp.new_string(text)?])
}

fn str_rep(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "rep")?;
    let n = interp.arg_int(&args, 1, "rep")?;
    let sep = match args.get(2) {
        None | Some(Value::Nil) => String::new(),
        Some(_) => interp.arg_str(&args, 2, "rep")?,
    };
    if n <= 0 {
        return Ok(vec![Value::Str(String::new())]);
    }
    let n = n as usize;
    let total = s
        .len()
        .saturating_mul(n)
        .saturating_add(sep.len().saturating_mul(n.saturating_sub(1)));
    if total > crate::interp::MAX_STRING_BYTES {
        return Err(interp.rt("resulting string too large in 'rep'"));
    }
    let mut out = String::with_capacity(total);
    for i in 0..n {
        if i > 0 {
            out.push_str(&sep);
        }
        out.push_str(&s);
    }
    Ok(vec![interp.new_string(out)?])
}

fn str_reverse(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "reverse")?;
    let reversed: String = s.chars().rev().collect();
    Ok(vec![interp.new_string(reversed)?])
}

fn str_upper(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "upper")?;
    Ok(vec![interp.new_string(s.to_ascii_uppercase())?])
}

fn str_lower(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "lower")?;
    Ok(vec![interp.new_string(s.to_ascii_lowercase())?])
}

// ---- find / match ------------------------------------------------------

fn capture_value(src: &[u8], cap: &CapValue) -> Value {
    match cap {
        CapValue::Str(a, b) => Value::Str(slice_lossy(&src[*a..*b])),
        CapValue::Pos(p) => Value::Number(*p as f64),
    }
}

fn find_plain(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn start_offset(
    interp: &mut Interp,
    args: &[Value],
    index: usize,
    len: usize,
    fname: &str,
) -> IResult<usize> {
    let init = match args.get(index) {
        None | Some(Value::Nil) => 1,
        Some(_) => interp.arg_int(args, index, fname)?,
    };
    if init > 0 && init as usize > len + 1 {
        return Ok(len + 1);
    }
    Ok(posrelat_start(init, len) - 1)
}

fn str_find(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "find")?;
    let p = interp.arg_str(&args, 1, "find")?;
    let plain = match args.get(3) {
        None | Some(Value::Nil) => false,
        Some(v) => v.truthy(),
    };
    let src = s.as_bytes();
    let pat = p.as_bytes();
    let start = start_offset(interp, &args, 2, src.len(), "find")?;
    if start > src.len() {
        return Ok(vec![Value::Nil]);
    }
    if plain || !pattern::has_specials(pat) {
        return Ok(match find_plain(&src[start..], pat) {
            Some(off) => {
                let a = start + off;
                vec![
                    Value::Number((a + 1) as f64),
                    Value::Number((a + pat.len()) as f64),
                ]
            }
            None => vec![Value::Nil],
        });
    }
    match pattern::find(src, pat, start) {
        Ok((Some(m), steps)) => {
            interp.charge_steps(steps)?;
            let mut out = vec![
                Value::Number((m.start + 1) as f64),
                Value::Number(m.end as f64),
            ];
            for cap in &m.caps {
                out.push(capture_value(src, cap));
            }
            Ok(out)
        }
        Ok((None, steps)) => {
            interp.charge_steps(steps)?;
            Ok(vec![Value::Nil])
        }
        Err(e) => Err(interp.rt(e)),
    }
}

fn str_match(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "match")?;
    let p = interp.arg_str(&args, 1, "match")?;
    let src = s.as_bytes();
    let pat = p.as_bytes();
    let start = start_offset(interp, &args, 2, src.len(), "match")?;
    if start > src.len() {
        return Ok(vec![Value::Nil]);
    }
    match pattern::find(src, pat, start) {
        Ok((Some(m), steps)) => {
            interp.charge_steps(steps)?;
            if m.caps.is_empty() {
                Ok(vec![Value::Str(slice_lossy(&src[m.start..m.end]))])
            } else {
                Ok(m.caps.iter().map(|c| capture_value(src, c)).collect())
            }
        }
        Ok((None, steps)) => {
            interp.charge_steps(steps)?;
            Ok(vec![Value::Nil])
        }
        Err(e) => Err(interp.rt(e)),
    }
}

fn str_gmatch(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "gmatch")?;
    let p = interp.arg_str(&args, 1, "gmatch")?;
    let state = Rc::new(RefCell::new(GmatchState {
        src: s.into_bytes(),
        pat: p.into_bytes(),
        pos: 0,
        last: None,
    }));
    Ok(vec![Value::Function(Rc::new(Function::gmatch(state)))])
}

pub(crate) fn gmatch_next(
    interp: &mut Interp,
    state: &Rc<RefCell<GmatchState>>,
    _args: Vec<Value>,
) -> IResult<Vec<Value>> {
    // Borrow the subject instead of cloning it per call: a gmatch over a large
    // file would otherwise copy the whole text once for every match.
    let mut st = state.borrow_mut();
    loop {
        if st.pos > st.src.len() {
            return Ok(vec![Value::Nil]);
        }
        let (found, steps) = pattern::find(&st.src, &st.pat, st.pos).map_err(|e| interp.rt(e))?;
        interp.charge_steps(steps)?;
        let m = match found {
            Some(m) => m,
            None => {
                st.pos = st.src.len() + 1;
                return Ok(vec![Value::Nil]);
            }
        };
        if st.last == Some(m.end) {
            // Empty match right where the previous one ended: step past it.
            st.pos = m.start + 1;
            continue;
        }
        st.pos = m.end;
        st.last = Some(m.end);
        let src = &st.src;
        if m.caps.is_empty() {
            return Ok(vec![Value::Str(slice_lossy(&src[m.start..m.end]))]);
        }
        return Ok(m.caps.iter().map(|c| capture_value(src, c)).collect());
    }
}

// ---- gsub --------------------------------------------------------------

fn expand_replacement(interp: &mut Interp, repl: &[u8], src: &[u8], m: &Match) -> IResult<Vec<u8>> {
    let mut out = Vec::with_capacity(repl.len());
    let mut i = 0;
    while i < repl.len() {
        if repl[i] != b'%' {
            out.push(repl[i]);
            i += 1;
            continue;
        }
        i += 1;
        let c = match repl.get(i) {
            Some(c) => *c,
            None => return Err(interp.rt("invalid use of '%' in replacement string")),
        };
        i += 1;
        match c {
            b'%' => out.push(b'%'),
            b'0' => out.extend_from_slice(&src[m.start..m.end]),
            b'1'..=b'9' => {
                let index = (c - b'1') as usize;
                match m.caps.get(index) {
                    Some(CapValue::Str(a, b)) => out.extend_from_slice(&src[*a..*b]),
                    Some(CapValue::Pos(p)) => out.extend_from_slice(p.to_string().as_bytes()),
                    None => {
                        return Err(interp.rt(format!(
                            "invalid capture index %{} in replacement",
                            c - b'0'
                        )))
                    }
                }
            }
            _ => return Err(interp.rt("invalid use of '%' in replacement string")),
        }
    }
    Ok(out)
}

fn replacement_value(
    interp: &mut Interp,
    repl: &Value,
    src: &[u8],
    m: &Match,
) -> IResult<Option<Vec<u8>>> {
    match repl {
        Value::Str(s) => {
            let expanded = expand_replacement(interp, s.as_bytes(), src, m)?;
            Ok(Some(expanded))
        }
        Value::Table(t) => {
            let key = match m.caps.first() {
                Some(cap) => capture_value(src, cap),
                None => Value::Str(slice_lossy(&src[m.start..m.end])),
            };
            let value = t.borrow().get(&key);
            replacement_to_bytes(interp, &value)
        }
        Value::Function(_) => {
            let mut call_args = Vec::with_capacity(m.caps.len().max(1));
            if m.caps.is_empty() {
                call_args.push(Value::Str(slice_lossy(&src[m.start..m.end])));
            } else {
                for cap in &m.caps {
                    call_args.push(capture_value(src, cap));
                }
            }
            let results = interp.call_value(repl, call_args)?;
            let value = results.into_iter().next().unwrap_or(Value::Nil);
            replacement_to_bytes(interp, &value)
        }
        other => Err(interp.rt(format!(
            "bad argument #3 to 'gsub' (string/function/table expected, got {})",
            other.type_name()
        ))),
    }
}

fn replacement_to_bytes(interp: &mut Interp, value: &Value) -> IResult<Option<Vec<u8>>> {
    match value {
        Value::Nil | Value::Bool(false) => Ok(None),
        Value::Str(s) => Ok(Some(s.clone().into_bytes())),
        Value::Number(n) => Ok(Some(numfmt::number_to_string(*n).into_bytes())),
        other => Err(interp.rt(format!(
            "invalid replacement value (a {})",
            other.type_name()
        ))),
    }
}

fn str_gsub(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let s = interp.arg_str(&args, 0, "gsub")?;
    let p = interp.arg_str(&args, 1, "gsub")?;
    let repl = interp.arg(&args, 2);
    let max_count = match args.get(3) {
        None | Some(Value::Nil) => usize::MAX,
        Some(_) => {
            let n = interp.arg_int(&args, 3, "gsub")?;
            if n <= 0 {
                0
            } else {
                n as usize
            }
        }
    };
    let src = s.as_bytes();
    let pat = p.as_bytes();
    let anchored = pat.first() == Some(&b'^');
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut pos = 0usize;
    let mut last_match = usize::MAX;
    let mut count = 0usize;
    while count < max_count {
        let m = match pattern::find(src, pat, pos) {
            Ok((Some(m), steps)) => {
                interp.charge_steps(steps)?;
                m
            }
            Ok((None, steps)) => {
                interp.charge_steps(steps)?;
                break;
            }
            Err(e) => return Err(interp.rt(e)),
        };
        if m.end == last_match && m.start == last_match {
            if pos < src.len() {
                out.push(src[pos]);
                pos += 1;
                if anchored {
                    break;
                }
                continue;
            }
            break;
        }
        out.extend_from_slice(&src[pos..m.start]);
        match replacement_value(interp, &repl, src, &m)? {
            Some(bytes) => out.extend_from_slice(&bytes),
            None => out.extend_from_slice(&src[m.start..m.end]),
        }
        pos = m.end;
        last_match = m.end;
        count += 1;
        if anchored {
            break;
        }
        if pos > src.len() {
            break;
        }
    }
    if pos <= src.len() {
        out.extend_from_slice(&src[pos..]);
    }
    let text = interp.new_string(slice_lossy(&out))?;
    Ok(vec![text, Value::Number(count as f64)])
}

// ---- string.format -----------------------------------------------------

#[derive(Default)]
struct Spec {
    minus: bool,
    plus: bool,
    space: bool,
    hash: bool,
    zero: bool,
    width: usize,
    prec: Option<usize>,
}

fn pad_field(spec: &Spec, sign: char, prefix: &str, body: &str) -> String {
    let mut field = String::with_capacity(spec.width.max(body.len() + 2));
    if sign != '\0' {
        field.push(sign);
    }
    field.push_str(prefix);
    field.push_str(body);
    if field.len() >= spec.width {
        return field;
    }
    let padding = spec.width - field.len();
    if spec.minus {
        let mut out = field;
        for _ in 0..padding {
            out.push(' ');
        }
        out
    } else if spec.zero {
        let mut out = String::with_capacity(spec.width);
        if sign != '\0' {
            out.push(sign);
        }
        out.push_str(prefix);
        for _ in 0..padding {
            out.push('0');
        }
        out.push_str(body);
        out
    } else {
        let mut out = String::with_capacity(spec.width);
        for _ in 0..padding {
            out.push(' ');
        }
        out.push_str(&field);
        out
    }
}

fn integer_field(
    interp: &mut Interp,
    value: f64,
    spec: &Spec,
    base: u32,
    upper: bool,
    signed: bool,
) -> IResult<String> {
    if !value.is_finite() {
        return Err(interp.rt("bad argument to 'format' (number has no integer representation)"));
    }
    let n = value as i64;
    let (sign, magnitude) = if signed {
        if n < 0 {
            ('-', (n as i128).unsigned_abs() as u64)
        } else if spec.plus {
            ('+', n as u64)
        } else if spec.space {
            (' ', n as u64)
        } else {
            ('\0', n as u64)
        }
    } else {
        ('\0', n as u64)
    };
    let mut digits = match base {
        16 => {
            if upper {
                format!("{magnitude:X}")
            } else {
                format!("{magnitude:x}")
            }
        }
        8 => format!("{magnitude:o}"),
        _ => format!("{magnitude}"),
    };
    if let Some(prec) = spec.prec {
        if prec == 0 && magnitude == 0 {
            digits.clear();
        } else if digits.len() < prec {
            let mut padded = String::new();
            for _ in 0..prec - digits.len() {
                padded.push('0');
            }
            padded.push_str(&digits);
            digits = padded;
        }
    }
    let prefix = if spec.hash {
        match base {
            16 if magnitude != 0 => {
                if upper {
                    "0X"
                } else {
                    "0x"
                }
            }
            8 if magnitude != 0 => "0",
            _ => "",
        }
    } else {
        ""
    };
    Ok(pad_field(spec, sign, prefix, &digits))
}

fn float_field(_interp: &mut Interp, value: f64, spec: &Spec, conv: u8) -> IResult<String> {
    let upper = conv.is_ascii_uppercase();
    if value.is_nan() {
        return Ok(pad_field(spec, '\0', "", if upper { "NAN" } else { "nan" }));
    }
    if value.is_infinite() {
        let body = if upper { "INF" } else { "inf" };
        let sign = if value < 0.0 {
            '-'
        } else if spec.plus {
            '+'
        } else if spec.space {
            ' '
        } else {
            '\0'
        };
        return Ok(pad_field(spec, sign, "", body));
    }
    let prec = spec.prec.unwrap_or(6);
    let rendered = match conv {
        b'f' | b'F' => numfmt::format_fixed(value, prec),
        b'e' | b'E' => numfmt::format_exp(value, prec, upper),
        _ => numfmt::format_g(value, prec, upper, spec.hash),
    };
    let (sign, body) = if let Some(rest) = rendered.strip_prefix('-') {
        ('-', rest.to_string())
    } else if spec.plus {
        ('+', rendered)
    } else if spec.space {
        (' ', rendered)
    } else {
        ('\0', rendered)
    };
    Ok(pad_field(spec, sign, "", &body))
}

fn str_q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    numfmt::quote_string(s, &mut out);
    out
}

fn str_format(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let fmt = interp.arg_str(&args, 0, "format")?;
    let bytes = fmt.as_bytes().to_vec();
    let mut out: Vec<u8> = Vec::with_capacity(fmt.len() + 16);
    let mut argi = 1usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if bytes.get(i) == Some(&b'%') {
            out.push(b'%');
            i += 1;
            continue;
        }
        let mut spec = Spec::default();
        loop {
            match bytes.get(i) {
                Some(b'-') => spec.minus = true,
                Some(b'+') => spec.plus = true,
                Some(b' ') => spec.space = true,
                Some(b'#') => spec.hash = true,
                Some(b'0') => spec.zero = true,
                _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        while let Some(c) = bytes.get(i) {
            if c.is_ascii_digit() {
                width = width.saturating_mul(10).saturating_add((c - b'0') as usize);
                i += 1;
            } else {
                break;
            }
        }
        if width > crate::interp::MAX_FORMAT_WIDTH {
            return Err(interp.rt("specifier field width too large in 'format'"));
        }
        spec.width = width;
        if bytes.get(i) == Some(&b'.') {
            i += 1;
            let mut prec = 0usize;
            while let Some(c) = bytes.get(i) {
                if c.is_ascii_digit() {
                    prec = prec.saturating_mul(10).saturating_add((c - b'0') as usize);
                    i += 1;
                } else {
                    break;
                }
            }
            if prec > crate::interp::MAX_FORMAT_PRECISION {
                return Err(interp.rt("specifier precision too large in 'format'"));
            }
            spec.prec = Some(prec);
        }
        let conv = match bytes.get(i) {
            Some(c) => *c,
            None => return Err(interp.rt("invalid conversion '%' to 'format'")),
        };
        i += 1;
        let fetch = |interp: &mut Interp| -> IResult<Value> {
            match args.get(argi) {
                Some(v) => Ok(v.clone()),
                None => {
                    Err(interp.rt(format!("bad argument #{} to 'format' (no value)", argi + 1)))
                }
            }
        };
        match conv {
            b'%' => out.push(b'%'),
            b'd' | b'i' => {
                let value = fetch(interp)?;
                let index = argi;
                argi += 1;
                let n = match value {
                    Value::Number(n) => n,
                    other => return Err(interp.bad_arg(index, "format", "number", &other)),
                };
                out.extend_from_slice(integer_field(interp, n, &spec, 10, false, true)?.as_bytes());
            }
            b'x' | b'X' => {
                let value = fetch(interp)?;
                let index = argi;
                argi += 1;
                let n = match value {
                    Value::Number(n) => n,
                    other => return Err(interp.bad_arg(index, "format", "number", &other)),
                };
                out.extend_from_slice(
                    integer_field(interp, n, &spec, 16, conv == b'X', false)?.as_bytes(),
                );
            }
            b'o' => {
                let value = fetch(interp)?;
                let index = argi;
                argi += 1;
                let n = match value {
                    Value::Number(n) => n,
                    other => return Err(interp.bad_arg(index, "format", "number", &other)),
                };
                out.extend_from_slice(integer_field(interp, n, &spec, 8, false, false)?.as_bytes());
            }
            b'c' => {
                let value = fetch(interp)?;
                let index = argi;
                argi += 1;
                let n = match value {
                    Value::Number(n) => n,
                    other => return Err(interp.bad_arg(index, "format", "number", &other)),
                };
                let ch = char::from_u32(n as u32).ok_or_else(|| {
                    interp.rt("bad argument to 'format' (invalid character code)")
                })?;
                let body = ch.to_string();
                out.extend_from_slice(pad_field(&spec, '\0', "", &body).as_bytes());
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let value = fetch(interp)?;
                let index = argi;
                argi += 1;
                let n = match value {
                    Value::Number(n) => n,
                    other => return Err(interp.bad_arg(index, "format", "number", &other)),
                };
                out.extend_from_slice(float_field(interp, n, &spec, conv)?.as_bytes());
            }
            b's' => {
                let value = fetch(interp)?;
                argi += 1;
                let mut text = interp.tostring(&value);
                if let Some(prec) = spec.prec {
                    if prec < text.len() {
                        let mut cut = prec;
                        while cut > 0 && !text.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        text.truncate(cut);
                    }
                }
                out.extend_from_slice(pad_field(&spec, '\0', "", &text).as_bytes());
            }
            b'q' => {
                let value = fetch(interp)?;
                argi += 1;
                let text = interp.tostring(&value);
                out.extend_from_slice(str_q(&text).as_bytes());
            }
            other => {
                return Err(interp.rt(format!(
                    "invalid conversion '%{}' to 'format'",
                    (other as char).escape_default()
                )))
            }
        }
    }
    let text = String::from_utf8(out).map_err(|_| interp.rt("'format' produced invalid UTF-8"))?;
    Ok(vec![interp.new_string(text)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_helpers_match_lua() {
        assert_eq!(posrelat_start(1, 5), 1);
        assert_eq!(posrelat_start(-1, 5), 5);
        assert_eq!(posrelat_start(0, 5), 1);
        assert_eq!(posrelat_start(-10, 5), 1);
        assert_eq!(posrelat_end(-1, 5), 5);
        assert_eq!(posrelat_end(10, 5), 5);
        assert_eq!(posrelat_end(0, 5), 0);
    }

    #[test]
    fn plain_search() {
        assert_eq!(find_plain(b"hello world", b"world"), Some(6));
        assert_eq!(find_plain(b"abc", b""), Some(0));
        assert_eq!(find_plain(b"abc", b"abcd"), None);
    }
}
