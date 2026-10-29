//! Base library and stdlib installation.
//!
//! print routes through Host::print, unknown global calls go to Host::call,
//! and the io/fs/proc/net namespaces resolve missing members to host calls.

use std::cell::RefCell;
use std::rc::Rc;

use crate::error::{Fault, IResult};
use crate::interp::Interp;
use crate::numfmt;
use crate::value::{Function, NativeFn, Table, Value};
use crate::{mathlib, oslib, strlib, tablelib};

pub(crate) fn native(name: &'static str, f: NativeFn) -> Value {
    Value::Function(Rc::new(Function::native(name, f)))
}

fn new_table() -> Rc<RefCell<Table>> {
    Rc::new(RefCell::new(Table::new()))
}

pub(crate) fn install(interp: &mut Interp) {
    let base: &[(&str, NativeFn)] = &[
        ("print", base_print),
        ("type", base_type),
        ("tostring", base_tostring),
        ("tonumber", base_tonumber),
        ("pairs", base_pairs),
        ("ipairs", base_ipairs),
        ("next", base_next),
        ("select", base_select),
        ("error", base_error),
        ("pcall", base_pcall),
        ("xpcall", base_xpcall),
        ("assert", base_assert),
        ("rawget", base_rawget),
        ("rawset", base_rawset),
        ("rawequal", base_rawequal),
        ("rawlen", base_rawlen),
        ("ipairs_iter", ipairs_iter),
    ];
    for (name, f) in base {
        interp.set_global(name, native(name, *f));
    }
    interp.set_global("_G", Value::Table(interp.globals.clone()));
    interp.set_global("_VERSION", Value::Str("emerag script 5.4".to_string()));

    let string_t = new_table();
    for (name, f) in strlib::FUNCS {
        string_t.borrow_mut().set_str(name, native(name, *f));
    }
    interp.set_global("string", Value::Table(string_t));

    let table_t = new_table();
    for (name, f) in tablelib::FUNCS {
        table_t.borrow_mut().set_str(name, native(name, *f));
    }
    interp.set_global("table", Value::Table(table_t));

    let math_t = new_table();
    for (name, f) in mathlib::FUNCS {
        math_t.borrow_mut().set_str(name, native(name, *f));
    }
    math_t
        .borrow_mut()
        .set_str("pi", Value::Number(core::f64::consts::PI));
    math_t
        .borrow_mut()
        .set_str("huge", Value::Number(f64::INFINITY));
    interp.set_global("math", Value::Table(math_t));

    let os_t = new_table();
    for (name, f) in oslib::FUNCS {
        os_t.borrow_mut().set_str(name, native(name, *f));
    }
    interp.set_global("os", Value::Table(os_t));

    for ns in ["io", "fs", "proc", "net"] {
        let table = interp.register_host_ns(ns);
        interp.set_global(ns, Value::Table(table));
    }
}

// ---- base functions ----------------------------------------------------

fn base_print(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let mut out = String::new();
    for (i, value) in args.iter().enumerate() {
        if i > 0 {
            out.push('\t');
        }
        out.push_str(&interp.tostring(value));
    }
    out.push('\n');
    interp.output(&out)?;
    Ok(Vec::new())
}

fn base_type(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let value = interp.arg(&args, 0);
    Ok(vec![Value::Str(value.type_name().to_string())])
}

fn base_tostring(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let value = interp.arg(&args, 0);
    Ok(vec![Value::Str(interp.tostring(&value))])
}

fn base_tonumber(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let value = interp.arg(&args, 0);
    let base = interp.arg(&args, 1);
    if base.is_nil() {
        return Ok(vec![match &value {
            Value::Number(n) => Value::Number(*n),
            Value::Str(s) => match numfmt::parse_number(s) {
                Some(n) => Value::Number(n),
                None => Value::Nil,
            },
            _ => Value::Nil,
        }]);
    }
    let base = interp.arg_number(&args, 1, "tonumber")?;
    if !(2.0..=36.0).contains(&base) {
        return Err(interp.rt("bad argument #2 to 'tonumber' (base out of range)"));
    }
    let text = match &value {
        Value::Str(s) => s.trim().to_string(),
        _ => return Ok(vec![Value::Nil]),
    };
    Ok(vec![match parse_in_base(&text, base as u32) {
        Some(n) => Value::Number(n),
        None => Value::Nil,
    }])
}

pub(crate) fn parse_in_base(text: &str, base: u32) -> Option<f64> {
    if !(2..=36).contains(&base) {
        return None;
    }
    let s = text.trim();
    let (neg, digits) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    if digits.is_empty() {
        return None;
    }
    let mut value = 0.0f64;
    for ch in digits.chars() {
        let d = ch.to_digit(36)?;
        if d >= base {
            return None;
        }
        value = value * base as f64 + d as f64;
    }
    Some(if neg { -value } else { value })
}

fn base_pairs(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "pairs")?;
    let next = interp.get_global("next");
    Ok(vec![next, Value::Table(table), Value::Nil])
}

fn base_ipairs(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "ipairs")?;
    let iter = native("ipairs_iter", ipairs_iter);
    Ok(vec![iter, Value::Table(table), Value::Number(0.0)])
}

fn ipairs_iter(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "ipairs iterator")?;
    let index = interp.arg_number(&args, 1, "ipairs iterator")? + 1.0;
    let value = table.borrow().get(&Value::Number(index));
    if value.is_nil() {
        Ok(vec![Value::Nil])
    } else {
        Ok(vec![Value::Number(index), value])
    }
}

fn base_next(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "next")?;
    let key = interp.arg(&args, 1);
    let valid = key.is_nil() || table.borrow().contains(&key);
    if !valid {
        return Err(interp.rt("invalid key to 'next'"));
    }
    let pair = table.borrow().next_pair(&key);
    match pair {
        Some((k, v)) => Ok(vec![k, v]),
        None => Ok(vec![Value::Nil]),
    }
}

fn base_select(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let first = interp.arg(&args, 0);
    if let Value::Str(s) = &first {
        if s == "#" {
            return Ok(vec![Value::Number(args.len().saturating_sub(1) as f64)]);
        }
    }
    let index = match first {
        Value::Number(n) => n,
        _ => return Err(interp.bad_arg(0, "select", "number", &first)),
    };
    let rest = args.len().saturating_sub(1);
    if index > 0.0 {
        let i = index as usize;
        if i > rest {
            return Ok(Vec::new());
        }
        Ok(args[1 + i - 1..].to_vec())
    } else if index < 0.0 {
        let i = (-index) as usize;
        if i > rest {
            return Ok(Vec::new());
        }
        Ok(args[args.len() - i..].to_vec())
    } else {
        Err(interp.rt("bad argument #1 to 'select' (index out of range)"))
    }
}

fn base_error(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let message = interp.arg(&args, 0);
    let level = interp.opt_number(&args, 1, 1.0);
    let line = interp.line();
    if level == 0.0 {
        return Err(Fault::lua_value(message, line));
    }
    match message {
        Value::Str(s) => Err(Fault::lua(s, line)),
        other => Err(Fault::lua_value(other, line)),
    }
}

fn base_assert(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let condition = interp.arg(&args, 0);
    if condition.truthy() {
        return Ok(args);
    }
    let message = interp.arg(&args, 1);
    let line = interp.line();
    match message {
        Value::Nil => Err(Fault::lua("assertion failed!", line)),
        Value::Str(s) => Err(Fault::lua(s, line)),
        other => Err(Fault::lua_value(other, line)),
    }
}

fn base_pcall(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let function = interp.arg(&args, 0);
    let rest: Vec<Value> = args.into_iter().skip(1).collect();
    match interp.call_value(&function, rest) {
        Ok(mut values) => {
            let mut out = Vec::with_capacity(values.len() + 1);
            out.push(Value::Bool(true));
            out.append(&mut values);
            Ok(out)
        }
        Err(fault) => {
            if fault.catchable {
                Ok(vec![Value::Bool(false), fault.value])
            } else {
                Err(fault)
            }
        }
    }
}

fn base_xpcall(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let function = interp.arg(&args, 0);
    let handler = interp.arg(&args, 1);
    let rest: Vec<Value> = args.into_iter().skip(2).collect();
    match interp.call_value(&function, rest) {
        Ok(mut values) => {
            let mut out = Vec::with_capacity(values.len() + 1);
            out.push(Value::Bool(true));
            out.append(&mut values);
            Ok(out)
        }
        Err(fault) => {
            if !fault.catchable {
                return Err(fault);
            }
            match interp.call_value(&handler, vec![fault.value]) {
                Ok(mut values) => {
                    let mut out = Vec::with_capacity(values.len() + 1);
                    out.push(Value::Bool(false));
                    out.append(&mut values);
                    Ok(out)
                }
                Err(inner) => {
                    if inner.catchable {
                        Ok(vec![Value::Bool(false), inner.value])
                    } else {
                        Err(inner)
                    }
                }
            }
        }
    }
}

fn base_rawget(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "rawget")?;
    let key = interp.arg(&args, 1);
    let value = table.borrow().get(&key);
    Ok(vec![value])
}

fn base_rawset(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "rawset")?;
    let key = interp.arg(&args, 1);
    let value = interp.arg(&args, 2);
    interp.set_table(&table, key, value)?;
    Ok(vec![Value::Table(table)])
}

fn base_rawequal(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let a = interp.arg(&args, 0);
    let b = interp.arg(&args, 1);
    Ok(vec![Value::Bool(a.equals(&b))])
}

fn base_rawlen(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let value = interp.arg(&args, 0);
    match &value {
        Value::Str(s) => Ok(vec![Value::Number(s.len() as f64)]),
        Value::Table(t) => Ok(vec![Value::Number(t.borrow().len() as f64)]),
        other => Err(interp.bad_arg(0, "rawlen", "table or string", other)),
    }
}
