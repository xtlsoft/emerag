//! The table library.

use std::cell::RefCell;
use std::rc::Rc;

use crate::error::IResult;
use crate::interp::Interp;
use crate::numfmt;
use crate::value::{NativeFn, Table, Value};

pub(crate) const FUNCS: &[(&str, NativeFn)] = &[
    ("insert", table_insert),
    ("remove", table_remove),
    ("concat", table_concat),
    ("sort", table_sort),
    ("len", table_len),
    ("unpack", table_unpack),
    ("pack", table_pack),
];

fn array_snapshot(table: &Rc<RefCell<Table>>) -> (usize, Vec<Value>) {
    let t = table.borrow();
    let len = t.len();
    let mut items = Vec::with_capacity(len);
    for i in 1..=len {
        items.push(t.get(&Value::Number(i as f64)));
    }
    (len, items)
}

fn table_insert(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "insert")?;
    let len = table.borrow().len();
    if args.len() < 2 {
        return Err(interp.rt("wrong number of arguments to 'insert'"));
    }
    let (pos, value) = if args.len() == 2 {
        (len + 1, interp.arg(&args, 1))
    } else {
        let pos = interp.arg_int(&args, 1, "insert")?;
        if pos < 1 || pos as usize > len + 1 {
            return Err(interp.rt("bad argument #2 to 'insert' (position out of bounds)"));
        }
        (pos as usize, interp.arg(&args, 2))
    };
    if pos < 1 || pos > len + 1 {
        return Err(interp.rt("bad argument #2 to 'insert' (position out of bounds)"));
    }
    for i in (pos..=len).rev() {
        let value = { table.borrow().get(&Value::Number(i as f64)) };
        interp.set_table(&table, Value::Number((i + 1) as f64), value)?;
    }
    interp.set_table(&table, Value::Number(pos as f64), value)?;
    Ok(Vec::new())
}

fn table_remove(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "remove")?;
    let len = table.borrow().len();
    let pos = match args.get(1) {
        None | Some(Value::Nil) => len as i64,
        Some(_) => interp.arg_int(&args, 1, "remove")?,
    };
    if len == 0 && (pos == 0 || pos == 1) {
        return Ok(vec![Value::Nil]);
    }
    if pos < 1 || pos as usize > len {
        return Err(interp.rt("bad argument #2 to 'remove' (position out of bounds)"));
    }
    let pos = pos as usize;
    let removed = { table.borrow().get(&Value::Number(pos as f64)) };
    for i in pos..len {
        let value = { table.borrow().get(&Value::Number((i + 1) as f64)) };
        interp.set_table(&table, Value::Number(i as f64), value)?;
    }
    interp.set_table(&table, Value::Number(len as f64), Value::Nil)?;
    Ok(vec![removed])
}

fn table_concat(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "concat")?;
    let sep = match args.get(1) {
        None | Some(Value::Nil) => String::new(),
        Some(_) => interp.arg_str(&args, 1, "concat")?,
    };
    let len = table.borrow().len();
    let i = match args.get(2) {
        None | Some(Value::Nil) => 1i64,
        Some(_) => interp.arg_int(&args, 2, "concat")?,
    };
    let j = match args.get(3) {
        None | Some(Value::Nil) => len as i64,
        Some(_) => interp.arg_int(&args, 3, "concat")?,
    };
    let mut out = String::new();
    if i <= j {
        if j.saturating_sub(i) as u64 > 1_000_000 {
            return Err(interp.rt("range too large in 'concat'"));
        }
        for k in i..=j {
            let value = { table.borrow().get(&Value::Number(k as f64)) };
            match value {
                Value::Str(s) => out.push_str(&s),
                Value::Number(n) => out.push_str(&numfmt::number_to_string(n)),
                other => {
                    return Err(interp.rt(format!(
                        "invalid value (a {}) at index {} in table for 'concat'",
                        other.type_name(),
                        k
                    )))
                }
            }
            if k < j {
                out.push_str(&sep);
            }
            if out.len() > crate::interp::MAX_STRING_BYTES {
                return Err(interp.rt("resulting string too large in 'concat'"));
            }
        }
    }
    Ok(vec![interp.new_string(out)?])
}

fn merge_sort(interp: &mut Interp, items: Vec<Value>, cmp: Option<Value>) -> IResult<Vec<Value>> {
    let n = items.len();
    if n <= 1 {
        return Ok(items);
    }
    let mut buf = items;
    let mut tmp: Vec<Value> = vec![Value::Nil; n];
    let mut width = 1usize;
    while width < n {
        let mut start = 0usize;
        while start < n {
            let mid = (start + width).min(n);
            let end = (start + 2 * width).min(n);
            let (mut l, mut r, mut k) = (start, mid, start);
            while l < mid && r < end {
                let take_right = interp.sort_less(&buf[r], &buf[l], cmp.as_ref())?;
                if take_right {
                    tmp[k] = buf[r].clone();
                    r += 1;
                } else {
                    tmp[k] = buf[l].clone();
                    l += 1;
                }
                k += 1;
            }
            while l < mid {
                tmp[k] = buf[l].clone();
                l += 1;
                k += 1;
            }
            while r < end {
                tmp[k] = buf[r].clone();
                r += 1;
                k += 1;
            }
            start += 2 * width;
        }
        core::mem::swap(&mut buf, &mut tmp);
        width *= 2;
    }
    Ok(buf)
}

fn table_sort(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "sort")?;
    let cmp = match args.get(1) {
        None | Some(Value::Nil) => None,
        Some(v) => {
            if !matches!(v, Value::Function(_)) {
                return Err(interp.bad_arg(1, "sort", "function", v));
            }
            Some(v.clone())
        }
    };
    let (_len, items) = array_snapshot(&table);
    let sorted = merge_sort(interp, items, cmp)?;
    for (i, value) in sorted.into_iter().enumerate() {
        interp.set_table(&table, Value::Number((i + 1) as f64), value)?;
    }
    Ok(Vec::new())
}

fn table_len(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "len")?;
    let len = table.borrow().len();
    Ok(vec![Value::Number(len as f64)])
}

fn table_unpack(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = interp.arg_table(&args, 0, "unpack")?;
    let len = table.borrow().len();
    let i = match args.get(1) {
        None | Some(Value::Nil) => 1i64,
        Some(_) => interp.arg_int(&args, 1, "unpack")?,
    };
    let j = match args.get(2) {
        None | Some(Value::Nil) => len as i64,
        Some(_) => interp.arg_int(&args, 2, "unpack")?,
    };
    let mut out = Vec::new();
    if i <= j {
        if (j.saturating_sub(i)) as u64 > 1_000_000 {
            return Err(interp.rt("too many results to 'unpack'"));
        }
        for k in i..=j {
            out.push(table.borrow().get(&Value::Number(k as f64)));
        }
    }
    Ok(out)
}

fn table_pack(_interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let table = Rc::new(RefCell::new(Table::new()));
    let n = args.len();
    {
        let mut t = table.borrow_mut();
        for (i, value) in args.into_iter().enumerate() {
            t.set(Value::Number((i + 1) as f64), value);
        }
        t.set_str("n", Value::Number(n as f64));
    }
    Ok(vec![Value::Table(table)])
}
