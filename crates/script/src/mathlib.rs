//! The math library. Everything is deterministic except math.randomseed's
//! default, which starts from a fixed constant so runs are reproducible.

use crate::error::IResult;
use crate::interp::Interp;
use crate::value::{NativeFn, Value};

pub(crate) const FUNCS: &[(&str, NativeFn)] = &[
    ("abs", math_abs),
    ("ceil", math_ceil),
    ("floor", math_floor),
    ("sqrt", math_sqrt),
    ("min", math_min),
    ("max", math_max),
    ("random", math_random),
    ("randomseed", math_randomseed),
    ("type", math_type),
    ("tointeger", math_tointeger),
    ("fmod", math_fmod),
    ("pow", math_pow),
];

fn unary(
    interp: &mut Interp,
    args: Vec<Value>,
    name: &str,
    f: fn(f64) -> f64,
) -> IResult<Vec<Value>> {
    let n = interp.arg_number(&args, 0, name)?;
    Ok(vec![Value::Number(f(n))])
}

fn math_abs(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    unary(interp, args, "abs", f64::abs)
}

fn math_ceil(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    unary(interp, args, "ceil", f64::ceil)
}

fn math_floor(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    unary(interp, args, "floor", f64::floor)
}

fn math_sqrt(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    unary(interp, args, "sqrt", f64::sqrt)
}

fn math_min(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    if args.is_empty() {
        return Err(interp.rt("bad argument #1 to 'min' (value expected)"));
    }
    let mut best = interp.arg_number(&args, 0, "min")?;
    for i in 1..args.len() {
        let n = interp.arg_number(&args, i, "min")?;
        if n < best {
            best = n;
        }
    }
    Ok(vec![Value::Number(best)])
}

fn math_max(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    if args.is_empty() {
        return Err(interp.rt("bad argument #1 to 'max' (value expected)"));
    }
    let mut best = interp.arg_number(&args, 0, "max")?;
    for i in 1..args.len() {
        let n = interp.arg_number(&args, i, "max")?;
        if n > best {
            best = n;
        }
    }
    Ok(vec![Value::Number(best)])
}

fn math_random(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    match args.len() {
        0 => Ok(vec![Value::Number(interp.next_random())]),
        1 => {
            let upper = interp.arg_int(&args, 0, "random")?;
            if upper < 1 {
                return Err(interp.rt("bad argument #1 to 'random' (interval is empty)"));
            }
            let r = interp.next_random();
            Ok(vec![Value::Number((r * upper as f64).floor() + 1.0)])
        }
        _ => {
            let lower = interp.arg_int(&args, 0, "random")?;
            let upper = interp.arg_int(&args, 1, "random")?;
            if lower > upper {
                return Err(interp.rt("bad argument #2 to 'random' (interval is empty)"));
            }
            let span = (upper - lower + 1) as f64;
            let r = interp.next_random();
            Ok(vec![Value::Number(lower as f64 + (r * span).floor())])
        }
    }
}

fn math_randomseed(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let seed = match args.first() {
        None | Some(Value::Nil) => 0,
        Some(_) => interp.arg_int(&args, 0, "randomseed")? as u64,
    };
    interp.seed_random(seed);
    Ok(Vec::new())
}

fn math_type(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let value = interp.arg(&args, 0);
    Ok(vec![match value {
        Value::Number(n) => {
            if n.fract() == 0.0 && n.is_finite() {
                Value::Str("integer".to_string())
            } else {
                Value::Str("float".to_string())
            }
        }
        _ => Value::Nil,
    }])
}

fn math_tointeger(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    match interp.arg(&args, 0) {
        Value::Number(n) if n.fract() == 0.0 && n.is_finite() => Ok(vec![Value::Number(n)]),
        _ => Ok(vec![Value::Nil]),
    }
}

fn math_fmod(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let a = interp.arg_number(&args, 0, "fmod")?;
    let b = interp.arg_number(&args, 1, "fmod")?;
    Ok(vec![Value::Number(a % b)])
}

fn math_pow(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let a = interp.arg_number(&args, 0, "pow")?;
    let b = interp.arg_number(&args, 1, "pow")?;
    Ok(vec![Value::Number(a.powf(b))])
}
