//! The os library. getenv asks the host first, so the agent can supply a
//! controlled environment; without a host implementation it returns nil.

use crate::error::IResult;
use crate::interp::Interp;
use crate::value::{NativeFn, Value};

pub(crate) const FUNCS: &[(&str, NativeFn)] = &[
    ("time", os_time),
    ("clock", os_clock),
    ("getenv", os_getenv),
];

fn os_time(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    match args.first() {
        None | Some(Value::Nil) => {}
        Some(_) => {
            return Err(interp.rt("os.time with a table argument is not supported"));
        }
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as f64)
        .unwrap_or(0.0);
    Ok(vec![Value::Number(seconds)])
}

fn os_clock(interp: &mut Interp, _args: Vec<Value>) -> IResult<Vec<Value>> {
    Ok(vec![Value::Number(interp.elapsed_secs())])
}

fn os_getenv(interp: &mut Interp, args: Vec<Value>) -> IResult<Vec<Value>> {
    let name = interp.arg_str(&args, 0, "getenv")?;
    match interp.host.call("os.getenv", vec![Value::Str(name)]) {
        Ok(value) => Ok(vec![value]),
        Err(_) => Ok(vec![Value::Nil]),
    }
}
