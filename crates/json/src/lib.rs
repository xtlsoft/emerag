//! emerag-json - a compact, strict JSON implementation.
//!
//! Why not serde_json? emerag intentionally has zero third-party crates so it
//! can be built offline, on unusual architectures and with old toolchains.
//! This implementation is strict on input (RFC 8259), lenient on duplicate
//! keys (last wins), and preserves object key order so transcripts round-trip
//! byte-for-byte where possible.

mod parse;
mod ser;
mod value;

pub use parse::{parse, parse_bytes, parse_prefix};
pub use ser::{to_string, to_string_pretty, write_to};
pub use value::{Map, Number, Value};

pub type Result<T> = core::result::Result<T, crate::Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<Error> for emerag_util::Error {
    fn from(e: Error) -> Self {
        emerag_util::Error::new(e.message)
    }
}

/// Build a Value from Rust values.
impl From<()> for Value {
    fn from(_: ()) -> Self {
        Value::Null
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Number(Number::Int(v))
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Number(Number::Int(v as i64))
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Number(Number::Int(v as i64))
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        if v <= i64::MAX as u64 {
            Value::Number(Number::Int(v as i64))
        } else {
            Value::Number(Number::Float(v as f64))
        }
    }
}
impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Value::from(v as u64)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Number(Number::Float(v))
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::Array(v)
    }
}
impl From<Map> for Value {
    fn from(v: Map) -> Self {
        Value::Object(v)
    }
}

/// Construct Values with JSON-like syntax.
#[macro_export]
macro_rules! json {
    (null) => { $crate::Value::Null };
    (true) => { $crate::Value::Bool(true) };
    (false) => { $crate::Value::Bool(false) };
    ([$($v:tt),* $(,)?]) => {
        $crate::Value::Array(vec![$($crate::json!($v)),*])
    };
    ({$($k:tt : $v:tt),* $(,)?}) => {{
        let mut map = $crate::Map::new();
        $(map.insert(($k).to_string(), $crate::json!($v));)*
        $crate::Value::Object(map)
    }};
    ($e:expr) => { $crate::Value::from($e) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_builds_nested_values() {
        let v = json!({
            "a": 1,
            "b": [true, null, "x"],
            "c": {"d": 1.5}
        });
        assert_eq!(v["a"].as_i64(), Some(1));
        assert_eq!(v["b"][2].as_str(), Some("x"));
        assert_eq!(v["c"]["d"].as_f64(), Some(1.5));
        assert_eq!(
            to_string(&v),
            "{\"a\":1,\"b\":[true,null,\"x\"],\"c\":{\"d\":1.5}}"
        );
    }
}
