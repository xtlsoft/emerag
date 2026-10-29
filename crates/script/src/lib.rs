//! emerag-script -- "emera script", a small Lua 5.4 subset in pure Rust.
//!
//! This is the emergency fallback for machines whose shells are broken: the
//! model writes a short script and emerag runs it in-process with a hard
//! instruction budget and no access to the operating system unless the host
//! grants it through Host.
//!
//! Example:
//!
//!     use emerag_script::{run, Host, Limits, Value};
//!
//!     struct Quiet;
//!     impl Host for Quiet {
//!         fn call(&mut self, name: &str, _args: Vec<Value>) -> emerag_script::Result<Value> {
//!             Err(emerag_script::ScriptError::host(format!("no such host function: {name}"), 0))
//!         }
//!         fn print(&mut self, text: &str) {
//!             print!("{text}");
//!         }
//!     }
//!
//!     let mut host = Quiet;
//!     let value = run("local t = {1, 2, 3} local s = 0 for _, v in ipairs(t) do s = s + v end return s",
//!         &mut host, Limits::default()).unwrap();
//!     assert_eq!(value, Value::Number(6.0));

#![deny(unsafe_code)]
#![forbid(unsafe_op_in_unsafe_fn)]

mod ast;
mod error;
mod interp;
mod lexer;
mod mathlib;
mod numfmt;
mod oslib;
mod parser;
mod pattern;
mod stdlib;
mod strlib;
mod tablelib;
mod value;

#[cfg(test)]
mod tests;

pub use error::{ErrorKind, ScriptError};
pub use value::{tostring, Function, Table, Value};

/// Result type used throughout the crate.
pub type Result<T> = core::result::Result<T, ScriptError>;

/// Execution limits. A zero field means "no limit" for that dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Deterministic step budget (statements, calls and loop iterations).
    pub max_instructions: u64,
    /// Maximum bytes written through Host::print (0 = unlimited).
    pub max_output_bytes: usize,
    /// Wall clock budget in milliseconds (0 = unlimited).
    pub wall_clock_ms: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_instructions: 2_000_000,
            max_output_bytes: 1 << 20,
            wall_clock_ms: 30_000,
        }
    }
}

impl Limits {
    /// No limits at all. Only use this for trusted scripts.
    pub fn unlimited() -> Limits {
        Limits {
            max_instructions: 0,
            max_output_bytes: 0,
            wall_clock_ms: 0,
        }
    }
}

/// Everything the outside world provides to a script.
///
/// call receives the dotted function name: stdlib namespaces such as
/// "os.getenv", host namespaces (io, fs, proc, net) and any global the script
/// calls that the stdlib does not define. Returning Err raises a Lua error
/// that pcall can catch.
pub trait Host {
    fn call(&mut self, name: &str, args: Vec<Value>) -> Result<Value>;
    fn print(&mut self, text: &str);
}

/// Parse and run a chunk, returning its first return value (or Nil).
pub fn run(source: &str, host: &mut dyn Host, limits: Limits) -> Result<Value> {
    let proto = parser::parse(source)?;
    let mut interp = interp::Interp::new(host, limits);
    interp.run_chunk(proto)
}
