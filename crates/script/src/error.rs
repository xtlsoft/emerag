//! Error type for emera script.

use core::fmt;

use crate::value::{tostring, Value};

/// What kind of failure a ScriptError describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The program could not be parsed.
    Syntax,
    /// A Lua-level runtime error (arithmetic on nil, bad argument, ...).
    Runtime,
    /// A safety limit was exceeded (instructions, wall clock, output, memory).
    Limit,
    /// A host callback failed or no host function exists.
    Host,
    /// A bug in emerag-script itself.
    Internal,
}

/// A parse or runtime error, with the source position that caused it.
///
/// Line numbers are 1-based; columns are 1-based and only meaningful for
/// syntax errors (runtime errors point at the statement being executed).
#[derive(Debug, Clone)]
pub struct ScriptError {
    pub kind: ErrorKind,
    pub message: String,
    pub line: u32,
    pub column: u32,
}

impl ScriptError {
    pub fn syntax(message: impl Into<String>, line: u32, column: u32) -> ScriptError {
        ScriptError {
            kind: ErrorKind::Syntax,
            message: message.into(),
            line,
            column,
        }
    }

    pub fn runtime(message: impl Into<String>, line: u32) -> ScriptError {
        ScriptError {
            kind: ErrorKind::Runtime,
            message: message.into(),
            line,
            column: 0,
        }
    }

    pub fn limit(message: impl Into<String>, line: u32) -> ScriptError {
        ScriptError {
            kind: ErrorKind::Limit,
            message: message.into(),
            line,
            column: 0,
        }
    }

    pub fn host(message: impl Into<String>, line: u32) -> ScriptError {
        ScriptError {
            kind: ErrorKind::Host,
            message: message.into(),
            line,
            column: 0,
        }
    }

    pub fn internal(message: impl Into<String>) -> ScriptError {
        ScriptError {
            kind: ErrorKind::Internal,
            message: message.into(),
            line: 0,
            column: 0,
        }
    }

    /// 1-based source line, or 0 when unknown.
    pub fn line(&self) -> u32 {
        self.line
    }
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Syntax => write!(
                f,
                "syntax error at line {}, column {}: {}",
                self.line, self.column, self.message
            ),
            ErrorKind::Runtime => {
                write!(f, "runtime error at line {}: {}", self.line, self.message)
            }
            ErrorKind::Limit => write!(
                f,
                "script limit exceeded at line {}: {}",
                self.line, self.message
            ),
            ErrorKind::Host => write!(f, "host error at line {}: {}", self.line, self.message),
            ErrorKind::Internal => write!(f, "internal script error: {}", self.message),
        }
    }
}

impl std::error::Error for ScriptError {}

/// Internal error carrier: a Lua error value (which pcall can catch) plus a
/// formatted error. Limit and internal failures are not catchable, otherwise a
/// script could retry forever after exhausting its budget.
#[derive(Debug, Clone)]
pub(crate) struct Fault {
    pub err: ScriptError,
    pub value: Value,
    pub catchable: bool,
}

impl Fault {
    /// A Lua error raised by the script (or by the stdlib) at line.
    pub fn lua(message: impl Into<String>, line: u32) -> Fault {
        let message = message.into();
        let value = Value::Str(format!("script:{line}: {message}"));
        Fault {
            err: ScriptError::runtime(message, line),
            value,
            catchable: true,
        }
    }

    /// A Lua error whose value is arbitrary (error with a table argument).
    pub fn lua_value(value: Value, line: u32) -> Fault {
        let message = tostring(&value);
        Fault {
            err: ScriptError::runtime(message, line),
            value,
            catchable: true,
        }
    }

    pub fn host(message: impl Into<String>, line: u32) -> Fault {
        let message = message.into();
        let value = Value::Str(format!("script:{line}: {message}"));
        Fault {
            err: ScriptError::host(message, line),
            value,
            catchable: true,
        }
    }

    /// Uncatchable: budget, recursion depth and internal errors.
    pub fn fatal(kind: ErrorKind, message: impl Into<String>, line: u32) -> Fault {
        let message = message.into();
        let err = ScriptError {
            kind,
            message: message.clone(),
            line,
            column: 0,
        };
        Fault {
            err,
            value: Value::Str(message),
            catchable: false,
        }
    }

    pub fn limit(message: impl Into<String>, line: u32) -> Fault {
        Fault::fatal(ErrorKind::Limit, message, line)
    }
}

pub(crate) type IResult<T> = core::result::Result<T, Fault>;
