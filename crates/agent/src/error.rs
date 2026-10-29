//! Agent errors with actionable messages.

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentError {
    pub message: String,
}

impl AgentError {
    pub fn new(message: impl Into<String>) -> Self {
        AgentError {
            message: message.into(),
        }
    }
    pub fn context(mut self, ctx: impl fmt::Display) -> Self {
        self.message = format!("{ctx}: {}", self.message);
        self
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentError {}

impl From<String> for AgentError {
    fn from(s: String) -> Self {
        AgentError::new(s)
    }
}

impl From<&str> for AgentError {
    fn from(s: &str) -> Self {
        AgentError::new(s)
    }
}

impl From<emerag_util::Error> for AgentError {
    fn from(e: emerag_util::Error) -> Self {
        AgentError::new(e.into_message())
    }
}

impl From<emerag_llm::Error> for AgentError {
    fn from(e: emerag_llm::Error) -> Self {
        AgentError::new(format!("{e} ({})", e.hint()))
    }
}

impl From<emerag_mcp::Error> for AgentError {
    fn from(e: emerag_mcp::Error) -> Self {
        AgentError::new(e.message)
    }
}

pub type Result<T> = core::result::Result<T, AgentError>;

#[macro_export]
macro_rules! bail_agent {
    ($($arg:tt)*) => {
        return Err($crate::error::AgentError::new(format!($($arg)*)))
    };
}
