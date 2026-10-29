//! Lexer for emera script (Lua 5.4 subset).
//!
//! Produces a vector of tokens with 1-based line and column information so
//! every syntax error can point at the offending character.

use crate::error::ScriptError;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Tok {
    Eof,
    Name(String),
    Number(f64),
    Str(String),

    And,
    Break,
    Do,
    Else,
    Elseif,
    End,
    False,
    For,
    Function,
    If,
    In,
    Local,
    Nil,
    Not,
    Or,
    Repeat,
    Return,
    Then,
    True,
    Until,
    While,

    Plus,
    Minus,
    Star,
    Slash,
    DSlash,
    Percent,
    Caret,
    Hash,
    Eq,
    Ne,
    Le,
    Ge,
    Lt,
    Gt,
    Assign,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
    Colon,
    Comma,
    Dot,
    DotDot,
    Ellipsis,
}

impl Tok {
    pub(crate) fn describe(&self) -> String {
        match self {
            Tok::Eof => "end of file".to_string(),
            Tok::Name(n) => format!("'{n}'"),
            Tok::Number(_) => "a number".to_string(),
            Tok::Str(_) => "a string".to_string(),
            other => format!("'{}'", other.text()),
        }
    }

    fn text(&self) -> &'static str {
        match self {
            Tok::And => "and",
            Tok::Break => "break",
            Tok::Do => "do",
            Tok::Else => "else",
            Tok::Elseif => "elseif",
            Tok::End => "end",
            Tok::False => "false",
            Tok::For => "for",
            Tok::Function => "function",
            Tok::If => "if",
            Tok::In => "in",
            Tok::Local => "local",
            Tok::Nil => "nil",
            Tok::Not => "not",
            Tok::Or => "or",
            Tok::Repeat => "repeat",
            Tok::Return => "return",
            Tok::Then => "then",
            Tok::True => "true",
            Tok::Until => "until",
            Tok::While => "while",
            Tok::Plus => "+",
            Tok::Minus => "-",
            Tok::Star => "*",
            Tok::Slash => "/",
            Tok::DSlash => "//",
            Tok::Percent => "%",
            Tok::Caret => "^",
            Tok::Hash => "#",
            Tok::Eq => "==",
            Tok::Ne => "~=",
            Tok::Le => "<=",
            Tok::Ge => ">=",
            Tok::Lt => "<",
            Tok::Gt => ">",
            Tok::Assign => "=",
            Tok::LParen => "(",
            Tok::RParen => ")",
            Tok::LBrace => "{",
            Tok::RBrace => "}",
            Tok::LBracket => "[",
            Tok::RBracket => "]",
            Tok::Semi => ";",
            Tok::Colon => ":",
            Tok::Comma => ",",
            Tok::Dot => ".",
            Tok::DotDot => "..",
            Tok::Ellipsis => "...",
            Tok::Eof | Tok::Name(_) | Tok::Number(_) | Tok::Str(_) => "?",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub tok: Tok,
    pub line: u32,
    pub col: u32,
}

pub(crate) struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Lexer<'a> {
        Lexer {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, ScriptError> {
        let mut out = Vec::new();
        loop {
            let token = self.next_token()?;
            let eof = matches!(token.tok, Tok::Eof);
            out.push(token);
            if eof {
                return Ok(out);
            }
        }
    }

    fn err(&self, msg: impl Into<String>) -> ScriptError {
        ScriptError::syntax(msg, self.line, self.col)
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.src.get(self.pos + n).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        match b {
            b'\n' => {
                self.line += 1;
                self.col = 1;
            }
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.pos += 1;
                }
                self.line += 1;
                self.col = 1;
            }
            _ => self.col += 1,
        }
        Some(b)
    }

    fn next_token(&mut self) -> Result<Token, ScriptError> {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') | Some(11) | Some(12) => {
                    self.bump();
                }
                Some(b'-') if self.peek_at(1) == Some(b'-') => {
                    self.bump();
                    self.bump();
                    if self.peek_long_bracket().is_some() {
                        self.read_long_string()?;
                    } else {
                        while let Some(c) = self.peek() {
                            if c == b'\n' || c == b'\r' {
                                break;
                            }
                            self.bump();
                        }
                    }
                }
                _ => break,
            }
        }
        let line = self.line;
        let col = self.col;
        let tok = match self.peek() {
            None => Tok::Eof,
            Some(b) if b.is_ascii_digit() => Tok::Number(self.read_number()?),
            Some(b)
                if b == b'.' && self.peek_at(1).map(|c| c.is_ascii_digit()).unwrap_or(false) =>
            {
                Tok::Number(self.read_number()?)
            }
            Some(b) if b == b'"' || b == b'\'' => {
                self.bump();
                Tok::Str(self.read_quoted(b)?)
            }
            Some(b'[') if self.peek_long_bracket().is_some() => Tok::Str(self.read_long_string()?),
            Some(b) if b == b'_' || b.is_ascii_alphabetic() => {
                let start = self.pos;
                while let Some(c) = self.peek() {
                    if c == b'_' || c.is_ascii_alphanumeric() {
                        self.bump();
                    } else {
                        break;
                    }
                }
                let word = core::str::from_utf8(&self.src[start..self.pos])
                    .unwrap_or("")
                    .to_string();
                match word.as_str() {
                    "and" => Tok::And,
                    "break" => Tok::Break,
                    "do" => Tok::Do,
                    "else" => Tok::Else,
                    "elseif" => Tok::Elseif,
                    "end" => Tok::End,
                    "false" => Tok::False,
                    "for" => Tok::For,
                    "function" => Tok::Function,
                    "if" => Tok::If,
                    "in" => Tok::In,
                    "local" => Tok::Local,
                    "nil" => Tok::Nil,
                    "not" => Tok::Not,
                    "or" => Tok::Or,
                    "repeat" => Tok::Repeat,
                    "return" => Tok::Return,
                    "then" => Tok::Then,
                    "true" => Tok::True,
                    "until" => Tok::Until,
                    "while" => Tok::While,
                    _ => Tok::Name(word),
                }
            }
            Some(b) => {
                self.bump();
                match b {
                    b'+' => Tok::Plus,
                    b'-' => Tok::Minus,
                    b'*' => Tok::Star,
                    b'/' => {
                        if self.peek() == Some(b'/') {
                            self.bump();
                            Tok::DSlash
                        } else {
                            Tok::Slash
                        }
                    }
                    b'%' => Tok::Percent,
                    b'^' => Tok::Caret,
                    b'#' => Tok::Hash,
                    b'=' => {
                        if self.peek() == Some(b'=') {
                            self.bump();
                            Tok::Eq
                        } else {
                            Tok::Assign
                        }
                    }
                    b'~' => {
                        if self.peek() == Some(b'=') {
                            self.bump();
                            Tok::Ne
                        } else {
                            return Err(self.err(
                                "unexpected character '~' (bitwise operators are not supported)",
                            ));
                        }
                    }
                    b'<' => {
                        if self.peek() == Some(b'=') {
                            self.bump();
                            Tok::Le
                        } else {
                            Tok::Lt
                        }
                    }
                    b'>' => {
                        if self.peek() == Some(b'=') {
                            self.bump();
                            Tok::Ge
                        } else {
                            Tok::Gt
                        }
                    }
                    b'(' => Tok::LParen,
                    b')' => Tok::RParen,
                    b'{' => Tok::LBrace,
                    b'}' => Tok::RBrace,
                    b'[' => Tok::LBracket,
                    b']' => Tok::RBracket,
                    b';' => Tok::Semi,
                    b':' => {
                        if self.peek() == Some(b':') {
                            self.bump();
                            return Err(self.err("labels ('::') are not supported"));
                        }
                        Tok::Colon
                    }
                    b',' => Tok::Comma,
                    b'.' => {
                        if self.peek() == Some(b'.') {
                            self.bump();
                            if self.peek() == Some(b'.') {
                                self.bump();
                                Tok::Ellipsis
                            } else {
                                Tok::DotDot
                            }
                        } else {
                            Tok::Dot
                        }
                    }
                    other => {
                        return Err(ScriptError::syntax(
                            format!(
                                "unexpected character '{}'",
                                (other as char).escape_default()
                            ),
                            line,
                            col,
                        ))
                    }
                }
            }
        };
        Ok(Token { tok, line, col })
    }

    /// If the input at the current position starts a long bracket, return its
    /// level (number of '=' characters) without consuming anything.
    fn peek_long_bracket(&self) -> Option<usize> {
        if self.peek() != Some(b'[') {
            return None;
        }
        let mut n = 1;
        while self.peek_at(n) == Some(b'=') {
            n += 1;
        }
        if self.peek_at(n) == Some(b'[') {
            Some(n - 1)
        } else {
            None
        }
    }

    fn read_long_string(&mut self) -> Result<String, ScriptError> {
        let level = match self.peek_long_bracket() {
            Some(l) => l,
            None => return Err(self.err("malformed long string")),
        };
        for _ in 0..level + 2 {
            self.bump();
        }
        let start = self.pos;
        // A newline immediately after the opening bracket is skipped.
        if self.peek() == Some(b'\n') || self.peek() == Some(b'\r') {
            self.bump();
        }
        let content_start = self.pos;
        loop {
            match self.peek() {
                None => {
                    return Err(ScriptError::syntax(
                        "unfinished long string",
                        self.line,
                        self.col,
                    ))
                }
                Some(b']') => {
                    let mut n = 1;
                    while self.peek_at(n) == Some(b'=') {
                        n += 1;
                    }
                    if n - 1 == level && self.peek_at(n) == Some(b']') {
                        let text = core::str::from_utf8(&self.src[content_start..self.pos])
                            .map_err(|_| self.err("invalid UTF-8 in long string"))?
                            .to_string();
                        for _ in 0..=n {
                            self.bump();
                        }
                        let _ = start;
                        return Ok(text);
                    }
                    self.bump();
                }
                Some(_) => {
                    self.bump();
                }
            }
        }
    }

    fn read_quoted(&mut self, quote: u8) -> Result<String, ScriptError> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let b = match self.bump() {
                Some(b) => b,
                None => return Err(self.err("unfinished string")),
            };
            if b == quote {
                break;
            }
            match b {
                b'\n' | b'\r' => {
                    return Err(ScriptError::syntax(
                        "unfinished string",
                        self.line.saturating_sub(1),
                        1,
                    ))
                }
                b'\\' => self.read_escape(&mut buf)?,
                _ => buf.push(b),
            }
        }
        String::from_utf8(buf).map_err(|_| self.err("string literal is not valid UTF-8"))
    }

    fn read_escape(&mut self, buf: &mut Vec<u8>) -> Result<(), ScriptError> {
        let e = match self.bump() {
            Some(e) => e,
            None => return Err(self.err("unfinished string")),
        };
        match e {
            b'a' => buf.push(7),
            b'b' => buf.push(8),
            b'f' => buf.push(12),
            b'n' => buf.push(b'\n'),
            b'r' => buf.push(b'\r'),
            b't' => buf.push(b'\t'),
            b'v' => buf.push(11),
            b'\\' => buf.push(b'\\'),
            b'"' => buf.push(b'"'),
            b'\'' => buf.push(b'\''),
            b'\n' | b'\r' => buf.push(b'\n'),
            b'x' => {
                let mut v: u32 = 0;
                for _ in 0..2 {
                    let c = self
                        .peek()
                        .ok_or_else(|| self.err("unfinished \\x escape"))?;
                    let d = (c as char)
                        .to_digit(16)
                        .ok_or_else(|| self.err("hexadecimal digit expected"))?;
                    self.bump();
                    v = v * 16 + d;
                }
                buf.push(v as u8);
            }
            b'z' => {
                while let Some(c) = self.peek() {
                    if c.is_ascii_whitespace() {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
            b'u' => {
                if self.peek() != Some(b'{') {
                    return Err(self.err("missing '{' in \\u{xxxx}"));
                }
                self.bump();
                let mut v: u32 = 0;
                let mut n = 0;
                loop {
                    let c = self
                        .peek()
                        .ok_or_else(|| self.err("unfinished \\u escape"))?;
                    if c == b'}' {
                        self.bump();
                        break;
                    }
                    let d = (c as char)
                        .to_digit(16)
                        .ok_or_else(|| self.err("hexadecimal digit expected"))?;
                    self.bump();
                    n += 1;
                    if n > 6 {
                        return Err(self.err("\\u escape too long"));
                    }
                    v = v.saturating_mul(16).saturating_add(d);
                }
                let ch = char::from_u32(v).ok_or_else(|| self.err("invalid Unicode code point"))?;
                let mut tmp = [0u8; 4];
                buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
            }
            b'0'..=b'9' => {
                let mut v: u32 = (e - b'0') as u32;
                for _ in 0..2 {
                    match self.peek() {
                        Some(c) if c.is_ascii_digit() => {
                            v = v * 10 + (c - b'0') as u32;
                            self.bump();
                        }
                        _ => break,
                    }
                }
                if v > 255 {
                    return Err(self.err("decimal escape too large"));
                }
                buf.push(v as u8);
            }
            other => {
                return Err(self.err(format!(
                    "invalid escape sequence '\\{}'",
                    (other as char).escape_default()
                )))
            }
        }
        Ok(())
    }

    fn read_number(&mut self) -> Result<f64, ScriptError> {
        let start = self.pos;
        let hex = self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'x') | Some(b'X'));
        if hex {
            self.bump();
            self.bump();
            let mut digits = 0;
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    self.bump();
                    digits += 1;
                } else {
                    break;
                }
            }
            if self.peek() == Some(b'.') {
                self.bump();
                while let Some(c) = self.peek() {
                    if c.is_ascii_hexdigit() {
                        self.bump();
                        digits += 1;
                    } else {
                        break;
                    }
                }
            }
            if digits == 0 {
                return Err(self.err("malformed number"));
            }
            if matches!(self.peek(), Some(b'p') | Some(b'P')) {
                self.bump();
                if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                    self.bump();
                }
                let mut exp_digits = 0;
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        self.bump();
                        exp_digits += 1;
                    } else {
                        break;
                    }
                }
                if exp_digits == 0 {
                    return Err(self.err("malformed number"));
                }
            }
        } else {
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    self.bump();
                } else {
                    break;
                }
            }
            if self.peek() == Some(b'.') {
                self.bump();
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
            if matches!(self.peek(), Some(b'e') | Some(b'E')) {
                self.bump();
                if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                    self.bump();
                }
                let mut exp_digits = 0;
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        self.bump();
                        exp_digits += 1;
                    } else {
                        break;
                    }
                }
                if exp_digits == 0 {
                    return Err(self.err("malformed number"));
                }
            }
        }
        if let Some(c) = self.peek() {
            if c == b'_' || c.is_ascii_alphanumeric() {
                return Err(self.err("malformed number"));
            }
        }
        let text = core::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        if hex {
            crate::numfmt::parse_hex_float(text).ok_or_else(|| self.err("malformed number"))
        } else {
            text.parse::<f64>()
                .map_err(|_| self.err("malformed number"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        Lexer::new(src)
            .tokenize()
            .expect("lex")
            .into_iter()
            .map(|t| t.tok)
            .collect()
    }

    #[test]
    fn numbers() {
        assert_eq!(
            toks("1 2.5 1e3 .5 0xff 0x1p4 0x1.8p1"),
            vec![
                Tok::Number(1.0),
                Tok::Number(2.5),
                Tok::Number(1000.0),
                Tok::Number(0.5),
                Tok::Number(255.0),
                Tok::Number(16.0),
                Tok::Number(3.0),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(
            toks(r#"'a\nb' "\x41" '\65'"#),
            vec![
                Tok::Str("a\nb".into()),
                Tok::Str("A".into()),
                Tok::Str("A".into()),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn long_strings_skip_first_newline() {
        assert_eq!(toks("[[\nhi]]"), vec![Tok::Str("hi".into()), Tok::Eof]);
        assert_eq!(
            toks("[==[a]]b]==]"),
            vec![Tok::Str("a]]b".into()), Tok::Eof]
        );
    }

    #[test]
    fn comments() {
        assert_eq!(
            toks("a --[[ multi\nline ]] b"),
            vec![Tok::Name("a".into()), Tok::Name("b".into()), Tok::Eof]
        );
        assert_eq!(
            toks("a -- one\nb"),
            vec![Tok::Name("a".into()), Tok::Name("b".into()), Tok::Eof]
        );
    }

    #[test]
    fn error_positions() {
        let err = Lexer::new("x = 1\ny = @").tokenize().unwrap_err();
        assert_eq!(err.line, 2);
        assert_eq!(err.column, 5);
        assert!(err.message.contains("unexpected character"));
    }

    #[test]
    fn malformed_numbers_rejected() {
        assert!(Lexer::new("3a").tokenize().is_err());
        assert!(Lexer::new("0x").tokenize().is_err());
        assert!(Lexer::new("1e").tokenize().is_err());
    }
}
