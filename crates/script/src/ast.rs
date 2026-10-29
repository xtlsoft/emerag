//! AST for emera script.
//!
//! Variables are resolved lexically at parse time into local slots, upvalue
//! indices or global names, exactly like Lua's compiler does. That keeps the
//! interpreter free of environment chains and makes upvalue semantics (shared,
//! mutable captures) correct by construction.

use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    IDiv,
    Mod,
    Pow,
    Concat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnOp {
    Neg,
    Not,
    Len,
}

#[derive(Debug)]
pub(crate) enum VarRef {
    Local(usize),
    Upval(usize),
    Global(String),
}

#[derive(Debug)]
pub(crate) struct Expr {
    pub kind: ExprKind,
}

impl Expr {
    pub fn new(kind: ExprKind) -> Expr {
        Expr { kind }
    }
}

#[derive(Debug)]
pub(crate) enum ExprKind {
    Nil,
    True,
    False,
    Number(f64),
    Str(String),
    Var(VarRef),
    /// base[key]
    Index(Box<Expr>, Box<Expr>),
    /// callee(args...) -- the callee is any expression.
    Call(Box<Expr>, Vec<Expr>),
    /// obj:name(args...)
    Method(Box<Expr>, String, Vec<Expr>),
    /// function body
    Function(Rc<Proto>),
    /// table constructor
    Table(Vec<Field>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
    Un(UnOp, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Vararg,
    /// (expr): truncates multiple results to one value, like Lua.
    Paren(Box<Expr>),
}

#[derive(Debug)]
pub(crate) enum Field {
    Array(Expr),
    Keyed(Expr, Expr),
}

#[derive(Debug)]
pub(crate) struct Stmt {
    pub line: u32,
    pub kind: StmtKind,
}

#[derive(Debug)]
pub(crate) enum StmtKind {
    /// local a, b = ...
    Local {
        slots: Vec<usize>,
        exprs: Vec<Expr>,
    },
    /// a, b.c, d[e] = ...
    Assign {
        targets: Vec<Expr>,
        exprs: Vec<Expr>,
    },
    /// a function call used as a statement
    Call(Expr),
    Do(Vec<Stmt>),
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    Repeat {
        body: Vec<Stmt>,
        cond: Expr,
    },
    If {
        arms: Vec<(Expr, Vec<Stmt>)>,
        els: Option<Vec<Stmt>>,
    },
    /// for var = start, end [, step] do body end
    NumFor {
        var: usize,
        start: Expr,
        end: Expr,
        step: Option<Expr>,
        body: Vec<Stmt>,
    },
    /// for a, b in exprs do body end
    GenFor {
        vars: Vec<usize>,
        exprs: Vec<Expr>,
        body: Vec<Stmt>,
    },
    Return(Vec<Expr>),
    Break,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UpvalDesc {
    /// true: capture the enclosing frame's local slot; false: its upvalue.
    pub in_stack: bool,
    pub index: usize,
}

/// A compiled function (or the main chunk).
#[derive(Debug)]
pub(crate) struct Proto {
    pub name: String,
    pub params: Vec<String>,
    pub is_vararg: bool,
    pub body: Vec<Stmt>,
    pub max_slots: usize,
    /// captured[i] is true when local slot i is ever captured by a closure.
    pub captured: Vec<bool>,
    pub upvals: Vec<UpvalDesc>,
}
