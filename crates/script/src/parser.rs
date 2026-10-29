//! Recursive-descent parser for emera script.
//!
//! Mirrors Lua's grammar and operator precedence. Variables are resolved to
//! local slots, upvalue indices or global names while parsing, so closures can
//! be created by simply capturing the right slots at runtime.

use std::rc::Rc;

use crate::ast::*;
use crate::error::ScriptError;
use crate::lexer::{Lexer, Tok, Token};

const MAX_DEPTH: usize = 400;
const MAX_CHAIN: usize = 2000;

pub(crate) fn parse(src: &str) -> Result<Rc<Proto>, ScriptError> {
    let tokens = Lexer::new(src).tokenize()?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        funcs: Vec::new(),
        depth: 0,
    };
    parser.parse_chunk()
}

struct LocalDef {
    name: String,
    slot: usize,
    captured: bool,
}

struct Block {
    base: usize,
    locals: Vec<LocalDef>,
}

struct FuncState {
    upvals: Vec<(String, UpvalDesc)>,
    blocks: Vec<Block>,
    nslots: usize,
    max_slots: usize,
    captured: Vec<bool>,
    is_vararg: bool,
    loop_depth: usize,
}

impl FuncState {
    fn new(is_vararg: bool) -> FuncState {
        FuncState {
            upvals: Vec::new(),
            blocks: vec![Block {
                base: 0,
                locals: Vec::new(),
            }],
            nslots: 0,
            max_slots: 0,
            captured: Vec::new(),
            is_vararg,
            loop_depth: 0,
        }
    }

    fn find_local(&self, name: &str) -> Option<usize> {
        for block in self.blocks.iter().rev() {
            for local in block.locals.iter().rev() {
                if local.name == name {
                    return Some(local.slot);
                }
            }
        }
        None
    }

    fn find_upval(&self, name: &str) -> Option<usize> {
        self.upvals.iter().position(|(n, _)| n == name)
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    funcs: Vec<FuncState>,
    depth: usize,
}

impl Parser {
    // ---- token helpers -------------------------------------------------

    fn tok(&self) -> &Tok {
        match self.tokens.get(self.pos) {
            Some(t) => &t.tok,
            None => &Tok::Eof,
        }
    }

    fn tok_at(&self, off: usize) -> &Tok {
        match self.tokens.get(self.pos + off) {
            Some(t) => &t.tok,
            None => &Tok::Eof,
        }
    }

    fn line(&self) -> u32 {
        self.tokens.get(self.pos).map(|t| t.line).unwrap_or(0)
    }

    fn col(&self) -> u32 {
        self.tokens.get(self.pos).map(|t| t.col).unwrap_or(0)
    }

    fn err(&self, msg: impl Into<String>) -> ScriptError {
        ScriptError::syntax(msg, self.line(), self.col())
    }

    fn advance(&mut self) {
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        } else if self.pos < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn check(&self, t: &Tok) -> bool {
        core::mem::discriminant(self.tok()) == core::mem::discriminant(t)
    }

    fn accept(&mut self, t: &Tok) -> bool {
        if self.check(t) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok) -> Result<(), ScriptError> {
        if self.accept(t) {
            Ok(())
        } else {
            Err(self.err(format!(
                "expected {} near {}",
                t.describe(),
                self.tok().describe()
            )))
        }
    }

    fn expect_name(&mut self) -> Result<String, ScriptError> {
        if let Tok::Name(n) = self.tok() {
            let n = n.clone();
            self.advance();
            Ok(n)
        } else {
            Err(self.err(format!("expected a name near {}", self.tok().describe())))
        }
    }

    fn block_follows(&self) -> bool {
        matches!(
            self.tok(),
            Tok::End | Tok::Else | Tok::Elseif | Tok::Until | Tok::Eof
        )
    }

    fn enter(&mut self) -> Result<(), ScriptError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err("expression nesting too deep"));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    // ---- scopes --------------------------------------------------------

    fn cur(&self) -> &FuncState {
        &self.funcs[self.funcs.len() - 1]
    }

    fn cur_mut(&mut self) -> &mut FuncState {
        let n = self.funcs.len();
        &mut self.funcs[n - 1]
    }

    fn open_block(&mut self) {
        let base = self.cur().nslots;
        self.cur_mut().blocks.push(Block {
            base,
            locals: Vec::new(),
        });
    }

    fn close_block(&mut self) {
        if let Some(block) = self.cur_mut().blocks.pop() {
            self.cur_mut().nslots = block.base;
        }
    }

    fn declare_local(&mut self, name: &str) -> usize {
        let fs = self.cur_mut();
        let slot = fs.nslots;
        fs.nslots += 1;
        if fs.max_slots < fs.nslots {
            fs.max_slots = fs.nslots;
        }
        if fs.captured.len() < fs.max_slots {
            fs.captured.resize(fs.max_slots, false);
        }
        if let Some(block) = fs.blocks.last_mut() {
            block.locals.push(LocalDef {
                name: name.to_string(),
                slot,
                captured: false,
            });
        }
        slot
    }

    fn mark_captured(&mut self, fi: usize, slot: usize) {
        if let Some(fs) = self.funcs.get_mut(fi) {
            if fs.captured.len() <= slot {
                fs.captured.resize(slot + 1, false);
            }
            fs.captured[slot] = true;
            for block in fs.blocks.iter_mut() {
                for local in block.locals.iter_mut() {
                    if local.slot == slot {
                        local.captured = true;
                    }
                }
            }
        }
    }

    fn resolve_upval(&mut self, fi: usize, name: &str) -> Option<usize> {
        if let Some(idx) = self.funcs.get(fi).and_then(|fs| fs.find_upval(name)) {
            return Some(idx);
        }
        if fi == 0 {
            return None;
        }
        let parent_slot = self.funcs.get(fi - 1).and_then(|fs| fs.find_local(name));
        if let Some(slot) = parent_slot {
            self.mark_captured(fi - 1, slot);
            if let Some(fs) = self.funcs.get_mut(fi) {
                let idx = fs.upvals.len();
                fs.upvals.push((
                    name.to_string(),
                    UpvalDesc {
                        in_stack: true,
                        index: slot,
                    },
                ));
                return Some(idx);
            }
            return None;
        }
        if fi >= 2 {
            if let Some(parent_up) = self.resolve_upval(fi - 1, name) {
                if let Some(fs) = self.funcs.get_mut(fi) {
                    let idx = fs.upvals.len();
                    fs.upvals.push((
                        name.to_string(),
                        UpvalDesc {
                            in_stack: false,
                            index: parent_up,
                        },
                    ));
                    return Some(idx);
                }
            }
        }
        None
    }

    fn resolve_var(&mut self, name: &str) -> VarRef {
        let fi = self.funcs.len() - 1;
        if let Some(slot) = self.funcs.get(fi).and_then(|fs| fs.find_local(name)) {
            return VarRef::Local(slot);
        }
        if fi > 0 {
            if let Some(idx) = self.resolve_upval(fi, name) {
                return VarRef::Upval(idx);
            }
        }
        VarRef::Global(name.to_string())
    }

    fn build_proto(
        &mut self,
        name: &str,
        params: Vec<String>,
        is_vararg: bool,
        body: Vec<Stmt>,
    ) -> Rc<Proto> {
        let fs = match self.funcs.pop() {
            Some(fs) => fs,
            None => FuncState::new(is_vararg),
        };
        Rc::new(Proto {
            name: name.to_string(),
            params,
            is_vararg,
            body,
            max_slots: fs.max_slots.max(1),
            captured: fs.captured,
            upvals: fs.upvals.into_iter().map(|(_, d)| d).collect(),
        })
    }

    // ---- chunks and blocks ---------------------------------------------

    fn parse_chunk(&mut self) -> Result<Rc<Proto>, ScriptError> {
        self.funcs.push(FuncState::new(true));
        let line = self.line();
        let body = self.parse_block()?;
        if !matches!(self.tok(), Tok::Eof) {
            return Err(self.err(format!(
                "unexpected {} after end of chunk",
                self.tok().describe()
            )));
        }
        let _ = line;
        Ok(self.build_proto("main chunk", Vec::new(), true, body))
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, ScriptError> {
        let mut stmts = Vec::new();
        loop {
            match self.tok() {
                Tok::End | Tok::Else | Tok::Elseif | Tok::Until | Tok::Eof => break,
                Tok::Semi => {
                    self.advance();
                }
                Tok::Return => {
                    let line = self.line();
                    self.advance();
                    let exprs = if self.block_follows() || self.check(&Tok::Semi) {
                        Vec::new()
                    } else {
                        self.parse_expr_list()?
                    };
                    let _ = self.accept(&Tok::Semi);
                    stmts.push(Stmt {
                        line,
                        kind: StmtKind::Return(exprs),
                    });
                    break;
                }
                _ => {
                    let stmt = self.parse_stmt()?;
                    stmts.push(stmt);
                }
            }
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ScriptError> {
        let line = self.line();
        match self.tok().clone() {
            Tok::Local => {
                self.advance();
                if self.accept(&Tok::Function) {
                    let name = self.expect_name()?;
                    let slot = self.declare_local(&name);
                    let proto = self.parse_funcbody(name.clone(), false, line)?;
                    Ok(Stmt {
                        line,
                        kind: StmtKind::Local {
                            slots: vec![slot],
                            exprs: vec![Expr::new(ExprKind::Function(proto))],
                        },
                    })
                } else {
                    let mut names = Vec::new();
                    loop {
                        let name = self.expect_name()?;
                        // Lua 5.4 attributes <const>/<close> are accepted and ignored.
                        if self.check(&Tok::Lt) {
                            self.advance();
                            let _ = self.expect_name()?;
                            self.expect(&Tok::Gt)?;
                        }
                        names.push(name);
                        if !self.accept(&Tok::Comma) {
                            break;
                        }
                    }
                    let exprs = if self.accept(&Tok::Assign) {
                        self.parse_expr_list()?
                    } else {
                        Vec::new()
                    };
                    let slots = names.iter().map(|n| self.declare_local(n)).collect();
                    Ok(Stmt {
                        line,
                        kind: StmtKind::Local { slots, exprs },
                    })
                }
            }
            Tok::Function => {
                self.advance();
                let base = self.expect_name()?;
                let mut target = Expr::new(ExprKind::Var(self.resolve_var(&base)));
                let mut name = base;
                let mut is_method = false;
                loop {
                    if self.accept(&Tok::Dot) {
                        let field = self.expect_name()?;
                        name = format!("{name}.{field}");
                        let key = Expr::new(ExprKind::Str(field));
                        target = Expr::new(ExprKind::Index(Box::new(target), Box::new(key)));
                    } else if self.accept(&Tok::Colon) {
                        let field = self.expect_name()?;
                        name = format!("{name}:{field}");
                        let key = Expr::new(ExprKind::Str(field));
                        target = Expr::new(ExprKind::Index(Box::new(target), Box::new(key)));
                        is_method = true;
                        break;
                    } else {
                        break;
                    }
                }
                let proto = self.parse_funcbody(name, is_method, line)?;
                Ok(Stmt {
                    line,
                    kind: StmtKind::Assign {
                        targets: vec![target],
                        exprs: vec![Expr::new(ExprKind::Function(proto))],
                    },
                })
            }
            Tok::Do => {
                self.advance();
                self.open_block();
                let body = self.parse_block()?;
                self.close_block();
                self.expect(&Tok::End)?;
                Ok(Stmt {
                    line,
                    kind: StmtKind::Do(body),
                })
            }
            Tok::While => {
                self.advance();
                let cond = self.parse_expr()?;
                self.expect(&Tok::Do)?;
                self.open_block();
                self.cur_mut().loop_depth += 1;
                let body = self.parse_block()?;
                self.cur_mut().loop_depth -= 1;
                self.close_block();
                self.expect(&Tok::End)?;
                Ok(Stmt {
                    line,
                    kind: StmtKind::While { cond, body },
                })
            }
            Tok::Repeat => {
                self.advance();
                self.open_block();
                self.cur_mut().loop_depth += 1;
                let body = self.parse_block()?;
                self.cur_mut().loop_depth -= 1;
                self.expect(&Tok::Until)?;
                let cond = self.parse_expr()?;
                self.close_block();
                Ok(Stmt {
                    line,
                    kind: StmtKind::Repeat { body, cond },
                })
            }
            Tok::If => {
                self.advance();
                let mut arms = Vec::new();
                let cond = self.parse_expr()?;
                self.expect(&Tok::Then)?;
                self.open_block();
                let body = self.parse_block()?;
                self.close_block();
                arms.push((cond, body));
                while self.accept(&Tok::Elseif) {
                    let cond = self.parse_expr()?;
                    self.expect(&Tok::Then)?;
                    self.open_block();
                    let body = self.parse_block()?;
                    self.close_block();
                    arms.push((cond, body));
                }
                let els = if self.accept(&Tok::Else) {
                    self.open_block();
                    let body = self.parse_block()?;
                    self.close_block();
                    Some(body)
                } else {
                    None
                };
                self.expect(&Tok::End)?;
                Ok(Stmt {
                    line,
                    kind: StmtKind::If { arms, els },
                })
            }
            Tok::For => {
                self.advance();
                let first = self.expect_name()?;
                if self.accept(&Tok::Assign) {
                    let start = self.parse_expr()?;
                    self.expect(&Tok::Comma)?;
                    let end = self.parse_expr()?;
                    let step = if self.accept(&Tok::Comma) {
                        Some(self.parse_expr()?)
                    } else {
                        None
                    };
                    self.expect(&Tok::Do)?;
                    self.open_block();
                    let var = self.declare_local(&first);
                    self.cur_mut().loop_depth += 1;
                    let body = self.parse_block()?;
                    self.cur_mut().loop_depth -= 1;
                    self.close_block();
                    self.expect(&Tok::End)?;
                    Ok(Stmt {
                        line,
                        kind: StmtKind::NumFor {
                            var,
                            start,
                            end,
                            step,
                            body,
                        },
                    })
                } else {
                    let mut names = vec![first];
                    while self.accept(&Tok::Comma) {
                        names.push(self.expect_name()?);
                    }
                    self.expect(&Tok::In)?;
                    let exprs = self.parse_expr_list()?;
                    self.expect(&Tok::Do)?;
                    self.open_block();
                    let vars = names.iter().map(|n| self.declare_local(n)).collect();
                    self.cur_mut().loop_depth += 1;
                    let body = self.parse_block()?;
                    self.cur_mut().loop_depth -= 1;
                    self.close_block();
                    self.expect(&Tok::End)?;
                    Ok(Stmt {
                        line,
                        kind: StmtKind::GenFor { vars, exprs, body },
                    })
                }
            }
            Tok::Break => {
                if self.cur().loop_depth == 0 {
                    return Err(self.err("'break' outside a loop"));
                }
                self.advance();
                Ok(Stmt {
                    line,
                    kind: StmtKind::Break,
                })
            }
            Tok::Return => {
                // Handled in parse_block; a return in the middle of a block is
                // still accepted and ends the block.
                self.advance();
                let exprs = if self.block_follows() {
                    Vec::new()
                } else {
                    self.parse_expr_list()?
                };
                let _ = self.accept(&Tok::Semi);
                Ok(Stmt {
                    line,
                    kind: StmtKind::Return(exprs),
                })
            }
            _ => {
                let first = self.parse_suffixed()?;
                if self.check(&Tok::Assign) || self.check(&Tok::Comma) {
                    let mut targets = vec![first];
                    while self.accept(&Tok::Comma) {
                        targets.push(self.parse_suffixed()?);
                    }
                    self.expect(&Tok::Assign)?;
                    let exprs = self.parse_expr_list()?;
                    Ok(Stmt {
                        line,
                        kind: StmtKind::Assign { targets, exprs },
                    })
                } else {
                    if !matches!(first.kind, ExprKind::Call(..) | ExprKind::Method(..)) {
                        return Err(
                            self.err("syntax error: expected an assignment or a function call")
                        );
                    }
                    Ok(Stmt {
                        line,
                        kind: StmtKind::Call(first),
                    })
                }
            }
        }
    }

    fn parse_funcbody(
        &mut self,
        name: String,
        is_method: bool,
        line: u32,
    ) -> Result<Rc<Proto>, ScriptError> {
        self.expect(&Tok::LParen)?;
        let mut params: Vec<String> = Vec::new();
        if is_method {
            params.push("self".to_string());
        }
        let mut is_vararg = false;
        if !self.check(&Tok::RParen) {
            loop {
                match self.tok().clone() {
                    Tok::Name(n) => {
                        self.advance();
                        params.push(n);
                    }
                    Tok::Ellipsis => {
                        self.advance();
                        is_vararg = true;
                        break;
                    }
                    _ => {
                        return Err(self.err(format!(
                            "expected a parameter name near {}",
                            self.tok().describe()
                        )))
                    }
                }
                if !self.accept(&Tok::Comma) {
                    break;
                }
            }
        }
        self.expect(&Tok::RParen)?;
        self.funcs.push(FuncState::new(is_vararg));
        for p in &params {
            self.declare_local(p);
        }
        let body = self.parse_block()?;
        self.expect(&Tok::End)?;
        let _ = line;
        Ok(self.build_proto(&name, params, is_vararg, body))
    }

    // ---- expressions ---------------------------------------------------

    fn parse_expr_list(&mut self) -> Result<Vec<Expr>, ScriptError> {
        let mut exprs = vec![self.parse_expr()?];
        while self.accept(&Tok::Comma) {
            exprs.push(self.parse_expr()?);
        }
        Ok(exprs)
    }

    fn parse_expr(&mut self) -> Result<Expr, ScriptError> {
        self.parse_subexpr(0)
    }

    fn parse_subexpr(&mut self, limit: u8) -> Result<Expr, ScriptError> {
        self.enter()?;
        let mut lhs = if let Some(op) = self.unop() {
            self.advance();
            let operand = self.parse_subexpr(12)?;
            Expr::new(ExprKind::Un(op, Box::new(operand)))
        } else {
            self.parse_simple()?
        };
        let mut chain = 0usize;
        loop {
            let (kind, left, right) = match self.tok() {
                Tok::Or => (OpKind::Or, 1u8, 1u8),
                Tok::And => (OpKind::And, 2, 2),
                Tok::Lt => (OpKind::Cmp(CmpOp::Lt), 3, 3),
                Tok::Gt => (OpKind::Cmp(CmpOp::Gt), 3, 3),
                Tok::Le => (OpKind::Cmp(CmpOp::Le), 3, 3),
                Tok::Ge => (OpKind::Cmp(CmpOp::Ge), 3, 3),
                Tok::Ne => (OpKind::Cmp(CmpOp::Ne), 3, 3),
                Tok::Eq => (OpKind::Cmp(CmpOp::Eq), 3, 3),
                Tok::DotDot => (OpKind::Bin(BinOp::Concat), 9, 8),
                Tok::Plus => (OpKind::Bin(BinOp::Add), 10, 10),
                Tok::Minus => (OpKind::Bin(BinOp::Sub), 10, 10),
                Tok::Star => (OpKind::Bin(BinOp::Mul), 11, 11),
                Tok::Slash => (OpKind::Bin(BinOp::Div), 11, 11),
                Tok::DSlash => (OpKind::Bin(BinOp::IDiv), 11, 11),
                Tok::Percent => (OpKind::Bin(BinOp::Mod), 11, 11),
                Tok::Caret => (OpKind::Bin(BinOp::Pow), 14, 13),
                _ => break,
            };
            if left <= limit {
                break;
            }
            chain += 1;
            if chain > MAX_CHAIN {
                return Err(self.err("expression too complex"));
            }
            self.advance();
            let rhs = self.parse_subexpr(right)?;
            lhs = match kind {
                OpKind::Bin(op) => Expr::new(ExprKind::Bin(op, Box::new(lhs), Box::new(rhs))),
                OpKind::Cmp(op) => Expr::new(ExprKind::Cmp(op, Box::new(lhs), Box::new(rhs))),
                OpKind::And => Expr::new(ExprKind::And(Box::new(lhs), Box::new(rhs))),
                OpKind::Or => Expr::new(ExprKind::Or(Box::new(lhs), Box::new(rhs))),
            };
        }
        self.leave();
        Ok(lhs)
    }

    fn unop(&self) -> Option<UnOp> {
        match self.tok() {
            Tok::Not => Some(UnOp::Not),
            Tok::Minus => Some(UnOp::Neg),
            Tok::Hash => Some(UnOp::Len),
            _ => None,
        }
    }

    fn parse_simple(&mut self) -> Result<Expr, ScriptError> {
        self.enter()?;
        let expr = match self.tok().clone() {
            Tok::Nil => {
                self.advance();
                Expr::new(ExprKind::Nil)
            }
            Tok::True => {
                self.advance();
                Expr::new(ExprKind::True)
            }
            Tok::False => {
                self.advance();
                Expr::new(ExprKind::False)
            }
            Tok::Number(n) => {
                self.advance();
                Expr::new(ExprKind::Number(n))
            }
            Tok::Str(s) => {
                self.advance();
                Expr::new(ExprKind::Str(s))
            }
            Tok::Ellipsis => {
                self.advance();
                if !self.cur().is_vararg {
                    return Err(self.err("cannot use '...' outside a vararg function"));
                }
                Expr::new(ExprKind::Vararg)
            }
            Tok::Function => {
                let line = self.line();
                self.advance();
                let proto = self.parse_funcbody("anonymous".to_string(), false, line)?;
                Expr::new(ExprKind::Function(proto))
            }
            Tok::LBrace => self.parse_table()?,
            Tok::Name(_) | Tok::LParen => self.parse_suffixed()?,
            _ => return Err(self.err(format!("unexpected symbol near {}", self.tok().describe()))),
        };
        self.leave();
        Ok(expr)
    }

    fn parse_suffixed(&mut self) -> Result<Expr, ScriptError> {
        let mut expr = if let Tok::Name(name) = self.tok().clone() {
            self.advance();
            let var = self.resolve_var(&name);
            Expr::new(ExprKind::Var(var))
        } else if self.check(&Tok::LParen) {
            self.advance();
            let inner = self.parse_expr()?;
            self.expect(&Tok::RParen)?;
            // Parentheses truncate multiple returns to exactly one value.
            Expr::new(ExprKind::Paren(Box::new(inner)))
        } else {
            return Err(self.err(format!("unexpected symbol near {}", self.tok().describe())));
        };
        loop {
            if self.accept(&Tok::Dot) {
                let name = self.expect_name()?;
                let key = Expr::new(ExprKind::Str(name));
                expr = Expr::new(ExprKind::Index(Box::new(expr), Box::new(key)));
            } else if self.check(&Tok::LBracket) {
                self.advance();
                let key = self.parse_expr()?;
                self.expect(&Tok::RBracket)?;
                expr = Expr::new(ExprKind::Index(Box::new(expr), Box::new(key)));
            } else if self.accept(&Tok::Colon) {
                let name = self.expect_name()?;
                let args = self.parse_args()?;
                expr = Expr::new(ExprKind::Method(Box::new(expr), name, args));
            } else if self.check(&Tok::LParen)
                || self.check(&Tok::LBrace)
                || matches!(self.tok(), Tok::Str(_))
            {
                let args = self.parse_args()?;
                expr = Expr::new(ExprKind::Call(Box::new(expr), args));
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>, ScriptError> {
        if matches!(self.tok(), Tok::Str(_)) {
            if let Tok::Str(s) = self.tok().clone() {
                self.advance();
                return Ok(vec![Expr::new(ExprKind::Str(s))]);
            }
        }
        if self.check(&Tok::LBrace) {
            return Ok(vec![self.parse_table()?]);
        }
        self.expect(&Tok::LParen)?;
        if self.accept(&Tok::RParen) {
            return Ok(Vec::new());
        }
        let args = self.parse_expr_list()?;
        self.expect(&Tok::RParen)?;
        Ok(args)
    }

    fn parse_table(&mut self) -> Result<Expr, ScriptError> {
        self.expect(&Tok::LBrace)?;
        let mut fields = Vec::new();
        while !self.check(&Tok::RBrace) {
            if self.check(&Tok::LBracket) {
                self.advance();
                let key = self.parse_expr()?;
                self.expect(&Tok::RBracket)?;
                self.expect(&Tok::Assign)?;
                let value = self.parse_expr()?;
                fields.push(Field::Keyed(key, value));
            } else if let Tok::Name(name) = self.tok().clone() {
                if matches!(self.tok_at(1), Tok::Assign) {
                    self.advance();
                    self.advance();
                    let value = self.parse_expr()?;
                    fields.push(Field::Keyed(Expr::new(ExprKind::Str(name)), value));
                } else {
                    fields.push(Field::Array(self.parse_expr()?));
                }
            } else {
                fields.push(Field::Array(self.parse_expr()?));
            }
            if !self.accept(&Tok::Comma) && !self.accept(&Tok::Semi) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        Ok(Expr::new(ExprKind::Table(fields)))
    }
}

enum OpKind {
    Bin(BinOp),
    Cmp(CmpOp),
    And,
    Or,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(src: &str) {
        parse(src).unwrap_or_else(|e| panic!("parse failed for {src:?}: {e}"));
    }

    #[test]
    fn parses_core_statements() {
        parse_ok("local a = 1 local b, c = 2, 3");
        parse_ok("x = a + b * c ^ 2 .. 'd'");
        parse_ok("if a then b() elseif c then d() else e() end");
        parse_ok("while x < 3 do x = x + 1 end");
        parse_ok("repeat x = x - 1 until x == 0");
        parse_ok("for i = 1, 10, 2 do print(i) end");
        parse_ok("for k, v in pairs(t) do print(k, v) end");
        parse_ok("function a.b.c(x, y, ...) return x end");
        parse_ok("local function f(n) if n <= 1 then return 1 end return n * f(n - 1) end");
        parse_ok("function t:m(x) return self.v + x end");
        parse_ok("local t = { 1, 2, x = 3, ['y'] = 4; }");
        parse_ok("do local x = 1 end");
        parse_ok("return 1, 2, 3");
    }

    #[test]
    fn syntax_errors_have_lines() {
        let err = parse("local x = 1\nlocal = 2").unwrap_err();
        assert_eq!(err.line, 2);
        let err = parse("if x then\nend\nend").unwrap_err();
        assert_eq!(err.line, 3);
    }

    #[test]
    fn rejects_deep_nesting() {
        let depth = 5000;
        let mut src = String::new();
        for _ in 0..depth {
            src.push('(');
        }
        src.push('1');
        for _ in 0..depth {
            src.push(')');
        }
        assert!(parse(&src).is_err());
    }

    #[test]
    fn upvalues_are_resolved() {
        let proto = parse("local x = 1 local f = function() return x end return f").unwrap();
        assert_eq!(proto.max_slots >= 2, true);
        let mut found = false;
        for stmt in &proto.body {
            if let StmtKind::Local { exprs, .. } = &stmt.kind {
                for e in exprs {
                    if let ExprKind::Function(p) = &e.kind {
                        assert_eq!(p.upvals.len(), 1);
                        assert!(p.upvals[0].in_stack);
                        found = true;
                    }
                }
            }
        }
        assert!(found);
    }
}
