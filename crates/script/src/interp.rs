//! Tree-walking interpreter for emera script.
//!
//! Locals live in fixed slots per call frame (resolved at parse time); locals
//! captured by closures are stored in `Rc<RefCell<Value>>` cells so closures
//! share mutation and per-iteration loop variables behave like Lua's.
//!
//! Every execution step is counted; instruction, wall clock, output and memory
//! limits return Err instead of hanging or aborting the agent.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use crate::ast::*;
use crate::error::{Fault, IResult, ScriptError};
use crate::numfmt;
use crate::value::{key_eq, tostring, FnKind, Function, Table, Value};
use crate::{Host, Limits};

/// Maximum number of nested Lua calls (the design's 200 frame cap).
pub(crate) const MAX_FRAMES: usize = 200;
/// Maximum entries in a single table.
pub(crate) const MAX_TABLE_ENTRIES: usize = 100_000;
/// Maximum size of a single string built by the stdlib.
pub(crate) const MAX_STRING_BYTES: usize = 8 << 20;
/// Approximate total memory budget for script-allocated tables and strings.
pub(crate) const MAX_MEMORY_BYTES: usize = 64 << 20;
/// Largest field width accepted by string.format.
pub(crate) const MAX_FORMAT_WIDTH: usize = 4096;
/// Largest precision accepted by string.format.
pub(crate) const MAX_FORMAT_PRECISION: usize = 1000;
const CLOCK_MASK: u64 = 0x0FFF;

pub(crate) struct Interp<'h> {
    pub host: &'h mut dyn Host,
    pub globals: Rc<RefCell<Table>>,
    frames: Vec<Frame>,
    limits: Limits,
    instr: u64,
    mem: usize,
    out_bytes: usize,
    start: Instant,
    line: u32,
    rng: u64,
    host_ns: Vec<(Rc<RefCell<Table>>, &'static str)>,
}

struct Frame {
    proto: Rc<Proto>,
    slots: Vec<Slot>,
    upvals: Vec<Rc<RefCell<Value>>>,
    varargs: Vec<Value>,
}

#[derive(Clone)]
enum Slot {
    Val(Value),
    Cell(Rc<RefCell<Value>>),
}

impl Slot {
    fn get(&self) -> Value {
        match self {
            Slot::Val(v) => v.clone(),
            Slot::Cell(c) => c.borrow().clone(),
        }
    }

    fn set(&mut self, value: Value) {
        match self {
            Slot::Val(v) => *v = value,
            Slot::Cell(c) => *c.borrow_mut() = value,
        }
    }

    fn cell(&self) -> Option<Rc<RefCell<Value>>> {
        match self {
            Slot::Cell(c) => Some(c.clone()),
            Slot::Val(_) => None,
        }
    }
}

enum Flow {
    Normal,
    Break,
    Return(Vec<Value>),
}

enum LValue {
    Local(usize),
    Upval(usize),
    Global(String),
    Index(Rc<RefCell<Table>>, Value),
}

impl<'h> Interp<'h> {
    pub(crate) fn new(host: &'h mut dyn Host, limits: Limits) -> Interp<'h> {
        Interp {
            host,
            globals: Rc::new(RefCell::new(Table::new())),
            frames: Vec::new(),
            limits,
            instr: 0,
            mem: 0,
            out_bytes: 0,
            start: Instant::now(),
            line: 1,
            rng: 0x9E37_79B9_7F4A_7C15,
            host_ns: Vec::new(),
        }
    }

    pub(crate) fn run_chunk(
        &mut self,
        proto: Rc<Proto>,
    ) -> core::result::Result<Value, ScriptError> {
        crate::stdlib::install(self);
        match self.call_lua(proto, Vec::new(), Vec::new()) {
            Ok(mut vals) => Ok(if vals.is_empty() {
                Value::Nil
            } else {
                vals.remove(0)
            }),
            Err(fault) => Err(fault.err),
        }
    }

    // ---- counters and limits -------------------------------------------

    fn tick(&mut self) -> IResult<()> {
        self.instr = self.instr.wrapping_add(1);
        if self.limits.max_instructions != 0 && self.instr > self.limits.max_instructions {
            return Err(Fault::limit(
                format!(
                    "instruction limit of {} exceeded",
                    self.limits.max_instructions
                ),
                self.line,
            ));
        }
        if self.instr & CLOCK_MASK == 0 && self.limits.wall_clock_ms != 0 {
            let elapsed = self.start.elapsed().as_millis() as u64;
            if elapsed >= self.limits.wall_clock_ms {
                return Err(Fault::limit(
                    format!(
                        "wall clock limit of {} ms exceeded",
                        self.limits.wall_clock_ms
                    ),
                    self.line,
                ));
            }
        }
        Ok(())
    }

    /// Charge pattern-matching work against the instruction budget.
    pub(crate) fn charge_steps(&mut self, steps: u32) -> IResult<()> {
        self.instr = self.instr.saturating_add(steps as u64);
        if self.limits.max_instructions != 0 && self.instr > self.limits.max_instructions {
            return Err(Fault::limit(
                format!(
                    "instruction limit of {} exceeded",
                    self.limits.max_instructions
                ),
                self.line,
            ));
        }
        Ok(())
    }

    pub(crate) fn charge(&mut self, bytes: usize) -> IResult<()> {
        self.mem = self.mem.saturating_add(bytes);
        if self.mem > MAX_MEMORY_BYTES {
            return Err(Fault::limit("script memory limit exceeded", self.line));
        }
        Ok(())
    }

    pub(crate) fn new_string(&mut self, s: String) -> IResult<Value> {
        if s.len() > MAX_STRING_BYTES {
            return Err(Fault::limit("string size limit exceeded", self.line));
        }
        self.charge(s.len())?;
        Ok(Value::Str(s))
    }

    pub(crate) fn output(&mut self, text: &str) -> IResult<()> {
        self.out_bytes = self.out_bytes.saturating_add(text.len());
        if self.limits.max_output_bytes != 0 && self.out_bytes > self.limits.max_output_bytes {
            return Err(Fault::limit(
                format!(
                    "output limit of {} bytes exceeded",
                    self.limits.max_output_bytes
                ),
                self.line,
            ));
        }
        self.host.print(text);
        Ok(())
    }

    pub(crate) fn rt(&self, message: impl Into<String>) -> Fault {
        Fault::lua(message, self.line)
    }

    pub(crate) fn line(&self) -> u32 {
        self.line
    }

    pub(crate) fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    // ---- random --------------------------------------------------------

    pub(crate) fn next_random(&mut self) -> f64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        ((v >> 11) as f64) / ((1u64 << 53) as f64)
    }

    pub(crate) fn seed_random(&mut self, seed: u64) {
        self.rng = seed ^ 0x9E37_79B9_7F4A_7C15;
        if self.rng == 0 {
            self.rng = 0x2545_F491_4F6C_DD1D;
        }
    }

    // ---- frames and slots ----------------------------------------------

    fn slot_get(&self, index: usize) -> Value {
        self.frames
            .last()
            .and_then(|f| f.slots.get(index))
            .map(|s| s.get())
            .unwrap_or(Value::Nil)
    }

    fn slot_set(&mut self, index: usize, value: Value) {
        if let Some(frame) = self.frames.last_mut() {
            if let Some(slot) = frame.slots.get_mut(index) {
                slot.set(value);
            }
        }
    }

    /// (Re)initialise a slot; captured slots get a fresh cell, which is what
    /// gives each loop iteration its own upvalue.
    fn slot_fresh(&mut self, index: usize, value: Value) {
        let captured = self
            .frames
            .last()
            .map(|f| f.proto.captured.get(index).copied().unwrap_or(false))
            .unwrap_or(false);
        if let Some(frame) = self.frames.last_mut() {
            if let Some(slot) = frame.slots.get_mut(index) {
                if captured {
                    *slot = Slot::Cell(Rc::new(RefCell::new(value)));
                } else {
                    *slot = Slot::Val(value);
                }
            }
        }
    }

    fn get_var(&self, var: &VarRef) -> Value {
        match var {
            VarRef::Local(i) => self.slot_get(*i),
            VarRef::Upval(i) => self
                .frames
                .last()
                .and_then(|f| f.upvals.get(*i))
                .map(|c| c.borrow().clone())
                .unwrap_or(Value::Nil),
            VarRef::Global(name) => self.globals.borrow().get_str(name),
        }
    }

    // ---- tables --------------------------------------------------------

    pub(crate) fn set_table(
        &mut self,
        table: &Rc<RefCell<Table>>,
        key: Value,
        value: Value,
    ) -> IResult<()> {
        if key.is_nil() {
            return Err(self.rt("table index is nil"));
        }
        if let Value::Number(n) = key {
            if n.is_nan() {
                return Err(self.rt("table index is NaN"));
            }
        }
        {
            let mut t = table.borrow_mut();
            if !t.contains(&key) {
                if t.entry_count() >= MAX_TABLE_ENTRIES {
                    return Err(Fault::limit("table has too many entries", self.line));
                }
                self.charge(48)?;
            }
            t.set(key, value);
        }
        Ok(())
    }

    fn index(&mut self, object: Value, key: Value) -> IResult<Value> {
        match object {
            Value::Table(t) => {
                let value = t.borrow().get(&key);
                if value.is_nil() {
                    if let Value::Str(name) = &key {
                        for (ns_table, ns_name) in &self.host_ns {
                            if Rc::ptr_eq(ns_table, &t) {
                                let full = format!("{ns_name}.{name}");
                                return Ok(Value::Function(Rc::new(Function::host(full))));
                            }
                        }
                    }
                }
                Ok(value)
            }
            Value::Str(_) => {
                // Lua exposes string methods through ("x"):upper(); we look
                // the member up in the string table instead of using a
                // metatable, which keeps the value model tiny.
                if let Value::Str(name) = &key {
                    if let Value::Table(string_table) = self.get_global("string") {
                        return Ok(string_table.borrow().get_str(name));
                    }
                }
                Ok(Value::Nil)
            }
            other => Err(self.rt(format!("attempt to index a {} value", other.type_name()))),
        }
    }

    /// Register a host namespace table (io, fs, proc, net) whose missing
    /// members resolve to Host::call("<ns>.<name>", ...).
    pub(crate) fn register_host_ns(&mut self, name: &'static str) -> Rc<RefCell<Table>> {
        let table = Rc::new(RefCell::new(Table::new()));
        self.host_ns.push((table.clone(), name));
        table
    }

    // ---- calls ---------------------------------------------------------

    pub(crate) fn call_value(&mut self, callee: &Value, args: Vec<Value>) -> IResult<Vec<Value>> {
        self.tick()?;
        match callee {
            Value::Function(fun) => match &fun.kind {
                FnKind::Native(f) => f(self, args),
                FnKind::Host(name) => {
                    let name = name.clone();
                    self.host_call(&name, args)
                }
                FnKind::Lua { proto, upvals } => {
                    let proto = proto.clone();
                    let upvals = upvals.clone();
                    self.call_lua(proto, upvals, args)
                }
                FnKind::Gmatch(state) => {
                    let state = state.clone();
                    crate::strlib::gmatch_next(self, &state, args)
                }
            },
            other => Err(self.rt(format!("attempt to call a {} value", other.type_name()))),
        }
    }

    fn host_call(&mut self, name: &str, args: Vec<Value>) -> IResult<Vec<Value>> {
        match self.host.call(name, args) {
            Ok(v) => Ok(vec![v]),
            Err(e) => Err(Fault::host(
                format!("host function '{name}' failed: {}", e.message),
                self.line,
            )),
        }
    }

    fn call_lua(
        &mut self,
        proto: Rc<Proto>,
        upvals: Vec<Rc<RefCell<Value>>>,
        args: Vec<Value>,
    ) -> IResult<Vec<Value>> {
        if self.frames.len() >= MAX_FRAMES {
            return Err(Fault::limit(
                format!("stack overflow: more than {MAX_FRAMES} nested calls"),
                self.line,
            ));
        }
        self.tick()?;
        let nparams = proto.params.len();
        let mut slots: Vec<Slot> = Vec::with_capacity(proto.max_slots);
        for i in 0..proto.max_slots {
            let value = args.get(i).cloned().unwrap_or(Value::Nil);
            if i < nparams {
                let captured = proto.captured.get(i).copied().unwrap_or(false);
                slots.push(if captured {
                    Slot::Cell(Rc::new(RefCell::new(value)))
                } else {
                    Slot::Val(value)
                });
            } else {
                slots.push(Slot::Val(Value::Nil));
            }
        }
        let varargs = if proto.is_vararg && args.len() > nparams {
            args[nparams..].to_vec()
        } else {
            Vec::new()
        };
        self.frames.push(Frame {
            proto: proto.clone(),
            slots,
            upvals,
            varargs,
        });
        let depth = self.frames.len();
        let result = self.exec_block(&proto.body);
        self.frames.truncate(depth - 1);
        match result? {
            Flow::Return(vals) => Ok(vals),
            _ => Ok(Vec::new()),
        }
    }

    fn make_closure(&self, proto: &Rc<Proto>) -> Value {
        let mut upvals = Vec::with_capacity(proto.upvals.len());
        for desc in &proto.upvals {
            let cell = if desc.in_stack {
                self.frames
                    .last()
                    .and_then(|f| f.slots.get(desc.index))
                    .and_then(|s| s.cell())
            } else {
                self.frames
                    .last()
                    .and_then(|f| f.upvals.get(desc.index))
                    .cloned()
            };
            upvals.push(cell.unwrap_or_else(|| Rc::new(RefCell::new(Value::Nil))));
        }
        Value::Function(Rc::new(Function::lua(
            proto.name.clone(),
            proto.clone(),
            upvals,
        )))
    }

    // ---- statements ----------------------------------------------------

    fn exec_block(&mut self, stmts: &[Stmt]) -> IResult<Flow> {
        for stmt in stmts {
            self.tick()?;
            self.line = stmt.line;
            match self.exec_stmt(stmt)? {
                Flow::Normal => {}
                flow => return Ok(flow),
            }
        }
        Ok(Flow::Normal)
    }

    fn exec_stmt(&mut self, stmt: &Stmt) -> IResult<Flow> {
        match &stmt.kind {
            StmtKind::Local { slots, exprs } => {
                // Cells are created before the initialisers run so that
                // "local function f() ... f() ... end" captures the very cell
                // the declaration then fills in.
                for slot in slots {
                    self.slot_fresh(*slot, Value::Nil);
                }
                let values = self.eval_list(exprs)?;
                for (i, slot) in slots.iter().enumerate() {
                    let value = values.get(i).cloned().unwrap_or(Value::Nil);
                    self.slot_set(*slot, value);
                }
                Ok(Flow::Normal)
            }
            StmtKind::Assign { targets, exprs } => {
                let values = self.eval_list(exprs)?;
                let mut lvalues = Vec::with_capacity(targets.len());
                for target in targets {
                    match &target.kind {
                        ExprKind::Var(VarRef::Local(i)) => lvalues.push(LValue::Local(*i)),
                        ExprKind::Var(VarRef::Upval(i)) => lvalues.push(LValue::Upval(*i)),
                        ExprKind::Var(VarRef::Global(n)) => lvalues.push(LValue::Global(n.clone())),
                        ExprKind::Index(obj, key) => {
                            let object = self.eval(obj)?;
                            let key = self.eval(key)?;
                            let table = match object {
                                Value::Table(t) => t,
                                other => {
                                    return Err(self.rt(format!(
                                        "attempt to index a {} value",
                                        other.type_name()
                                    )))
                                }
                            };
                            lvalues.push(LValue::Index(table, key));
                        }
                        _ => return Err(self.rt("cannot assign to this expression")),
                    }
                }
                for (i, lvalue) in lvalues.into_iter().enumerate() {
                    let value = values.get(i).cloned().unwrap_or(Value::Nil);
                    match lvalue {
                        LValue::Local(slot) => self.slot_set(slot, value),
                        LValue::Upval(slot) => {
                            if let Some(cell) = self.frames.last().and_then(|f| f.upvals.get(slot))
                            {
                                *cell.borrow_mut() = value;
                            }
                        }
                        LValue::Global(name) => {
                            let globals = self.globals.clone();
                            self.set_table(&globals, Value::Str(name), value)?;
                        }
                        LValue::Index(table, key) => self.set_table(&table, key, value)?,
                    }
                }
                Ok(Flow::Normal)
            }
            StmtKind::Call(expr) => {
                self.eval(expr)?;
                Ok(Flow::Normal)
            }
            StmtKind::Do(body) => self.exec_block(body),
            StmtKind::While { cond, body } => {
                loop {
                    self.tick()?;
                    if !self.eval(cond)?.truthy() {
                        break;
                    }
                    match self.exec_block(body)? {
                        Flow::Normal => {}
                        Flow::Break => break,
                        flow => return Ok(flow),
                    }
                }
                Ok(Flow::Normal)
            }
            StmtKind::Repeat { body, cond } => {
                loop {
                    self.tick()?;
                    match self.exec_block(body)? {
                        Flow::Normal => {}
                        Flow::Break => break,
                        flow => return Ok(flow),
                    }
                    if self.eval(cond)?.truthy() {
                        break;
                    }
                }
                Ok(Flow::Normal)
            }
            StmtKind::If { arms, els } => {
                for (cond, body) in arms {
                    if self.eval(cond)?.truthy() {
                        return self.exec_block(body);
                    }
                }
                if let Some(body) = els {
                    return self.exec_block(body);
                }
                Ok(Flow::Normal)
            }
            StmtKind::NumFor {
                var,
                start,
                end,
                step,
                body,
            } => {
                let start = self.eval_number(start, "'for' initial value")?;
                let end = self.eval_number(end, "'for' limit")?;
                let step = match step {
                    Some(e) => self.eval_number(e, "'for' step")?,
                    None => 1.0,
                };
                if step == 0.0 || step.is_nan() {
                    return Err(self.rt("'for' step is zero"));
                }
                let mut i = start;
                loop {
                    if step > 0.0 {
                        if !(i <= end) {
                            break;
                        }
                    } else if !(i >= end) {
                        break;
                    }
                    self.tick()?;
                    self.slot_fresh(*var, Value::Number(i));
                    match self.exec_block(body)? {
                        Flow::Normal => {}
                        Flow::Break => break,
                        flow => return Ok(flow),
                    }
                    i += step;
                    if !i.is_finite() {
                        break;
                    }
                }
                Ok(Flow::Normal)
            }
            StmtKind::GenFor { vars, exprs, body } => {
                let values = self.eval_list(exprs)?;
                let iter = values.first().cloned().unwrap_or(Value::Nil);
                let state = values.get(1).cloned().unwrap_or(Value::Nil);
                let mut control = values.get(2).cloned().unwrap_or(Value::Nil);
                loop {
                    self.tick()?;
                    let results = self.call_value(&iter, vec![state.clone(), control.clone()])?;
                    let first = results.first().cloned().unwrap_or(Value::Nil);
                    if first.is_nil() {
                        break;
                    }
                    control = first;
                    for (i, var) in vars.iter().enumerate() {
                        let value = results.get(i).cloned().unwrap_or(Value::Nil);
                        self.slot_fresh(*var, value);
                    }
                    match self.exec_block(body)? {
                        Flow::Normal => {}
                        Flow::Break => break,
                        flow => return Ok(flow),
                    }
                }
                Ok(Flow::Normal)
            }
            StmtKind::Return(exprs) => {
                let values = self.eval_list(exprs)?;
                Ok(Flow::Return(values))
            }
            StmtKind::Break => Ok(Flow::Break),
        }
    }

    // ---- expressions ---------------------------------------------------

    fn eval_list(&mut self, exprs: &[Expr]) -> IResult<Vec<Value>> {
        let mut out = Vec::with_capacity(exprs.len());
        for (i, expr) in exprs.iter().enumerate() {
            if i + 1 == exprs.len() {
                out.extend(self.eval_multi(expr)?);
            } else {
                out.push(self.eval(expr)?);
            }
        }
        Ok(out)
    }

    fn eval_multi(&mut self, expr: &Expr) -> IResult<Vec<Value>> {
        match &expr.kind {
            ExprKind::Call(callee, args) => {
                let callee = self.eval(callee)?;
                let args = self.eval_list(args)?;
                self.call_dispatch(callee, args, expr)
            }
            ExprKind::Method(object, name, args) => {
                let object = self.eval(object)?;
                let mut full = Vec::with_capacity(args.len() + 1);
                full.push(object.clone());
                full.extend(self.eval_list(args)?);
                let callee = self.index(object, Value::Str(name.clone()))?;
                self.call_dispatch(callee, full, expr)
            }
            ExprKind::Vararg => Ok(self.varargs()),
            _ => Ok(vec![self.eval(expr)?]),
        }
    }

    fn call_dispatch(
        &mut self,
        callee: Value,
        args: Vec<Value>,
        expr: &Expr,
    ) -> IResult<Vec<Value>> {
        if callee.is_nil() {
            if let ExprKind::Call(inner, _) = &expr.kind {
                if let ExprKind::Var(VarRef::Global(name)) = &inner.kind {
                    return self.host_call(name, args);
                }
            }
        }
        self.call_value(&callee, args)
    }

    fn varargs(&self) -> Vec<Value> {
        self.frames
            .last()
            .map(|f| f.varargs.clone())
            .unwrap_or_default()
    }

    fn eval(&mut self, expr: &Expr) -> IResult<Value> {
        match &expr.kind {
            ExprKind::Nil => Ok(Value::Nil),
            ExprKind::True => Ok(Value::Bool(true)),
            ExprKind::False => Ok(Value::Bool(false)),
            ExprKind::Number(n) => Ok(Value::Number(*n)),
            ExprKind::Str(s) => Ok(Value::Str(s.clone())),
            ExprKind::Var(v) => Ok(self.get_var(v)),
            ExprKind::Index(object, key) => {
                let object = self.eval(object)?;
                let key = self.eval(key)?;
                self.index(object, key)
            }
            ExprKind::Call(_, _) | ExprKind::Method(_, _, _) => {
                let mut values = self.eval_multi(expr)?;
                Ok(if values.is_empty() {
                    Value::Nil
                } else {
                    values.remove(0)
                })
            }
            ExprKind::Function(proto) => Ok(self.make_closure(proto)),
            ExprKind::Table(fields) => self.make_table(fields),
            ExprKind::Vararg => Ok(self.varargs().into_iter().next().unwrap_or(Value::Nil)),
            ExprKind::Paren(inner) => self.eval(inner),
            ExprKind::And(lhs, rhs) => {
                let left = self.eval(lhs)?;
                if left.truthy() {
                    self.eval(rhs)
                } else {
                    Ok(left)
                }
            }
            ExprKind::Or(lhs, rhs) => {
                let left = self.eval(lhs)?;
                if left.truthy() {
                    Ok(left)
                } else {
                    self.eval(rhs)
                }
            }
            ExprKind::Un(op, operand) => {
                let value = self.eval(operand)?;
                self.unary(*op, value)
            }
            ExprKind::Bin(op, lhs, rhs) => {
                let left = self.eval(lhs)?;
                let right = self.eval(rhs)?;
                self.binary(*op, left, right)
            }
            ExprKind::Cmp(op, lhs, rhs) => {
                let left = self.eval(lhs)?;
                let right = self.eval(rhs)?;
                self.compare(*op, &left, &right)
            }
        }
    }

    fn eval_number(&mut self, expr: &Expr, what: &str) -> IResult<f64> {
        let value = self.eval(expr)?;
        match to_number(&value) {
            Some(n) => Ok(n),
            None => Err(self.rt(format!("{what} must be a number"))),
        }
    }

    fn make_table(&mut self, fields: &[Field]) -> IResult<Value> {
        let table = Rc::new(RefCell::new(Table::new()));
        let mut array_index = 1usize;
        for (i, field) in fields.iter().enumerate() {
            match field {
                Field::Array(expr) => {
                    let values = if i + 1 == fields.len() {
                        self.eval_multi(expr)?
                    } else {
                        vec![self.eval(expr)?]
                    };
                    for value in values {
                        self.set_table(&table, Value::Number(array_index as f64), value)?;
                        array_index += 1;
                    }
                }
                Field::Keyed(key, value) => {
                    let key = self.eval(key)?;
                    let value = self.eval(value)?;
                    self.set_table(&table, key, value)?;
                }
            }
        }
        Ok(Value::Table(table))
    }

    fn unary(&mut self, op: UnOp, value: Value) -> IResult<Value> {
        match op {
            UnOp::Not => Ok(Value::Bool(!value.truthy())),
            UnOp::Neg => match to_number(&value) {
                Some(n) => Ok(Value::Number(-n)),
                None => Err(self.rt(format!(
                    "attempt to perform arithmetic on a {} value",
                    value.type_name()
                ))),
            },
            UnOp::Len => match &value {
                Value::Str(s) => Ok(Value::Number(s.len() as f64)),
                Value::Table(t) => Ok(Value::Number(t.borrow().len() as f64)),
                other => Err(self.rt(format!(
                    "attempt to get length of a {} value",
                    other.type_name()
                ))),
            },
        }
    }

    fn binary(&mut self, op: BinOp, left: Value, right: Value) -> IResult<Value> {
        if matches!(op, BinOp::Concat) {
            let a = concat_string(&left).ok_or_else(|| {
                self.rt(format!(
                    "attempt to concatenate a {} value",
                    left.type_name()
                ))
            })?;
            let b = concat_string(&right).ok_or_else(|| {
                self.rt(format!(
                    "attempt to concatenate a {} value",
                    right.type_name()
                ))
            })?;
            let mut out = String::with_capacity(a.len() + b.len());
            out.push_str(&a);
            out.push_str(&b);
            return self.new_string(out);
        }
        let x = match to_number(&left) {
            Some(n) => n,
            None => {
                return Err(self.rt(format!(
                    "attempt to perform arithmetic on a {} value",
                    left.type_name()
                )))
            }
        };
        let y = match to_number(&right) {
            Some(n) => n,
            None => {
                return Err(self.rt(format!(
                    "attempt to perform arithmetic on a {} value",
                    right.type_name()
                )))
            }
        };
        let value = match op {
            BinOp::Add => x + y,
            BinOp::Sub => x - y,
            BinOp::Mul => x * y,
            BinOp::Div => x / y,
            BinOp::IDiv => {
                if y == 0.0 {
                    return Err(self.rt("attempt to divide by zero"));
                }
                (x / y).floor()
            }
            BinOp::Mod => {
                if y == 0.0 {
                    return Err(self.rt("attempt to perform 'n%0'"));
                }
                x - (x / y).floor() * y
            }
            BinOp::Pow => x.powf(y),
            BinOp::Concat => {
                return Err(self.rt("internal error: concat reached the arithmetic path"))
            }
        };
        Ok(Value::Number(value))
    }

    fn compare(&mut self, op: CmpOp, left: &Value, right: &Value) -> IResult<Value> {
        let result = match op {
            CmpOp::Eq => left.equals(right),
            CmpOp::Ne => !left.equals(right),
            CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => match (left, right) {
                (Value::Number(a), Value::Number(b)) => match op {
                    CmpOp::Lt => a < b,
                    CmpOp::Le => a <= b,
                    CmpOp::Gt => a > b,
                    _ => a >= b,
                },
                (Value::Str(a), Value::Str(b)) => match op {
                    CmpOp::Lt => a < b,
                    CmpOp::Le => a <= b,
                    CmpOp::Gt => a > b,
                    _ => a >= b,
                },
                _ => {
                    return Err(self.rt(format!(
                        "attempt to compare {} with {}",
                        left.type_name(),
                        right.type_name()
                    )))
                }
            },
        };
        Ok(Value::Bool(result))
    }

    // ---- argument helpers for the stdlib ------------------------------

    pub(crate) fn arg(&self, args: &[Value], index: usize) -> Value {
        args.get(index).cloned().unwrap_or(Value::Nil)
    }

    pub(crate) fn arg_number(&self, args: &[Value], index: usize, fname: &str) -> IResult<f64> {
        let value = self.arg(args, index);
        match to_number(&value) {
            Some(n) => Ok(n),
            None => Err(self.bad_arg(index, fname, "number", &value)),
        }
    }

    pub(crate) fn arg_int(&self, args: &[Value], index: usize, fname: &str) -> IResult<i64> {
        let n = self.arg_number(args, index, fname)?;
        if !n.is_finite() {
            return Err(self.bad_arg(index, fname, "integer", &self.arg(args, index)));
        }
        Ok(n as i64)
    }

    pub(crate) fn arg_str(&mut self, args: &[Value], index: usize, fname: &str) -> IResult<String> {
        let value = self.arg(args, index);
        match &value {
            Value::Str(s) => Ok(s.clone()),
            Value::Number(n) => Ok(numfmt::number_to_string(*n)),
            other => Err(self.bad_arg(index, fname, "string", other)),
        }
    }

    pub(crate) fn arg_table(
        &self,
        args: &[Value],
        index: usize,
        fname: &str,
    ) -> IResult<Rc<RefCell<Table>>> {
        let value = self.arg(args, index);
        match value {
            Value::Table(t) => Ok(t),
            other => Err(self.bad_arg(index, fname, "table", &other)),
        }
    }

    pub(crate) fn opt_number(&self, args: &[Value], index: usize, default: f64) -> f64 {
        match args.get(index) {
            None | Some(Value::Nil) => default,
            Some(v) => to_number(v).unwrap_or(default),
        }
    }

    pub(crate) fn bad_arg(&self, index: usize, fname: &str, expected: &str, got: &Value) -> Fault {
        Fault::lua(
            format!(
                "bad argument #{} to '{}' ({} expected, got {})",
                index + 1,
                fname,
                expected,
                got.type_name()
            ),
            self.line,
        )
    }

    pub(crate) fn set_global(&mut self, name: &str, value: Value) {
        let globals = self.globals.clone();
        let _ = self.set_table(&globals, Value::Str(name.to_string()), value);
    }

    pub(crate) fn get_global(&self, name: &str) -> Value {
        self.globals.borrow().get_str(name)
    }

    /// Lua-style tostring of a value (used by print and string.format %s).
    pub(crate) fn tostring(&self, value: &Value) -> String {
        tostring(value)
    }

    /// Compare two values for table.sort, calling a Lua comparator when given.
    pub(crate) fn sort_less(&mut self, a: &Value, b: &Value, cmp: Option<&Value>) -> IResult<bool> {
        match cmp {
            None => match (a, b) {
                (Value::Number(x), Value::Number(y)) => Ok(x < y),
                (Value::Str(x), Value::Str(y)) => Ok(x < y),
                _ => Err(self.rt(format!(
                    "attempt to compare {} with {} in table.sort",
                    a.type_name(),
                    b.type_name()
                ))),
            },
            Some(f) => {
                let result = self.call_value(f, vec![a.clone(), b.clone()])?;
                Ok(result.first().map(|v| v.truthy()).unwrap_or(false))
            }
        }
    }
}

/// Lua's string-to-number coercion for arithmetic and tonumber.
pub(crate) fn to_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => Some(*n),
        Value::Str(s) => numfmt::parse_number(s),
        _ => None,
    }
}

fn concat_string(value: &Value) -> Option<String> {
    match value {
        Value::Str(s) => Some(s.clone()),
        Value::Number(n) => Some(numfmt::number_to_string(*n)),
        _ => None,
    }
}

/// Table equality helper re-exported for tests and stdlib.
#[allow(dead_code)]
pub(crate) fn same_key(a: &Value, b: &Value) -> bool {
    key_eq(a, b)
}
