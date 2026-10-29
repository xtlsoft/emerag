//! Value model: Lua values, tables and functions.
//!
//! Every value is owned or reference counted; tables and functions share
//! mutable state through Rc<RefCell<..>> exactly like a small embedded Lua.
//! Numbers are f64 (emerag-script deliberately has no separate integer type;
//! integral values print without a decimal point).

use core::fmt;
use std::cell::RefCell;
use std::rc::Rc;

use crate::ast::Proto;
use crate::error::IResult;
use crate::interp::Interp;
use crate::numfmt;

/// A Lua value.
#[derive(Clone)]
pub enum Value {
    Nil,
    Bool(bool),
    Number(f64),
    Str(String),
    Table(Rc<RefCell<Table>>),
    Function(Rc<Function>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Nil => "nil",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::Str(_) => "string",
            Value::Table(_) => "table",
            Value::Function(_) => "function",
        }
    }

    /// Lua truthiness: everything except nil and false is true.
    pub fn truthy(&self) -> bool {
        !matches!(self, Value::Nil | Value::Bool(false))
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, Value::Nil)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_table(&self) -> Option<&Rc<RefCell<Table>>> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_function(&self) -> Option<&Rc<Function>> {
        match self {
            Value::Function(f) => Some(f),
            _ => None,
        }
    }

    /// Raw equality (Lua's ==, without metamethods).
    pub fn equals(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Nil, Value::Nil) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Table(a), Value::Table(b)) => Rc::ptr_eq(a, b),
            (Value::Function(a), Value::Function(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }

    /// Lua's tostring() for this value.
    pub fn to_lua_string(&self) -> String {
        tostring(self)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => f.write_str(s),
            other => f.write_str(&tostring(other)),
        }
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Nil => f.write_str("nil"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Number(n) => write!(f, "{}", numfmt::number_to_string(*n)),
            Value::Str(s) => write!(f, "{s:?}"),
            Value::Table(t) => write!(f, "table({})", t.borrow().len()),
            Value::Function(fun) => write!(f, "function({})", fun.name),
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        self.equals(other)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Value {
        Value::Number(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Value {
        Value::Number(v as f64)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Value {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::Str(v.to_string())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Value {
        Value::Str(v)
    }
}

impl From<Table> for Value {
    fn from(t: Table) -> Value {
        Value::Table(Rc::new(RefCell::new(t)))
    }
}

/// Lua's tostring: numbers use %.14g semantics and integral values have no
/// trailing .0; tables and functions print an identity.
pub fn tostring(v: &Value) -> String {
    match v {
        Value::Nil => "nil".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(n) => numfmt::number_to_string(*n),
        Value::Str(s) => s.clone(),
        Value::Table(t) => {
            let p = Rc::as_ptr(t) as *const u8 as usize;
            format!("table: 0x{p:x}")
        }
        Value::Function(f) => {
            let p = Rc::as_ptr(f) as *const u8 as usize;
            format!("function: 0x{p:x}")
        }
    }
}

/// A Lua table: a dense 1-based array part plus an insertion-ordered key part.
///
/// Iteration order is deterministic (array part in index order, then keys in
/// insertion order), which matters because emerag scripts are expected to be
/// reproducible.
pub struct Table {
    arr: Vec<Value>,
    map: Vec<(Value, Value)>,
}

impl Default for Table {
    fn default() -> Table {
        Table::new()
    }
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Table")
            .field("array", &self.arr.len())
            .field("keys", &self.map.len())
            .finish()
    }
}

impl Table {
    pub fn new() -> Table {
        Table {
            arr: Vec::new(),
            map: Vec::new(),
        }
    }

    pub fn with_capacity(n: usize) -> Table {
        Table {
            arr: Vec::with_capacity(n),
            map: Vec::new(),
        }
    }

    /// Number of array elements, i.e. Lua's # operator (simple border).
    pub fn len(&self) -> usize {
        self.arr.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arr.is_empty() && self.map.is_empty()
    }

    /// Total number of stored pairs (array plus keyed).
    pub fn entry_count(&self) -> usize {
        self.arr.len() + self.map.len()
    }

    pub fn get(&self, key: &Value) -> Value {
        if let Value::Number(n) = key {
            if n.fract() == 0.0 && *n >= 1.0 && *n <= self.arr.len() as f64 {
                return self.arr[*n as usize - 1].clone();
            }
        }
        for (k, v) in &self.map {
            if key_eq(k, key) {
                return v.clone();
            }
        }
        Value::Nil
    }

    pub fn get_str(&self, key: &str) -> Value {
        for (k, v) in &self.map {
            if let Value::Str(s) = k {
                if s == key {
                    return v.clone();
                }
            }
        }
        Value::Nil
    }

    pub fn contains(&self, key: &Value) -> bool {
        if let Value::Number(n) = key {
            if n.fract() == 0.0 && *n >= 1.0 && *n <= self.arr.len() as f64 {
                return !self.arr[*n as usize - 1].is_nil();
            }
        }
        self.map.iter().any(|(k, _)| key_eq(k, key))
    }

    /// Raw set with Lua's semantics: nil removes, integral keys extend the
    /// array part, everything else goes into the key part.
    pub fn set(&mut self, key: Value, value: Value) {
        if let Value::Number(n) = key {
            if n.fract() == 0.0 && n >= 1.0 && n <= (self.arr.len() + 1) as f64 {
                let i = n as usize - 1;
                if i < self.arr.len() {
                    if value.is_nil() {
                        self.arr[i] = Value::Nil;
                        self.trim_tail();
                    } else {
                        self.arr[i] = value;
                    }
                    return;
                }
                // i == arr.len(): append
                if !value.is_nil() {
                    self.remove_map_key(&key);
                    self.arr.push(value);
                }
                return;
            }
        }
        if value.is_nil() {
            self.remove_map_key(&key);
            return;
        }
        if let Some(slot) = self.map.iter_mut().find(|(k, _)| key_eq(k, &key)) {
            slot.1 = value;
        } else {
            self.map.push((key, value));
        }
    }

    pub fn set_str(&mut self, key: &str, value: Value) {
        if let Some(slot) = self
            .map
            .iter_mut()
            .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
        {
            slot.1 = value;
            return;
        }
        if value.is_nil() {
            return;
        }
        self.map.push((Value::Str(key.to_string()), value));
    }

    pub fn clear(&mut self) {
        self.arr.clear();
        self.map.clear();
    }

    /// Snapshot of every pair, array part first.
    pub fn iter(&self) -> Vec<(Value, Value)> {
        let mut out = Vec::with_capacity(self.entry_count());
        for (i, v) in self.arr.iter().enumerate() {
            if !v.is_nil() {
                out.push((Value::Number((i + 1) as f64), v.clone()));
            }
        }
        for (k, v) in &self.map {
            out.push((k.clone(), v.clone()));
        }
        out
    }

    /// The pair after key (nil means "first"), for Lua's next().
    pub(crate) fn next_pair(&self, key: &Value) -> Option<(Value, Value)> {
        let mut started = key.is_nil();
        for (i, v) in self.arr.iter().enumerate() {
            if v.is_nil() {
                continue;
            }
            let k = Value::Number((i + 1) as f64);
            if started {
                return Some((k, v.clone()));
            }
            if key_eq(&k, key) {
                started = true;
            }
        }
        for (k, v) in &self.map {
            if started {
                return Some((k.clone(), v.clone()));
            }
            if key_eq(k, key) {
                started = true;
            }
        }
        None
    }

    fn trim_tail(&mut self) {
        while matches!(self.arr.last(), Some(v) if v.is_nil()) {
            self.arr.pop();
        }
    }

    fn remove_map_key(&mut self, key: &Value) {
        if let Some(pos) = self.map.iter().position(|(k, _)| key_eq(k, key)) {
            self.map.remove(pos);
        }
    }
}

/// Equality of table keys.
pub(crate) fn key_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Table(x), Value::Table(y)) => Rc::ptr_eq(x, y),
        (Value::Function(x), Value::Function(y)) => Rc::ptr_eq(x, y),
        (Value::Nil, Value::Nil) => true,
        _ => false,
    }
}

/// Native function signature: receives the interpreter (host, limits, rng).
pub(crate) type NativeFn = for<'h> fn(&mut Interp<'h>, Vec<Value>) -> IResult<Vec<Value>>;

/// How a function is implemented.
pub(crate) enum FnKind {
    /// A compiled Lua function plus its captured upvalues.
    Lua {
        proto: Rc<Proto>,
        upvals: Vec<Rc<RefCell<Value>>>,
    },
    /// A compiled-in stdlib function.
    Native(NativeFn),
    /// A host function placeholder (resolved through Host::call).
    Host(String),
    /// A stateful iterator created by string.gmatch.
    Gmatch(Rc<RefCell<crate::strlib::GmatchState>>),
}

/// A callable Lua function value.
pub struct Function {
    pub(crate) name: String,
    pub(crate) kind: FnKind,
}

impl Function {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn lua(name: String, proto: Rc<Proto>, upvals: Vec<Rc<RefCell<Value>>>) -> Function {
        Function {
            name,
            kind: FnKind::Lua { proto, upvals },
        }
    }

    pub(crate) fn native(name: &str, f: NativeFn) -> Function {
        Function {
            name: name.to_string(),
            kind: FnKind::Native(f),
        }
    }

    pub(crate) fn host(name: String) -> Function {
        Function {
            name: name.clone(),
            kind: FnKind::Host(name),
        }
    }

    pub(crate) fn gmatch(state: Rc<RefCell<crate::strlib::GmatchState>>) -> Function {
        Function {
            name: "gmatch iterator".to_string(),
            kind: FnKind::Gmatch(state),
        }
    }
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "function({})", self.name)
    }
}
