//! JSON value model.

use core::fmt;
use std::ops::Index;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Number {
    Int(i64),
    Float(f64),
}

impl Number {
    pub fn as_f64(self) -> f64 {
        match self {
            Number::Int(i) => i as f64,
            Number::Float(f) => f,
        }
    }

    pub fn as_i64(self) -> Option<i64> {
        match self {
            Number::Int(i) => Some(i),
            Number::Float(f)
                if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 =>
            {
                Some(f as i64)
            }
            Number::Float(_) => None,
        }
    }

    pub fn as_u64(self) -> Option<u64> {
        self.as_i64().and_then(|v| u64::try_from(v).ok())
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Number::Int(i) => write!(f, "{i}"),
            Number::Float(x) => crate::ser::write_f64(f, *x),
        }
    }
}

impl From<i64> for Number {
    fn from(v: i64) -> Self {
        Number::Int(v)
    }
}

impl From<f64> for Number {
    fn from(v: f64) -> Self {
        Number::Float(v)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Map),
}

impl Value {
    pub const NULL: Value = Value::Null;

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Value::Number(_))
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_str_or_default(&self) -> &str {
        self.as_str().unwrap_or("")
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(n.as_f64()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Map> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut Map> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn take(&mut self) -> Value {
        std::mem::take(self)
    }

    /// Key lookup for objects; returns Null for anything else.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|m| m.get(key))
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.as_object_mut().and_then(|m| m.get_mut(key))
    }

    pub fn get_path(&self, path: &[&str]) -> Option<&Value> {
        let mut cur = self;
        for key in path {
            cur = cur.get(key)?;
        }
        Some(cur)
    }

    pub fn as_str_at(&self, path: &[&str]) -> Option<&str> {
        self.get_path(path).and_then(|v| v.as_str())
    }

    pub fn as_u64_at(&self, path: &[&str]) -> Option<u64> {
        self.get_path(path).and_then(|v| v.as_u64())
    }

    pub fn as_array_at(&self, path: &[&str]) -> Option<&Vec<Value>> {
        self.get_path(path).and_then(|v| v.as_array())
    }
}

impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&Value::NULL)
    }
}

impl Index<usize> for Value {
    type Output = Value;
    fn index(&self, idx: usize) -> &Value {
        match self {
            Value::Array(a) => a.get(idx).unwrap_or(&Value::NULL),
            _ => &Value::NULL,
        }
    }
}

/// Insertion-ordered string map. JSON object key order is preserved, which
/// matters when proxying requests for strict providers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Map {
    entries: Vec<(String, Value)>,
}

impl Map {
    pub fn new() -> Self {
        Map {
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(n: usize) -> Self {
        Map {
            entries: Vec::with_capacity(n),
        }
    }

    pub fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        for (k, v) in self.entries.iter_mut() {
            if *k == key {
                return Some(std::mem::replace(v, value));
            }
        }
        self.entries.push((key, value));
        None
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let idx = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(idx).1)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &Value> {
        self.entries.iter().map(|(_, v)| v)
    }

    /// Merge another object into this one (right-hand side wins).
    pub fn extend(&mut self, other: &Map) {
        for (k, v) in other.iter() {
            self.insert(k.clone(), v.clone());
        }
    }
}

impl FromIterator<(String, Value)> for Map {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        let mut m = Map::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_order_and_replacement() {
        let mut m = Map::new();
        m.insert("b".into(), Value::from(1));
        m.insert("a".into(), Value::from(2));
        m.insert("b".into(), Value::from(3));
        let keys: Vec<&str> = m.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["b", "a"]);
        assert_eq!(m.get("b").unwrap().as_i64(), Some(3));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn accessors_are_safe() {
        let v = crate::parse(r#"{"a":{"b":[1,2,3]}}"#).unwrap();
        assert_eq!(
            v.get_path(&["a", "b"]).unwrap().as_array().unwrap().len(),
            3
        );
        assert_eq!(v["missing"]["deeper"], Value::Null);
        assert_eq!(v["a"]["b"][99], Value::Null);
    }
}
