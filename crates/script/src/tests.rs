//! Behavioural tests for emera script.
//!
//! These use a small mock host that provides a fake virtual filesystem, so the
//! same scripts the agent would run against a real machine can be exercised
//! deterministically.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::{run, ErrorKind, Host, Limits, Result, ScriptError, Table, Value};

struct TestHost {
    out: Rc<RefCell<String>>,
    files: BTreeMap<String, String>,
    env: BTreeMap<String, String>,
    calls: Rc<RefCell<Vec<String>>>,
}

impl TestHost {
    fn new() -> TestHost {
        TestHost {
            out: Rc::new(RefCell::new(String::new())),
            files: BTreeMap::new(),
            env: BTreeMap::new(),
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn with_file(mut self, path: &str, content: &str) -> TestHost {
        self.files.insert(path.to_string(), content.to_string());
        self
    }

    fn out(&self) -> String {
        self.out.borrow().clone()
    }
}

impl Host for TestHost {
    fn call(&mut self, name: &str, args: Vec<Value>) -> Result<Value> {
        self.calls.borrow_mut().push(name.to_string());
        match name {
            "os.getenv" => {
                let key = args.first().and_then(|v| v.as_str()).unwrap_or("");
                Ok(match self.env.get(key) {
                    Some(v) => Value::Str(v.clone()),
                    None => Value::Nil,
                })
            }
            "fs.read" => {
                let path = args.first().and_then(|v| v.as_str()).unwrap_or("");
                match self.files.get(path) {
                    Some(text) => Ok(Value::Str(text.clone())),
                    None => Err(ScriptError::host(format!("no such file: {path}"), 0)),
                }
            }
            "fs.write" => {
                let path = args
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let text = args
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                self.files.insert(path, text);
                Ok(Value::Bool(true))
            }
            "fs.exists" => {
                let path = args.first().and_then(|v| v.as_str()).unwrap_or("");
                Ok(Value::Bool(self.files.contains_key(path)))
            }
            "fs.size" => {
                let path = args.first().and_then(|v| v.as_str()).unwrap_or("");
                match self.files.get(path) {
                    Some(text) => Ok(Value::Number(text.len() as f64)),
                    None => Err(ScriptError::host(format!("no such file: {path}"), 0)),
                }
            }
            "fs.list" => {
                let raw = args
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string();
                let prefix = if raw.ends_with('/') {
                    raw
                } else {
                    format!("{raw}/")
                };
                let mut table = Table::new();
                let mut index = 1.0;
                for path in self.files.keys() {
                    if let Some(rest) = path.strip_prefix(&prefix) {
                        if !rest.is_empty() && !rest.contains('/') {
                            table.set(Value::Number(index), Value::Str(rest.to_string()));
                            index += 1.0;
                        }
                    }
                }
                Ok(Value::Table(Rc::new(RefCell::new(table))))
            }
            other => Err(ScriptError::host(
                format!("unknown host function: {other}"),
                0,
            )),
        }
    }

    fn print(&mut self, text: &str) {
        self.out.borrow_mut().push_str(text);
    }
}

fn run_in(src: &str, host: &mut TestHost, limits: Limits) -> Result<Value> {
    run(src, host, limits)
}

fn eval(src: &str) -> Value {
    let mut host = TestHost::new();
    match run_in(src, &mut host, Limits::default()) {
        Ok(value) => value,
        Err(e) => panic!("script failed: {e}\n-- source --\n{src}"),
    }
}

fn eval_host(src: &str, host: &mut TestHost) -> Value {
    match run_in(src, host, Limits::default()) {
        Ok(value) => value,
        Err(e) => panic!("script failed: {e}\n-- source --\n{src}"),
    }
}

fn fails(src: &str) -> ScriptError {
    let mut host = TestHost::new();
    match run_in(src, &mut host, Limits::default()) {
        Ok(value) => panic!("expected failure, got {value:?}\n-- source --\n{src}"),
        Err(e) => e,
    }
}

fn num(src: &str) -> f64 {
    match eval(src) {
        Value::Number(n) => n,
        other => panic!("expected a number from {src:?}, got {other:?}"),
    }
}

fn text(src: &str) -> String {
    match eval(src) {
        Value::Str(s) => s,
        other => panic!("expected a string from {src:?}, got {other:?}"),
    }
}

fn output(src: &str) -> String {
    let mut host = TestHost::new();
    let _ = run_in(src, &mut host, Limits::default());
    host.out()
}

// ---- literals, precedence, numbers -------------------------------------

#[test]
fn integer_and_float_semantics() {
    assert_eq!(num("return 1//2"), 0.0);
    assert_eq!(num("return 7//2"), 3.0);
    assert_eq!(num("return -7//2"), -4.0);
    assert_eq!(num("return -7%3"), 2.0);
    assert_eq!(num("return 7%-3"), -2.0);
    assert_eq!(num("return 2^10"), 1024.0);
    assert_eq!(num("return 2^3^2"), 512.0);
    assert_eq!(num("return -2^2"), -4.0);
    assert_eq!(num("return 10/4"), 2.5);
    assert_eq!(num("return 3 == 3.0 and 1 or 0"), 1.0);
    assert_eq!(num("return '10' + 5"), 15.0);
    assert_eq!(num("return '3.5' * 2"), 7.0);
    assert_eq!(num("return 0x10 + 0x1p4"), 32.0);
    assert_eq!(num("return 1e3 / 8"), 125.0);
}

#[test]
fn precedence_and_associativity() {
    assert_eq!(num("return 1 + 2 * 3"), 7.0);
    assert_eq!(num("return (1 + 2) * 3"), 9.0);
    assert_eq!(num("return 2 + 3 * 4 ^ 2"), 50.0);
    assert_eq!(
        num("return (1 < 2 and 2 <= 2 and not false) and 1 or 0"),
        1.0
    );
    assert_eq!(text("return 1 .. 2 .. 3"), "123");
    assert_eq!(text("return 'a' .. 1 + 1"), "a2");
    assert_eq!(num("return 1 + 2 == 3 and 10 or 20"), 10.0);
    assert_eq!(text("return 'x' .. ('y' .. 'z')"), "xyz");
    assert_eq!(num("return 3 - 2 - 1"), 0.0);
    assert_eq!(num("return 2^-2 * 4"), 1.0);
}

#[test]
fn number_to_string_semantics() {
    assert_eq!(text("return tostring(3)"), "3");
    assert_eq!(text("return tostring(3.5)"), "3.5");
    assert_eq!(text("return tostring(2^10)"), "1024");
    assert_eq!(text("return tostring(1/3)"), "0.33333333333333");
    assert_eq!(text("return tostring(-0.0)"), "-0");
    assert_eq!(text("return 100 .. ''"), "100");
}

#[test]
fn string_escapes_and_long_strings() {
    assert_eq!(text(r#"return "a\tb\nc""#), "a\tb\nc");
    assert_eq!(text(r#"return '\65\66\67'"#), "ABC");
    assert_eq!(text(r#"return "\x41\x42""#), "AB");
    assert_eq!(text(r#"return "\u{48}\u{49}""#), "HI");
    assert_eq!(
        text(
            r#"return "a\z
          b""#
        ),
        "ab"
    );
    assert_eq!(text("return [[hello\nworld]]"), "hello\nworld");
    assert_eq!(text("return [==[a]]b]==]"), "a]]b");
    assert_eq!(text("return [[\nfirst line]]"), "first line");
    assert_eq!(num("return #\"hello\""), 5.0);
    assert_eq!(num(r#"return #"é""#), 2.0);
}

#[test]
fn comments_are_ignored() {
    assert_eq!(num("-- one\nreturn 1 --[[ block\ncomment ]] + 1"), 2.0);
    assert_eq!(num("return 1 --[[x]] + 2"), 3.0);
}

// ---- control flow ------------------------------------------------------

#[test]
fn conditionals_and_loops() {
    assert_eq!(
        num("local x = 5 if x > 3 then return 1 elseif x > 1 then return 2 else return 3 end"),
        1.0
    );
    assert_eq!(
        num("local x = 2 if x > 3 then return 1 elseif x > 1 then return 2 else return 3 end"),
        2.0
    );
    assert_eq!(
        num("local x = 0 if x > 3 then return 1 elseif x > 1 then return 2 else return 3 end"),
        3.0
    );
    assert_eq!(
        num("local s = 0 local i = 1 while i <= 5 do s = s + i i = i + 1 end return s"),
        15.0
    );
    assert_eq!(
        num("local s = 0 repeat s = s + 1 until s >= 4 return s"),
        4.0
    );
    assert_eq!(
        num("local s = 0 for i = 1, 10, 2 do s = s + i end return s"),
        25.0
    );
    assert_eq!(
        num("local s = 0 for i = 10, 1, -2 do s = s + i end return s"),
        30.0
    );
    assert_eq!(num("local s = 0 for i = 1, 3 do for j = 1, 3 do if j == 2 then break end s = s + 1 end end return s"), 3.0);
    assert_eq!(num("local s = 0 do local x = 5 s = x end return s"), 5.0);
}

#[test]
fn nested_break_only_leaves_inner_loop() {
    let src = r#"
        local hits = 0
        for i = 1, 3 do
            for j = 1, 10 do
                if j > 2 then break end
                hits = hits + 1
            end
        end
        return hits
    "#;
    assert_eq!(num(src), 6.0);
}

// ---- functions, closures, varargs -------------------------------------

#[test]
fn recursion_factorial_and_fib() {
    assert_eq!(
        num("local function f(n) if n <= 1 then return 1 end return n * f(n - 1) end return f(10)"),
        3628800.0
    );
    assert_eq!(num("local function fib(n) if n < 2 then return n end return fib(n-1) + fib(n-2) end return fib(15)"), 610.0);
    assert_eq!(num("function g(n) return n + 1 end return g(41)"), 42.0);
}

#[test]
fn closures_share_upvalues() {
    let src = r#"
        local function counter()
            local n = 0
            return function() n = n + 1 return n end
        end
        local c = counter()
        c() c()
        return c()
    "#;
    assert_eq!(num(src), 3.0);
}

#[test]
fn two_closures_share_one_upvalue() {
    let src = r#"
        local n = 0
        local inc = function() n = n + 1 end
        local get = function() return n end
        inc() inc() inc()
        return get()
    "#;
    assert_eq!(num(src), 3.0);
}

#[test]
fn loop_closures_capture_per_iteration_values() {
    let src = r#"
        local fs = {}
        for i = 1, 3 do fs[i] = function() return i end end
        return fs[1]() + fs[2]() * 10 + fs[3]() * 100
    "#;
    assert_eq!(num(src), 321.0);
}

#[test]
fn shadowing_and_globals() {
    assert_eq!(
        num("x = 5 local function f() return x end x = 7 return f()"),
        7.0
    );
    assert_eq!(num("local x = 1 do local x = 2 x = 3 end return x"), 1.0);
    assert_eq!(
        num("local a = 1 local b = 2 a, b = b, a return a * 10 + b"),
        21.0
    );
    assert_eq!(num("local t = {} t.a, t.b = 1, 2 return t.a + t.b"), 3.0);
}

#[test]
fn multiple_returns_and_varargs() {
    assert_eq!(
        num("local function f() return 1, 2, 3 end local a, b, c = f() return a + b + c"),
        6.0
    );
    assert_eq!(
        num("local function f() return 1, 2 end local t = {f()} return #t"),
        2.0
    );
    assert_eq!(
        num("local function f() return 1, 2 end local t = {f(), 10} return #t"),
        2.0
    );
    assert_eq!(num("local function f() return 1, 2 end return (f())"), 1.0);
    assert_eq!(
        num("local function f() return 1, 2 end local t = {(f())} return #t"),
        1.0
    );
    assert_eq!(
        num("local function f() return 1, 2 end local a, b = (f()) return b == nil and 1 or 0"),
        1.0
    );
    assert_eq!(
        num("local function f() return 1, 2 end local a, b = f(), 9 return b"),
        9.0
    );
    assert_eq!(num("local function sum(...) local s = 0 for i = 1, select('#', ...) do s = s + select(i, ...) end return s end return sum(1,2,3,4)"), 10.0);
    assert_eq!(
        num("local function f(...) return ... end return f(7, 8, 9)"),
        7.0
    );
    assert_eq!(text("local function f(a, ...) return a .. table.concat({...}, '-') end return f('x', 'y', 'z')"), "xy-z");
    assert_eq!(num("return select('#', 1, nil, 3)"), 3.0);
    assert_eq!(
        num("return select(2, 'a', 'b', 'c') == 'b' and 1 or 0"),
        1.0
    );
}

// ---- tables ------------------------------------------------------------

#[test]
fn table_constructors_and_nesting() {
    assert_eq!(num("local t = {1, 2, x = 3, [4] = 5, nested = {a = {b = 7}}} return t[1] + t[2] + t.x + t[4] + t.nested.a.b"), 18.0);
    assert_eq!(
        num("local t = {} for i = 1, 5 do t[i] = i * i end return #t + t[5]"),
        30.0
    );
    assert_eq!(
        text("local t = {a = 'x'} t['b'] = 'y' return t.a .. t.b"),
        "xy"
    );
    assert_eq!(num("local t = {1, 2, 3} t[3] = nil return #t"), 2.0);
    assert_eq!(num("local t = {[1] = 'a', [2] = 'b'} return #t"), 2.0);
    assert_eq!(
        text("local t = { 'a', 'b', 'c' } return table.concat(t, '')"),
        "abc"
    );
}

#[test]
fn pairs_and_ipairs_are_order_independent() {
    let src = r#"
        local t = { a = 1, b = 2, c = 3 }
        local sum = 0
        local count = 0
        for k, v in pairs(t) do
            sum = sum + v
            count = count + 1
        end
        return sum * 10 + count
    "#;
    assert_eq!(num(src), 63.0);

    let src = r#"
        local t = { 'x', 'y', 'z' }
        local out = ''
        for i, v in ipairs(t) do out = out .. i .. v end
        return out
    "#;
    assert_eq!(text(src), "1x2y3z");

    let src = r#"
        local t = { 10, 20, 30 }
        local total = 0
        local k, v = next(t)
        while k ~= nil do
            total = total + v
            k, v = next(t, k)
        end
        return total
    "#;
    assert_eq!(num(src), 60.0);
}

#[test]
fn table_library() {
    assert_eq!(
        num("local t = {1,2,3} table.insert(t, 4) return #t * 10 + t[4]"),
        44.0
    );
    assert_eq!(
        text("local t = {'a','b'} table.insert(t, 1, 'z') return table.concat(t, '')"),
        "zab"
    );
    assert_eq!(
        num("local t = {1,2,3} local v = table.remove(t) return v * 10 + #t"),
        32.0
    );
    assert_eq!(
        text(
            "local t = {'a','b','c'} local v = table.remove(t, 1) return v .. table.concat(t, '')"
        ),
        "abc"
    );
    assert_eq!(
        text("local t = {1, 2, 3} return table.concat(t, '-')"),
        "1-2-3"
    );
    assert_eq!(
        text("local t = {1, 2, 3} return table.concat(t, ',', 2, 3)"),
        "2,3"
    );
    assert_eq!(
        num("local t = {3,1,2} table.sort(t) return t[1] * 100 + t[2] * 10 + t[3]"),
        123.0
    );
    assert_eq!(num("local t = {3,1,2} table.sort(t, function(a, b) return a > b end) return t[1] * 100 + t[2] * 10 + t[3]"), 321.0);
    assert_eq!(
        num("local a, b, c = table.unpack({7, 8, 9}) return a + b + c"),
        24.0
    );
    assert_eq!(num("local t = table.pack(1, 2, 3) return t.n"), 3.0);
    assert_eq!(num("local t = {} return table.len(t)"), 0.0);
}

// ---- methods -----------------------------------------------------------

#[test]
fn method_calls_and_self() {
    let src = r#"
        local obj = { v = 10 }
        function obj:add(x) return self.v + x end
        function obj:get() return self.v end
        return obj:add(5) + obj:get()
    "#;
    assert_eq!(num(src), 25.0);

    let src = r#"
        local account = { balance = 5 }
        function account:deposit(n) self.balance = self.balance + n return self end
        account:deposit(3):deposit(2)
        return account.balance
    "#;
    assert_eq!(num(src), 10.0);
}

// ---- strings -----------------------------------------------------------

#[test]
fn string_functions() {
    assert_eq!(num("return string.len('hello')"), 5.0);
    assert_eq!(text("return string.sub('hello', 2, 4)"), "ell");
    assert_eq!(text("return string.sub('hello', -3)"), "llo");
    assert_eq!(text("return string.sub('hello', 2)"), "ello");
    assert_eq!(text("return string.sub('hello', 0, 1)"), "h");
    assert_eq!(text("return string.sub('hello', 4, 2)"), "");
    assert_eq!(num("return ('A'):byte()"), 65.0);
    assert_eq!(
        num("local a, b = string.byte('AB', 1, 2) return a * 100 + b"),
        6566.0
    );
    assert_eq!(text("return string.char(72, 105)"), "Hi");
    assert_eq!(text("return string.rep('ab', 3)"), "ababab");
    assert_eq!(text("return string.rep('a', 3, '-')"), "a-a-a");
    assert_eq!(text("return string.rep('x', 0)"), "");
    assert_eq!(text("return string.reverse('abc')"), "cba");
    assert_eq!(text("return string.upper('aBc')"), "ABC");
    assert_eq!(text("return string.lower('aBc')"), "abc");
    assert_eq!(text("return ('x'):rep(3)"), "xxx");
}

#[test]
fn string_format_all_specifiers() {
    assert_eq!(text("return string.format('%d', 42)"), "42");
    assert_eq!(text("return string.format('%i', -7)"), "-7");
    assert_eq!(text("return string.format('%5d', 42)"), "   42");
    assert_eq!(text("return string.format('%-5d|', 42)"), "42   |");
    assert_eq!(text("return string.format('%05d', 42)"), "00042");
    assert_eq!(text("return string.format('%+d', 42)"), "+42");
    assert_eq!(text("return string.format('% d', 42)"), " 42");
    assert_eq!(text("return string.format('%x', 255)"), "ff");
    assert_eq!(text("return string.format('%X', 255)"), "FF");
    assert_eq!(text("return string.format('%#x', 255)"), "0xff");
    assert_eq!(text("return string.format('%o', 8)"), "10");
    assert_eq!(text("return string.format('%#o', 8)"), "010");
    assert_eq!(text("return string.format('%c', 65)"), "A");
    assert_eq!(text("return string.format('%f', 1.5)"), "1.500000");
    assert_eq!(text("return string.format('%.2f', 3.14159)"), "3.14");
    assert_eq!(text("return string.format('%8.2f', 3.14159)"), "    3.14");
    assert_eq!(text("return string.format('%g', 0.5)"), "0.5");
    assert_eq!(text("return string.format('%g', 100)"), "100");
    assert_eq!(text("return string.format('%.3g', 3.14159)"), "3.14");
    assert_eq!(text("return string.format('%e', 1234.5)"), "1.234500e+03");
    assert_eq!(text("return string.format('%E', 1234.5)"), "1.234500E+03");
    assert_eq!(text("return string.format('%s', 'x')"), "x");
    assert_eq!(text("return string.format('%s', 12)"), "12");
    assert_eq!(text("return string.format('%5s', 'x')"), "    x");
    assert_eq!(text("return string.format('%-5s|', 'x')"), "x    |");
    assert_eq!(text("return string.format('%.2s', 'abcdef')"), "ab");
    assert_eq!(text("return string.format('%%')"), "%");
    assert_eq!(text(r#"return string.format('%q', 'a"b')"#), r#""a\"b""#);
    assert_eq!(text(r#"return string.format("%q", "a\nb")"#), r#""a\nb""#);
    assert_eq!(text("return string.format('%s=%d', 'n', 3)"), "n=3");
}

// ---- patterns ----------------------------------------------------------

#[test]
fn pattern_find_and_match() {
    assert_eq!(
        text("local a, b = string.find('hello world', 'world') return a .. ',' .. b"),
        "7,11"
    );
    assert_eq!(
        text("return string.find('abc', 'xyz') == nil and 'none' or 'found'"),
        "none"
    );
    assert_eq!(text("return string.match('hello 123', '%d+')"), "123");
    assert_eq!(text("return string.match('hello 123', '%a+')"), "hello");
    assert_eq!(
        text("local k, v = string.match('key=value', '(%w+)=(%w+)') return k .. ':' .. v"),
        "key:value"
    );
    assert_eq!(
        text("return string.match('xabc', '^abc') == nil and 'no' or 'yes'"),
        "no"
    );
    assert_eq!(text("return string.match('abc', '^abc')"), "abc");
    assert_eq!(text("return string.match('abc', 'bc$')"), "bc");
    assert_eq!(
        text("return string.match('abc', 'ab$') == nil and 'no' or 'yes'"),
        "no"
    );
    assert_eq!(text("return string.match('f(a(b)c)d', '%b()')"), "(a(b)c)");
    assert_eq!(text("return string.match('abcabc', '(abc)%1')"), "abc");
    assert_eq!(
        text("return string.match('abcabd', '(abc)%1') == nil and 'no' or 'yes'"),
        "no"
    );
    assert_eq!(text("return string.match('a1b2', '[%a%d]+')"), "a1b2");
    assert_eq!(
        text("return string.match('abc', '[^a-c]+') == nil and 'no' or 'yes'"),
        "no"
    );
    assert_eq!(num("local p = string.match('abc', '()b()') return p"), 2.0);
    assert_eq!(
        text("local a, b = string.match('abc', '()b()') return a .. ',' .. b"),
        "2,3"
    );
    assert_eq!(text("return string.match('a.b', '%p')"), ".");
    assert_eq!(num("return string.find('a.b', '.', 1, true)"), 2.0);
    assert_eq!(num("return string.find('abcabc', 'b', 3)"), 5.0);
    assert_eq!(num("return string.find('abc', '', 1)"), 1.0);
    assert_eq!(text("return string.match('<a><b>', '<.->')"), "<a>");
    assert_eq!(text("return string.match('<a><b>', '<.*>')"), "<a><b>");
}

#[test]
fn pattern_gmatch_and_gsub() {
    let src = r#"
        local words = {}
        for w in string.gmatch('one two three', '%a+') do words[#words + 1] = w end
        return table.concat(words, ',')
    "#;
    assert_eq!(text(src), "one,two,three");

    let src = r#"
        local pairs_found = 0
        for k, v in string.gmatch('a=1,b=2', '(%w+)=(%w+)') do pairs_found = pairs_found + 1 end
        return pairs_found
    "#;
    assert_eq!(num(src), 2.0);

    // Lua 5.4 skips an empty match where the previous match ended.
    let src = r#"
        local parts = {}
        for w in string.gmatch('abc  de', '%a*') do parts[#parts + 1] = '[' .. w .. ']' end
        return table.concat(parts)
    "#;
    assert_eq!(text(src), "[abc][][de]");

    assert_eq!(
        text("local s, n = string.gsub('hello world', 'o', '0') return s .. n"),
        "hell0 w0rld2"
    );
    assert_eq!(
        text("local s, n = string.gsub('abc', '%w', '%0%0') return s"),
        "aabbcc"
    );
    assert_eq!(
        text("local s = string.gsub('hello', 'l+', 'L') return s"),
        "heLo"
    );
    assert_eq!(
        text("local s = string.gsub('a b c', '%s', '_') return s"),
        "a_b_c"
    );
    assert_eq!(
        text("local s = string.gsub('abc', '', '-') return s"),
        "-a-b-c-"
    );
    assert_eq!(
        text("local s, n = string.gsub('aaa', 'a', 'b', 2) return s .. n"),
        "bba2"
    );

    let src = r#"
        local map = { cat = 'dog', bird = 'fish' }
        local s = string.gsub('cat and bird', '%a+', map)
        return s
    "#;
    assert_eq!(text(src), "dog and fish");

    let src = r#"
        local s = string.gsub('1 2 3', '%d', function(d) return tostring(tonumber(d) * 2) end)
        return s
    "#;
    assert_eq!(text(src), "2 4 6");

    let src = r#"
        local out = {}
        for a, b in string.gmatch('x=1 y=2', '(%a)=(%d)') do
            out[#out + 1] = b .. a
        end
        return table.concat(out, ' ')
    "#;
    assert_eq!(text(src), "1x 2y");
}

#[test]
fn malformed_patterns_are_errors() {
    let err = fails("return string.find('x', '[abc')");
    assert_eq!(err.kind, ErrorKind::Runtime);
    assert!(err.message.contains("malformed") || err.message.contains("pattern"));
}

// ---- errors and pcall --------------------------------------------------

#[test]
fn pcall_catches_errors() {
    let src = r#"
        local ok, err = pcall(function() error('boom') end)
        return tostring(ok) .. '|' .. err
    "#;
    assert_eq!(text(src), "false|script:2: boom");

    let src = r#"
        local ok, a, b = pcall(function() return 1, 2 end)
        return tostring(ok) .. '|' .. a .. b
    "#;
    assert_eq!(text(src), "true|12");

    let src = r#"
        local ok, err = pcall(function() return nil + 1 end)
        return tostring(ok) .. '|' .. tostring(err ~= nil)
    "#;
    assert_eq!(text(src), "false|true");
}

#[test]
fn error_with_table_values() {
    let src = r#"
        local ok, e = pcall(function() error({ code = 42 }) end)
        return tostring(ok) .. '|' .. type(e) .. '|' .. e.code
    "#;
    assert_eq!(text(src), "false|table|42");

    let src = r#"
        local ok, e = pcall(function() error({ code = 7 }, 0) end)
        return tostring(ok) .. '|' .. e.code
    "#;
    assert_eq!(text(src), "false|7");
}

#[test]
fn assert_and_runtime_errors() {
    let err = fails("assert(false, 'nope')");
    assert_eq!(err.kind, ErrorKind::Runtime);
    assert!(err.message.contains("nope"));

    let err = fails("return nil + 1");
    assert!(err.message.contains("arithmetic"));

    let err = fails("local x = nil\nreturn x.y");
    assert_eq!(err.line, 2);
    assert!(err.message.contains("index"));

    let err = fails("return #5");
    assert!(err.message.contains("length"));
}

#[test]
fn xpcall_uses_the_handler() {
    let src = r#"
        local ok, e = xpcall(function() error('bad') end, function(err) return 'handled: ' .. err end)
        return tostring(ok) .. '|' .. e
    "#;
    assert_eq!(text(src), "false|handled: script:2: bad");
}

#[test]
fn unknown_host_function_names_the_host() {
    let err = fails("return nope(1)");
    assert_eq!(err.kind, ErrorKind::Host);
    assert!(err.message.contains("nope"));
    assert!(err.message.contains("host"));

    let err = fails("return fs.nonexistent('/x')");
    assert_eq!(err.kind, ErrorKind::Host);
    assert!(err.message.contains("fs.nonexistent"));
}

// ---- limits ------------------------------------------------------------

#[test]
fn instruction_limit_terminates_infinite_loops() {
    let mut host = TestHost::new();
    let limits = Limits {
        max_instructions: 10_000,
        max_output_bytes: 0,
        wall_clock_ms: 0,
    };
    let err = run_in("while true do end", &mut host, limits).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Limit);
    assert!(err.message.contains("instruction"));

    let mut host = TestHost::new();
    let limits = Limits {
        max_instructions: 5_000,
        max_output_bytes: 0,
        wall_clock_ms: 0,
    };
    let err = run_in(
        "local function f() return f() end return f()",
        &mut host,
        limits,
    )
    .unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Limit));
}

#[test]
fn output_limit_terminates_chatty_scripts() {
    let mut host = TestHost::new();
    let limits = Limits {
        max_instructions: 0,
        max_output_bytes: 64,
        wall_clock_ms: 0,
    };
    let err = run_in(
        "for i = 1, 100 do print('0123456789') end",
        &mut host,
        limits,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Limit);
    assert!(err.message.contains("output"));
    assert!(host.out().len() <= 64);
}

#[test]
fn wall_clock_limit_terminates() {
    let mut host = TestHost::new();
    let limits = Limits {
        max_instructions: 0,
        max_output_bytes: 0,
        wall_clock_ms: 1,
    };
    let err = run_in("local x = 0 while true do x = x + 1 end", &mut host, limits).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Limit);
    assert!(err.message.contains("wall clock"));
}

#[test]
fn recursion_depth_is_bounded() {
    let mut host = TestHost::new();
    let err = run_in(
        "local function f(n) return f(n + 1) end return f(1)",
        &mut host,
        Limits::default(),
    )
    .unwrap_err();
    assert!(err.message.contains("stack overflow"));
    assert!(err.line > 0);
}

#[test]
fn table_size_is_bounded() {
    let mut host = TestHost::new();
    let limits = Limits::default();
    let err = run_in(
        "local t = {} local i = 1 while true do t[i] = i i = i + 1 end",
        &mut host,
        limits,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Limit);
}

// ---- parse errors ------------------------------------------------------

#[test]
fn syntax_errors_report_line_and_column() {
    let err = fails("local x = 1\nlocal = 2");
    assert_eq!(err.kind, ErrorKind::Syntax);
    assert_eq!(err.line, 2);
    assert!(err.column > 0);

    let err = fails("if x then\nend\nend");
    assert_eq!(err.kind, ErrorKind::Syntax);
    assert_eq!(err.line, 3);

    let err = fails("local s = 'unterminated");
    assert_eq!(err.kind, ErrorKind::Syntax);
    assert_eq!(err.line, 1);

    let err = fails("return 1 +");
    assert_eq!(err.kind, ErrorKind::Syntax);

    let err = fails("break");
    assert_eq!(err.kind, ErrorKind::Syntax);
    assert!(err.message.contains("break"));
}

#[test]
fn deeply_nested_expressions_return_err() {
    let depth = 5000;
    let mut src = String::with_capacity(depth * 2 + 16);
    for _ in 0..depth {
        src.push('(');
    }
    src.push('1');
    for _ in 0..depth {
        src.push(')');
    }
    let err = fails(&src);
    assert_eq!(err.kind, ErrorKind::Syntax);
    assert!(err.message.contains("deep"));

    let mut src = String::new();
    for _ in 0..depth {
        src.push_str("{ ");
    }
    src.push('1');
    for _ in 0..depth {
        src.push_str(" }");
    }
    let err = fails(&format!("return {src}"));
    assert_eq!(err.kind, ErrorKind::Syntax);
}

#[test]
fn long_flat_expressions_are_fine() {
    let mut src = String::from("return ");
    for i in 0..500 {
        if i > 0 {
            src.push('+');
        }
        src.push('1');
    }
    assert_eq!(num(&src), 500.0);
}

// ---- host integration --------------------------------------------------

#[test]
fn print_routes_to_host_with_tostring_semantics() {
    assert_eq!(
        output("print('a', 1, 1.5, true, nil)"),
        "a\t1\t1.5\ttrue\tnil\n"
    );
    assert_eq!(output("print(2^10)"), "1024\n");
    assert_eq!(output("io.write('x')"), "");
}

#[test]
fn os_getenv_uses_the_host() {
    let mut host = TestHost::new();
    host.env.insert("EMERAG".to_string(), "1".to_string());
    assert_eq!(
        eval_host("return os.getenv('EMERAG')", &mut host),
        Value::Str("1".to_string())
    );
    assert_eq!(
        eval_host(
            "return os.getenv('MISSING') == nil and 'nil' or 'set'",
            &mut host
        ),
        Value::Str("nil".to_string())
    );
}

#[test]
fn os_time_and_clock_are_numbers() {
    assert!(matches!(eval("return os.time()"), Value::Number(n) if n > 1_600_000_000.0));
    assert!(matches!(eval("return os.clock()"), Value::Number(n) if n >= 0.0));
}

#[test]
fn fake_filesystem_walk() {
    let mut host = TestHost::new()
        .with_file("/data/a.txt", "hello world")
        .with_file("/data/b.txt", "one two three");
    let src = r#"
        local names = fs.list('/data')
        local total = 0
        local report = {}
        for _, name in ipairs(names) do
            local path = '/data/' .. name
            local text = fs.read(path)
            if text then
                local words = 0
                for _ in string.gmatch(text, '%a+') do words = words + 1 end
                total = total + words
                table.insert(report, string.format('%s=%d', name, words))
            end
        end
        table.sort(report)
        fs.write('/data/summary.txt', table.concat(report, ',') .. ' total=' .. total)
        return total
    "#;
    let value = eval_host(src, &mut host);
    assert_eq!(value, Value::Number(5.0));
    assert_eq!(
        host.files.get("/data/summary.txt").map(|s| s.as_str()),
        Some("a.txt=2,b.txt=3 total=5")
    );
    assert!(host.calls.borrow().iter().any(|c| c == "fs.write"));
}

#[test]
fn host_errors_are_catchable() {
    let mut host = TestHost::new();
    let src = r#"
        local ok, err = pcall(function() return fs.read('/nope') end)
        return tostring(ok) .. '|' .. tostring(err ~= nil)
    "#;
    assert_eq!(
        eval_host(src, &mut host),
        Value::Str("false|true".to_string())
    );
}

#[test]
fn host_namespaces_can_be_extended_from_script() {
    let mut host = TestHost::new();
    let src = r#"
        fs.custom = function(x) return 'custom:' .. x end
        return fs.custom('ok')
    "#;
    assert_eq!(
        eval_host(src, &mut host),
        Value::Str("custom:ok".to_string())
    );
}

// ---- misc --------------------------------------------------------------

#[test]
fn type_and_tonumber() {
    assert_eq!(text("return type(nil) .. ',' .. type(true) .. ',' .. type(1) .. ',' .. type('s') .. ',' .. type({}) .. ',' .. type(print)"), "nil,boolean,number,string,table,function");
    assert_eq!(num("return tonumber('42')"), 42.0);
    assert_eq!(num("return tonumber('0x10')"), 16.0);
    assert_eq!(text("return tostring(tonumber('abc'))"), "nil");
    assert_eq!(num("return tonumber('ff', 16)"), 255.0);
    assert_eq!(num("return tonumber('z', 36)"), 35.0);
    assert_eq!(num("return tonumber('  7  ')"), 7.0);
    assert_eq!(num("return tonumber(3.5)"), 3.5);
}

#[test]
fn math_library() {
    assert_eq!(num("return math.abs(-3)"), 3.0);
    assert_eq!(num("return math.floor(2.9)"), 2.0);
    assert_eq!(num("return math.ceil(2.1)"), 3.0);
    assert_eq!(num("return math.sqrt(16)"), 4.0);
    assert_eq!(num("return math.min(3, 1, 2)"), 1.0);
    assert_eq!(num("return math.max(3, 1, 2)"), 3.0);
    assert_eq!(num("return math.pi > 3.14 and 1 or 0"), 1.0);
    assert_eq!(num("return math.huge > 1e300 and 1 or 0"), 1.0);
    assert_eq!(
        text("return math.type(3) .. ',' .. math.type(3.5) .. ',' .. tostring(math.type('x'))"),
        "integer,float,nil"
    );
    let src = r#"
        math.randomseed(1234)
        local a = math.random(1, 100)
        math.randomseed(1234)
        local b = math.random(1, 100)
        return a == b and a >= 1 and a <= 100 and 1 or 0
    "#;
    assert_eq!(num(src), 1.0);
    assert!(num("return math.random()") < 1.0);
    assert!(num("return math.random(6)") >= 1.0);
}

#[test]
fn rawequal_and_rawlen() {
    assert_eq!(num("local t = {1,2} return rawlen(t)"), 2.0);
    assert_eq!(num("return rawequal(1, 1) and 1 or 0"), 1.0);
    assert_eq!(
        num("local t = {} rawset(t, 'k', 5) return rawget(t, 'k')"),
        5.0
    );
}

#[test]
fn panic_free_on_garbage_input() {
    // Random bytes and truncated programs must return errors, never panic.
    let samples = [
        "\u{0}",
        "local function",
        "((((",
        "return 1e",
        "return '\\999'",
        "for for for",
        "return ...",
        "return function() end end",
        "t = {} t[nil] = 1",
        "return 'x' .. {}",
        "return {[1/0] = 1}",
        "local a = 1 local a = 2",
    ];
    for src in samples {
        let mut host = TestHost::new();
        let _ = run_in(
            src,
            &mut host,
            Limits {
                max_instructions: 100_000,
                max_output_bytes: 1024,
                wall_clock_ms: 0,
            },
        );
    }
}

#[test]
fn script_return_value_is_first_result() {
    assert_eq!(eval("return 1, 2, 3"), Value::Number(1.0));
    assert_eq!(eval("local x = 1"), Value::Nil);
    assert_eq!(eval("return 'text'"), Value::Str("text".to_string()));
}

// ---- robustness --------------------------------------------------------

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn random_programs_never_panic() {
    let alphabet: &[&str] = &[
        "local",
        "function",
        "end",
        "if",
        "then",
        "else",
        "elseif",
        "for",
        "in",
        "do",
        "while",
        "repeat",
        "until",
        "return",
        "break",
        "and",
        "or",
        "not",
        "nil",
        "true",
        "false",
        "1",
        "2.5",
        "0x10",
        "'s'",
        "[[x]]",
        "{",
        "}",
        "(",
        ")",
        "[",
        "]",
        "=",
        "==",
        "~=",
        "..",
        "...",
        "+",
        "-",
        "*",
        "/",
        "//",
        "%",
        "^",
        "#",
        ",",
        ";",
        ":",
        ".",
        "x",
        "y",
        "t",
        "print",
        "table",
        "string",
        "pairs",
        "ipairs",
        "select",
        "error",
        "pcall",
        "tonumber",
        "type",
        "math.random",
        "fs.read",
        "'/x'",
        "{}",
        "()",
    ];
    let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
    for _ in 0..800 {
        let mut src = String::new();
        let tokens = (xorshift(&mut seed) % 40) as usize;
        for _ in 0..tokens {
            src.push_str(alphabet[(xorshift(&mut seed) as usize) % alphabet.len()]);
            src.push(' ');
        }
        let mut host = TestHost::new();
        let _ = run_in(
            &src,
            &mut host,
            Limits {
                max_instructions: 20_000,
                max_output_bytes: 4096,
                wall_clock_ms: 500,
            },
        );
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut seed: u64 = 0x0BAD_C0DE_DEAD_BEEF;
    let mut samples: Vec<String> = Vec::new();
    for _ in 0..400 {
        let len = (xorshift(&mut seed) % 60) as usize;
        let mut s = String::new();
        for _ in 0..len {
            let n = (xorshift(&mut seed) % 96) as u32;
            let ch = char::from_u32(0x20 + n).unwrap_or('?');
            s.push(ch);
        }
        samples.push(s);
    }
    for src in samples {
        let mut host = TestHost::new();
        let _ = run_in(
            &src,
            &mut host,
            Limits {
                max_instructions: 10_000,
                max_output_bytes: 1024,
                wall_clock_ms: 200,
            },
        );
    }
}

#[test]
fn catastrophic_backtracking_is_bounded() {
    let mut host = TestHost::new();
    let start = std::time::Instant::now();
    let src =
        "return string.match('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'a*a*a*a*a*a*a*a*a*a*a*a*b')";
    let result = run_in(src, &mut host, Limits::default());
    assert!(result.is_err(), "pathological pattern must be rejected");
    assert!(start.elapsed().as_millis() < 5000);
}

#[test]
fn long_literal_patterns_still_match() {
    let pattern = "a".repeat(400);
    let subject = "a".repeat(400);
    let src = format!("return string.match('{subject}', '{pattern}')");
    let mut host = TestHost::new();
    assert_eq!(
        run_in(&src, &mut host, Limits::default()).unwrap(),
        Value::Str(subject)
    );
}

#[test]
fn gsub_over_large_input_is_bounded() {
    let src = "local s = string.rep('a', 5000) local r, n = string.gsub(s, 'a', 'b') return n";
    assert_eq!(num(src), 5000.0);
}

#[test]
fn oversized_requests_are_rejected_not_allocated() {
    let err = fails("return string.format('%999999999d', 1)");
    assert_eq!(err.kind, ErrorKind::Runtime);
    assert!(err.message.contains("width"));

    let err = fails("return string.format('%.999999999f', 1)");
    assert_eq!(err.kind, ErrorKind::Runtime);

    let err = fails("local t = {1} return table.unpack(t, 1, 100000000)");
    assert_eq!(err.kind, ErrorKind::Runtime);

    let err = fails("return string.rep('x', 1000000000)");
    assert_eq!(err.kind, ErrorKind::Runtime);

    let err = fails("return string.char(300)");
    assert_eq!(err.kind, ErrorKind::Runtime);

    let err = fails("return string.rep('xxxx', 5000000, 'y')");
    assert_eq!(err.kind, ErrorKind::Runtime);
}

#[test]
fn gsub_replacement_fallbacks() {
    assert_eq!(
        text("return (string.gsub('abc', '%w', function() return nil end))"),
        "abc"
    );
    assert_eq!(
        text("return (string.gsub('abc', 'a', function() return false end))"),
        "abc"
    );
    assert_eq!(
        text("local m = {a = 'A'} return (string.gsub('abc', 'a', m))"),
        "Abc"
    );
    assert_eq!(
        text("return (string.gsub('abc', 'b', function(v) return v:upper() end))"),
        "aBc"
    );
}
