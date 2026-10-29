//! Lua 5.4 pattern matching (no regex crate, no backtracking bombs).
//!
//! Implements the same language as Lua's lstrlib: classes (%a %c %d %g %l %p
//! %s %u %w %x and uppercase complements), sets, '.', the quantifiers * + - ?,
//! anchors ^ $, captures, position captures, %b and %f, and %1-%9
//! backreferences. Matching operates on bytes, exactly like Lua.
//!
//! Recursion is bounded (MAX_DEPTH) so a pathological pattern returns an error
//! instead of exhausting the native stack.

const UNFINISHED: usize = usize::MAX;
const POSITION: usize = usize::MAX - 1;
const MAX_DEPTH: u32 = 220;
/// Upper bound on matching steps for one find() call; protects against
/// exponential backtracking and is charged to the interpreter's budget.
const MAX_STEPS: u32 = 200_000;

/// A captured value: a byte span into the subject, or a position (1-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapValue {
    Str(usize, usize),
    Pos(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Match {
    pub start: usize,
    pub end: usize,
    pub caps: Vec<CapValue>,
}

#[derive(Debug, Clone, Copy)]
struct Cap {
    start: usize,
    len: usize,
}

pub(crate) struct MatchState<'a> {
    src: &'a [u8],
    pat: &'a [u8],
    caps: Vec<Cap>,
    depth: u32,
    steps: u32,
    pub too_complex: bool,
    pub malformed: bool,
}

/// True when the pattern contains characters that make it a pattern rather
/// than a literal (Lua uses this to pick the plain path in string.find).
pub(crate) fn has_specials(pat: &[u8]) -> bool {
    pat.iter().any(|c| {
        matches!(
            c,
            b'^' | b'$' | b'*' | b'+' | b'?' | b'.' | b'(' | b'[' | b'%' | b'-'
        )
    })
}

/// Find the first match at or after init (byte offset).
///
/// Returns the match (if any) and the number of matching steps consumed, so
/// the caller can charge them against the script's instruction budget.
pub(crate) fn find(
    src: &[u8],
    pat: &[u8],
    init: usize,
) -> Result<(Option<Match>, u32), &'static str> {
    let anchored = pat.first() == Some(&b'^');
    let pstart = if anchored { 1 } else { 0 };
    let mut pos = init;
    loop {
        let mut ms = MatchState::new(src, pat, pstart);
        let found = ms.do_match(pos);
        let steps = ms.steps;
        if let Some(end) = found {
            let caps = ms.capture_values().ok_or("invalid capture in pattern")?;
            return Ok((
                Some(Match {
                    start: pos,
                    end,
                    caps,
                }),
                steps,
            ));
        }
        if ms.malformed {
            return Err("malformed pattern (missing ']')");
        }
        if ms.too_complex {
            return Err("pattern too complex");
        }
        if anchored || pos >= src.len() {
            return Ok((None, steps));
        }
        pos += 1;
    }
}

/// Try to match pat at exactly pos, returning the end offset and captures.
#[allow(dead_code)]
pub(crate) fn match_at(
    src: &[u8],
    pat: &[u8],
    pos: usize,
) -> Result<Option<(usize, Vec<CapValue>)>, &'static str> {
    let anchored = pat.first() == Some(&b'^');
    let pstart = if anchored { 1 } else { 0 };
    let mut ms = MatchState::new(src, pat, pstart);
    if let Some(end) = ms.do_match(pos) {
        let caps = ms.capture_values().ok_or("invalid capture in pattern")?;
        Ok(Some((end, caps)))
    } else if ms.malformed {
        Err("malformed pattern (missing ']')")
    } else if ms.too_complex {
        Err("pattern too complex")
    } else {
        Ok(None)
    }
}

impl<'a> MatchState<'a> {
    fn new(src: &'a [u8], pat: &'a [u8], _pstart: usize) -> MatchState<'a> {
        MatchState {
            src,
            pat,
            caps: Vec::new(),
            depth: 0,
            steps: 0,
            too_complex: false,
            malformed: false,
        }
    }

    fn capture_values(&self) -> Option<Vec<CapValue>> {
        let mut out = Vec::with_capacity(self.caps.len());
        for cap in &self.caps {
            if cap.len == UNFINISHED {
                return None;
            }
            if cap.len == POSITION {
                out.push(CapValue::Pos(cap.start + 1));
            } else {
                out.push(CapValue::Str(cap.start, cap.start + cap.len));
            }
        }
        Some(out)
    }

    /// End of the single pattern item starting at p.
    fn class_end(&mut self, p: usize) -> Option<usize> {
        match *self.pat.get(p)? {
            b'%' => {
                if p + 1 >= self.pat.len() {
                    self.malformed = true;
                    None
                } else {
                    Some(p + 2)
                }
            }
            b'[' => {
                let mut i = p + 1;
                if self.pat.get(i) == Some(&b'^') {
                    i += 1;
                }
                if self.pat.get(i) == Some(&b']') {
                    i += 1;
                }
                while i < self.pat.len() {
                    match self.pat[i] {
                        b']' => return Some(i + 1),
                        b'%' => i += 2,
                        _ => i += 1,
                    }
                }
                self.malformed = true;
                None
            }
            _ => Some(p + 1),
        }
    }

    fn match_class(&self, c: u8, cl: u8) -> bool {
        let lower = cl.to_ascii_lowercase();
        let matched = match lower {
            b'a' => c.is_ascii_alphabetic(),
            b'c' => c.is_ascii_control(),
            b'd' => c.is_ascii_digit(),
            b'g' => c.is_ascii_graphic(),
            b'l' => c.is_ascii_lowercase(),
            b'p' => c.is_ascii_punctuation(),
            b's' => c == b' ' || (9..=13).contains(&c),
            b'u' => c.is_ascii_uppercase(),
            b'w' => c.is_ascii_alphanumeric(),
            b'x' => c.is_ascii_hexdigit(),
            _ => return cl == c,
        };
        if cl.is_ascii_uppercase() {
            !matched
        } else {
            matched
        }
    }

    fn match_bracket(&self, c: u8, p: usize, ep: usize) -> bool {
        let mut i = p + 1;
        let mut negate = false;
        if self.pat.get(i) == Some(&b'^') {
            negate = true;
            i += 1;
        }
        let end = ep.saturating_sub(1);
        let mut found = false;
        while i < end {
            if self.pat[i] == b'%' && i + 1 < end {
                if self.match_class(c, self.pat[i + 1]) {
                    found = true;
                }
                i += 2;
            } else if i + 2 < end && self.pat[i + 1] == b'-' {
                if self.pat[i] <= c && c <= self.pat[i + 2] {
                    found = true;
                }
                i += 3;
            } else {
                if self.pat[i] == c {
                    found = true;
                }
                i += 1;
            }
        }
        found != negate
    }

    fn single_match(&self, s: usize, p: usize, ep: usize) -> bool {
        if s >= self.src.len() {
            return false;
        }
        let c = self.src[s];
        match self.pat[p] {
            b'.' => true,
            b'%' => self.match_class(c, self.pat[p + 1]),
            b'[' => self.match_bracket(c, p, ep),
            pc => pc == c,
        }
    }

    fn match_balance(&self, s: usize, p: usize) -> Option<usize> {
        let open = *self.pat.get(p)?;
        let close = *self.pat.get(p + 1)?;
        if self.src.get(s).copied()? != open {
            return None;
        }
        let mut depth = 1i32;
        let mut i = s + 1;
        while i < self.src.len() {
            let c = self.src[i];
            if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            i += 1;
        }
        None
    }

    fn match_capture(&self, s: usize, index: usize) -> Option<usize> {
        let cap = *self.caps.get(index)?;
        if cap.len == UNFINISHED || cap.len == POSITION {
            return None;
        }
        let end = cap.start + cap.len;
        if end > self.src.len() || s + cap.len > self.src.len() {
            return None;
        }
        if &self.src[cap.start..end] == &self.src[s..s + cap.len] {
            Some(s + cap.len)
        } else {
            None
        }
    }

    fn start_capture(&mut self, s: usize, p: usize, len: usize) -> Option<usize> {
        let index = self.caps.len();
        self.caps.push(Cap { start: s, len });
        match self.do_match_at(s, p) {
            Some(r) => Some(r),
            None => {
                self.caps.truncate(index);
                None
            }
        }
    }

    fn end_capture(&mut self, s: usize, p: usize) -> Option<usize> {
        let index = self.caps.len();
        if index == 0 || self.caps[index - 1].len != UNFINISHED {
            return None;
        }
        self.caps[index - 1].len = s - self.caps[index - 1].start;
        match self.do_match_at(s, p) {
            Some(r) => Some(r),
            None => {
                self.caps[index - 1].len = UNFINISHED;
                None
            }
        }
    }

    fn max_expand(&mut self, s: usize, p: usize, ep: usize) -> Option<usize> {
        let mut i = 0usize;
        while self.single_match(s + i, p, ep) {
            i += 1;
        }
        loop {
            if let Some(r) = self.do_match_at(s + i, ep + 1) {
                return Some(r);
            }
            if i == 0 {
                return None;
            }
            i -= 1;
        }
    }

    fn min_expand(&mut self, mut s: usize, p: usize, ep: usize) -> Option<usize> {
        loop {
            if let Some(r) = self.do_match_at(s, ep + 1) {
                return Some(r);
            }
            if self.single_match(s, p, ep) {
                s += 1;
            } else {
                return None;
            }
        }
    }

    fn do_match(&mut self, s: usize) -> Option<usize> {
        // Entry used by find/match_at: honour an initial '^' by skipping it.
        let p = if self.pat.first() == Some(&b'^') {
            1
        } else {
            0
        };
        self.do_match_at(s, p)
    }

    fn do_match_at(&mut self, mut s: usize, mut p: usize) -> Option<usize> {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            self.too_complex = true;
            return None;
        }
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            self.too_complex = true;
            return None;
        }
        let result = loop {
            if p >= self.pat.len() {
                break Some(s);
            }
            match self.pat[p] {
                b'(' => {
                    if self.pat.get(p + 1) == Some(&b')') {
                        break self.start_capture(s, p + 2, POSITION);
                    }
                    break self.start_capture(s, p + 1, UNFINISHED);
                }
                b')' => break self.end_capture(s, p + 1),
                b'$' if p + 1 == self.pat.len() => {
                    break if s == self.src.len() { Some(s) } else { None };
                }
                b'%' if p + 1 < self.pat.len()
                    && matches!(self.pat[p + 1], b'b' | b'f' | b'1'..=b'9') =>
                {
                    match self.pat[p + 1] {
                        b'b' => {
                            if p + 3 >= self.pat.len() {
                                self.malformed = true;
                                break None;
                            }
                            match self.match_balance(s, p + 2) {
                                Some(next) => {
                                    s = next;
                                    p += 4;
                                    continue;
                                }
                                None => break None,
                            }
                        }
                        b'f' => {
                            if self.pat.get(p + 2) != Some(&b'[') {
                                self.malformed = true;
                                break None;
                            }
                            let ep = match self.class_end(p + 2) {
                                Some(ep) => ep,
                                None => break None,
                            };
                            let prev_in = s > 0 && self.match_bracket(self.src[s - 1], p + 2, ep);
                            let cur_in =
                                s < self.src.len() && self.match_bracket(self.src[s], p + 2, ep);
                            if !prev_in && cur_in {
                                p = ep;
                                continue;
                            }
                            break None;
                        }
                        digit => {
                            let index = (digit - b'1') as usize;
                            match self.match_capture(s, index) {
                                Some(next) => {
                                    s = next;
                                    p += 2;
                                    continue;
                                }
                                None => break None,
                            }
                        }
                    }
                }
                _ => {
                    let ep = match self.class_end(p) {
                        Some(ep) => ep,
                        None => break None,
                    };
                    if !self.single_match(s, p, ep) {
                        match self.pat.get(ep) {
                            Some(b'*') | Some(b'?') | Some(b'-') => {
                                p = ep + 1;
                                continue;
                            }
                            _ => break None,
                        }
                    } else {
                        match self.pat.get(ep).copied() {
                            Some(b'?') => {
                                if let Some(r) = self.do_match_at(s + 1, ep + 1) {
                                    break Some(r);
                                }
                                p = ep + 1;
                                continue;
                            }
                            Some(b'+') => break self.max_expand(s + 1, p, ep),
                            Some(b'*') => break self.max_expand(s, p, ep),
                            Some(b'-') => break self.min_expand(s, p, ep),
                            _ => {
                                s += 1;
                                p = ep;
                                continue;
                            }
                        }
                    }
                }
            }
        };
        self.depth -= 1;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(src: &str, pat: &str) -> Option<Match> {
        find(src.as_bytes(), pat.as_bytes(), 0).expect("pattern").0
    }

    fn caps_text<'a>(src: &'a str, mat: &Match) -> Vec<String> {
        mat.caps
            .iter()
            .map(|c| match c {
                CapValue::Str(a, b) => src[*a..*b].to_string(),
                CapValue::Pos(p) => p.to_string(),
            })
            .collect()
    }

    #[test]
    fn plain_and_classes() {
        assert_eq!(
            m("hello world", "world").map(|x| (x.start, x.end)),
            Some((6, 11))
        );
        assert_eq!(m("abc", "xyz"), None);
        assert_eq!(m("hello 123", "%d+").map(|x| x.end), Some(9));
        assert_eq!(m("ABC def", "%u+").map(|x| x.end), Some(3));
        assert_eq!(m("abc", "^abc").map(|x| x.end), Some(3));
        assert_eq!(m("xabc", "^abc"), None);
        assert_eq!(m("abc", "bc$").map(|x| x.start), Some(1));
        assert_eq!(m("abc", "ab$"), None);
    }

    #[test]
    fn sets_and_ranges() {
        assert_eq!(m("a1b", "[0-9]").map(|x| x.start), Some(1));
        assert_eq!(m("abc", "[^a-c]"), None);
        assert_eq!(m("x%", "[%%]").map(|x| x.start), Some(1));
        assert_eq!(m("a1", "[%a%d]+").map(|x| x.end), Some(2));
        assert_eq!(m("]x", "[]]").map(|x| x.start), Some(0));
    }

    #[test]
    fn captures_and_positions() {
        let mat = m("key=value", "(%w+)=(%w+)").unwrap();
        assert_eq!(caps_text("key=value", &mat), vec!["key", "value"]);
        let mat = m("abc", "()b()").unwrap();
        assert_eq!(caps_text("abc", &mat), vec!["2", "3"]);
        let mat = m("abcabc", "(abc)%1").unwrap();
        assert_eq!(caps_text("abcabc", &mat), vec!["abc"]);
        assert!(m("abcabd", "(abc)%1").is_none());
    }

    #[test]
    fn balance_and_frontier() {
        let mat = m("f(a(b)c)d", "%b()").unwrap();
        assert_eq!(&"f(a(b)c)d"[mat.start..mat.end], "(a(b)c)");
        let mat = m("THE (quick) fox", "%f[%a]%a+").unwrap();
        assert_eq!(&"THE (quick) fox"[mat.start..mat.end], "THE");
    }

    #[test]
    fn greedy_and_lazy() {
        let mat = m("<a><b>", "<.->").unwrap();
        assert_eq!(mat.end, 3);
        let mat = m("<a><b>", "<.*>").unwrap();
        assert_eq!(mat.end, 6);
        let mat = m("aaa", "a?").unwrap();
        assert_eq!(mat.end, 1);
        let mat = m("aaa", "a*").unwrap();
        assert_eq!(mat.end, 3);
    }

    #[test]
    fn malformed_patterns_error() {
        assert!(find(b"x", b"[abc", 0).is_err());
        assert!(find(b"x", b"%", 0).is_err());
    }

    #[test]
    fn anchors_only_at_start() {
        assert!(find(b"a^b", b"a^b", 0).expect("pattern").0.is_some());
        assert!(find(b"xxa", b"^a", 0).expect("pattern").0.is_none());
    }
}
