//! ANSI-aware string measurement and truncation.
//!
//! Prompt rendering needs to know how many *columns* a string occupies, not
//! how many bytes or chars it has. Escape sequences occupy zero columns and
//! East Asian wide characters occupy two. The tables here are deliberately
//! compact range checks: no generated width table, because the release binary
//! has a size budget and this is not security-critical.

/// Length in bytes of an escape sequence beginning at byte index i.
///
/// Unknown or truncated sequences consume the rest of the string, which keeps
/// the scanner progressing and cannot panic.
fn escape_len(bytes: &[u8], i: usize) -> usize {
    let len = bytes.len();
    if i >= len {
        return 0;
    }
    debug_assert_eq!(bytes[i], 0x1b);
    if i + 1 >= len {
        return 1;
    }
    match bytes[i + 1] {
        b'[' => {
            // CSI: parameter/intermediate bytes then one final byte 0x40..=0x7e.
            let mut j = i + 2;
            while j < len {
                let b = bytes[j];
                if (0x40..=0x7e).contains(&b) {
                    return j - i + 1;
                }
                if b < 0x20 || b == 0x7f {
                    // Malformed: the control byte ends the (invalid) sequence.
                    return j - i;
                }
                j += 1;
            }
            len - i
        }
        b']' | b'P' | b'_' | b'^' | b'X' => {
            // OSC/DCS/APC/PM/SOS: terminated by BEL or ST (ESC \).
            let mut j = i + 2;
            while j < len {
                if bytes[j] == 0x07 {
                    return j - i + 1;
                }
                if bytes[j] == 0x1b && j + 1 < len && bytes[j + 1] == b'\\' {
                    return j - i + 2;
                }
                j += 1;
            }
            len - i
        }
        _ => {
            // ESC followed by one other character (Alt+key or a two-byte
            // control sequence). Keep multi-byte UTF-8 intact.
            let n = utf8_len(bytes[i + 1]);
            (1 + n).min(len - i)
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

fn char_at(s: &str, i: usize) -> Option<(char, usize)> {
    s.get(i..)
        .and_then(|rest| rest.chars().next())
        .map(|c| (c, c.len_utf8()))
}

/// Number of terminal columns a single char occupies.
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    if u == 0 || u < 0x20 || (0x7f..0xa0).contains(&u) {
        return 0;
    }
    if is_zero_width(u) {
        return 0;
    }
    if is_wide(u) {
        2
    } else {
        1
    }
}

fn is_zero_width(u: u32) -> bool {
    matches!(u,
        0x0300..=0x036f
        | 0x0483..=0x0489
        | 0x0591..=0x05bd
        | 0x05bf
        | 0x05c1..=0x05c2
        | 0x05c4..=0x05c5
        | 0x0610..=0x061a
        | 0x064b..=0x065f
        | 0x0670
        | 0x06d6..=0x06dc
        | 0x06df..=0x06e4
        | 0x06e7..=0x06e8
        | 0x06ea..=0x06ed
        | 0x0711
        | 0x0730..=0x074a
        | 0x07a6..=0x07b0
        | 0x0900..=0x0902
        | 0x093a
        | 0x093c
        | 0x0941..=0x0948
        | 0x094d
        | 0x0951..=0x0957
        | 0x0962..=0x0963
        | 0x1ab0..=0x1aff
        | 0x1dc0..=0x1dff
        | 0x200b..=0x200f
        | 0x202a..=0x202e
        | 0x2060..=0x206f
        | 0x20d0..=0x20ff
        | 0xfe00..=0xfe0f
        | 0xfe20..=0xfe2f
        | 0xfeff
        | 0xe0100..=0xe01ef
    )
}

fn is_wide(u: u32) -> bool {
    matches!(u,
        0x1100..=0x115f
        | 0x2329..=0x232a
        | 0x2e80..=0x303e
        | 0x3041..=0x33ff
        | 0x3400..=0x4dbf
        | 0x4e00..=0x9fff
        | 0xa000..=0xa4cf
        | 0xa960..=0xa97f
        | 0xac00..=0xd7a3
        | 0xf900..=0xfaff
        | 0xfe10..=0xfe19
        | 0xfe30..=0xfe6f
        | 0xff00..=0xff60
        | 0xffe0..=0xffe6
        | 0x1b000..=0x1b2ff
        | 0x1f300..=0x1f64f
        | 0x1f900..=0x1f9ff
        | 0x20000..=0x3fffd
    )
}

/// Remove ANSI escape sequences. Used to make arbitrary caller text safe for
/// dumb terminals and for tests that assert zero 0x1b bytes.
pub fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            let n = escape_len(bytes, i);
            i += n.max(1);
            continue;
        }
        if let Some((c, n)) = char_at(s, i) {
            out.push(c);
            i += n;
        } else {
            i += 1;
        }
    }
    out
}

/// Visible width of a string in terminal columns, ignoring ANSI escapes.
pub fn display_width(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut width = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += escape_len(bytes, i).max(1);
            continue;
        }
        if let Some((c, n)) = char_at(s, i) {
            width = width.saturating_add(char_width(c));
            i += n;
        } else {
            i += 1;
        }
    }
    width
}

/// Truncate to at most max visible columns, preserving ANSI sequences and
/// never splitting a UTF-8 character. A reset is appended when any escape was
/// copied so colour state cannot leak into the next line.
pub fn truncate_to_width(s: &str, max: usize) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len().min(max.saturating_mul(3) + 8));
    let mut used = 0usize;
    let mut i = 0;
    let mut saw_escape = false;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            let n = escape_len(bytes, i).max(1);
            out.push_str(&s[i..(i + n).min(s.len())]);
            saw_escape = true;
            i += n;
            continue;
        }
        let (c, n) = match char_at(s, i) {
            Some(v) => v,
            None => break,
        };
        let w = char_width(c);
        if used.saturating_add(w) > max {
            break;
        }
        out.push(c);
        used += w;
        i += n;
    }
    if saw_escape {
        out.push_str("\x1b[0m");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_widths() {
        assert_eq!(display_width("hello"), 5);
        assert_eq!(display_width(""), 0);
        assert_eq!(display_width("a\tb"), 2);
    }

    #[test]
    fn ansi_is_zero_width() {
        assert_eq!(display_width("\x1b[31mred\x1b[0m"), 3);
        assert_eq!(display_width("\x1b]0;title\x07x"), 1);
        assert_eq!(display_width("\x1b[?25l"), 0);
    }

    #[test]
    fn wide_and_combining() {
        assert_eq!(char_width('中'), 2);
        assert_eq!(display_width("中文"), 4);
        assert_eq!(display_width("e\u{0301}"), 1);
        assert_eq!(display_width("🙂"), 2);
    }

    #[test]
    fn stripping_removes_escapes_and_keeps_text() {
        assert_eq!(strip_ansi("\x1b[1;31mhi\x1b[0m!"), "hi!");
        assert_eq!(strip_ansi("plain"), "plain");
        assert_eq!(strip_ansi("\x1b[31"), "");
        assert!(!strip_ansi("\x1b[31mred\x1b[0m").contains('\x1b'));
    }

    #[test]
    fn truncation_respects_columns_and_escapes() {
        assert_eq!(truncate_to_width("abcdef", 3), "abc");
        assert_eq!(truncate_to_width("中文", 3), "中");
        assert_eq!(
            display_width(&truncate_to_width("\x1b[31mabcdef\x1b[0m", 4)),
            4
        );
        assert!(truncate_to_width("\x1b[31mabcdef", 4).ends_with("\x1b[0m"));
    }

    #[test]
    fn malformed_input_never_panics_or_hangs() {
        for s in ["\x1b", "\x1b[", "\x1b[999", "\x1b]", "\x1b]0;x", "a\x1b"] {
            let _ = display_width(s);
            let t = truncate_to_width(s, 2);
            let _ = strip_ansi(&t);
        }
    }
}
