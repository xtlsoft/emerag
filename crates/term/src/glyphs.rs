//! Glyph sets with an ASCII fallback.
//!
//! Every glyph used by the wizard lives here so a terminal without UTF-8 can
//! be supported without scattering "if unicode" branches through the UI.
//! The ASCII table is intentionally tiny and entirely ASCII, which also keeps
//! serial consoles usable when the locale is C or POSIX.

/// A complete glyph set. All fields are static strings so lookup is free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyphs {
    pub unicode: bool,
    pub hline: &'static str,
    pub vline: &'static str,
    pub tl: &'static str,
    pub tr: &'static str,
    pub bl: &'static str,
    pub br: &'static str,
    pub tee_left: &'static str,
    pub tee_right: &'static str,
    pub tee_top: &'static str,
    pub tee_bottom: &'static str,
    pub cross: &'static str,
    pub arrow_up: &'static str,
    pub arrow_down: &'static str,
    pub arrow_left: &'static str,
    pub arrow_right: &'static str,
    pub bullet: &'static str,
    pub check: &'static str,
    pub cross_mark: &'static str,
    pub ellipsis: &'static str,
    pub cursor: &'static str,
    pub selected: &'static str,
    pub unselected: &'static str,
}

impl Glyphs {
    /// ASCII-only fallback for VT100, serial consoles and C locales.
    pub const ASCII: Glyphs = Glyphs {
        unicode: false,
        hline: "-",
        vline: "|",
        tl: "+",
        tr: "+",
        bl: "+",
        br: "+",
        tee_left: "+",
        tee_right: "+",
        tee_top: "+",
        tee_bottom: "+",
        cross: "+",
        arrow_up: "^",
        arrow_down: "v",
        arrow_left: "<",
        arrow_right: ">",
        bullet: "*",
        check: "v",
        cross_mark: "x",
        ellipsis: "...",
        cursor: ">",
        selected: ">",
        unselected: " ",
    };

    /// Unicode (UTF-8) glyph set.
    pub const UNICODE: Glyphs = Glyphs {
        unicode: true,
        hline: "─",
        vline: "│",
        tl: "┌",
        tr: "┐",
        bl: "└",
        br: "┘",
        tee_left: "├",
        tee_right: "┤",
        tee_top: "┬",
        tee_bottom: "┴",
        cross: "┼",
        arrow_up: "↑",
        arrow_down: "↓",
        arrow_left: "←",
        arrow_right: "→",
        bullet: "•",
        check: "✓",
        cross_mark: "✗",
        ellipsis: "…",
        cursor: "›",
        selected: "▶",
        unselected: "·",
    };

    pub fn new(unicode: bool) -> Glyphs {
        if unicode {
            Glyphs::UNICODE
        } else {
            Glyphs::ASCII
        }
    }

    /// Look up a glyph by name. Unknown names return "?" rather than panicking.
    pub fn get(&self, name: &str) -> &'static str {
        match name {
            "hline" => self.hline,
            "vline" => self.vline,
            "tl" => self.tl,
            "tr" => self.tr,
            "bl" => self.bl,
            "br" => self.br,
            "tee_left" => self.tee_left,
            "tee_right" => self.tee_right,
            "tee_top" => self.tee_top,
            "tee_bottom" => self.tee_bottom,
            "cross" => self.cross,
            "arrow_up" => self.arrow_up,
            "arrow_down" => self.arrow_down,
            "arrow_left" => self.arrow_left,
            "arrow_right" => self.arrow_right,
            "bullet" => self.bullet,
            "check" => self.check,
            "cross_mark" => self.cross_mark,
            "ellipsis" => self.ellipsis,
            "cursor" => self.cursor,
            "selected" => self.selected,
            "unselected" => self.unselected,
            _ => "?",
        }
    }
}

/// Names understood by [Glyphs::get].
pub const NAMES: &[&str] = &[
    "hline",
    "vline",
    "tl",
    "tr",
    "bl",
    "br",
    "tee_left",
    "tee_right",
    "tee_top",
    "tee_bottom",
    "cross",
    "arrow_up",
    "arrow_down",
    "arrow_left",
    "arrow_right",
    "bullet",
    "check",
    "cross_mark",
    "ellipsis",
    "cursor",
    "selected",
    "unselected",
];

/// Default (Unicode) glyph set, for callers that already checked capabilities.
pub const GLYPHS: Glyphs = Glyphs::UNICODE;

/// Look up a Unicode glyph by name (compatibility helper).
pub fn glyph(name: &str) -> &'static str {
    GLYPHS.get(name)
}

/// Look up the ASCII fallback for a glyph name.
pub fn ascii_glyph(name: &str) -> &'static str {
    Glyphs::ASCII.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_set_is_ascii() {
        for name in NAMES {
            let g = Glyphs::ASCII.get(name);
            assert!(!g.is_empty(), "empty glyph {name}");
            assert!(g.is_ascii(), "non-ASCII glyph for {name}: {g:?}");
        }
        assert_eq!(ascii_glyph("hline"), "-");
        assert_eq!(ascii_glyph("arrow_up"), "^");
        assert_eq!(ascii_glyph("unknown"), "?");
    }

    #[test]
    fn unicode_set_is_not_ascii_for_box_drawing() {
        assert_eq!(glyph("tl"), "┌");
        assert_eq!(Glyphs::UNICODE.get("br"), "┘");
        let unicode = Glyphs::new(true);
        let ascii = Glyphs::new(false);
        assert!(unicode.unicode);
        assert!(!ascii.unicode);
    }
}
