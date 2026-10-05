//! `.dockerignore`: what of the context directory a build never sees.
//!
//! ```text
//!  # comments, and blank lines, are ignored
//!  target/          everything below target/
//!  **/*.log         .log files at any depth
//!  !keep.log        …except this one (a later line wins)
//!  /secret          a leading / is the context's root (the same as without)
//! ```
//!
//! Docker's semantics (`moby/patternmatcher`): each line is a pattern for
//! the path relative to the context, `/`-separated, cleaned (`a/../b` is
//! `b`); `*`, `?` and `[…]` match within one component (Go's
//! `filepath.Match`), `**` any number of components; a pattern that matches
//! a directory excludes everything below it; the last pattern that matches
//! a path (itself or a parent directory) decides, and `!` patterns include
//! again. A walk that meets an excluded directory must still enter it when
//! an exception could include something below
//! ([`IgnoreRules::may_include_below`]).
//!
//! The file: `<Containerfile>.dockerignore` next to the Containerfile
//! (BuildKit's), else `.containerignore` (Podman's), else `.dockerignore`, in
//! the context's root ([`ignore_file`]).
//!
//! The file's syntax is `moby/patternmatcher`'s reader's: a line starting
//! with `#` is a comment (only in the first column: `  # x` is a pattern),
//! whitespace around a pattern is trimmed, a lone `!` is an error. Its
//! quirks are kept too: `**` first followed by plain text (`**foo`)
//! matches any path ending in that text (`barfoo` too), and a pattern
//! ending in `**` (`dir/**`) doesn't match `dir` itself.

use std::path::{Path, PathBuf};

use regex::{Regex, RegexBuilder};

use crate::path::clean;

/// Parsed ignore patterns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoreRules {
    patterns: Vec<Pattern>,
}

impl IgnoreRules {
    /// Parses an ignore file's text. Malformed patterns (an unclosed `[`)
    /// are an error, with their line.
    pub fn parse(text: &str) -> Result<IgnoreRules, String> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut patterns = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.starts_with('#') {
                continue;
            }
            let mut pattern = line.trim();
            if pattern.is_empty() {
                continue;
            }
            let exclusion = pattern.starts_with('!');
            if exclusion {
                pattern = pattern[1..].trim();
            }
            if pattern.is_empty() {
                return Err(format!("line {}: \"!\" alone is not a pattern", index + 1));
            }
            // Relative to the context: a leading `/` means the same.
            let cleaned = clean(pattern);
            let cleaned = match cleaned.strip_prefix('/') {
                Some(rest) if !rest.is_empty() => rest.to_owned(),
                _ => cleaned,
            };
            let pattern =
                Pattern::compile(cleaned, exclusion).map_err(|e| format!("line {}: {pattern}: {e}", index + 1))?;
            patterns.push(pattern);
        }
        Ok(IgnoreRules { patterns })
    }

    /// Is the context path `rel` (relative, `/`-separated) excluded?
    pub fn excludes(&self, rel: &str) -> bool {
        let parents: Vec<&str> = rel.match_indices('/').map(|(i, _)| &rel[..i]).collect();
        let mut excluded = false;
        for pattern in &self.patterns {
            // Only a pattern that would change the answer is tried.
            if pattern.exclusion != excluded {
                continue;
            }
            if pattern.matches(rel) || parents.iter().any(|parent| pattern.matches(parent)) {
                excluded = !pattern.exclusion;
            }
        }
        excluded
    }

    /// Below the excluded directory `rel`, could an exception include
    /// something?
    pub fn may_include_below(&self, rel: &str) -> bool {
        let dir = format!("{}/", rel.trim_end_matches('/'));
        // An exception's text before its first wildcard must lead into
        // `rel`, or be a prefix of it (`!**/keep`: anything could match).
        self.patterns.iter().filter(|pattern| pattern.exclusion).any(|pattern| {
            let literal = pattern.literal_prefix();
            literal.starts_with(&dir) || dir.starts_with(literal)
        })
    }
}

/// One line of the file.
#[derive(Debug, Clone)]
struct Pattern {
    /// The cleaned pattern, without its `!`.
    text: String,
    /// `!`: an exception, which includes again.
    exclusion: bool,
    kind: Kind,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text && self.exclusion == other.exclusion
    }
}

impl Eq for Pattern {}

/// The same fast paths as patternmatcher, otherwise a compiled expression.
#[derive(Debug, Clone)]
enum Kind {
    Exact,
    Prefix(String),
    Suffix(String),
    Regex(Regex),
}

impl Pattern {
    /// Translate the glob the way patternmatcher's Linux compiler does.
    /// In particular, a backslash is a regex escape, not always a literal
    /// next character: `\d` matches digits and `\i` is an error.
    fn compile(text: String, exclusion: bool) -> Result<Pattern, String> {
        #[derive(PartialEq)]
        enum Type {
            Exact,
            Prefix,
            Suffix,
            Regex,
        }
        let chars: Vec<char> = text.chars().collect();
        let mut expression = String::from("^");
        let mut kind = Type::Exact;
        let mut i = 0;
        while i < chars.len() {
            let first = i == 0;
            let c = chars[i];
            i += 1;
            match c {
                '*' if chars.get(i) == Some(&'*') => {
                    i += 1;
                    if chars.get(i) == Some(&'/') {
                        i += 1;
                    }
                    if i == chars.len() {
                        if kind == Type::Exact {
                            kind = Type::Prefix;
                        } else {
                            expression.push_str(".*");
                            kind = Type::Regex;
                        }
                    } else {
                        expression.push_str("(.*/)?");
                        kind = Type::Regex;
                    }
                    if first {
                        kind = Type::Suffix;
                    }
                }
                '*' => {
                    expression.push_str("[^/]*");
                    kind = Type::Regex;
                }
                '?' => {
                    expression.push_str("[^/]");
                    kind = Type::Regex;
                }
                '\\' => {
                    let next = chars.get(i).ok_or("a pattern can't end with \\")?;
                    expression.push('\\');
                    expression.push(*next);
                    i += 1;
                    kind = Type::Regex;
                }
                '[' => {
                    let next = class(&chars, i)?;
                    expression.push('[');
                    let mut content = chars[i..next - 1].iter();
                    while let Some(&c) = content.next() {
                        if c == '\\' {
                            expression.push('\\');
                            expression.push(*content.next().expect("validated class escape"));
                        } else {
                            // A nested `[` is literal in Go's class syntax.
                            if "[.+()|{}$".contains(c) {
                                expression.push('\\');
                            }
                            expression.push(c);
                        }
                    }
                    expression.push(']');
                    i = next;
                    kind = Type::Regex;
                }
                c if ".+()|{}$".contains(c) => {
                    expression.push('\\');
                    expression.push(c);
                }
                c => expression.push(c),
            }
        }
        let kind = match kind {
            Type::Exact => Kind::Exact,
            Type::Prefix => Kind::Prefix(text[..text.len() - 2].to_owned()),
            Type::Suffix => Kind::Suffix(text[2..].to_owned()),
            Type::Regex => {
                expression.push('$');
                let expression = go_regex_escapes(&expression)?;
                let compiled = RegexBuilder::new(&expression)
                    .octal(true)
                    .build()
                    .map_err(|e| format!("syntax error in pattern: {e}"))?;
                Kind::Regex(compiled)
            }
        };
        Ok(Pattern { text, exclusion, kind })
    }

    fn matches(&self, path: &str) -> bool {
        match &self.kind {
            Kind::Exact => path == self.text,
            Kind::Prefix(prefix) => path.starts_with(prefix.as_str()),
            Kind::Suffix(suffix) => {
                path.ends_with(suffix.as_str()) || suffix.strip_prefix('/').is_some_and(|bare| path == bare)
            }
            Kind::Regex(regex) => regex.is_match(path),
        }
    }

    /// The text up to the first wildcard or escape.
    fn literal_prefix(&self) -> &str {
        let end = self.text.find(['*', '?', '[', '\\']).unwrap_or(self.text.len());
        &self.text[..end]
    }
}

/// Go's shorthand classes and word boundaries are ASCII, while Rust's
/// regex defaults to Unicode. Go also has a literal-quoting escape.
fn go_regex_escapes(raw: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        if c != '\\' {
            if c == '[' {
                in_class = true;
            } else if c == ']' {
                in_class = false;
            }
            out.push(c);
            continue;
        }
        let next = chars.next().ok_or("trailing escape in pattern")?;
        if in_class && matches!(next, 'A' | 'z' | 'b' | 'B' | 'Q') {
            return Err(format!("syntax error in pattern: invalid class escape \\{next}"));
        }
        match next {
            'd' => out.push_str("[0-9]"),
            'D' => out.push_str("[^0-9]"),
            's' => out.push_str("[\\t\\n\\f\\r ]"),
            'S' => out.push_str("[^\\t\\n\\f\\r ]"),
            'w' => out.push_str("[0-9A-Za-z_]"),
            'W' => out.push_str("[^0-9A-Za-z_]"),
            'b' | 'B' => out.push_str(&format!("(?-u:\\{next})")),
            'a' => out.push_str("\\x07"),
            'v' => out.push_str("\\x0B"),
            'Q' => {
                let mut literal = String::new();
                while let Some(c) = chars.next() {
                    if c == '\\' && chars.peek() == Some(&'E') {
                        chars.next();
                        break;
                    }
                    literal.push(c);
                }
                out.push_str(&regex::escape(&literal));
            }
            c if c.is_ascii_alphabetic() && !"fnrtAxzpP".contains(c) => {
                return Err(format!("syntax error in pattern: invalid escape \\{c}"));
            }
            c => {
                out.push('\\');
                out.push(c);
            }
        }
    }
    Ok(out)
}

/// A character class whose `[` is just before `start`: Go's
/// `filepath.Match` syntax (`[abc]`, `[a-z]`, `[^…]`, `\` escaping). Returns
/// where the class ends, after checking filepath.Match's syntax.
fn class(chars: &[char], start: usize) -> Result<usize, String> {
    let malformed = || "malformed character class ([…])".to_owned();
    let mut i = start;
    let negated = chars.get(i) == Some(&'^');
    if negated {
        i += 1;
    }
    // One character, maybe escaped; never a bare `-` or `]`.
    let one = |i: &mut usize| -> Result<char, String> {
        let c = match chars.get(*i) {
            None | Some('-' | ']') => return Err(malformed()),
            Some('\\') => {
                *i += 1;
                *chars.get(*i).ok_or_else(malformed)?
            }
            Some(&c) => c,
        };
        *i += 1;
        Ok(c)
    };
    let mut elements = 0;
    loop {
        if chars.get(i) == Some(&']') && elements > 0 {
            return Ok(i + 1);
        }
        let low = one(&mut i)?;
        let high = if chars.get(i) == Some(&'-') {
            i += 1;
            one(&mut i)?
        } else {
            low
        };
        if i >= chars.len() || low > high {
            return Err(malformed());
        }
        elements += 1;
    }
}

/// The ignore file that applies to a build of `context` with `containerfile`
/// (a path, as given), if one exists.
pub fn ignore_file(context: &Path, containerfile: &Path) -> Option<PathBuf> {
    let mut beside = containerfile.as_os_str().to_owned();
    beside.push(".dockerignore");
    [PathBuf::from(beside), context.join(".containerignore"), context.join(".dockerignore")]
        .into_iter()
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests;
