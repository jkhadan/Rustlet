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
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    /// The cleaned pattern, without its `!`.
    text: String,
    /// `!`: an exception, which includes again.
    exclusion: bool,
    kind: Kind,
}

/// How a pattern matches, as `patternmatcher` compiles it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// No wildcard: the path itself.
    Exact,
    /// `text**`: paths starting with `text`.
    Prefix(String),
    /// `**text`, `text` without wildcards: paths ending with `text` (and,
    /// for `**/text`, `text` itself).
    Suffix(String),
    /// Anything else: the tokens of `patternmatcher`'s regular expression.
    Tokens(Vec<Token>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Char(char),
    /// `?`: a character but `/`.
    Any,
    /// `*`: characters but `/`.
    Star,
    /// `**/`, or `**` inside: any number of whole components, none
    /// included (`(.*/)?`).
    Dirs,
    /// `**` at the end: anything (`.*`).
    Rest,
    /// `[…]`.
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

impl Pattern {
    /// `patternmatcher`'s `compile`, with Go's `filepath.Match` syntax
    /// checks.
    fn compile(text: String, exclusion: bool) -> Result<Pattern, String> {
        #[derive(PartialEq)]
        enum Type {
            Exact,
            Prefix,
            Suffix,
            Regexp,
        }
        let chars: Vec<char> = text.chars().collect();
        let mut tokens = Vec::new();
        let mut kind = Type::Exact;
        let mut i = 0;
        while i < chars.len() {
            let first = i == 0;
            let c = chars[i];
            i += 1;
            match c {
                '*' if chars.get(i) == Some(&'*') => {
                    i += 1;
                    // `**/` is `**`.
                    if chars.get(i) == Some(&'/') {
                        i += 1;
                    }
                    if i == chars.len() {
                        if kind == Type::Exact {
                            kind = Type::Prefix;
                        } else {
                            tokens.push(Token::Rest);
                            kind = Type::Regexp;
                        }
                    } else {
                        tokens.push(Token::Dirs);
                        kind = Type::Regexp;
                    }
                    if first {
                        kind = Type::Suffix;
                    }
                }
                '*' => {
                    tokens.push(Token::Star);
                    kind = Type::Regexp;
                }
                '?' => {
                    tokens.push(Token::Any);
                    kind = Type::Regexp;
                }
                '\\' => match chars.get(i) {
                    Some(&next) => {
                        tokens.push(Token::Char(next));
                        i += 1;
                        kind = Type::Regexp;
                    }
                    None => return Err("a pattern can't end with \\".to_owned()),
                },
                '[' => {
                    let (class, next) = class(&chars, i)?;
                    tokens.push(class);
                    i = next;
                    kind = Type::Regexp;
                }
                c => tokens.push(Token::Char(c)),
            }
        }
        let kind = match kind {
            Type::Exact => Kind::Exact,
            Type::Prefix => Kind::Prefix(text[..text.len() - 2].to_owned()),
            Type::Suffix => Kind::Suffix(text[2..].to_owned()),
            Type::Regexp => Kind::Tokens(tokens),
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
            Kind::Tokens(tokens) => {
                let mut memo = vec![None; (tokens.len() + 1) * (path.len() + 1)];
                match_tokens(tokens, path, 0, 0, &mut memo)
            }
        }
    }

    /// The text up to the first wildcard or escape.
    fn literal_prefix(&self) -> &str {
        let end = self.text.find(['*', '?', '[', '\\']).unwrap_or(self.text.len());
        &self.text[..end]
    }
}

/// A character class whose `[` is just before `start`: Go's
/// `filepath.Match` syntax (`[abc]`, `[a-z]`, `[^…]`, `\` escaping). Returns
/// the token and where the class ends.
fn class(chars: &[char], start: usize) -> Result<(Token, usize), String> {
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
    let mut ranges = Vec::new();
    loop {
        if chars.get(i) == Some(&']') && !ranges.is_empty() {
            return Ok((Token::Class { negated, ranges }, i + 1));
        }
        let low = one(&mut i)?;
        let high = if chars.get(i) == Some(&'-') {
            i += 1;
            one(&mut i)?
        } else {
            low
        };
        if i >= chars.len() {
            return Err(malformed());
        }
        ranges.push((low, high));
    }
}

/// Do `tokens[t..]` match `path[at..]`? Memoized on `(t, at)`, so no
/// pattern takes more than tokens × bytes steps.
fn match_tokens(tokens: &[Token], path: &str, t: usize, at: usize, memo: &mut [Option<bool>]) -> bool {
    let key = t * (path.len() + 1) + at;
    if let Some(known) = memo[key] {
        return known;
    }
    let rest = &path[at..];
    let next = rest.chars().next();
    let step = next.map_or(0, char::len_utf8);
    let result = match tokens.get(t) {
        None => rest.is_empty(),
        Some(Token::Char(c)) => next == Some(*c) && match_tokens(tokens, path, t + 1, at + step, memo),
        Some(Token::Any) => next.is_some_and(|c| c != '/') && match_tokens(tokens, path, t + 1, at + step, memo),
        Some(Token::Class { negated, ranges }) => {
            next.is_some_and(|c| ranges.iter().any(|(low, high)| (*low..=*high).contains(&c)) != *negated)
                && match_tokens(tokens, path, t + 1, at + step, memo)
        }
        Some(Token::Star) => {
            match_tokens(tokens, path, t + 1, at, memo)
                || (next.is_some_and(|c| c != '/') && match_tokens(tokens, path, t, at + step, memo))
        }
        Some(Token::Dirs) => {
            match_tokens(tokens, path, t + 1, at, memo)
                || rest.match_indices('/').any(|(i, _)| match_tokens(tokens, path, t + 1, at + i + 1, memo))
        }
        Some(Token::Rest) => true,
    };
    memo[key] = Some(result);
    result
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
