//! `${VAR}` in compose files, and the `.env` files variables come from.
//!
//! Compose substitutes variables in every string **value** of a compose
//! file (never in keys) before anything else reads it, with the shell's
//! syntax:
//!
//! | written | becomes |
//! |---|---|
//! | `$VAR`, `${VAR}` | its value; unset: empty, with a warning |
//! | `${VAR:-default}` | `default` if `VAR` is unset or empty |
//! | `${VAR-default}` | `default` if `VAR` is unset |
//! | `${VAR:?message}` | an error if `VAR` is unset or empty |
//! | `${VAR?message}` | an error if `VAR` is unset |
//! | `${VAR:+other}` | `other` if `VAR` is set and not empty, else empty |
//! | `${VAR+other}` | `other` if `VAR` is set, else empty |
//! | `$$` | a literal `$` |
//!
//! A default, message or replacement may hold variables itself
//! (`${A:-${B}}`); it is substituted only if it is used. A `$` that starts
//! none of these (`$1`, `$ `, a `$` at the end) stays as it is, as with
//! Compose; a `${` without a name and its `}` is an error.
//!
//! The variables are the environment the CLI runs in, over the project
//! directory's `.env` file ([`parse_dotenv`]), whose syntax `env_file:`
//! files share.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_yaml_ng::Value;

/// A string with its variables substituted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Substituted {
    pub value: String,
    /// The variables it used that weren't set and had no default (each
    /// once): Compose warns about them.
    pub unset: Vec<String>,
}

/// Substitutes the variables of `text`, reading them with `lookup`.
pub fn substitute(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Substituted, String> {
    let mut out = Substituted { value: String::with_capacity(text.len()), unset: Vec::new() };
    substitute_into(text, lookup, &mut out.value, &mut out.unset)?;
    Ok(out)
}

/// Substitutes every string scalar of `value`, in place (keys stay as they
/// are). The names of unset variables without a default are added to
/// `unset`, once each. An error says where (`services.web.image: …`).
pub fn interpolate(
    value: &mut Value,
    lookup: &dyn Fn(&str) -> Option<String>,
    unset: &mut Vec<String>,
) -> Result<(), String> {
    walk(value, &mut String::new(), lookup, unset)
}

/// The warning Compose gives for a variable used without a value.
pub fn unset_warning(name: &str) -> String {
    format!("The {name:?} variable is not set. Defaulting to a blank string.")
}

fn walk(
    value: &mut Value,
    path: &mut String,
    lookup: &dyn Fn(&str) -> Option<String>,
    unset: &mut Vec<String>,
) -> Result<(), String> {
    match value {
        Value::String(s) if s.contains('$') => {
            let mut out = String::with_capacity(s.len());
            substitute_into(s, lookup, &mut out, unset).map_err(|e| at(path, &e))?;
            *s = out;
        }
        Value::Sequence(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = path.len();
                let _ = write!(path, "[{i}]");
                walk(item, path, lookup, unset)?;
                path.truncate(len);
            }
        }
        Value::Mapping(map) => {
            for (key, item) in map.iter_mut() {
                let len = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                match key {
                    Value::String(k) => path.push_str(k),
                    other => {
                        let _ = write!(path, "{other:?}");
                    }
                }
                walk(item, path, lookup, unset)?;
                path.truncate(len);
            }
        }
        Value::Tagged(tagged) => walk(&mut tagged.value, path, lookup, unset)?,
        _ => {}
    }
    Ok(())
}

/// `message`, prefixed with where it happened.
fn at(path: &str, message: &str) -> String {
    if path.is_empty() { message.to_owned() } else { format!("{path}: {message}") }
}

fn substitute_into(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    out: &mut String,
    unset: &mut Vec<String>,
) -> Result<(), String> {
    let mut rest = text;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        if let Some(r) = after.strip_prefix('$') {
            out.push('$');
            rest = r;
        } else if let Some(inner) = after.strip_prefix('{') {
            let close = closing_brace(inner).ok_or_else(|| invalid(text, "a ${ without its }"))?;
            braced(&inner[..close], text, lookup, out, unset)?;
            rest = &inner[close + 1..];
        } else {
            let len = name_length(after);
            if len > 0 {
                let name = &after[..len];
                match lookup(name) {
                    Some(v) => out.push_str(&v),
                    None => note(unset, name),
                }
            } else {
                // Not a variable: `$1`, `$ `, a final `$`.
                out.push('$');
            }
            rest = &after[len..];
        }
    }
    out.push_str(rest);
    Ok(())
}

/// What is between `${` and `}`: a name, maybe an operator and its word.
fn braced(
    expr: &str,
    text: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    out: &mut String,
    unset: &mut Vec<String>,
) -> Result<(), String> {
    let len = name_length(expr);
    if len == 0 {
        return Err(invalid(text, &format!("${{{expr}}} doesn't start with a variable's name")));
    }
    let (name, tail) = expr.split_at(len);
    let value = lookup(name);
    if tail.is_empty() {
        match value {
            Some(v) => out.push_str(&v),
            None => note(unset, name),
        }
        return Ok(());
    }
    let Some((op, word)) =
        [":-", ":?", ":+", "-", "?", "+"].iter().find_map(|op| tail.strip_prefix(op).map(|w| (*op, w)))
    else {
        return Err(invalid(text, &format!("${{{expr}}}: expected :-, -, :?, ?, :+ or + after {name}")));
    };
    // The `:` forms treat an empty value as unset.
    let present = if op.starts_with(':') { value.as_deref().is_some_and(|v| !v.is_empty()) } else { value.is_some() };
    match op.trim_start_matches(':') {
        "-" if present => out.push_str(value.as_deref().unwrap_or_default()),
        "-" => substitute_into(word, lookup, out, unset)?,
        "?" if present => out.push_str(value.as_deref().unwrap_or_default()),
        "?" => {
            let mut message = String::new();
            substitute_into(word, lookup, &mut message, unset)?;
            return Err(if message.is_empty() {
                format!("required variable {name} is missing a value")
            } else {
                format!("required variable {name} is missing a value: {message}")
            });
        }
        _ if present => substitute_into(word, lookup, out, unset)?,
        _ => {}
    }
    Ok(())
}

fn invalid(text: &str, why: &str) -> String {
    format!("invalid interpolation format in {text:?}: {why} (a literal $ is written $$)")
}

/// The index of the `}` that closes a `${`, `s` starting after it. Every `{`
/// opens a level, `${` or not, as compose-go counts them (its
/// `getFirstBraceClosingIndex`): a default may hold braces of its own
/// (`${JSON:-{"a":1}}`), and when the variable is set, all of it is skipped.
/// `$$` is an escaped `$`. Without a `}` that balances them (`${V:-{}`), the
/// first `}` closes, as it always did.
fn closing_brace(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 1;
    let mut first = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'$' if bytes.get(i + 1) == Some(&b'$') => {
                i += 2;
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                first.get_or_insert(i);
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    first
}

/// The length of the variable name `s` starts with: `[A-Za-z_][A-Za-z0-9_]*`.
fn name_length(s: &str) -> usize {
    s.bytes()
        .enumerate()
        .take_while(|&(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        .count()
}

fn note(unset: &mut Vec<String>, name: &str) {
    if !unset.iter().any(|n| n == name) {
        unset.push(name.to_owned());
    }
}

/// Parses a `.env` file (and `env_file:`'s files), as Compose does (its
/// `dotenv` package, whose own test cases this follows):
///
/// - a UTF-8 byte-order mark at the start is skipped (Windows editors add
///   one);
/// - `KEY=VALUE` lines (`KEY: VALUE` too), optionally `export KEY=VALUE`;
///   blank lines and lines starting with `#` are skipped;
/// - an unquoted value ends at its line's end or at a ` #` comment, its
///   surrounding blanks dropped, its variables substituted;
/// - `'single quotes'`: literal (a backslash before the quote makes it part
///   of the value: `'it\'s'`), and may span lines;
/// - `"double quotes"`: the escapes `\a`, `\b`, `\f`, `\n`, `\r`, `\t`, `\v`,
///   the octal `\0NNN`, `\"`, `\\` and `\$` (a literal `$`), variables
///   substituted, and may span lines; any other backslash stays as written;
/// - a line with only `KEY`: `None`, for the caller to look up (an
///   `env_file` entry takes the environment's value, or is left out).
///
/// Variables in values are read with `lookup` first, then among the file's
/// earlier entries; an unset one is empty, without a warning. Errors give
/// the line.
pub fn parse_dotenv(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<(String, Option<String>)>, String> {
    parse_dotenv_with_base(text, lookup, &BTreeMap::new())
}

/// Parses another env file with earlier files available for interpolation.
pub(crate) fn parse_dotenv_with_base(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    base: &BTreeMap<String, String>,
) -> Result<Vec<(String, Option<String>)>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let chars: Vec<char> = text.chars().collect();
    let mut p = Parser { chars: &chars, i: 0, line: 1 };
    let mut entries: Vec<(String, Option<String>)> = Vec::new();
    let mut defined = base.clone();
    loop {
        // Blank lines and comments.
        match p.peek() {
            None => break,
            Some('\n') => {
                p.bump();
                continue;
            }
            Some(c) if c.is_whitespace() => {
                p.bump();
                continue;
            }
            Some('#') => {
                p.skip_line();
                continue;
            }
            Some(_) => {}
        }
        let line = p.line;
        let text_of_line: String = chars[p.i..].iter().take_while(|&&c| c != '\n').collect();
        let mut key = p.key();
        if key == "export" && matches!(p.peek(), Some(' ' | '\t')) {
            p.skip_blanks();
            key = p.key();
        }
        if key.is_empty() || key.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(format!("line {line}: {text_of_line:?} doesn't start with a variable's name (KEY=VALUE)"));
        }
        p.skip_blanks();
        match p.peek() {
            None | Some('\n' | '#') => {
                match lookup(&key) {
                    Some(value) => {
                        defined.insert(key.clone(), value);
                    }
                    None => {
                        defined.remove(&key);
                    }
                }
                entries.push((key, None));
                p.skip_line();
                continue;
            }
            Some('=' | ':') => p.bump(),
            Some(c) => {
                return Err(format!("line {line}: unexpected character {c:?} after the variable name {key:?}"));
            }
        }
        p.skip_blanks();
        let lookup_here = |name: &str| lookup(name).or_else(|| defined.get(name).cloned());
        let expand = |raw: &str| -> Result<String, String> {
            let mut out = String::with_capacity(raw.len());
            substitute_into(raw, &lookup_here, &mut out, &mut Vec::new()).map_err(|e| format!("line {line}: {e}"))?;
            Ok(out)
        };
        let value = match p.peek() {
            Some('\'') => {
                p.bump();
                let raw = p.until_quote('\'', line)?;
                p.end_of_value(line)?;
                raw
            }
            Some('"') => {
                p.bump();
                let raw = p.until_quote('"', line)?;
                p.end_of_value(line)?;
                expand(&raw)?
            }
            _ => {
                let raw = p.rest_of_line();
                // ` #` starts a comment; a `#` inside a word doesn't.
                let cut = raw
                    .char_indices()
                    .find(|&(i, c)| c == '#' && raw[..i].ends_with(char::is_whitespace))
                    .map_or(raw.len(), |(i, _)| i);
                expand(raw[..cut].trim())?
            }
        };
        defined.insert(key.clone(), value.clone());
        entries.push((key, Some(value)));
    }
    Ok(entries)
}

/// A cursor over a `.env` file's characters.
struct Parser<'a> {
    chars: &'a [char],
    i: usize,
    line: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn bump(&mut self) {
        if self.peek() == Some('\n') {
            self.line += 1;
        }
        self.i += 1;
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\r')) {
            self.bump();
        }
    }

    /// To the start of the next line.
    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            self.bump();
            if c == '\n' {
                break;
            }
        }
    }

    /// A variable's name: letters, digits, `_`, `.`, `-`, `[`, `]`.
    fn key(&mut self) -> String {
        let mut key = String::new();
        while let Some(c) = self.peek().filter(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-' | '[' | ']')) {
            key.push(c);
            self.bump();
        }
        key
    }

    /// The rest of this line, without its `\n` (which is consumed).
    fn rest_of_line(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            self.bump();
            if c == '\n' {
                break;
            }
            s.push(c);
        }
        s
    }

    /// A quoted value's text, up to its closing `quote` (consumed). A
    /// backslash before the quote makes the quote part of the value, in both
    /// kinds of quotes (compose-go's rule). In double quotes, escapes are
    /// translated ([`Parser::escape`]); `\$` becomes `$$`, which substitution
    /// then turns into a literal `$`. In single quotes, everything else is
    /// literal, a pair of backslashes staying a pair (so `'a\\'` ends after
    /// them).
    fn until_quote(&mut self, quote: char, line: usize) -> Result<String, String> {
        let mut s = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(format!("line {line}: the value's {quote} quote is never closed"));
            };
            self.bump();
            if c == quote {
                return Ok(s);
            }
            if c != '\\' {
                s.push(c);
                continue;
            }
            // A backslash at the very end: the next round says the quote is never closed.
            let Some(next) = self.peek() else { continue };
            if next == quote {
                s.push(quote);
                self.bump();
            } else if quote == '\'' {
                s.push('\\');
                if next == '\\' {
                    s.push('\\');
                    self.bump();
                }
            } else if let Some((escaped, taken)) = self.escape() {
                s.push_str(&escaped);
                self.i += taken;
            } else {
                s.push('\\');
            }
        }
    }

    /// What the backslash just read means in double quotes, from the
    /// character after it: the text it stands for, and how many characters
    /// that took. The shell's escapes, as compose-go's `escapeSeqRegex` has
    /// them: `\a \b \f \n \r \t \v`, `\0` and three octal digits (`\0123` is
    /// `S`), `\"`, `\\`, and `\$`, which is written `$$` for the
    /// substitution that follows. Anything else (`\x07`, `ዤ`, `\ `) is
    /// not an escape here.
    fn escape(&self) -> Option<(String, usize)> {
        let simple = match self.peek()? {
            'a' => '\u{7}',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{b}',
            '"' => '"',
            '\\' => '\\',
            '$' => return Some(("$$".to_owned(), 1)),
            '0' => {
                let digits: String = self.chars[self.i + 1..].iter().take(3).collect();
                if digits.len() != 3 || !digits.chars().all(|d| ('0'..='7').contains(&d)) {
                    return None;
                }
                let value = u32::from_str_radix(&digits, 8).ok().filter(|v| *v <= 0o377)?;
                return Some((char::from_u32(value)?.to_string(), 4));
            }
            _ => return None,
        };
        Some((simple.to_string(), 1))
    }

    /// After a quoted value: only blanks or a comment to the line's end.
    fn end_of_value(&mut self, line: usize) -> Result<(), String> {
        self.skip_blanks();
        match self.peek() {
            None | Some('\n' | '#') => {
                self.skip_line();
                Ok(())
            }
            Some(c) => Err(format!("line {line}: unexpected {c:?} after the closing quote")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(name: &str) -> Option<String> {
        match name {
            "TAG" => Some("1.27".into()),
            "EMPTY" => Some(String::new()),
            "HOST" => Some("db".into()),
            "A_1" => Some("a".into()),
            _ => None,
        }
    }

    fn sub(text: &str) -> String {
        substitute(text, &vars).unwrap().value
    }

    #[test]
    fn plain_and_braced_variables_are_replaced() {
        assert_eq!(sub("nginx:$TAG"), "nginx:1.27");
        assert_eq!(sub("nginx:${TAG}-alpine"), "nginx:1.27-alpine");
        assert_eq!(sub("$A_1$A_1"), "aa");
        assert_eq!(sub("postgres://$HOST:5432/$TAG.db"), "postgres://db:5432/1.27.db");
        assert_eq!(sub("no variables"), "no variables");
        assert_eq!(sub("ünïcödé ${HOST} ✓"), "ünïcödé db ✓");
    }

    #[test]
    fn unset_variables_become_empty_and_are_reported_once() {
        let s = substitute("${NOPE}-$NOPE-${OTHER}", &vars).unwrap();
        assert_eq!(s.value, "--");
        assert_eq!(s.unset, ["NOPE", "OTHER"]);
        assert_eq!(unset_warning("NOPE"), "The \"NOPE\" variable is not set. Defaulting to a blank string.");
    }

    #[test]
    fn defaults_tell_unset_from_empty() {
        assert_eq!(sub("${NOPE:-d}"), "d");
        assert_eq!(sub("${EMPTY:-d}"), "d");
        assert_eq!(sub("${TAG:-d}"), "1.27");
        assert_eq!(sub("${NOPE-d}"), "d");
        assert_eq!(sub("${EMPTY-d}"), "", "set but empty: no default without the colon");
        assert_eq!(sub("${TAG-d}"), "1.27");
        assert_eq!(sub("${NOPE:-}"), "");
        // A default that isn't used reports nothing.
        assert!(substitute("${TAG:-$MISSING}", &vars).unwrap().unset.is_empty());
    }

    #[test]
    fn replacements_apply_only_to_set_variables() {
        assert_eq!(sub("${TAG:+yes}"), "yes");
        assert_eq!(sub("${EMPTY:+yes}"), "");
        assert_eq!(sub("${NOPE:+yes}"), "");
        assert_eq!(sub("${EMPTY+yes}"), "yes");
        assert_eq!(sub("${NOPE+yes}"), "");
    }

    #[test]
    fn required_variables_fail_with_their_message() {
        assert_eq!(sub("${TAG:?set TAG}"), "1.27");
        assert_eq!(sub("${EMPTY?set it}"), "");
        let e = substitute("${NOPE:?set it in .env}", &vars).unwrap_err();
        assert_eq!(e, "required variable NOPE is missing a value: set it in .env");
        let e = substitute("${EMPTY:?}", &vars).unwrap_err();
        assert_eq!(e, "required variable EMPTY is missing a value");
        let e = substitute("${NOPE?for $HOST}", &vars).unwrap_err();
        assert_eq!(e, "required variable NOPE is missing a value: for db");
    }

    #[test]
    fn defaults_nest() {
        assert_eq!(sub("${NOPE:-${HOST}:${TAG}}"), "db:1.27");
        assert_eq!(sub("${NOPE:-${ALSO_NOT:-deep}}"), "deep");
        assert_eq!(sub("${NOPE:-{literal}}"), "{literal}", "a plain {{ opens a level too: the last }} closes");
        assert_eq!(sub("x${NOPE:-a}y${TAG}z"), "xay1.27z");
    }

    /// compose-go's template tests (`TestValueWithCurlyBracesDefault`,
    /// `TestNoValueWithCurlyBracesDefault`): a default may hold braces, and
    /// when the variable is set, all of the default is skipped, whatever it
    /// holds.
    #[test]
    fn a_default_holding_braces_is_one_default() {
        let json = |name: &str| match name {
            "JSON" => Some(r#"{"json":2}"#.to_owned()),
            "Y" => Some("why".to_owned()),
            _ => None,
        };
        let sub = |text: &str| substitute(text, &json).unwrap().value;
        assert_eq!(sub(r#"ok ${JSON:-{"json":1}}"#), r#"ok {"json":2}"#);
        assert_eq!(sub(r#"ok ${JSON-{"json":1}}"#), r#"ok {"json":2}"#);
        assert_eq!(sub(r#"ok ${MISSING:-{"json":1}}"#), r#"ok {"json":1}"#);
        assert_eq!(sub(r#"ok ${MISSING-{"json":1}}"#), r#"ok {"json":1}"#);
        assert_eq!(sub("ok ${JSON:+x{y}z}"), "ok x{y}z");
        assert_eq!(sub(r#"${MISSING:-{"a":{"b":"${Y}"}}} and ${Y}"#), r#"{"a":{"b":"why"}} and why"#);
        assert_eq!(sub(r#"${JSON:-{"a":{"b":"${Y}"}}} and ${Y}"#), r#"{"json":2} and why"#);
        // An escaped `$` before a brace is text, and the brace still counts.
        assert_eq!(sub("${MISSING:-$${x}}"), "${x}");
        // No `}` balances the `{`: the first one closes, as it always did.
        assert_eq!(sub("${MISSING:-{}"), "{");
        assert_eq!(sub("${JSON:-{}"), r#"{"json":2}"#);
        // A `${` whose own `}` is missing is still an error.
        assert!(substitute("a ${MISSING:-${Y}", &json).is_err());
    }

    /// compose-go's own cases (template/template_test.go): nesting, which of
    /// `-`, `:-`, `+`, `:+`, `?` an expression is by the one that comes
    /// first (`${V?bar-baz}` is a `?`), and what a stray `$` is.
    #[test]
    fn template_cases_from_compose_go() {
        let go = |name: &str| match name {
            "FOO" => Some("first".to_owned()),
            "BAR" => Some(String::new()),
            "JSON" => Some(r#"{"json":2}"#.to_owned()),
            _ => None,
        };
        let cases: &[(&str, &str)] = &[
            ("ok ${missing:-{\"json\":1}}", "ok {\"json\":1}"),
            ("ok ${missing-{\"json\":1}}", "ok {\"json\":1}"),
            ("${A:+${A},}B", "B"),
            ("+ok ${UNSET:-${BAR-defaultValue}}", "+ok "),
            (":?ok ${BAR:-defaultValue}", ":?ok defaultValue"),
            ("ok ${BAR+$FOO ${FOO:+second}}", "ok first second"),
            ("ok ${UNSET_VAR-${FOO} ${FOO}}", "ok first first"),
            ("${UNSET_VAR-myerror?msg}", "myerror?msg"),
            ("${FOO?bar-baz}", "first"),
            ("ok ${BAR:-/non:-alphanumeric}", "ok /non:-alphanumeric"),
            ("$}", "$}"),
            ("^REGEX$", "^REGEX$"),
            ("a $ string", "a $ string"),
            ("$FOO-bar", "first-bar"),
            ("ok ${SUBDOMAIN:-redis}.${FOO:?}", "ok redis.first"),
        ];
        for (template, expected) in cases {
            assert_eq!(substitute(template, &go).unwrap().value, *expected, "{template}");
        }
        let e = substitute("${UNSET_VAR?bar-baz}", &go).unwrap_err();
        assert_eq!(e, "required variable UNSET_VAR is missing a value: bar-baz");
        // A default is substituted only when it is used: no warning for what isn't.
        assert!(substitute("${A:+${A},}B", &go).unwrap().unset.is_empty());
        assert_eq!(substitute("${A:-${B}}", &go).unwrap().unset, ["B"]);
        for invalid in ["${", "${}", "${ }", "${ foo}", "${foo }", "${foo!}"] {
            assert!(substitute(invalid, &go).is_err(), "{invalid}");
        }
    }

    /// compose-go's own cases (dotenv/godotenv_test.go `TestParsing` and
    /// `TestExpanding`), the ones the other tests here don't spell out.
    #[test]
    fn dotenv_cases_from_compose_go() {
        let one = |text: &str| dotenv(text).remove(0).1.unwrap();
        let cases: &[(&str, &str)] = &[
            ("FOO =bar", "bar"),
            ("FOO= bar", "bar"),
            ("FOO=bar #", "bar"),
            ("FOO=bar #this is foo", "bar"),
            ("FOO=123#not-an-inline-comment", "123#not-an-inline-comment"),
            ("FOO=\"bar#baz\"#", "bar#baz"),
            ("FOO='bar#baz' # comment", "bar#baz"),
            ("FOO=\"bar#baz#bang\" # comment", "bar#baz#bang"),
            ("export\tOPTION_A=2", "2"),
            ("  export OPTION_A=2", "2"),
            ("export OPTION_A=\"export A\"", "export A"),
            ("export OPTION_B='\\n'", "\\n"),
            ("OPTION_A: Foo=bar", "Foo=bar"),
            ("OPTION_A=1:B", "1:B"),
            ("FOO=foobar=", "foobar="),
            ("FOO=a\\tb", "a\\tb"),
            ("FOO=\"a\\tb\"", "a\tb"),
            ("FOO=\"bar\\nbaz\\\\\"", "bar\nbaz\\"),
            ("FOO=\"foo\\${BAR}\"", "foo${BAR}"),
            ("FOO=\"quote $TAG\"", "quote 1.27"),
            ("FOO='quote $TAG'", "quote $TAG"),
            ("FOO=\"foo\\$BAR\"", "foo$BAR"),
            ("TEST_URLS=\"stratum+tcp://a:3333\nstratum+tcp://a:443\"", "stratum+tcp://a:3333\nstratum+tcp://a:443"),
        ];
        for (text, expected) in cases {
            assert_eq!(one(text), *expected, "{text:?}");
        }
        assert!(parse_dotenv("lol$wut", &vars).is_err(), "a line that isn't KEY=VALUE");
    }

    #[test]
    fn dollars_escape_and_stray_dollars_stay() {
        assert_eq!(sub("$$HOME and $${TAG}"), "$HOME and ${TAG}");
        assert_eq!(sub("cost: 5$"), "cost: 5$");
        assert_eq!(sub("awk '{print $1}'"), "awk '{print $1}'");
        assert_eq!(sub("a $ b"), "a $ b");
        assert_eq!(sub("${NOPE:-$$}"), "$");
    }

    #[test]
    fn malformed_braces_are_errors() {
        for bad in ["${", "${TAG", "${}", "${1A}", "${TAG:x}", "${TAG!}", "${ TAG}", "a ${NOPE:-${B}"] {
            let e = substitute(bad, &vars).unwrap_err();
            assert!(e.starts_with("invalid interpolation format in "), "{bad}: {e}");
            assert!(e.ends_with("(a literal $ is written $$)"), "{bad}: {e}");
        }
    }

    #[test]
    fn yaml_values_are_interpolated_and_keys_are_not() {
        let mut v: Value = serde_yaml_ng::from_str(
            "services:\n  $HOST:\n    image: nginx:${TAG}\n    ports: [\"${PORT:-80}:80\", 443]\n",
        )
        .unwrap();
        let mut unset = Vec::new();
        interpolate(&mut v, &vars, &mut unset).unwrap();
        assert_eq!(v["services"]["$HOST"]["image"], "nginx:1.27");
        assert_eq!(v["services"]["$HOST"]["ports"][0], "80:80");
        assert_eq!(v["services"]["$HOST"]["ports"][1], 443);
        assert!(unset.is_empty());
    }

    #[test]
    fn interpolation_errors_name_their_place() {
        let mut v: Value =
            serde_yaml_ng::from_str("services:\n  web:\n    ports: [\"80\", \"${P:?pick a port}\"]\n").unwrap();
        let e = interpolate(&mut v, &vars, &mut Vec::new()).unwrap_err();
        assert_eq!(e, "services.web.ports[1]: required variable P is missing a value: pick a port");
        let mut v: Value = serde_yaml_ng::from_str("a: [x, {b: $X}, !custom $Y]").unwrap();
        let mut unset = Vec::new();
        interpolate(&mut v, &vars, &mut unset).unwrap();
        assert_eq!(unset, ["X", "Y"]);
    }

    fn dotenv(text: &str) -> Vec<(String, Option<String>)> {
        parse_dotenv(text, &vars).unwrap()
    }

    fn pairs(entries: &[(&str, &str)]) -> Vec<(String, Option<String>)> {
        entries.iter().map(|(k, v)| (k.to_string(), Some(v.to_string()))).collect()
    }

    #[test]
    fn dotenv_lines_comments_and_export() {
        let text = "# settings\n\nA=1\nexport B=two words\n  C = spaced  \nD=\nE=a#b # comment\nF: yaml\r\n";
        assert_eq!(
            dotenv(text),
            pairs(&[("A", "1"), ("B", "two words"), ("C", "spaced"), ("D", ""), ("E", "a#b"), ("F", "yaml")])
        );
        assert_eq!(dotenv("export=1\n"), pairs(&[("export", "1")]), "a variable named export");
        assert_eq!(dotenv("KEY\nOTHER # comment\n"), [("KEY".to_owned(), None), ("OTHER".to_owned(), None)]);
        assert!(dotenv("").is_empty());
    }

    #[test]
    fn dotenv_quotes() {
        let text = "S='lit $TAG \\n # not a comment'\nD=\"tab\\tnl\\nq\\\" \\\\ \\$TAG $TAG\" # comment\nM='multi\nline'\nN=\"a\nb\"\nU=\\n\n";
        assert_eq!(
            dotenv(text),
            pairs(&[
                ("S", "lit $TAG \\n # not a comment"),
                ("D", "tab\tnl\nq\" \\ $TAG 1.27"),
                ("M", "multi\nline"),
                ("N", "a\nb"),
                ("U", "\\n"),
            ])
        );
    }

    /// compose-go dotenv/godotenv.go: "seek past the UTF-8 BOM if it exists
    /// (particularly on Windows, some editors tend to add it, and it'll cause
    /// parsing to fail)"; its `TestUTF8BOM`.
    #[test]
    fn dotenv_skips_a_utf8_byte_order_mark() {
        assert_eq!(dotenv("\u{feff}TAG=1.27\nPORT=8080\n"), pairs(&[("TAG", "1.27"), ("PORT", "8080")]));
        assert_eq!(dotenv("\u{feff}# comment\nA=1\n"), pairs(&[("A", "1")]));
        assert!(dotenv("\u{feff}").is_empty());
    }

    /// compose-go dotenv/parser.go: "skip escaped quote symbol (\" or \',
    /// depends on quote)"; `TestUnterminatedQuotes`.
    #[test]
    fn dotenv_single_quotes_take_an_escaped_quote() {
        assert_eq!(dotenv("A='it\\'s here'\n"), pairs(&[("A", "it's here")]));
        // Any other backslash is literal, and a pair stays a pair.
        assert_eq!(dotenv("B='C:\\path\\n'\n"), pairs(&[("B", "C:\\path\\n")]));
        assert_eq!(dotenv("C='a\\\\' # comment\n"), pairs(&[("C", "a\\\\")]));
        // In double quotes the escaped quote was always there.
        assert_eq!(dotenv("D=\"say \\\"hi\\\"\"\n"), pairs(&[("D", "say \"hi\"")]));
        for open in ["KEY='value\\'", "KEY='", "KEY=\"value\\\"", "KEY='value\""] {
            let e = parse_dotenv(open, &vars).unwrap_err();
            assert!(e.contains("never closed"), "{open}: {e}");
        }
    }

    /// compose-go dotenv/parser.go `escapeSeqRegex` and `TestParsing`: the
    /// shell's escapes in double quotes, `\0` and three octal digits among
    /// them; the rest (`\x07`, `\u12e4`) is not an escape.
    #[test]
    fn dotenv_double_quotes_take_the_shell_escapes() {
        let one = |text: &str| dotenv(text).remove(0).1.unwrap();
        assert_eq!(one("K=\"Z\\aZ\\bZ\\fZ\\nZ\\rZ\\tZ\\vZ\\\\Z\\0123Z\""), "Z\u{7}Z\u{8}Z\u{c}Z\nZ\rZ\tZ\u{b}Z\\ZSZ");
        assert_eq!(one("K=\"\\0123\""), "S");
        assert_eq!(one("K=\"\\0377\""), "\u{ff}");
        assert_eq!(one("K=\"\\0000\""), "\0");
        // Not three octal digits, or too big for a byte: as written.
        for same in ["\\0", "\\01", "\\012", "\\0128", "\\0400", "\\x07", "\\u12e4", "\\U00101234", "\\ b", "\\c"] {
            assert_eq!(one(&format!("K=\"{same}\"")), same, "{same}");
        }
        // Variables are substituted after the escapes: `\$` stays a dollar.
        assert_eq!(one("K=\"\\$TAG ${TAG}\\0101\""), "$TAG 1.27A");
    }

    #[test]
    fn dotenv_values_see_the_environment_then_earlier_lines() {
        let text = "BASE=/srv\nDATA=${BASE}/data\nTAG=local\nIMAGE=app:${TAG}\nX=${MISSING:-d}\n";
        assert_eq!(
            dotenv(text),
            pairs(&[("BASE", "/srv"), ("DATA", "/srv/data"), ("TAG", "local"), ("IMAGE", "app:1.27"), ("X", "d")])
        );
    }

    #[test]
    fn dotenv_errors_give_the_line() {
        for (text, start) in [
            ("A=1\nB='open\n", "line 2: "),
            ("A=1\n\nB=\"open\n", "line 3: "),
            ("A='x' y\n", "line 1: "),
            ("A=1\n1A=2\n", "line 2: "),
            ("A B=1\n", "line 1: "),
            ("=1\n", "line 1: "),
            ("A=${NOPE:?needed}\n", "line 1: required variable NOPE"),
        ] {
            let e = parse_dotenv(text, &vars).unwrap_err();
            assert!(e.starts_with(start), "{text:?}: {e}");
        }
    }
}
