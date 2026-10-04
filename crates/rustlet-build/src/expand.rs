//! Variables and quotes in instruction arguments, as Docker processes them
//! (BuildKit's `shell.Lex`: `ProcessWord`, `ProcessWords`).
//!
//! ```text
//!  ENV DIR=/srv  NAME="my app"
//!  WORKDIR $DIR/${NAME}       → /srv/my app
//!  COPY ${SRC:-src}/ ./       → src/ ./           (SRC unset: the default)
//!  LABEL v=\$NOT              → $NOT              (escaped: literal)
//! ```
//!
//! `$NAME` and `${NAME}` expand to the value (nothing if unset);
//! `${NAME:-word}` to `word` if unset or empty, `${NAME-word}` if unset;
//! `${NAME:+word}` to `word` if set and not empty, `${NAME+word}` if set;
//! `${NAME:?message}` and `${NAME?message}` fail with the message if unset
//! (or empty, with `:`). `word` is itself processed. Single quotes keep
//! everything literal; double quotes keep whitespace and the escape
//! character's meaning only before `"`, `$` and itself; quotes are removed
//! from the result. The escape character (`\` or `` ` ``) makes the next
//! character literal outside single quotes.
//!
//! [`word`] makes one string of its input (an `ENV` value, a `WORKDIR`);
//! [`words`] splits at unquoted whitespace, in the input *and* in what
//! unquoted variables expand to, as a shell does (`EXPOSE`, `VOLUME`,
//! `COPY` in shell form). Empty words are dropped, a quoted `""` included
//! (BuildKit's `ProcessWords` does the same).
//!
//! Names are `[A-Za-z_][A-Za-z0-9_]*`. Where BuildKit differs:
//!
//! - a `$` not followed by a name or `{` is itself: `$1`, `$$` and a final
//!   `$` stay as written (BuildKit reads `$1`, `$$`, `$@`… as the shell's
//!   special parameters, always empty in a build);
//! - `${NAME#pattern}`, `%`, `/` and the other forms are refused, not
//!   applied (BuildKit's newer syntax has some);
//! - a default keeps its own quoting: `${V:-"a b"}` unquoted is one word
//!   when V is unset, as in a shell (BuildKit splits it in two).

/// A variable that had to be set wasn't (`${NAME:?message}`), or a `${`
/// that never closes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ExpandError(pub String);

/// Expands `raw` as one word. `lookup` gives a variable's value.
pub fn word(raw: &str, escape: char, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String, ExpandError> {
    Ok(Lexer::run(raw, escape, lookup)?.into_iter().map(|piece| piece.ch).collect())
}

/// Expands `raw` into words.
pub fn words(raw: &str, escape: char, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Vec<String>, ExpandError> {
    let mut words = Vec::new();
    let mut current = String::new();
    for piece in Lexer::run(raw, escape, lookup)? {
        if piece.splits && piece.ch.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(piece.ch);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

/// One character of the result. `splits`: whitespace that separates words
/// (unquoted, as written or from an unquoted variable); quoted or escaped
/// whitespace is part of a word.
#[derive(Debug, Clone, Copy)]
struct Piece {
    ch: char,
    splits: bool,
}

fn quoted(ch: char) -> Piece {
    Piece { ch, splits: false }
}

/// A variable's value, unquoted: subject to splitting.
fn unquoted(value: &str) -> Vec<Piece> {
    value.chars().map(|ch| Piece { ch, splits: true }).collect()
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    escape: char,
    lookup: &'a dyn Fn(&str) -> Option<String>,
}

impl Lexer<'_> {
    fn run(raw: &str, escape: char, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Vec<Piece>, ExpandError> {
        let mut lexer = Lexer { chars: raw.chars().collect(), pos: 0, escape, lookup };
        lexer.until(None).map_err(|e| ExpandError(format!("failed to process {raw:?}: {e}")))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    /// Processes up to `stop` (unquoted and unescaped, consumed), or to the
    /// end without one.
    fn until(&mut self, stop: Option<char>) -> Result<Vec<Piece>, String> {
        let mut out = Vec::new();
        loop {
            let Some(c) = self.next() else {
                return match stop {
                    None => Ok(out),
                    Some(_) => Err("missing '}'".to_owned()),
                };
            };
            if Some(c) == stop {
                return Ok(out);
            }
            match c {
                '\'' => self.single_quoted(&mut out)?,
                '"' => self.double_quoted(&mut out)?,
                '$' => out.extend(self.dollar()?),
                // The next character as itself, whatever it is; an escape
                // character at the very end is dropped.
                c if c == self.escape => out.extend(self.next().map(quoted)),
                c => out.push(Piece { ch: c, splits: true }),
            }
        }
    }

    /// After a `'`: everything literal, up to the next `'`.
    fn single_quoted(&mut self, out: &mut Vec<Piece>) -> Result<(), String> {
        loop {
            match self.next() {
                None => return Err("unterminated single quote".to_owned()),
                Some('\'') => return Ok(()),
                Some(c) => out.push(quoted(c)),
            }
        }
    }

    /// After a `"`: variables expand, the escape character escapes only
    /// `"`, `$`, itself and a newline.
    fn double_quoted(&mut self, out: &mut Vec<Piece>) -> Result<(), String> {
        loop {
            match self.next() {
                None => return Err("unterminated double quote".to_owned()),
                Some('"') => return Ok(()),
                Some('$') => out.extend(self.dollar()?.into_iter().map(|piece| quoted(piece.ch))),
                Some(c) if c == self.escape => match self.peek() {
                    Some(n) if n == '"' || n == '$' || n == '\n' || n == self.escape => {
                        self.pos += 1;
                        out.push(quoted(n));
                    }
                    // Before anything else the escape character is itself.
                    _ => out.push(quoted(c)),
                },
                Some(c) => out.push(quoted(c)),
            }
        }
    }

    /// After a `$`.
    fn dollar(&mut self) -> Result<Vec<Piece>, String> {
        match self.peek() {
            Some('{') => {
                self.pos += 1;
                self.braced()
            }
            Some(c) if is_name_start(c) => {
                let name = self.name();
                Ok(unquoted(&(self.lookup)(&name).unwrap_or_default()))
            }
            _ => Ok(vec![quoted('$')]),
        }
    }

    /// After a `${`.
    fn braced(&mut self) -> Result<Vec<Piece>, String> {
        match self.peek() {
            None => return Err("missing '}'".to_owned()),
            Some(c) if is_name_start(c) => {}
            Some(_) => return Err("bad substitution: ${ needs a variable name".to_owned()),
        }
        let name = self.name();
        let value = (self.lookup)(&name);
        let unsupported = |modifier: String| {
            format!("unsupported modifier ({modifier}) in ${{{name}…}}: only :- - :+ + :? ? are supported")
        };
        let (colon, op) = match self.next() {
            None => return Err("missing '}'".to_owned()),
            Some('}') => return Ok(unquoted(&value.unwrap_or_default())),
            Some(':') => match self.next() {
                None => return Err("missing '}'".to_owned()),
                Some(op @ ('-' | '+' | '?')) => (true, op),
                Some(other) => return Err(unsupported(format!(":{other}"))),
            },
            Some(op @ ('-' | '+' | '?')) => (false, op),
            Some(other) => return Err(unsupported(other.to_string())),
        };
        let word = self.until(Some('}'))?;
        // With `:`, an empty value counts as unset.
        let unset = match &value {
            None => true,
            Some(v) => colon && v.is_empty(),
        };
        match (op, value) {
            ('-', Some(value)) if !unset => Ok(unquoted(&value)),
            ('-', _) => Ok(word),
            ('+', _) if unset => Ok(Vec::new()),
            ('+', _) => Ok(word),
            (_, Some(value)) if !unset => Ok(unquoted(&value)),
            (_, value) => {
                let message: String = word.iter().map(|piece| piece.ch).collect();
                let message = match (message.is_empty(), value) {
                    (false, _) => message,
                    (true, None) => "is not allowed to be unset".to_owned(),
                    (true, Some(_)) => "is not allowed to be empty".to_owned(),
                };
                Err(format!("{name}: {message}"))
            }
        }
    }

    /// A variable name; its first character is already checked.
    fn name(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }
}

#[cfg(test)]
mod tests;
