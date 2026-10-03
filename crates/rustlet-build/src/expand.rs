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
//! `COPY` in shell form).

/// A variable that had to be set wasn't (`${NAME:?message}`), or a `${`
/// that never closes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ExpandError(pub String);

/// Expands `raw` as one word. `lookup` gives a variable's value.
pub fn word(raw: &str, escape: char, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String, ExpandError> {
    let _ = (raw, escape, lookup);
    unimplemented!("expand::word: agent A")
}

/// Expands `raw` into words.
pub fn words(raw: &str, escape: char, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Vec<String>, ExpandError> {
    let _ = (raw, escape, lookup);
    unimplemented!("expand::words: agent A")
}
