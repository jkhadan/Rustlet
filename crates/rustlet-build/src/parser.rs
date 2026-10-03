//! The Containerfile's syntax: lines, continuations, comments, parser
//! directives, instructions and their flags, JSON ("exec") and shell forms.
//!
//! ```dockerfile
//! # escape=\                          ← a parser directive (only before anything else)
//! ARG BASE=alpine                     ← a global ARG: usable in FROM lines
//! FROM ${BASE}:3.20 AS build          ← a stage, named `build`
//! RUN apk add --no-cache gcc \        ← continued on the next line
//!     musl-dev
//! COPY --chown=1000:1000 src/ /src/   ← flags, then sources and destination
//! CMD ["/app", "--serve"]             ← exec form: a JSON array of strings
//! ```
//!
//! The parser keeps values as written: variables are expanded, and quotes
//! removed, only when a step runs (`op`), against what the image's `ENV` and
//! the stage's `ARG`s say at that point. What it does check is syntax: a
//! known instruction with its arguments, flags it knows, a JSON array where
//! one is required. Instruction names are case-insensitive; stage names
//! are lowercased (as Docker's). Errors carry the line the instruction
//! starts on.
//!
//! Directives: `escape` (`\` or `` ` ``) is honoured; `syntax` and `check`
//! are accepted and ignored (there is one parser). A line that ends with
//! the escape character continues on the next; comment lines (`#` first)
//! inside a continuation are dropped, and so are empty lines there (with a
//! warning, as Docker gives).
//!
//! Refused, with the line: heredocs (`<<EOF`), `RUN --mount`, `--network`,
//! `--security`; `COPY`/`ADD` `--link`, `--parents`, `--exclude`;
//! `ADD --checksum`, `--keep-git-dir`; `FROM --platform` other than
//! `linux/amd64` (or a variable); an instruction before the first `FROM`
//! other than `ARG`; unknown instructions and flags.

/// A parsed Containerfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Containerfile {
    /// The escape character: `\`, or `` ` `` after ``# escape=` ``.
    pub escape: char,
    /// The `ARG`s before the first `FROM`, usable in `FROM` lines (and in a
    /// stage once declared there again, without a value).
    pub global_args: Vec<ArgDecl>,
    pub stages: Vec<Stage>,
    /// What the parser accepted but Docker warns about (an empty
    /// continuation line, `MAINTAINER`), with line numbers.
    pub warnings: Vec<String>,
}

/// One `FROM` and the instructions up to the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// Its place in the file, from 0 (what `COPY --from=0` names).
    pub index: usize,
    /// `AS <name>`, lowercased.
    pub name: Option<String>,
    /// The image (or stage name, or `scratch`), as written.
    pub base: String,
    /// `--platform`, as written.
    pub platform: Option<String>,
    /// The `FROM` line.
    pub line: usize,
    pub instructions: Vec<Instruction>,
}

/// One instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The line it starts on, from 1.
    pub line: usize,
    /// The instruction as written, its lines joined (continuations and the
    /// comments between them dropped): for messages.
    pub original: String,
    pub kind: InstructionKind,
}

/// An instruction's arguments, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionKind {
    Run(Command),
    Cmd(Command),
    Entrypoint(Command),
    Copy(CopyArgs),
    Add(CopyArgs),
    /// `ENV a=1 b="x y"`, or the old `ENV a 1 2` (one pair: the rest of the
    /// line is the value): (name, value) pairs, each still to be expanded.
    Env(Vec<(String, String)>),
    Arg(Vec<ArgDecl>),
    /// `LABEL k=v …`: pairs, still to be expanded.
    Label(Vec<(String, String)>),
    Workdir(String),
    User(String),
    /// The arguments, still to be expanded and split into ports.
    Expose(String),
    Volume(Args),
    StopSignal(String),
    Healthcheck(Healthcheck),
    /// The JSON array.
    Shell(Vec<String>),
    Maintainer(String),
    /// The instruction it records, unparsed.
    Onbuild(String),
}

/// `RUN`, `CMD`, `ENTRYPOINT` and `HEALTHCHECK CMD`'s command: a string for
/// the shell, or a JSON array to `exec`. Never expanded by the builder: a
/// shell form's `$VAR` is the shell's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Shell(String),
    Exec(Vec<String>),
}

/// Arguments that are a list: a JSON array, or words separated by
/// whitespace (split when expanded: quotes can hold whitespace, a
/// variable's value can hold several words).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Args {
    Json(Vec<String>),
    Shell(String),
}

/// `COPY` and `ADD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyArgs {
    /// `--from=<stage, index or image>`, as written.
    pub from: Option<String>,
    /// `--chown=<user>[:<group>]`, as written.
    pub chown: Option<String>,
    /// `--chmod=<octal>`, as written.
    pub chmod: Option<String>,
    /// The sources and, last, the destination (at least two once expanded).
    pub args: Args,
}

/// `ARG name[=default]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgDecl {
    pub name: String,
    /// As written, still to be expanded.
    pub default: Option<String>,
}

/// `HEALTHCHECK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Healthcheck {
    /// `HEALTHCHECK NONE`: no healthcheck, not even the base image's.
    None,
    /// `HEALTHCHECK [--interval=…] [--timeout=…] [--start-period=…]
    /// [--start-interval=…] [--retries=…] CMD <command>`; options as written.
    Check {
        command: Command,
        interval: Option<String>,
        timeout: Option<String>,
        start_period: Option<String>,
        start_interval: Option<String>,
        retries: Option<String>,
    },
}

/// What was wrong, and where.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct ParseError {
    /// From 1; 0 for the file as a whole (no `FROM` at all).
    pub line: usize,
    pub message: String,
}

/// Parses a Containerfile.
pub fn parse(text: &str) -> Result<Containerfile, ParseError> {
    let _ = text;
    unimplemented!("parse: agent A")
}

/// Parses one instruction on its own (`commit --change 'CMD ["sh"]'`),
/// with the default escape character. A `FROM` is refused.
pub fn parse_instruction(text: &str) -> Result<Instruction, ParseError> {
    let _ = text;
    unimplemented!("parse_instruction: agent A")
}
