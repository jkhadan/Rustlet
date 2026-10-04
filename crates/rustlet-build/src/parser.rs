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
//! are accepted and ignored (there is one parser). They count only at the
//! very top: the first line that isn't one (an instruction, a comment, an
//! unknown directive, an empty line) ends them. A line that ends with the
//! escape character (spaces or tabs may follow it) continues on the next;
//! comment lines (`#` first) inside a continuation are dropped, and so are
//! empty lines there (with a warning, as Docker gives).
//!
//! Flags (`--name=value`) are the words at the start of the arguments that
//! begin with `--`; quotes in them are removed and `\` escapes, as
//! BuildKit's flag reader does; a lone `--` ends them. A string flag needs
//! its `=`. An argument that is a JSON array of strings is the exec form;
//! anything else, invalid JSON included, the shell form (Docker's rule); a
//! JSON array holding something other than strings is an error, as in
//! Docker.
//!
//! Refused, with the line: heredocs (`<<EOF`), `RUN --mount`, `--network`,
//! `--security`; `COPY`/`ADD` `--link`, `--parents`, `--exclude`;
//! `ADD --checksum`, `--keep-git-dir` (and `--from`, which `ADD` has never
//! had); `FROM --platform` other than `linux/amd64` (or a variable); an
//! instruction before the first `FROM` other than `ARG`; unknown
//! instructions and flags; a stage named `scratch` (Docker only warns,
//! then reads `FROM scratch` as that stage: here it is always the empty
//! image).

use std::collections::BTreeMap;

use serde_json::Value;

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

const DEFAULT_ESCAPE: char = '\\';

/// The instructions there are.
const INSTRUCTIONS: &[&str] = &[
    "ADD",
    "ARG",
    "CMD",
    "COPY",
    "ENTRYPOINT",
    "ENV",
    "EXPOSE",
    "FROM",
    "HEALTHCHECK",
    "LABEL",
    "MAINTAINER",
    "ONBUILD",
    "RUN",
    "SHELL",
    "STOPSIGNAL",
    "USER",
    "VOLUME",
    "WORKDIR",
];

/// Parses a Containerfile.
pub fn parse(text: &str) -> Result<Containerfile, ParseError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let escape = directives(&lines)?;
    let mut warnings = Vec::new();
    let mut global_args = Vec::new();
    let mut stages: Vec<Stage> = Vec::new();
    for logical in logical_lines(&lines, escape, &mut warnings) {
        let at = |message: String| ParseError { line: logical.line, message };
        match parse_text(&logical.text, escape).map_err(at)? {
            Parsed::From(from) => {
                if let Some(name) = &from.name
                    && let Some(earlier) = stages.iter().find(|s| s.name.as_ref() == Some(name))
                {
                    return Err(at(format!("duplicate stage name {name:?} (also on line {})", earlier.line)));
                }
                stages.push(Stage {
                    index: stages.len(),
                    name: from.name,
                    base: from.base,
                    platform: from.platform,
                    line: logical.line,
                    instructions: Vec::new(),
                });
            }
            Parsed::Instruction(kind) => {
                if matches!(kind, InstructionKind::Maintainer(_)) {
                    warnings.push(format!(
                        "line {}: MAINTAINER is deprecated: use LABEL org.opencontainers.image.authors=\"…\"",
                        logical.line
                    ));
                }
                match stages.last_mut() {
                    Some(stage) => {
                        stage.instructions.push(Instruction { line: logical.line, original: logical.original(), kind })
                    }
                    None => match kind {
                        InstructionKind::Arg(args) => global_args.extend(args),
                        _ => {
                            let keyword = logical.keyword();
                            return Err(at(format!("{keyword} before the first FROM: only ARG can come before it")));
                        }
                    },
                }
            }
        }
    }
    if stages.is_empty() {
        return Err(ParseError { line: 0, message: "no FROM instruction: there is nothing to build".to_owned() });
    }
    Ok(Containerfile { escape, global_args, stages, warnings })
}

/// Parses one instruction on its own (`commit --change 'CMD ["sh"]'`),
/// with the default escape character. A `FROM` is refused.
pub fn parse_instruction(text: &str) -> Result<Instruction, ParseError> {
    let lines: Vec<&str> = text.lines().collect();
    let logical = logical_lines(&lines, DEFAULT_ESCAPE, &mut Vec::new());
    let instruction = match logical.as_slice() {
        [] => return Err(ParseError { line: 0, message: "no instruction".to_owned() }),
        [one] => one,
        [_, second, ..] => {
            return Err(ParseError { line: second.line, message: "one instruction expected, not several".to_owned() });
        }
    };
    let at = |message: String| ParseError { line: instruction.line, message };
    match parse_text(&instruction.text, DEFAULT_ESCAPE).map_err(at)? {
        Parsed::From(_) => Err(at("FROM can't be used here: it starts a build stage".to_owned())),
        Parsed::Instruction(kind) => Ok(Instruction { line: instruction.line, original: instruction.original(), kind }),
    }
}

/// The escape character, from the parser directives at the top.
fn directives(lines: &[&str]) -> Result<char, ParseError> {
    let mut escape = DEFAULT_ESCAPE;
    let mut seen: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some((key, value)) = directive(line) else { break };
        let key = key.to_ascii_lowercase();
        // An unknown directive is a comment, and the first comment ends them.
        if !matches!(key.as_str(), "escape" | "syntax" | "check") {
            break;
        }
        let at = |message: String| ParseError { line: i + 1, message };
        if seen.contains(&key) {
            return Err(at(format!("only one {key} parser directive can be used")));
        }
        if key == "escape" {
            escape = match value {
                "\\" => '\\',
                "`" => '`',
                _ => return Err(at(format!("invalid escape character {value:?}: it can be \\ or `"))),
            };
        }
        seen.push(key);
    }
    Ok(escape)
}

/// `# key=value`, whitespace allowed around each part: a directive's
/// syntax, known or not.
fn directive(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim_start().strip_prefix('#')?.trim_start_matches(is_go_space);
    let (key, rest) = rest.split_at(rest.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len()));
    if !key.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    let value = rest.trim_start_matches(is_go_space).strip_prefix('=')?.trim_matches(is_go_space);
    (!value.is_empty()).then_some((key, value))
}

/// `\s` in Go's regular expressions.
fn is_go_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0c' | '\r')
}

/// The whitespace Docker splits an instruction's words at: `[\t\v\f\r ]`.
fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\x0b' | '\x0c' | '\r')
}

/// An instruction's lines, joined.
struct Logical {
    /// Where it starts, from 1.
    line: usize,
    text: String,
}

impl Logical {
    fn original(&self) -> String {
        self.text.trim_end().to_owned()
    }

    fn keyword(&self) -> String {
        split_keyword(&self.text).0.to_ascii_uppercase()
    }
}

/// The instructions of `lines`: continued lines joined (the escape
/// character, and spaces or tabs after it, removed; the next line kept as it
/// is), comment lines dropped, empty lines too (inside an instruction, with
/// a warning).
fn logical_lines(lines: &[&str], escape: char, warnings: &mut Vec<String>) -> Vec<Logical> {
    let mut out = Vec::new();
    let mut next = 0;
    while next < lines.len() {
        let line = next + 1;
        let first = lines[next].trim_start();
        next += 1;
        if first.is_empty() || first.starts_with('#') {
            continue;
        }
        let (part, mut continues) = continuation(first, escape);
        let mut text = part.to_owned();
        while continues && next < lines.len() {
            let raw = lines[next];
            next += 1;
            let trimmed = raw.trim_start();
            if trimmed.starts_with('#') {
                continue;
            }
            if trimmed.is_empty() {
                warnings.push(format!(
                    "line {next}: empty continuation line (Docker will refuse these in a future release)"
                ));
                continue;
            }
            let (part, more) = continuation(raw, escape);
            text.push_str(part);
            continues = more;
        }
        // A lone escape character with nothing after it is no instruction.
        if !text.trim().is_empty() {
            out.push(Logical { line, text });
        }
    }
    out
}

/// `line` without a final escape character (and the spaces or tabs after
/// it), and whether it had one: then the instruction goes on.
fn continuation(line: &str, escape: char) -> (&str, bool) {
    match line.trim_end_matches([' ', '\t']).strip_suffix(escape) {
        Some(part) => (part, true),
        None => (line, false),
    }
}

/// What one instruction is.
enum Parsed {
    From(From),
    Instruction(InstructionKind),
}

/// A `FROM`, its stage still to number.
struct From {
    base: String,
    name: Option<String>,
    platform: Option<String>,
}

fn parse_text(text: &str, escape: char) -> Result<Parsed, String> {
    let (keyword, rest) = split_keyword(text);
    let instruction = keyword.to_ascii_uppercase();
    let name = instruction.as_str();
    let (flags, rest) = extract_flags(rest);
    let rest = rest.trim();
    let no_flags = || check_flags(name, &flags, &[], &[]).map(|_| ());
    let kind = match name {
        "FROM" => return parse_from(&flags, rest).map(Parsed::From),
        "RUN" => {
            check_flags(name, &flags, &[], &["mount", "network", "security"])?;
            let command = command(rest)?;
            match &command {
                Command::Shell(s) if s.is_empty() => return Err(at_least_one(name)),
                Command::Exec(args) if args.is_empty() => return Err(at_least_one(name)),
                Command::Shell(s) => refuse_heredoc(name, s, escape)?,
                Command::Exec(_) => {}
            }
            InstructionKind::Run(command)
        }
        "CMD" => {
            no_flags()?;
            InstructionKind::Cmd(command(rest)?)
        }
        "ENTRYPOINT" => {
            no_flags()?;
            InstructionKind::Entrypoint(command(rest)?)
        }
        "COPY" => InstructionKind::Copy(copy_args(name, &flags, rest, escape)?),
        "ADD" => InstructionKind::Add(copy_args(name, &flags, rest, escape)?),
        "ENV" => {
            no_flags()?;
            InstructionKind::Env(name_values(name, rest, escape)?)
        }
        "LABEL" => {
            no_flags()?;
            InstructionKind::Label(name_values(name, rest, escape)?)
        }
        "ARG" => {
            no_flags()?;
            InstructionKind::Arg(arg_decls(rest, escape)?)
        }
        "WORKDIR" => {
            no_flags()?;
            InstructionKind::Workdir(exactly_one(name, rest)?)
        }
        "USER" => {
            no_flags()?;
            InstructionKind::User(exactly_one(name, rest)?)
        }
        "STOPSIGNAL" => {
            no_flags()?;
            InstructionKind::StopSignal(exactly_one(name, rest)?)
        }
        "MAINTAINER" => {
            no_flags()?;
            InstructionKind::Maintainer(exactly_one(name, rest)?)
        }
        "EXPOSE" => {
            no_flags()?;
            if rest.is_empty() {
                return Err(at_least_one(name));
            }
            InstructionKind::Expose(rest.to_owned())
        }
        "VOLUME" => {
            no_flags()?;
            InstructionKind::Volume(volume(rest)?)
        }
        "HEALTHCHECK" => InstructionKind::Healthcheck(healthcheck(&flags, rest)?),
        "SHELL" => {
            no_flags()?;
            InstructionKind::Shell(shell(rest)?)
        }
        "ONBUILD" => {
            no_flags()?;
            InstructionKind::Onbuild(onbuild(rest, escape)?)
        }
        _ => return Err(format!("unknown instruction: {instruction}")),
    };
    Ok(Parsed::Instruction(kind))
}

fn at_least_one(instruction: &str) -> String {
    format!("{instruction} requires at least one argument")
}

fn exactly_one(instruction: &str, rest: &str) -> Result<String, String> {
    if rest.is_empty() { Err(format!("{instruction} requires exactly one argument")) } else { Ok(rest.to_owned()) }
}

/// The instruction's name and the rest of its text.
fn split_keyword(text: &str) -> (&str, &str) {
    split_blank_once(text.trim())
}

/// `text` at its first run of whitespace.
fn split_blank_once(text: &str) -> (&str, &str) {
    match text.find(is_blank) {
        Some(i) => (&text[..i], text[i..].trim_start_matches(is_blank)),
        None => (text, ""),
    }
}

/// The flags at the start of `args` (its words that begin with `--`, quotes
/// removed, `\` escaping the next character), and the rest: BuildKit's
/// `extractBuilderFlags`. A lone `--` ends them.
fn extract_flags(args: &str) -> (Vec<String>, &str) {
    let mut flags = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = args.char_indices();
    while let Some((pos, c)) = chars.next() {
        if !in_word {
            if c.is_whitespace() {
                continue;
            }
            if !args[pos..].starts_with("--") {
                return (flags, &args[pos..]);
            }
            in_word = true;
        }
        if let Some(q) = quote {
            match c {
                c if c == q => quote = None,
                '\\' => match chars.next() {
                    Some((_, next)) => word.push(next),
                    None => quote = None,
                },
                c => word.push(c),
            }
            continue;
        }
        match c {
            c if c.is_whitespace() => {
                if word == "--" {
                    return (flags, &args[pos..]);
                }
                flags.push(std::mem::take(&mut word));
                in_word = false;
            }
            '\'' | '"' => quote = Some(c),
            '\\' => word.extend(chars.next().map(|(_, next)| next)),
            c => word.push(c),
        }
    }
    if in_word && word != "--" {
        flags.push(word);
    }
    (flags, "")
}

/// The flags' values, by name. `allowed`: the instruction's flags, each
/// `--name=value`; `buildkit`: flags Docker has that Rustlets refuses.
fn check_flags(
    instruction: &str,
    flags: &[String],
    allowed: &[&str],
    buildkit: &[&str],
) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for flag in flags {
        let flag = flag.strip_prefix("--").unwrap_or(flag);
        let (name, value) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (flag, None),
        };
        if buildkit.contains(&name) {
            let hint = match (instruction, name) {
                ("RUN", "network") => " (rustlet build --network sets the network of every RUN)",
                _ => "",
            };
            return Err(format!("{instruction} --{name} is a BuildKit feature Rustlets doesn't support{hint}"));
        }
        if !allowed.contains(&name) {
            return Err(format!("{instruction}: unknown flag --{name}"));
        }
        let Some(value) = value else {
            return Err(format!("{instruction} --{name} needs a value: --{name}=…"));
        };
        if values.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("{instruction}: --{name} is given twice"));
        }
    }
    Ok(values)
}

fn parse_from(flags: &[String], rest: &str) -> Result<From, String> {
    let values = check_flags("FROM", flags, &["platform"], &[])?;
    let platform = values.get("platform").filter(|p| !p.is_empty()).cloned();
    if let Some(p) = &platform
        && p != "linux/amd64"
        && !p.contains('$')
    {
        return Err(format!("FROM --platform={p}: Rustlets builds linux/amd64 images only"));
    }
    let words: Vec<&str> = rest.split(is_blank).filter(|w| !w.is_empty()).collect();
    let (base, name) = match words.as_slice() {
        [base] => (*base, None),
        [base, keyword, name] if keyword.eq_ignore_ascii_case("as") => (*base, Some(stage_name(name)?)),
        _ => return Err("FROM requires either one or three arguments: FROM <image> [AS <name>]".to_owned()),
    };
    Ok(From { base: base.to_owned(), name, platform })
}

/// `AS <name>`, lowercased: `[a-z][a-z0-9_.-]*`, and not `scratch`.
fn stage_name(written: &str) -> Result<String, String> {
    let name = written.to_ascii_lowercase();
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
    if !valid {
        return Err(format!(
            "invalid stage name {written:?}: it must start with a letter, and hold only letters, digits, '-', '_' and '.'"
        ));
    }
    if name == "scratch" {
        return Err("a stage can't be named \"scratch\": FROM scratch is the empty image".to_owned());
    }
    Ok(name)
}

/// `[…]`, a JSON array of strings: the exec form. `None`: not JSON (the
/// shell form). A JSON array of anything else is an error, as in Docker.
fn json_array(rest: &str) -> Result<Option<Vec<String>>, String> {
    if !rest.starts_with('[') {
        return Ok(None);
    }
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(rest) else { return Ok(None) };
    items
        .into_iter()
        .map(|item| match item {
            Value::String(s) => Ok(s),
            _ => Err("when using JSON array syntax, arrays must be comprised of strings only".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn command(rest: &str) -> Result<Command, String> {
    Ok(match json_array(rest)? {
        Some(args) => Command::Exec(args),
        None => Command::Shell(rest.to_owned()),
    })
}

fn copy_args(instruction: &str, flags: &[String], rest: &str, escape: char) -> Result<CopyArgs, String> {
    let values = if instruction == "ADD" {
        check_flags(
            instruction,
            flags,
            &["chown", "chmod"],
            &["link", "exclude", "parents", "checksum", "keep-git-dir"],
        )?
    } else {
        check_flags(instruction, flags, &["from", "chown", "chmod"], &["link", "exclude", "parents"])?
    };
    let too_few = || format!("{instruction} requires at least two arguments: the sources, then the destination");
    let args = match json_array(rest)? {
        Some(args) if args.len() < 2 => return Err(too_few()),
        Some(args) => Args::Json(args),
        None => {
            refuse_heredoc(instruction, rest, escape)?;
            if split_words(rest, escape).len() < 2 {
                return Err(too_few());
            }
            Args::Shell(rest.to_owned())
        }
    };
    // An empty value (`--from=`) is no value, as in Docker.
    let value = |name: &str| values.get(name).filter(|v| !v.is_empty()).cloned();
    Ok(CopyArgs { from: value("from"), chown: value("chown"), chmod: value("chmod"), args })
}

/// `ENV`/`LABEL`: `name=value …`, each value as written (quotes included),
/// or the old form `name value…`: one pair, the rest of the line its value.
fn name_values(instruction: &str, rest: &str, escape: char) -> Result<Vec<(String, String)>, String> {
    let words = split_words(rest, escape);
    let Some(first) = words.first() else { return Err(at_least_one(instruction)) };
    if !first.contains('=') {
        let (name, value) = split_blank_once(rest);
        if value.is_empty() {
            return Err(format!(
                "{instruction} must have two arguments: {instruction} name=value (or the old {instruction} name value)"
            ));
        }
        return Ok(vec![(name.to_owned(), value.to_owned())]);
    }
    words
        .iter()
        .map(|word| {
            let Some((name, value)) = word.split_once('=') else {
                return Err(format!("{instruction}: no = in {word:?}: each pair is name=value"));
            };
            if name.is_empty() {
                return Err(format!("{instruction} names can't be empty"));
            }
            Ok((name.to_owned(), value.to_owned()))
        })
        .collect()
}

fn arg_decls(rest: &str, escape: char) -> Result<Vec<ArgDecl>, String> {
    let words = split_words(rest, escape);
    if words.is_empty() {
        return Err(at_least_one("ARG"));
    }
    words
        .iter()
        .map(|word| {
            let (name, default) = match word.split_once('=') {
                Some((name, default)) => (name, Some(default.to_owned())),
                None => (word.as_str(), None),
            };
            if name.is_empty() {
                return Err("ARG names can't be empty".to_owned());
            }
            Ok(ArgDecl { name: name.to_owned(), default })
        })
        .collect()
}

fn volume(rest: &str) -> Result<Args, String> {
    match json_array(rest)? {
        Some(paths) if paths.is_empty() => Err(at_least_one("VOLUME")),
        Some(paths) => Ok(Args::Json(paths)),
        None if rest.is_empty() => Err(at_least_one("VOLUME")),
        None => Ok(Args::Shell(rest.to_owned())),
    }
}

fn healthcheck(flags: &[String], rest: &str) -> Result<Healthcheck, String> {
    let (kind, command) = match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], rest[i..].trim_start()),
        None => (rest, ""),
    };
    match kind.to_ascii_uppercase().as_str() {
        "" => {
            Err("HEALTHCHECK requires at least one argument: HEALTHCHECK [options] CMD <command>, or HEALTHCHECK NONE"
                .to_owned())
        }
        // As in Docker, options are not even read here.
        "NONE" if command.is_empty() => Ok(Healthcheck::None),
        "NONE" => Err("HEALTHCHECK NONE takes no arguments".to_owned()),
        "CMD" => {
            let options = check_flags(
                "HEALTHCHECK",
                flags,
                &["interval", "timeout", "start-period", "start-interval", "retries"],
                &[],
            )?;
            let missing = || "HEALTHCHECK CMD needs a command".to_owned();
            let command = match json_array(command)? {
                Some(args) if args.is_empty() => return Err(missing()),
                Some(args) => Command::Exec(args),
                None if command.is_empty() => return Err(missing()),
                None => Command::Shell(command.to_owned()),
            };
            let option = |name: &str| options.get(name).filter(|v| !v.is_empty()).cloned();
            let (interval, timeout) = (option("interval"), option("timeout"));
            let (start_period, start_interval) = (option("start-period"), option("start-interval"));
            let retries = option("retries");
            // Checked now for the line number; `op` reads them again.
            for (name, value) in [
                ("interval", &interval),
                ("timeout", &timeout),
                ("start-period", &start_period),
                ("start-interval", &start_interval),
            ] {
                crate::op::health_duration(name, value.as_deref())?;
            }
            crate::op::health_retries(retries.as_deref())?;
            Ok(Healthcheck::Check { command, interval, timeout, start_period, start_interval, retries })
        }
        _ => Err(format!("HEALTHCHECK {kind}: unknown type (it is CMD, or NONE)")),
    }
}

fn shell(rest: &str) -> Result<Vec<String>, String> {
    match json_array(rest)? {
        Some(shell) if !shell.is_empty() => Ok(shell),
        Some(_) => Err(at_least_one("SHELL")),
        None if rest.is_empty() => Err(at_least_one("SHELL")),
        None => {
            Err("SHELL requires the arguments to be in JSON form: SHELL [\"executable\", \"parameters\"]".to_owned())
        }
    }
}

/// `ONBUILD <instruction>`, kept as written for whoever builds from the
/// image, so checked only as far as Docker does (no `ONBUILD`, `FROM` or
/// `MAINTAINER`), plus a known name and no heredoc (whose lines would be
/// read as instructions).
fn onbuild(rest: &str, escape: char) -> Result<String, String> {
    if rest.is_empty() {
        return Err(at_least_one("ONBUILD"));
    }
    let (keyword, args) = split_keyword(rest);
    let trigger = keyword.to_ascii_uppercase();
    match trigger.as_str() {
        "ONBUILD" => return Err("ONBUILD ONBUILD isn't allowed".to_owned()),
        "FROM" | "MAINTAINER" => return Err(format!("{trigger} isn't allowed as an ONBUILD trigger")),
        "RUN" | "COPY" | "ADD" => {
            let args = extract_flags(args).1.trim();
            if json_array(args)?.is_none() {
                refuse_heredoc(&format!("ONBUILD {trigger}"), args, escape)?;
            }
        }
        known if INSTRUCTIONS.contains(&known) => {}
        _ => return Err(format!("ONBUILD: unknown instruction: {trigger}")),
    }
    Ok(rest.to_owned())
}

/// Refuses a heredoc in shell-form arguments: a word `[n]<<[-]DELIMITER`
/// (BuildKit's rule; `<<<`, `<< EOF` and a quoted `"<<EOF"` aren't).
fn refuse_heredoc(instruction: &str, args: &str, escape: char) -> Result<(), String> {
    if args.contains("<<") && split_words(args, escape).iter().any(|word| is_heredoc(word)) {
        return Err(format!(
            "{instruction} with a heredoc (<<EOF) is a BuildKit feature Rustlets doesn't support: put the text in a file in the context"
        ));
    }
    Ok(())
}

fn is_heredoc(word: &str) -> bool {
    let Some(rest) = word.trim_start_matches(|c: char| c.is_ascii_digit()).strip_prefix("<<") else {
        return false;
    };
    let delimiter = rest.strip_prefix('-').unwrap_or(rest);
    !delimiter.is_empty() && !delimiter.contains('<')
}

/// Words at whitespace, quotes and escape characters kept as written
/// (BuildKit's `parseWords`): `ENV`, `LABEL` and `ARG` pairs, `COPY`'s
/// arguments counted.
fn split_words(text: &str, escape: char) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == escape && q != '\'' {
                // The escape character and what it escapes, both kept; at the
                // very end it is dropped.
                match chars.next() {
                    Some(next) => word.extend([c, next]),
                    None => quote = None,
                }
                continue;
            }
            word.push(c);
        } else if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else if c == escape {
            if let Some(next) = chars.next() {
                word.extend([c, next]);
            }
        } else {
            if c == '\'' || c == '"' {
                quote = Some(c);
            }
            word.push(c);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests;
