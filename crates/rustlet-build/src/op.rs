//! An instruction ready to run: its words expanded against the build's
//! variables at that point, its options parsed and checked.
//!
//! Which arguments are expanded is Docker's choice: `FROM` (with the
//! global `ARG`s only), `ENV`, `ARG` defaults, `LABEL`, `WORKDIR`, `USER`,
//! `EXPOSE`, `VOLUME`, `STOPSIGNAL`, `COPY`/`ADD` (sources, destination and
//! flags). `RUN`, `CMD`, `ENTRYPOINT`, `SHELL`, `HEALTHCHECK`'s command and
//! `ONBUILD` are not: the shell, or the program, sees them as written.
//!
//! Checked here: `EXPOSE` ports (`80`, `80/tcp`, `53/udp`, ranges
//! `8000-8002`, become one `port/proto` each), `--chmod` (octal), the
//! `HEALTHCHECK` options (Go durations such as `30s` or `1m30s`, a retry
//! count), a `COPY` with fewer than two words, `ADD` from a URL (refused:
//! "use RUN with curl or wget"), `STOPSIGNAL` (a signal's name or number).
//!
//! Where this differs from BuildKit: `COPY`, `ADD` and `VOLUME` in shell
//! form split their words as a shell would ([`expand::words`]): quotes can
//! hold a space (`COPY "my file" /dst/`), and a variable holding several
//! words is several sources (BuildKit splits at whitespace first and
//! expands each piece as one word). `EXPOSE 8080:80` is refused (BuildKit
//! takes the container port and warns). An `ADD` source that names a git
//! repository gets its own hint ("use RUN with git clone").

use std::collections::HashSet;
use std::time::Duration;

use crate::config::parse_duration;
use crate::expand;
use crate::parser::{Args, Command, CopyArgs, Healthcheck, InstructionKind};

/// An instruction with its arguments expanded and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Run(Command),
    Cmd(Command),
    Entrypoint(Command),
    /// `COPY` (`add: false`) or `ADD`.
    Copy(CopyOp),
    Env(Vec<(String, String)>),
    /// `ARG`s declared: names and expanded defaults.
    Arg(Vec<(String, Option<String>)>),
    Label(Vec<(String, String)>),
    Workdir(String),
    User(String),
    /// `port/proto` each (`80/tcp`).
    Expose(Vec<String>),
    Volume(Vec<String>),
    StopSignal(String),
    /// `None`: `HEALTHCHECK NONE`.
    Healthcheck(Option<HealthcheckOp>),
    Shell(Vec<String>),
    Maintainer(String),
    Onbuild(String),
}

/// `COPY` or `ADD`, expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyOp {
    pub add: bool,
    pub sources: Vec<String>,
    pub dest: String,
    pub from: Option<String>,
    pub chown: Option<String>,
    pub chmod: Option<u32>,
}

/// `HEALTHCHECK CMD …`, with its options parsed (`None`: the default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthcheckOp {
    /// `["CMD", args…]` or `["CMD-SHELL", command]`, as the image config
    /// stores it.
    pub test: Vec<String>,
    pub interval: Option<Duration>,
    pub timeout: Option<Duration>,
    pub start_period: Option<Duration>,
    pub start_interval: Option<Duration>,
    pub retries: Option<u32>,
}

impl Op {
    /// `kind` with its words expanded (`escape`: the file's escape
    /// character; `lookup`: the variables in scope, `ENV` over `ARG`).
    pub fn new(kind: &InstructionKind, escape: char, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Op, String> {
        let x = Expander { escape, lookup };
        Ok(match kind {
            InstructionKind::Run(command) => Op::Run(command.clone()),
            InstructionKind::Cmd(command) => Op::Cmd(command.clone()),
            InstructionKind::Entrypoint(command) => Op::Entrypoint(command.clone()),
            InstructionKind::Copy(args) => Op::Copy(copy_op(args, false, &x)?),
            InstructionKind::Add(args) => Op::Copy(copy_op(args, true, &x)?),
            InstructionKind::Env(pairs) => Op::Env(name_values("ENV", pairs, &x)?),
            InstructionKind::Label(pairs) => Op::Label(name_values("LABEL", pairs, &x)?),
            InstructionKind::Arg(decls) => Op::Arg(
                decls
                    .iter()
                    .map(|decl| Ok((decl.name.clone(), decl.default.as_deref().map(|d| x.word("ARG", d)).transpose()?)))
                    .collect::<Result<_, String>>()?,
            ),
            InstructionKind::Workdir(raw) => {
                let path = x.word("WORKDIR", raw)?;
                if path.is_empty() {
                    return Err(format!("WORKDIR {raw}: the path is empty"));
                }
                Op::Workdir(path)
            }
            InstructionKind::User(raw) => Op::User(x.word("USER", raw)?),
            InstructionKind::Expose(raw) => Op::Expose(ports(&x.words("EXPOSE", raw)?)?),
            InstructionKind::Volume(args) => Op::Volume(volumes(args, &x)?),
            InstructionKind::StopSignal(raw) => {
                let signal = x.word("STOPSIGNAL", raw)?;
                check_signal(&signal)?;
                Op::StopSignal(signal)
            }
            InstructionKind::Healthcheck(check) => Op::Healthcheck(healthcheck(check)?),
            InstructionKind::Shell(shell) => Op::Shell(shell.clone()),
            InstructionKind::Maintainer(raw) => Op::Maintainer(x.word("MAINTAINER", raw)?),
            InstructionKind::Onbuild(trigger) => Op::Onbuild(trigger.clone()),
        })
    }

    /// Does this step change the filesystem (`RUN`, `COPY`, `ADD`)? The
    /// others only change the config, or the build's variables.
    pub fn makes_layer(&self) -> bool {
        matches!(self, Op::Run(_) | Op::Copy(_))
    }
}

/// Expansion with the step's variables; errors name the instruction.
struct Expander<'a> {
    escape: char,
    lookup: &'a dyn Fn(&str) -> Option<String>,
}

impl Expander<'_> {
    fn word(&self, instruction: &str, raw: &str) -> Result<String, String> {
        expand::word(raw, self.escape, self.lookup).map_err(|e| format!("{instruction}: {e}"))
    }

    fn words(&self, instruction: &str, raw: &str) -> Result<Vec<String>, String> {
        expand::words(raw, self.escape, self.lookup).map_err(|e| format!("{instruction}: {e}"))
    }
}

/// `ENV` and `LABEL` pairs: both sides expanded, all against the variables
/// as they were before the instruction (`ENV a=1 b=$a` reads the old `a`,
/// as in Docker).
fn name_values(
    instruction: &str,
    pairs: &[(String, String)],
    x: &Expander<'_>,
) -> Result<Vec<(String, String)>, String> {
    pairs
        .iter()
        .map(|(name, value)| {
            let name = x.word(instruction, name)?;
            if name.is_empty() {
                return Err(format!("{instruction} names can't be empty"));
            }
            Ok((name, x.word(instruction, value)?))
        })
        .collect()
}

fn copy_op(args: &CopyArgs, add: bool, x: &Expander<'_>) -> Result<CopyOp, String> {
    let instruction = if add { "ADD" } else { "COPY" };
    // A flag that expands to nothing is no flag, as in Docker.
    let flag = |value: &Option<String>| -> Result<Option<String>, String> {
        Ok(value.as_deref().map(|v| x.word(instruction, v)).transpose()?.filter(|v| !v.is_empty()))
    };
    let chmod = flag(&args.chmod)?.map(|mode| chmod(instruction, &mode)).transpose()?;
    let mut words = match &args.args {
        Args::Json(items) => items.iter().map(|item| x.word(instruction, item)).collect::<Result<Vec<_>, _>>()?,
        Args::Shell(raw) => x.words(instruction, raw)?,
    };
    if words.len() < 2 {
        return Err(format!(
            "{instruction} requires at least two arguments, the sources and then the destination: {} after expansion",
            words.len()
        ));
    }
    if words.iter().any(String::is_empty) {
        return Err(format!("{instruction}: a path is empty"));
    }
    let dest = words.pop().unwrap_or_default();
    if add && let Some(source) = words.iter().find(|s| is_remote(s)) {
        let hint = if is_git(source) { "use RUN with git clone" } else { "use RUN with curl or wget" };
        return Err(format!("ADD from a URL is not supported: {hint} ({source})"));
    }
    Ok(CopyOp { add, sources: words, dest, from: flag(&args.from)?, chown: flag(&args.chown)?, chmod })
}

/// `--chmod`: octal, at most `7777`.
fn chmod(instruction: &str, mode: &str) -> Result<u32, String> {
    let bad = || format!("{instruction} --chmod={mode}: expected an octal mode such as 755 or 0644");
    if !mode.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(bad());
    }
    u32::from_str_radix(mode, 8).ok().filter(|m| *m <= 0o7777).ok_or_else(bad)
}

/// What BuildKit's `ADD` fetches instead of reading the context: an HTTP(S)
/// URL, or a git repository (`git://`, `ssh://`, `user@host:path`).
fn is_remote(source: &str) -> bool {
    ["http://", "https://", "git://", "ssh://"].iter().any(|scheme| source.starts_with(scheme)) || is_scp_like(source)
}

fn is_git(source: &str) -> bool {
    let http = source.starts_with("http://") || source.starts_with("https://");
    !http || source.ends_with(".git") || source.contains(".git#")
}

/// `git@github.com:owner/repo.git`: git's scp-like remote syntax.
fn is_scp_like(source: &str) -> bool {
    let Some((user, rest)) = source.split_once('@') else { return false };
    let Some((host, _)) = rest.split_once(':') else { return false };
    !user.is_empty()
        && user.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !host.is_empty()
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// `EXPOSE`'s words as `port/proto`, ranges spread out, each once.
fn ports(words: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for word in words {
        let bad = |why: &str| format!("EXPOSE {word}: {why}");
        let (range, proto) = match word.split_once('/') {
            Some((range, "")) => (range, "tcp".to_owned()),
            Some((range, proto)) => (range, proto.to_ascii_lowercase()),
            None => (word.as_str(), "tcp".to_owned()),
        };
        if !matches!(proto.as_str(), "tcp" | "udp" | "sctp") {
            return Err(bad("the protocol can be tcp, udp or sctp"));
        }
        let port = |s: &str| {
            s.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| {
                bad("expected the container's ports, from 1 to 65535: 80, 80/udp, 8000-8010 (rustlet run -p publishes them)")
            })
        };
        let (start, end) = match range.split_once('-') {
            Some((start, end)) => (port(start)?, port(end)?),
            None => {
                let p = port(range)?;
                (p, p)
            }
        };
        if start > end {
            return Err(bad("the range ends before it starts"));
        }
        for p in start..=end {
            let entry = format!("{p}/{proto}");
            if seen.insert(entry.clone()) {
                out.push(entry);
            }
        }
    }
    if out.is_empty() {
        return Err("EXPOSE: no port (after expansion)".to_owned());
    }
    Ok(out)
}

fn volumes(args: &Args, x: &Expander<'_>) -> Result<Vec<String>, String> {
    let paths = match args {
        Args::Json(items) => items.iter().map(|item| x.word("VOLUME", item)).collect::<Result<Vec<_>, _>>()?,
        Args::Shell(raw) => x.words("VOLUME", raw)?,
    };
    let paths: Vec<String> = paths.iter().map(|p| p.trim().to_owned()).collect();
    if paths.is_empty() {
        return Err("VOLUME: no path (after expansion)".to_owned());
    }
    if paths.iter().any(String::is_empty) {
        return Err("VOLUME: a path can't be empty".to_owned());
    }
    Ok(paths)
}

/// Linux's signals by name, without `SIG` (Docker's table).
const SIGNALS: &[&str] = &[
    "ABRT", "ALRM", "BUS", "CHLD", "CLD", "CONT", "FPE", "HUP", "ILL", "INT", "IO", "IOT", "KILL", "PIPE", "POLL",
    "PROF", "PWR", "QUIT", "SEGV", "STKFLT", "STOP", "SYS", "TERM", "TRAP", "TSTP", "TTIN", "TTOU", "URG", "USR1",
    "USR2", "VTALRM", "WINCH", "XCPU", "XFSZ", "RTMIN", "RTMAX",
];

/// `STOPSIGNAL`: a number from 1 to 64, or a name (`SIGTERM`, `term`,
/// `RTMIN+3`), as Docker accepts them.
fn check_signal(signal: &str) -> Result<(), String> {
    if signal.parse::<u32>().is_ok_and(|n| (1..=64).contains(&n)) {
        return Ok(());
    }
    let upper = signal.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let realtime = |prefix: &str, max: u32| {
        name.strip_prefix(prefix).and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| (1..=max).contains(&n))
    };
    if SIGNALS.contains(&name) || realtime("RTMIN+", 15) || realtime("RTMAX-", 14) {
        Ok(())
    } else {
        Err(format!("STOPSIGNAL {signal}: unknown signal"))
    }
}

fn healthcheck(check: &Healthcheck) -> Result<Option<HealthcheckOp>, String> {
    let Healthcheck::Check { command, interval, timeout, start_period, start_interval, retries } = check else {
        return Ok(None);
    };
    let test = match command {
        Command::Shell(command) => vec!["CMD-SHELL".to_owned(), command.clone()],
        Command::Exec(args) => std::iter::once("CMD".to_owned()).chain(args.iter().cloned()).collect(),
    };
    Ok(Some(HealthcheckOp {
        test,
        interval: health_duration("interval", interval.as_deref())?,
        timeout: health_duration("timeout", timeout.as_deref())?,
        start_period: health_duration("start-period", start_period.as_deref())?,
        start_interval: health_duration("start-interval", start_interval.as_deref())?,
        retries: health_retries(retries.as_deref())?,
    }))
}

/// A `HEALTHCHECK` duration option: a Go duration, at least 1ms; `0` (or
/// nothing) is the default, `None`.
pub(crate) fn health_duration(option: &str, value: Option<&str>) -> Result<Option<Duration>, String> {
    let Some(value) = value.filter(|v| !v.is_empty()) else { return Ok(None) };
    let duration = parse_duration(value).map_err(|e| format!("HEALTHCHECK --{option}: {e}"))?;
    if duration.is_zero() {
        return Ok(None);
    }
    if duration < Duration::from_millis(1) {
        return Err(format!("HEALTHCHECK --{option}={value}: can't be less than 1ms"));
    }
    // Image configs hold Go's int64 nanoseconds.
    if duration.as_nanos() > i64::MAX as u128 {
        return Err(format!("HEALTHCHECK --{option}={value}: too long"));
    }
    Ok(Some(duration))
}

/// `HEALTHCHECK --retries`: a count; `0` (or nothing) is the default, `None`.
pub(crate) fn health_retries(value: Option<&str>) -> Result<Option<u32>, String> {
    let Some(value) = value.filter(|v| !v.is_empty()) else { return Ok(None) };
    let retries: i64 = value.parse().map_err(|_| format!("HEALTHCHECK --retries={value}: not a number"))?;
    if retries < 0 {
        return Err(format!("HEALTHCHECK --retries={value}: can't be negative"));
    }
    let retries = i32::try_from(retries)
        .ok()
        .and_then(|r| u32::try_from(r).ok())
        .ok_or_else(|| format!("HEALTHCHECK --retries={value}: too many"))?;
    Ok((retries != 0).then_some(retries))
}

#[cfg(test)]
mod tests;
