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
//! "use RUN with curl or wget").

use std::time::Duration;

use crate::parser::{Command, InstructionKind};

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
        let _ = (kind, escape, lookup);
        unimplemented!("Op::new: agent A")
    }

    /// Does this step change the filesystem (`RUN`, `COPY`, `ADD`)? The
    /// others only change the config, or the build's variables.
    pub fn makes_layer(&self) -> bool {
        matches!(self, Op::Run(_) | Op::Copy(_))
    }
}
