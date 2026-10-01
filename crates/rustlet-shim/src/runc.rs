//! Running `rustlet-runc`, the OCI runtime, and turning its failures into
//! messages.
//!
//! Every invocation gets `--root` (the runtime's state directory) and its
//! own `--log` file with `--log-format json`: when `create` or `exec` runs
//! without a terminal, the runtime's stderr *is* the container's (the
//! container inherits it), so its error message can't be read from there.
//! The log has it as a JSON line, `{"level":"ERROR","fields":{"message":…}}`.

use std::cell::Cell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rustlet_sys::process::WaitResult;

use crate::reaper::Reaper;

/// A failed `rustlet-runc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuncError {
    pub message: String,
    /// Its exit status: 127 if the program to run wasn't found, 126 if it
    /// couldn't be executed, 1 otherwise. `None` if it didn't run at all.
    pub exit_code: Option<i32>,
}

impl std::fmt::Display for RuncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The three standard streams of a `rustlet-runc` process.
pub struct Stdio3 {
    pub stdin: Stdio,
    pub stdout: Stdio,
    pub stderr: Stdio,
}

impl Stdio3 {
    pub fn null() -> Stdio3 {
        Stdio3 { stdin: Stdio::null(), stdout: Stdio::null(), stderr: Stdio::null() }
    }
}

pub struct Runc {
    binary: PathBuf,
    root: PathBuf,
    /// Where the per-invocation log files go (the shim's directory).
    dir: PathBuf,
    counter: Cell<u64>,
}

impl Runc {
    pub fn new(binary: PathBuf, root: PathBuf, dir: PathBuf) -> Runc {
        Runc { binary, root, dir, counter: Cell::new(0) }
    }

    /// Runs `rustlet-runc <args>` with `stdio` and waits for it.
    pub async fn run(&self, reaper: &Reaper, args: Vec<OsString>, stdio: Stdio3) -> Result<(), RuncError> {
        let n = self.counter.get();
        self.counter.set(n + 1);
        let log = self.dir.join(format!("runc-{n}.log"));
        let what = args.first().map(|a| a.to_string_lossy().into_owned()).unwrap_or_default();
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--root").arg(&self.root).arg("--log").arg(&log).args(["--log-format", "json"]).args(&args);
        cmd.stdin(stdio.stdin).stdout(stdio.stdout).stderr(stdio.stderr);
        let child = cmd.spawn().map_err(|e| RuncError {
            message: format!("run {} {what}: {e}", self.binary.display()),
            exit_code: None,
        })?;
        // No `.await` between the spawn and `watch`: see `reaper`. The
        // `Child` is dropped without waiting; the reaper collects it.
        let exited = reaper.watch(child.id() as i32);
        drop(child);
        let status = exited.await.map_err(|_| RuncError {
            message: format!("rustlet-runc {what}: the reaper went away"),
            exit_code: None,
        })?;
        let result = match status {
            WaitResult::Exited { code: 0, .. } => Ok(()),
            other => {
                let code = other.exit_code();
                let message =
                    error_from_log(&log).unwrap_or_else(|| format!("rustlet-runc {what} failed ({})", describe(other)));
                Err(RuncError { message, exit_code: code })
            }
        };
        let _ = std::fs::remove_file(&log);
        result
    }
}

fn describe(status: WaitResult) -> String {
    match status {
        WaitResult::Exited { code, .. } => format!("exit status {code}"),
        WaitResult::Signaled { signal, .. } => format!("killed by signal {signal}"),
        WaitResult::StillAlive => "still running".into(),
    }
}

/// The message of the last `ERROR` line of a `--log-format json` log.
fn error_from_log(log: &Path) -> Option<String> {
    let text = std::fs::read_to_string(log).ok()?;
    text.lines().rev().find_map(|line| {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        if v["level"] != "ERROR" {
            return None;
        }
        v["fields"]["message"].as_str().map(str::to_owned)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_come_from_the_last_error_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("runc.log");
        std::fs::write(
            &log,
            concat!(
                r#"{"timestamp":"t","level":"WARN","fields":{"message":"just a warning"}}"#,
                "\n",
                r#"{"timestamp":"t","level":"ERROR","fields":{"message":"first"}}"#,
                "\n",
                "not json\n",
                r#"{"timestamp":"t","level":"ERROR","fields":{"message":"exec \"nope\": no such file"}}"#,
                "\n",
            ),
        )
        .unwrap();
        assert_eq!(error_from_log(&log).as_deref(), Some("exec \"nope\": no such file"));
        assert_eq!(error_from_log(&dir.path().join("missing")), None);
    }
}
