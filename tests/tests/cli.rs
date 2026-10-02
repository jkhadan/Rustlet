//! Phase 4: the `rustlet` CLI against a daemon of the test's own: what a
//! user types, what they see, and the exit codes. Run with
//! `cargo xtask itest -- cl_`.

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use rustlet_itests::daemon::TestDaemon;
use rustlet_itests::workspace_binary;

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

/// `rustlet --host <the test daemon> <args>`.
fn rustlet(d: &TestDaemon, args: &[&str]) -> Command {
    let mut c = Command::new(workspace_binary("rustlet"));
    c.arg("--host").arg(&d.socket).args(args).stdin(Stdio::null());
    c
}

#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn out(o: Output) -> Out {
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn cli(d: &TestDaemon, args: &[&str]) -> Out {
    out(rustlet(d, args).output().unwrap())
}

#[track_caller]
fn ok(d: &TestDaemon, args: &[&str]) -> String {
    let o = cli(d, args);
    assert_eq!(o.code, 0, "rustlet {args:?}: {o:#?}");
    o.stdout
}

/// Runs `args` under `script(1)`, which gives it a terminal, with `input`
/// typed into it.
fn with_terminal(d: &TestDaemon, args: &[&str], input: &[u8]) -> Out {
    let mut line = format!("{} --host {}", workspace_binary("rustlet").display(), d.socket.display());
    for a in args {
        line.push(' ');
        line.push_str(&format!("'{}'", a.replace('\'', r"'\''")));
    }
    let mut child = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // Give the container time to come up before typing, as a person would.
    std::thread::sleep(Duration::from_millis(1500));
    stdin.write_all(input).unwrap();
    drop(stdin);
    out(child.wait_with_output().unwrap())
}

/// `run --rm` in the foreground: output, the exit status, nothing left.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_run_rm_passes_output_and_status_through() {
    let d = daemon();
    let o = cli(&d, &["run", "--rm", "alpine", "sh", "-c", "echo out; echo err >&2; exit 3"]);
    assert_eq!((o.code, o.stdout.as_str()), (3, "out\n"), "{o:#?}");
    assert!(o.stderr.contains("err\n"), "{o:#?}");
    assert_eq!(ok(&d, &["ps", "-a", "-q"]), "", "--rm left a container");
    // Piped input with -i.
    let mut child = rustlet(&d, &["run", "--rm", "-i", "alpine", "tr", "a-z", "A-Z"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"shout\n").unwrap();
    let o = out(child.wait_with_output().unwrap());
    assert_eq!((o.code, o.stdout.as_str()), (0, "SHOUT\n"), "{o:#?}");
}

/// Docker's exit codes for things that fail before or instead of the
/// program: 125 (rustlet's), 127 (not found), 126 (not executable).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_exit_codes_say_whose_fault() {
    let d = daemon();
    let o = cli(&d, &["run", "--rm", "--pull", "never", "nosuchimage:1"]);
    assert_eq!(o.code, 125, "{o:#?}");
    assert!(o.stderr.contains("nosuchimage"), "{o:#?}");
    let o = cli(&d, &["run", "--rm", "alpine", "/no/such/program"]);
    assert_eq!(o.code, 127, "{o:#?}");
    let o = cli(&d, &["run", "--rm", "alpine", "/etc/passwd"]);
    assert_eq!(o.code, 126, "{o:#?}");
    let o = cli(&d, &["stop", "nonexistent"]);
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("nonexistent"), "{o:#?}");
}

/// The detached life of a container: run -d, ps, logs, exec, stop, start,
/// restart, rm.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_detached_container_lifecycle() {
    let d = daemon();
    let id = ok(&d, &["run", "-d", "--name", "web", "alpine", "sh", "-c", "echo started; while :; do sleep 0.2; done"]);
    let id = id.trim();
    assert_eq!(id.len(), 64, "{id:?}");
    let ps = ok(&d, &["ps"]);
    assert!(ps.lines().any(|l| l.starts_with(&id[..12]) && l.contains("web") && l.contains("Up")), "{ps}");
    assert_eq!(ok(&d, &["ps", "-q"]).trim(), &id[..12]);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(ok(&d, &["logs", "web"]), "started\n");
    assert_eq!(ok(&d, &["exec", "web", "sh", "-c", "echo $((6*7))"]), "42\n");
    let o = cli(&d, &["exec", "web", "sh", "-c", "exit 4"]);
    assert_eq!(o.code, 4, "{o:#?}");
    assert_eq!(ok(&d, &["stop", "-t", "1", "web"]).trim(), "web");
    let ps = ok(&d, &["ps", "-a"]);
    assert!(ps.contains("Exited (137)"), "{ps}");
    assert!(ok(&d, &["ps"]).lines().count() <= 1, "only the header once it stopped");
    ok(&d, &["start", "web"]);
    ok(&d, &["restart", "-t", "1", "web"]);
    assert!(ok(&d, &["ps"]).contains("web"));
    let inspect: serde_json::Value = serde_json::from_str(&ok(&d, &["inspect", "web"])).unwrap();
    assert_eq!(inspect[0]["state"]["status"], "running", "{inspect}");
    let o = cli(&d, &["rm", "web"]);
    assert_ne!(o.code, 0, "rm of a running container needs -f: {o:#?}");
    assert_eq!(ok(&d, &["rm", "-f", "web"]).trim(), "web");
    assert_eq!(ok(&d, &["ps", "-a", "-q"]), "");
}

/// `run -it`: a shell on a terminal, its exit status passed through.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_interactive_terminal() {
    let d = daemon();
    let o = with_terminal(&d, &["run", "-it", "--rm", "alpine", "sh"], b"echo answer=$((6*7)); tty; exit 5\n");
    assert!(o.stdout.contains("answer=42"), "{o:#?}");
    assert!(o.stdout.contains("/dev/pts/"), "{o:#?}");
    assert_eq!(o.code, 5, "{o:#?}");
    assert_eq!(ok(&d, &["ps", "-a", "-q"]), "");
    // exec -it into a running container.
    ok(&d, &["run", "-d", "--name", "box", "alpine", "sleep", "300"]);
    let o = with_terminal(&d, &["exec", "-it", "box", "sh"], b"echo inside=$(hostname | wc -c); exit 6\n");
    assert!(o.stdout.contains("inside=13"), "the hostname is the 12-character short id: {o:#?}");
    assert_eq!(o.code, 6, "{o:#?}");
    ok(&d, &["rm", "-f", "box"]);
}

/// `logs -f` follows to the end; images, inspect and stats print.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_logs_follow_images_stats() {
    let d = daemon();
    ok(&d, &["run", "-d", "--name", "counter", "alpine", "sh", "-c", "for i in 1 2 3; do echo $i; sleep 0.3; done"]);
    assert_eq!(ok(&d, &["logs", "-f", "counter"]), "1\n2\n3\n");
    assert_eq!(ok(&d, &["logs", "--tail", "1", "counter"]), "3\n");
    let images = ok(&d, &["images"]);
    assert!(images.lines().any(|l| l.starts_with("alpine") && l.contains("latest")), "{images}");
    ok(&d, &["run", "-d", "--name", "busy", "--memory", "64m", "alpine", "sleep", "300"]);
    let stats = ok(&d, &["stats", "--no-stream", "busy"]);
    assert!(stats.contains("busy") && stats.contains("64MiB"), "{stats}");
    let inspect: serde_json::Value = serde_json::from_str(&ok(&d, &["inspect", "alpine"])).unwrap();
    assert!(inspect[0]["names"][0].as_str().unwrap().contains("alpine"), "{inspect}");
    ok(&d, &["rm", "-f", "busy", "counter"]);
}

/// Input still flowing when the container exits (`yes | rustlet run -i …
/// head -c1`): the daemon shuts the shim down while it waits to report the
/// exit, and a write to the gone shim used to end the session there,
/// without the exit (125, "rustletd closed the session").
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_flowing_input_keeps_the_exit_status() {
    let d = daemon();
    for i in 0..10 {
        let mut child = rustlet(&d, &["run", "--rm", "-i", "alpine", "head", "-c", "1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let feeder = std::thread::spawn(move || {
            let chunk = vec![b'y'; 64 << 10];
            while stdin.write_all(&chunk).is_ok() {}
        });
        let o = out(child.wait_with_output().unwrap());
        feeder.join().unwrap();
        assert_eq!((o.code, o.stdout.as_str()), (0, "y"), "run {i}: {o:#?}");
    }
}

/// A program in a terminal sees the client's terminal size from its first
/// look: `run -t` sends it before the start, `exec -t` with the request
/// (a resize once it runs came after `stty size` had printed `0 0`).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cl_programs_start_with_the_terminals_size() {
    let d = daemon();
    let sized = |args: &str| {
        let line = format!(
            "stty rows 30 cols 100; {} --host {} {args}",
            workspace_binary("rustlet").display(),
            d.socket.display()
        );
        out(Command::new("script")
            .args(["-qec", &line, "/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap())
    };
    let o = sized("run --rm -t alpine stty size");
    assert!(o.stdout.contains("30 100"), "run: {o:#?}");
    ok(&d, &["run", "-d", "--name", "box", "alpine", "sleep", "300"]);
    let o = sized("exec -t box stty size");
    ok(&d, &["rm", "-f", "box"]);
    assert!(o.stdout.contains("30 100"), "exec: {o:#?}");
}
