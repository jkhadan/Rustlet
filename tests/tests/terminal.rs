//! Phase 2a: `process.terminal: true` through `rustlet-runc`: the PTY that
//! foreground `run` relays, the container's view of it (`/dev/pts/0`,
//! `/dev/console`, session and controlling terminal, console size), and the
//! OCI console-socket protocol for `create`.
//!
//! Run with `cargo xtask itest -- tty_`.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::Spec;

/// Foreground `run` of `spec` with a terminal (and `consoleSize`, if given),
/// with `input` on stdin; returns what came out.
#[track_caller]
fn run_tty(mut s: Spec, size: Option<(u64, u64)>, input: &[u8]) -> CmdOut {
    set_terminal(&mut s, size);
    let mut c = Container::new(&s);
    let out = c.run_foreground(&[], Some(input), TIMEOUT);
    c.assert_gone();
    out
}

/// Output lines without the `\r` a terminal puts before each `\n`.
fn tty_lines(out: &str) -> Vec<&str> {
    out.lines().map(|l| l.trim_end_matches('\r')).collect()
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_run_relays_stdio_through_a_pty() {
    // An interactive shell, fed through the relay.
    let out = run_tty(spec(&["sh"]), None, b"tty; exit 5\n");
    assert_eq!(out.status, 5, "{out:#?}");
    // The terminal's output processing turns `\n` into `\r\n`.
    assert!(out.stdout.contains("/dev/pts/0\r\n"), "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_stdin_eof_sends_end_of_file() {
    // cat only exits once it reads EOF: the ^D the relay sends when its stdin
    // runs dry. Without it this hangs until the timeout.
    let mut s = spec(&["cat"]);
    set_terminal(&mut s, None);
    let mut c = Container::new(&s);
    let out = c.run_foreground(&[], Some(b"hello\n"), Duration::from_secs(15));
    assert_eq!(out.status, 0, "{out:#?}");
    assert!(out.stdout.contains("hello"), "{out:#?}");
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_dev_console_is_the_pty() {
    let script = "test -c /dev/console && echo chardev; stat -c '%t %T' /dev/console; stat -c '%t %T' \"$(tty)\"";
    let out = run_tty(sh(script), None, b"");
    // Major 136 (0x88) is the first pts major; minor 0 is /dev/pts/0.
    assert_eq!(tty_lines(out.ok()), ["chardev", "88 0", "88 0"], "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_init_is_a_session_leader_with_a_controlling_terminal() {
    // `; true` keeps the shell from exec'ing cat, so this is the shell's stat.
    let out = run_tty(sh("cat /proc/$$/stat; true"), None, b"");
    let line = tty_lines(out.ok()).into_iter().find(|l| l.starts_with("1 (")).map(str::to_owned);
    let line = line.unwrap_or_else(|| panic!("no stat line for PID 1: {out:#?}"));
    // After `(comm)`: state ppid pgrp session tty_nr tpgid …
    let f = stat_fields(&line);
    assert_eq!(f[3], "1", "session: init is not a session leader: {line}");
    assert_eq!(f[2], "1", "pgrp: {line}");
    let tty_nr: u32 = f[4].parse().unwrap();
    assert_ne!(tty_nr, 0, "init has no controlling terminal: {line}");
    assert_eq!((tty_nr >> 8) & 0xfff, 136, "the controlling terminal is not a pts: {line}");
    assert_eq!(f[5], "1", "tpgid: init's process group is not in the foreground: {line}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_console_size_is_applied() {
    let out = run_tty(spec(&["stty", "size"]), Some((30, 100)), b"");
    assert_eq!(tty_lines(out.ok()), ["30 100"], "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_create_requires_a_console_socket() {
    let mut s = spec(&["true"]);
    set_terminal(&mut s, None);
    set_cgroup(&mut s, "tty-no-socket");
    let mut c = Container::new(&s);
    c.create(&[]).refused("console");
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tty_console_socket_receives_the_master() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("console.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();

    // The last `sleep` keeps the slave open until we have read everything.
    let mut s = sh("tty; echo ready; read x; echo got-$x; sleep 1");
    set_terminal(&mut s, None);
    set_cgroup(&mut s, "tty-console-socket");
    let mut c = Container::new(&s);

    // `create` connects and sends the master while it sets up; accept in
    // parallel so neither side can wait on the other.
    let (created, stream) = std::thread::scope(|scope| {
        let create = scope.spawn(|| c.create(&["--console-socket", sock.to_str().unwrap()]));
        let deadline = Instant::now() + TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("accept on the console socket: {e}"),
            }
            if create.is_finished() {
                // It may have connected just before exiting.
                if let Ok((stream, _)) = listener.accept() {
                    break stream;
                }
                panic!("`create` never connected to the console socket: {:#?}", create.join());
            }
            assert!(Instant::now() < deadline, "`create` never connected to the console socket");
            std::thread::sleep(Duration::from_millis(20));
        };
        (create.join().unwrap(), stream)
    });
    created.ok();
    assert_eq!(c.status(), "created");

    stream.set_read_timeout(Some(PROMPT)).unwrap();
    let master = rustlet_runtime::console::receive_master(stream.as_fd()).expect("no PTY master on the console socket");
    let master = File::from(master);

    c.start().ok();
    let mut seen = String::new();
    pty_read_until(&master, &mut seen, "ready", PROMPT);
    assert!(seen.contains("/dev/pts/0"), "{seen:?}");
    // Both directions: what we type reaches the program.
    (&master).write_all(b"ping\n").unwrap();
    pty_read_until(&master, &mut seen, "got-ping", PROMPT);
    c.wait_for_status("stopped", PROMPT);
    c.delete(false).ok();
    c.assert_gone();
}
