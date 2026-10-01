//! Phase 4: `rustlet-shim` on its own, driven over `shim.sock` the way the
//! daemon drives it. Run with `cargo xtask itest -- sh_`.

use rustlet_itests::e2e::*;
use rustlet_itests::shim::{TestShim, block_on, collect};
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{LinuxMemoryBuilder, LinuxResourcesBuilder};
use rustlet_shim::protocol::{ExecRequest, ExecUser, Handshake, Request, Response, ShimState};

fn ready(shim: &TestShim) -> i32 {
    match &shim.handshake {
        Handshake::Ready { init_pid, .. } => *init_pid,
        other => panic!("not ready: {other:?}; shim.log: {}", shim.shim_log()),
    }
}

/// Output reaches an attached client and the log, stream by stream; the
/// exit status reaches the stream, `Wait` and `Status`; Delete and Shutdown
/// leave nothing behind.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_output_is_streamed_and_logged_and_the_exit_reported() {
    let mut s = sh("echo out; echo err >&2; printf 'no newline'; exit 3");
    set_cgroup(&mut s, "sh-output");
    let shim = TestShim::start(&s, false, false);
    let init = ready(&shim);
    assert!(init > 1);
    block_on(async {
        match shim.call(Request::Status).await {
            Response::Status(st) => assert_eq!((st.state, st.init_pid), (ShimState::Created, init)),
            other => panic!("{other:?}"),
        }
        let (r, stream) = shim.stream(Request::Attach { stdin: false }).await;
        assert_eq!(r, Response::Ok);
        shim.ok(Request::Start).await;
        let got = collect(&mut stream.unwrap()).await;
        assert_eq!(got.stdout, "out\nno newline");
        assert_eq!(got.stderr, "err\n");
        let exit = got.exit.expect("an exit");
        assert_eq!((exit.code, exit.signal, exit.oom_killed), (3, None, false));
        assert_eq!(shim.call(Request::Wait).await, Response::Exited(exit.clone()));
        match shim.call(Request::Status).await {
            Response::Status(st) => assert_eq!((st.state, st.exit), (ShimState::Exited, Some(exit))),
            other => panic!("{other:?}"),
        }
        let mut entries = shim.log_entries();
        entries.sort();
        assert_eq!(
            entries,
            [
                ("stderr".to_string(), "err\n".to_string()),
                ("stdout".into(), "no newline".into()),
                ("stdout".into(), "out\n".into()),
            ]
        );
        assert!(shim.paths.exit_json().exists());
        // A second start is refused; the exited container can't be exec'd into.
        assert!(matches!(shim.call(Request::Start).await, Response::Error { .. }));
        shim.finish().await;
    });
}

/// `--stdin --stdin-once`: what the first attached client sends arrives,
/// and its end of input becomes the container's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_stdin_once_ends_the_containers_input() {
    let mut s = spec(&["cat"]);
    set_cgroup(&mut s, "sh-stdin");
    let shim = TestShim::start(&s, true, true);
    ready(&shim);
    block_on(async {
        let (_, stream) = shim.stream(Request::Attach { stdin: true }).await;
        let mut stream = stream.unwrap();
        shim.ok(Request::Start).await;
        stream.writer().stdin(b"hello\n").await.unwrap();
        stream.writer().stdin(b"world\n").await.unwrap();
        stream.writer().close_stdin().await.unwrap();
        let got = collect(&mut stream).await;
        assert_eq!(got.stdout, "hello\nworld\n");
        assert_eq!(got.exit.unwrap().code, 0);
        shim.finish().await;
    });
}

/// A terminal: the size set before start is the program's, input and
/// output go through the PTY master.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_terminal_with_resize_and_input() {
    let mut s = sh("stty size; read line; echo \"got $line\"; exit 7");
    edit_process(&mut s, |p| {
        p.set_terminal(Some(true));
    });
    set_cgroup(&mut s, "sh-tty");
    let shim = TestShim::start(&s, true, false);
    ready(&shim);
    block_on(async {
        let (_, stream) = shim.stream(Request::Attach { stdin: true }).await;
        let mut stream = stream.unwrap();
        stream.writer().resize(30, 100).await.unwrap();
        // Resize also works as a request of its own.
        shim.ok(Request::Resize { rows: 30, cols: 100 }).await;
        shim.ok(Request::Start).await;
        stream.writer().stdin(b"typed\n").await.unwrap();
        let got = collect(&mut stream).await;
        assert!(got.stdout.contains("30 100"), "{got:?}");
        assert!(got.stdout.contains("got typed"), "{got:?}");
        assert_eq!(got.stderr, "", "a terminal has one output");
        assert_eq!(got.exit.unwrap().code, 7);
        shim.finish().await;
    });
}

/// Exec with pipes, with input, and with a terminal; each process's exit
/// status comes back on its own stream. Then a kill.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_exec_processes_and_kill() {
    let mut s = sh("while :; do sleep 1; done");
    set_cgroup(&mut s, "sh-exec");
    let shim = TestShim::start(&s, false, false);
    ready(&shim);
    block_on(async {
        // Not before the container runs.
        let r = shim.stream(Request::Exec(ExecRequest { args: vec!["true".into()], ..Default::default() })).await;
        assert!(matches!(r.0, Response::Error { .. }), "{r:?}");
        shim.ok(Request::Start).await;

        let exec = |args: &[&str], tty, stdin| {
            Request::Exec(ExecRequest {
                exec_id: "e".into(),
                args: args.iter().map(|a| a.to_string()).collect(),
                env: vec!["GREETING=hi".into()],
                tty,
                stdin,
                ..Default::default()
            })
        };
        let (r, stream) =
            shim.stream(exec(&["sh", "-c", "echo $GREETING; echo there >&2; exit 4"], false, false)).await;
        assert!(matches!(r, Response::Started { pid } if pid > 1), "{r:?}");
        let got = collect(&mut stream.unwrap()).await;
        assert_eq!((got.stdout.as_str(), got.stderr.as_str(), got.exit.unwrap().code), ("hi\n", "there\n", 4));

        let (_, stream) = shim.stream(exec(&["cat"], false, true)).await;
        let mut stream = stream.unwrap();
        stream.writer().stdin(b"piped\n").await.unwrap();
        stream.writer().close_stdin().await.unwrap();
        let got = collect(&mut stream).await;
        assert_eq!((got.stdout.as_str(), got.exit.unwrap().code), ("piped\n", 0));

        let (_, stream) = shim.stream(exec(&["sh", "-c", "tty; exit 5"], true, false)).await;
        let got = collect(&mut stream.unwrap()).await;
        assert!(got.stdout.contains("/dev/pts/"), "{got:?}");
        assert_eq!(got.exit.unwrap().code, 5);

        // As another user, resolved by the caller.
        let r = Request::Exec(ExecRequest {
            args: vec!["id".into()],
            user: Some(ExecUser { uid: 1000, gid: 1000, additional_gids: vec![1000] }),
            ..Default::default()
        });
        let (_, stream) = shim.stream(r).await;
        let got = collect(&mut stream.unwrap()).await;
        assert!(got.stdout.starts_with("uid=1000 gid=1000"), "{got:?}");

        // A missing program: the runtime's 127, before anything runs.
        match shim.stream(exec(&["/no/such/program"], false, false)).await.0 {
            Response::Error { exit_code, message } => assert_eq!(exit_code, Some(127), "{message}"),
            other => panic!("{other:?}"),
        }

        shim.ok(Request::Kill { signal: 9, all: false }).await;
        match shim.call(Request::Wait).await {
            Response::Exited(e) => assert_eq!((e.code, e.signal), (137, Some(9))),
            other => panic!("{other:?}"),
        }
        shim.finish().await;
    });
}

/// A container that can't be created: the handshake says why, with the
/// runtime's exit status, and nothing is left behind.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_create_failure_is_reported_in_the_handshake() {
    let mut s = spec(&["/no/such/program"]);
    set_cgroup(&mut s, "sh-fail");
    let shim = TestShim::start(&s, false, false);
    match &shim.handshake {
        Handshake::Failed { exit_code, message } => {
            assert_eq!(*exit_code, Some(127), "{message}");
            assert!(message.contains("no/such/program"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    assert!(!runtime_root().join(&shim.bundle.id).exists());
}

/// Pipes belong to the process's user, as the host sees it: a non-root
/// process, rootful and in a user namespace, can reopen its stdio.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_stdio_pipes_belong_to_the_process_user() {
    for userns in [false, true] {
        let script = "echo out >/dev/stdout && echo err >/dev/stderr && stat -L -c '%u:%g' /proc/self/fd/1";
        let mut s = if userns { userns_sh(script) } else { sh(script) };
        set_user(&mut s, 1000, 1000, &[]);
        set_cgroup(&mut s, "sh-pipes");
        let shim = TestShim::start(&s, false, false);
        ready(&shim);
        block_on(async {
            let (_, stream) = shim.stream(Request::Attach { stdin: false }).await;
            shim.ok(Request::Start).await;
            let got = collect(&mut stream.unwrap()).await;
            // Inside a user namespace, host 1001000 shows as 1000 again.
            assert_eq!(got.stdout, "out\n1000:1000\n", "userns={userns}: {got:?}");
            assert_eq!(got.stderr, "err\n", "userns={userns}");
            assert_eq!(got.exit.unwrap().code, 0, "userns={userns}");
            shim.finish().await;
        });
    }
}

/// An OOM kill in the container's cgroup is part of the exit status.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sh_oom_kill_is_reported() {
    let mut s = spec(&["dd", "if=/dev/zero", "of=/dev/null", "bs=64M", "count=1"]);
    set_cgroup(&mut s, "sh-oom");
    let mib = 1 << 20;
    set_resources(
        &mut s,
        LinuxResourcesBuilder::default()
            .memory(LinuxMemoryBuilder::default().limit(32 * mib).swap(32 * mib).build().unwrap())
            .build()
            .unwrap(),
    );
    let shim = TestShim::start(&s, false, false);
    ready(&shim);
    block_on(async {
        shim.ok(Request::Start).await;
        match shim.call(Request::Wait).await {
            Response::Exited(e) => assert!(e.oom_killed && e.code == 137, "{e:?}"),
            other => panic!("{other:?}"),
        }
        shim.finish().await;
    });
}
