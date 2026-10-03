//! Phase 4: rustletd, end to end through its API (rustlet-client), each
//! test with a daemon of its own. Run with `cargo xtask itest -- dm_`.

use std::time::Duration;

use futures::StreamExt;
use rustlet_client::{Client, SessionEvent};
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_spec::ErrorKind;
use rustlet_spec::container::{ContainerConfig, ContainerStatus, RestartPolicy, UsernsMode, WaitCondition};
use rustlet_spec::exec::ExecConfig;
use rustlet_spec::logs::{LogStream, LogsQuery};

fn alpine(cmd: &[&str]) -> ContainerConfig {
    ContainerConfig { image: "alpine".into(), cmd: cmd.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

fn sh(script: &str) -> ContainerConfig {
    alpine(&["sh", "-c", script])
}

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

/// What a session delivered, up to its end.
#[derive(Debug, Default)]
struct Got {
    stdout: String,
    stderr: String,
    exit: Option<i32>,
    error: Option<String>,
}

async fn drain(session: &mut rustlet_client::SessionReceiver) -> Got {
    let mut got = Got::default();
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(30), session.recv()).await.expect("the session never ended");
        match ev.expect("session error") {
            Some(SessionEvent::Stdout(b)) => got.stdout.push_str(&String::from_utf8_lossy(&b)),
            Some(SessionEvent::Stderr(b)) => got.stderr.push_str(&String::from_utf8_lossy(&b)),
            Some(SessionEvent::Exit { code, .. }) => {
                got.exit = Some(code);
                return got;
            }
            Some(SessionEvent::Error { message, .. }) => {
                got.error = Some(message);
                return got;
            }
            None => return got,
        }
    }
}

async fn logs(c: &Client, id: &str, q: LogsQuery) -> Vec<(LogStream, String)> {
    let mut s = c.logs(id, &q).await.unwrap();
    let mut out = Vec::new();
    while let Some(e) = tokio::time::timeout(Duration::from_secs(30), s.next()).await.expect("logs never ended") {
        let e = e.unwrap();
        out.push((e.stream, e.log));
    }
    out
}

async fn status(c: &Client, id: &str) -> ContainerStatus {
    c.inspect_container(id).await.unwrap().state.status
}

async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !f().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The basic cycle: create, start, wait, logs, inspect, rm; nothing is
/// left mounted or running.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_run_wait_logs_and_remove() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let r = c.create_container(&sh("echo out; echo err >&2; exit 3")).await.unwrap();
        assert_eq!(r.id.len(), 64);
        assert!(rustlet_spec::valid_container_name(&r.name), "{}", r.name);
        assert_eq!(status(&c, &r.id).await, ContainerStatus::Created);
        c.start(&r.id).await.unwrap();
        let w = c.wait(&r.id, WaitCondition::NextExit).await.unwrap();
        assert_eq!((w.status_code, w.oom_killed), (3, false));
        let i = c.inspect_container(&r.name).await.unwrap();
        assert_eq!(i.state.status, ContainerStatus::Exited);
        assert_eq!(i.state.exit_code, Some(3));
        assert!(i.state.started_at.is_some() && i.state.finished_at.is_some());
        assert_eq!(i.rootfs, None, "unmounted after the exit");
        let mut l = logs(&c, &r.id, LogsQuery::default()).await;
        l.sort();
        assert_eq!(l, [(LogStream::Stdout, "out\n".to_string()), (LogStream::Stderr, "err\n".into())]);
        let only_err = logs(&c, &r.id, LogsQuery { stdout: false, ..Default::default() }).await;
        assert_eq!(only_err, [(LogStream::Stderr, "err\n".to_string())]);
        // Short ids and names find it too.
        assert_eq!(c.inspect_container(&r.id[..12]).await.unwrap().id, r.id);
        c.remove_container(&r.id, false).await.unwrap();
        let e = c.inspect_container(&r.id).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::NoSuchContainer));
        assert!(c.list_containers(true).await.unwrap().is_empty());
    });
    assert!(d.mounts().iter().all(|m| m.ends_with("/containers")), "{:?}", d.mounts());
}

/// An attach made before start sees everything; `stdin_once` turns the
/// client's end of input into the container's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_attach_before_start_and_stdin_once() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig { open_stdin: true, stdin_once: true, ..sh("echo first; cat") };
        let id = c.create_container(&cfg).await.unwrap().id;
        let session = c.attach(&id, true).await.unwrap();
        let (mut tx, mut rx) = session.split();
        c.start(&id).await.unwrap();
        tx.send_stdin(b"hello\n").await.unwrap();
        tx.stdin_eof().await.unwrap();
        let got = drain(&mut rx).await;
        assert_eq!(got.stdout, "first\nhello\n", "{got:?}");
        assert_eq!(got.exit, Some(0), "{got:?}");
        c.remove_container(&id, false).await.unwrap();
    });
}

/// A terminal: the size sent before start is the program's; input and
/// output through the PTY.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_terminal_session() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig {
            tty: true,
            open_stdin: true,
            stdin_once: true,
            ..sh("stty size; read x; echo \"got $x\"; exit 4")
        };
        let id = c.create_container(&cfg).await.unwrap().id;
        let (mut tx, mut rx) = c.attach(&id, true).await.unwrap().split();
        tx.resize(33, 99).await.unwrap();
        // The size reaches the daemon before the start does.
        tokio::time::sleep(Duration::from_millis(200)).await;
        c.start(&id).await.unwrap();
        tx.send_stdin(b"typed\n").await.unwrap();
        let got = drain(&mut rx).await;
        assert!(got.stdout.contains("33 99"), "{got:?}");
        assert!(got.stdout.contains("got typed"), "{got:?}");
        assert_eq!(got.exit, Some(4));
        c.remove_container(&id, true).await.unwrap();
    });
}

/// `logs -f` delivers output as it is written and ends with the container.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_logs_follow_until_the_exit() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c.create_container(&sh("for i in 1 2 3; do echo $i; sleep 0.3; done")).await.unwrap().id;
        c.start(&id).await.unwrap();
        let followed = logs(&c, &id, LogsQuery { follow: true, ..Default::default() }).await;
        let texts: Vec<_> = followed.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(texts, ["1\n", "2\n", "3\n"]);
        assert_eq!(status(&c, &id).await, ContainerStatus::Exited);
        let tail = logs(&c, &id, LogsQuery { tail: Some(1), ..Default::default() }).await;
        assert_eq!(tail, [(LogStream::Stdout, "3\n".to_string())]);
        c.remove_container(&id, false).await.unwrap();
    });
}

/// Exec: pipes with an exit status, a terminal, input, another user, a
/// detached process, and the errors.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_exec_processes() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c.create_container(&sh("while :; do sleep 0.2; done")).await.unwrap().id;
        // Not before it runs.
        let e = c.create_exec(&id, &ExecConfig { cmd: vec!["true".into()], ..Default::default() }).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Conflict));
        c.start(&id).await.unwrap();
        let run = async |cfg: ExecConfig| {
            let x = c.create_exec(&id, &cfg).await.unwrap();
            let (_, mut rx) = c.start_exec(&x.id).await.unwrap().split();
            (x.id, drain(&mut rx).await)
        };
        let cmd = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (x, got) = run(ExecConfig {
            cmd: cmd(&["sh", "-c", "echo $GREETING; echo oops >&2; exit 5"]),
            env: vec!["GREETING=hi".into()],
            ..Default::default()
        })
        .await;
        assert_eq!((got.stdout.as_str(), got.stderr.as_str(), got.exit), ("hi\n", "oops\n", Some(5)), "{got:?}");
        let inspected = c.inspect_exec(&x).await.unwrap();
        assert_eq!((inspected.running, inspected.exit_code), (false, Some(5)));
        let (_, got) =
            run(ExecConfig { cmd: cmd(&["sh", "-c", "tty; exit 6"]), tty: true, ..Default::default() }).await;
        assert!(got.stdout.contains("/dev/pts/"), "{got:?}");
        assert_eq!(got.exit, Some(6));
        let (_, got) = run(ExecConfig { cmd: cmd(&["id"]), user: Some("nobody".into()), ..Default::default() }).await;
        assert!(got.stdout.starts_with("uid=65534(nobody) gid=65534(nobody)"), "{got:?}");
        let (_, got) = run(ExecConfig { cmd: cmd(&["pwd"]), workdir: Some("/tmp".into()), ..Default::default() }).await;
        assert_eq!(got.stdout, "/tmp\n");
        // Input.
        let x =
            c.create_exec(&id, &ExecConfig { cmd: cmd(&["cat"]), stdin: true, ..Default::default() }).await.unwrap();
        let (mut tx, mut rx) = c.start_exec(&x.id).await.unwrap().split();
        tx.send_stdin(b"piped\n").await.unwrap();
        tx.stdin_eof().await.unwrap();
        let got = drain(&mut rx).await;
        assert_eq!((got.stdout.as_str(), got.exit), ("piped\n", Some(0)));
        // Detached: it runs; its exit status shows up in inspect.
        let x =
            c.create_exec(&id, &ExecConfig { cmd: cmd(&["sh", "-c", "exit 9"]), ..Default::default() }).await.unwrap();
        let started = c.start_exec_detached(&x.id).await.unwrap();
        assert!(started.pid > 1);
        until("the detached exec to exit", async || c.inspect_exec(&x.id).await.unwrap().exit_code == Some(9)).await;
        // A missing program: 127, as a shell says.
        let x = c.create_exec(&id, &ExecConfig { cmd: cmd(&["/no/such"]), ..Default::default() }).await.unwrap();
        let (_, mut rx) = c.start_exec(&x.id).await.unwrap().split();
        let got = drain(&mut rx).await;
        assert!(got.error.is_some(), "{got:?}");
        let e = c
            .create_exec(&id, &ExecConfig { cmd: cmd(&["id"]), user: Some("nosuchuser".into()), ..Default::default() })
            .await;
        assert!(e.is_err());
        c.remove_container(&id, true).await.unwrap();
    });
}

/// stop (the signal, then KILL after the timeout), restart, pause, kill.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_stop_restart_pause_kill() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c
            .create_container(&sh("trap 'echo bye; exit 0' TERM; echo ready; while :; do sleep 0.1; done"))
            .await
            .unwrap()
            .id;
        c.start(&id).await.unwrap();
        // PID 1 ignores TERM without a handler: stop once the trap is set.
        until("the trap", async || logs(&c, &id, LogsQuery::default()).await.iter().any(|(_, t)| t == "ready\n")).await;
        c.stop(&id, Some(5)).await.unwrap();
        let i = c.inspect_container(&id).await.unwrap();
        assert_eq!((i.state.status, i.state.exit_code), (ContainerStatus::Exited, Some(0)));
        assert!(logs(&c, &id, LogsQuery::default()).await.iter().any(|(_, t)| t == "bye\n"));
        // A second stop is a no-op.
        c.stop(&id, Some(1)).await.unwrap();
        c.restart(&id, Some(1)).await.unwrap();
        assert_eq!(status(&c, &id).await, ContainerStatus::Running);
        c.pause(&id).await.unwrap();
        assert_eq!(status(&c, &id).await, ContainerStatus::Paused);
        let e = c.pause(&id).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Conflict));
        c.unpause(&id).await.unwrap();
        assert_eq!(status(&c, &id).await, ContainerStatus::Running);
        // rm of a running container needs force.
        assert_eq!(c.remove_container(&id, false).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        c.kill(&id, None).await.unwrap();
        let w = c.wait(&id, WaitCondition::NotRunning).await.unwrap();
        assert_eq!(w.status_code, 137);
        assert_eq!(c.kill(&id, None).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        // A process that ignores TERM is killed after the timeout.
        let stubborn = c.create_container(&sh("trap '' TERM; while :; do sleep 0.1; done")).await.unwrap().id;
        c.start(&stubborn).await.unwrap();
        let t = std::time::Instant::now();
        c.stop(&stubborn, Some(1)).await.unwrap();
        assert!(t.elapsed() >= Duration::from_secs(1));
        assert_eq!(c.inspect_container(&stubborn).await.unwrap().state.exit_code, Some(137));
        for x in [id, stubborn] {
            c.remove_container(&x, false).await.unwrap();
        }
    });
}

/// on-failure:N restarts N times; always restarts until a stop.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_restart_policies() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig { restart: RestartPolicy::parse("on-failure:2").unwrap(), ..sh("echo run; exit 1") };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        until("two restarts", async || {
            let s = c.inspect_container(&id).await.unwrap().state;
            s.status == ContainerStatus::Exited && s.restart_count == 2
        })
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let s = c.inspect_container(&id).await.unwrap().state;
        assert_eq!((s.status, s.restart_count, s.exit_code), (ContainerStatus::Exited, 2, Some(1)));
        assert_eq!(logs(&c, &id, LogsQuery::default()).await.len(), 3, "three runs, one log");
        // on-failure leaves a success alone.
        let ok = c
            .create_container(&ContainerConfig { restart: RestartPolicy::parse("on-failure").unwrap(), ..sh("exit 0") })
            .await
            .unwrap()
            .id;
        c.start(&ok).await.unwrap();
        c.wait(&ok, WaitCondition::NextExit).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(c.inspect_container(&ok).await.unwrap().state.restart_count, 0);
        // always: until stopped.
        let always = c
            .create_container(&ContainerConfig { restart: RestartPolicy::parse("always").unwrap(), ..sh("sleep 0.2") })
            .await
            .unwrap()
            .id;
        c.start(&always).await.unwrap();
        until("a restart", async || c.inspect_container(&always).await.unwrap().state.restart_count >= 2).await;
        c.stop(&always, Some(2)).await.unwrap();
        let n = c.inspect_container(&always).await.unwrap().state.restart_count;
        tokio::time::sleep(Duration::from_millis(800)).await;
        let s = c.inspect_container(&always).await.unwrap().state;
        assert_eq!((s.status, s.restart_count), (ContainerStatus::Exited, n), "stopped means stopped");
        for x in [id, ok, always] {
            c.remove_container(&x, true).await.unwrap();
        }
    });
}

/// --rm: gone once it has exited.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_auto_remove() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c.create_container(&ContainerConfig { auto_remove: true, ..sh("exit 2") }).await.unwrap().id;
        c.start(&id).await.unwrap();
        let w = c.wait(&id, WaitCondition::Removed).await.unwrap();
        assert_eq!(w.status_code, 2);
        assert_eq!(c.inspect_container(&id).await.unwrap_err().kind(), Some(ErrorKind::NoSuchContainer));
        // A restart policy and --rm don't go together.
        let both =
            ContainerConfig { auto_remove: true, restart: RestartPolicy::parse("always").unwrap(), ..sh("true") };
        assert_eq!(c.create_container(&both).await.unwrap_err().kind(), Some(ErrorKind::Invalid));
    });
}

/// Containers survive the daemon: a crash and a new daemon find them
/// again, still running (same init), still manageable; one that exited
/// while there was no daemon is reported with its status.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_containers_survive_the_daemon() {
    let mut d = daemon();
    let (keep, quit) = block_on(async {
        let c = d.client();
        let keep = c
            .create_container(&ContainerConfig {
                name: Some("keeper".into()),
                ..sh("echo up; while :; do sleep 0.1; done")
            })
            .await
            .unwrap()
            .id;
        c.start(&keep).await.unwrap();
        let quit = c.create_container(&sh("sleep 1; exit 7")).await.unwrap().id;
        let pid = c.inspect_container(&keep).await.unwrap().state.pid.unwrap();
        c.start(&quit).await.unwrap();
        ((keep, pid), quit)
    });
    d.crash();
    // While no daemon runs: `keep` runs on, `quit` ends.
    assert!(std::path::Path::new(&format!("/proc/{}", keep.1)).exists(), "the container died with the daemon");
    std::thread::sleep(Duration::from_millis(1500));
    d.restart();
    block_on(async {
        let c = d.client();
        let i = c.inspect_container("keeper").await.unwrap();
        assert_eq!((i.state.status, i.state.pid), (ContainerStatus::Running, Some(keep.1)), "taken over");
        let q = c.inspect_container(&quit).await.unwrap();
        assert_eq!((q.state.status, q.state.exit_code), (ContainerStatus::Exited, Some(7)), "{:?}", q.state);
        // Still manageable: logs, exec, stop.
        assert!(logs(&c, "keeper", LogsQuery::default()).await.iter().any(|(_, t)| t == "up\n"));
        let x = c
            .create_exec("keeper", &ExecConfig { cmd: vec!["echo".into(), "inside".into()], ..Default::default() })
            .await
            .unwrap();
        let (_, mut rx) = c.start_exec(&x.id).await.unwrap().split();
        assert_eq!(drain(&mut rx).await.stdout, "inside\n");
        c.stop("keeper", Some(1)).await.unwrap();
        assert_eq!(status(&c, "keeper").await, ContainerStatus::Exited);
        c.remove_container("keeper", false).await.unwrap();
        c.remove_container(&quit, false).await.unwrap();
    });
}

/// A run that never got its stdin closed: it exits once killed; stats and
/// events describe the run.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_stats_and_events() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let mut events = c.events(&Default::default()).await.unwrap();
        let cfg = ContainerConfig { memory: Some(64 << 20), pids_limit: Some(50), ..sh("while :; do sleep 0.1; done") };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        let s = c.stats_once(&id).await.unwrap();
        assert!(s.memory_current > 0 && s.memory_max == Some(64 << 20), "{s:?}");
        assert_eq!(s.pids_max, Some(50));
        assert!(s.pids_current >= 1 && s.cpus_online >= 1);
        assert!(s.network.iter().any(|n| n.name == "lo"), "{:?}", s.network);
        let mut stream = c.stats(&id).await.unwrap();
        let a = stream.next().await.unwrap().unwrap();
        let b = stream.next().await.unwrap().unwrap();
        assert!(b.read > a.read && b.cpu["usage_usec"] >= a.cpu["usage_usec"]);
        drop(stream);
        c.remove_container(&id, true).await.unwrap();
        let mut actions = Vec::new();
        while actions.last().map(String::as_str) != Some("destroy") {
            let e = tokio::time::timeout(Duration::from_secs(10), events.next()).await.unwrap().unwrap().unwrap();
            if e.id == id {
                actions.push(e.action);
            }
        }
        assert_eq!(actions, ["create", "start", "die", "destroy"]);
    });
}

/// --userns=remap: container root is host uid 1000000, the layers are
/// idmapped, and a non-root process can reopen its stdio.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_user_namespace_container() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        // As nobody: its pipes belong to nobody's host uid (1065534).
        let cfg = ContainerConfig {
            userns: UsernsMode::Remap,
            user: Some("nobody".into()),
            ..sh("cat /proc/self/uid_map; stat -c '%u' /bin/busybox; echo reopened >/dev/stderr")
        };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        assert_eq!(
            c.wait(&id, WaitCondition::NextExit).await.unwrap().status_code,
            0,
            "{:?}",
            logs(&c, &id, Default::default()).await
        );
        let l = logs(&c, &id, LogsQuery::default()).await;
        let text: String = l.iter().map(|(_, t)| t.as_str()).collect();
        assert!(text.split_whitespace().collect::<Vec<_>>().starts_with(&["0", "1000000", "65536", "0"]), "{text}");
        assert!(l.contains(&(LogStream::Stderr, "reopened\n".to_string())), "{l:?}");
        assert_eq!(c.inspect_container(&id).await.unwrap().uid_map.as_deref(), Some("0 1000000 65536"));
        c.remove_container(&id, false).await.unwrap();
    });
}

/// The kernel's OOM killer, reported in the exit.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_oom_kill_is_reported() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig {
            memory: Some(32 << 20),
            ..alpine(&["dd", "if=/dev/zero", "of=/dev/null", "bs=64M", "count=1"])
        };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        let w = c.wait(&id, WaitCondition::NextExit).await.unwrap();
        assert!(w.oom_killed && w.status_code == 137, "{w:?}");
        assert!(c.inspect_container(&id).await.unwrap().state.oom_killed);
        c.remove_container(&id, false).await.unwrap();
    });
}

/// Errors with the kinds a CLI acts on.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_errors_have_kinds() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let e =
            c.create_container(&ContainerConfig { image: "nope:1".into(), ..Default::default() }).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::NoSuchImage));
        let named = ContainerConfig { name: Some("dup".into()), ..sh("true") };
        c.create_container(&named).await.unwrap();
        assert_eq!(c.create_container(&named).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        let bad = ContainerConfig { cap_add: vec!["NOT_A_CAP".into()], ..sh("true") };
        assert_eq!(c.create_container(&bad).await.unwrap_err().kind(), Some(ErrorKind::Invalid));
        let missing = c.create_container(&alpine(&["/no/such/program"])).await.unwrap().id;
        let e = c.start(&missing).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::CommandNotFound), "{e}");
        let i = c.inspect_container(&missing).await.unwrap();
        assert_eq!(i.state.status, ContainerStatus::Created);
        assert!(i.state.error.is_some());
        assert_eq!(c.start("nope").await.unwrap_err().kind(), Some(ErrorKind::NoSuchContainer));
        c.remove_container("dup", false).await.unwrap();
        c.remove_container(&missing, false).await.unwrap();
    });
}

/// Images: listed, inspected, unpacked on first use (in a worker), kept
/// while a container uses them, collected after.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_images_and_garbage_collection() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let list = c.list_images().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].names, ["docker.io/library/alpine:latest"]);
        let i = c.inspect_image("alpine").await.unwrap();
        assert!(!i.unpacked, "imported, not unpacked yet");
        // `pull` with policy never: no registry, only the unpack.
        let mut events = c.pull("alpine", rustlet_spec::image::PullPolicy::Never).await.unwrap();
        let mut last = None;
        while let Some(e) = events.next().await {
            last = Some(e.unwrap());
        }
        assert!(matches!(last, Some(rustlet_spec::image::PullEvent::Ready { .. })), "{last:?}");
        assert!(c.inspect_image("alpine").await.unwrap().unpacked);
        let id = c.create_container(&sh("true")).await.unwrap().id;
        let e = c.remove_image("alpine", false).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Conflict), "{e}");
        // Forced: the name goes, the layers stay for the container.
        let r = c.remove_image("alpine", true).await.unwrap();
        assert_eq!(r.untagged, ["docker.io/library/alpine:latest"]);
        assert!(r.deleted.is_empty(), "{r:?}");
        c.start(&id).await.unwrap();
        assert_eq!(c.wait(&id, WaitCondition::NextExit).await.unwrap().status_code, 0);
        c.remove_container(&id, false).await.unwrap();
        // Its last container gone, the unnamed image is collected with it
        // (in the background: `rm` doesn't wait for a pull to finish).
        let store = rustlet_image::Store::open(&d.data).unwrap();
        until("the image's collection", async || store.snapshots().list().unwrap().is_empty()).await;
        let e = c.remove_image("alpine", false).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::NoSuchImage));
        assert!(c.list_images().await.unwrap().is_empty());
    });
}

/// The isolation report (Phase 6, the desktop app's inspector): namespaces
/// made, joined and shared (with the host and between containers), the
/// capability sets, seccomp, the user namespace's maps and the cgroup's
/// limits, read from a running container; a stopped one has none.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_isolation_report() {
    use rustlet_spec::isolation::{NamespaceMode, SeccompMode};
    use rustlet_spec::network::NetworkMode;
    let d = daemon();
    block_on(async {
        let c = d.client();
        let run = async |cfg: ContainerConfig| {
            let id = c.create_container(&cfg).await.unwrap().id;
            c.start(&id).await.unwrap();
            id
        };
        let web = run(ContainerConfig { name: Some("web".into()), ..sh("sleep 1000") }).await;
        let side = run(ContainerConfig {
            name: Some("side".into()),
            network: NetworkMode::Container("web".into()),
            cap_drop: vec!["ALL".into()],
            memory: Some(64 << 20),
            pids_limit: Some(50),
            cpus: Some(0.5),
            ..sh("sleep 1000")
        })
        .await;
        let remapped = run(ContainerConfig {
            name: Some("remapped".into()),
            userns: UsernsMode::Remap,
            network: NetworkMode::Host,
            read_only: true,
            security_opt: vec!["seccomp=unconfined".into()],
            ..sh("sleep 1000")
        })
        .await;

        let r = c.isolation("web").await.unwrap();
        assert_eq!(r.id, web);
        let ns = |r: &rustlet_spec::isolation::Isolation, kind: &str| {
            r.namespaces.iter().find(|n| n.kind == kind).unwrap_or_else(|| panic!("no {kind}")).clone()
        };
        assert_eq!(r.namespaces.len(), 8);
        for kind in ["mnt", "uts", "ipc", "pid", "cgroup"] {
            let n = ns(&r, kind);
            assert!(n.mode == NamespaceMode::New && !n.shared_with_host && n.inode != 0, "{n:?}");
        }
        let user = ns(&r, "user");
        assert!(user.mode == NamespaceMode::Host && user.shared_with_host, "{user:?}");
        assert!(r.uid_map.is_empty(), "no user namespace of its own: {:?}", r.uid_map);
        let net = ns(&r, "net");
        assert_eq!(net.mode, NamespaceMode::Join, "a pinned namespace: {net:?}");
        assert_eq!(net.shared_with, ["side"]);
        assert!(!net.shared_with_host);
        assert!(r.capabilities.effective.contains(&"CAP_CHOWN".to_string()), "{:?}", r.capabilities);
        assert!(!r.capabilities.bounding.contains(&"CAP_SYS_ADMIN".to_string()));
        assert!(r.capabilities.known.len() >= 41);
        assert_eq!(r.seccomp.mode, SeccompMode::Filter);
        assert!(r.seccomp.filters >= 1);
        let profile = r.seccomp.profile.clone().expect("the default profile");
        assert_eq!(profile.default_action, "SCMP_ACT_ERRNO");
        assert!(profile.allowed.iter().any(|s| s == "read"), "{profile:?}");
        assert!(!profile.allowed.iter().any(|s| s == "mount"), "mount needs CAP_SYS_ADMIN");
        assert!(r.filesystem.masked_paths.iter().any(|p| p == "/proc/kcore"), "{:?}", r.filesystem);
        assert!(!r.filesystem.read_only);
        assert!(r.filesystem.mounts.iter().any(|m| m.destination == "/proc" && m.kind == "proc"));
        let null = r.devices.iter().find(|d| (d.kind.as_str(), d.major, d.minor) == ("c", Some(1), Some(3)));
        assert!(null.is_some_and(|d| d.allow && d.access == "rwm"), "/dev/null: {:?}", r.devices);
        assert_eq!((r.credentials.uid, r.credentials.host_uid), (0, 0));
        // Not the daemon's -500 (the test daemon has it, as the service).
        assert_eq!(r.oom_score_adj, 0);
        assert!(r.cgroup.path.ends_with(&web), "{:?}", r.cgroup);
        assert_eq!(r.cgroup.memory_max, None);
        assert!(r.cgroup.pids_current >= 1);

        let s = c.isolation("side").await.unwrap();
        assert_eq!(ns(&s, "net").shared_with, ["web"]);
        assert_eq!(ns(&s, "net").inode, net.inode);
        assert_ne!(ns(&s, "pid").inode, ns(&r, "pid").inode);
        assert!(s.capabilities.effective.is_empty() && s.capabilities.bounding.is_empty(), "{:?}", s.capabilities);
        assert_eq!(s.cgroup.memory_max, Some(64 << 20));
        assert_eq!(s.cgroup.pids_max, Some(50));
        assert_eq!((s.cgroup.cpu_quota, s.cgroup.cpu_period), (Some(50_000), 100_000));

        let m = c.isolation(&remapped).await.unwrap();
        let user = ns(&m, "user");
        assert!(user.mode == NamespaceMode::New && !user.shared_with_host, "{user:?}");
        assert_eq!(m.uid_map.len(), 1);
        assert_eq!((m.uid_map[0].container_id, m.uid_map[0].host_id, m.uid_map[0].size), (0, 1_000_000, 65536));
        assert_eq!((m.credentials.uid, m.credentials.host_uid), (0, 1_000_000));
        assert!(ns(&m, "net").shared_with_host && ns(&m, "net").mode == NamespaceMode::Host);
        assert_eq!(m.seccomp.mode, SeccompMode::Disabled);
        assert!(m.seccomp.profile.is_none());
        assert!(m.filesystem.read_only);

        // An entrypoint that drops to another user (as `su-exec` and `gosu`
        // do): the ids are the process's own, inside and out, not the user
        // `config.json` started it as.
        let dropped = run(ContainerConfig {
            name: Some("dropped".into()),
            userns: UsernsMode::Remap,
            ..sh("exec su -s /bin/sh nobody -c 'exec sleep 1000'")
        })
        .await;
        let mut cred = c.isolation(&dropped).await.unwrap().credentials;
        for _ in 0..50 {
            if cred.host_uid != 1_000_000 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            cred = c.isolation(&dropped).await.unwrap().credentials;
        }
        assert_eq!((cred.uid, cred.gid), (65534, 65534), "{cred:?}");
        assert_eq!((cred.host_uid, cred.host_gid), (1_065_534, 1_065_534), "{cred:?}");
        assert!(!cred.additional_gids.contains(&0), "root's groups are gone: {cred:?}");

        // Not running: nothing to read.
        c.kill(&side, None).await.unwrap();
        c.wait(&side, WaitCondition::NotRunning).await.unwrap();
        assert_eq!(c.isolation(&side).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        assert_eq!(c.isolation("nope").await.unwrap_err().kind(), Some(ErrorKind::NoSuchContainer));

        // The image's layers, with their sizes and snapshots.
        let image = c.inspect_image("alpine").await.unwrap();
        assert_eq!(image.layer_details.len(), image.summary.layers);
        let layer = &image.layer_details[0];
        assert!(layer.digest.starts_with("sha256:") && layer.size > 0 && layer.unpacked, "{layer:?}");
        assert_eq!(layer.chain_id, image.chain_ids[0]);
        assert_eq!(layer.diff_id, image.diff_ids[0]);

        for id in [&web, &side, &remapped, &dropped] {
            c.remove_container(id, true).await.unwrap();
        }
    });
}

/// A terminal that goes away hangs up its exec (Phase 6: a closed terminal
/// tab in the desktop app): the process gets SIGHUP and the session ends
/// with its exit, 128 + 1. In an attach session a hangup is a detach.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dm_exec_hangup() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig { tty: true, open_stdin: true, ..sh("sleep 1000") };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        let shell = ExecConfig { cmd: vec!["sh".into()], tty: true, stdin: true, ..Default::default() };
        let exec = c.create_exec(&id, &shell).await.unwrap().id;
        let (mut tx, mut rx) = c.start_exec(&exec).await.unwrap().split();
        tx.send_stdin(b"echo rea''dy\n").await.unwrap();
        let mut seen = String::new();
        while !seen.contains("ready") {
            match tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.expect("no output") {
                Ok(Some(SessionEvent::Stdout(b))) => seen.push_str(&String::from_utf8_lossy(&b)),
                other => panic!("{other:?} before the shell answered: {seen:?}"),
            }
        }
        tx.hangup().await.unwrap();
        let got = drain(&mut rx).await;
        assert_eq!(got.exit, Some(129), "{got:?}");
        assert_eq!(c.inspect_exec(&exec).await.unwrap().exit_code, Some(129));

        // As the desktop app closes a tab: hang up and go at once. The
        // daemon still hears the exit, and records it, through the output
        // that nobody reads any more (the trap's).
        let script = "trap 'echo bye; exit 3' HUP; echo rea''dy; while :; do sleep 0.1; done";
        let trapping = ExecConfig { cmd: vec!["sh".into(), "-c".into(), script.into()], ..shell.clone() };
        let exec = c.create_exec(&id, &trapping).await.unwrap().id;
        let (mut tx, mut rx) = c.start_exec(&exec).await.unwrap().split();
        let mut seen = String::new();
        while !seen.contains("ready") {
            match tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.expect("no output") {
                Ok(Some(SessionEvent::Stdout(b))) => seen.push_str(&String::from_utf8_lossy(&b)),
                other => panic!("{other:?} before the trap was set: {seen:?}"),
            }
        }
        tx.hangup().await.unwrap();
        tx.close().await.unwrap();
        drop(rx);
        let mut code = None;
        for _ in 0..50 {
            code = c.inspect_exec(&exec).await.unwrap().exit_code;
            if code.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(code, Some(3), "the exit of an exec whose client hung up and left");

        let (mut tx, rx) = c.attach(&id, true).await.unwrap().split();
        tx.hangup().await.unwrap();
        tx.close().await.unwrap();
        drop(rx);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(status(&c, &id).await, ContainerStatus::Running);
        c.remove_container(&id, true).await.unwrap();
    });
}
