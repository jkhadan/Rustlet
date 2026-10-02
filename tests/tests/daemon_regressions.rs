//! Regression tests for the Phase 4 review findings: the daemon, its
//! shims and the CLI's sessions. Each test names the failure it pins down.
//! Run with `cargo xtask itest -- rr_`.
//!
//! A binary of their own: their daemons mount overlays on the host, which
//! the runtime tests in `review_regressions.rs`, running alongside, would
//! take for changes to the host's mount table.

use std::time::Duration;

use rustlet_client::SessionEvent;
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_spec::container::{ContainerConfig, ContainerStatus, WaitCondition};
use tokio::io::AsyncWriteExt;

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

fn sh(script: &str) -> ContainerConfig {
    ContainerConfig { image: "alpine".into(), cmd: vec!["sh".into(), "-c".into(), script.into()], ..Default::default() }
}

async fn eventually(what: &str, mut f: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !f().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Every shim has exited (they leave once their container is gone).
fn assert_no_shims_left(d: &TestDaemon) {
    let procs = format!("/sys/fs/cgroup{}/shims/cgroup.procs", d.cgroup_parent);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = std::fs::read_to_string(&procs).unwrap_or_default();
        if left.trim().is_empty() {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "shims outlived their containers: {left}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A client that hung up in the middle of a request (Ctrl-C on `rustlet
/// start`) cancelled the daemon's side of it at whatever `.await` it had
/// reached: hyper drops the handler of a connection that closes. A start
/// cut off after the shim was spawned left a container nobody watched,
/// in a shim nobody would ever shut down.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_a_start_outlives_the_client_that_asked_for_it() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        // Unpacked beforehand, so that the start spends its time on the
        // shim and `create`.
        let warm = c.create_container(&sh("true")).await.unwrap().id;
        c.start(&warm).await.unwrap();
        c.wait(&warm, WaitCondition::NotRunning).await.unwrap();
        c.remove_container(&warm, false).await.unwrap();

        let id = c.create_container(&sh("sleep 1; exit 4")).await.unwrap().id;
        let mut s = tokio::net::UnixStream::connect(&d.socket).await.unwrap();
        let path = rustlet_spec::routes::container_action(&id, rustlet_spec::routes::action::START);
        let request = format!("POST {path} HTTP/1.1\r\nHost: rustlet\r\nContent-Length: 0\r\n\r\n");
        s.write_all(request.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(s);
        eventually("the start to finish", async || {
            c.inspect_container(&id).await.unwrap().state.status != ContainerStatus::Created
        })
        .await;
        let w = c.wait(&id, WaitCondition::NotRunning).await.unwrap();
        assert_eq!(w.status_code, 4, "{w:?}");
        assert_eq!(c.inspect_container(&id).await.unwrap().state.status, ContainerStatus::Exited);
        c.remove_container(&id, false).await.unwrap();
    });
    assert_no_shims_left(&d);
}

/// A daemon that died between the shim's `Start` and recording the
/// container as running (a crash, or SIGTERM in the middle of `start`)
/// left a running container that the next daemon took for `created`:
/// it detached the overlay under it and never watched it. The next
/// daemon now asks a container's shim whatever the database says.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_a_start_the_database_missed_is_taken_over() {
    let mut d = daemon();
    let (id, pid) = block_on(async {
        let c = d.client();
        let id = c.create_container(&sh("while :; do sleep 0.1; done")).await.unwrap().id;
        c.start(&id).await.unwrap();
        let pid = c.inspect_container(&id).await.unwrap().state.pid.unwrap();
        (id, pid)
    });
    d.crash();
    // As if the crash had come before the start was recorded.
    let db = rusqlite::Connection::open(d.data.join("state.db")).unwrap();
    let sql = "UPDATE containers SET state = json_set(state, '$.state.status', 'created', '$.state.pid', NULL) \
               WHERE id = ?1";
    assert_eq!(db.execute(sql, [&id]).unwrap(), 1);
    drop(db);
    d.restart();
    block_on(async {
        let c = d.client();
        let i = c.inspect_container(&id).await.unwrap();
        assert_eq!((i.state.status, i.state.pid), (ContainerStatus::Running, Some(pid)), "{:?}", i.state);
        assert!(i.rootfs.is_some());
        c.stop(&id, Some(1)).await.unwrap();
        assert_eq!(c.inspect_container(&id).await.unwrap().state.status, ContainerStatus::Exited);
        c.remove_container(&id, false).await.unwrap();
    });
    assert_no_shims_left(&d);
}

/// An attach waiting for a start that failed stayed registered after its
/// client had gone. The next start connected it anyway: with
/// `stdin_once`, the dead attach claimed the container's input and
/// closed it at once, and the live client's input never arrived.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_an_attach_left_by_a_failed_start_keeps_off_stdin() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig { open_stdin: true, stdin_once: true, ..sh("cat") };
        let id = c.create_container(&cfg).await.unwrap().id;
        // The first start fails: its rootfs mount point is missing.
        let rootfs = d.data.join("containers").join(&id).join("rootfs");
        let hidden = rootfs.with_file_name("rootfs.hidden");
        std::fs::rename(&rootfs, &hidden).unwrap();
        let first = c.attach(&id, true).await.unwrap();
        assert!(c.start(&id).await.is_err());
        // As `rustlet run` does when the start fails.
        drop(first);
        std::fs::rename(&hidden, &rootfs).unwrap();
        let (mut tx, mut rx) = c.attach(&id, true).await.unwrap().split();
        c.start(&id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = tx.send_stdin(b"hello\n").await;
        let _ = tx.stdin_eof().await;
        let mut out = String::new();
        let code = loop {
            let ev = tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.expect("no exit");
            match ev.unwrap() {
                Some(SessionEvent::Stdout(b)) => out.push_str(&String::from_utf8_lossy(&b)),
                Some(SessionEvent::Exit { code, .. }) => break Some(code),
                Some(other) => panic!("{other:?}"),
                None => break None,
            }
        };
        assert_eq!((out.as_str(), code), ("hello\n", Some(0)));
        c.remove_container(&id, false).await.unwrap();
    });
}

/// A detached exec that asked for input (`exec -d -i … cat`, or any API
/// client) kept its stdin open for good: nothing sends it input, and
/// nothing ended it. Its input now ends at once.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_a_detached_exec_gets_the_end_of_its_input() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c.create_container(&sh("while :; do sleep 0.1; done")).await.unwrap().id;
        c.start(&id).await.unwrap();
        let config = rustlet_spec::exec::ExecConfig { cmd: vec!["cat".into()], stdin: true, ..Default::default() };
        let x = c.create_exec(&id, &config).await.unwrap();
        c.start_exec_detached(&x.id).await.unwrap();
        eventually("cat to see the end of its input", async || {
            c.inspect_exec(&x.id).await.unwrap().exit_code == Some(0)
        })
        .await;
        c.remove_container(&id, true).await.unwrap();
    });
}

/// `run --rm` waits for the removal (`wait?condition=removed`). A removal
/// that failed left the container `dead` and the wait unanswered forever;
/// it now ends with the removal's error, as in Docker.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_a_failed_auto_removal_ends_the_wait() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c
            .create_container(&ContainerConfig { auto_remove: true, ..sh("touch /pinned; sleep 1") })
            .await
            .unwrap()
            .id;
        c.start(&id).await.unwrap();
        let pinned = d.data.join("containers").join(&id).join("upper/pinned");
        eventually("/pinned", async || pinned.exists()).await;
        let chattr = |flag: &str| {
            let ok = std::process::Command::new("chattr").arg(flag).arg(&pinned).status().unwrap().success();
            assert!(ok, "chattr {flag}");
        };
        // Immutable: the removal can't unlink it.
        chattr("+i");
        let waited = tokio::time::timeout(Duration::from_secs(30), c.wait(&id, WaitCondition::Removed)).await;
        chattr("-i");
        let w = waited.expect("the wait for the removal never ended").unwrap();
        assert!(w.error.is_some(), "{w:?}");
        assert_eq!(c.inspect_container(&id).await.unwrap().state.status, ContainerStatus::Dead);
        c.remove_container(&id, true).await.unwrap();
    });
}
