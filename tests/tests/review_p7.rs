//! Phase 7's independent review: what it found in the daemon, each a test
//! that failed before its fix. Run with `cargo xtask itest -- review_`.

use std::time::Duration;

use futures::StreamExt;
use rustlet_client::{Client, RequestBody, SessionEvent};
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_spec::build::{BuildEvent, BuildOptions, CommitRequest};
use rustlet_spec::container::ContainerConfig;
use rustlet_spec::event::{EventKind, EventsQuery};

const BUILD_LABEL: &str = "io.rustlet.build";

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

fn context(files: &[(&str, &[u8], u32)]) -> RequestBody {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data, mode) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(*mode);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    RequestBody::from_bytes(b.into_inner().unwrap())
}

fn upload_closed(message: &str) -> bool {
    message
        == "connection to rustletd: the daemon closed the connection while the request's body was still being sent (it refused or failed the request: see rustletd's log)"
}

fn tagged(tag: &str) -> BuildOptions {
    BuildOptions { tags: vec![tag.into()], ..Default::default() }
}

/// Builds; the image's id, the number of cached steps, or the error.
async fn build_with(c: &Client, options: BuildOptions, body: RequestBody) -> Result<(String, usize), String> {
    let mut stream = c.build(&options, body).await.map_err(|e| e.to_string())?;
    let mut cached = 0;
    while let Some(item) = tokio::time::timeout(Duration::from_secs(120), stream.next()).await.expect("the build hung")
    {
        match item {
            Ok(BuildEvent::Done { id, .. }) => return Ok((id, cached)),
            Ok(BuildEvent::Cached { .. }) => cached += 1,
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("no done event".into())
}

async fn build(c: &Client, options: BuildOptions, files: &[(&str, &[u8], u32)]) -> (String, usize) {
    build_with(c, options, context(files)).await.unwrap()
}

async fn run(c: &Client, image: &str, cmd: &[&str]) -> (String, i32) {
    let config =
        ContainerConfig { image: image.into(), cmd: cmd.iter().map(|s| s.to_string()).collect(), ..Default::default() };
    let id = c.create_container(&config).await.unwrap().id;
    let mut session = c.attach(&id, false).await.unwrap();
    c.start(&id).await.unwrap();
    let mut out = String::new();
    let mut code = -1;
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(30), session.recv()).await.expect("the run hung");
        match ev.unwrap() {
            Some(SessionEvent::Stdout(b) | SessionEvent::Stderr(b)) => out.push_str(&String::from_utf8_lossy(&b)),
            Some(SessionEvent::Exit { code: c, .. }) => {
                code = c;
                break;
            }
            Some(SessionEvent::Error { message, .. }) => panic!("{message}"),
            None => break,
        }
    }
    c.remove_container(&id, true).await.unwrap();
    (out, code)
}

/// `COPY --from` without `--chown` keeps the owners the files have in the
/// stage they come from: Docker's classic builder (`preserveOwnership` in
/// `dispatchCopy`) and BuildKit both do. Only the context's files become
/// root's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_copy_from_a_stage_keeps_its_owners() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = br#"
FROM alpine AS b
RUN mkdir /data && echo x > /data/f && chown -R 1234:2345 /data
FROM alpine
COPY --from=b /data /data
COPY --from=b --chown=7:8 /data/f /g
"#;
        build(&c, tagged("owners"), &[("Containerfile", file, 0o644)]).await;
        let (out, code) = run(&c, "owners", &["stat", "-c", "%u:%g", "/data/f", "/g"]).await;
        assert_eq!((out.as_str(), code), ("1234:2345\n7:8\n", 0));
    });
}

/// A client that hangs up stops its build even while a `RUN` prints
/// nothing: the step's container goes (architecture §2.9: "A client that
/// hangs up stops it (its step container killed)").
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_a_client_that_hangs_up_stops_a_quiet_run() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = b"FROM alpine\nRUN sleep 60\n";
        let mut stream = c.build(&tagged("quiet"), context(&[("Containerfile", file, 0o644)])).await.unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(60), stream.next()).await.expect("no container event") {
                Some(Ok(BuildEvent::Container { .. })) => break,
                Some(Ok(_)) => {}
                other => panic!("{other:?}"),
            }
        }
        // The step runs; the client goes.
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(stream);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let left = c.list_containers(true).await.unwrap();
            if !left.iter().any(|s| s.labels.contains_key(BUILD_LABEL)) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the step's container is still there 15 s after its client went away"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
}

/// The cache tells `ENV A="b C=d"` (one variable) from `ENV A=b C=d` (two):
/// a `RUN` after one isn't the other's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_the_cache_tells_env_values_apart() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let one = b"FROM alpine\nENV A=b C=d\nRUN echo \"$A\" > /x\nCMD [\"cat\", \"/x\"]\n";
        build(&c, tagged("env1"), &[("Containerfile", one, 0o644)]).await;
        assert_eq!(run(&c, "env1", &[]).await.0, "b\n");
        let two = b"FROM alpine\nENV A=\"b C=d\"\nRUN echo \"$A\" > /x\nCMD [\"cat\", \"/x\"]\n";
        let (_, cached) = build(&c, tagged("env2"), &[("Containerfile", two, 0o644)]).await;
        assert_eq!(run(&c, "env2", &[]).await.0, "b C=d\n", "{cached} cached steps");
    });
}

/// What the client adds to the context only for the daemon stays out of
/// `COPY . …`: a Containerfile from outside the context
/// (`.rustlet-containerfile`), and a Containerfile and ignore file the
/// ignore file excludes (Docker's CLI hides the first behind a random name
/// it adds to `.dockerignore`; its daemon removes the others after reading
/// the Dockerfile: `removeDockerfile` in builder/remotecontext/detect.go).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_copy_leaves_out_what_only_the_daemon_needs() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let dir = tempfile::tempdir().unwrap();
        let context_dir = dir.path().join("context");
        std::fs::create_dir(&context_dir).unwrap();
        std::fs::write(context_dir.join("app.txt"), "app\n").unwrap();
        let file = "FROM alpine\nCOPY . /app/\nCMD [\"ls\", \"-A\", \"/app\"]\n";
        // Outside the context.
        let outside = dir.path().join("Containerfile");
        std::fs::write(&outside, file).unwrap();
        let mut tar = Vec::new();
        let packed = rustlet_build::context::pack(&context_dir, &outside, &mut tar).unwrap();
        let options = BuildOptions { dockerfile: Some(packed.dockerfile), ..tagged("outside") };
        build_with(&c, options, RequestBody::from_bytes(tar)).await.unwrap();
        assert_eq!(run(&c, "outside", &[]).await.0, "app.txt\n", "-f from outside the context");
        // Inside, both excluded by the ignore file.
        std::fs::write(context_dir.join("Containerfile"), file).unwrap();
        std::fs::write(context_dir.join(".dockerignore"), "Containerfile\n.dockerignore\n").unwrap();
        let mut tar = Vec::new();
        let packed = rustlet_build::context::pack(&context_dir, &context_dir.join("Containerfile"), &mut tar).unwrap();
        let options = BuildOptions { dockerfile: Some(packed.dockerfile), ..tagged("ignored") };
        build_with(&c, options, RequestBody::from_bytes(tar)).await.unwrap();
        assert_eq!(run(&c, "ignored", &[]).await.0, "app.txt\n", "the ignore file excludes both");
    });
}

/// A `user.overlay.opaque` attribute a container sets is the container's
/// own data, not overlay's mark: the daemon's overlays keep their marks in
/// `trusted.overlay.*` (no `userxattr`), and overlay showed the container
/// the directory's lower files all along. So the commit keeps them.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_a_user_overlay_attribute_is_the_containers_data() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let config =
            ContainerConfig { image: "alpine".into(), cmd: vec!["sleep".into(), "30".into()], ..Default::default() };
        let id = c.create_container(&config).await.unwrap().id;
        c.start(&id).await.unwrap();
        // As a process in the container would: through its overlay.
        let etc = d.data.join("containers").join(&id).join("rootfs/etc");
        rustlet_sys::xattr::lset(&etc, "user.overlay.opaque", b"y").unwrap();
        let request = CommitRequest { container: id.clone(), reference: Some("marked".into()), ..Default::default() };
        c.commit(&request).await.unwrap();
        c.remove_container(&id, true).await.unwrap();
        let (out, code) = run(&c, "marked", &["cat", "/etc/alpine-release"]).await;
        assert_eq!(code, 0, "the image's /etc lost the layers below: {out}");
    });
}

/// The images a build makes for its `RUN` steps' containers are the build's
/// own: collecting them afterwards isn't news. No image `delete` event
/// (Event.ts: "once the image itself is gone") for blobs nobody listed.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_a_builds_intermediate_images_are_collected_quietly() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let mut events = c.events(&EventsQuery::default()).await.unwrap();
        // An ENV before the RUN: the RUN's container runs from an image
        // that no name, cache entry or other image is.
        let file = b"FROM alpine\nENV A=1\nRUN true\n";
        build(&c, tagged("quiet-intermediates"), &[("Containerfile", file, 0o644)]).await;
        let mut announced = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(Ok(e)) = events.next().await {
                if e.kind == EventKind::Image && e.action == "delete" {
                    announced.push(e.id);
                }
            }
        })
        .await;
        assert!(announced.is_empty(), "images never listed were announced as deleted: {announced:?}");
    });
}

/// A daemon that dies in the middle of a `RUN` leaves the build's context
/// and its step's container; the next one removes both at startup
/// (architecture §2.9: "A daemon that dies mid-build leaves leftovers the
/// next one removes"; `remove_build_leftovers` had no test).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_a_daemon_that_died_mid_build_leaves_nothing() {
    let mut d = daemon();
    let builds = d.data.join("builds");
    block_on(async {
        let c = d.client();
        let file = b"FROM alpine\nCOPY marker /marker\nRUN sleep 600\n";
        let mut stream = c
            .build(&tagged("interrupted"), context(&[("Containerfile", file, 0o644), ("marker", b"x", 0o644)]))
            .await
            .unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(60), stream.next()).await.expect("no container event") {
                Some(Ok(BuildEvent::Container { .. })) => break,
                Some(Ok(_)) => {}
                other => panic!("{other:?}"),
            }
        }
        // The step runs, its context is on disk, and the daemon dies.
        assert_eq!(std::fs::read_dir(&builds).unwrap().count(), 1);
        assert_eq!(c.list_containers(true).await.unwrap().len(), 1);
        d.crash();
        drop(stream);
        d.restart();
        let c = d.client();
        let left: Vec<String> = c.list_containers(true).await.unwrap().into_iter().map(|c| c.name).collect();
        assert!(left.is_empty(), "the dead build's step container is still there: {left:?}");
        let dirs: Vec<_> = std::fs::read_dir(&builds).unwrap().flatten().map(|e| e.path()).collect();
        assert!(dirs.is_empty(), "the dead build's directory is still there: {dirs:?}");
        let containers: Vec<_> = std::fs::read_dir(d.data.join("containers"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(containers.is_empty(), "container directories left: {containers:?}");
    });
}

/// During a large upload, an early refusal or invalid archive yields its
/// daemon reason when received, or the documented closed-upload diagnostic
/// if the connection ends first. Never accept the upload or expose only a
/// generic transport error. Exercise the real daemon repeatedly.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_upload_failures_are_reported_while_sending() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let mut context = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(8 << 20);
        h.set_mode(0o644);
        h.set_cksum();
        context.append_data(&mut h, "big", &vec![7u8; 8 << 20][..]).unwrap();
        let context = context.into_inner().unwrap();
        let mut lost = Vec::new();
        for i in 0..15 {
            // Refused before the body is read.
            let options = BuildOptions { tags: vec!["Bad Name".into()], ..Default::default() };
            let message = match c.build(&options, RequestBody::from_bytes(context.clone())).await {
                Ok(_) => "accepted".to_owned(),
                Err(e) => e.to_string(),
            };
            if !message.contains("Bad Name") && !upload_closed(&message) {
                lost.push(format!("refusal {i}: {message}"));
            }
            // Fails while its body is read: not an archive at all.
            let garbage = RequestBody::from_bytes(vec![7u8; 8 << 20]);
            let message = match c.build(&tagged("garbage"), garbage).await {
                Ok(mut stream) => match stream.next().await {
                    Some(Err(e)) => e.to_string(),
                    other => format!("{other:?}"),
                },
                Err(e) => e.to_string(),
            };
            if !message.contains("build context") && !upload_closed(&message) {
                lost.push(format!("garbage {i}: {message}"));
            }
            // And an archive to load that isn't one.
            let message = match c.load_images(RequestBody::from_bytes(vec![7u8; 8 << 20])).await {
                Ok(mut stream) => loop {
                    match stream.next().await {
                        Some(Err(e)) => break e.to_string(),
                        Some(Ok(_)) => {}
                        None => break "no error".to_owned(),
                    }
                },
                Err(e) => e.to_string(),
            };
            if !message.contains("archive") && !upload_closed(&message) {
                lost.push(format!("load {i}: {message}"));
            }
        }
        assert!(
            lost.is_empty(),
            "upload failures lacked useful diagnostics {} times:\n{}",
            lost.len(),
            lost.join("\n")
        );
    });
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_stage_args_are_inherited() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file =
            b"FROM alpine AS base\nARG NAME=joe\nFROM base\nRUN echo \"$NAME\" > /name\nCMD [\"cat\",\"/name\"]\n";
        build(&c, tagged("inherited-args"), &[("Containerfile", file, 0o644)]).await;
        let actual = run(&c, "inherited-args", &[]).await;
        assert_eq!(actual, ("joe\n".to_owned(), 0));
    });
}
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_workdir_creates_its_directory() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = b"FROM alpine AS base\nWORKDIR /newdir\nFROM scratch\nCOPY --from=base /newdir /copied\n";
        let actual = build_with(&c, tagged("workdir-create"), context(&[("Containerfile", file, 0o644)])).await;
        assert!(actual.is_ok(), "WORKDIR source missing: {actual:?}");
    });
}
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_nested_expansion_keeps_daemon_alive() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = format!("FROM scratch\nENV VALUE={}x{}\n", "${A:-".repeat(20000), "}".repeat(20000));
        let actual = build_with(&c, tagged("nested"), context(&[("Containerfile", file.as_bytes(), 0o644)])).await;
        assert!(actual.is_err(), "excessively nested expansion must be refused");
        let alive = c.version().await;
        assert!(alive.is_ok(), "daemon died after build {actual:?}; version {alive:?}; log {}", d.log());
    });
}
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_restart_cleans_up_inflight_health_process() {
    let mut d = daemon();
    block_on(async {
        let c = d.client();
        let config = ContainerConfig {
            image: "alpine".into(),
            cmd: vec!["sleep".into(), "600".into()],
            healthcheck: Some(rustlet_spec::container::HealthConfig {
                test: vec!["CMD".into(), "sleep".into(), "500".into()],
                interval: Some(1_000_000_000),
                timeout: Some(3_000_000_000),
                ..Default::default()
            }),
            ..Default::default()
        };
        let id = c.create_container(&config).await.unwrap().id;
        c.start(&id).await.unwrap();
        let procs = format!("/sys/fs/cgroup{}/containers/{id}/cgroup.procs", d.cgroup_parent);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let original = loop {
            let found = std::fs::read_to_string(&procs).unwrap().lines().find_map(|pid| {
                let command = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                (command == b"sleep\x00500\x00").then(|| pid.to_owned())
            });
            if let Some(pid) = found {
                break pid;
            }
            assert!(std::time::Instant::now() < deadline, "no health process");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        d.restart();
        tokio::time::sleep(Duration::from_secs(6)).await;
        let remained = std::fs::read(format!("/proc/{original}/cmdline")).unwrap_or_default() == b"sleep\x00500\x00";
        assert!(!remained, "health process {original} survived daemon restart and twice its timeout");
    });
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_workdir_owns_new_directories_as_the_selected_user_and_caches() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = b"FROM alpine\nUSER 1234:2345\nWORKDIR /newdir/sub\nUSER 0\nCMD [\"stat\",\"-c\",\"%u:%g\",\"/newdir\",\"/newdir/sub\"]\n";
        let (first, _) = build(&c, tagged("workdir-owner"), &[("Containerfile", file, 0o644)]).await;
        let (second, cached) = build(&c, tagged("workdir-owner"), &[("Containerfile", file, 0o644)]).await;
        assert_eq!(first, second);
        assert_eq!(cached, 1);
        assert_eq!(run(&c, "workdir-owner", &[]).await, ("1234:2345\n1234:2345\n".into(), 0));
    });
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn review_explicit_empty_command_and_unset_environment_survive_run_and_commit() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = br#"FROM alpine
ENV A=image B=image
ENTRYPOINT ["/bin/sh", "-c", "printf '%s:%s:%s' \"${A-unset}\" \"$B\" \"$#\"", "--"]
CMD ["argument"]
"#;
        build(&c, tagged("env-base"), &[("Containerfile", file, 0o644)]).await;
        let id = c
            .create_container(&ContainerConfig {
                image: "env-base".into(),
                clear_cmd: true,
                unset_env: vec!["A".into()],
                env: vec!["B=override".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .id;
        let mut attached = c.attach(&id, false).await.unwrap();
        c.start(&id).await.unwrap();
        let mut output = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(30), attached.recv()).await.unwrap().unwrap();
            match event {
                Some(SessionEvent::Stdout(bytes)) => output.extend_from_slice(&bytes),
                Some(SessionEvent::Exit { code, .. }) => {
                    assert_eq!(code, 0);
                    break;
                }
                Some(SessionEvent::Error { message, .. }) => panic!("{message}"),
                None => panic!("no exit"),
                _ => {}
            }
        }
        assert_eq!(output, b"unset:override:0");
        c.commit(&CommitRequest {
            container: id.clone(),
            reference: Some("env-committed".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(run(&c, "env-committed", &[]).await, ("unset:override:0".into(), 0));
        c.remove_container(&id, true).await.unwrap();
    });
}
