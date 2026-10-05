//! Phase 7: images Rustlets makes. Builds (`bd_`), commits (`cm_`), and
//! save/load (`sl_`), through the daemon. Run with `cargo xtask itest --
//! bd_` (or `cm_`, `sl_`).

use std::io::Write;
use std::time::Duration;

use futures::StreamExt;
use rustlet_client::{Client, RequestBody, SessionEvent};
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_itests::images::LayerBuilder;
use rustlet_spec::build::{BuildEvent, BuildOptions, CommitRequest};
use rustlet_spec::container::{ContainerConfig, HealthStatus, UsernsMode};
use rustlet_spec::image::LoadEvent;

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

/// A build context: files (with their modes), as `context::pack` would
/// send them.
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

/// A build's events, and how it ended: its image's id and names, or the
/// error.
struct Built {
    events: Vec<BuildEvent>,
    result: Result<(String, Vec<String>), String>,
}

impl Built {
    fn id(&self) -> &str {
        match &self.result {
            Ok((id, _)) => id,
            Err(e) => panic!("the build failed: {e}\n{:#?}", self.events),
        }
    }

    fn cached(&self) -> usize {
        self.events.iter().filter(|e| matches!(e, BuildEvent::Cached { .. })).count()
    }

    fn containers(&self) -> usize {
        self.events.iter().filter(|e| matches!(e, BuildEvent::Container { .. })).count()
    }

    fn output(&self) -> String {
        self.events
            .iter()
            .filter_map(|e| match e {
                BuildEvent::Output { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }
}

async fn build(c: &Client, options: BuildOptions, files: &[(&str, &[u8], u32)]) -> Built {
    let mut stream = c.build(&options, context(files)).await.unwrap();
    let mut events = Vec::new();
    let mut result = Err("no done event".to_owned());
    while let Some(item) = tokio::time::timeout(Duration::from_secs(120), stream.next()).await.expect("the build hung")
    {
        match item {
            Ok(BuildEvent::Done { id, names }) => result = Ok((id, names)),
            Ok(e) => events.push(e),
            Err(e) => {
                result = Err(e.to_string());
                break;
            }
        }
    }
    Built { events, result }
}

fn tagged(tag: &str) -> BuildOptions {
    BuildOptions { tags: vec![tag.into()], ..Default::default() }
}

/// Runs `image` (with `cmd`, if any) to its end: its output and status.
async fn run(c: &Client, image: &str, cmd: &[&str]) -> (String, i32) {
    run_config(
        c,
        ContainerConfig { image: image.into(), cmd: cmd.iter().map(|s| s.to_string()).collect(), ..Default::default() },
    )
    .await
}

async fn run_config(c: &Client, config: ContainerConfig) -> (String, i32) {
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

const BASIC: &str = r#"
FROM alpine
ARG GREETING=hi
ENV WHO=world
WORKDIR /app
COPY hello.txt .
RUN echo "$GREETING $WHO" > greeting && cat hello.txt
CMD ["cat", "/app/greeting", "/app/hello.txt"]
"#;

/// A build runs its steps (a RUN's output streamed back), and its image
/// runs: config, layers and history as the file says.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_a_build_and_its_image() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let files: &[(&str, &[u8], u32)] =
            &[("Containerfile", BASIC.as_bytes(), 0o644), ("hello.txt", b"hello\n", 0o600)];
        let b = build(&c, tagged("app"), files).await;
        assert_eq!(b.result.as_ref().map(|(_, n)| n.clone()), Ok(vec!["docker.io/library/app:latest".to_owned()]));
        assert_eq!(b.output(), "hello\n");
        let bytes = BASIC.len() as u64 + 6;
        assert!(matches!(b.events[0], BuildEvent::Context { files: 2, bytes: n } if n == bytes), "{:?}", b.events[0]);
        let steps: Vec<&str> = b
            .events
            .iter()
            .filter_map(|e| match e {
                BuildEvent::Step { instruction, total: 7, .. } => Some(instruction.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(steps.len(), 7, "{:#?}", b.events);
        assert_eq!(steps[0], "FROM alpine");
        assert_eq!(b.containers(), 1, "one RUN");
        assert_eq!(run(&c, "app", &[]).await, ("hi world\nhello\n".to_owned(), 0));
        // The COPY keeps the file's mode; owner root.
        assert_eq!(run(&c, "app", &["stat", "-c", "%a %u:%g", "/app/hello.txt"]).await.0, "600 0:0\n");
        let i = c.inspect_image("app").await.unwrap();
        assert_eq!(i.summary.id, b.id());
        assert_eq!(i.summary.layers, 4, "alpine, WORKDIR, COPY, RUN");
        let config = &i.config["config"];
        assert_eq!(config["WorkingDir"], "/app");
        assert!(config["Env"].as_array().unwrap().iter().any(|e| e == "WHO=world"));
        assert_eq!(config["Cmd"], serde_json::json!(["cat", "/app/greeting", "/app/hello.txt"]));
        let history: Vec<String> = i.config["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["created_by"].as_str().unwrap().to_owned())
            .collect();
        assert!(history.iter().any(|h| h == "WORKDIR /app"), "{history:?}");
        assert!(history.iter().any(|h| h.starts_with("RUN /bin/sh -c echo")), "{history:?}");
        // No step container is left, nothing is mounted for the build, and
        // its context is gone.
        assert!(c.list_containers(true).await.unwrap().is_empty());
        assert!(d.mounts().iter().all(|m| m.ends_with("/containers")), "{:?}", d.mounts());
        assert_eq!(std::fs::read_dir(d.data.join("builds")).unwrap().count(), 0);
    });
}

/// The same build again runs nothing; a changed file runs its COPY and
/// what follows; --no-cache runs everything.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_the_cache_runs_nothing_twice() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = BASIC.as_bytes();
        let first = build(&c, tagged("app"), &[("Containerfile", file, 0o644), ("hello.txt", b"hello\n", 0o644)]).await;
        first.id();
        let second =
            build(&c, tagged("app"), &[("Containerfile", file, 0o644), ("hello.txt", b"hello\n", 0o644)]).await;
        second.id();
        assert_eq!((second.cached(), second.containers()), (3, 0), "{:#?}", second.events);
        assert_eq!(second.output(), "");
        let layers = |id: &str| {
            let c = c.clone();
            let id = id.to_owned();
            async move { c.inspect_image(&id).await.unwrap().diff_ids }
        };
        assert_eq!(layers(first.id()).await, layers(second.id()).await, "the same layers");
        assert_eq!(first.id(), second.id(), "from the cache alone: the same image");
        // A file's mtime alone doesn't count; its content does.
        let changed =
            build(&c, tagged("app"), &[("Containerfile", file, 0o644), ("hello.txt", b"hello again\n", 0o644)]).await;
        assert_eq!((changed.cached(), changed.containers()), (1, 1));
        assert_eq!(changed.output(), "hello again\n");
        let again = build(
            &c,
            BuildOptions { no_cache: true, ..tagged("app") },
            &[("Containerfile", file, 0o644), ("hello.txt", b"hello again\n", 0o644)],
        )
        .await;
        assert_eq!((again.cached(), again.containers()), (0, 1));
        // A build arg changes what follows its ARG.
        let arg = build(
            &c,
            BuildOptions { build_args: [("GREETING".to_owned(), "hey".to_owned())].into(), ..tagged("app") },
            &[("Containerfile", file, 0o644), ("hello.txt", b"hello again\n", 0o644)],
        )
        .await;
        assert_eq!((arg.cached(), arg.containers()), (0, 1));
        assert_eq!(run(&c, "app", &[]).await.0, "hey world\nhello again\n");
        // builder prune forgets it all.
        assert!(!c.prune_build_cache().await.unwrap().deleted.is_empty());
        let after = build(&c, tagged("app"), &[("Containerfile", file, 0o644), ("hello.txt", b"hello\n", 0o644)]).await;
        assert_eq!(after.cached(), 0);
    });
}

/// Only the stages the target needs are built; COPY --from takes files of
/// an earlier stage, and nothing else of it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_multi_stage() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = br#"
FROM alpine AS builder
RUN mkdir /out && echo built > /out/artifact && echo junk > /junk

FROM alpine AS unused
RUN echo never-runs

FROM alpine
COPY --from=builder /out/artifact /artifact
CMD ["cat", "/artifact"]
"#;
        let b = build(&c, tagged("multi"), &[("Containerfile", file, 0o644)]).await;
        b.id();
        assert!(!b.output().contains("never-runs"));
        assert!(!b.events.iter().any(|e| matches!(e, BuildEvent::Stage { index: 1, .. })));
        assert_eq!(run(&c, "multi", &[]).await.0, "built\n");
        assert_eq!(run(&c, "multi", &["ls", "/junk", "/out"]).await.1, 1, "nothing else of the builder");
        // --target: up to that stage.
        let b = build(
            &c,
            BuildOptions { target: Some("builder".into()), ..tagged("builder") },
            &[("Containerfile", file, 0o644)],
        )
        .await;
        b.id();
        assert_eq!(run(&c, "builder", &["cat", "/junk"]).await.0, "junk\n");
    });
}

/// A RUN that deletes base files and remakes a directory: the layer holds a
/// whiteout and an opaque directory, and the image shows only what's left.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_deletions_are_whiteouts_and_opaque_directories() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = b"FROM alpine\nRUN rm /etc/motd && rm -rf /etc/apk && mkdir /etc/apk && echo new > /etc/apk/only\n";
        build(&c, tagged("trimmed"), &[("Containerfile", file, 0o644)]).await.id();
        let (out, _) = run(&c, "trimmed", &["sh", "-c", "ls /etc/motd 2>&1; ls /etc/apk"]).await;
        assert!(out.contains("No such file"), "{out}");
        assert!(out.ends_with("only\n"), "the lower layer's /etc/apk is hidden: {out}");
    });
}

/// A COPY into a path of the image that is a symlink to an absolute path
/// lands inside the image, never on the host.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_copy_stays_inside_the_image() {
    let d = TestDaemon::start();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().to_str().unwrap().trim_start_matches('/').to_owned();
    // The image has the directory the symlink names; the host has one of
    // the same path too, which must stay empty.
    let layer = LayerBuilder::new()
        .dir(&format!("{target}/"), 0o755, (0, 0))
        .symlink("app", &format!("/{target}"), (0, 0))
        .symlink("dangling", "/nowhere/at/all", (0, 0))
        .finish();
    d.import_alpine_layers("linked", &[layer]);
    block_on(async {
        let c = d.client();
        let file = b"FROM linked\nCOPY f.txt /app/\nRUN cat /app/f.txt\n";
        let b = build(&c, tagged("copied"), &[("Containerfile", file, 0o644), ("f.txt", b"inside\n", 0o644)]).await;
        b.id();
        assert_eq!(b.output(), "inside\n");
        assert_eq!(run(&c, "copied", &["cat", &format!("/{target}/f.txt")]).await.0, "inside\n");
        // Through a symlink to nothing: refused (BuildKit would make the
        // directory; nothing is ever made outside the image either way).
        let file = b"FROM linked\nCOPY f.txt /dangling/\n";
        let b = build(&c, tagged("dangling"), &[("Containerfile", file, 0o644), ("f.txt", b"x\n", 0o644)]).await;
        assert!(b.result.unwrap_err().contains("doesn't exist"));
    });
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0, "the host's directory was written");
}

/// FROM scratch and ADD of a gzipped root filesystem: an image from a
/// tarball, which runs.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_add_extracts_an_archive_from_scratch() {
    let d = TestDaemon::start();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&rustlet_itests::images::alpine_layer()).unwrap();
    let tarball = gz.finish().unwrap();
    block_on(async {
        let c = d.client();
        let file = b"FROM scratch\nADD rootfs.tar.gz /\nCMD [\"/bin/sh\", \"-c\", \"echo from-scratch\"]\n";
        let b =
            build(&c, tagged("tarball"), &[("Containerfile", file, 0o644), ("rootfs.tar.gz", &tarball, 0o644)]).await;
        b.id();
        assert_eq!(run(&c, "tarball", &[]).await.0, "from-scratch\n");
        assert_eq!(c.inspect_image("tarball").await.unwrap().summary.layers, 1);
    });
}

/// A RUN that fails fails the build, and leaves no container, mount or
/// context behind; its output came first.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_a_failing_run_fails_the_build_and_leaves_nothing() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = b"FROM alpine\nRUN echo trying; exit 3\n";
        let b = build(&c, tagged("never"), &[("Containerfile", file, 0o644)]).await;
        assert_eq!(b.output(), "trying\n");
        let e = b.result.unwrap_err();
        assert!(e.contains("returned a non-zero code: 3"), "{e}");
        assert!(c.list_containers(true).await.unwrap().is_empty());
        assert!(c.inspect_image("never").await.is_err());
        assert!(d.mounts().iter().all(|m| m.ends_with("/containers")), "{:?}", d.mounts());
        assert_eq!(std::fs::read_dir(d.data.join("builds")).unwrap().count(), 0);
        // A missing Containerfile, an unknown instruction: refused with where.
        let b = build(&c, tagged("x"), &[("README", b"no file", 0o644)]).await;
        assert!(b.result.unwrap_err().contains("no Containerfile"));
        let b = build(&c, tagged("x"), &[("Containerfile", b"FROM alpine\nFROBNICATE x\n", 0o644)]).await;
        assert!(b.result.unwrap_err().contains("line 2"));
    });
}

/// USER, --chown by name, a VOLUME whose RUN changes are lost (as with
/// Docker's classic builder), and a HEALTHCHECK the image keeps.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_users_volumes_and_healthchecks() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file = br#"
FROM alpine
RUN adduser -D -u 1234 app
COPY --chown=app:app f /home/app/f
VOLUME /data
RUN echo lost > /data/x
USER app
RUN id -u && stat -c %u:%g /home/app/f && ls -A /data | wc -l
HEALTHCHECK --interval=100ms --retries=1 CMD ["true"]
CMD ["sleep", "600"]
"#;
        let b = build(&c, tagged("users"), &[("Containerfile", file, 0o644), ("f", b"x", 0o644)]).await;
        b.id();
        assert_eq!(b.output(), "1234\n1234:1234\n0\n");
        let id = c.create_container(&ContainerConfig { image: "users".into(), ..Default::default() }).await.unwrap().id;
        c.start(&id).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let h = c.inspect_container(&id).await.unwrap().state.health;
            if h.as_ref().is_some_and(|h| h.status == HealthStatus::Healthy) {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "never healthy: {h:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        c.remove_container(&id, true).await.unwrap();
    });
}

/// A RUN's layer keeps what the container changed in directories that
/// hold mount points (a chown above a volume's target, a chmod of /etc),
/// and nothing the runtime made for its mounts: a RUN that changes nothing
/// adds an empty layer.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bd_changes_beside_mount_points_stay_and_mount_points_go() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let file =
            b"FROM alpine\nVOLUME /var/lib/app/data\nRUN chown nobody /var/lib/app && chmod 700 /etc\nRUN true\n";
        build(&c, tagged("beside"), &[("Containerfile", file, 0o644)]).await.id();
        let (out, _) = run(&c, "beside", &["stat", "-c", "%U %a %n", "/var/lib/app", "/etc"]).await;
        assert_eq!(out, "nobody 755 /var/lib/app\nroot 700 /etc\n");
        let i = c.inspect_image("beside").await.unwrap();
        let diff_ids: Vec<&str> =
            i.config["rootfs"]["diff_ids"].as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect();
        // An archive of nothing: two zero blocks.
        let empty = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef";
        assert_eq!(diff_ids[diff_ids.len() - 2..], [diff_ids[diff_ids.len() - 2], empty], "{diff_ids:?}");
        assert_ne!(diff_ids[diff_ids.len() - 2], empty);
    });
}

/// commit: a container's changes (a new file, a deleted one) and its
/// options as a new image, with --change on top; a running container keeps
/// running.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cm_commit_keeps_changes_and_options() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig {
            image: "alpine".into(),
            cmd: vec!["sh".into(), "-c".into(), "echo data > /new; rm /etc/motd; touch /ready; sleep 600".into()],
            env: vec!["A=1".into()],
            ..Default::default()
        };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while c.inspect_container(&id).await.unwrap().state.status.is_live() {
            // `/ready` shows in the upper directory once the script wrote it.
            if d.data.join("containers").join(&id).join("upper/ready").exists() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let request = CommitRequest {
            container: id.clone(),
            reference: Some("committed".into()),
            comment: Some("by a test".into()),
            changes: vec![r#"CMD ["sh", "-c", "cat /new; ls /etc/motd; echo A=$A"]"#.into()],
            ..Default::default()
        };
        let r = c.commit(&request).await.unwrap();
        assert_eq!(r.name.as_deref(), Some("docker.io/library/committed:latest"));
        assert_eq!(c.inspect_container(&id).await.unwrap().state.status.to_string(), "running", "thawed");
        let (out, _) = run(&c, "committed", &[]).await;
        assert!(out.starts_with("data\n") && out.contains("No such file") && out.ends_with("A=1\n"), "{out}");
        let i = c.inspect_image("committed").await.unwrap();
        assert_eq!(i.summary.layers, 2);
        let last = i.config["history"].as_array().unwrap().last().unwrap().clone();
        assert_eq!(
            (last["created_by"].as_str(), last["comment"].as_str()),
            (Some("rustlet commit"), Some("by a test"))
        );
        // The runtime's mount points (/etc/hosts…) aren't the container's
        // changes. (A container of the new image can't tell: its own mounts
        // cover them.) The layer itself:
        let layer = i.layer_details.last().unwrap().digest.trim_start_matches("sha256:").to_owned();
        let blob = std::fs::File::open(d.data.join("content/blobs/sha256").join(layer)).unwrap();
        let names: Vec<String> = tar::Archive::new(flate2::read::GzDecoder::new(blob))
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "new") && names.iter().any(|n| n == "etc/.wh.motd"), "{names:?}");
        for mount_point in ["etc/hostname", "etc/hosts", "etc/resolv.conf"] {
            assert!(!names.iter().any(|n| n == mount_point), "{mount_point} committed: {names:?}");
        }
        c.remove_container(&id, true).await.unwrap();
        // Without a name: kept, listed as <none>, removed by its id.
        let id = c
            .create_container(&ContainerConfig {
                image: "alpine".into(),
                cmd: vec!["true".into()],
                ..Default::default()
            })
            .await
            .unwrap()
            .id;
        let unnamed = c.commit(&CommitRequest { container: id.clone(), ..Default::default() }).await.unwrap();
        let listed = c.list_images().await.unwrap();
        assert!(listed.iter().any(|i| i.id == unnamed.id && i.names.is_empty()), "{listed:?}");
        c.remove_container(&id, true).await.unwrap();
        c.remove_image(&unnamed.id, false).await.unwrap();
        assert!(!c.list_images().await.unwrap().iter().any(|i| i.id == unnamed.id));
    });
}

/// A `--userns=remap` container's upper directory holds host ids; its
/// commit has the image's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cm_a_remapped_containers_commit_has_the_images_owners() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let script = "touch /by-root && adduser -D -u 4321 u && su u -c 'touch /tmp/by-u'";
        let cfg = ContainerConfig {
            image: "alpine".into(),
            cmd: vec!["sh".into(), "-c".into(), script.into()],
            userns: UsernsMode::Remap,
            ..Default::default()
        };
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        c.wait(&id, rustlet_spec::container::WaitCondition::NotRunning).await.unwrap();
        c.commit(&CommitRequest { container: id.clone(), reference: Some("unshifted".into()), ..Default::default() })
            .await
            .unwrap();
        let (out, _) = run(&c, "unshifted", &["stat", "-c", "%u", "/by-root", "/tmp/by-u"]).await;
        assert_eq!(out, "0\n4321\n");
        c.remove_container(&id, true).await.unwrap();
    });
}

/// save then load: the same image under the same name, runnable; an
/// unnamed image loads kept.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sl_save_and_load() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let id = c.inspect_image("alpine").await.unwrap().summary.id;
        let save = |names: Vec<String>| {
            let c = c.clone();
            async move { c.save_images(&names).await.unwrap().map(|b| b.unwrap()).collect::<Vec<_>>().await.concat() }
        };
        let archive = save(vec!["alpine".into()]).await;
        assert_eq!(&archive[257..262], b"ustar", "a tar archive");
        assert_eq!(save(vec!["alpine".into()]).await, archive, "the same images make the same archive");
        c.remove_image("alpine", false).await.unwrap();
        assert!(c.list_images().await.unwrap().is_empty());
        let events: Vec<LoadEvent> =
            c.load_images(RequestBody::from_bytes(archive)).await.unwrap().map(|e| e.unwrap()).collect().await;
        assert!(
            events
                .contains(&LoadEvent::Loaded { id: id.clone(), name: Some("docker.io/library/alpine:latest".into()) }),
            "{events:?}"
        );
        assert_eq!(run(&c, "alpine", &["echo", "loaded"]).await.0, "loaded\n");
        // By id: unnamed, kept.
        let archive = save(vec![id.clone()]).await;
        c.remove_image("alpine", false).await.unwrap();
        let events: Vec<LoadEvent> =
            c.load_images(RequestBody::from_bytes(archive)).await.unwrap().map(|e| e.unwrap()).collect().await;
        assert!(events.contains(&LoadEvent::Loaded { id: id.clone(), name: None }), "{events:?}");
        assert!(c.list_images().await.unwrap().iter().any(|i| i.id == id && i.names.is_empty()));
        // A broken archive fails, naming nothing.
        let e = c.load_images(RequestBody::from_bytes(b"not a tar archive at all".repeat(40))).await.unwrap();
        let last = e.collect::<Vec<_>>().await.pop().unwrap();
        assert!(last.is_err());
        // tag names an image (a kept one stops being kept).
        c.tag_image(&id, "again:1").await.unwrap();
        let listed = c.list_images().await.unwrap();
        assert_eq!(listed.iter().filter(|i| i.id == id).count(), 1);
        assert_eq!(listed.iter().find(|i| i.id == id).unwrap().names, ["docker.io/library/again:1"]);
    });
}
