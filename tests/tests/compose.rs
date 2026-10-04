//! Phase 7: compose projects (the `rustlet-compose` library) against a
//! daemon of the test's own. Run with `cargo xtask itest -- cp_`.

use std::sync::Mutex;
use std::time::Duration;

use futures::StreamExt;
use rustlet_compose::run::{Action, BuildPolicy, ResourceKind};
use rustlet_compose::{Compose, ComposeEvent, DownOptions, LoadOptions, UpOptions};
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_spec::logs::LogsQuery;

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

const PROJECT: &str = r#"
name: shop
services:
  db:
    image: alpine
    command: ["sh", "-c", "sleep 0.5; touch /tmp/ready; exec sleep 600"]
    healthcheck:
      test: ["CMD", "test", "-e", "/tmp/ready"]
      interval: 100ms
      retries: 3
      # Failures before /tmp/ready don't count, however fast the checks.
      start_period: 30s
      start_interval: 100ms
  init:
    image: alpine
    command: ["sh", "-c", "echo seeded"]
  web:
    image: alpine
    command: ["sh", "-c", "getent hosts db; echo $${GREETING}; exec sleep 600"]
    environment:
      GREETING: ${GREETING:-hello}
    depends_on:
      db:
        condition: service_healthy
      init:
        condition: service_completed_successfully
"#;

/// Collects a project operation's events.
#[derive(Default)]
struct Seen(Mutex<Vec<ComposeEvent>>);

impl Seen {
    fn take(&self) -> Vec<ComposeEvent> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn containers(events: &[ComposeEvent], action: Action) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            ComposeEvent::Resource { kind: ResourceKind::Container, name, action: a } if *a == action => {
                Some(name.clone())
            }
            _ => None,
        })
        .collect()
}

fn project(yaml: &str, dir: &std::path::Path) -> rustlet_compose::Project {
    rustlet_compose::load_str(yaml, dir, &LoadOptions::default()).unwrap()
}

/// up: the network, then each service once its dependencies are as
/// `depends_on` says (db healthy, init exited 0), names resolving between
/// them; up again leaves them be; a changed service is recreated; ps and
/// logs by labels; down removes everything.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cp_up_waits_for_dependencies_and_down_removes_everything() {
    let d = daemon();
    let dir = tempfile::tempdir().unwrap();
    block_on(async {
        let c = d.client();
        let compose = Compose::new(c.clone(), project(PROJECT, dir.path()));
        let seen = Seen::default();
        let events = |e: ComposeEvent| seen.0.lock().unwrap().push(e);
        compose.up(&UpOptions::default(), &events).await.unwrap();
        let ev = seen.take();
        let started = containers(&ev, Action::Started);
        assert_eq!(started.len(), 3, "{ev:#?}");
        let at = |name: &str, action| containers(&ev, action).iter().position(|n| n == name);
        let db_healthy = ev.iter().position(
            |e| matches!(e, ComposeEvent::Resource { name, action: Action::Healthy, .. } if name == "shop-db-1"),
        );
        let web_created = ev.iter().position(
            |e| matches!(e, ComposeEvent::Resource { name, action: Action::Created, .. } if name == "shop-web-1"),
        );
        assert!(db_healthy.is_some() && db_healthy < web_created, "web after db is healthy: {ev:#?}");
        assert!(at("shop-web-1", Action::Started).is_some());
        // The project's network, labels, DNS between services.
        let net = c.inspect_network("shop_default").await.unwrap();
        assert_eq!(net.labels.get(rustlet_compose::LABEL_PROJECT).map(String::as_str), Some("shop"));
        let ps = compose.ps(false).await.unwrap();
        let services: Vec<&str> = ps.iter().map(|s| s.service.as_str()).collect();
        assert_eq!(services, ["db", "web"], "init has exited");
        assert_eq!(compose.ps(true).await.unwrap().len(), 3);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let text = loop {
            let lines: Vec<_> = compose
                .logs(&["web".into()], &LogsQuery::default())
                .await
                .unwrap()
                .map(|l| l.unwrap().entry.log)
                .collect()
                .await;
            let text = lines.concat();
            if text.contains("hello") || tokio::time::Instant::now() > deadline {
                break text;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert!(text.contains(" db") && text.ends_with("hello\n"), "{text:?}");
        let stacks = rustlet_compose::run::stacks(&c).await.unwrap();
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].name, "shop");
        // Again: nothing changes.
        compose.up(&UpOptions::default(), &events).await.unwrap();
        let ev = seen.take();
        assert!(
            containers(&ev, Action::Created).is_empty() && containers(&ev, Action::Recreated).is_empty(),
            "{ev:#?}"
        );
        // A changed service is recreated, alone.
        let changed = project(&PROJECT.replace("echo $${GREETING}", "echo changed $${GREETING}"), dir.path());
        Compose::new(c.clone(), changed).up(&UpOptions::default(), &events).await.unwrap();
        let ev = seen.take();
        let recreated: Vec<String> =
            containers(&ev, Action::Recreated).into_iter().chain(containers(&ev, Action::Recreating)).collect();
        assert!(recreated.iter().all(|n| n == "shop-web-1") && !recreated.is_empty(), "{ev:#?}");
        // down: containers, then the network.
        compose.down(&DownOptions::default(), &events).await.unwrap();
        assert!(c.list_containers(true).await.unwrap().is_empty());
        assert!(c.inspect_network("shop_default").await.is_err());
    });
}

/// A dependency that never becomes healthy fails the up, and nothing
/// depending on it is created.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cp_an_unhealthy_dependency_fails_the_up() {
    let d = daemon();
    let dir = tempfile::tempdir().unwrap();
    let yaml = r#"
services:
  db:
    image: alpine
    command: ["sleep", "600"]
    healthcheck:
      test: ["CMD", "false"]
      interval: 100ms
      retries: 2
  web:
    image: alpine
    command: ["sleep", "600"]
    depends_on:
      db:
        condition: service_healthy
"#;
    block_on(async {
        let c = d.client();
        let p = rustlet_compose::load_str(
            yaml,
            dir.path(),
            &LoadOptions { project_name: Some("sick".into()), ..LoadOptions::default() },
        )
        .unwrap();
        let compose = Compose::new(c.clone(), p);
        let e = compose.up(&UpOptions::default(), &|_| {}).await.unwrap_err();
        assert!(e.to_string().contains("unhealthy"), "{e}");
        let names: Vec<String> = c.list_containers(true).await.unwrap().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["sick-db-1"]);
        compose.down(&DownOptions::default(), &|_| {}).await.unwrap();
    });
}

/// A service with `build:` gets its image built (named after the project
/// and service), and up runs it; down -v removes the project's volume.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cp_a_service_is_built_and_its_volume_goes_with_down_v() {
    let d = daemon();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("app")).unwrap();
    std::fs::write(
        dir.path().join("app/Containerfile"),
        "FROM alpine\nRUN echo built > /built\nCMD [\"sleep\", \"600\"]\n",
    )
    .unwrap();
    let yaml = r#"
name: made
services:
  app:
    build: ./app
    volumes:
      - data:/data
volumes:
  data:
"#;
    block_on(async {
        let c = d.client();
        let compose = Compose::new(c.clone(), project(yaml, dir.path()));
        compose.up(&UpOptions { build: BuildPolicy::Missing, ..UpOptions::default() }, &|_| {}).await.unwrap();
        let image = c.inspect_image("made-app").await.unwrap();
        assert_eq!(image.containers, ["made-app-1"]);
        assert!(c.inspect_volume("made_data").await.is_ok());
        compose.down(&DownOptions { volumes: true, ..DownOptions::default() }, &|_| {}).await.unwrap();
        assert!(c.inspect_volume("made_data").await.is_err());
    });
}
