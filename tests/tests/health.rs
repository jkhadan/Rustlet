//! Phase 7: healthchecks, through the daemon. Run with `cargo xtask itest
//! -- hc_`.

use std::time::Duration;

use futures::StreamExt;
use rustlet_client::Client;
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_spec::container::{ContainerConfig, Health, HealthConfig, HealthStatus};
use rustlet_spec::event::{EventKind, EventsQuery};
use rustlet_spec::exec::ExecConfig;

const MS: u64 = 1_000_000;

fn sh(script: &str) -> ContainerConfig {
    ContainerConfig { image: "alpine".into(), cmd: vec!["sh".into(), "-c".into(), script.into()], ..Default::default() }
}

fn check(test: &str, interval_ms: u64, retries: u32) -> HealthConfig {
    HealthConfig {
        test: vec!["CMD-SHELL".into(), test.into()],
        interval: Some(interval_ms * MS),
        retries: Some(retries),
        ..Default::default()
    }
}

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

async fn health(c: &Client, id: &str) -> Option<Health> {
    c.inspect_container(id).await.unwrap().state.health
}

/// Waits until the container's health is `want` (and returns it).
async fn until_status(c: &Client, id: &str, want: HealthStatus) -> Health {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(h) = health(c, id).await
            && h.status == want
        {
            return h;
        }
        assert!(tokio::time::Instant::now() < deadline, "never {want}: {:?}", health(c, id).await);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn run(c: &Client, config: &ContainerConfig) -> String {
    let id = c.create_container(config).await.unwrap().id;
    c.start(&id).await.unwrap();
    id
}

/// A check that starts passing makes the container healthy, with an event;
/// one that starts failing makes it unhealthy after `retries` failures in a
/// row, with what the check printed.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hc_healthy_then_unhealthy_with_events() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let mut events = c.events(&EventsQuery::default()).await.unwrap();
        // A start period, so that a slow start (a loaded host) can't make
        // it unhealthy before it is healthy: then the order is certain.
        let cfg = ContainerConfig {
            healthcheck: Some(HealthConfig {
                start_period: Some(30_000 * MS),
                start_interval: Some(100 * MS),
                ..check("echo checked; test -e /tmp/ok", 100, 3)
            }),
            ..sh("sleep 0.5; touch /tmp/ok; sleep 600")
        };
        let id = run(&c, &cfg).await;
        let h = health(&c, &id).await.expect("a container with a check has health from its start");
        assert_eq!(h.status, HealthStatus::Starting);
        let h = until_status(&c, &id, HealthStatus::Healthy).await;
        assert_eq!(h.failing_streak, 0);
        let last = h.log.last().unwrap();
        assert_eq!((last.exit_code, last.output.as_str()), (0, "checked\n"));
        assert!(h.log.len() <= 5);
        // Failing from now on: unhealthy after three in a row.
        let rm = ExecConfig { cmd: vec!["rm".into(), "/tmp/ok".into()], ..Default::default() };
        let exec = c.create_exec(&id, &rm).await.unwrap().id;
        c.start_exec_detached(&exec).await.unwrap();
        let h = until_status(&c, &id, HealthStatus::Unhealthy).await;
        assert_eq!(h.failing_streak, 3);
        assert_eq!(h.log.last().unwrap().exit_code, 1);
        // `ps` shows it too.
        let listed = c.list_containers(false).await.unwrap();
        assert_eq!(listed[0].state.health.as_ref().map(|h| h.status), Some(HealthStatus::Unhealthy));
        // One event per change of verdict, none for the checks themselves.
        let mut seen = Vec::new();
        while seen.len() < 2 {
            let e = tokio::time::timeout(Duration::from_secs(10), events.next()).await.unwrap().unwrap().unwrap();
            assert!(!e.action.starts_with("exec_") || e.attributes.get("exec_id").is_some_and(|x| x == &exec));
            if e.kind == EventKind::Container && e.action == "health_status" {
                assert_eq!(e.id, id);
                seen.push(e.attributes["health_status"].clone());
            }
        }
        assert_eq!(seen, ["healthy", "unhealthy"]);
        c.remove_container(&id, true).await.unwrap();
    });
}

/// A check that hangs is killed after its timeout and counts as a failure;
/// no check process is left in the container.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hc_a_check_that_hangs_is_killed_after_its_timeout() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig {
            healthcheck: Some(HealthConfig { timeout: Some(300 * MS), ..check("sleep 1000", 100, 2) }),
            ..sh("sleep 600")
        };
        let id = run(&c, &cfg).await;
        let h = until_status(&c, &id, HealthStatus::Unhealthy).await;
        let last = h.log.last().unwrap();
        assert_eq!(last.exit_code, -1);
        assert!(last.output.contains("exceeded timeout"), "{last:?}");
        // The killed checks are gone (a moment for the last one's kill).
        tokio::time::sleep(Duration::from_millis(300)).await;
        let ps = ExecConfig {
            cmd: vec!["sh".into(), "-c".into(), "ps -o args | grep -c '^sleep 1000'".into()],
            ..Default::default()
        };
        let exec = c.create_exec(&id, &ps).await.unwrap().id;
        let mut session = c.start_exec(&exec).await.unwrap();
        let mut out = String::new();
        while let Ok(Some(ev)) = session.recv().await {
            match ev {
                rustlet_client::SessionEvent::Stdout(b) => out.push_str(&String::from_utf8_lossy(&b)),
                rustlet_client::SessionEvent::Exit { .. } => break,
                _ => {}
            }
        }
        // At most the one check running right now.
        let left: u32 = out.trim().parse().unwrap();
        assert!(left <= 1, "{left} hung checks left");
        c.remove_container(&id, true).await.unwrap();
    });
}

/// Failures during the start period don't count: a slow starter becomes
/// healthy without ever being unhealthy.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hc_the_start_period_forgives_failures() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig {
            healthcheck: Some(HealthConfig {
                start_period: Some(5_000 * MS),
                start_interval: Some(50 * MS),
                ..check("test -e /tmp/ok", 60_000, 1)
            }),
            ..sh("sleep 1; touch /tmp/ok; sleep 600")
        };
        let id = run(&c, &cfg).await;
        let h = until_status(&c, &id, HealthStatus::Healthy).await;
        assert!(h.log.iter().any(|r| r.exit_code != 0), "the early checks failed: {h:?}");
        assert_eq!(h.failing_streak, 0);
        c.remove_container(&id, true).await.unwrap();
    });
}

/// The image's HEALTHCHECK applies (with its SHELL), container options go
/// over it, `NONE` turns it off, and a container without one has no health.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hc_the_images_healthcheck_and_the_containers_options() {
    let d = daemon();
    d.import_alpine_json("checked", |config| {
        config["config"]["Healthcheck"] =
            serde_json::json!({"Test": ["CMD-SHELL", "echo \"$0\" | grep -q ash"], "Interval": 100 * MS, "Retries": 1});
        config["config"]["Shell"] = serde_json::json!(["/bin/ash", "-c"]);
    });
    block_on(async {
        let c = d.client();
        let image = ContainerConfig { image: "checked".into(), ..sh("sleep 600") };
        let id = run(&c, &image).await;
        let h = until_status(&c, &id, HealthStatus::Healthy).await;
        assert_eq!(h.log.last().unwrap().exit_code, 0, "the image's command, through its SHELL");
        // Options over the image's command: it fails now (retries 2).
        let own = ContainerConfig {
            healthcheck: Some(HealthConfig { test: vec!["CMD".into(), "false".into()], ..Default::default() }),
            ..image.clone()
        };
        let failing = run(&c, &own).await;
        let h = until_status(&c, &failing, HealthStatus::Unhealthy).await;
        assert_eq!(h.failing_streak, 1, "the image's retries");
        // NONE: no health at all.
        let none = ContainerConfig {
            healthcheck: Some(HealthConfig { test: vec!["NONE".into()], ..Default::default() }),
            ..image.clone()
        };
        let quiet = run(&c, &none).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(health(&c, &quiet).await, None);
        let plain = run(&c, &sh("sleep 600")).await;
        assert_eq!(health(&c, &plain).await, None);
        // A check the daemon would refuse is refused at create.
        let bad = ContainerConfig {
            healthcheck: Some(HealthConfig { test: vec!["CMD-SHELL".into()], ..Default::default() }),
            ..sh("true")
        };
        assert!(c.create_container(&bad).await.is_err());
        for id in [id, failing, quiet, plain] {
            c.remove_container(&id, true).await.unwrap();
        }
    });
}

/// A new daemon goes on checking the containers it takes over, from their
/// saved health; a restart of the container starts it over.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hc_checks_go_on_after_a_daemon_restart() {
    let mut d = daemon();
    let id = block_on(async {
        let c = d.client();
        let cfg =
            ContainerConfig { healthcheck: Some(check("test -e /tmp/ok", 100, 2)), ..sh("touch /tmp/ok; sleep 600") };
        let id = run(&c, &cfg).await;
        until_status(&c, &id, HealthStatus::Healthy).await;
        id
    });
    d.restart();
    block_on(async {
        let c = d.client();
        assert_eq!(health(&c, &id).await.unwrap().status, HealthStatus::Healthy, "saved");
        let rm = ExecConfig { cmd: vec!["rm".into(), "/tmp/ok".into()], ..Default::default() };
        let exec = c.create_exec(&id, &rm).await.unwrap().id;
        c.start_exec_detached(&exec).await.unwrap();
        until_status(&c, &id, HealthStatus::Unhealthy).await;
        // A restart: starting again (the file is back with the new run).
        c.restart(&id, Some(1)).await.unwrap();
        let h = health(&c, &id).await.unwrap();
        assert!(matches!(h.status, HealthStatus::Starting | HealthStatus::Healthy), "{h:?}");
        until_status(&c, &id, HealthStatus::Healthy).await;
        c.remove_container(&id, true).await.unwrap();
    });
}
