//! `up`, `down`, `ps`, `logs`, `stop`, `start`, `stacks` and
//! `down_project` against a fake daemon ([`fake`]): what they ask it for,
//! in what order, and what they report.

mod fake;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake::{Fake, Script};
use futures::StreamExt;
use rustlet_compose::run::{Action, BuildPolicy, ComposeEvent, DownOptions, ResourceKind, UpOptions};
use rustlet_compose::{
    Compose, Condition, Error, LABEL_CONFIG_FILES, LABEL_CONFIG_HASH, LABEL_DEPENDS_ON, LABEL_NETWORK, LABEL_NUMBER,
    LABEL_PROJECT, LABEL_SERVICE, LABEL_VOLUME, LABEL_WORKING_DIR, LoadOptions, Project, down_project, load,
    load_selected, load_str, stacks,
};
use rustlet_spec::container::ContainerStatus;
use rustlet_spec::logs::{LogEntry, LogStream, LogsQuery};
use rustlet_spec::network::NetworkMode;

/// The shop: web needs db, which keeps its data in a volume.
const SHOP: &str = r#"
name: shop
services:
  web:
    image: nginx
    depends_on: [db]
    ports: ["8080:80"]
  db:
    image: postgres
    volumes: [data:/var/lib/postgresql/data]
volumes:
  data:
"#;

/// A project directory that doesn't exist: no `.env` to read.
const DIR: &str = "/rustlet-compose-tests/shop";

fn project(yaml: &str) -> Project {
    load_str(yaml, Path::new(DIR), &LoadOptions::default()).unwrap()
}

fn compose(fake: &Fake, yaml: &str) -> Compose {
    Compose::new(fake.client.clone(), project(yaml))
}

/// Fails a test that would otherwise hang.
async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), f).await.expect("timed out")
}

/// Keeps what an operation reports.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<ComposeEvent>>>);

impl Recorder {
    fn sink(&self) -> impl Fn(ComposeEvent) + Send + Sync + 'static {
        let events = self.0.clone();
        move |e| events.lock().unwrap().push(e)
    }

    fn take(&self) -> Vec<ComposeEvent> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

/// The resource events, as `Container shop-db-1 Created`.
fn resources(events: &[ComposeEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            ComposeEvent::Resource { kind, name, action } => Some(format!("{kind:?} {name} {action:?}")),
            _ => None,
        })
        .collect()
}

fn warnings(events: &[ComposeEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            ComposeEvent::Warning(w) => Some(w.clone()),
            _ => None,
        })
        .collect()
}

async fn up_with(compose: &Compose, options: &UpOptions) -> (rustlet_compose::Result<()>, Vec<ComposeEvent>) {
    let events = Recorder::default();
    let result = within(compose.up(options, &events.sink())).await;
    (result, events.take())
}

async fn up(compose: &Compose) -> Vec<ComposeEvent> {
    let (result, events) = up_with(compose, &UpOptions::default()).await;
    result.unwrap();
    events
}

async fn down_with(compose: &Compose, options: &DownOptions) -> Vec<ComposeEvent> {
    let events = Recorder::default();
    within(compose.down(options, &events.sink())).await.unwrap();
    events.take()
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// `events` has `first` before `then`.
fn before(events: &[String], first: &str, then: &str) -> bool {
    let at = |e: &str| events.iter().position(|x| x == e).unwrap_or_else(|| panic!("no {e:?} in {events:?}"));
    at(first) < at(then)
}

#[tokio::test]
async fn up_creates_networks_volumes_then_containers_in_dependency_order() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("compose.yaml"), SHOP).unwrap();
    let project = load(&LoadOptions { project_dir: Some(dir.path().into()), ..LoadOptions::default() }).unwrap();
    let compose = Compose::new(fake.client.clone(), project.clone());

    let events = up(&compose).await;
    assert_eq!(
        fake.calls(),
        [
            "network create shop_default",
            "volume create shop_data",
            "create shop-db-1",
            "start shop-db-1",
            "create shop-web-1",
            "start shop-web-1",
        ]
    );
    assert_eq!(
        resources(&events),
        [
            "Network shop_default Creating",
            "Network shop_default Created",
            "Volume shop_data Creating",
            "Volume shop_data Created",
            "Container shop-db-1 Creating",
            "Container shop-db-1 Created",
            "Container shop-db-1 Starting",
            "Container shop-db-1 Started",
            "Container shop-web-1 Creating",
            "Container shop-web-1 Created",
            "Container shop-web-1 Starting",
            "Container shop-web-1 Started",
        ]
    );
    let d = fake.lock();
    assert_eq!(d.network("shop_default").labels, labels(&[(LABEL_PROJECT, "shop"), (LABEL_NETWORK, "default")]));
    let volume = d.volume("shop_data").unwrap();
    assert_eq!(volume.labels, labels(&[(LABEL_PROJECT, "shop"), (LABEL_VOLUME, "data")]));
    let web = d.container("shop-web-1");
    assert_eq!(web.state.status, ContainerStatus::Running);
    let hash = project.service("web").unwrap().config_hash();
    let file = dir.path().join("compose.yaml");
    let expected = labels(&[
        (LABEL_PROJECT, "shop"),
        (LABEL_SERVICE, "web"),
        (LABEL_NUMBER, "1"),
        (LABEL_CONFIG_HASH, &hash),
        (LABEL_WORKING_DIR, dir.path().to_str().unwrap()),
        (LABEL_CONFIG_FILES, file.to_str().unwrap()),
        (LABEL_DEPENDS_ON, "db:service_started:true"),
    ]);
    assert_eq!(web.config.labels, expected);
    assert_eq!(web.config.network, NetworkMode::Network("shop_default".into()));
    assert_eq!(web.endpoints.len(), 1);
    assert_eq!(web.endpoints[0].aliases, ["web"], "its service's name, for the DNS server");
    assert_eq!(web.config.ports[0].host_port, Some(8080));
    assert_eq!(d.container("shop-db-1").config.mounts[0].source.as_deref(), Some("shop_data"));
}

#[tokio::test]
async fn a_second_up_leaves_containers_that_match_alone() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let compose = compose(&fake, SHOP);
    up(&compose).await;
    fake.calls();

    let events = up(&compose).await;
    assert!(fake.calls().is_empty());
    assert_eq!(
        resources(&events),
        [
            "Network shop_default Running",
            "Volume shop_data Running",
            "Container shop-db-1 Running",
            "Container shop-web-1 Running",
        ]
    );

    // A stopped one is started again as it is.
    within(compose.stop(&["db".into()], None, &|_: ComposeEvent| {})).await.unwrap();
    fake.calls();
    let events = resources(&up(&compose).await);
    assert_eq!(fake.calls(), ["start shop-db-1"]);
    assert!(events.contains(&"Container shop-db-1 Started".to_owned()), "{events:?}");
    assert!(!events.iter().any(|e| e.ends_with(" Created")), "{events:?}");
}

#[tokio::test]
async fn a_changed_service_or_image_is_recreated_and_force_recreates_everything() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let shop = compose(&fake, SHOP);
    up(&shop).await;
    fake.calls();
    let old_web = fake.lock().container("shop-web-1").id.clone();

    let changed = compose(&fake, &SHOP.replace("8080:80", "8081:80"));
    let events = resources(&up(&changed).await);
    assert_eq!(fake.calls(), ["stop shop-web-1", "rm shop-web-1", "create shop-web-1", "start shop-web-1"]);
    assert_eq!(
        events[2..],
        [
            "Container shop-db-1 Running",
            "Container shop-web-1 Recreating",
            "Container shop-web-1 Recreated",
            "Container shop-web-1 Starting",
            "Container shop-web-1 Started",
        ]
    );
    {
        let d = fake.lock();
        assert_ne!(d.container("shop-web-1").id, old_web);
        assert_eq!(d.container("shop-web-1").config.ports[0].host_port, Some(8081));
    }

    // The image's name now names another image.
    fake.lock().images.insert("postgres".into(), "sha256:rebuilt".into());
    up(&changed).await;
    assert_eq!(fake.calls(), ["stop shop-db-1", "rm shop-db-1", "create shop-db-1", "start shop-db-1"]);

    let force = UpOptions { force_recreate: true, timeout: Some(1), ..UpOptions::default() };
    up_with(&changed, &force).await.0.unwrap();
    assert_eq!(
        fake.calls(),
        [
            "stop shop-db-1 timeout=1",
            "rm shop-db-1",
            "create shop-db-1",
            "start shop-db-1",
            "stop shop-web-1 timeout=1",
            "rm shop-web-1",
            "create shop-web-1",
            "start shop-web-1",
        ]
    );

    // --no-recreate: the old file's service is left as the new one made it.
    let keep = UpOptions { no_recreate: true, ..UpOptions::default() };
    let (result, events) = up_with(&shop, &keep).await;
    result.unwrap();
    assert!(fake.calls().is_empty());
    assert!(resources(&events).contains(&"Container shop-web-1 Running".to_owned()));
    let both = UpOptions { no_recreate: true, force_recreate: true, ..UpOptions::default() };
    assert!(up_with(&shop, &both).await.0.unwrap_err().to_string().contains("can't go together"));
}

const HEALTHY: &str = r#"
name: shop
services:
  web:
    image: nginx
    depends_on:
      db:
        condition: service_healthy
  db:
    image: postgres
    healthcheck:
      test: [CMD, pg_isready]
      interval: 1s
"#;

#[tokio::test]
async fn service_healthy_waits_until_the_dependency_is_healthy() {
    let fake = Fake::start(&["nginx", "postgres"]);
    fake.lock().scripts.insert("shop-db-1".into(), Script::Healthy(3));
    let events = up(&compose(&fake, HEALTHY)).await;
    assert_eq!(
        fake.calls(),
        [
            "network create shop_default",
            "create shop-db-1",
            "start shop-db-1",
            "healthy shop-db-1",
            "create shop-web-1",
            "start shop-web-1",
        ]
    );
    let waiting = ComposeEvent::Waiting { service: "web".into(), on: "db".into(), condition: Condition::Healthy };
    assert!(events.contains(&waiting), "{events:?}");
    let resources = resources(&events);
    assert!(before(&resources, "Container shop-db-1 Started", "Container shop-db-1 Healthy"));
    assert!(before(&resources, "Container shop-db-1 Healthy", "Container shop-web-1 Created"));
}

#[tokio::test]
async fn a_dependency_that_turns_unhealthy_or_exits_fails_up() {
    for (script, expected) in [
        (Script::Unhealthy(2), "dependency failed to start: container shop-db-1 is unhealthy"),
        (Script::Exits(3, 2), "dependency failed to start: container shop-db-1 exited (3)"),
    ] {
        let fake = Fake::start(&["nginx", "postgres"]);
        fake.lock().scripts.insert("shop-db-1".into(), script);
        let (result, _) = up_with(&compose(&fake, HEALTHY), &UpOptions::default()).await;
        match result {
            Err(Error::Dependency(message)) => assert_eq!(message, expected),
            other => panic!("{other:?}"),
        }
        assert!(!fake.lock().has_container("shop-web-1"), "web waits for db, which never gets there");
    }
}

#[tokio::test]
async fn an_images_healthcheck_counts_and_none_at_all_is_an_error() {
    let yaml = HEALTHY.replace("    healthcheck:\n      test: [CMD, pg_isready]\n      interval: 1s\n", "");
    // The daemon reports nothing until a check of the image's has run.
    let fake = Fake::start(&["nginx", "postgres"]);
    fake.lock().image_healthchecks.insert("postgres".into());
    fake.lock().scripts.insert("shop-db-1".into(), Script::Healthy(2));
    up(&compose(&fake, &yaml)).await;
    assert!(fake.lock().has_container("shop-web-1"));

    for yaml in [yaml.clone(), HEALTHY.replace("test: [CMD, pg_isready]", "disable: true")] {
        let fake = Fake::start(&["nginx", "postgres"]);
        fake.lock().image_healthchecks.insert("nginx".into());
        let (result, _) = up_with(&compose(&fake, &yaml), &UpOptions::default()).await;
        let e = result.unwrap_err().to_string();
        assert_eq!(e, "dependency failed to start: container shop-db-1 has no healthcheck configured");
    }
}

#[tokio::test]
async fn a_dependency_is_waited_for_only_as_long_as_asked() {
    let fake = Fake::start(&["nginx", "postgres"]);
    fake.lock().scripts.insert("shop-db-1".into(), Script::Healthy(1000));
    let options = UpOptions { wait_timeout: Some(Duration::from_millis(600)), ..UpOptions::default() };
    let (result, _) = up_with(&compose(&fake, HEALTHY), &options).await;
    let e = result.unwrap_err();
    assert!(matches!(e, Error::Dependency(_)));
    assert_eq!(e.to_string(), "dependency failed to start: container shop-db-1 is still starting after 600ms");
}

#[tokio::test]
async fn an_optional_dependency_that_fails_is_a_warning() {
    let fake = Fake::start(&["nginx", "postgres"]);
    fake.lock().scripts.insert("shop-db-1".into(), Script::Unhealthy(1));
    let yaml = HEALTHY.replace("condition: service_healthy", "condition: service_healthy\n        required: false");
    let events = up(&compose(&fake, &yaml)).await;
    assert_eq!(
        warnings(&events),
        ["dependency failed to start: container shop-db-1 is unhealthy (web goes on without it: required: false)"]
    );
    assert!(fake.lock().has_container("shop-web-1"));
}

const MIGRATE: &str = r#"
name: shop
services:
  web:
    image: nginx
    depends_on:
      migrate:
        condition: service_completed_successfully
  migrate:
    image: alpine
"#;

#[tokio::test]
async fn service_completed_successfully_waits_for_an_exit_with_0() {
    let fake = Fake::start(&["nginx", "alpine"]);
    fake.lock().scripts.insert("shop-migrate-1".into(), Script::Exits(0, 2));
    let events = resources(&up(&compose(&fake, MIGRATE)).await);
    let calls = fake.calls();
    assert_eq!(calls[3..], ["exited shop-migrate-1 0", "create shop-web-1", "start shop-web-1"], "{calls:?}");
    assert!(before(&events, "Container shop-migrate-1 Exited", "Container shop-web-1 Created"));

    let fake = Fake::start(&["nginx", "alpine"]);
    fake.lock().scripts.insert("shop-migrate-1".into(), Script::Exits(1, 1));
    let (result, _) = up_with(&compose(&fake, MIGRATE), &UpOptions::default()).await;
    assert_eq!(result.unwrap_err().to_string(), "service \"migrate\" didn't complete successfully: exit 1");
}

#[tokio::test]
async fn down_removes_dependents_first_then_networks_and_with_v_volumes() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let compose = compose(&fake, SHOP);
    up(&compose).await;
    fake.calls();

    let events = down_with(&compose, &DownOptions::default()).await;
    assert_eq!(
        fake.calls(),
        ["stop shop-web-1", "rm shop-web-1", "stop shop-db-1", "rm shop-db-1", "network rm shop_default"]
    );
    assert_eq!(
        resources(&events),
        [
            "Container shop-web-1 Stopping",
            "Container shop-web-1 Stopped",
            "Container shop-web-1 Removing",
            "Container shop-web-1 Removed",
            "Container shop-db-1 Stopping",
            "Container shop-db-1 Stopped",
            "Container shop-db-1 Removing",
            "Container shop-db-1 Removed",
            "Network shop_default Removing",
            "Network shop_default Removed",
        ]
    );
    assert!(fake.lock().volume("shop_data").is_some(), "volumes stay without -v");

    up(&compose).await;
    fake.calls();
    let events = down_with(&compose, &DownOptions { volumes: true, timeout: Some(2), ..DownOptions::default() }).await;
    assert_eq!(
        fake.calls(),
        [
            "stop shop-web-1 timeout=2",
            "rm shop-web-1 -v",
            "stop shop-db-1 timeout=2",
            "rm shop-db-1 -v",
            "network rm shop_default",
            "volume rm shop_data",
        ]
    );
    assert!(
        resources(&events).ends_with(&["Volume shop_data Removing".to_owned(), "Volume shop_data Removed".to_owned()])
    );
    assert!(fake.lock().volume("shop_data").is_none());
}

#[tokio::test]
async fn external_networks_and_volumes_must_exist_and_are_never_removed() {
    let yaml = r#"
name: shop
services:
  web:
    image: nginx
    networks: [outside]
    volumes: [keep:/data]
networks:
  outside:
    external: true
volumes:
  keep:
    external: true
    name: precious
"#;
    let fake = Fake::start(&["nginx"]);
    let compose = compose(&fake, yaml);
    let (result, _) = up_with(&compose, &UpOptions::default()).await;
    assert_eq!(
        result.unwrap_err().to_string(),
        "network outside is external (external: true), but there is no such network: create it first"
    );
    fake.lock().add_network("outside");
    let (result, _) = up_with(&compose, &UpOptions::default()).await;
    assert!(result.unwrap_err().to_string().starts_with("volume precious is external"));
    fake.lock().add_volume("precious");
    fake.calls();
    let events = up(&compose).await;
    assert_eq!(fake.calls(), ["create shop-web-1", "start shop-web-1"]);
    assert!(warnings(&events).is_empty(), "external resources aren't expected to carry the project's labels");
    down_with(&compose, &DownOptions { volumes: true, ..DownOptions::default() }).await;
    assert_eq!(fake.calls(), ["stop shop-web-1", "rm shop-web-1 -v"]);
}

#[tokio::test]
async fn ps_lists_the_projects_containers_in_service_order() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let compose = compose(&fake, SHOP);
    up(&compose).await;
    fake.lock().add_container("loner", "nginx");
    within(compose.stop(&["db".into()], None, &|_: ComposeEvent| {})).await.unwrap();

    let names = |containers: Vec<rustlet_compose::ServiceContainer>| -> Vec<(String, u32, String)> {
        containers.into_iter().map(|c| (c.service, c.number, c.summary.name)).collect()
    };
    let running = within(compose.ps(false)).await.unwrap();
    assert_eq!(names(running), [("web".to_owned(), 1, "shop-web-1".to_owned())]);
    let all = within(compose.ps(true)).await.unwrap();
    assert_eq!(all[1].summary.state.status, ContainerStatus::Exited);
    assert_eq!(
        names(all),
        [("web".to_owned(), 1, "shop-web-1".to_owned()), ("db".to_owned(), 1, "shop-db-1".to_owned())],
        "the file's order"
    );
}

#[tokio::test]
async fn stacks_and_down_project_work_from_labels_alone() {
    let fake = Fake::start(&["nginx", "postgres"]);
    up(&compose(&fake, SHOP)).await;
    let blog = Compose::new(
        fake.client.clone(),
        load_str("name: blog\nservices:\n  app:\n    image: nginx\n", Path::new("/srv/blog"), &LoadOptions::default())
            .unwrap(),
    );
    up(&blog).await;
    fake.lock().add_container("loner", "nginx");
    fake.calls();

    let stacks = within(stacks(&fake.client)).await.unwrap();
    assert_eq!(stacks.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["blog", "shop"]);
    let shop = &stacks[1];
    assert_eq!(shop.working_dir.as_deref(), Some(DIR));
    assert!(shop.config_files.is_empty(), "loaded from text, not a file");
    let containers: Vec<&str> = shop.containers.iter().map(|c| c.summary.name.as_str()).collect();
    assert_eq!(containers, ["shop-db-1", "shop-web-1"], "by service");

    let events = Recorder::default();
    let options = DownOptions { volumes: true, ..DownOptions::default() };
    within(down_project(&fake.client, "shop", &options, &events.sink())).await.unwrap();
    assert_eq!(
        fake.calls(),
        [
            "stop shop-web-1",
            "rm shop-web-1 -v",
            "stop shop-db-1",
            "rm shop-db-1 -v",
            "network rm shop_default",
            "volume rm shop_data",
        ],
        "dependents first, from the depends-on label"
    );
    let d = fake.lock();
    assert!(d.has_container("blog-app-1") && d.has_container("loner"));
    assert!(d.networks.iter().any(|n| n.name == "blog_default"));
}

#[tokio::test]
async fn scaling_down_removes_the_highest_numbers() {
    let fake = Fake::start(&["nginx"]);
    let scaled = |n: u32| compose(&fake, &format!("name: shop\nservices:\n  web:\n    image: nginx\n    scale: {n}\n"));
    up(&scaled(3)).await;
    assert_eq!(fake.calls()[1..].iter().filter(|c| c.starts_with("create")).count(), 3);

    let events = resources(&up(&scaled(1)).await);
    assert_eq!(fake.calls(), ["stop shop-web-3", "rm shop-web-3", "stop shop-web-2", "rm shop-web-2"]);
    assert!(events.contains(&"Container shop-web-1 Running".to_owned()), "the replica count isn't in the hash");

    up(&scaled(2)).await;
    assert_eq!(fake.calls(), ["create shop-web-2", "start shop-web-2"]);
    up(&scaled(0)).await;
    assert_eq!(fake.calls(), ["stop shop-web-2", "rm shop-web-2", "stop shop-web-1", "rm shop-web-1"]);
}

#[tokio::test]
async fn further_networks_are_connected_with_their_aliases_before_the_start() {
    let yaml = r#"
name: shop
services:
  web:
    image: nginx
    networks:
      front:
      back:
        aliases: [api]
        ipv4_address: 10.89.9.10
networks:
  front:
  back:
    internal: true
    ipam:
      config:
        - subnet: 10.89.9.0/24
"#;
    let fake = Fake::start(&["nginx"]);
    up(&compose(&fake, yaml)).await;
    assert_eq!(
        fake.calls(),
        [
            "network create shop_back",
            "network create shop_front",
            "create shop-web-1",
            "connect shop_back shop-web-1 aliases=web,api ip=10.89.9.10",
            "start shop-web-1",
        ]
    );
    let d = fake.lock();
    let web = d.container("shop-web-1");
    assert_eq!(web.config.network, NetworkMode::Network("shop_front".into()));
    assert!(web.config.extra_networks.is_empty(), "connected instead, with aliases");
    assert_eq!(web.endpoints[0].aliases, ["web"]);
    let back = d.network("shop_back");
    assert_eq!((back.subnet.as_str(), back.internal), ("10.89.9.0/24", true));
}

#[tokio::test]
async fn missing_images_are_pulled_unless_the_policy_says_never() {
    let yaml = "name: shop\nservices:\n  web:\n    image: nginx\n";
    let fake = Fake::start(&[]);
    let events = up(&compose(&fake, yaml)).await;
    assert_eq!(
        fake.calls(),
        ["network create shop_default", "pull nginx missing", "create shop-web-1", "start shop-web-1"]
    );
    assert!(before(&resources(&events), "Image nginx Pulling", "Image nginx Pulled"));
    let pulled: Vec<&ComposeEvent> = events.iter().filter(|e| matches!(e, ComposeEvent::Pull { .. })).collect();
    assert_eq!(pulled.len(), 2, "resolving, ready");
    assert!(matches!(pulled[0], ComposeEvent::Pull { service, image, .. } if service == "web" && image == "nginx"));

    // Present: only `always` asks again.
    up(&compose(&fake, yaml)).await;
    assert!(fake.calls().is_empty());
    up(&compose(&fake, &format!("{yaml}    pull_policy: always\n"))).await;
    assert_eq!(fake.calls(), ["pull nginx always"]);

    let fake = Fake::start(&[]);
    let (result, _) = up_with(&compose(&fake, &format!("{yaml}    pull_policy: never\n")), &UpOptions::default()).await;
    let e = result.unwrap_err().to_string();
    assert_eq!(e, "service \"web\": there is no image nginx, and it may not be pulled (pull_policy: never)");
    let (result, _) = up_with(&compose(&fake, &yaml.replace("nginx", "unpullable/app")), &UpOptions::default()).await;
    assert_eq!(result.unwrap_err().to_string(), "unpullable/app: not found in the registry");
}

#[tokio::test]
async fn a_present_image_isnt_built_again_and_no_build_pulls_a_missing_one() {
    let yaml = "name: shop\nservices:\n  web:\n    build: ./app\n";
    let fake = Fake::start(&["shop-web"]);
    up(&compose(&fake, yaml)).await;
    assert_eq!(fake.calls(), ["network create shop_default", "create shop-web-1", "start shop-web-1"]);

    let fake = Fake::start(&[]);
    let options = UpOptions { build: BuildPolicy::Never, ..UpOptions::default() };
    up_with(&compose(&fake, yaml), &options).await.0.unwrap();
    assert_eq!(fake.calls()[1], "pull shop-web missing");

    let fake = Fake::start(&[]);
    let never = format!("{yaml}    image: app\n    pull_policy: never\n");
    let (result, _) = up_with(&compose(&fake, &never), &options).await;
    assert!(result.unwrap_err().to_string().contains("neither built (--no-build) nor pulled (pull_policy: never)"));

    // Nothing to build for a service without a build section.
    let fake = Fake::start(&["nginx"]);
    let events = Recorder::default();
    within(compose(&fake, SHOP).build(&["web".into()], false, &events.sink())).await.unwrap();
    assert_eq!(warnings(&events.take()), ["service \"web\" has no build section: there is nothing to build"]);
}

#[tokio::test]
async fn orphans_are_reported_or_removed_and_profiles_make_none() {
    let fake = Fake::start(&["nginx", "postgres"]);
    up(&compose(&fake, SHOP)).await;
    let alone = compose(&fake, "name: shop\nservices:\n  web:\n    image: nginx\n");
    let events = up(&alone).await;
    assert_eq!(
        warnings(&events),
        ["Found orphan containers (shop-db-1) for this project. If you removed or renamed this service in your \
          compose file, you can run this command with the --remove-orphans flag to clean it up."]
    );
    assert!(fake.lock().has_container("shop-db-1"));
    fake.calls();
    up_with(&alone, &UpOptions { remove_orphans: true, ..UpOptions::default() }).await.0.unwrap();
    assert_eq!(fake.calls(), ["stop shop-db-1", "rm shop-db-1"]);

    // A service a profile leaves out has no orphans.
    let yaml = "name: shop\nservices:\n  web:\n    image: nginx\n  debug:\n    image: nginx\n    profiles: [debug]\n";
    let with_debug = LoadOptions { profiles: vec!["debug".into()], ..LoadOptions::default() };
    let debugging = Compose::new(fake.client.clone(), load_str(yaml, Path::new(DIR), &with_debug).unwrap());
    up(&debugging).await;
    assert!(fake.lock().has_container("shop-debug-1"));
    fake.calls();
    let events = up_with(&compose(&fake, yaml), &UpOptions { remove_orphans: true, ..UpOptions::default() }).await.1;
    assert!(fake.calls().is_empty() && warnings(&events).is_empty());
}

#[tokio::test]
async fn logs_merge_in_time_order_or_as_they_come() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let compose = compose(&fake, SHOP);
    up(&compose).await;
    let entry = |ts: &str, log: &str| LogEntry {
        ts: format!("2026-10-04T00:00:{ts}Z"),
        stream: LogStream::Stdout,
        log: log.into(),
    };
    fake.lock().logs.insert("shop-web-1".into(), vec![entry("00.25", "w1\n"), entry("01", "w2\n")]);
    fake.lock().logs.insert("shop-db-1".into(), vec![entry("00.5", "d1\n"), entry("00.75", "d2\n")]);

    let collect = |services: &'static [&'static str], follow: bool| {
        let compose = compose.clone();
        async move {
            let services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
            let query = LogsQuery { follow, ..LogsQuery::default() };
            let lines = within(compose.logs(&services, &query)).await.unwrap();
            within(lines.map(|l| l.unwrap()).collect::<Vec<_>>()).await
        }
    };
    let all = collect(&[], false).await;
    let texts: Vec<&str> = all.iter().map(|l| l.entry.log.as_str()).collect();
    assert_eq!(texts, ["w1\n", "d1\n", "d2\n", "w2\n"], "by time, whatever the digits");
    assert_eq!((all[1].service.as_str(), all[1].container.as_str()), ("db", "shop-db-1"));

    let web: Vec<String> = collect(&["web"], false).await.into_iter().map(|l| l.entry.log).collect();
    assert_eq!(web, ["w1\n", "w2\n"]);

    let mut followed: Vec<String> = collect(&[], true).await.into_iter().map(|l| l.entry.log).collect();
    followed.sort();
    assert_eq!(followed, ["d1\n", "d2\n", "w1\n", "w2\n"]);

    let Err(e) = within(compose.logs(&["nope".into()], &LogsQuery::default())).await else {
        panic!("logs of a service the project doesn't have");
    };
    assert_eq!(e.to_string(), "no such service: nope");
}

#[tokio::test]
async fn stop_takes_dependents_first_and_start_brings_dependencies() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let compose = compose(&fake, SHOP);
    up(&compose).await;
    fake.calls();
    let quiet = |_: ComposeEvent| {};

    within(compose.stop(&[], None, &quiet)).await.unwrap();
    assert_eq!(fake.calls(), ["stop shop-web-1", "stop shop-db-1"]);
    within(compose.start(&[], &quiet)).await.unwrap();
    assert_eq!(fake.calls(), ["start shop-db-1", "start shop-web-1"]);

    within(compose.stop(&["db".into()], Some(4), &quiet)).await.unwrap();
    assert_eq!(fake.calls(), ["stop shop-db-1 timeout=4"]);
    let events = Recorder::default();
    within(compose.start(&["web".into()], &events.sink())).await.unwrap();
    assert_eq!(fake.calls(), ["start shop-db-1"], "web's dependency, then web, which runs");
    assert_eq!(
        resources(&events.take()),
        ["Container shop-db-1 Starting", "Container shop-db-1 Started", "Container shop-web-1 Running"]
    );

    down_with(&compose, &DownOptions::default()).await;
    let e = within(compose.start(&[], &quiet)).await.unwrap_err();
    assert_eq!(e.to_string(), "service \"db\" has no container to start (up creates them)");
    assert_eq!(
        within(compose.stop(&["nope".into()], None, &quiet)).await.unwrap_err().to_string(),
        "no such service: nope"
    );
}

#[tokio::test]
async fn network_mode_service_shares_the_first_containers_namespace() {
    let yaml =
        "name: shop\nservices:\n  web:\n    image: nginx\n    network_mode: service:db\n  db:\n    image: postgres\n";
    let fake = Fake::start(&["nginx", "postgres"]);
    up(&compose(&fake, yaml)).await;
    assert_eq!(
        fake.calls(),
        ["network create shop_default", "create shop-db-1", "start shop-db-1", "create shop-web-1", "start shop-web-1"]
    );
    let d = fake.lock();
    let web = d.container("shop-web-1");
    assert_eq!(web.config.network, NetworkMode::Container("shop-db-1".into()));
    assert!(web.endpoints.is_empty() && web.config.network_aliases.is_empty());
}

#[tokio::test]
async fn down_removes_built_images_with_rmi_local_and_every_image_with_all() {
    let yaml = "name: shop\nservices:\n  web:\n    build: ./app\n  db:\n    image: postgres\n";
    for (which, removed) in [
        (rustlet_compose::RemoveImages::Local, vec!["rmi shop-web"]),
        (rustlet_compose::RemoveImages::All, vec!["rmi shop-web", "rmi postgres"]),
    ] {
        let fake = Fake::start(&["shop-web", "postgres"]);
        let compose = compose(&fake, yaml);
        up(&compose).await;
        fake.calls();
        let events = down_with(&compose, &DownOptions { images: Some(which), ..DownOptions::default() }).await;
        let calls = fake.calls();
        assert_eq!(calls[calls.len() - removed.len()..], removed);
        let events = resources(&events);
        assert!(events.contains(&"Image shop-web Removed".to_owned()), "{events:?}");
    }
}

#[test]
fn resource_events_name_their_kind_and_action() {
    let event =
        ComposeEvent::Resource { kind: ResourceKind::Container, name: "shop-web-1".into(), action: Action::Healthy };
    assert_eq!(resources(&[event]), ["Container shop-web-1 Healthy"]);
}

// ── what a change recreates ────────────────────────────────────────────────

/// A service that joins another's network namespace: web is in db's.
const SIDECAR: &str = "name: shop\nservices:\n  web:\n    image: nginx\n    network_mode: service:db\n  db:\n    image: postgres\n    environment: [V=1]\n";

fn calls_of(fake: &Fake, prefix: &str) -> Vec<String> {
    fake.calls().into_iter().filter(|c| c.starts_with(prefix)).collect()
}

// `network_mode: service:db` puts web in db's network namespace. When `up`
// recreates db, Compose recreates web too: it resolves `service:db` to
// `container:<db's id>` before it hashes web, so a new db makes a new hash
// (docker/compose v2.29.7 pkg/compose/convergence.go `ensureService`:
// `resolveServiceReferences` → `resolveSharedNamespaces` before
// `mustRecreate`; main: reconcile.go `parentNamespaceRecreated`, "so the
// cascade fires only when a stale container:<id> reference would otherwise
// be left behind"). rustletd ties web to the namespace by db's id at create
// (lifecycle.rs `network_container`), tears the namespace's interfaces down
// when db goes, and refuses to start web again once the container it joined
// is gone (network.rs `attach_network`). And without a change, neither is
// touched: the id in the hash is the same until db is recreated.
#[tokio::test]
async fn a_service_joining_a_namespace_is_recreated_with_its_target() {
    let fake = Fake::start(&["nginx", "postgres"]);
    up(&compose(&fake, SIDECAR)).await;
    assert_eq!(
        fake.calls(),
        ["network create shop_default", "create shop-db-1", "start shop-db-1", "create shop-web-1", "start shop-web-1"]
    );
    // web's label is the hash with db's id in it, not the file's alone.
    let web_hash = |fake: &Fake| fake.lock().container("shop-web-1").config.labels[LABEL_CONFIG_HASH].clone();
    let db_id = |fake: &Fake| fake.lock().container("shop-db-1").id.clone();
    let shop = project(SIDECAR);
    let web = shop.service("web").unwrap();
    assert_eq!(web_hash(&fake), web.effective_hash(Some(&db_id(&fake))));
    assert_ne!(web_hash(&fake), web.config_hash());
    // db's own hash is the file's: only what joins a namespace has the id in it.
    let db_hash = fake.lock().container("shop-db-1").config.labels[LABEL_CONFIG_HASH].clone();
    assert_eq!(db_hash, shop.service("db").unwrap().config_hash());

    // Nothing changed: nothing is recreated, however often `up` is run.
    for _ in 0..2 {
        up(&compose(&fake, SIDECAR)).await;
        assert!(fake.calls().is_empty());
    }

    // db changed: it is recreated, and web after it, into the new container.
    let old_db = db_id(&fake);
    let changed = SIDECAR.replace("V=1", "V=2");
    up(&compose(&fake, &changed)).await;
    assert_eq!(
        fake.calls(),
        [
            "stop shop-db-1",
            "rm shop-db-1",
            "create shop-db-1",
            "start shop-db-1",
            "stop shop-web-1",
            "rm shop-web-1",
            "create shop-web-1",
            "start shop-web-1",
        ]
    );
    assert_ne!(db_id(&fake), old_db);
    assert_eq!(web_hash(&fake), project(&changed).service("web").unwrap().effective_hash(Some(&db_id(&fake))));
    up(&compose(&fake, &changed)).await;
    assert!(fake.calls().is_empty(), "and then it is stable again");

    // The same when db is recreated for another reason: its image changed, or it is forced as a dependency.
    fake.lock().images.insert("postgres".into(), "sha256:rebuilt".into());
    up(&compose(&fake, &changed)).await;
    assert_eq!(calls_of(&fake, "create"), ["create shop-db-1", "create shop-web-1"]);
    let forced_dependency =
        UpOptions { services: vec!["web".into()], always_recreate_deps: true, ..UpOptions::default() };
    up_with(&compose(&fake, &changed), &forced_dependency).await.0.unwrap();
    assert_eq!(calls_of(&fake, "create"), ["create shop-db-1", "create shop-web-1"]);
    // `up db` brings web along no more than Compose's does (it is not what db depends on): web is left
    // as it was until the next `up` that has it, which puts it in the new namespace.
    let force_db = UpOptions { services: vec!["db".into()], force_recreate: true, ..UpOptions::default() };
    up_with(&compose(&fake, &changed), &force_db).await.0.unwrap();
    assert_eq!(calls_of(&fake, "create"), ["create shop-db-1"]);
    up(&compose(&fake, &changed)).await;
    assert_eq!(calls_of(&fake, "create"), ["create shop-web-1"]);

    // `--no-recreate` leaves both, whatever happened to db.
    let keep = UpOptions { no_recreate: true, ..UpOptions::default() };
    up_with(&compose(&fake, SIDECAR), &keep).await.0.unwrap();
    assert!(fake.calls().is_empty());
}

// Compose refuses to share a namespace with a service that has no container
// ("cannot share network namespace with service %s: container missing"); so
// does `up`, before it creates the service that would join it.
#[tokio::test]
async fn a_service_cannot_join_the_namespace_of_a_service_with_no_container() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let yaml = SIDECAR.replace("    environment: [V=1]\n", "    scale: 0\n");
    let (result, _) = up_with(&compose(&fake, &yaml), &UpOptions::default()).await;
    match result {
        Err(Error::Dependency(m)) => {
            assert_eq!(m, "cannot share the network namespace of service \"db\" with \"web\": it has no container")
        }
        other => panic!("{other:?}"),
    }
    assert!(!fake.lock().has_container("shop-web-1"));
}

// `--force-recreate` is for the services named on the command line (all of
// them when none is); what they depend on gets the dependencies' strategy,
// "diverged": recreated only if it changed, unless `--always-recreate-deps`
// (docker/compose cmd/compose/create.go `recreateStrategy` and
// `dependenciesRecreateStrategy`; pkg/compose/convergence.go `apply`, v2.29.7:
// `strategy := options.RecreateDependencies; if contains(options.Services,
// name) { strategy = options.Recreate }`; main: reconcile.go
// `reconcileService`). Recreating a database that wasn't asked for orphans its
// anonymous volumes; and with no service named, all are named
// (`options.Services = project.ServiceNames()`), so `--always-recreate-deps`
// adds nothing then.
#[tokio::test]
async fn force_recreate_is_for_the_services_named_and_their_dependencies_have_a_flag_of_their_own() {
    let fake = Fake::start(&["nginx", "postgres"]);
    let shop = compose(&fake, SHOP);
    up(&shop).await;
    fake.calls();
    let up_removing = |options: UpOptions| {
        let shop = shop.clone();
        let fake = &fake;
        async move {
            up_with(&shop, &options).await.0.unwrap();
            calls_of(fake, "rm ")
        }
    };
    let named = vec!["web".to_owned()];

    // web is named: forced; its unchanged dependency db stays.
    let forced = UpOptions { services: named.clone(), force_recreate: true, ..UpOptions::default() };
    assert_eq!(up_removing(forced).await, ["rm shop-web-1"]);
    // None named: all are.
    let forced = UpOptions { force_recreate: true, ..UpOptions::default() };
    assert_eq!(up_removing(forced).await, ["rm shop-db-1", "rm shop-web-1"]);
    // The dependencies' flag: what web brings along, not web.
    let deps = UpOptions { services: named.clone(), always_recreate_deps: true, ..UpOptions::default() };
    assert_eq!(up_removing(deps).await, ["rm shop-db-1"]);
    // Both: everything.
    let both =
        UpOptions { services: named.clone(), force_recreate: true, always_recreate_deps: true, ..UpOptions::default() };
    assert_eq!(up_removing(both).await, ["rm shop-db-1", "rm shop-web-1"]);
    // With nothing named, every service is named, and there is nothing else to bring along.
    let deps = UpOptions { always_recreate_deps: true, ..UpOptions::default() };
    assert!(up_removing(deps).await.is_empty());
    // Named: db, which web doesn't bring along, as it depends on db and not the other way round.
    let forced = UpOptions { services: vec!["db".into()], force_recreate: true, ..UpOptions::default() };
    assert_eq!(up_removing(forced).await, ["rm shop-db-1"]);

    // Neither goes with `--no-recreate`.
    let both = UpOptions { no_recreate: true, always_recreate_deps: true, ..UpOptions::default() };
    assert!(up_with(&shop, &both).await.0.unwrap_err().to_string().contains("can't go together"));
}

// Known limitation: a container is recreated by removing the old one and
// then creating the new, where Compose creates the new one first, under a
// temporary name, and renames it (docker/compose v2.29.7
// pkg/compose/convergence.go `recreateContainer`). rustletd has no rename,
// and checks a container's options only at create (lifecycle.rs
// `spec::check`: an unknown capability, a bad signal or device…): so a
// replacement it refuses leaves the service without a container, which the
// next `up` creates once the file is right. (The fake refuses a create whose
// image isn't there, which stands for any refusal.) See `Compose::recreate`.
#[tokio::test]
async fn a_recreate_the_daemon_refuses_leaves_the_service_without_a_container() {
    let yaml = "name: shop\nservices:\n  web:\n    image: nginx\n";
    let fake = Fake::start(&["nginx"]);
    up(&compose(&fake, yaml)).await;
    fake.calls();

    let mut refused = project("name: shop\nservices:\n  web:\n    image: nginx\n    environment: [V=2]\n");
    refused.services[0].config.image = "refused".into();
    let (result, _) = up_with(&Compose::new(fake.client.clone(), refused), &UpOptions::default()).await;
    assert!(result.is_err(), "the daemon refuses the new container");
    assert_eq!(fake.calls(), ["stop shop-web-1", "rm shop-web-1"]);
    assert!(!fake.lock().has_container("shop-web-1"));

    up(&compose(&fake, "name: shop\nservices:\n  web:\n    image: nginx\n    environment: [V=3]\n")).await;
    assert_eq!(fake.calls(), ["create shop-web-1", "start shop-web-1"]);
}

// ── services named on the command line, and profiles ───────────────────────

// A service named on the command line is enabled together with its profiles:
// `docker compose up debug`, `logs debug`, `stop debug`, `ps debug` work with
// `debug` in a profile nobody asked for (docker/compose cmd/compose/compose.go
// v2.29.7 `project.WithServicesEnabled(services...)`; main:
// pkg/compose/loader.go; the Compose docs, "Auto-enabling profiles and
// dependency resolution"). `load_selected` is how a command says which.
#[tokio::test]
async fn a_service_in_an_inactive_profile_is_up_when_named() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "name: shop\nservices:\n  web:\n    image: nginx\n  debug:\n    image: nginx\n    profiles: [debug]\n    depends_on: [web]\n";
    std::fs::write(dir.path().join("compose.yaml"), yaml).unwrap();
    let options = LoadOptions { files: vec![dir.path().join("compose.yaml")], ..LoadOptions::default() };
    let fake = Fake::start(&["nginx"]);
    let named = vec!["debug".to_owned()];
    let debug = Compose::new(fake.client.clone(), load_selected(&options, &named).unwrap());

    let up_debug = UpOptions { services: named.clone(), ..UpOptions::default() };
    up_with(&debug, &up_debug).await.0.unwrap();
    assert_eq!(
        fake.calls(),
        [
            "network create shop_default",
            "create shop-web-1",
            "start shop-web-1",
            "create shop-debug-1",
            "start shop-debug-1"
        ],
        "debug, and web, which it depends on"
    );
    // `ps`, `stop`, `start` and `logs` find it by name too.
    let names = |c: Vec<rustlet_compose::ServiceContainer>| c.into_iter().map(|c| c.summary.name).collect::<Vec<_>>();
    assert_eq!(names(within(debug.ps(false)).await.unwrap()), ["shop-web-1", "shop-debug-1"]);
    within(debug.stop(&named, None, &|_: ComposeEvent| {})).await.unwrap();
    assert_eq!(fake.calls(), ["stop shop-debug-1"]);
    within(debug.start(&named, &|_: ComposeEvent| {})).await.unwrap();
    assert_eq!(fake.calls(), ["start shop-debug-1"]);
    assert!(within(debug.logs(&named, &LogsQuery::default())).await.is_ok());

    // Without the name, the project doesn't have it, and what is left of it is no orphan.
    let plain = Compose::new(fake.client.clone(), load(&options).unwrap());
    let (result, events) = up_with(&plain, &UpOptions { remove_orphans: true, ..UpOptions::default() }).await;
    result.unwrap();
    assert!(fake.calls().is_empty() && warnings(&events).is_empty(), "debug is a service the file has");
    let e = within(plain.logs(&named, &LogsQuery::default())).await.err().unwrap();
    assert_eq!(e.to_string(), "no such service: debug");
}

// ── down: what the file says is external ───────────────────────────────────

// `down -v` removes "the named volumes the file declares (not external
// ones)" (`DownOptions::volumes`; docker/compose pkg/compose/down.go
// `ensureVolumesDown` goes over the project's volumes and skips the
// external). A volume an earlier `up` made, which the file now declares
// external so as to keep it, survives, label or not.
#[tokio::test]
async fn down_v_keeps_a_volume_the_file_declares_external() {
    let fake = Fake::start(&["nginx", "postgres"]);
    up(&compose(&fake, SHOP)).await;
    assert!(fake.lock().volume("shop_data").is_some());

    let keep = SHOP.replace("volumes:\n  data:\n", "volumes:\n  data:\n    external: true\n    name: shop_data\n");
    assert!(project(&keep).volumes["data"].external);
    down_with(&compose(&fake, &keep), &DownOptions { volumes: true, ..DownOptions::default() }).await;
    assert!(fake.lock().volume("shop_data").is_some(), "an external volume is never the project's to remove");
    // Without the file, a volume with the project's label is the project's.
    up(&compose(&fake, SHOP)).await;
    within(down_project(&fake.client, "shop", &DownOptions { volumes: true, ..DownOptions::default() }, &|_| {}))
        .await
        .unwrap();
    assert!(fake.lock().volume("shop_data").is_none());
}

// `down` removes the project's networks, "not external ones" (`Compose::down`;
// docker/compose down.go `ensureNetworksDown` skips the external): a network
// an earlier `up` made, which the file now declares external, stays, and the
// next `up` finds it.
#[tokio::test]
async fn down_keeps_a_network_the_file_declares_external() {
    let fake = Fake::start(&["nginx", "postgres"]);
    up(&compose(&fake, SHOP)).await;

    let external = format!("{SHOP}networks:\n  default:\n    external: true\n    name: shop_default\n");
    let shop = compose(&fake, &external);
    down_with(&shop, &DownOptions::default()).await;
    assert!(fake.lock().networks.iter().any(|n| n.name == "shop_default"), "an external network stays");
    let (result, _) = up_with(&shop, &UpOptions::default()).await;
    assert!(result.is_ok(), "up after down: {result:?}");
}

#[tokio::test]
async fn down_v_preserves_external_resources_after_their_attachments_are_removed() {
    let fake = Fake::start(&["nginx"]);
    let yaml = "name: shop\nservices:\n  app:\n    image: nginx\n    volumes: [data:/data]\n    networks: [legacy]\nvolumes:\n  data:\nnetworks:\n  legacy:\n";
    up(&compose(&fake, yaml)).await;
    fake.calls();
    let changed = "name: shop\nservices:\n  app:\n    image: nginx\nvolumes:\n  data:\n    external: true\n    name: shop_data\nnetworks:\n  legacy:\n    external: true\n    name: shop_legacy\n";
    down_with(&compose(&fake, changed), &DownOptions { volumes: true, ..DownOptions::default() }).await;
    let d = fake.lock();
    assert!(d.volume("shop_data").is_some());
    assert!(d.networks.iter().any(|n| n.name == "shop_legacy"));
    assert_eq!(d.calls, ["stop shop-app-1", "rm shop-app-1 -v"]);
}

#[tokio::test]
async fn up_does_not_create_or_require_unused_declared_resources() {
    let fake = Fake::start(&["nginx"]);
    let yaml = "name: shop\nservices:\n  app:\n    image: nginx\nvolumes:\n  unused:\n    external: true\n  internal:\nnetworks:\n  unused:\n    external: true\n  internal:\n";
    up(&compose(&fake, yaml)).await;
    assert_eq!(fake.calls(), ["network create shop_default", "create shop-app-1", "start shop-app-1"]);
}

#[tokio::test]
async fn a_service_using_a_shared_image_does_not_suppress_its_build() {
    let fake = Fake::start(&["custom"]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Containerfile"), "FROM scratch\n").unwrap();
    let yaml = "name: shop\nservices:\n  app:\n    image: custom\n  worker:\n    image: custom\n    build: .\n  other:\n    image: custom\n";
    let project = load_str(yaml, dir.path(), &LoadOptions::default()).unwrap();
    let compose = Compose::new(fake.client.clone(), project);
    let options = UpOptions { build: BuildPolicy::Always, ..UpOptions::default() };
    let (result, events) = up_with(&compose, &options).await;
    result.unwrap();
    assert_eq!(
        fake.calls().iter().filter(|c| c.starts_with("build ")).collect::<Vec<_>>(),
        [&"build custom".to_owned()]
    );
    assert!(events.iter().any(|e| matches!(e, ComposeEvent::Build { service, event: rustlet_spec::build::BuildEvent::Done { .. } } if service == "worker")));
}

#[tokio::test]
async fn a_build_stream_without_done_cannot_start_a_stale_image() {
    let fake = Fake::start(&["custom"]);
    fake.lock().build_events =
        Some(vec![rustlet_spec::build::BuildEvent::Step { step: 1, total: 1, instruction: "FROM scratch".into() }]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Containerfile"), "FROM scratch\n").unwrap();
    let project = load_str(
        "name: shop\nservices:\n  worker:\n    image: custom\n    build: .\n",
        dir.path(),
        &LoadOptions::default(),
    )
    .unwrap();
    let compose = Compose::new(fake.client.clone(), project);
    let options = UpOptions { build: BuildPolicy::Always, ..UpOptions::default() };
    let (result, events) = up_with(&compose, &options).await;
    assert!(result.unwrap_err().to_string().contains("ended without storing an image"));
    assert!(!fake.lock().has_container("shop-worker-1"));
    assert!(!events.iter().any(|e| matches!(e, ComposeEvent::Resource { action: Action::Built, .. })));
}
