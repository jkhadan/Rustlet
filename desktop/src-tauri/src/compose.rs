//! Compose projects ("stacks"): the ones the daemon has containers of, and
//! `up` and `down`.
//!
//! Compose is client-side, as in Compose v2: the daemon knows nothing of
//! projects, only of containers, networks and volumes that carry a
//! project's labels. So the app does what the CLI does, through the same
//! library (`rustlet-compose`): it reads the compose file, then creates
//! and starts what the file asks for, in dependency order, over the API.
//!
//! ```text
//!  Stacks view                      this module                       rustletd
//!  stack_list ────────────────────► run::stacks: containers by label ─► GET /containers?all
//!  compose_up(files, name, dir) ──► load (the app's environment, .env)
//!            ◄── stream id ──────── Compose::up, in a task of its own ─► networks, volumes, pulls,
//!  onmessage({items: [progress]}) ◄─ ComposeEvents, batched                builds, containers
//!  compose_down(project) ─────────► run::down_project ────────────────► stop, rm, network rm
//! ```
//!
//! The library's types aren't `Serialize` (they are its own, not the
//! API's): the shapes the frontend gets are this module's, pinned by its
//! tests and written out by hand in `src/lib/ipc.ts`.

use std::collections::BTreeMap;

use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use rustlet_client::Client;
use rustlet_compose::run::{Action, ResourceKind};
use rustlet_compose::{ComposeEvent, Condition, DownOptions, LoadOptions, UpOptions};
use rustlet_spec::build::BuildEvent;
use rustlet_spec::container::ContainerSummary;
use rustlet_spec::image::PullEvent;
use serde::Serialize;

use crate::error::{CommandError, CommandResult};
use crate::paths;

/// A project the daemon has containers of.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Stack {
    pub name: String,
    /// Where it was brought up from (its containers' label), if they say.
    pub working_dir: Option<String>,
    /// The compose files it was brought up from, absolute: what "up" again
    /// loads. Empty when its containers don't say.
    pub config_files: Vec<String>,
    /// By service, then number.
    pub containers: Vec<StackContainer>,
}

/// One container of a stack.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StackContainer {
    pub service: String,
    /// From 1, within its service.
    pub number: u32,
    pub container: ContainerSummary,
}

impl From<rustlet_compose::Stack> for Stack {
    fn from(s: rustlet_compose::Stack) -> Stack {
        Stack {
            name: s.name,
            working_dir: s.working_dir,
            config_files: s.config_files,
            containers: s
                .containers
                .into_iter()
                .map(|c| StackContainer { service: c.service, number: c.number, container: c.summary })
                .collect(),
        }
    }
}

/// What `up` reports as it goes: [`ComposeEvent`], as the frontend gets it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ComposeProgress {
    /// A network, volume, container or image changed state.
    Resource {
        kind: &'static str,
        name: String,
        action: &'static str,
    },
    /// A service's image is being built.
    Build {
        service: String,
        event: BuildEvent,
    },
    /// A service's image is being pulled.
    Pull {
        service: String,
        image: String,
        event: PullEvent,
    },
    /// `service` waits for its dependency `on` to reach `condition`
    /// (`started`, `healthy`, `completed_successfully`).
    Waiting {
        service: String,
        on: String,
        condition: Condition,
    },
    Warning {
        message: String,
    },
}

impl From<ComposeEvent> for ComposeProgress {
    fn from(e: ComposeEvent) -> ComposeProgress {
        match e {
            ComposeEvent::Resource { kind, name, action } => {
                ComposeProgress::Resource { kind: kind_name(kind), name, action: action_name(action) }
            }
            ComposeEvent::Build { service, event } => ComposeProgress::Build { service, event },
            ComposeEvent::Pull { service, image, event } => ComposeProgress::Pull { service, image, event },
            ComposeEvent::Waiting { service, on, condition } => ComposeProgress::Waiting { service, on, condition },
            ComposeEvent::Warning(message) => ComposeProgress::Warning { message },
        }
    }
}

fn kind_name(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Network => "network",
        ResourceKind::Volume => "volume",
        ResourceKind::Container => "container",
        ResourceKind::Image => "image",
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Creating => "creating",
        Action::Created => "created",
        Action::Running => "running",
        Action::Recreating => "recreating",
        Action::Recreated => "recreated",
        Action::Starting => "starting",
        Action::Started => "started",
        Action::Healthy => "healthy",
        Action::Exited => "exited",
        Action::Stopping => "stopping",
        Action::Stopped => "stopped",
        Action::Removing => "removing",
        Action::Removed => "removed",
        Action::Building => "building",
        Action::Built => "built",
        Action::Pulling => "pulling",
        Action::Pulled => "pulled",
    }
}

/// A compose failure as the frontend gets it: the daemon's own errors keep
/// their kinds (`unreachable`, `conflict`, …); a file that doesn't parse,
/// or asks for something wrong, is `invalid`.
pub fn error(e: rustlet_compose::Error) -> CommandError {
    use rustlet_compose::Error;
    match e {
        Error::Client(e) => e.into(),
        Error::Parse(m) | Error::Invalid(m) => CommandError::invalid(m),
        e @ Error::Context(_) => CommandError::invalid(e.to_string()),
        e @ (Error::Io { .. } | Error::Dependency(_)) => CommandError::failed(e.to_string()),
    }
}

/// The app's environment, which `${VAR}` in a compose file reads, as the
/// CLI's reads its shell's. A variable that isn't UTF-8 is left out:
/// nothing could put it into a file's text (and `std::env::vars` would
/// panic on it).
pub fn app_env() -> BTreeMap<String, String> {
    std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect()
}

/// Every stack the daemon has containers of.
pub async fn list(client: &Client) -> CommandResult<Vec<Stack>> {
    let stacks = rustlet_compose::run::stacks(client).await.map_err(error)?;
    Ok(stacks.into_iter().map(Stack::from).collect())
}

/// What to load: `files` (at least one: the app has no working directory
/// to look for a `compose.yaml` in), the project's name (else the file's
/// `name:`, … as the CLI decides it) and directory (else the first file's),
/// interpolated with `env`, the app's environment, as the CLI's is its
/// shell's.
pub fn load_options(
    files: &[String],
    project_name: Option<String>,
    project_dir: Option<String>,
    env: BTreeMap<String, String>,
) -> CommandResult<LoadOptions> {
    let files = files
        .iter()
        .filter(|f| !f.trim().is_empty())
        .map(|f| paths::user_path(f))
        .collect::<CommandResult<Vec<_>>>()?;
    if files.is_empty() {
        return Err(CommandError::invalid("name a compose file (compose.yaml, docker-compose.yml, …)"));
    }
    let project_dir = project_dir.filter(|d| !d.trim().is_empty()).map(|d| paths::user_path(&d)).transpose()?;
    let project_name = project_name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
    Ok(LoadOptions { files, project_dir, project_name, env, profiles: Vec::new() })
}

/// Loads the project, then brings it up (`compose up -d`: no logs
/// followed) in a task of its own, whose progress, then failure if it
/// fails, come out of the returned stream; it ends when the project is up.
/// A file that can't be loaded fails this, before anything is created.
///
/// The task runs to its end whether or not the stream is followed (a
/// dialog closed, a page reloaded): a project left half up, its first
/// services started and the rest never created, is worse than one that
/// comes up while nobody watches, as rustletd runs a pull to its end.
pub async fn up(
    client: Client,
    options: LoadOptions,
) -> CommandResult<UnboundedReceiver<Result<ComposeProgress, CommandError>>> {
    let project = tokio::task::spawn_blocking(move || rustlet_compose::load(&options))
        .await
        .map_err(|e| CommandError::failed(format!("loading the compose file failed: {e}")))?
        .map_err(error)?;
    let (tx, rx) = unbounded();
    tauri::async_runtime::spawn(async move {
        let name = project.name.clone();
        let compose = rustlet_compose::Compose::new(client, project);
        // A follower that has gone leaves the sends failing: the up goes on.
        let report = |event: ComposeEvent| {
            let _ = tx.unbounded_send(Ok(event.into()));
        };
        match compose.up(&UpOptions::default(), &report).await {
            Ok(()) => tracing::info!(project = %name, "compose up: done"),
            Err(e) => {
                tracing::info!(project = %name, "compose up: {e}");
                let _ = tx.unbounded_send(Err(error(e)));
            }
        }
    });
    Ok(rx)
}

/// `compose -p PROJECT down`: the project's containers and networks, found
/// by their labels (no file needed), and with `volumes` its volumes.
pub async fn down(client: &Client, project: &str, volumes: bool) -> CommandResult<()> {
    let options = DownOptions { volumes, ..DownOptions::default() };
    // Nobody watches a down: the stack's card follows the daemon's events.
    let log = |event: ComposeEvent| tracing::debug!(project, ?event, "compose down");
    rustlet_compose::run::down_project(client, project, &options, &log).await.map_err(error)
}

#[cfg(test)]
mod tests {
    use std::io;

    use rustlet_compose::ServiceContainer;
    use rustlet_spec::ErrorKind;
    use rustlet_spec::container::{ContainerState, ContainerStatus, HealthStatus};
    use serde_json::json;

    use super::*;

    #[test]
    fn a_stack_keeps_its_containers_whole_by_service_and_number() {
        let summary = ContainerSummary {
            id: "c0ffee".into(),
            name: "hits-web-1".into(),
            state: ContainerState { status: ContainerStatus::Running, ..ContainerState::default() },
            ..ContainerSummary::default()
        };
        let stack = rustlet_compose::Stack {
            name: "hits".into(),
            working_dir: Some("/home/u/hits".into()),
            config_files: vec!["/home/u/hits/compose.yaml".into()],
            containers: vec![ServiceContainer { service: "web".into(), number: 1, summary: summary.clone() }],
        };
        let json = serde_json::to_value(Stack::from(stack)).unwrap();
        assert_eq!(json["name"], "hits");
        assert_eq!(json["working_dir"], "/home/u/hits");
        assert_eq!(json["config_files"], json!(["/home/u/hits/compose.yaml"]));
        assert_eq!(json["containers"][0]["service"], "web");
        assert_eq!(json["containers"][0]["number"], 1);
        // The API's own summary, as `container_list` gives it.
        assert_eq!(json["containers"][0]["container"], serde_json::to_value(&summary).unwrap());
        assert_eq!(json.as_object().unwrap().len(), 4);
        assert_eq!(json["containers"][0].as_object().unwrap().len(), 3);
    }

    #[test]
    fn a_stack_whose_containers_dont_say_where_it_came_from() {
        let stack =
            rustlet_compose::Stack { name: "x".into(), working_dir: None, config_files: vec![], containers: vec![] };
        assert_eq!(
            serde_json::to_value(Stack::from(stack)).unwrap(),
            json!({"name": "x", "working_dir": null, "config_files": [], "containers": []})
        );
    }

    #[test]
    fn progress_is_tagged_by_type() {
        let p = |e: ComposeEvent| serde_json::to_value(ComposeProgress::from(e)).unwrap();
        let created = ComposeEvent::Resource {
            kind: ResourceKind::Network,
            name: "hits_default".into(),
            action: Action::Created,
        };
        assert_eq!(
            p(created),
            json!({"type": "resource", "kind": "network", "name": "hits_default", "action": "created"})
        );
        let waiting =
            ComposeEvent::Waiting { service: "web".into(), on: "redis".into(), condition: Condition::Healthy };
        assert_eq!(p(waiting), json!({"type": "waiting", "service": "web", "on": "redis", "condition": "healthy"}));
        let waiting = ComposeEvent::Waiting {
            service: "app".into(),
            on: "migrate".into(),
            condition: Condition::CompletedSuccessfully,
        };
        assert_eq!(p(waiting)["condition"], "completed_successfully");
        assert_eq!(p(ComposeEvent::Warning("x".into())), json!({"type": "warning", "message": "x"}));
        let build = ComposeEvent::Build { service: "web".into(), event: BuildEvent::Cached { step: 3 } };
        assert_eq!(p(build), json!({"type": "build", "service": "web", "event": {"type": "cached", "step": 3}}));
        let pull = ComposeEvent::Pull {
            service: "redis".into(),
            image: "redis:7-alpine".into(),
            event: PullEvent::Resolving { reference: "redis:7-alpine".into() },
        };
        assert_eq!(
            p(pull),
            json!({"type": "pull", "service": "redis", "image": "redis:7-alpine",
                   "event": {"status": "resolving", "reference": "redis:7-alpine"}})
        );
    }

    #[test]
    fn every_resource_kind_and_action_has_its_word() {
        let kinds = [ResourceKind::Network, ResourceKind::Volume, ResourceKind::Container, ResourceKind::Image];
        assert_eq!(kinds.map(kind_name), ["network", "volume", "container", "image"]);
        let actions = [
            (Action::Creating, "creating"),
            (Action::Recreated, "recreated"),
            (Action::Healthy, "healthy"),
            (Action::Exited, "exited"),
            (Action::Removed, "removed"),
            (Action::Pulled, "pulled"),
        ];
        for (a, word) in actions {
            assert_eq!(action_name(a), word);
        }
        // The health words are the API's.
        assert_eq!(action_name(Action::Healthy), HealthStatus::Healthy.to_string());
    }

    #[test]
    fn errors_keep_the_daemons_kinds_and_a_bad_file_is_invalid() {
        let e = error(rustlet_compose::Error::Client(rustlet_client::Error::api(ErrorKind::Conflict, "name in use")));
        assert_eq!((e.kind.as_str(), e.message.as_str()), ("conflict", "name in use"));
        let e = error(rustlet_compose::Error::Parse("compose.yaml: line 3: expected a mapping".into()));
        assert_eq!(e, CommandError::invalid("compose.yaml: line 3: expected a mapping"));
        assert_eq!(error(rustlet_compose::Error::Invalid("a dependency cycle".into())).kind, "invalid");
        let e = error(rustlet_compose::Error::Io {
            path: "/x/compose.yaml".into(),
            source: io::ErrorKind::NotFound.into(),
        });
        assert_eq!(e.kind, "failed");
        assert!(e.message.starts_with("/x/compose.yaml: "), "{e:?}");
        let e = error(rustlet_compose::Error::Dependency("redis is unhealthy".into()));
        assert_eq!(e, CommandError::failed("redis is unhealthy"));
    }

    #[test]
    fn a_project_is_loaded_from_the_files_named_with_the_apps_environment() {
        let env: BTreeMap<String, String> = [("TAG".to_owned(), "1".to_owned())].into();
        let o = load_options(
            &["/srv/hits/compose.yaml".into(), " ".into(), "/srv/hits/compose.override.yaml".into()],
            Some(" hits ".into()),
            Some("/srv/hits".into()),
            env.clone(),
        )
        .unwrap();
        assert_eq!(
            o.files,
            ["/srv/hits/compose.yaml", "/srv/hits/compose.override.yaml"].map(std::path::PathBuf::from)
        );
        assert_eq!(o.project_name.as_deref(), Some("hits"));
        assert_eq!(o.project_dir, Some("/srv/hits".into()));
        assert_eq!(o.env, env);
        let o = load_options(&["/srv/hits/compose.yaml".into()], Some("".into()), Some(" ".into()), env).unwrap();
        assert_eq!((o.project_name, o.project_dir), (None, None));
    }

    #[test]
    fn interpolation_sees_the_apps_environment() {
        let env = app_env();
        for (k, v) in std::env::vars_os() {
            if let (Some(k), Some(v)) = (k.to_str(), v.to_str()) {
                assert_eq!(env.get(k).map(String::as_str), Some(v), "{k}");
            }
        }
    }

    #[test]
    fn a_project_needs_a_file_named_by_an_absolute_path() {
        let e = load_options(&[], None, None, BTreeMap::new()).unwrap_err();
        assert_eq!(e.kind, "invalid");
        assert!(e.message.contains("compose file"), "{e:?}");
        assert_eq!(load_options(&["compose.yaml".into()], None, None, BTreeMap::new()).unwrap_err().kind, "invalid");
        let e = load_options(&["/a/compose.yaml".into()], None, Some("rel".into()), BTreeMap::new()).unwrap_err();
        assert!(e.message.starts_with("rel: "), "{e:?}");
    }
}
