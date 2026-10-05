//! # rustlet-compose: multi-container applications from one file
//!
//! ```text
//!  compose.yaml ──load──► Project ──Compose::up──► rustletd (networks, volumes, builds,
//!   + .env, -f overrides      services in              containers, in dependency order,
//!   + ${VAR} interpolation    dependency order          waiting for health)
//! ```
//!
//! Client-side, as Docker's Compose v2: the daemon knows nothing of
//! projects. A project's state is its resources' **labels**: every
//! container, network and volume `up` makes carries [`LABEL_PROJECT`] (and
//! containers [`LABEL_SERVICE`], [`LABEL_NUMBER`], [`LABEL_CONFIG_HASH`]),
//! and `ps`, `down` and the desktop app's stacks find them by those. A
//! container whose config hash still matches its service is left running
//! by the next `up`; one whose service changed is recreated (and so is one
//! that shares the network namespace of a container that was).
//!
//! | module | what |
//! |---|---|
//! | `model` | the compose file as written (the supported subset of the Compose Specification) |
//! | `interpolate` | `${VAR}`, `${VAR:-default}`, … from the environment and `.env` |
//! | `load` | files (`-f`, `COMPOSE_FILE`, the default ones) → [`project::Project`]: defaults, overrides, names, paths |
//! | `project` | the normalized project: each service's `ContainerConfig`, networks, volumes, dependencies |
//! | `run` | `up`, `down`, `ps`, `logs`, `build`, `stop`, `start` against rustletd |
//!
//! Names follow Compose v2: containers `<project>-<service>-<n>`, networks
//! `<project>_<network>` (`<project>_default` for services that name
//! none), volumes `<project>_<volume>`, images built for a service without
//! an `image:` `<project>-<service>`.
#![forbid(unsafe_code)]

pub mod interpolate;
pub mod load;
pub mod model;
pub mod project;
pub mod run;

pub use load::{LoadOptions, given_project_name, has_config_file, load, load_selected, load_str};
pub use project::{Condition, Dependency, Project, Service};
pub use run::{
    Action, BuildPolicy, Compose, ComposeEvent, DownOptions, Events, LogLine, RemoveImages, ResourceKind,
    ServiceContainer, Stack, UpOptions, down_project, stacks,
};

/// Every container, network and volume of a project: its name.
pub const LABEL_PROJECT: &str = "io.rustlet.compose.project";
/// A container's service.
pub const LABEL_SERVICE: &str = "io.rustlet.compose.service";
/// A container's number within its service, from 1.
pub const LABEL_NUMBER: &str = "io.rustlet.compose.container-number";
/// A hash of what the container was created from
/// ([`project::Service::effective_hash`]).
pub const LABEL_CONFIG_HASH: &str = "io.rustlet.compose.config-hash";
/// The project's directory, on containers: for the desktop app.
pub const LABEL_WORKING_DIR: &str = "io.rustlet.compose.project.working-dir";
/// The project's files, comma-separated, on containers.
pub const LABEL_CONFIG_FILES: &str = "io.rustlet.compose.project.config-files";
/// A container's service's dependencies, comma-separated
/// `service:condition:required` (`db:service_healthy:true`), as Compose
/// records them: so that `down` without the file still takes dependents
/// down first.
pub const LABEL_DEPENDS_ON: &str = "io.rustlet.compose.depends-on";
/// A network's key in the file (`default`, `backend`).
pub const LABEL_NETWORK: &str = "io.rustlet.compose.network";
/// A volume's key in the file.
pub const LABEL_VOLUME: &str = "io.rustlet.compose.volume";

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file that can't be read.
    #[error("{path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file isn't YAML, or not a compose file: where and why.
    #[error("{0}")]
    Parse(String),
    /// A compose file that is well-formed but asks for something wrong or
    /// unsupported (a dependency cycle, an unknown service, `network_mode`
    /// of a service that doesn't exist…).
    #[error("{0}")]
    Invalid(String),
    /// The daemon refused, or wasn't reached.
    #[error(transparent)]
    Client(#[from] rustlet_client::Error),
    /// A service's dependency didn't get where `depends_on` asks (exited,
    /// unhealthy, failed).
    #[error("{0}")]
    Dependency(String),
    /// Packing a build context failed.
    #[error("{0}")]
    Context(#[from] rustlet_build::context::ContextError),
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
