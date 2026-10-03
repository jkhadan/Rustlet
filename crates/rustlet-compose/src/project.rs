//! A project, normalized: what `up` creates, with every default applied,
//! every path absolute, every name final. It serializes (`compose config`
//! prints it as JSON).

use std::collections::BTreeMap;
use std::path::PathBuf;

use rustlet_spec::container::ContainerConfig;
use rustlet_spec::image::PullPolicy;

/// A loaded compose project.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Project {
    /// `-p`, else the file's `name:`, else `COMPOSE_PROJECT_NAME`, else its
    /// directory's name; lowercased, only `[a-z0-9_-]`.
    pub name: String,
    /// Where relative paths start: `--project-directory`, else the first
    /// file's directory.
    pub dir: PathBuf,
    /// The files it was loaded from, absolute.
    pub files: Vec<PathBuf>,
    /// The services, in the file's order (profiles applied).
    pub services: Vec<Service>,
    /// By key in the file: `default` too, if a service uses it.
    pub networks: BTreeMap<String, Network>,
    /// By key in the file.
    pub volumes: BTreeMap<String, Volume>,
}

/// One service.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Service {
    pub name: String,
    /// The image its containers run: `image:`, else `<project>-<service>`
    /// (built).
    pub image: String,
    pub build: Option<Build>,
    /// `pull_policy`: `missing` (default), `always`, `never` (`build`: only
    /// build).
    pub pull_policy: PullPolicy,
    /// `container_name`: one container with exactly this name.
    pub container_name: Option<String>,
    /// `scale` / `deploy.replicas` (default 1).
    pub replicas: u32,
    pub depends_on: Vec<Dependency>,
    /// What each of its containers is created with: everything but its
    /// name and the compose labels, which `run` adds per container; its
    /// networks as `network` + `extra_networks` (daemon names), its named
    /// volumes as `<project>_<volume>`.
    pub config: ContainerConfig,
    /// Per network (daemon name, in `config`'s order): its aliases (the
    /// service's name is always one), and the addresses asked for.
    pub networks: Vec<ServiceNetwork>,
}

/// `build:`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Build {
    /// The context directory, absolute.
    pub context: PathBuf,
    /// `dockerfile`, relative to the context (as given).
    pub dockerfile: Option<String>,
    pub args: BTreeMap<String, String>,
    pub target: Option<String>,
    pub labels: BTreeMap<String, String>,
    /// `network` for the build's `RUN` steps.
    pub network: Option<String>,
    pub no_cache: bool,
}

/// One of a service's `depends_on`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Dependency {
    pub service: String,
    pub condition: Condition,
    /// `required: false`: a dependency that isn't in the project (another
    /// profile) is skipped instead of an error.
    pub required: bool,
}

/// What a dependency must reach before the service starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// `service_started` (the short syntax's): running.
    #[default]
    Started,
    /// `service_healthy`: its healthcheck said healthy.
    Healthy,
    /// `service_completed_successfully`: exited with 0.
    CompletedSuccessfully,
}

/// A service on one network.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServiceNetwork {
    /// The network's daemon name (`<project>_default`).
    pub network: String,
    pub aliases: Vec<String>,
    pub ipv4_address: Option<std::net::Ipv4Addr>,
    pub ipv6_address: Option<std::net::Ipv6Addr>,
}

/// A network of the project.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Network {
    /// The daemon's name: `<project>_<key>`, or `name:`, or an external
    /// network's.
    pub name: String,
    /// Made elsewhere: never created or removed by the project.
    pub external: bool,
    pub internal: bool,
    pub enable_ipv6: bool,
    /// `ipam.config[].subnet`, by family as given.
    pub subnets: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

/// A named volume of the project.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Volume {
    /// `<project>_<key>`, or `name:`, or an external volume's.
    pub name: String,
    pub external: bool,
    pub labels: BTreeMap<String, String>,
}

impl Project {
    pub fn service(&self, name: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.name == name)
    }

    /// The services `only` names (all if empty) and everything they depend
    /// on, each after its dependencies; a cycle, or an unknown service, is
    /// an error.
    pub fn startup_order(&self, only: &[String]) -> crate::Result<Vec<&Service>> {
        let _ = only;
        unimplemented!("startup_order: agent B")
    }
}

impl Service {
    /// The name of its container number `n` (from 1): `container_name`, or
    /// `<project>-<service>-<n>`.
    pub fn container_name(&self, project: &str, n: u32) -> String {
        match &self.container_name {
            Some(name) => name.clone(),
            None => format!("{project}-{}-{n}", self.name),
        }
    }

    /// A hash of everything its containers are created from (config,
    /// image name, networks): a container labelled with another hash is
    /// recreated by `up`.
    pub fn config_hash(&self) -> String {
        unimplemented!("config_hash: agent B")
    }
}
