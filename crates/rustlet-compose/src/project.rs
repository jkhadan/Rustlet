//! A project, normalized: what `up` creates, with every default applied,
//! every path absolute, every name final. It serializes (`compose config`
//! prints it as JSON).

use std::collections::BTreeMap;
use std::path::PathBuf;

use rustlet_spec::container::ContainerConfig;
use rustlet_spec::image::PullPolicy;
use sha2::{Digest as _, Sha256};

use crate::Error;

/// A loaded compose project.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Project {
    /// `-p`, else `COMPOSE_PROJECT_NAME`, else the file's `name:`, else its
    /// directory's name; lowercased, only `[a-z0-9_-]`.
    pub name: String,
    /// Where relative paths start: `--project-directory`, else the first
    /// file's directory.
    pub dir: PathBuf,
    /// The files it was loaded from, absolute.
    pub files: Vec<PathBuf>,
    /// The services, in the file's order (profiles applied).
    pub services: Vec<Service>,
    /// By key in the file, those the services use (as Compose, which
    /// creates no network nothing is on): `default` too, if a service uses
    /// it.
    pub networks: BTreeMap<String, Network>,
    /// By key in the file, those the services mount.
    pub volumes: BTreeMap<String, Volume>,
    /// Services that profiles left out. Their containers aren't orphans:
    /// `up --remove-orphans` leaves them alone, as Compose does.
    pub disabled_services: Vec<String>,
    /// What loading noticed and went on: variables used without a value,
    /// settings that are accepted but ignored.
    pub warnings: Vec<String>,
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
    /// `pull_policy: build`: built by every `up`, as with `--build`, not
    /// only when the image is missing.
    pub always: bool,
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

/// The image a service with `build:` and no `image:` gets:
/// `<project>-<service>`, lowercased (an image's name has no capitals).
pub fn default_image(project: &str, service: &str) -> String {
    format!("{project}-{}", service.to_ascii_lowercase())
}

impl Project {
    pub fn service(&self, name: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.name == name)
    }

    /// The services `only` names (all if empty) and everything they depend
    /// on, each after its dependencies; a cycle, or an unknown service, is
    /// an error.
    ///
    /// Services that are free to go at the same time go in the file's
    /// order. A dependency that isn't in the project (its profile isn't
    /// enabled) is an error, unless it is `required: false`: then it is
    /// left out, as Compose does.
    pub fn startup_order(&self, only: &[String]) -> crate::Result<Vec<&Service>> {
        self.dependency_order(only, true)
    }

    /// [`startup_order`](Self::startup_order); without `strict`, a missing
    /// dependency, required or not, is left out (`stop` and `down` take
    /// down what is there).
    pub(crate) fn dependency_order(&self, only: &[String], strict: bool) -> crate::Result<Vec<&Service>> {
        let n = self.services.len();
        let index = |name: &str| self.services.iter().position(|s| s.name == name);
        // What `only` asks for, and everything it depends on.
        let mut wanted = vec![false; n];
        let mut stack: Vec<usize> = Vec::new();
        if only.is_empty() {
            stack.extend((0..n).rev());
        }
        for name in only.iter().rev() {
            stack.push(index(name).ok_or_else(|| Error::Invalid(format!("no such service: {name}")))?);
        }
        while let Some(i) = stack.pop() {
            if std::mem::replace(&mut wanted[i], true) {
                continue;
            }
            for dep in &self.services[i].depends_on {
                match index(&dep.service) {
                    Some(j) => stack.push(j),
                    None if dep.required && strict => {
                        return Err(Error::Invalid(format!(
                            "service {:?} depends on {:?}, which is not in the project (not defined, or in a profile \
                             that isn't enabled)",
                            self.services[i].name, dep.service
                        )));
                    }
                    None => {}
                }
            }
        }
        // Each service's dependencies, as indices.
        let deps: Vec<Vec<usize>> =
            self.services.iter().map(|s| s.depends_on.iter().filter_map(|d| index(&d.service)).collect()).collect();
        // Kahn's algorithm, the first ready service in the file's order
        // each time.
        let mut placed = vec![false; n];
        let mut order = Vec::new();
        while let Some(i) = (0..n).find(|&i| wanted[i] && !placed[i] && deps[i].iter().all(|&d| placed[d])) {
            placed[i] = true;
            order.push(&self.services[i]);
        }
        if let Some(start) = (0..n).find(|&i| wanted[i] && !placed[i]) {
            // Every service left waits for another one left: following
            // those waits must come round in a circle.
            let mut path = vec![start];
            let cycle_start = loop {
                let last = path[path.len() - 1];
                let Some(&next) = deps[last].iter().find(|&&d| !placed[d]) else { break 0 };
                if let Some(p) = path.iter().position(|&i| i == next) {
                    break p;
                }
                path.push(next);
            };
            let mut names: Vec<&str> = path[cycle_start..].iter().map(|&i| self.services[i].name.as_str()).collect();
            names.push(names[0]);
            return Err(Error::Invalid(format!("dependency cycle between services: {}", names.join(" -> "))));
        }
        Ok(order)
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
    ///
    /// SHA-256 of the canonical JSON of those (object keys sorted, no
    /// blanks), so it is the same for the same service whatever order its
    /// file wrote things in. The container name chosen with
    /// `container_name` is part of it too; the number of replicas, the
    /// dependencies and how the image is made (`build`, `pull_policy`) are
    /// not: they change no container.
    pub fn config_hash(&self) -> String {
        #[derive(serde::Serialize)]
        struct Hashed<'a> {
            image: &'a str,
            container_name: &'a Option<String>,
            config: &'a ContainerConfig,
            networks: &'a [ServiceNetwork],
        }
        let hashed = Hashed {
            image: &self.image,
            container_name: &self.container_name,
            config: &self.config,
            networks: &self.networks,
        };
        let value = serde_json::to_value(&hashed).expect("a service's config serializes");
        let mut text = String::new();
        canonical_json(&value, &mut text);
        hex::encode(Sha256::digest(text.as_bytes()))
    }
}

/// `value` as JSON with every object's keys in order: the same text for the
/// same value, whatever order a map produced its keys in.
fn canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push(':');
                canonical_json(&map[key], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use rustlet_spec::network::NetworkMode;

    use super::*;

    fn service(name: &str, deps: &[(&str, bool)]) -> Service {
        Service {
            name: name.into(),
            image: "alpine".into(),
            build: None,
            pull_policy: PullPolicy::Missing,
            container_name: None,
            replicas: 1,
            depends_on: deps
                .iter()
                .map(|(s, required)| Dependency {
                    service: s.to_string(),
                    condition: Condition::Started,
                    required: *required,
                })
                .collect(),
            config: ContainerConfig { image: "alpine".into(), ..ContainerConfig::default() },
            networks: Vec::new(),
        }
    }

    fn project(services: Vec<Service>) -> Project {
        Project {
            name: "demo".into(),
            dir: "/srv/demo".into(),
            files: vec![],
            services,
            networks: BTreeMap::new(),
            volumes: BTreeMap::new(),
            disabled_services: vec![],
            warnings: vec![],
        }
    }

    fn names(order: crate::Result<Vec<&Service>>) -> Vec<&str> {
        order.unwrap().into_iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn dependencies_start_first_and_ties_keep_the_files_order() {
        let p = project(vec![
            service("web", &[("api", true), ("cache", true)]),
            service("api", &[("db", true)]),
            service("cache", &[]),
            service("db", &[]),
            service("tools", &[]),
        ]);
        assert_eq!(names(p.startup_order(&[])), ["cache", "db", "api", "web", "tools"]);
        assert_eq!(names(p.startup_order(&["api".into()])), ["db", "api"], "what api needs, and api");
        assert_eq!(names(p.startup_order(&["tools".into(), "api".into()])), ["db", "api", "tools"]);
        assert_eq!(names(p.startup_order(&["db".into()])), ["db"]);
    }

    #[test]
    fn unknown_services_and_missing_dependencies() {
        let p = project(vec![service("web", &[("db", true)]), service("worker", &[("queue", false)])]);
        let e = p.startup_order(&["nope".into()]).unwrap_err().to_string();
        assert_eq!(e, "no such service: nope");
        let e = p.startup_order(&[]).unwrap_err().to_string();
        assert!(e.starts_with("service \"web\" depends on \"db\", which is not in the project"), "{e}");
        // An optional dependency that isn't there is left out.
        assert_eq!(names(p.startup_order(&["worker".into()])), ["worker"]);
        // Taking things down, nothing missing matters.
        assert_eq!(names(p.dependency_order(&[], false)), ["web", "worker"]);
    }

    #[test]
    fn cycles_name_their_services() {
        let p = project(vec![
            service("web", &[("api", true)]),
            service("api", &[("db", true)]),
            service("db", &[("api", true)]),
            service("ok", &[]),
        ]);
        let e = p.startup_order(&[]).unwrap_err().to_string();
        assert_eq!(e, "dependency cycle between services: api -> db -> api");
        assert_eq!(names(p.startup_order(&["ok".into()])), ["ok"], "a cycle elsewhere doesn't matter");
        let p = project(vec![service("selfish", &[("selfish", true)])]);
        assert_eq!(
            p.startup_order(&[]).unwrap_err().to_string(),
            "dependency cycle between services: selfish -> selfish"
        );
    }

    #[test]
    fn container_names() {
        let mut s = service("web", &[]);
        assert_eq!(s.container_name("demo", 2), "demo-web-2");
        s.container_name = Some("the-web".into());
        assert_eq!(s.container_name("demo", 1), "the-web");
    }

    #[test]
    fn config_hashes_follow_what_containers_are_made_of() {
        let base = service("web", &[]);
        let hash = base.config_hash();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, base.clone().config_hash(), "stable");
        // Labels built in another order are the same labels.
        let mut a = base.clone();
        let mut b = base.clone();
        a.config.labels = [("x".to_owned(), "1".to_owned()), ("a".to_owned(), "2".to_owned())].into_iter().collect();
        b.config.labels = [("a".to_owned(), "2".to_owned()), ("x".to_owned(), "1".to_owned())].into_iter().collect();
        assert_eq!(a.config_hash(), b.config_hash());
        assert_ne!(a.config_hash(), hash);
        // Everything a container is created from counts…
        let changed = |f: &dyn Fn(&mut Service)| {
            let mut s = base.clone();
            f(&mut s);
            s.config_hash()
        };
        assert_ne!(changed(&|s| s.config.env = vec!["A=1".into()]), hash);
        assert_ne!(changed(&|s| s.image = "alpine:3.20".into()), hash);
        assert_ne!(changed(&|s| s.config.network = NetworkMode::Network("demo_back".into())), hash);
        assert_ne!(
            changed(&|s| s.networks.push(ServiceNetwork {
                network: "demo_default".into(),
                aliases: vec!["web".into()],
                ipv4_address: None,
                ipv6_address: None
            })),
            hash
        );
        assert_ne!(changed(&|s| s.container_name = Some("w".into())), hash);
        // …and nothing else.
        assert_eq!(changed(&|s| s.replicas = 3), hash);
        assert_eq!(changed(&|s| s.pull_policy = PullPolicy::Always), hash);
        assert_eq!(
            changed(&|s| s.depends_on.push(Dependency {
                service: "db".into(),
                condition: Condition::Healthy,
                required: true
            })),
            hash
        );
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level() {
        let v = serde_json::json!({"b": [{"z": 1, "a": "x\"y"}], "a": null});
        let mut out = String::new();
        canonical_json(&v, &mut out);
        assert_eq!(out, r#"{"a":null,"b":[{"a":"x\"y","z":1}]}"#);
    }
}
