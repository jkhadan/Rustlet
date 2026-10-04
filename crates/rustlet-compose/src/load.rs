//! From files to a [`Project`]: finding the file, `.env`, interpolation,
//! overrides, names and paths.
//!
//! ```text
//!  compose.yaml ──┐  each file: YAML → `<<` merge keys → ${VAR} → checked alone
//!  override.yaml ─┘  (an error names its file)
//!                      │
//!                      ▼ merged by Compose's rules → model::ComposeFile → Project
//! ```
//!
//! As Compose v2 does it:
//!
//! - **Files.** `-f` in order, else the first of `compose.yaml`,
//!   `compose.yml`, `docker-compose.yaml`, `docker-compose.yml` in the
//!   project directory (`--project-directory`, else the current one) and,
//!   as Compose does, `compose.override.yaml` (or `.yml`, or the
//!   `docker-compose.` ones) beside it. **Deviation:** parent directories
//!   aren't searched.
//! - **Variables** ([`crate::interpolate`]): the environment given, over the
//!   project directory's `.env`. A bare `environment` key and a bare build
//!   argument take their value from the same variables.
//! - **Merging** a later file into an earlier one: mappings are merged key
//!   by key; the lists `ports`, `expose`, `dns`, `dns_search`, `dns_opt`,
//!   `tmpfs`, `cap_add`, `cap_drop`, `devices`, `security_opt`,
//!   `extra_hosts` and `env_file` are concatenated (an item given twice
//!   kept once); `volumes` are merged by target, the later mount replacing
//!   the earlier in its place; `environment`, `labels` and `build.args`, as
//!   lists or mappings, merge as mappings; a service's `networks` and
//!   `depends_on`, as lists or mappings, merge as mappings too, and `build:
//!   DIR` as `{context: DIR}`; anything else (`command`, `healthcheck.test`,
//!   any scalar) is replaced. An empty value doesn't replace anything.
//!   Compose's tags `!reset` (remove what earlier files set) and
//!   `!override` (replace instead of merging) are understood.
//! - **The project's name**: `-p`, else the file's `name:`, else
//!   `COMPOSE_PROJECT_NAME`, else the project directory's name. **Deviation:**
//!   Compose puts `COMPOSE_PROJECT_NAME` before `name:`. A name given (`-p`,
//!   `COMPOSE_PROJECT_NAME`) must be `[a-z0-9][a-z0-9_-]*` (lowercased
//!   first); one taken from `name:` or the directory is made into one, as
//!   Compose does (lowercased, other characters dropped).
//! - **Profiles**: `--profile`, else `COMPOSE_PROFILES` (comma-separated); a
//!   service with `profiles:` is in the project only if one of them is active
//!   (or `*` is).
//! - **Normalization**: names (`<project>_<network>`, `<project>_<volume>`,
//!   `<project>-<service>` for an image built without `image:`), relative
//!   host paths made absolute against the project directory (`~` against
//!   `HOME`), `env_file` read (its entries first, `environment` over them,
//!   sorted by name), each service's `ContainerConfig`.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};

use rustlet_spec::container::ContainerConfig;
use rustlet_spec::image::PullPolicy;
use rustlet_spec::network::{DEFAULT_NETWORK, NetworkMode};
use rustlet_spec::volume::{MountSpec, MountType};
use serde_yaml_ng::{Mapping, Value};

use crate::interpolate::{interpolate, parse_dotenv, unset_warning};
use crate::model::{self, ComposeFile, PullPolicyDef, ServiceDef};
use crate::project::{Build, Condition, Dependency, Network, Project, Service, ServiceNetwork, Volume};
use crate::{Error, Result};

/// What to load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// `-f`: the files, in order; a later one overrides and extends an
    /// earlier one (Compose's merge rules). Empty: the first of
    /// `compose.yaml`, `compose.yml`, `docker-compose.yaml`,
    /// `docker-compose.yml` in the current directory.
    pub files: Vec<PathBuf>,
    /// `--project-directory`.
    pub project_dir: Option<PathBuf>,
    /// `-p`.
    pub project_name: Option<String>,
    /// The environment interpolation reads (the process's), over the
    /// project directory's `.env`.
    pub env: BTreeMap<String, String>,
    /// `--profile`: services with `profiles:` only when one of theirs is
    /// listed.
    pub profiles: Vec<String>,
}

/// The default files, in order of preference.
pub const DEFAULT_FILES: [&str; 4] = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"];

/// The override files that go with a default file, in order of preference.
pub const OVERRIDE_FILES: [&str; 4] =
    ["compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml"];

/// Loads a project from files (see [`LoadOptions`]).
pub fn load(options: &LoadOptions) -> Result<Project> {
    let project_dir = options.project_dir.as_deref().map(absolute).transpose()?;
    let files = if options.files.is_empty() {
        let dir = match &project_dir {
            Some(dir) => dir.clone(),
            None => std::env::current_dir().map_err(|source| Error::Io { path: ".".into(), source })?,
        };
        default_files(&dir)?
    } else {
        options.files.iter().map(|f| absolute(f)).collect::<Result<_>>()?
    };
    let dir = match project_dir {
        Some(dir) => dir,
        None => files.first().and_then(|f| f.parent()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/")),
    };
    let mut texts = Vec::with_capacity(files.len());
    for file in &files {
        let text = std::fs::read_to_string(file).map_err(|source| Error::Io { path: file.clone(), source })?;
        texts.push(text);
    }
    let sources: Vec<(Option<&Path>, &str)> =
        files.iter().map(|f| Some(f.as_path())).zip(texts.iter().map(String::as_str)).collect();
    build_project(&sources, dir, files.clone(), options)
}

/// Loads a project from YAML text, as if it were a file in `dir`.
pub fn load_str(yaml: &str, dir: &Path, options: &LoadOptions) -> Result<Project> {
    let dir = absolute(options.project_dir.as_deref().unwrap_or(dir))?;
    build_project(&[(None, yaml)], dir, Vec::new(), options)
}

/// The default file in `dir`, and its override file if there is one.
fn default_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let first = DEFAULT_FILES.iter().map(|f| dir.join(f)).find(|p| p.is_file()).ok_or_else(|| {
        Error::Invalid(format!(
            "no compose file in {}: looked for {} (give one with -f)",
            dir.display(),
            DEFAULT_FILES.join(", ")
        ))
    })?;
    let mut files = vec![first];
    files.extend(OVERRIDE_FILES.iter().map(|f| dir.join(f)).find(|p| p.is_file()));
    Ok(files)
}

/// `path` made absolute against the current directory, `.` and `..`
/// resolved by its text (as Go's `filepath.Abs`, which Compose uses).
fn absolute(path: &Path) -> Result<PathBuf> {
    let abs = std::path::absolute(path).map_err(|source| Error::Io { path: path.to_path_buf(), source })?;
    Ok(clean(&abs))
}

/// The absolute `path` without `.` and `..` components; a `..` takes the
/// component before it away (none at `/`).
fn clean(path: &Path) -> PathBuf {
    let mut clean = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(name) => clean.push(name),
            Component::ParentDir => {
                clean.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    clean
}

/// The variables interpolation reads: `env` over `dir/.env`.
fn variables(dir: &Path, env: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let path = dir.join(".env");
    let mut vars = BTreeMap::new();
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let entries = parse_dotenv(&text, &|name| env.get(name).cloned())
                .map_err(|e| Error::Parse(format!("{}: {e}", path.display())))?;
            for (key, value) in entries {
                if let Some(value) = value.or_else(|| env.get(&key).cloned()) {
                    vars.insert(key, value);
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Error::Io { path, source }),
    }
    vars.extend(env.iter().map(|(k, v)| (k.clone(), v.clone())));
    Ok(vars)
}

/// The files' texts (each with its path, for errors) → the project.
fn build_project(
    sources: &[(Option<&Path>, &str)],
    dir: PathBuf,
    files: Vec<PathBuf>,
    options: &LoadOptions,
) -> Result<Project> {
    let vars = variables(&dir, &options.env)?;
    let mut unset = Vec::new();
    let mut merged: Option<Value> = None;
    for (file, text) in sources {
        let doc = read_document(*file, text, &vars, &mut unset)?;
        merged = Some(match merged {
            None => strip_tags(doc, &mut Vec::new())?,
            Some(base) => merge(&mut Vec::new(), base, doc)?,
        });
    }
    let file = model::parse(&merged.unwrap_or(Value::Null))?;

    let mut warnings: Vec<String> = unset.iter().map(|name| unset_warning(name)).collect();
    if file.version {
        warnings.push("the top-level version is obsolete and ignored: you can remove it".into());
    }
    let name = project_name(options, file.name.as_deref(), &vars, &dir)?;
    let active = active_profiles(options, &vars);
    let enabled = |s: &ServiceDef| s.profiles.is_empty() || active.iter().any(|a| a == "*" || s.profiles.contains(a));

    let cx = Context { project: &name, dir: &dir, vars: &vars, file: &file };
    let mut services = Vec::new();
    let mut used_networks = BTreeSet::new();
    let mut used_volumes = BTreeSet::new();
    for def in file.services.iter().filter(|s| enabled(s)) {
        let normalized = cx.service(def, &mut warnings)?;
        used_networks.extend(normalized.network_keys);
        used_volumes.extend(normalized.volume_keys);
        services.push(normalized.service);
    }
    check_container_names(&services)?;
    let networks = used_networks.into_iter().map(|key| Ok((key.clone(), cx.network(&key)?))).collect::<Result<_>>()?;
    let volumes = used_volumes.into_iter().map(|key| Ok((key.clone(), cx.volume(&key)?))).collect::<Result<_>>()?;
    let disabled_services = file.services.iter().filter(|s| !enabled(s)).map(|s| s.name.clone()).collect();

    let mut seen = BTreeSet::new();
    warnings.retain(|w| seen.insert(w.clone()));
    let project = Project { name, dir, files, services, networks, volumes, disabled_services, warnings };
    // A cycle is an error now, not only at `up`: `compose config` should
    // say so.
    project.dependency_order(&[], false)?;
    Ok(project)
}

/// One file: parsed, `<<` keys merged, interpolated, and checked on its own
/// so that an error names it. Tags are kept, for the merge.
fn read_document(
    file: Option<&Path>,
    text: &str,
    vars: &BTreeMap<String, String>,
    unset: &mut Vec<String>,
) -> Result<Value> {
    let named = |message: String| match file {
        Some(path) => format!("{}: {message}", path.display()),
        None => message,
    };
    let mut doc: Value = serde_yaml_ng::from_str(text).map_err(|e| Error::Parse(named(e.to_string())))?;
    doc.apply_merge().map_err(|e| Error::Parse(named(e.to_string())))?;
    interpolate(&mut doc, &|name| vars.get(name).cloned(), unset).map_err(|e| Error::Invalid(named(e)))?;
    let alone = strip_tags(doc.clone(), &mut Vec::new()).map_err(|e| in_file(e, file))?;
    model::parse(&alone).map_err(|e| in_file(e, file))?;
    Ok(doc)
}

/// `e`, saying which file it is about.
fn in_file(e: Error, file: Option<&Path>) -> Error {
    match (e, file) {
        (Error::Parse(m), Some(f)) => Error::Parse(format!("{}: {m}", f.display())),
        (Error::Invalid(m), Some(f)) => Error::Invalid(format!("{}: {m}", f.display())),
        (e, _) => e,
    }
}

/// How a key's value in a later file combines with an earlier file's.
enum Rule {
    /// Mappings key by key, anything else replaced.
    Deep,
    /// Lists concatenated, duplicates dropped.
    Append,
    /// Mounts merged by target.
    ByTarget,
    /// `KEY=VALUE` lists or mappings, merged as mappings.
    AsMap,
    /// A list of names is a mapping of names to nothing, then [`Rule::Deep`].
    NamesAsMap,
    /// `build: DIR` is `{context: DIR}`, then [`Rule::Deep`].
    Build,
}

fn rule(path: &[String]) -> Rule {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["services", _, field] => match *field {
            "ports" | "expose" | "dns" | "dns_search" | "dns_opt" | "tmpfs" | "cap_add" | "cap_drop" | "devices"
            | "security_opt" | "extra_hosts" | "env_file" => Rule::Append,
            "volumes" => Rule::ByTarget,
            "environment" | "labels" => Rule::AsMap,
            "networks" | "depends_on" => Rule::NamesAsMap,
            "build" => Rule::Build,
            _ => Rule::Deep,
        },
        ["services", _, "build", "args" | "labels"] | ["networks" | "volumes", _, "labels"] => Rule::AsMap,
        _ => Rule::Deep,
    }
}

/// `over` (a later file's value at `path`) merged into `base` (which has
/// no tags left).
fn merge(path: &mut Vec<String>, base: Value, over: Value) -> Result<Value> {
    if over.is_null() {
        return Ok(base);
    }
    // A mapping's tags are its entries' business (`merge_mappings`); in
    // anything else, they are dropped or refused first.
    let untagged = |over: Value, path: &mut Vec<String>| match over {
        Value::Mapping(_) => Ok(over),
        other => strip_tags(other, path),
    };
    Ok(match (rule(path), base, over) {
        (Rule::Deep, Value::Mapping(base), Value::Mapping(over)) => Value::Mapping(merge_mappings(path, base, over)?),
        (Rule::Deep, _, over) => strip_tags(over, path)?,
        (Rule::Append, base, over) => {
            let over = strip_tags(over, path)?;
            let field = path.last().map(String::as_str);
            let mut items = Vec::new();
            for item in as_list(base, field).into_iter().chain(as_list(over, field)) {
                if !items.contains(&item) {
                    items.push(item);
                }
            }
            Value::Sequence(items)
        }
        (Rule::ByTarget, base, over) => {
            let over = strip_tags(over, path)?;
            let mut mounts: Vec<Value> = Vec::new();
            for mount in as_list(base, None).into_iter().chain(as_list(over, None)) {
                let target = mount_target(&mount);
                match mounts.iter().position(|m| target.is_some() && mount_target(m) == target) {
                    Some(i) => mounts[i] = mount,
                    None => mounts.push(mount),
                }
            }
            Value::Sequence(mounts)
        }
        (Rule::AsMap, base, over) => {
            let mut map = as_map(base);
            map.extend(as_map(strip_tags(over, path)?));
            Value::Mapping(map)
        }
        (Rule::NamesAsMap, base, over) => {
            let over = untagged(over, path)?;
            Value::Mapping(merge_mappings(path, names_as_map(base), names_as_map(over))?)
        }
        (Rule::Build, base, over) => {
            let over = untagged(over, path)?;
            Value::Mapping(merge_mappings(path, build_as_map(base), build_as_map(over))?)
        }
    })
}

/// `over`'s keys merged into `base`'s, `!reset` and `!override` applied.
fn merge_mappings(path: &mut Vec<String>, mut base: Mapping, over: Mapping) -> Result<Mapping> {
    for (key, value) in over {
        path.push(key_text(&key));
        match value {
            Value::Tagged(t) if t.tag == "reset" => {
                base.shift_remove(&key);
            }
            Value::Tagged(t) if t.tag == "override" => {
                let value = strip_tags(t.value, path)?;
                base.insert(key, value);
            }
            Value::Tagged(t) => return Err(tag_error(path, &t.tag.to_string())),
            value => {
                let merged = match base.get_mut(&key) {
                    Some(slot) => merge(path, std::mem::take(slot), value)?,
                    None => strip_tags(value, path)?,
                };
                base.insert(key, merged);
            }
        }
        path.pop();
    }
    Ok(base)
}

/// `value` without tags: an entry tagged `!reset` removed, `!override`
/// taken as its value; any other tag is an error.
fn strip_tags(value: Value, path: &mut Vec<String>) -> Result<Value> {
    Ok(match value {
        Value::Mapping(map) => {
            let mut out = Mapping::new();
            for (key, value) in map {
                path.push(key_text(&key));
                match value {
                    Value::Tagged(t) if t.tag == "reset" => {}
                    Value::Tagged(t) if t.tag == "override" => {
                        let value = strip_tags(t.value, path)?;
                        out.insert(key, value);
                    }
                    Value::Tagged(t) => return Err(tag_error(path, &t.tag.to_string())),
                    value => {
                        let value = strip_tags(value, path)?;
                        out.insert(key, value);
                    }
                }
                path.pop();
            }
            Value::Mapping(out)
        }
        Value::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                path.push(format!("[{i}]"));
                if let Value::Tagged(t) = &item {
                    return Err(tag_error(path, &t.tag.to_string()));
                }
                out.push(strip_tags(item, path)?);
                path.pop();
            }
            Value::Sequence(out)
        }
        Value::Tagged(t) => return Err(tag_error(path, &t.tag.to_string())),
        other => other,
    })
}

fn tag_error(path: &[String], tag: &str) -> Error {
    Error::Invalid(format!(
        "{}: the YAML tag {tag} isn't supported here (only !reset and !override, on a key)",
        dotted(path)
    ))
}

/// `services.web.ports[1]`.
fn dotted(path: &[String]) -> String {
    let mut s = String::new();
    for part in path {
        if !s.is_empty() && !part.starts_with('[') {
            s.push('.');
        }
        s.push_str(part);
    }
    if s.is_empty() { "the file".into() } else { s }
}

fn key_text(key: &Value) -> String {
    match key {
        Value::String(s) => s.clone(),
        other => serde_yaml_ng::to_string(other).map(|s| s.trim().to_owned()).unwrap_or_default(),
    }
}

/// A scalar's text (for `KEY=VALUE` items).
fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A value of a list field as a list: one item is a list of one;
/// `extra_hosts` given as a mapping is `host=ip` items.
fn as_list(v: Value, field: Option<&str>) -> Vec<Value> {
    match v {
        Value::Sequence(items) => items,
        Value::Null => Vec::new(),
        Value::Mapping(map) if field == Some("extra_hosts") => map
            .into_iter()
            .flat_map(|(host, ips)| {
                let host = key_text(&host);
                let ips = match ips {
                    Value::Sequence(ips) => ips,
                    one => vec![one],
                };
                ips.into_iter()
                    .filter_map(|ip| scalar_text(&ip))
                    .map(move |ip| Value::String(format!("{host}={ip}")))
                    .collect::<Vec<_>>()
            })
            .collect(),
        one => vec![one],
    }
}

/// The target of a mount in short (`SOURCE:TARGET[:MODE]`) or long syntax.
fn mount_target(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => {
            let parts: Vec<&str> = s.split(':').collect();
            Some(parts.get(1).copied().unwrap_or(parts[0]).to_owned())
        }
        Value::Mapping(m) => m.get("target").and_then(scalar_text),
        _ => None,
    }
}

/// `KEY=VALUE` items (a bare `KEY` maps to nothing) or a mapping, as a
/// mapping.
fn as_map(v: Value) -> Mapping {
    match v {
        Value::Mapping(map) => map,
        Value::Sequence(items) => items
            .iter()
            .filter_map(scalar_text)
            .map(|item| match item.split_once('=') {
                Some((k, v)) => (Value::String(k.to_owned()), Value::String(v.to_owned())),
                None => (Value::String(item), Value::Null),
            })
            .collect(),
        _ => Mapping::new(),
    }
}

/// A list of names as a mapping of each to nothing.
fn names_as_map(v: Value) -> Mapping {
    match v {
        Value::Mapping(map) => map,
        Value::Sequence(items) => items.into_iter().map(|name| (name, Value::Null)).collect(),
        _ => Mapping::new(),
    }
}

/// `build: DIR` as `{context: DIR}`.
fn build_as_map(v: Value) -> Mapping {
    match v {
        Value::Mapping(map) => map,
        Value::Null => Mapping::new(),
        context => [(Value::String("context".into()), context)].into_iter().collect(),
    }
}

fn project_name(
    options: &LoadOptions,
    from_file: Option<&str>,
    vars: &BTreeMap<String, String>,
    dir: &Path,
) -> Result<String> {
    if let Some(name) = &options.project_name {
        return given_name(name, "-p");
    }
    if let Some(name) = from_file.filter(|n| !n.is_empty()) {
        return made_name(name, "the file's name:");
    }
    if let Some(name) = vars.get("COMPOSE_PROJECT_NAME").filter(|n| !n.is_empty()) {
        return given_name(name, "COMPOSE_PROJECT_NAME");
    }
    let base = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    made_name(&base, "the project directory's name")
}

/// A name given as such: it must be one (once lowercased).
fn given_name(name: &str, source: &str) -> Result<String> {
    let lower = name.to_ascii_lowercase();
    let valid = lower.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && lower.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !valid {
        return Err(Error::Invalid(format!(
            "invalid project name {name:?} ({source}): only letters, digits, '-' and '_', starting with a letter or \
             digit"
        )));
    }
    Ok(lower)
}

/// A name made from another (the directory's): lowercased, other
/// characters dropped, and no leading `-` or `_`, as Compose does.
fn made_name(name: &str, source: &str) -> Result<String> {
    let made: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-')
        .collect();
    let made = made.trim_start_matches(['_', '-']);
    if made.is_empty() {
        return Err(Error::Invalid(format!(
            "{source} {name:?} makes no project name (letters, digits, '-' and '_'): give one with -p"
        )));
    }
    Ok(made.to_owned())
}

/// `--profile`, else `COMPOSE_PROFILES`.
fn active_profiles(options: &LoadOptions, vars: &BTreeMap<String, String>) -> Vec<String> {
    if !options.profiles.is_empty() {
        return options.profiles.clone();
    }
    let listed = vars.get("COMPOSE_PROFILES").map(String::as_str).unwrap_or_default();
    listed.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_owned).collect()
}

/// Two services can't name their containers alike.
fn check_container_names(services: &[Service]) -> Result<()> {
    let mut owners: BTreeMap<&str, &str> = BTreeMap::new();
    for s in services {
        if let Some(name) = &s.container_name
            && let Some(other) = owners.insert(name, &s.name)
        {
            return Err(Error::Invalid(format!(
                "services.{}.container_name: {name:?} is the container name of service {other:?} too",
                s.name
            )));
        }
    }
    Ok(())
}

/// What normalizing a service needs to know.
struct Context<'a> {
    project: &'a str,
    dir: &'a Path,
    vars: &'a BTreeMap<String, String>,
    file: &'a ComposeFile,
}

/// A service, and the file's networks and volumes it uses (by key).
struct Normalized {
    service: Service,
    network_keys: Vec<String>,
    volume_keys: Vec<String>,
}

/// How a service is attached to networks.
#[derive(Default)]
struct Attachment {
    /// Its network mode: its first network, or `network_mode`.
    mode: NetworkMode,
    /// Its place on each network, in order.
    networks: Vec<ServiceNetwork>,
    /// The file's networks, by key.
    keys: Vec<String>,
    /// What `network_mode: service:x` makes it depend on.
    implied: Option<Dependency>,
}

impl Context<'_> {
    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }

    fn service(&self, def: &ServiceDef, warnings: &mut Vec<String>) -> Result<Normalized> {
        let at = format!("services.{}", def.name);
        let always_build = def.pull_policy == Some(PullPolicyDef::Build);
        let build = def.build.as_ref().map(|b| self.build(b, &at, always_build)).transpose()?;
        let image = match (&def.image, &build) {
            (Some(image), _) => image.clone(),
            (None, Some(_)) => crate::project::default_image(self.project, &def.name),
            (None, None) => return Err(Error::Invalid(format!("{at}: a service needs an image or a build section"))),
        };
        let pull_policy = match def.pull_policy {
            None | Some(PullPolicyDef::Missing) => PullPolicy::Missing,
            Some(PullPolicyDef::Always) => PullPolicy::Always,
            Some(PullPolicyDef::Never) => PullPolicy::Never,
            Some(PullPolicyDef::Build) if build.is_none() => {
                return Err(Error::Invalid(format!("{at}.pull_policy: build needs a build section")));
            }
            Some(PullPolicyDef::Build) => PullPolicy::Never,
        };
        let replicas = agree(&at, def.scale, def.deploy.replicas, "scale", "deploy.replicas")?.unwrap_or(1);
        if let Some(name) = &def.container_name {
            if !rustlet_spec::valid_container_name(name) {
                return Err(Error::Invalid(format!(
                    "{at}.container_name: {name:?} is not a container name ([a-zA-Z0-9][a-zA-Z0-9_.-]*)"
                )));
            }
            if replicas > 1 {
                return Err(Error::Invalid(format!(
                    "{at}: container_name names one container, so the service can't have {replicas} replicas"
                )));
            }
        }
        let memory = agree(&at, def.mem_limit, def.deploy.memory, "mem_limit", "deploy.resources.limits.memory")?;
        let cpus = agree(&at, def.cpus, def.deploy.cpus, "cpus", "deploy.resources.limits.cpus")?;
        let pids_limit = agree(&at, def.pids_limit, def.deploy.pids, "pids_limit", "deploy.resources.limits.pids")?;
        for (i, dns) in def.dns.iter().enumerate() {
            if dns.parse::<std::net::IpAddr>().is_err() {
                return Err(Error::Invalid(format!("{at}.dns[{i}]: {dns:?} is not an IP address")));
            }
        }
        if !def.expose.is_empty() {
            warnings.push(format!("{at}.expose is ignored: Rustlets has no --expose (ports: publishes ports)"));
        }

        let Attachment { mode: network, networks, keys: network_keys, implied } = self.networks(def, &at)?;
        let (mounts, volume_keys) = self.mounts(def, &at)?;
        let mut depends_on: Vec<Dependency> = def
            .depends_on
            .iter()
            .map(|d| Dependency { service: d.service.clone(), condition: d.condition, required: d.required })
            .collect();
        if let Some(implied) = implied
            && !depends_on.iter().any(|d| d.service == implied.service)
        {
            depends_on.push(implied);
        }
        for d in &depends_on {
            if d.required && !self.file.services.iter().any(|s| s.name == d.service) {
                return Err(Error::Invalid(format!(
                    "{at}.depends_on: {:?} is not a service of the project",
                    d.service
                )));
            }
        }
        // Aliases and addresses go with the first network, the others get
        // theirs from `network connect`.
        let first = networks.first();
        let config = ContainerConfig {
            image: image.clone(),
            cmd: def.command.clone().unwrap_or_default(),
            entrypoint: def.entrypoint.clone(),
            env: self.environment(def, &at)?,
            user: def.user.clone(),
            workdir: def.working_dir.clone(),
            hostname: def.hostname.clone(),
            tty: def.tty,
            open_stdin: def.stdin_open,
            labels: def.labels.clone(),
            read_only: def.read_only,
            memory,
            cpus,
            pids_limit,
            restart: def.restart.unwrap_or_default(),
            stop_signal: def.stop_signal.clone(),
            // Whole seconds, as Compose rounds them.
            stop_timeout: def.stop_grace_period.map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX)),
            healthcheck: def.healthcheck.clone(),
            cap_add: def.cap_add.clone(),
            cap_drop: def.cap_drop.clone(),
            privileged: def.privileged,
            security_opt: def.security_opt.clone(),
            devices: def.devices.clone(),
            network_aliases: first.map(|n| n.aliases.clone()).unwrap_or_default(),
            ip: first.and_then(|n| n.ipv4_address),
            ip6: first.and_then(|n| n.ipv6_address),
            extra_networks: networks.iter().skip(1).map(|n| n.network.clone()).collect(),
            network,
            ports: def.ports.clone(),
            dns: def.dns.clone(),
            dns_search: def.dns_search.clone(),
            dns_options: def.dns_opt.clone(),
            extra_hosts: def.extra_hosts.clone(),
            mounts,
            ..ContainerConfig::default()
        };
        let service = Service {
            name: def.name.clone(),
            image,
            build,
            pull_policy,
            container_name: def.container_name.clone(),
            replicas,
            depends_on,
            config,
            networks,
        };
        Ok(Normalized { service, network_keys, volume_keys })
    }

    fn build(&self, def: &model::BuildDef, at: &str, always: bool) -> Result<Build> {
        let context = if Path::new(&def.context).is_absolute() {
            PathBuf::from(&def.context)
        } else {
            clean(&self.dir.join(&def.context))
        };
        if let Some(network) = &def.network {
            match NetworkMode::parse(network) {
                Ok(NetworkMode::Container(_)) => {
                    return Err(Error::Invalid(format!(
                        "{at}.build.network: a build can't use another container's network"
                    )));
                }
                Ok(_) => {}
                Err(e) => return Err(Error::Invalid(format!("{at}.build.network: {e}"))),
            }
        }
        Ok(Build {
            context,
            dockerfile: def.dockerfile.clone(),
            // A bare argument takes the environment's value, or is left out.
            args: def.args.iter().filter_map(|(k, v)| Some((k.clone(), v.clone().or_else(|| self.var(k))?))).collect(),
            target: def.target.clone(),
            labels: def.labels.clone(),
            network: def.network.clone(),
            no_cache: def.no_cache,
            always,
        })
    }

    /// `env_file` entries, then `environment` over them; a bare key takes
    /// the variables' value, or is left out.
    fn environment(&self, def: &ServiceDef, at: &str) -> Result<Vec<String>> {
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        for file in &def.env_file {
            let path = self.host_path(&file.path, &format!("{at}.env_file"))?;
            let path = PathBuf::from(path);
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == io::ErrorKind::NotFound && !file.required => continue,
                Err(source) => return Err(Error::Io { path, source }),
            };
            let entries = parse_dotenv(&text, &|name| self.var(name))
                .map_err(|e| Error::Parse(format!("{}: {e}", path.display())))?;
            for (key, value) in entries {
                if let Some(value) = value.or_else(|| self.var(&key)) {
                    env.insert(key, value);
                }
            }
        }
        for (key, value) in &def.environment {
            if let Some(value) = value.clone().or_else(|| self.var(key)) {
                env.insert(key.clone(), value);
            }
        }
        Ok(env.into_iter().map(|(k, v)| format!("{k}={v}")).collect())
    }

    /// Where the service's network namespace comes from, and its place on
    /// each network.
    fn networks(&self, def: &ServiceDef, at: &str) -> Result<Attachment> {
        if let Some(mode) = &def.network_mode {
            let at = format!("{at}.network_mode");
            if !def.networks.is_empty() {
                return Err(Error::Invalid(format!("{at}: network_mode and networks can't go together")));
            }
            if let Some(other) = mode.strip_prefix("service:") {
                let Some(target) = self.file.services.iter().find(|s| s.name == other) else {
                    return Err(Error::Invalid(format!("{at}: {other:?} is not a service of the project")));
                };
                if other == def.name {
                    return Err(Error::Invalid(format!("{at}: a service can't share its own network namespace")));
                }
                // Its first container's namespace, once that has started.
                let container = target.container_name.clone().unwrap_or_else(|| format!("{}-{other}-1", self.project));
                return Ok(Attachment {
                    mode: NetworkMode::Container(container),
                    implied: Some(Dependency {
                        service: other.to_owned(),
                        condition: Condition::Started,
                        required: true,
                    }),
                    ..Attachment::default()
                });
            }
            return match NetworkMode::parse(mode) {
                Ok(NetworkMode::Network(_)) | Err(_) => Err(Error::Invalid(format!(
                    "{at}: {mode:?} isn't a network mode (host, none, bridge, service:NAME, container:NAME; a network \
                     of the file goes in networks:)"
                ))),
                Ok(mode) => Ok(Attachment { mode, ..Attachment::default() }),
            };
        }
        let defs = if def.networks.is_empty() {
            vec![model::ServiceNetworkDef { key: "default".into(), ..Default::default() }]
        } else {
            def.networks.clone()
        };
        let mut networks = Vec::new();
        let mut keys = Vec::new();
        for n in &defs {
            let at = format!("{at}.networks.{}", n.key);
            let Some(name) = self.network_name(&n.key) else {
                return Err(Error::Invalid(format!(
                    "{at}: the network {:?} isn't declared in the top-level networks",
                    n.key
                )));
            };
            // The service's own name is a name for it on every network
            // with DNS: the default bridge network has none.
            let mut aliases = Vec::new();
            if name == DEFAULT_NETWORK {
                if !n.aliases.is_empty() || n.ipv4_address.is_some() || n.ipv6_address.is_some() {
                    return Err(Error::Invalid(format!(
                        "{at}: the default bridge network takes no aliases or addresses"
                    )));
                }
            } else {
                aliases.push(def.name.clone());
                for alias in &n.aliases {
                    if !aliases.contains(alias) {
                        aliases.push(alias.clone());
                    }
                }
            }
            keys.push(n.key.clone());
            networks.push(ServiceNetwork {
                network: name,
                aliases,
                ipv4_address: n.ipv4_address,
                ipv6_address: n.ipv6_address,
            });
        }
        let mode = match networks.first().map(|n| (n.network.as_str(), NetworkMode::parse(&n.network))) {
            Some((_, Ok(mode @ (NetworkMode::Bridge | NetworkMode::Network(_))))) => mode,
            Some((name, _)) => {
                return Err(Error::Invalid(format!(
                    "{at}.networks.{}: {name:?} can't be a network's name",
                    defs[0].key
                )));
            }
            None => NetworkMode::Bridge,
        };
        Ok(Attachment { mode, networks, keys, implied: None })
    }

    /// A network's daemon name: `name:`, an external network's key, or
    /// `<project>_<key>`. `default` exists without being declared.
    fn network_name(&self, key: &str) -> Option<String> {
        match self.file.networks.get(key) {
            Some(def) => Some(def.name.clone().unwrap_or_else(|| self.resource_name(key, def.external))),
            None if key == "default" => Some(format!("{}_default", self.project)),
            None => None,
        }
    }

    /// An undeclared name: an external resource's key, or
    /// `<project>_<key>`.
    fn resource_name(&self, key: &str, external: bool) -> String {
        if external { key.to_owned() } else { format!("{}_{key}", self.project) }
    }

    fn network(&self, key: &str) -> Result<Network> {
        let def = self.file.networks.get(key).cloned().unwrap_or_default();
        let at = format!("networks.{key}.ipam.config");
        let v6 = def.subnets.iter().filter(|s| s.contains(':')).count();
        if v6 > 1 || def.subnets.len() - v6 > 1 {
            return Err(Error::Invalid(format!("{at}: one IPv4 and one IPv6 subnet at most")));
        }
        if v6 > 0 && !def.enable_ipv6 {
            return Err(Error::Invalid(format!("{at}: an IPv6 subnet needs enable_ipv6: true")));
        }
        Ok(Network {
            name: self.network_name(key).unwrap_or_else(|| format!("{}_{key}", self.project)),
            external: def.external,
            internal: def.internal,
            enable_ipv6: def.enable_ipv6,
            subnets: def.subnets,
            labels: def.labels,
        })
    }

    /// A named volume's daemon name: `name:`, an external volume's key, or
    /// `<project>_<key>`.
    fn volume_name(&self, key: &str) -> Option<String> {
        let def = self.file.volumes.get(key)?;
        Some(def.name.clone().unwrap_or_else(|| self.resource_name(key, def.external)))
    }

    fn volume(&self, key: &str) -> Result<Volume> {
        let def = self.file.volumes.get(key).cloned().unwrap_or_default();
        Ok(Volume {
            name: self.volume_name(key).unwrap_or_else(|| format!("{}_{key}", self.project)),
            external: def.external,
            labels: def.labels,
        })
    }

    /// The service's mounts (`volumes`, then `tmpfs`), and the file's
    /// volumes they use (by key).
    fn mounts(&self, def: &ServiceDef, at: &str) -> Result<(Vec<MountSpec>, Vec<String>)> {
        let mut mounts = Vec::new();
        let mut keys = Vec::new();
        for (i, m) in def.volumes.iter().enumerate() {
            let at = format!("{at}.volumes[{i}]");
            let mut spec = MountSpec {
                kind: m.kind,
                target: m.target.clone(),
                read_only: m.read_only,
                no_copy: m.no_copy,
                create_host_path: m.create_host_path,
                tmpfs_size: m.tmpfs_size,
                ..MountSpec::default()
            };
            match (m.kind, &m.source) {
                (MountType::Bind, Some(source)) => spec.source = Some(self.host_path(source, &at)?),
                (MountType::Volume, Some(key)) => {
                    let Some(name) = self.volume_name(key) else {
                        return Err(Error::Invalid(format!(
                            "{at}: the volume {key:?} isn't declared in the top-level volumes"
                        )));
                    };
                    keys.push(key.clone());
                    spec.source = Some(name);
                }
                _ => {}
            }
            mounts.push(spec);
        }
        mounts.extend(def.tmpfs.iter().cloned());
        // Two mounts on one path can't both be seen there.
        let mut seen = BTreeSet::new();
        for m in &mounts {
            let place: Vec<&str> = m.target.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
            if !seen.insert(place) {
                return Err(Error::Invalid(format!("{at}: two mounts on {}", m.target)));
            }
        }
        Ok((mounts, keys))
    }

    /// A host path as written, absolute: relative to the project
    /// directory, `~` to `HOME`.
    fn host_path(&self, source: &str, at: &str) -> Result<String> {
        let path = if source == "~" || source.starts_with("~/") {
            let home = self
                .var("HOME")
                .ok_or_else(|| Error::Invalid(format!("{at}: {source:?} needs HOME, which isn't set")))?;
            clean(&Path::new(&home).join(source.trim_start_matches('~').trim_start_matches('/')))
        } else if source.starts_with('~') {
            return Err(Error::Invalid(format!("{at}: {source:?}: only ~ (yours) is expanded, not ~user")));
        } else if Path::new(source).is_absolute() {
            PathBuf::from(source)
        } else {
            clean(&self.dir.join(source))
        };
        path.into_os_string()
            .into_string()
            .map_err(|p| Error::Invalid(format!("{at}: the path {} isn't UTF-8", Path::new(&p).display())))
    }
}

/// Two settings for one thing (`scale` and `deploy.replicas`) must agree.
fn agree<T: PartialEq + Copy>(at: &str, a: Option<T>, b: Option<T>, a_name: &str, b_name: &str) -> Result<Option<T>> {
    match (a, b) {
        (Some(x), Some(y)) if x != y => {
            Err(Error::Invalid(format!("{at}: {a_name} and {b_name} are both set, to different values")))
        }
        (x, y) => Ok(x.or(y)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustlet_spec::container::{HealthConfig, RestartPolicy, RestartPolicyName};
    use rustlet_spec::network::PortMapping;

    use super::*;

    /// A project directory that doesn't exist: no `.env` to read.
    const DIR: &str = "/rustlet-compose-tests/demo";

    /// A temporary directory holding `files`.
    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// `yaml`, as a file in [`DIR`] (project `demo`).
    fn project(yaml: &str) -> Project {
        load_str(yaml, Path::new(DIR), &LoadOptions::default()).unwrap()
    }

    fn load_error(yaml: &str) -> String {
        load_str(yaml, Path::new(DIR), &LoadOptions::default()).unwrap_err().to_string()
    }

    /// `base`, then `over`, as two files of the project `demo`.
    fn merged(base: &str, over: &str) -> Project {
        let dir = dir_with(&[("base.yaml", base), ("over.yaml", over)]);
        let files = vec![dir.path().join("base.yaml"), dir.path().join("over.yaml")];
        load(&LoadOptions { files, project_name: Some("demo".into()), ..LoadOptions::default() }).unwrap()
    }

    #[test]
    fn the_default_file_and_its_override_are_found_in_the_project_directory() {
        let dir = dir_with(&[
            ("compose.yaml", "services:\n  web:\n    image: nginx\n    ports: [\"80:80\"]\n"),
            ("docker-compose.yml", "services:\n  other:\n    image: x\n"),
            ("compose.override.yml", "services:\n  web:\n    ports: [\"443:443\"]\n"),
        ]);
        let p = load(&LoadOptions { project_dir: Some(dir.path().into()), ..LoadOptions::default() }).unwrap();
        assert_eq!(p.files, [dir.path().join("compose.yaml"), dir.path().join("compose.override.yml")]);
        assert_eq!(p.dir, dir.path());
        assert_eq!(p.services.len(), 1, "compose.yaml is preferred to docker-compose.yml");
        assert_eq!(p.services[0].config.ports.len(), 2, "the override is merged");
    }

    #[test]
    fn without_a_file_the_error_says_where_it_looked() {
        let dir = dir_with(&[]);
        let e = load(&LoadOptions { project_dir: Some(dir.path().into()), ..LoadOptions::default() }).unwrap_err();
        let expected = format!("no compose file in {}: looked for compose.yaml, compose.yml, ", dir.path().display());
        assert!(e.to_string().starts_with(&expected), "{e}");
        let e = load(&LoadOptions { files: vec![dir.path().join("nope.yaml")], ..LoadOptions::default() }).unwrap_err();
        assert!(matches!(&e, Error::Io { path, .. } if path.ends_with("nope.yaml")), "{e}");
    }

    #[test]
    fn files_given_with_f_merge_in_order_and_the_first_places_the_project() {
        let dir = dir_with(&[
            ("app/base.yaml", "services:\n  web:\n    image: nginx:1\n    volumes: [./site:/www]\n"),
            ("elsewhere/prod.yaml", "services:\n  web:\n    image: nginx:2\n"),
        ]);
        let files = vec![dir.path().join("app/base.yaml"), dir.path().join("elsewhere/../elsewhere/prod.yaml")];
        let p = load(&LoadOptions { files, ..LoadOptions::default() }).unwrap();
        assert_eq!(p.dir, dir.path().join("app"));
        assert_eq!(p.name, "app", "the project directory's name");
        assert_eq!(p.files[1], dir.path().join("elsewhere/prod.yaml"), "absolute and clean");
        assert_eq!(p.services[0].image, "nginx:2");
        let site = dir.path().join("app/site");
        assert_eq!(p.services[0].config.mounts[0].source.as_deref(), site.to_str());
    }

    #[test]
    fn a_later_file_merges_by_composes_rules() {
        let p = merged(
            r#"
services:
  web:
    image: app
    build: ./app
    command: [serve, --port, "80"]
    ports: ["80:80", "443:443"]
    dns: 1.1.1.1
    cap_add: [NET_ADMIN]
    volumes: ["data:/data", "./a:/a", "/cache"]
    environment: [A=1, B=2]
    labels: {tier: front}
    networks: [front]
    depends_on: [db]
    healthcheck:
      test: [CMD, a]
      interval: 5s
    extra_hosts: ["db:10.0.0.1"]
  db:
    image: postgres
networks:
  front:
  back:
volumes:
  data:
  other:
"#,
            r#"
services:
  web:
    build:
      target: prod
    command: serve
    ports: ["443:443", "8080:80"]
    dns: [8.8.8.8]
    cap_add: [SYS_TIME]
    volumes: ["other:/data:ro", "./b:/b"]
    environment:
      B: 3
      C: 4
    labels: [extra=1]
    networks:
      back:
        aliases: [api]
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: [CMD, b]
    extra_hosts:
      cache: 10.0.0.2
"#,
        );
        let web = p.service("web").unwrap();
        assert_eq!(web.config.cmd, ["serve"], "replaced");
        let ports: Vec<String> = web.config.ports.iter().map(ToString::to_string).collect();
        assert_eq!(ports, ["80:80/tcp", "443:443/tcp", "8080:80/tcp"], "concatenated, each once");
        assert_eq!(web.config.dns, ["1.1.1.1", "8.8.8.8"]);
        assert_eq!(web.config.cap_add, ["NET_ADMIN", "SYS_TIME"]);
        let targets: Vec<&str> = web.config.mounts.iter().map(|m| m.target.as_str()).collect();
        assert_eq!(targets, ["/data", "/a", "/cache", "/b"], "by target, the later in the earlier's place");
        assert_eq!(web.config.mounts[0].source.as_deref(), Some("demo_other"));
        assert!(web.config.mounts[0].read_only);
        assert_eq!(web.config.env, ["A=1", "B=3", "C=4"]);
        let labels: BTreeMap<String, String> =
            [("extra".to_owned(), "1".to_owned()), ("tier".to_owned(), "front".to_owned())].into();
        assert_eq!(web.config.labels, labels);
        let networks: Vec<&str> = web.networks.iter().map(|n| n.network.as_str()).collect();
        assert_eq!(networks, ["demo_front", "demo_back"]);
        assert_eq!(web.networks[1].aliases, ["web", "api"]);
        assert_eq!(
            web.depends_on,
            [Dependency { service: "db".into(), condition: Condition::Healthy, required: true }]
        );
        let health = web.config.healthcheck.as_ref().unwrap();
        assert_eq!(
            (health.test.as_slice(), health.interval),
            (&["CMD".to_owned(), "b".to_owned()][..], Some(5_000_000_000))
        );
        assert_eq!(web.config.extra_hosts, ["db:10.0.0.1", "cache:10.0.0.2"]);
        let build = web.build.as_ref().unwrap();
        assert_eq!((build.context.clone(), build.target.as_deref()), (p.dir.join("app"), Some("prod")));
        assert_eq!(p.networks.keys().collect::<Vec<_>>(), ["back", "default", "front"], "db is on default");
        assert_eq!(p.volumes.keys().collect::<Vec<_>>(), ["other"], "only what is mounted");
    }

    #[test]
    fn reset_and_override_tags_undo_and_replace() {
        let p = merged(
            "services:\n  web:\n    image: app\n    ports: ['80:80']\n    environment: {A: '1', B: '2'}\n    healthcheck:\n      test: [CMD, a]\n      interval: 5s\n",
            "services:\n  web:\n    ports: !reset []\n    environment: !override {C: '3'}\n    healthcheck: !reset null\n",
        );
        let web = p.service("web").unwrap();
        assert!(web.config.ports.is_empty());
        assert_eq!(web.config.env, ["C=3"]);
        assert_eq!(web.config.healthcheck, None);
        let dir = dir_with(&[("a.yaml", "services:\n  web:\n    image: !custom x\n")]);
        let e = load(&LoadOptions { files: vec![dir.path().join("a.yaml")], ..LoadOptions::default() }).unwrap_err();
        let expected =
            "services.web.image: the YAML tag !custom isn't supported here (only !reset and !override, on a key)";
        assert!(e.to_string().ends_with(expected), "{e}");
    }

    #[test]
    fn errors_name_the_file_they_are_in() {
        let dir = dir_with(&[
            ("a.yaml", "services:\n  web:\n    image: x\n"),
            ("b.yaml", "services:\n  web:\n    secrets: [s]\n"),
            ("c.yaml", "services: [\n"),
            ("d.yaml", "services:\n  web:\n    image: ${IMAGE:?set IMAGE}\n"),
        ]);
        let error = |names: &[&str]| {
            let files = names.iter().map(|n| dir.path().join(n)).collect();
            load(&LoadOptions { files, ..LoadOptions::default() }).unwrap_err().to_string()
        };
        let b = dir.path().join("b.yaml");
        assert_eq!(error(&["a.yaml", "b.yaml"]), format!("{}: services.web.secrets is not supported", b.display()));
        let c = error(&["c.yaml"]);
        assert!(c.starts_with(&format!("{}: ", dir.path().join("c.yaml").display())), "{c}");
        let d = dir.path().join("d.yaml");
        assert_eq!(
            error(&["d.yaml"]),
            format!("{}: services.web.image: required variable IMAGE is missing a value: set IMAGE", d.display())
        );
        assert_eq!(load_error("services:\n  web:\n    ports: [x]\n").split(':').next(), Some("services.web.ports[0]"));
    }

    #[test]
    fn the_project_name_comes_from_p_then_name_then_the_environment_then_the_directory() {
        let vars = env(&[("COMPOSE_PROJECT_NAME", "from-env")]);
        let none = BTreeMap::new();
        let name = |p: Option<&str>, file: Option<&str>, vars: &BTreeMap<String, String>| {
            let options = LoadOptions { project_name: p.map(Into::into), ..LoadOptions::default() };
            project_name(&options, file, vars, Path::new("/home/me/My_App 2")).map_err(|e| e.to_string())
        };
        assert_eq!(name(Some("Cli"), Some("file"), &vars).unwrap(), "cli");
        assert_eq!(name(None, Some("File Name!"), &vars).unwrap(), "filename");
        assert_eq!(name(None, None, &vars).unwrap(), "from-env");
        assert_eq!(name(None, None, &none).unwrap(), "my_app2");
        let e = name(Some("-x"), None, &none).unwrap_err();
        assert!(e.starts_with("invalid project name \"-x\" (-p): "), "{e}");
        assert!(name(Some("a b"), None, &none).is_err());
        let bad_env = env(&[("COMPOSE_PROJECT_NAME", "a.b")]);
        assert!(name(None, None, &bad_env).unwrap_err().contains("(COMPOSE_PROJECT_NAME)"));
        assert_eq!(made_name("__Weird--Dir", "x").unwrap(), "weird--dir");
        assert!(made_name("...", "x").unwrap_err().to_string().contains("give one with -p"));
        // `name:` is interpolated like the rest.
        assert_eq!(project("name: ${N:-Shop}\nservices: {}\n").name, "shop");
    }

    #[test]
    fn variables_come_from_the_environment_over_dot_env() {
        let dir = dir_with(&[(".env", "TAG=from-file\nPORT=8080\nCOMPOSE_PROJECT_NAME=dotenv\n")]);
        let yaml = "services:\n  web:\n    image: nginx:${TAG}\n    ports: [\"${PORT}:80\"]\n    environment: [HOME, PORT, MISSING]\n    labels: [\"x=$UNSET1\", \"y=${UNSET2}\", \"z=$UNSET1\"]\n";
        let options = LoadOptions { env: env(&[("TAG", "from-env"), ("HOME", "/home/me")]), ..LoadOptions::default() };
        let p = load_str(yaml, dir.path(), &options).unwrap();
        assert_eq!(p.name, "dotenv");
        let web = &p.services[0];
        assert_eq!(web.image, "nginx:from-env", "the environment wins");
        assert_eq!(web.config.ports[0].host_port, Some(8080));
        assert_eq!(
            web.config.env,
            ["HOME=/home/me", "PORT=8080"],
            "bare keys take the variables' values, or are left out"
        );
        assert_eq!(p.warnings, [unset_warning("UNSET1"), unset_warning("UNSET2")]);
    }

    #[test]
    fn profiles_choose_services() {
        let yaml = "services:\n  web:\n    image: a\n  debug:\n    image: b\n    profiles: [debug]\n  tools:\n    image: c\n    profiles: [tools, debug]\n";
        let names = |options: LoadOptions| {
            let p = load_str(yaml, Path::new(DIR), &options).unwrap();
            (p.services.iter().map(|s| s.name.clone()).collect::<Vec<_>>(), p.disabled_services)
        };
        assert_eq!(
            names(LoadOptions::default()),
            (vec!["web".to_owned()], vec!["debug".to_owned(), "tools".to_owned()])
        );
        assert_eq!(names(LoadOptions { profiles: vec!["tools".into()], ..LoadOptions::default() }).0, ["web", "tools"]);
        let from_env = LoadOptions { env: env(&[("COMPOSE_PROFILES", "debug, other")]), ..LoadOptions::default() };
        assert_eq!(names(from_env).0, ["web", "debug", "tools"]);
        assert_eq!(names(LoadOptions { profiles: vec!["*".into()], ..LoadOptions::default() }).0.len(), 3);
    }

    #[test]
    fn a_service_becomes_the_daemons_container_config() {
        let dir = dir_with(&[("web.env", "FROM_FILE=1\nSHARED=file\n")]);
        let yaml = r#"
name: shop
services:
  web:
    image: nginx:1.27
    command: nginx -g 'daemon off;'
    entrypoint: [/docker-entrypoint.sh]
    env_file: web.env
    environment:
      SHARED: env
      PLAIN: x
    user: "101:101"
    working_dir: /srv
    hostname: front
    tty: true
    stdin_open: true
    labels: {tier: front}
    read_only: true
    restart: unless-stopped
    stop_signal: SIGQUIT
    stop_grace_period: 1m30s
    healthcheck:
      test: curl -f http://localhost
      interval: 10s
    cap_add: [NET_ADMIN]
    cap_drop: [ALL]
    security_opt: [no-new-privileges]
    devices: [/dev/fuse]
    networks:
      back:
        aliases: [www]
        ipv4_address: 10.89.9.10
      front:
    ports: ["8080:80"]
    dns: [10.0.0.2]
    dns_search: corp.example
    dns_opt: [ndots:2]
    extra_hosts: ["db=10.0.0.5"]
    volumes:
      - assets:/assets:ro
      - ./conf:/etc/nginx/conf.d
      - /var/cache/nginx
    tmpfs: /run
    mem_limit: 256m
    cpus: 0.5
    pids_limit: 100
networks:
  back:
    ipam:
      config:
        - subnet: 10.89.9.0/24
  front:
volumes:
  assets:
"#;
        let p = load_str(yaml, dir.path(), &LoadOptions::default()).unwrap();
        let web = &p.services[0];
        let conf = dir.path().join("conf");
        let expected = ContainerConfig {
            image: "nginx:1.27".into(),
            cmd: vec!["nginx".into(), "-g".into(), "daemon off;".into()],
            entrypoint: Some(vec!["/docker-entrypoint.sh".into()]),
            env: vec!["FROM_FILE=1".into(), "PLAIN=x".into(), "SHARED=env".into()],
            user: Some("101:101".into()),
            workdir: Some("/srv".into()),
            hostname: Some("front".into()),
            tty: true,
            open_stdin: true,
            labels: [("tier".to_owned(), "front".to_owned())].into(),
            read_only: true,
            memory: Some(256 << 20),
            cpus: Some(0.5),
            pids_limit: Some(100),
            restart: RestartPolicy { name: RestartPolicyName::UnlessStopped, max_retries: 0 },
            stop_signal: Some("SIGQUIT".into()),
            stop_timeout: Some(90),
            healthcheck: Some(HealthConfig {
                test: vec!["CMD-SHELL".into(), "curl -f http://localhost".into()],
                interval: Some(10_000_000_000),
                ..HealthConfig::default()
            }),
            cap_add: vec!["NET_ADMIN".into()],
            cap_drop: vec!["ALL".into()],
            security_opt: vec!["no-new-privileges".into()],
            devices: vec!["/dev/fuse".into()],
            network: NetworkMode::Network("shop_back".into()),
            network_aliases: vec!["web".into(), "www".into()],
            ip: Some(Ipv4Addr::new(10, 89, 9, 10)),
            extra_networks: vec!["shop_front".into()],
            ports: PortMapping::parse("8080:80").unwrap(),
            dns: vec!["10.0.0.2".into()],
            dns_search: vec!["corp.example".into()],
            dns_options: vec!["ndots:2".into()],
            extra_hosts: vec!["db:10.0.0.5".into()],
            mounts: vec![
                MountSpec {
                    source: Some("shop_assets".into()),
                    target: "/assets".into(),
                    read_only: true,
                    ..MountSpec::default()
                },
                MountSpec {
                    kind: MountType::Bind,
                    source: Some(conf.to_str().unwrap().into()),
                    target: "/etc/nginx/conf.d".into(),
                    create_host_path: true,
                    ..MountSpec::default()
                },
                MountSpec { target: "/var/cache/nginx".into(), ..MountSpec::default() },
                MountSpec::parse_tmpfs("/run").unwrap(),
            ],
            ..ContainerConfig::default()
        };
        assert_eq!(web.config, expected);
        let addressed = ServiceNetwork {
            network: "shop_back".into(),
            aliases: vec!["web".into(), "www".into()],
            ipv4_address: Some(Ipv4Addr::new(10, 89, 9, 10)),
            ipv6_address: None,
        };
        let plain = ServiceNetwork {
            network: "shop_front".into(),
            aliases: vec!["web".into()],
            ipv4_address: None,
            ipv6_address: None,
        };
        assert_eq!(web.networks, [addressed, plain]);
        assert_eq!((web.image.as_str(), web.replicas, web.pull_policy), ("nginx:1.27", 1, PullPolicy::Missing));
        let back = Network {
            name: "shop_back".into(),
            external: false,
            internal: false,
            enable_ipv6: false,
            subnets: vec!["10.89.9.0/24".into()],
            labels: BTreeMap::new(),
        };
        assert_eq!(p.networks["back"], back);
        assert_eq!(
            p.volumes["assets"],
            Volume { name: "shop_assets".into(), external: false, labels: BTreeMap::new() }
        );
        assert!(!p.networks.contains_key("default"), "no service is on it");
        // `compose config` prints it.
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["services"][0]["config"]["network"], "shop_back");
    }

    #[test]
    fn services_without_networks_join_the_projects_default_network() {
        let p = project(
            "services:\n  web:\n    image: a\n  db:\n    image: b\n    networks: [default, ext]\nnetworks:\n  ext:\n    external: true\n  unused:\n    name: given\n",
        );
        assert_eq!(p.networks.keys().collect::<Vec<_>>(), ["default", "ext"]);
        assert_eq!(p.networks["default"].name, "demo_default");
        assert!(p.networks["ext"].external && p.networks["ext"].name == "ext");
        let web = p.service("web").unwrap();
        assert_eq!(web.config.network, NetworkMode::Network("demo_default".into()));
        assert_eq!((web.config.network_aliases.as_slice(), web.networks.len()), (&["web".to_owned()][..], 1));
        let db = p.service("db").unwrap();
        assert_eq!(db.config.extra_networks, ["ext"]);
        assert_eq!(db.networks[1].aliases, ["db"]);
        // The default network may be the daemon's own bridge: no DNS there,
        // so no aliases.
        let p =
            project("services:\n  web:\n    image: a\nnetworks:\n  default:\n    name: bridge\n    external: true\n");
        assert_eq!(p.services[0].config.network, NetworkMode::Bridge);
        assert!(p.services[0].config.network_aliases.is_empty() && p.services[0].networks[0].aliases.is_empty());
        for (yaml, expected) in [
            (
                "services:\n  web:\n    image: a\n    networks: [nope]\n",
                "services.web.networks.nope: the network \"nope\" isn't declared",
            ),
            (
                "services:\n  web:\n    image: a\nnetworks:\n  default:\n    ipam:\n      config: [{subnet: \"fd00::/64\"}]\n",
                "networks.default.ipam.config: an IPv6 subnet needs enable_ipv6: true",
            ),
            (
                "services:\n  web:\n    image: a\nnetworks:\n  default:\n    ipam:\n      config: [{subnet: 10.1.0.0/24}, {subnet: 10.2.0.0/24}]\n",
                "networks.default.ipam.config: one IPv4 and one IPv6 subnet at most",
            ),
            (
                "services:\n  web:\n    image: a\n    networks:\n      default:\n        aliases: [x]\nnetworks:\n  default:\n    name: bridge\n    external: true\n",
                "services.web.networks.default: the default bridge network takes no aliases or addresses",
            ),
        ] {
            let e = load_error(yaml);
            assert!(e.starts_with(expected), "{yaml}: {e}");
        }
    }

    #[test]
    fn mounts_resolve_names_and_paths() {
        let options = LoadOptions { env: env(&[("HOME", "/home/me")]), ..LoadOptions::default() };
        let yaml = "services:\n  web:\n    image: a\n    volumes:\n      - data:/data\n      - ext:/ext\n      - ~/cache:/cache\n      - ../shared/./x:/x\n      - /abs/../path:/abs\n      - type: bind\n        source: .\n        target: /src\nvolumes:\n  data:\n    name: kept-name\n  ext:\n    external: true\n";
        let p = load_str(yaml, Path::new(DIR), &options).unwrap();
        let sources: Vec<Option<&str>> = p.services[0].config.mounts.iter().map(|m| m.source.as_deref()).collect();
        assert_eq!(
            sources,
            [
                Some("kept-name"),
                Some("ext"),
                Some("/home/me/cache"),
                Some("/rustlet-compose-tests/shared/x"),
                Some("/abs/../path"),
                Some(DIR),
            ]
        );
        assert_eq!(p.volumes.keys().collect::<Vec<_>>(), ["data", "ext"]);
        assert!(p.volumes["ext"].external);
        for (yaml, expected) in [
            (
                "services:\n  web:\n    image: a\n    volumes: [nope:/x]\n",
                "services.web.volumes[0]: the volume \"nope\" isn't declared in the top-level volumes",
            ),
            (
                "services:\n  web:\n    image: a\n    volumes: [\"~bob/x:/x\"]\n",
                "services.web.volumes[0]: \"~bob/x\": only ~ (yours) is expanded",
            ),
            (
                "services:\n  web:\n    image: a\n    volumes: [\"~/x:/x\"]\n",
                "services.web.volumes[0]: \"~/x\" needs HOME",
            ),
            (
                "services:\n  web:\n    image: a\n    volumes: [/data]\n    tmpfs: /data/\n",
                "services.web: two mounts on /data/",
            ),
        ] {
            let e = load_error(yaml);
            assert!(e.starts_with(expected), "{yaml}: {e}");
        }
    }

    #[test]
    fn network_modes_and_the_dependency_service_implies() {
        let p = project(
            "services:\n  db:\n    image: a\n    container_name: the-db\n  web:\n    image: b\n    network_mode: service:db\n  sidecar:\n    image: c\n    network_mode: service:web\n  host:\n    image: d\n    network_mode: host\n  none:\n    image: e\n    network_mode: none\n  other:\n    image: f\n    network_mode: container:elsewhere\n  plain:\n    image: g\n    network_mode: bridge\n",
        );
        let mode = |name: &str| p.service(name).unwrap().config.network.clone();
        assert_eq!(mode("web"), NetworkMode::Container("the-db".into()));
        assert_eq!(mode("sidecar"), NetworkMode::Container("demo-web-1".into()));
        assert_eq!(
            (mode("host"), mode("none"), mode("plain")),
            (NetworkMode::Host, NetworkMode::None, NetworkMode::Bridge)
        );
        assert_eq!(mode("other"), NetworkMode::Container("elsewhere".into()));
        let web = p.service("web").unwrap();
        assert_eq!(
            web.depends_on,
            [Dependency { service: "db".into(), condition: Condition::Started, required: true }]
        );
        assert!(web.networks.is_empty() && web.config.extra_networks.is_empty());
        assert_eq!(p.networks.keys().collect::<Vec<_>>(), ["default"], "only db is on a network of the project");
        let order: Vec<&str> = p.startup_order(&["sidecar".into()]).unwrap().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(order, ["db", "web", "sidecar"]);
        for (yaml, expected) in [
            (
                "services:\n  web:\n    image: a\n    network_mode: service:nope\n",
                "services.web.network_mode: \"nope\" is not a service of the project",
            ),
            (
                "services:\n  web:\n    image: a\n    network_mode: service:web\n",
                "services.web.network_mode: a service can't share its own",
            ),
            (
                "services:\n  web:\n    image: a\n    network_mode: host\n    networks: [default]\n",
                "services.web.network_mode: network_mode and networks can't go together",
            ),
            (
                "services:\n  web:\n    image: a\n    network_mode: mynet\n",
                "services.web.network_mode: \"mynet\" isn't a network mode",
            ),
        ] {
            let e = load_error(yaml);
            assert!(e.starts_with(expected), "{yaml}: {e}");
        }
    }

    #[test]
    fn env_files_are_read_from_the_project_directory() {
        let dir =
            dir_with(&[("conf/app.env", "# comment\nA=1\nexport B=\"two\\nlines\"\nBARE\nC=${FROM_ENV:-none}\n")]);
        let options = LoadOptions { env: env(&[("BARE", "from-env"), ("FROM_ENV", "yes")]), ..LoadOptions::default() };
        let yaml = "services:\n  web:\n    image: a\n    env_file:\n      - conf/app.env\n      - path: missing.env\n        required: false\n    environment: [A=override]\n";
        let p = load_str(yaml, dir.path(), &options).unwrap();
        assert_eq!(p.services[0].config.env, ["A=override", "B=two\nlines", "BARE=from-env", "C=yes"]);
        let e =
            load_str("services:\n  web:\n    image: a\n    env_file: missing.env\n", dir.path(), &options).unwrap_err();
        assert!(matches!(&e, Error::Io { path, .. } if *path == dir.path().join("missing.env")), "{e}");
        std::fs::write(dir.path().join("bad.env"), "A='open\n").unwrap();
        let e = load_str("services:\n  web:\n    image: a\n    env_file: bad.env\n", dir.path(), &options).unwrap_err();
        assert!(e.to_string().starts_with(&format!("{}: line 1: ", dir.path().join("bad.env").display())), "{e}");
    }

    #[test]
    fn builds_get_absolute_contexts_and_default_image_names() {
        let options = LoadOptions { env: env(&[("FROM_ENV", "e")]), ..LoadOptions::default() };
        let yaml = "services:\n  Web:\n    build:\n      context: ./app\n      args: [A=1, FROM_ENV, UNSET]\n  api:\n    build: /abs/api\n    image: registry.example/api:2\n    pull_policy: build\n";
        let p = load_str(yaml, Path::new(DIR), &options).unwrap();
        let web = p.service("Web").unwrap();
        assert_eq!(web.image, "demo-web", "an image's name has no capitals");
        assert_eq!(web.container_name("demo", 1), "demo-Web-1");
        let build = web.build.as_ref().unwrap();
        assert_eq!(build.context, Path::new(DIR).join("app"));
        assert_eq!(build.args, [("A".to_owned(), "1".to_owned()), ("FROM_ENV".to_owned(), "e".to_owned())].into());
        assert!(!build.always);
        let api = p.service("api").unwrap();
        assert_eq!(api.image, "registry.example/api:2");
        assert_eq!((api.pull_policy, api.build.as_ref().unwrap().always), (PullPolicy::Never, true));
        assert_eq!(api.build.as_ref().unwrap().context, Path::new("/abs/api"));
        for (yaml, expected) in [
            ("services:\n  web:\n    command: x\n", "services.web: a service needs an image or a build section"),
            (
                "services:\n  web:\n    image: a\n    pull_policy: build\n",
                "services.web.pull_policy: build needs a build section",
            ),
            (
                "services:\n  web:\n    build:\n      network: container:x\n",
                "services.web.build.network: a build can't use",
            ),
        ] {
            let e = load_error(yaml);
            assert!(e.starts_with(expected), "{yaml}: {e}");
        }
    }

    #[test]
    fn replicas_and_limits_given_twice_must_agree() {
        let p = project(
            "services:\n  a:\n    image: x\n    scale: 3\n  b:\n    image: x\n    deploy:\n      replicas: 0\n  c:\n    image: x\n    mem_limit: 1g\n    deploy:\n      resources:\n        limits:\n          memory: 1024m\n          cpus: '2'\n",
        );
        let replicas: Vec<u32> = p.services.iter().map(|s| s.replicas).collect();
        assert_eq!(replicas, [3, 0, 1]);
        assert_eq!((p.services[2].config.memory, p.services[2].config.cpus), (Some(1 << 30), Some(2.0)));
        for (yaml, expected) in [
            (
                "services:\n  a:\n    image: x\n    scale: 2\n    deploy:\n      replicas: 3\n",
                "services.a: scale and deploy.replicas are both set, to different values",
            ),
            (
                "services:\n  a:\n    image: x\n    scale: 2\n    container_name: one\n",
                "services.a: container_name names one container, so the service can't have 2 replicas",
            ),
            (
                "services:\n  a:\n    image: x\n    container_name: one\n  b:\n    image: x\n    container_name: one\n",
                "services.b.container_name: \"one\" is the container name of service \"a\" too",
            ),
            (
                "services:\n  a:\n    image: x\n    container_name: -bad\n",
                "services.a.container_name: \"-bad\" is not a container name",
            ),
            (
                "services:\n  a:\n    image: x\n    mem_limit: 1g\n    deploy:\n      resources:\n        limits:\n          memory: 2g\n",
                "services.a: mem_limit and deploy.resources.limits.memory are both set",
            ),
            ("services:\n  a:\n    image: x\n    dns: [nope]\n", "services.a.dns[0]: \"nope\" is not an IP address"),
        ] {
            let e = load_error(yaml);
            assert!(e.starts_with(expected), "{yaml}: {e}");
        }
    }

    #[test]
    fn dependencies_must_name_services_and_must_not_go_round() {
        let e = load_error("services:\n  web:\n    image: a\n    depends_on: [nope]\n");
        assert_eq!(e, "services.web.depends_on: \"nope\" is not a service of the project");
        project("services:\n  web:\n    image: a\n    depends_on:\n      nope:\n        required: false\n");
        let e =
            load_error("services:\n  a:\n    image: x\n    depends_on: [b]\n  b:\n    image: x\n    depends_on: [a]\n");
        assert_eq!(e, "dependency cycle between services: a -> b -> a");
        // A dependency in a profile that isn't active: loading is fine, `up`
        // says what is missing.
        let p = project(
            "services:\n  web:\n    image: a\n    depends_on: [debug]\n  debug:\n    image: b\n    profiles: [debug]\n",
        );
        let e = p.startup_order(&[]).unwrap_err().to_string();
        assert!(e.starts_with("service \"web\" depends on \"debug\", which is not in the project"), "{e}");
    }

    #[test]
    fn ignored_settings_warn() {
        let p = project("version: '3.8'\nservices:\n  web:\n    image: a\n    expose: [80]\n");
        assert_eq!(
            p.warnings,
            [
                "the top-level version is obsolete and ignored: you can remove it",
                "services.web.expose is ignored: Rustlets has no --expose (ports: publishes ports)",
            ]
        );
    }

    #[test]
    fn the_config_hash_doesnt_depend_on_how_the_file_is_written() {
        let hash = |yaml: &str| project(yaml).services[0].config_hash();
        let a = hash(
            "services:\n  web:\n    image: a\n    environment: {X: '1', Y: '2'}\n    labels: [b=2, a=1]\n    ports: ['80:80']\n",
        );
        let b = hash(
            "services:\n  web:\n    ports: ['80:80']\n    labels: {a: '1', b: '2'}\n    environment: [Y=2, X=1]\n    image: a\n",
        );
        assert_eq!(a, b);
        let c = hash(
            "services:\n  web:\n    image: a\n    environment: {X: '1', Y: '3'}\n    labels: [b=2, a=1]\n    ports: ['80:80']\n",
        );
        assert_ne!(a, c);
    }
}
