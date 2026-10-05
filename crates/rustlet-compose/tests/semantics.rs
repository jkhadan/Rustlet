//! What a compose file means: loading, merging and normalizing, through the
//! public API only, checked against what docker/compose, compose-go and the
//! Compose Specification do (each test says where it comes from). The
//! daemon's side (`up`, `down`) is `tests/run.rs`'s, the syntax of
//! `${VAR}` and `.env` files `interpolate.rs`'s own tests.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustlet_compose::{Condition, Error, LoadOptions, Project, given_project_name, load, load_selected, load_str};

/// A project directory that doesn't exist: no `.env` to read.
const DIR: &str = "/rustlet-compose-tests/shop";

fn project(yaml: &str) -> Project {
    load_str(yaml, Path::new(DIR), &LoadOptions::default()).unwrap()
}

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

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

/// `names` in `dir`, as `-f` gives them.
fn files(dir: &tempfile::TempDir, names: &[&str]) -> Vec<PathBuf> {
    names.iter().map(|n| dir.path().join(n)).collect()
}

/// `base`, then `over`, loaded as two `-f` files.
fn merged(base: &str, over: &str) -> Project {
    let dir = dir_with(&[("compose.yaml", base), ("more.yaml", over)]);
    load(&LoadOptions { files: files(&dir, &["compose.yaml", "more.yaml"]), ..LoadOptions::default() }).unwrap()
}

// ── files ─────────────────────────────────────────────────────────────────

// COMPOSE_FILE, from the environment or the project directory's `.env`, names
// the files when `-f` isn't given: compose-go cli/options.go
// `WithConfigFileEnv` (split on COMPOSE_PATH_SEPARATOR, `:` by default), which
// docker/compose cmd/compose/compose.go `toProjectOptions` runs after
// `WithDotEnv` and before the default file discovery. No override file is
// added to what it lists, as with `-f`; `-f` wins over it.
#[test]
fn compose_file_variable_names_the_files() {
    let dir = dir_with(&[
        ("compose.yaml", "services:\n  web:\n    image: nginx\n"),
        ("prod.yaml", "services:\n  web:\n    image: nginx:prod\n"),
        ("compose.override.yaml", "services:\n  web:\n    labels: [from=override]\n"),
    ]);
    let abs = |name: &str| dir.path().join(name).display().to_string();
    let load_with = |env: BTreeMap<String, String>, files: Vec<PathBuf>| {
        load(&LoadOptions { project_dir: Some(dir.path().into()), env, files, ..LoadOptions::default() })
    };

    let list = format!("{}:{}", abs("compose.yaml"), abs("prod.yaml"));
    let p = load_with(env(&[("COMPOSE_FILE", &list)]), vec![]).unwrap();
    assert_eq!(p.services[0].image, "nginx:prod");
    assert_eq!(p.files, files(&dir, &["compose.yaml", "prod.yaml"]), "compose.override.yaml isn't looked for");
    assert!(p.services[0].config.labels.is_empty());

    // A separator of one's own; empty entries (a trailing one) are skipped.
    let list = format!("{};{};", abs("compose.yaml"), abs("prod.yaml"));
    let p = load_with(env(&[("COMPOSE_FILE", &list), ("COMPOSE_PATH_SEPARATOR", ";")]), vec![]).unwrap();
    assert_eq!(p.files, files(&dir, &["compose.yaml", "prod.yaml"]));

    // `-f` wins; so does an empty variable, over nothing: the default files.
    let p = load_with(env(&[("COMPOSE_FILE", &list)]), files(&dir, &["compose.yaml"])).unwrap();
    assert_eq!(p.files, files(&dir, &["compose.yaml"]));
    let p = load_with(env(&[("COMPOSE_FILE", "")]), vec![]).unwrap();
    assert_eq!(p.files, files(&dir, &["compose.yaml", "compose.override.yaml"]));

    // In the project directory's `.env`, under the environment.
    std::fs::write(dir.path().join(".env"), format!("COMPOSE_FILE={}\n", abs("prod.yaml"))).unwrap();
    let p = load_with(BTreeMap::new(), vec![]).unwrap();
    assert_eq!(p.files, files(&dir, &["prod.yaml"]));
    let p = load_with(env(&[("COMPOSE_FILE", &abs("compose.yaml"))]), vec![]).unwrap();
    assert_eq!(p.files, files(&dir, &["compose.yaml"]));
}

// Each entry of COMPOSE_FILE must be a file, and an error says which entry
// the variable named (compose-go: "compose file %q set by COMPOSE_FILE
// environment variable is invalid"). A relative entry is relative to the
// current directory, not the project directory: `acceptComposeFile` makes it
// absolute with `filepath.Abs`.
#[test]
fn compose_file_entries_must_be_files_and_relative_ones_start_at_the_current_directory() {
    let dir = dir_with(&[("compose.yaml", "services:\n  web:\n    image: nginx\n"), ("sub/keep", "")]);
    let error = |entry: &str| {
        let options = LoadOptions {
            project_dir: Some(dir.path().into()),
            env: env(&[("COMPOSE_FILE", entry)]),
            ..LoadOptions::default()
        };
        load(&options).unwrap_err().to_string()
    };
    // The project directory has a compose.yaml; the current directory (this crate's) hasn't.
    let cwd = std::env::current_dir().unwrap();
    let e = error("compose.yaml");
    assert!(e.starts_with("compose file \"compose.yaml\" set by COMPOSE_FILE is invalid: "), "{e}");
    assert!(e.contains(&cwd.join("compose.yaml").display().to_string()), "{e}");
    let e = error(&format!("{}/nope.yaml", dir.path().display()));
    assert!(e.contains("nope.yaml") && e.contains("set by COMPOSE_FILE"), "{e}");
    let e = error(&format!("{}/sub", dir.path().display()));
    assert!(e.contains("is not a regular file"), "{e}");
    assert!(error("-").contains("reading the compose file from stdin isn't supported"));
}

// `-f -` (the file on standard input) is Compose's, and isn't supported here:
// a clear error, not a file named `-`.
#[test]
fn stdin_is_not_a_compose_file() {
    let e = load(&LoadOptions { files: vec!["-".into()], ..LoadOptions::default() }).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)));
    assert!(e.to_string().starts_with("reading the compose file from stdin isn't supported"), "{e}");
}

// A service named on the command line is enabled together with its profiles
// (docker/compose cmd/compose/compose.go v2.29.7 `project.WithServicesEnabled
// (services...)`, main pkg/compose/loader.go; the Compose docs, "Auto-enabling
// profiles and dependency resolution"): `up debug`, `logs debug` and `stop
// debug` work with `debug` in a profile nobody asked for. compose-go's
// `WithServicesEnabled` adds the named service's *profiles* to the active
// ones, so the profile's other services are in the project too (a command only
// acts on the ones it names, and what they depend on).
#[test]
fn a_service_named_on_the_command_line_is_enabled_with_its_profiles() {
    let dir = dir_with(&[(
        "compose.yaml",
        "services:\n  web:\n    image: a\n  debug:\n    image: b\n    profiles: [debug]\n  tools:\n    image: c\n    profiles: [debug, tools]\n  other:\n    image: d\n    profiles: [other]\n",
    )]);
    let options = LoadOptions { files: files(&dir, &["compose.yaml"]), ..LoadOptions::default() };
    let names = |p: &Project| p.services.iter().map(|s| s.name.clone()).collect::<Vec<_>>();
    let named = |names: &[&str], options: &LoadOptions| {
        load_selected(options, &names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap()
    };

    assert_eq!(names(&load(&options).unwrap()), ["web"]);
    let p = named(&["debug"], &options);
    assert_eq!(names(&p), ["web", "debug", "tools"]);
    assert_eq!(p.disabled_services, ["other"], "what stays off is still known, so that it makes no orphans");
    // A name that is no service is the command's to refuse; one already in is no change.
    assert_eq!(names(&named(&["nope", "web"], &options)), ["web"]);
    assert_eq!(names(&named(&["other", "nope"], &options)), ["web", "other"]);
    // With profiles asked for too: both.
    let with_tools = LoadOptions { profiles: vec!["other".into()], ..options.clone() };
    assert_eq!(names(&named(&["debug"], &with_tools)), ["web", "debug", "tools", "other"]);
}

// ── merging files ─────────────────────────────────────────────────────────

// An override that turns a healthcheck off: `healthcheck` merges key by key,
// and `disable: true` makes the check `NONE` whatever `test` the base file
// set (docker/compose pkg/compose/convert.go `ToMobyHealthCheck`: `if
// check.Disable { test = []string{"NONE"} }`; the schema has no constraint
// between `disable` and `test`).
#[test]
fn healthcheck_disabled_by_an_override_file() {
    let p = merged(
        "services:\n  db:\n    image: postgres\n    healthcheck:\n      test: [CMD, pg_isready]\n      interval: 5s\n",
        "services:\n  db:\n    healthcheck:\n      disable: true\n",
    );
    assert!(p.services[0].config.healthcheck.as_ref().is_some_and(|h| h.is_none()));
    // And `test: [NONE]` in the override does too.
    let p = merged(
        "services:\n  db:\n    image: postgres\n    healthcheck:\n      test: [CMD, pg_isready]\n",
        "services:\n  db:\n    healthcheck:\n      test: [NONE]\n",
    );
    assert!(p.services[0].config.healthcheck.as_ref().is_some_and(|h| h.is_none()));
}

// A YAML sequence is merged by appending the later file's values to the
// earlier file's (the Compose Specification's merge chapter, "Sequence"),
// except the shell commands (`command`, `entrypoint`, `healthcheck.test`) and
// what is unique by a key. `profiles` is no exception: compose-go's
// TestMergeProfilesUnicity has `[profile1, profile2]` and `[profile2,
// profile3]` make `[profile1, profile2, profile3]`.
#[test]
fn an_override_adds_profiles_to_the_base_files() {
    let dir = dir_with(&[
        ("compose.yaml", "services:\n  web:\n    image: a\n  tools:\n    image: b\n    profiles: [debug]\n"),
        ("more.yaml", "services:\n  tools:\n    profiles: [ops, debug]\n"),
    ]);
    for profile in ["debug", "ops"] {
        let options = LoadOptions {
            files: files(&dir, &["compose.yaml", "more.yaml"]),
            profiles: vec![profile.into()],
            ..LoadOptions::default()
        };
        let p = load(&options).unwrap();
        assert!(p.service("tools").is_some(), "tools has profiles [debug, ops]; disabled: {:?}", p.disabled_services);
    }
}

// The same rule for a service's aliases on a network (compose-go
// Test_mergeYamlServiceNetworksMapping: `[alias1, alias2]` and `[alias3,
// alias1]` make `[alias1, alias2, alias3]`); the service's own name is an
// alias on every network, first.
#[test]
fn an_override_adds_network_aliases() {
    let p = merged(
        "services:\n  web:\n    image: a\n    networks:\n      back:\n        aliases: [api]\nnetworks:\n  back:\n",
        "services:\n  web:\n    networks:\n      back:\n        aliases: [www, api]\n",
    );
    assert_eq!(p.services[0].networks[0].aliases, ["web", "api", "www"]);
}

// `devices` entries are unique by their path in the container: a later
// file's `/dev/nvme0n1p1:/dev/sda` replaces the earlier `/dev/sda:/dev/sda`,
// in its place (compose-go override/uncity.go `deviceMappingIndexer`;
// override/merge_devices_test.go Test_mergeYamlDevicesOverride).
#[test]
fn an_override_replaces_devices_by_container_path() {
    let p = merged(
        "services:\n  web:\n    image: a\n    devices: ['/dev/sda:/dev/sda', '/dev/sdb:/dev/sdb']\n",
        "services:\n  web:\n    devices: ['/dev/nvme0n1p1:/dev/sda', '/dev/sdc']\n",
    );
    assert_eq!(p.services[0].config.devices, ["/dev/nvme0n1p1:/dev/sda", "/dev/sdb:/dev/sdb", "/dev/sdc"]);
}

// `depends_on` merges as a mapping, and a name in a list means `{condition:
// service_started, required: true}` (compose-go override/merge.go
// `mergeDependsOn`): an override listing `[db, cache]` sets `db` back to
// `service_started`. A mapping that says nothing of the condition leaves it.
#[test]
fn an_override_listing_depends_on_means_service_started() {
    let base = "services:\n  web:\n    image: a\n    depends_on:\n      db:\n        condition: service_healthy\n      cache:\n        condition: service_healthy\n        required: false\n  db:\n    image: b\n  cache:\n    image: c\n";
    let condition = |p: &Project, name: &str| {
        let d = p.service("web").unwrap().depends_on.iter().find(|d| d.service == name).unwrap().clone();
        (d.condition, d.required)
    };
    let p = merged(base, "services:\n  web:\n    depends_on: [db, cache]\n");
    assert_eq!(condition(&p, "db"), (Condition::Started, true));
    assert_eq!(condition(&p, "cache"), (Condition::Started, true), "required: true is the default too");
    let p = merged(base, "services:\n  web:\n    depends_on:\n      db:\n      cache: {required: true}\n");
    assert_eq!(condition(&p, "db"), (Condition::Healthy, true));
    assert_eq!(condition(&p, "cache"), (Condition::Healthy, true));
    // A list in the base, a mapping over it.
    let p = merged(
        "services:\n  web:\n    image: a\n    depends_on: [db]\n  db:\n    image: b\n",
        "services:\n  web:\n    depends_on:\n      db:\n        condition: service_healthy\n",
    );
    assert_eq!(condition(&p, "db"), (Condition::Healthy, true));
}

// ── normalizing ───────────────────────────────────────────────────────────

// `build: ~/src/app`: `~` in a build context is the home directory, as in
// any path compose-go resolves (paths/resolve.go: `build.context` →
// `absContextPath` → `absPath` → `ExpandUser`).
#[test]
fn a_build_context_under_home() {
    let options = LoadOptions { env: env(&[("HOME", "/home/me")]), ..LoadOptions::default() };
    let build = |yaml: &str| {
        let p = load_str(yaml, Path::new(DIR), &options).unwrap();
        p.services[0].build.as_ref().unwrap().context.clone()
    };
    assert_eq!(build("services:\n  web:\n    build: ~/src/app\n"), Path::new("/home/me/src/app"));
    assert_eq!(build("services:\n  web:\n    build: {context: \"~\"}\n"), Path::new("/home/me"));
    assert_eq!(build("services:\n  web:\n    build: ./app\n"), Path::new(DIR).join("app"));
    assert_eq!(build("services:\n  web:\n    build: /abs/app\n"), Path::new("/abs/app"));
    let e = load_str("services:\n  web:\n    build: ~bob/app\n", Path::new(DIR), &options).unwrap_err();
    assert!(e.to_string().starts_with("services.web.build.context: \"~bob/app\": only ~ (yours) is expanded"), "{e}");
}

// A boolean may be written `yes`, `on`, `y`, `no`, `off` or `n`, in a
// variable or not, with a warning that YAML 1.2 wants `true` or `false`:
// compose-go loader/interpolate.go `toBoolean`, which the interpolation applies
// to every string at a boolean field (v2.2.0, in Compose v2.29.7, and main).
#[test]
fn a_boolean_may_say_yes_with_a_warning() {
    let options = LoadOptions { env: env(&[("TTY", "yes"), ("RO", "Off")]), ..LoadOptions::default() };
    let p = load_str(
        "services:\n  web:\n    image: a\n    tty: ${TTY}\n    read_only: ${RO}\n    stdin_open: on\n    privileged: ${NO_SUCH:-false}\n",
        Path::new(DIR),
        &options,
    )
    .unwrap();
    let web = &p.services[0].config;
    assert!(web.tty && web.open_stdin && !web.read_only && !web.privileged);
    assert_eq!(
        p.warnings,
        [
            "services.web.tty: \"yes\" for boolean is not supported by YAML 1.2, please use `true`",
            "services.web.read_only: \"Off\" for boolean is not supported by YAML 1.2, please use `false`",
            "services.web.stdin_open: \"on\" for boolean is not supported by YAML 1.2, please use `true`",
        ]
    );
    let e = load_str("services:\n  web:\n    image: a\n    tty: maybe\n", Path::new(DIR), &options).unwrap_err();
    assert!(e.to_string().contains("expected true or false"), "{e}");
}

// `mem_limit: 0` is no limit, as Docker has it (0 is the engine's "unlimited")
// and as `cpus: 0` is here: rustletd refuses `--memory 0`, so `mem_limit:
// ${MEM_LIMIT:-0}` has to load as no limit, not as a limit of nothing.
#[test]
fn mem_limit_zero_is_no_limit() {
    let p = project("services:\n  web:\n    image: a\n    mem_limit: 0\n");
    assert_eq!(p.services[0].config.memory, None);
    let p = project(
        "services:\n  web:\n    image: a\n    deploy:\n      resources:\n        limits: {memory: 0, cpus: 0}\n",
    );
    assert_eq!((p.services[0].config.memory, p.services[0].config.cpus), (None, None));
    let p = project(
        "services:\n  web:\n    image: a\n    mem_limit: 0\n    deploy: {resources: {limits: {memory: 64m}}}\n",
    );
    assert_eq!(p.services[0].config.memory, Some(64 << 20), "0 says nothing, so it disagrees with nothing");
}

// A project name given as such must be one once lowercased
// (`[a-z0-9][a-z0-9_-]*`); the one rule for `-p` and COMPOSE_PROJECT_NAME,
// whether a file is loaded or the project is acted on by its name alone.
#[test]
fn a_given_project_name_is_lowercased_or_refused() {
    assert_eq!(given_project_name("Shop-2_b", "-p").unwrap(), "shop-2_b");
    for bad in ["", "-x", "_x", "my shop", "a.b", "é"] {
        let e = given_project_name(bad, "COMPOSE_PROJECT_NAME").unwrap_err().to_string();
        assert!(e.starts_with(&format!("invalid project name {bad:?} (COMPOSE_PROJECT_NAME): ")), "{bad:?}: {e}");
    }
}

// ── YAML: merge keys ──────────────────────────────────────────────────────

// An anchored mapping that itself merges another (`x-app: &app {<<: *base,
// …}`, then `<<: *app` in a service) is the usual way to layer shared
// settings, and compose-go resolves it (loader/reset_test.go TestResetCycle,
// "nested_merge_no_cycle", the gluetun layout; TestNestedAliasReset). Several
// levels, and several merged mappings that each merge another, all count; the
// mapping's own keys win over a merged one's, and an earlier merged mapping
// over a later one (YAML's merge key type).
#[test]
fn nested_merge_keys_are_resolved() {
    let yaml = r#"
x-base: &base
  restart: unless-stopped
  environment: &base-env
    TZ: UTC
    LEVEL: info
x-app: &app
  <<: *base
  environment:
    <<: *base-env
    APP: 1
x-extra: &extra
  <<: *base
  cap_add: [NET_ADMIN]
  restart: always
x-deep: &deep
  <<: *app
services:
  web:
    <<: *app
    image: nginx
  worker:
    <<: [*extra, *app]
    image: busybox
    environment:
      LEVEL: debug
  deep:
    <<: *deep
    image: busybox
"#;
    let p = load_str(yaml, Path::new(DIR), &LoadOptions::default()).expect("a merge target that itself uses <<");
    let web = p.service("web").unwrap();
    assert_eq!(web.config.restart.to_string(), "unless-stopped");
    assert_eq!(web.config.env, ["APP=1", "LEVEL=info", "TZ=UTC"]);
    let worker = p.service("worker").unwrap();
    assert_eq!(worker.config.restart.to_string(), "always", "the first merged mapping's own key wins");
    assert_eq!(worker.config.cap_add, ["NET_ADMIN"], "and what the second brings that the first hasn't");
    assert_eq!(worker.config.env, ["LEVEL=debug"], "its own environment replaces a merged one");
    assert_eq!(p.service("deep").unwrap().config.env, ["APP=1", "LEVEL=info", "TZ=UTC"]);
    // What isn't something to merge is an error that says so.
    for bad in ["<<: 1", "<<: [1]", "<<: [[a: 1]]", "<<: !tag {a: 1}"] {
        let e =
            load_str(&format!("services:\n  web:\n    image: a\n    {bad}\n"), Path::new(DIR), &LoadOptions::default())
                .unwrap_err();
        assert!(matches!(e, Error::Parse(_)) && e.to_string().contains("a << merge key"), "{bad}: {e}");
    }
}

// ── checked, and found right ──────────────────────────────────────────────

// Anchors, aliases and `<<` (one level, a list of mappings, an explicit key
// over a merged one), as real files use them; `restart: no`, unquoted
// `8080:80` and `1000:1000`, `yes` and `off` as plain strings in a mapping of
// names, a bare environment key taking the shell's value.
#[test]
fn yaml_anchors_merge_keys_and_unquoted_scalars() {
    let yaml = r#"
x-common: &common
  restart: unless-stopped
  environment: &env
    TZ: UTC
    LEVEL: info
  labels: [tier=app]
x-extra: &extra
  cap_add: [NET_ADMIN]
  restart: always
services:
  web:
    <<: *common
    image: nginx
    environment:
      <<: *env
      LEVEL: debug
  worker:
    <<: [*extra, *common]
    image: busybox
    command: [sleep, "1"]
  other:
    image: busybox
    environment: *env
    restart: no
    user: 1000:1000
    ports: [8080:80, 22:22]
  plain:
    image: busybox
    environment:
      A: yes
      B: off
      C:
"#;
    let options = LoadOptions { env: env(&[("C", "from-env")]), ..LoadOptions::default() };
    let p = load_str(yaml, Path::new(DIR), &options).unwrap();
    let web = p.service("web").unwrap();
    assert_eq!(web.config.restart.to_string(), "unless-stopped");
    assert_eq!(web.config.env, ["LEVEL=debug", "TZ=UTC"]);
    assert_eq!(web.config.labels["tier"], "app");
    let worker = p.service("worker").unwrap();
    assert_eq!(worker.config.restart.to_string(), "always", "the first merged mapping wins");
    assert_eq!(worker.config.cap_add, ["NET_ADMIN"]);
    let other = p.service("other").unwrap();
    assert_eq!(other.config.env, ["LEVEL=info", "TZ=UTC"]);
    assert_eq!((other.config.restart.to_string().as_str(), other.config.user.as_deref()), ("no", Some("1000:1000")));
    assert_eq!(other.config.ports.len(), 2);
    assert_eq!(p.service("plain").unwrap().config.env, ["A=yes", "B=off", "C=from-env"]);
}

// A number or boolean that arrives through a variable, in each field of the
// supported set that takes one (compose-go casts by path:
// loader/interpolate.go `interpolateTypeCastMapping`).
#[test]
fn typed_values_from_variables() {
    let yaml = "services:\n  web:\n    image: a\n    scale: ${N}\n    cpus: ${C}\n    read_only: ${RO}\n    privileged: ${PRIV:-false}\n    pids_limit: ${PIDS}\n    stop_grace_period: ${T}\n    mem_limit: ${MEM}\n    healthcheck:\n      test: [CMD, 'true']\n      retries: ${R}\n      interval: ${I}\n    ports:\n      - target: ${TARGET}\n        published: ${PUB}\n    depends_on:\n      db:\n        required: ${REQ}\n  db:\n    image: b\n    volumes:\n      - type: volume\n        source: data\n        target: /data\n        read_only: ${RO}\nvolumes:\n  data:\n    external: ${EXT}\n";
    let options = LoadOptions {
        env: env(&[
            ("N", "2"),
            ("C", "0.5"),
            ("RO", "true"),
            ("PIDS", "50"),
            ("T", "15s"),
            ("MEM", "64m"),
            ("R", "4"),
            ("I", "2s"),
            ("TARGET", "80"),
            ("PUB", "8080"),
            ("REQ", "false"),
            ("EXT", "true"),
        ]),
        ..LoadOptions::default()
    };
    let p = load_str(yaml, Path::new(DIR), &options).unwrap();
    let web = p.service("web").unwrap();
    assert_eq!(web.replicas, 2);
    assert_eq!(web.config.cpus, Some(0.5));
    assert!(web.config.read_only && !web.config.privileged);
    assert_eq!(web.config.ports[0].to_string(), "8080:80/tcp");
    assert!(!web.depends_on[0].required);
    assert!(p.volumes["data"].external);
}

// `!reset` reaching a later file through an anchor, a direct alias of a
// tagged value, and `!override {}` on a top-level network (compose-go
// loader/reset_test.go: TestResetTagWithSharedAlias, TestDirectAliasWithReset,
// TestOverrideReplace).
#[test]
fn reset_through_anchors_and_override_of_a_network() {
    let base = "services:\n  svc1:\n    image: alpine\n    ports: [\"8080:80\"]\n  svc2:\n    image: nginx\n    ports: [\"9090:90\"]\n";
    let p = merged(
        base,
        "x-reset-ports: &reset-ports\n  ports: !reset []\nservices:\n  svc1:\n    <<: *reset-ports\n  svc2:\n    <<: *reset-ports\n",
    );
    assert!(p.services.iter().all(|s| s.config.ports.is_empty()), "shared anchor with !reset");
    let p =
        merged(base, "x-reset: &reset !reset []\nservices:\n  svc1:\n    ports: *reset\n  svc2:\n    ports: *reset\n");
    assert!(p.services.iter().all(|s| s.config.ports.is_empty()), "alias of !reset []");
    let p = merged(
        base,
        "x-inner: &inner\n  ports: !reset []\nx-outer: &outer\n  <<: *inner\nservices:\n  svc1:\n    <<: *outer\n",
    );
    assert!(p.service("svc1").unwrap().config.ports.is_empty(), "through two levels of anchors");
    assert_eq!(p.service("svc2").unwrap().config.ports.len(), 1);
    let p = merged(
        "services:\n  web:\n    image: a\n    networks: [n]\nnetworks:\n  n:\n    name: n\n    external: true\n",
        "networks:\n  n: !override {}\n",
    );
    assert!(!p.networks["n"].external);
    for yaml in [
        "x-base: &base\n  image: nginx\nservices:\n  s1:\n    <<: [*base, {restart: unless-stopped}]\n",
        "x-list: &alist\n  - image: nginx\nservices:\n  s1:\n    <<: *alist\n",
    ] {
        project(yaml);
    }
}

// Files as editors and platforms write them: a BOM, CRLF, nothing at all, a
// leading `---`; and input Compose refuses too fails with an error, never a
// panic (duplicate keys, tabs, a second document, absurd nesting). A key that
// is not a string (`123:`, `true:`) is refused as compose-go refuses it
// (`non-string key in services: 123`).
#[test]
fn odd_files_load_or_fail_without_panicking() {
    let try_load = |yaml: &str| load_str(yaml, Path::new(DIR), &LoadOptions::default()).map(|p| p.services.len());
    assert_eq!(try_load("\u{feff}services:\n  web:\n    image: a\n").unwrap(), 1);
    assert_eq!(try_load("services:\r\n  web:\r\n    image: a\r\n    command: sleep 1\r\n").unwrap(), 1);
    assert_eq!(try_load("").unwrap(), 0);
    assert_eq!(try_load("# nothing\n").unwrap(), 0);
    assert_eq!(try_load("---\nservices:\n  web:\n    image: a\n").unwrap(), 1);
    for bad in [
        "services:\n  web:\n    image: a\n    image: b\n",
        "services:\n\tweb:\n\t\timage: a\n",
        "services:\n  web:\n    image: a\n---\nservices:\n  db:\n    image: b\n",
        "services:\n  123:\n    image: a\n",
        "services:\n  web:\n    image: a\n    labels:\n      true: x\n",
    ] {
        assert!(try_load(bad).is_err(), "{bad:?}");
    }
    let deep = "[".repeat(2000) + &"]".repeat(2000);
    assert!(try_load(&format!("services:\n  web:\n    image: a\nx-deep: {deep}\n")).is_err());
}

// Teardown must see declarations even after service attachments or profiles
// change; creation filters them separately by the services actually selected.
#[test]
fn external_declarations_survive_unused_and_inactive_services() {
    let p = project(
        "services:\n  app:\n    image: a\n  offline:\n    image: b\n    profiles: [offline]\n    volumes: [data:/data]\n    networks: [legacy]\nvolumes:\n  data:\n    external: true\n    name: shop_data\n  unused:\n    external: true\nnetworks:\n  legacy:\n    external: true\n    name: shop_legacy\n  unused:\n    external: true\n",
    );
    assert!(p.volumes["data"].external && p.volumes["unused"].external);
    assert!(p.networks["legacy"].external && p.networks["unused"].external);
    assert_eq!(p.disabled_services, ["offline"]);
}

#[test]
fn unresolved_environment_keys_remove_file_and_image_values() {
    let dir = dir_with(&[("base.env", "REMOVE=secret\nEMPTY=secret\nKEEP=good\n"), ("unset.env", "REMOVE\n")]);
    let yaml = "services:\n  app:\n    image: a\n    env_file: base.env\n    environment:\n      REMOVE:\n      IMAGE_ONLY:\n      EMPTY: ''\n";
    let p = load_str(yaml, dir.path(), &LoadOptions::default()).unwrap();
    assert_eq!(p.services[0].config.env, ["EMPTY=", "KEEP=good"]);
    assert_eq!(p.services[0].config.unset_env, ["IMAGE_ONLY", "REMOVE"]);
    let p = load_str(
        "services:\n  app:\n    image: a\n    env_file: [base.env, unset.env]\n",
        dir.path(),
        &LoadOptions::default(),
    )
    .unwrap();
    assert_eq!(p.services[0].config.env, ["EMPTY=secret", "KEEP=good"]);
    assert_eq!(p.services[0].config.unset_env, ["REMOVE"]);
    let options = LoadOptions { env: env(&[("REMOVE", "from-shell")]), ..LoadOptions::default() };
    let p = load_str(yaml, dir.path(), &options).unwrap();
    assert!(p.services[0].config.env.contains(&"REMOVE=from-shell".to_owned()));
    assert_eq!(p.services[0].config.unset_env, ["IMAGE_ONLY"]);
}

#[test]
fn env_files_interpolate_previous_files_and_current_overrides() {
    let dir = dir_with(&[
        ("first.env", "BASE=first\n"),
        ("next.env", "PREVIOUS=${BASE}\nBASE=next\nCURRENT=${BASE}\nEXPLICIT=${FROM_SERVICE}\n"),
    ]);
    let yaml = "services:\n  app:\n    image: a\n    env_file: [first.env, next.env]\n    environment: {FROM_SERVICE: service}\n";
    let p = load_str(yaml, dir.path(), &LoadOptions::default()).unwrap();
    assert_eq!(
        p.services[0].config.env,
        ["BASE=next", "CURRENT=next", "EXPLICIT=service", "FROM_SERVICE=service", "PREVIOUS=first"]
    );
    let options = LoadOptions { env: env(&[("BASE", "shell")]), ..LoadOptions::default() };
    let p = load_str(yaml, dir.path(), &options).unwrap();
    assert!(p.services[0].config.env.contains(&"PREVIOUS=shell".to_owned()));
    assert!(p.services[0].config.env.contains(&"CURRENT=shell".to_owned()));
}

#[test]
fn explicit_empty_command_clears_the_image_and_changes_the_hash() {
    let base = "services:\n  app:\n    image: a\n";
    let inherited = project(base);
    assert!(!inherited.services[0].config.clear_cmd);
    for empty in ["[]", "''"] {
        let cleared = project(&format!("{base}    command: {empty}\n"));
        assert!(cleared.services[0].config.clear_cmd);
        assert!(cleared.services[0].config.cmd.is_empty());
        assert_ne!(cleared.services[0].config_hash(), inherited.services[0].config_hash());
    }
    let null = project(&format!("{base}    command: null\n"));
    assert_eq!(null.services[0].config_hash(), inherited.services[0].config_hash());
}

#[test]
fn equivalent_short_and_long_ports_merge_by_the_normalized_key() {
    let p = merged(
        "services:\n  app:\n    image: a\n    ports: ['8080:80', '8081:81/tcp', '8082:82/udp']\n",
        "services:\n  app:\n    ports:\n      - {target: 80, published: 8080, host_ip: 0.0.0.0, protocol: tcp}\n      - {target: 81, published: '8081'}\n      - {target: 82, published: 8082, protocol: udp}\n      - {target: 80, published: 8080, protocol: udp}\n",
    );
    assert_eq!(
        p.services[0].config.ports.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["8080:80/tcp", "8081:81/tcp", "8082:82/udp", "8080:80/udp"]
    );
}

#[test]
fn configuration_discovery_uses_compose_file_and_preserves_selection_errors() {
    let dir = dir_with(&[("selected.yaml", "services: {}\n")]);
    let options = LoadOptions { project_dir: Some(dir.path().to_owned()), ..LoadOptions::default() };
    assert!(!rustlet_compose::has_config_file(&options).unwrap());
    let selected = dir.path().join("selected.yaml").display().to_string();
    let variable = LoadOptions { env: env(&[("COMPOSE_FILE", &selected)]), ..options.clone() };
    assert!(rustlet_compose::has_config_file(&variable).unwrap());
    std::fs::write(dir.path().join(".env"), format!("COMPOSE_FILE={selected}\n")).unwrap();
    assert!(rustlet_compose::has_config_file(&options).unwrap());
    std::fs::write(dir.path().join(".env"), "COMPOSE_FILE=/does/not/exist.yaml\n").unwrap();
    assert!(rustlet_compose::has_config_file(&options).unwrap_err().to_string().contains("set by COMPOSE_FILE"));
    let explicit = LoadOptions { files: vec![dir.path().join("selected.yaml")], ..options.clone() };
    assert!(rustlet_compose::has_config_file(&explicit).unwrap());
    std::fs::remove_file(dir.path().join(".env")).unwrap();
    std::os::unix::fs::symlink("missing.yaml", dir.path().join("compose.yaml")).unwrap();
    assert!(
        rustlet_compose::has_config_file(&options).unwrap(),
        "a broken default file must not cause fileless teardown"
    );
}
