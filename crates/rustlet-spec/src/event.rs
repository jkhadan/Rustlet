//! `GET /v1/events`: what happened, as it happens.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One event. Container actions: `create`, `start`, `die` (attributes
/// `exit_code`, `oom_killed`; or `error`, when the restart policy couldn't
/// start it again), `oom`, `stop`, `kill` (`signal`), `pause`, `unpause`,
/// `restart` (by the restart policy), `destroy`, `exec_create`,
/// `exec_start`, `exec_die` (`exec_id`, `exit_code`), `health_status`
/// (attribute `health_status`: `healthy` or `unhealthy`, when its
/// healthcheck's verdict changes; a start begins at `starting` without an
/// event), `commit` (attribute `new_image`: the new image's id). Every container
/// event carries `name` and `image`. Image actions, by name, with the
/// image's digest in `id`: `pull`, `build` (a build made it; by id, named
/// or not), `tag` (a build, `tag`, `commit` or `load` gave it the name),
/// `untag`, `load` (an unnamed image was loaded; by id), `delete` once the
/// image itself is gone (named as `rmi` was given it), and `prune` (the build
/// cache was forgotten: id `build cache`, attribute `deleted`, a count).
/// Network actions: `create`, `destroy`, `connect` and `disconnect`
/// (attribute `container`, running or not); volume actions: `create`,
/// `destroy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Event {
    /// RFC 3339 with nanoseconds, UTC.
    pub time: String,
    pub kind: EventKind,
    pub action: String,
    /// The container's or network's id, or the image's or volume's name.
    pub id: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    #[default]
    Container,
    Image,
    Network,
    Volume,
}

/// Query of `GET /v1/events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct EventsQuery {
    /// Replay the recent events at or after this time (RFC 3339, or Unix
    /// seconds) before the live ones. The daemon keeps the last 1024.
    pub since: Option<String>,
    /// Only events of this container (id, prefix or name).
    pub container: Option<String>,
}
