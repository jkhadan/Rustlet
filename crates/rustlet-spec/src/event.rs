//! `GET /v1/events`: what happened, as it happens.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One event. Container actions: `create`, `start`, `die` (attributes
/// `exit_code`, `oom_killed`), `oom`, `stop`, `kill` (`signal`), `pause`,
/// `unpause`, `restart` (by the restart policy), `destroy`, `exec_create`,
/// `exec_start`, `exec_die` (`exec_id`, `exit_code`). Image actions: `pull`,
/// `untag`, `delete`. Every container event carries `name` and `image`.
/// Network actions: `create`, `destroy`, `connect` and `disconnect`
/// (attribute `container`); volume actions: `create`, `destroy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    #[default]
    Container,
    Image,
    Network,
    Volume,
}

/// Query of `GET /v1/events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsQuery {
    /// Replay the recent events at or after this time (RFC 3339, or Unix
    /// seconds) before the live ones. The daemon keeps the last 1024.
    pub since: Option<String>,
    /// Only events of this container (id, prefix or name).
    pub container: Option<String>,
}
