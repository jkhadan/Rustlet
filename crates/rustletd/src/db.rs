//! The daemon's durable state: `state.db`, SQLite.
//!
//! Three tables. A container's row holds what never changes after `create`
//! (its [`Record`], as JSON) and what does (its [`Persisted`] state, as
//! JSON, rewritten on every change), plus the columns that need an index:
//! the id and the unique name. A network's row and a volume's hold their
//! records ([`NetworkRecord`], [`VolumeRecord`]). JSON columns keep the
//! schema stable while the records grow fields (every field has a
//! default). Images are not here: their names live in the store's
//! `index.json` (docs/architecture.md §2.4), and which images and snapshots
//! are in use is derived from the containers' rows; so are the addresses
//! in use (each running container's [`NetRun`]) and the volumes in use.
//!
//! Schema versions (`PRAGMA user_version`): 1, containers (Phase 4); 2,
//! networks and volumes too (Phase 5). A version-1 database gains the two
//! tables in one transaction.
//!
//! `rusqlite` is synchronous. Every call is one short statement on a local
//! file under a mutex, so they run on the async threads directly.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use rusqlite::{Connection, ErrorCode, params};
use serde::{Deserialize, Serialize};

use rustlet_spec::container::{ContainerConfig, ContainerState};
use rustlet_spec::network::{PortMapping, PublishedPort};
use rustlet_spec::volume::MountSpec;

use crate::error::{ApiError, ApiResult};

/// `PRAGMA user_version` of the current schema.
const SCHEMA: i64 = 2;

/// The containers table, as version 1 made it.
const CONTAINERS: &str = "CREATE TABLE containers (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE,
    created TEXT NOT NULL,
    record  TEXT NOT NULL,
    state   TEXT NOT NULL
);";

/// What version 2 added.
const NETWORKS_AND_VOLUMES: &str = "CREATE TABLE networks (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE,
    created TEXT NOT NULL,
    record  TEXT NOT NULL
);
CREATE TABLE volumes (
    name    TEXT PRIMARY KEY,
    created TEXT NOT NULL,
    record  TEXT NOT NULL
);";

/// What a container was created with.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    pub id: String,
    pub name: String,
    pub created: String,
    /// As given.
    pub image: String,
    /// The manifest digest it was created from.
    pub image_id: String,
    /// Entrypoint + command, resolved at create.
    pub command: Vec<String>,
    pub config: ContainerConfig,
    /// The stop signal: the config's, else the image's, else SIGTERM.
    pub stop_signal: String,
    pub hostname: String,
    /// `--network container:<x>`: the full id `x` named at create.
    pub network_container: Option<String>,
    /// What it publishes: `-p`, plus the image's exposed ports with `-P`.
    pub ports: Vec<PortMapping>,
    /// Its mounts, with anonymous volumes named and the image's `VOLUME`s
    /// added (as anonymous volumes).
    pub mounts: Vec<MountSpec>,
}

/// What changes as the container runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Persisted {
    pub state: ContainerState,
    /// Stopped (or killed) by request: restart policies leave it alone.
    pub manually_stopped: bool,
    /// The cgroup of the current (or last) run. Recorded rather than
    /// derived: the daemon's cgroup parent may differ by its next start.
    pub cgroup: Option<String>,
    /// What the current run set up on the network, to undo after it.
    /// Recorded before the shim starts, so a daemon that dies mid-start
    /// leaves the next one enough to clean up (and the addresses in use).
    pub network: Option<NetRun>,
}

/// A run's network: its namespace, its place on a network, its published
/// ports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetRun {
    /// The pinned network namespace, if the run has one of its own.
    pub netns: Option<PathBuf>,
    /// `--network container:<id>`: whose namespace it shares.
    pub joined: Option<String>,
    /// The bridge network it is on.
    pub network_id: Option<String>,
    pub network_name: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
    pub gateway: Option<Ipv4Addr>,
    pub mac: Option<String>,
    /// The host's end of its veth pair.
    pub veth: Option<String>,
    pub ports: Vec<PublishedPort>,
    /// What the embedded DNS server answers for it (user-defined networks).
    pub dns_names: Vec<String>,
}

/// A network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkRecord {
    pub id: String,
    pub name: String,
    pub created: String,
    /// `10.89.0.0/24`.
    pub subnet: String,
    pub gateway: Ipv4Addr,
    pub bridge: String,
    pub internal: bool,
    pub labels: BTreeMap<String, String>,
}

impl Default for NetworkRecord {
    fn default() -> NetworkRecord {
        NetworkRecord {
            id: String::new(),
            name: String::new(),
            created: String::new(),
            subnet: String::new(),
            gateway: Ipv4Addr::UNSPECIFIED,
            bridge: String::new(),
            internal: false,
            labels: BTreeMap::new(),
        }
    }
}

/// A volume.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VolumeRecord {
    pub name: String,
    pub created: String,
    pub labels: BTreeMap<String, String>,
    pub anonymous: bool,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Opens (or creates, mode 0600) the database at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| anyhow::anyhow!("create {}: {e}", path.display()))?;
        let conn = Connection::open(path).map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match version {
            // One transaction each (`user_version` is part of it): a crash
            // in between can't leave tables at an older version.
            0 => conn.execute_batch(&format!(
                "BEGIN; {CONTAINERS} {NETWORKS_AND_VOLUMES} PRAGMA user_version = {SCHEMA}; COMMIT;"
            ))?,
            1 => {
                conn.execute_batch(&format!("BEGIN; {NETWORKS_AND_VOLUMES} PRAGMA user_version = {SCHEMA}; COMMIT;"))?
            }
            SCHEMA => {}
            v => anyhow::bail!("{}: schema version {v} is newer than this daemon's ({SCHEMA})", path.display()),
        }
        Ok(Db { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds a container. A name that is taken is a conflict.
    pub fn insert(&self, record: &Record, state: &Persisted) -> ApiResult<()> {
        let r = self.conn().execute(
            "INSERT INTO containers (id, name, created, record, state) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![record.id, record.name, record.created, json(record), json(state)],
        );
        match r {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation => {
                Err(ApiError::conflict(format!("the container name {:?} is already in use", record.name)))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_state(&self, id: &str, state: &Persisted) -> ApiResult<()> {
        self.conn().execute("UPDATE containers SET state = ?2 WHERE id = ?1", params![id, json(state)])?;
        Ok(())
    }

    pub fn remove(&self, id: &str) -> ApiResult<()> {
        self.conn().execute("DELETE FROM containers WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Every container, oldest first.
    pub fn all(&self) -> ApiResult<Vec<(Record, Persisted)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT record, state FROM containers ORDER BY created, id")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (record, state) = row?;
            let record: Record =
                serde_json::from_str(&record).map_err(|e| ApiError::internal(format!("a container record: {e}")))?;
            let state = serde_json::from_str(&state).unwrap_or_else(|e| {
                tracing::warn!(id = %record.id, "unreadable state, starting from scratch: {e}");
                Persisted::default()
            });
            out.push((record, state));
        }
        Ok(out)
    }

    // ── networks ──────────────────────────────────────────────────────────

    /// Adds a network. A name that is taken is a conflict.
    pub fn insert_network(&self, n: &NetworkRecord) -> ApiResult<()> {
        let r = self.conn().execute(
            "INSERT INTO networks (id, name, created, record) VALUES (?1, ?2, ?3, ?4)",
            params![n.id, n.name, n.created, json(n)],
        );
        match r {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation => {
                Err(ApiError::conflict(format!("a network named {:?} exists already", n.name)))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn remove_network(&self, id: &str) -> ApiResult<()> {
        self.conn().execute("DELETE FROM networks WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Every network, oldest first.
    pub fn networks(&self) -> ApiResult<Vec<NetworkRecord>> {
        self.records("SELECT record FROM networks ORDER BY created, id", "a network record")
    }

    // ── volumes ───────────────────────────────────────────────────────────

    /// Adds a volume. A name that is taken is a conflict.
    pub fn insert_volume(&self, v: &VolumeRecord) -> ApiResult<()> {
        let r = self.conn().execute(
            "INSERT INTO volumes (name, created, record) VALUES (?1, ?2, ?3)",
            params![v.name, v.created, json(v)],
        );
        match r {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation => {
                Err(ApiError::conflict(format!("a volume named {:?} exists already", v.name)))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn remove_volume(&self, name: &str) -> ApiResult<()> {
        self.conn().execute("DELETE FROM volumes WHERE name = ?1", params![name])?;
        Ok(())
    }

    /// Every volume, oldest first.
    pub fn volumes(&self) -> ApiResult<Vec<VolumeRecord>> {
        self.records("SELECT record FROM volumes ORDER BY created, name", "a volume record")
    }

    fn records<T: serde::de::DeserializeOwned>(&self, sql: &str, what: &str) -> ApiResult<Vec<T>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?).map_err(|e| ApiError::internal(format!("{what}: {e}")))?);
        }
        Ok(out)
    }

    #[cfg(test)]
    pub fn exists(&self, id: &str) -> ApiResult<bool> {
        use rusqlite::OptionalExtension;
        let n: Option<i64> =
            self.conn().query_row("SELECT 1 FROM containers WHERE id = ?1", params![id], |r| r.get(0)).optional()?;
        Ok(n.is_some())
    }
}

fn json(v: &impl Serialize) -> String {
    serde_json::to_string(v).expect("records serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustlet_spec::container::ContainerStatus;

    fn record(id: &str, name: &str) -> Record {
        Record { id: id.into(), name: name.into(), created: format!("2026-10-01T00:00:0{id}Z"), ..Default::default() }
    }

    #[test]
    fn containers_round_trip_and_names_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let db = Db::open(&path).unwrap();
        db.insert(&record("1", "web"), &Persisted::default()).unwrap();
        db.insert(&record("2", "db"), &Persisted::default()).unwrap();
        let e = db.insert(&record("3", "web"), &Persisted::default()).unwrap_err();
        assert_eq!(e.kind, rustlet_spec::ErrorKind::Conflict);
        let mut st = Persisted::default();
        st.state.status = ContainerStatus::Running;
        st.state.pid = Some(42);
        st.manually_stopped = true;
        db.save_state("2", &st).unwrap();
        drop(db);
        // Reopened: the same rows.
        let db = Db::open(&path).unwrap();
        let all = db.all().unwrap();
        assert_eq!(all.iter().map(|(r, _)| r.name.as_str()).collect::<Vec<_>>(), ["web", "db"]);
        assert_eq!(all[1].1, st);
        db.remove("1").unwrap();
        assert!(!db.exists("1").unwrap() && db.exists("2").unwrap());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn networks_and_volumes_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("state.db")).unwrap();
        let net = NetworkRecord {
            id: "n1".into(),
            name: "backend".into(),
            created: "2026-10-02T00:00:00Z".into(),
            subnet: "10.89.1.0/24".into(),
            gateway: Ipv4Addr::new(10, 89, 1, 1),
            bridge: "rlbn1".into(),
            ..Default::default()
        };
        db.insert_network(&net).unwrap();
        let taken = db.insert_network(&NetworkRecord { id: "n2".into(), ..net.clone() }).unwrap_err();
        assert_eq!(taken.kind, rustlet_spec::ErrorKind::Conflict);
        assert_eq!(db.networks().unwrap(), [net]);
        db.remove_network("n1").unwrap();
        assert!(db.networks().unwrap().is_empty());
        let vol = VolumeRecord { name: "data".into(), created: "2026-10-02T00:00:00Z".into(), ..Default::default() };
        db.insert_volume(&vol).unwrap();
        assert!(db.insert_volume(&vol).is_err());
        assert_eq!(db.volumes().unwrap(), [vol]);
        db.remove_volume("data").unwrap();
        assert!(db.volumes().unwrap().is_empty());
    }

    #[test]
    fn a_version_1_database_gains_the_new_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("{CONTAINERS} PRAGMA user_version = 1;")).unwrap();
            conn.execute(
                "INSERT INTO containers (id, name, created, record, state) VALUES ('1', 'old', 'x', ?1, '{}')",
                params![json(&record("1", "old"))],
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(db.all().unwrap()[0].0.name, "old", "its containers stay");
        assert!(db.networks().unwrap().is_empty() && db.volumes().unwrap().is_empty());
        let v: i64 = db.conn().pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v, SCHEMA);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        Db::open(&path).unwrap();
        Connection::open(&path).unwrap().pragma_update(None, "user_version", 99).unwrap();
        assert!(Db::open(&path).is_err());
    }
}
