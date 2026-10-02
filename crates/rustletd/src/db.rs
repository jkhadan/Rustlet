//! The daemon's durable state: `state.db`, SQLite.
//!
//! One table for now. A container's row holds what never changes after
//! `create` (its [`Record`], as JSON) and what does (its [`Persisted`]
//! state, as JSON, rewritten on every change), plus the columns that need
//! an index: the id and the unique name. JSON columns keep the schema
//! stable while the records grow fields (every field has a default).
//! Images are not here: their names live in the store's `index.json`
//! (docs/architecture.md §2.4), and which images and snapshots are in use is
//! derived from these rows.
//!
//! `rusqlite` is synchronous. Every call is one short statement on a local
//! file under a mutex, so they run on the async threads directly.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, ErrorCode, params};
use serde::{Deserialize, Serialize};

use rustlet_spec::container::{ContainerConfig, ContainerState};

use crate::error::{ApiError, ApiResult};

/// `PRAGMA user_version` of the current schema.
const SCHEMA: i64 = 1;

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
            0 => {
                conn.execute_batch(
                    "CREATE TABLE containers (
                        id      TEXT PRIMARY KEY,
                        name    TEXT NOT NULL UNIQUE,
                        created TEXT NOT NULL,
                        record  TEXT NOT NULL,
                        state   TEXT NOT NULL
                    );",
                )?;
                conn.pragma_update(None, "user_version", SCHEMA)?;
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
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        Db::open(&path).unwrap();
        Connection::open(&path).unwrap().pragma_update(None, "user_version", 99).unwrap();
        assert!(Db::open(&path).is_err());
    }
}
