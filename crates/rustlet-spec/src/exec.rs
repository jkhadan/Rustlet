//! Running another process in a live container (`rustlet exec`).
//!
//! Two steps, as in Docker: `POST /v1/containers/{id}/exec` checks the
//! request and returns an exec id; then `GET /v1/exec/{id}/start` (a
//! WebSocket, [`crate::stream`]) runs the process attached, or `POST
//! /v1/exec/{id}/start` runs it detached. An exec that isn't started within
//! a minute is forgotten.

use serde::{Deserialize, Serialize};

/// `POST /v1/containers/{id}/exec`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecConfig {
    /// The program and its arguments (looked up in the container's `PATH`).
    pub cmd: Vec<String>,
    /// A PTY of its own.
    pub tty: bool,
    /// Send the client's input to it.
    pub stdin: bool,
    /// `KEY=VALUE`, over the container's environment.
    pub env: Vec<String>,
    /// `user[:group]`, resolved in the container's `/etc/passwd`; default
    /// the container's user.
    pub user: Option<String>,
    /// Default: the container's working directory.
    pub workdir: Option<String>,
}

/// `201` from `POST /v1/containers/{id}/exec`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecCreated {
    pub id: String,
}

/// `POST /v1/exec/{id}/start` (detached).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecStarted {
    /// Host PID of the process.
    pub pid: i32,
}

/// `GET /v1/exec/{id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecInspect {
    pub id: String,
    pub container_id: String,
    pub config: ExecConfig,
    pub running: bool,
    pub pid: Option<i32>,
    pub exit_code: Option<i32>,
}
