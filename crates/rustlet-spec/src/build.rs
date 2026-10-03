//! Building images: `rustlet build`, `rustlet builder prune`, and `rustlet
//! commit`.
//!
//! A build is one request. The client packs the build context (a directory,
//! less what its `.dockerignore` excludes) into a tar archive and sends it as
//! the body of `POST /v1/build`; the options travel in the query, as one
//! JSON value ([`BuildQuery`]), since they hold lists and maps that a query
//! string has no syntax for. The daemon answers with NDJSON [`BuildEvent`]s
//! as the build goes, and ends with [`BuildEvent::Done`] or
//! [`BuildEvent::Error`].
//!
//! ```text
//!  client                                   rustletd
//!  pack the context ──tar──► POST /v1/build?options={…}
//!                                           unpack it, read the Containerfile
//!                     ◄──── {"type":"step","step":1,"total":4,"instruction":"FROM alpine"}
//!                     ◄──── {"type":"output","step":2,"stream":"stdout","text":"…"}
//!                     ◄──── {"type":"done","id":"sha256:…","names":["docker.io/library/app:latest"]}
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::image::{PullEvent, PullPolicy};
use crate::logs::LogStream;
use crate::network::NetworkMode;

/// What a build is asked to do: the JSON in [`BuildQuery::options`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct BuildOptions {
    /// Names for the image (`-t`): `app`, `registry.example/app:1.0`.
    /// Without one, the image is kept unnamed (`rustlet images` lists it as
    /// `<none>`) until it is removed by its id.
    pub tags: Vec<String>,
    /// The Containerfile's path inside the context; default `Containerfile`,
    /// else `Dockerfile`.
    pub dockerfile: Option<String>,
    /// `--build-arg NAME=VALUE`: values for the file's `ARG`s.
    pub build_args: BTreeMap<String, String>,
    /// `--target`: build up to this stage (its name, or its index from 0);
    /// default the last stage.
    pub target: Option<String>,
    /// `--no-cache`: run every step again, whatever the cache has.
    pub no_cache: bool,
    /// When to pull base images: `missing` (default), or `always` (ask the
    /// registry what each tag points at now, `--pull`).
    pub pull: PullPolicy,
    /// The network `RUN` steps get: `bridge` (default), `host`, `none`, or a
    /// network's name. Not `container:<x>`.
    pub network: NetworkMode,
    /// `--label`: labels for the image, over the Containerfile's `LABEL`s.
    pub labels: BTreeMap<String, String>,
}

/// Query of `POST /v1/build`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct BuildQuery {
    /// [`BuildOptions`], as JSON.
    pub options: String,
}

impl BuildQuery {
    pub fn new(options: &BuildOptions) -> BuildQuery {
        BuildQuery { options: serde_json::to_string(options).expect("build options serialize") }
    }

    /// The options; empty means the defaults.
    pub fn options(&self) -> Result<BuildOptions, String> {
        if self.options.trim().is_empty() {
            return Ok(BuildOptions::default());
        }
        serde_json::from_str(&self.options).map_err(|e| format!("build options: {e}"))
    }
}

/// One line of the NDJSON `build` response, in order: `context`; then for
/// each stage built, `stage` and its steps; each step `step`, then `cached`
/// or the work (`pull` events for a base image, `container` and `output`
/// for a `RUN`), then `step_done`; last `done`. A failure ends the stream
/// with `error`. `warning`s may come anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuildEvent {
    /// The daemon has the context: `files` entries, `bytes` of file data.
    Context {
        files: u64,
        bytes: u64,
    },
    /// A stage starts. Only the stages the target needs are built, in the
    /// file's order.
    Stage {
        index: usize,
        name: Option<String>,
        base: String,
    },
    /// An instruction starts: `step` of `total`, counted over the stages
    /// built (the `FROM` lines included), as written but with variables
    /// expanded.
    Step {
        step: usize,
        total: usize,
        instruction: String,
    },
    /// Progress of pulling a stage's base image.
    Pull {
        event: PullEvent,
    },
    /// The step's result came from the build cache: nothing ran.
    Cached {
        step: usize,
    },
    /// The container a `RUN` step runs in (removed once the step is done).
    Container {
        step: usize,
        id: String,
    },
    /// What a `RUN` step printed, as it comes.
    Output {
        step: usize,
        stream: LogStream,
        text: String,
    },
    /// The step is done. `layer`: the digest of the layer it added, if it
    /// added one (`RUN`, `COPY` and `ADD` do; the others only change the
    /// image's config).
    StepDone {
        step: usize,
        layer: Option<String>,
    },
    /// Something the build ignored or did differently than asked.
    Warning {
        message: String,
    },
    /// The image is stored: its id (manifest digest) and its names.
    Done {
        id: String,
        names: Vec<String>,
    },
    Error {
        message: String,
    },
}

/// `POST /v1/commit`: a container's changes as a new image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct CommitRequest {
    /// The container: id, unique id prefix, or name.
    pub container: String,
    /// The new image's name; without one it is kept unnamed.
    pub reference: Option<String>,
    /// `-m`: the comment of the image's new history entry.
    pub comment: Option<String>,
    /// `-a`: the image's author.
    pub author: Option<String>,
    /// Freeze a running container while its changes are read (default
    /// true): otherwise a file it writes meanwhile may be caught half-way.
    pub pause: bool,
    /// `-c`: Containerfile instructions applied to the new image's config:
    /// `CMD`, `ENTRYPOINT`, `ENV`, `EXPOSE`, `LABEL`, `ONBUILD`, `USER`,
    /// `VOLUME`, `WORKDIR`, `STOPSIGNAL`, `HEALTHCHECK`.
    pub changes: Vec<String>,
}

impl Default for CommitRequest {
    fn default() -> CommitRequest {
        CommitRequest {
            container: String::new(),
            reference: None,
            comment: None,
            author: None,
            pause: true,
            changes: Vec::new(),
        }
    }
}

/// `201` from `POST /v1/commit`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct CommitResponse {
    /// The new image's id (manifest digest).
    pub id: String,
    /// Its name, if it was given one.
    pub name: Option<String>,
    /// The digest of the layer holding the container's changes.
    pub layer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_travel_as_json_in_the_query() {
        let o = BuildOptions {
            tags: vec!["app:1".into()],
            build_args: [("V".to_owned(), "a b&c=d".to_owned())].into(),
            network: NetworkMode::None,
            ..Default::default()
        };
        let q = BuildQuery::new(&o);
        assert_eq!(q.options().unwrap(), o);
        assert_eq!(BuildQuery::default().options().unwrap(), BuildOptions::default());
        assert!(BuildQuery { options: "{".into() }.options().is_err());
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(json["network"], "none");
        assert_eq!(json["pull"], "missing");
    }

    #[test]
    fn events_are_tagged_by_type() {
        let e = BuildEvent::Output { step: 2, stream: LogStream::Stderr, text: "x\n".into() };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"type":"output","step":2,"stream":"stderr","text":"x\n"}"#);
        let pull: BuildEvent = serde_json::from_str(
            r#"{"type":"pull","event":{"status":"ready","reference":"r","manifest":"sha256:ab"}}"#,
        )
        .unwrap();
        assert_eq!(
            pull,
            BuildEvent::Pull { event: PullEvent::Ready { reference: "r".into(), manifest: "sha256:ab".into() } }
        );
        let done = BuildEvent::StepDone { step: 1, layer: None };
        assert_eq!(serde_json::to_string(&done).unwrap(), r#"{"type":"step_done","step":1,"layer":null}"#);
    }

    #[test]
    fn commits_pause_unless_told_not_to() {
        let c: CommitRequest = serde_json::from_str(r#"{"container":"web"}"#).unwrap();
        assert!(c.pause);
        let c: CommitRequest = serde_json::from_str(r#"{"container":"web","pause":false}"#).unwrap();
        assert!(!c.pause);
    }
}
