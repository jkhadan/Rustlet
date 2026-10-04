//! Building an image: the client's half of `rustlet build`.
//!
//! ```text
//!  the Build view                 this module                               rustletd
//!  ──────────────                 ───────────                               ────────
//!  image_build(context, file, ──► locate: the directory, its Containerfile
//!              options)                  (default Containerfile, else
//!                                        Dockerfile), the name it has in
//!                                        the archive (options.dockerfile)
//!                                 pack, on a blocking thread ──tar──► POST /v1/build?options=…
//!            ◄──── stream id ──── (the daemon answers at once)
//!  onmessage({items: [step, …]}) ◄─ BuildEvents, batched ◄──────────────── NDJSON
//! ```
//!
//! As with the CLI, the client packs the context (`rustlet_build::context`:
//! the directory less what its ignore file excludes), so what is excluded
//! never leaves it; the archive is sent as it is written
//! (`RequestBody::pipe`), never held whole.
//!
//! **Whose failure it is.** A packer that fails (a file the user may not
//! read) cuts the body short, and the daemon then reports a truncated
//! context, or the request fails as a whole, neither of which says what
//! went wrong. So a failed request or stream waits briefly for the packer:
//! if it failed on its own, its error is the one shown. If it stopped only
//! because the request was gone (the daemon refused the options, the build
//! failed, the view stopped the build), its failure says nothing new and
//! the request's error stands. That is told by the packer's writes, not by
//! its message: [`Tracked`] notes a write the request no longer took.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::{BoxFuture, FutureExt, Shared};
use futures::stream::{BoxStream, Stream, StreamExt};
use rustlet_build::context::{ContextError, Packed};
use rustlet_client::{BodyWriter, Client, RequestBody};
use rustlet_spec::build::{BuildEvent, BuildOptions};

use crate::error::{CommandError, CommandResult};
use crate::paths;

/// How long a failed request waits to hear whether the packer failed.
/// The packer stops at its next write once the request is gone, so only a
/// packer stuck in a read could take this long.
const PACKER_GRACE: Duration = Duration::from_secs(5);

/// What the packer's failure was, once it has stopped: `None` when it
/// finished, or when it stopped because the request was gone.
pub type Packing = Shared<BoxFuture<'static, Option<String>>>;

/// A build the daemon accepted: its events as they come, and the packer,
/// which may still be sending the context.
pub struct Build {
    pub events: rustlet_client::JsonStream<BuildEvent>,
    pub packing: Packing,
}

/// The context directory, its Containerfile, and the Containerfile's name
/// inside the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub context: PathBuf,
    pub containerfile: PathBuf,
    pub dockerfile: String,
}

/// Finds what to pack: `context` must be a directory; `containerfile`, if
/// given, is a file (relative to the context, absolute, or from `~/`);
/// without one, the context's `Containerfile`, else its `Dockerfile`.
pub fn locate(context: &str, containerfile: Option<&str>) -> CommandResult<Located> {
    let dir = paths::user_path(context)?;
    match dir.metadata() {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(CommandError::invalid(format!("{}: not a directory", dir.display()))),
        Err(e) => return Err(CommandError::invalid(format!("{}: {e}", dir.display()))),
    }
    let file = match containerfile.map(str::trim).filter(|f| !f.is_empty()) {
        Some(typed) => containerfile_path(&dir, typed)?,
        None => rustlet_build::context::default_containerfile(&dir).ok_or_else(|| {
            CommandError::invalid(format!(
                "{}: no Containerfile or Dockerfile there; name the file to build from",
                dir.display()
            ))
        })?,
    };
    match file.metadata() {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(CommandError::invalid(format!("{}: not a file", file.display()))),
        Err(e) => return Err(CommandError::invalid(format!("{}: {e}", file.display()))),
    }
    let dockerfile = rustlet_build::context::dockerfile_name(&dir, &file)
        .map_err(|e| CommandError::invalid(format!("the Containerfile: {e}")))?;
    Ok(Located { context: dir, containerfile: file, dockerfile })
}

/// A Containerfile as typed in the form: relative to the context (as a
/// compose file's `dockerfile:` is; the app has no working directory),
/// absolute, or from `~/`.
pub fn containerfile_path(context: &Path, typed: &str) -> CommandResult<PathBuf> {
    let typed = typed.trim();
    if typed.starts_with('/') || typed.starts_with('~') { paths::user_path(typed) } else { Ok(context.join(typed)) }
}

/// Starts the build: packs the context into the request's body as it is
/// sent. The daemon's refusals before the build starts (options it can't
/// take) and an unreachable daemon fail this; the build's own failure ends
/// its stream.
pub async fn start(
    client: &Client,
    context: &str,
    containerfile: Option<&str>,
    mut options: BuildOptions,
) -> CommandResult<Build> {
    let located = locate(context, containerfile)?;
    options.dockerfile = Some(located.dockerfile.clone());
    let (body, writer) = RequestBody::pipe();
    let packing = pack_in_background(located, writer);
    match client.build(&options, body).await {
        Ok(events) => Ok(Build { events, packing }),
        Err(e) => Err(request_error(e, packing).await),
    }
}

/// Packs on a blocking thread (the tar writer blocks, and so does the
/// pipe while the connection catches up).
fn pack_in_background(located: Located, mut writer: BodyWriter) -> Packing {
    let task = tokio::task::spawn_blocking(move || {
        let mut out = Tracked { writer: &mut writer, gone: false };
        let packed = rustlet_build::context::pack(&located.context, &located.containerfile, &mut out);
        let gone = out.gone;
        match &packed {
            Ok(p) => {
                tracing::debug!(entries = p.entries, bytes = p.bytes, excluded = p.excluded, "context packed");
                // A body that can't end has lost its request, which reports it.
                let _ = writer.finish();
            }
            Err(e) => writer.abort(io::Error::other(e.to_string())),
        }
        (packed, gone)
    });
    async move { packer_failure(task.await) }.boxed().shared()
}

/// The body's writer, noting a write the request no longer took (every
/// error a [`BodyWriter`] gives means that), whatever the packer then makes
/// of the error.
struct Tracked<'a> {
    writer: &'a mut BodyWriter,
    gone: bool,
}

impl Write for Tracked<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writer.write(data).inspect_err(|_| self.gone = true)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().inspect_err(|_| self.gone = true)
    }
}

/// The packer's own failure, if it had one: the second value says the
/// request went away under it, in which case its error is only an echo.
fn packer_failure(joined: Result<(Result<Packed, ContextError>, bool), tokio::task::JoinError>) -> Option<String> {
    match joined {
        Ok((Ok(_), _)) | Ok((Err(_), true)) => None,
        Ok((Err(e), false)) => Some(format!("the build context: {e}")),
        Err(e) => Some(format!("packing the build context failed: {e}")),
    }
}

/// Why the request failed: the daemon's refusal, or an unreachable daemon,
/// as they are; otherwise (the body broke off) the packer's failure, if it
/// failed.
pub async fn request_error(e: rustlet_client::Error, packing: Packing) -> CommandError {
    if matches!(e, rustlet_client::Error::Api { .. } | rustlet_client::Error::Connect { .. }) {
        return e.into();
    }
    blame(e, packing).await
}

/// The packer's failure if it failed, else `e`.
async fn blame(e: rustlet_client::Error, packing: Packing) -> CommandError {
    match tokio::time::timeout(PACKER_GRACE, packing).await {
        Ok(Some(why)) => CommandError::invalid(why),
        _ => e.into(),
    }
}

/// The build's events, as the frontend gets them: a failure is the
/// packer's when the packer failed (see the module's docs).
pub fn events(build: Build) -> BoxStream<'static, Result<BuildEvent, CommandError>> {
    events_of(build.events, build.packing)
}

fn events_of<S>(events: S, packing: Packing) -> BoxStream<'static, Result<BuildEvent, CommandError>>
where
    S: Stream<Item = rustlet_client::Result<BuildEvent>> + Send + 'static,
{
    events
        .then(move |item| {
            let packing = packing.clone();
            async move {
                match item {
                    Ok(event) => Ok(event),
                    Err(e) => Err(blame(e, packing).await),
                }
            }
        })
        .boxed()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rustlet_spec::ErrorKind;
    use rustlet_spec::logs::LogStream;
    use tauri::ipc::{Channel, InvokeResponseBody};

    use super::*;
    use crate::streams::{StreamMessage, forward};

    fn packed() -> Packing {
        futures::future::ready(None).boxed().shared()
    }

    fn failed_packing(why: &str) -> Packing {
        futures::future::ready(Some(why.to_owned())).boxed().shared()
    }

    /// A packer that never stops (stuck reading a file on a dead mount).
    fn stuck() -> Packing {
        futures::future::pending().boxed().shared()
    }

    fn recorder() -> (Channel<StreamMessage<BuildEvent>>, Arc<Mutex<Vec<serde_json::Value>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let sink = got.clone();
        let channel = Channel::new(move |body| {
            if let InvokeResponseBody::Json(json) = body {
                sink.lock().unwrap().push(serde_json::from_str(&json).unwrap());
            }
            Ok(())
        });
        (channel, got)
    }

    #[test]
    fn a_containerfile_is_relative_to_the_context_unless_it_says_otherwise() {
        let ctx = Path::new("/srv/app");
        assert_eq!(
            containerfile_path(ctx, "build/Containerfile").unwrap(),
            PathBuf::from("/srv/app/build/Containerfile")
        );
        assert_eq!(containerfile_path(ctx, "../Dockerfile").unwrap(), PathBuf::from("/srv/app/../Dockerfile"));
        assert_eq!(containerfile_path(ctx, " /etc/x/Dockerfile ").unwrap(), PathBuf::from("/etc/x/Dockerfile"));
        if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
            assert_eq!(containerfile_path(ctx, "~/Dockerfile").unwrap(), PathBuf::from(home).join("Dockerfile"));
        }
    }

    #[test]
    fn a_context_that_is_no_directory_is_refused_before_anything_is_sent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        let e = locate(file.to_str().unwrap(), None).unwrap_err();
        assert_eq!((e.kind.as_str(), e.message.ends_with("not a directory")), ("invalid", true), "{e:?}");
        let e = locate(dir.path().join("missing").to_str().unwrap(), None).unwrap_err();
        assert_eq!(e.kind, "invalid");
        // A Containerfile named but not there, before the file's name is
        // asked for.
        let e = locate(dir.path().to_str().unwrap(), Some("Nope")).unwrap_err();
        assert!(e.message.starts_with(&dir.path().join("Nope").display().to_string()), "{e:?}");
        assert_eq!(locate("relative/dir", None).unwrap_err().kind, "invalid");
    }

    #[test]
    fn the_packer_is_blamed_only_for_a_failure_of_its_own() {
        let invalid = || Err(ContextError::Invalid("a symlink loops".into()));
        assert_eq!(packer_failure(Ok((invalid(), false))).as_deref(), Some("the build context: a symlink loops"));
        // It stopped because the request was gone: the request says why.
        assert_eq!(packer_failure(Ok((invalid(), true))), None);
        let gone = ContextError::Io { path: "app/big.bin".into(), source: io::ErrorKind::BrokenPipe.into() };
        assert_eq!(packer_failure(Ok((Err(gone), true))), None);
        assert_eq!(packer_failure(Ok((Ok(Packed::default()), false))), None);
    }

    #[tokio::test]
    async fn a_refusal_is_the_daemons_whatever_became_of_the_packer() {
        let refused = rustlet_client::Error::api(ErrorKind::Invalid, "--network container:x: a build can't use one");
        let e = request_error(refused, failed_packing("x: permission denied")).await;
        assert_eq!((e.kind.as_str(), e.message.as_str()), ("invalid", "--network container:x: a build can't use one"));
        let down = rustlet_client::Error::Connect {
            socket: "/run/rustlet/rustlet.sock".into(),
            cause: io::ErrorKind::ConnectionRefused.into(),
        };
        assert_eq!(request_error(down, stuck()).await.kind, "unreachable");
    }

    #[tokio::test]
    async fn a_body_that_broke_off_is_blamed_on_a_packer_that_failed() {
        let broke = || rustlet_client::Error::Io(io::ErrorKind::UnexpectedEof.into());
        let e = request_error(broke(), failed_packing("the build context: secret.key: permission denied")).await;
        assert_eq!(e, CommandError::invalid("the build context: secret.key: permission denied"));
        let e = request_error(broke(), packed()).await;
        assert_eq!(e.kind, "failed");
        assert!(e.message.starts_with("connection to rustletd"), "{e:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_packer_holds_the_error_up_only_so_long() {
        let e = request_error(rustlet_client::Error::Protocol("x".into()), stuck()).await;
        assert_eq!(e.message, "protocol error: x");
    }

    #[tokio::test]
    async fn the_build_streams_to_the_frontend_and_its_failure_names_the_packer() {
        let (channel, got) = recorder();
        let events = futures::stream::iter([
            Ok(BuildEvent::Step { step: 1, total: 2, instruction: "FROM alpine".into() }),
            Ok(BuildEvent::Output { step: 2, stream: LogStream::Stdout, text: "hi\n".into() }),
            // The daemon's own error line, which rustlet-client makes the
            // stream's error: the context it got was cut short.
            Err(rustlet_client::Error::Stream("the build context: unexpected end of archive".into())),
        ]);
        forward(events_of(events, failed_packing("the build context: app/db: permission denied")), channel).await;
        assert_eq!(
            *got.lock().unwrap(),
            [
                serde_json::json!({"type": "items", "items": [
                    {"type": "step", "step": 1, "total": 2, "instruction": "FROM alpine"},
                    {"type": "output", "step": 2, "stream": "stdout", "text": "hi\n"},
                ]}),
                serde_json::json!({"type": "error", "error": {
                    "kind": "invalid", "message": "the build context: app/db: permission denied",
                }}),
            ]
        );
    }

    #[tokio::test]
    async fn a_step_that_fails_is_the_builds_own_failure() {
        let (channel, got) = recorder();
        let failure = "The command '/bin/sh -c exit 3' returned a non-zero code: 3";
        let events = futures::stream::iter([
            Ok(BuildEvent::Step { step: 2, total: 2, instruction: "RUN exit 3".into() }),
            Err(rustlet_client::Error::Stream(failure.into())),
        ]);
        forward(events_of(events, packed()), channel).await;
        let got = got.lock().unwrap();
        assert_eq!(got[1], serde_json::json!({"type": "error", "error": {"kind": "failed", "message": failure}}));
    }
}
