//! Image archives in files the user names: `rustlet save -o FILE` and
//! `rustlet load -i FILE`.
//!
//! The daemon streams `save`'s archive (an OCI image layout in a tar), and
//! `load` takes one as its request body; the app is the one with the
//! user's files, so it writes the one and reads the other. Nothing here is
//! held whole: an archive of a few gigabytes goes through in chunks.
//!
//! A saved file is created new (one that exists is never overwritten: the
//! user picks another name), and removed again if the save fails halfway,
//! so a file under that name is always a whole archive.

use std::io;
use std::path::Path;

use futures::{Stream, StreamExt};
use rustlet_client::Client;
use tokio::io::AsyncWriteExt;

use crate::error::{CommandError, CommandResult};
use crate::paths;

/// Saves the images `names` (names or ids) into a new file at `path`;
/// returns its size.
pub async fn save(client: &Client, names: &[String], path: &str) -> CommandResult<u64> {
    let path = paths::user_path(path)?;
    // What the daemon refuses (no such image) is refused before any file
    // exists.
    let archive = client.save_images(names).await?;
    write_new(&path, archive).await
}

/// Writes `chunks` into a new file at `path`; a failure removes what was
/// written.
pub async fn write_new<S, B>(path: &Path, chunks: S) -> CommandResult<u64>
where
    S: Stream<Item = rustlet_client::Result<B>> + Unpin,
    B: AsRef<[u8]>,
{
    let file =
        tokio::fs::OpenOptions::new().write(true).create_new(true).open(path).await.map_err(|e| file_error(path, e))?;
    let written = write_all(file, chunks, path).await;
    if written.is_err() {
        // Best effort: what stays behind is the failure the user is told of.
        let _ = tokio::fs::remove_file(path).await;
    }
    written
}

async fn write_all<S, B>(mut file: tokio::fs::File, mut chunks: S, path: &Path) -> CommandResult<u64>
where
    S: Stream<Item = rustlet_client::Result<B>> + Unpin,
    B: AsRef<[u8]>,
{
    let mut size = 0u64;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        let chunk = chunk.as_ref();
        file.write_all(chunk).await.map_err(|e| file_error(path, e))?;
        size += chunk.len() as u64;
    }
    // A tokio file may still hold the last write; and saved means on the
    // disk, since this file may be the only copy that is kept.
    file.flush().await.map_err(|e| file_error(path, e))?;
    file.sync_all().await.map_err(|e| file_error(path, e))?;
    Ok(size)
}

/// The archive at `path`, to be read as `load`'s body.
pub fn open(path: &str) -> CommandResult<std::fs::File> {
    let path = paths::user_path(path)?;
    let file = std::fs::File::open(&path).map_err(|e| file_error(&path, e))?;
    match file.metadata() {
        Ok(m) if m.is_file() => Ok(file),
        Ok(_) => Err(CommandError::invalid(format!("{}: not a file", path.display()))),
        Err(e) => Err(file_error(&path, e)),
    }
}

/// A file that can't be used: the user's to fix (a wrong name, a file in
/// the way, a directory that isn't theirs) is `invalid`; the rest (a full
/// disk) `failed`.
fn file_error(path: &Path, e: io::Error) -> CommandError {
    let message = match e.kind() {
        io::ErrorKind::AlreadyExists => format!("{} already exists: choose another name", path.display()),
        _ => format!("{}: {e}", path.display()),
    };
    match e.kind() {
        io::ErrorKind::AlreadyExists
        | io::ErrorKind::NotFound
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::IsADirectory
        | io::ErrorKind::NotADirectory
        | io::ErrorKind::ReadOnlyFilesystem => CommandError::invalid(message),
        _ => CommandError::failed(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(
        items: Vec<rustlet_client::Result<&'static [u8]>>,
    ) -> impl Stream<Item = rustlet_client::Result<&'static [u8]>> + Unpin {
        futures::stream::iter(items)
    }

    #[tokio::test]
    async fn an_archive_is_written_whole_into_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.tar");
        let size = write_new(&path, chunks(vec![Ok(b"oci-"), Ok(b"layout")])).await.unwrap();
        assert_eq!(size, 10);
        assert_eq!(std::fs::read(&path).unwrap(), b"oci-layout");
    }

    #[tokio::test]
    async fn a_save_that_breaks_off_leaves_no_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.tar");
        // The daemon ends a failed save's body early: the stream fails.
        let broken = chunks(vec![Ok(b"oci-"), Err(rustlet_client::Error::Stream("the body ended early".into()))]);
        let e = write_new(&path, broken).await.unwrap_err();
        assert_eq!(e.message, "the body ended early");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_file_that_exists_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keep.tar");
        std::fs::write(&path, "precious").unwrap();
        let e = write_new(&path, chunks(vec![Ok(b"x")])).await.unwrap_err();
        assert_eq!(e.kind, "invalid");
        assert!(e.message.ends_with("already exists: choose another name"), "{e:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "precious");
        let e = write_new(&dir.path().join("no/such/dir.tar"), chunks(vec![])).await.unwrap_err();
        assert_eq!(e.kind, "invalid");
    }

    #[test]
    fn only_a_file_can_be_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let e = open(dir.path().to_str().unwrap()).unwrap_err();
        assert_eq!(e, CommandError::invalid(format!("{}: not a file", dir.path().display())));
        let e = open(dir.path().join("missing.tar").to_str().unwrap()).unwrap_err();
        assert_eq!(e.kind, "invalid");
        assert_eq!(open("app.tar").unwrap_err().kind, "invalid");
        let path = dir.path().join("app.tar");
        std::fs::write(&path, "tar").unwrap();
        assert!(open(path.to_str().unwrap()).is_ok());
    }
}
