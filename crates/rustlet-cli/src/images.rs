//! `images`, `rmi`, `pull`, `tag`, `save` and `load`.
//!
//! `save` and `load` move archives that can be gigabytes, so neither holds
//! one whole: `save` writes the daemon's answer out as it arrives, and
//! `load` sends a file (or stdin) as it is read
//! ([`RequestBody::from_reader`]). An archive is never written to a
//! terminal, nor read from one, as with Docker.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use futures::StreamExt;
use rustlet_client::{ByteStream, Error, RequestBody};
use rustlet_spec::image::{LoadEvent, PullPolicy};

use crate::Ctx;
use crate::format::{Table, ago, bytes_si, short_digest, split_image_name};
use crate::pull::{self, Reference};

/// `rustlet images`: a row per name (an image with two names has two
/// rows, one with none a `<none>` row), newest first.
pub async fn images(ctx: &mut Ctx, quiet: bool, no_trunc: bool) -> anyhow::Result<i32> {
    let mut images = ctx.client.list_images().await?;
    images.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.names.cmp(&b.names)));
    let id = |digest: &str| if no_trunc { digest.to_owned() } else { short_digest(digest).to_owned() };
    if quiet {
        // One id per image, however many names it has: `rmi $(images -q)`
        // shouldn't try to remove an image twice.
        let mut seen = HashSet::new();
        for image in &images {
            if seen.insert(&image.id) {
                writeln!(ctx.console.stdout, "{}", id(&image.id))?;
            }
        }
        return Ok(0);
    }
    let now = Utc::now();
    let mut table = Table::new(&["REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"]);
    for image in &images {
        let created = image.created.as_deref().map_or_else(|| "N/A".to_owned(), |c| ago(c, now));
        let names: Vec<(String, String)> = if image.names.is_empty() {
            vec![("<none>".to_owned(), "<none>".to_owned())]
        } else {
            image.names.iter().map(|n| split_image_name(n)).collect()
        };
        for (repository, tag) in names {
            table.row(vec![repository, tag, id(&image.id), created.clone(), bytes_si(image.size)]);
        }
    }
    table.write(&mut *ctx.console.stdout)?;
    Ok(0)
}

/// `rustlet rmi`: removes each name, printing what went (`Untagged:` for
/// names, `Deleted:` for blobs and snapshots nothing uses any more).
pub async fn rmi(ctx: &mut Ctx, force: bool, names: &[String]) -> anyhow::Result<i32> {
    let mut failed = false;
    for name in names {
        match ctx.client.remove_image(name, force).await {
            Ok(removed) => {
                for n in &removed.untagged {
                    writeln!(ctx.console.stdout, "Untagged: {n}")?;
                }
                for d in &removed.deleted {
                    writeln!(ctx.console.stdout, "Deleted: {d}")?;
                }
            }
            Err(e @ Error::Connect { .. }) => return Err(e.into()),
            Err(e) => {
                writeln!(ctx.console.stderr, "rustlet: error: {e}")?;
                failed = true;
            }
        }
    }
    Ok(i32::from(failed))
}

/// `rustlet pull`: always asks the registry (a `docker pull` is how one
/// updates a tag), progress on stdout, the full reference last.
pub async fn pull(ctx: &mut Ctx, quiet: bool, image: &str) -> anyhow::Result<i32> {
    let reference = Reference::parse(image);
    let console = &mut ctx.console;
    if !quiet && reference.is_untagged() {
        writeln!(console.stdout, "Using default tag: latest")?;
    }
    let pulled =
        pull::pull(&ctx.client, &mut *console.stdout, console.stdout_tty, image, PullPolicy::Always, quiet).await?;
    if !quiet {
        pull::summary(&mut *console.stdout, &pulled, &reference.familiar())?;
    }
    writeln!(console.stdout, "{}", pulled.reference)?;
    Ok(0)
}

/// `rustlet tag`: `target` names `source`'s image too (and no longer
/// whatever it named before). Nothing is printed, as with Docker.
pub async fn tag(ctx: &mut Ctx, source: &str, target: &str) -> anyhow::Result<i32> {
    ctx.client.tag_image(source, target).await?;
    Ok(0)
}

/// `rustlet save`: the images as one tar archive, into `output` or onto
/// stdout, which mustn't be a terminal.
pub async fn save(ctx: &mut Ctx, output: Option<&Path>, images: &[String]) -> anyhow::Result<i32> {
    let Some(path) = output else {
        if ctx.console.stdout_tty {
            bail!("refusing to write an archive to a terminal; use -o or redirect");
        }
        let mut archive = ctx.client.save_images(images).await?;
        while let Some(chunk) = archive.next().await {
            ctx.console.stdout.write_all(&chunk?)?;
        }
        ctx.console.stdout.flush()?;
        return Ok(0);
    };
    // The daemon is asked first: a save it refuses (no such image) leaves
    // no file behind, nor touches one that is there.
    let archive = ctx.client.save_images(images).await?;
    match fs::metadata(path) {
        // `-o /dev/stdout`, a FIFO: written as they are. Replacing one with
        // a file would be wrong, and for root, possible.
        Ok(m) if !m.is_file() => {
            let file = OpenOptions::new().write(true).open(path).with_context(|| format!("-o {}", path.display()))?;
            write_archive(archive, file).await.with_context(|| format!("-o {}", path.display()))
        }
        _ => save_to_file(archive, path).await,
    }?;
    Ok(0)
}

/// Writes the archive into a new file beside `path`, renamed to `path`
/// once it is whole (as Docker's CLI does): a save that fails midway
/// removes what it wrote, and leaves a file that was there as it was.
async fn save_to_file(archive: ByteStream, path: &Path) -> anyhow::Result<()> {
    let partial = partial_path(path)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .with_context(|| format!("-o {}: creating {}", path.display(), partial.display()))?;
    let saved = write_archive(archive, file)
        .await
        .and_then(|()| fs::rename(&partial, path).with_context(|| format!("renaming {}", partial.display())));
    if let Err(e) = saved {
        let _ = fs::remove_file(&partial);
        return Err(e.context(format!("-o {}", path.display())));
    }
    Ok(())
}

/// `dir/.name.rustlet-partial-<pid>`, for `dir/name`.
fn partial_path(path: &Path) -> anyhow::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| anyhow!("-o {}: not a file name", path.display()))?;
    Ok(path.with_file_name(format!(".{}.rustlet-partial-{}", name.to_string_lossy(), std::process::id())))
}

/// The archive, chunk by chunk as it arrives, into `file`.
async fn write_archive(mut archive: ByteStream, mut file: File) -> anyhow::Result<()> {
    while let Some(chunk) = archive.next().await {
        // A blocking write: the local disk is the bottleneck we want.
        file.write_all(&chunk?)?;
    }
    file.flush()?;
    Ok(())
}

/// `rustlet load`: the images of an archive (`input`, else stdin, which
/// mustn't be a terminal), and what they are called now. As with Docker,
/// each blob's line is shown only on a terminal, and not with `-q`.
pub async fn load(ctx: &mut Ctx, input: Option<&Path>, quiet: bool) -> anyhow::Result<i32> {
    let archive = match input {
        Some(path) => {
            let file = File::open(path).with_context(|| format!("-i {}", path.display()))?;
            RequestBody::from_reader(file)
        }
        None => {
            if ctx.console.stdin_tty {
                bail!("requested load from stdin, but stdin is a terminal; use -i or redirect an archive in");
            }
            let stdin = ctx.console.stdin.take().ok_or_else(|| anyhow!("stdin is already in use"))?;
            RequestBody::from_reader(stdin)
        }
    };
    let blobs = !quiet && ctx.console.stdout_tty;
    let mut events = ctx.client.load_images(archive).await?;
    let out = &mut ctx.console.stdout;
    while let Some(event) = events.next().await {
        match event? {
            LoadEvent::Blob { digest, existed: true, .. } if blobs => {
                writeln!(out, "{}: Already exists", short_digest(&digest))?;
            }
            LoadEvent::Blob { digest, size, .. } if blobs => {
                writeln!(out, "{}: Loaded {}", short_digest(&digest), bytes_si(size))?;
            }
            LoadEvent::Blob { .. } => {}
            LoadEvent::Loaded { name: Some(name), .. } => {
                writeln!(out, "Loaded image: {}", Reference::parse(&name).familiar())?;
            }
            LoadEvent::Loaded { id, name: None } => writeln!(out, "Loaded image ID: {id}")?,
            // The client turns it into the stream's error.
            LoadEvent::Error { message } => bail!(message),
        }
        out.flush()?;
    }
    Ok(0)
}
