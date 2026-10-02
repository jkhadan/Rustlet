//! `images`, `rmi` and `pull`.

use std::collections::HashSet;
use std::io::Write;

use chrono::Utc;
use rustlet_client::Error;
use rustlet_spec::image::PullPolicy;

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
