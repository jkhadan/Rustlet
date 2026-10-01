//! `cargo xtask images [inspect IMAGE | ls PATH]`: look inside the image
//! store. It is root's and `0700` (images can contain anything), so like
//! `image-run` this builds as you and runs the reading part through sudo.
//!
//! ```text
//! cargo xtask images                         names, digests, sizes (≈ docker images --digests)
//! cargo xtask images inspect nginx           manifest, config, layers with diff and chain IDs
//! cargo xtask images inspect nginx --json    the manifest and config documents, pretty-printed
//! cargo xtask images ls snapshots/<chain ID>/fs/etc
//! cargo xtask images ls -R containers/<id>/upper    (after image-run --keep)
//! cargo xtask images cat content/index.json          (any regular file in the store, as it is)
//! cargo xtask images prune-containers                (delete what --keep left)
//! ```
//!
//! `ls` shows what `ls -l` would, plus overlay's view of each entry: a
//! character device 0:0 is a *whiteout*, a directory with
//! `trusted.overlay.opaque=y` is *opaque*. Paths are resolved inside the
//! store root (`RESOLVE_IN_ROOT`), so `ls` can't be pointed elsewhere.

use std::ffi::OsString;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use clap::{Args, Subcommand};
use rustlet_image::config::MAX_CONFIG_BYTES;
use rustlet_image::manifest::MAX_MANIFEST_BYTES;
use rustlet_image::{Image, Store};
use rustlet_sys::fs::{ResolveFlags, openat2};

use crate::imagerun::size;

#[derive(Args, Debug, Clone)]
pub(crate) struct ImagesArgs {
    #[command(subcommand)]
    command: Option<ImagesCommand>,
    /// The image store.
    #[arg(long, global = true, default_value = Store::DEFAULT_ROOT)]
    store: PathBuf,
}

#[derive(Subcommand, Debug, Clone)]
enum ImagesCommand {
    /// List the store's image names (the default).
    List,
    /// An image's manifest, config and layers.
    Inspect {
        /// Name (alpine, nginx:1.27, …) or manifest digest (sha256:…).
        image: String,
        /// Print the manifest and config JSON, pretty-printed (`images cat` gives the stored bytes).
        #[arg(long)]
        json: bool,
    },
    /// Copy a file inside the store to stdout as it is (a blob, index.json, a config.json).
    Cat {
        /// A path relative to the store root, e.g. content/index.json.
        path: PathBuf,
    },
    /// Delete the container directories `image-run --keep` left behind (not ones in use).
    PruneContainers,
    /// List a directory inside the store, with overlay's whiteouts and opaque directories marked.
    Ls {
        /// A path relative to the store root, e.g. snapshots/<chain ID>/fs/etc.
        path: PathBuf,
        /// Recurse into subdirectories.
        #[arg(short = 'R', long)]
        recursive: bool,
    },
}

/// The user's half: hand the same arguments to root.
pub(crate) fn run(_args: &ImagesArgs) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("locate the xtask binary")?;
    let forwarded: Vec<OsString> = std::env::args_os().skip(2).collect();
    let status = Command::new("sudo")
        .arg(&exe)
        .arg("images-root")
        .args(&forwarded)
        .status()
        .context("run sudo xtask images-root")?;
    std::process::exit(status.code().unwrap_or(1));
}

/// The root half (`xtask images-root`).
pub(crate) fn run_as_root(args: &ImagesArgs) -> anyhow::Result<()> {
    let store = Store::open(&args.store).with_context(|| format!("open the image store {}", args.store.display()))?;
    match args.command.clone().unwrap_or(ImagesCommand::List) {
        ImagesCommand::List => list(&store),
        ImagesCommand::Inspect { image, json } => inspect(&store, &image, json),
        ImagesCommand::Ls { path, recursive } => ls(&store, &path, recursive),
        ImagesCommand::Cat { path } => cat(&store, &path),
        ImagesCommand::PruneContainers => prune_containers(&store),
    }
}

/// Copies a regular file below the store root to stdout, byte for byte
/// (resolved like `ls`, inside the root; never a device or FIFO).
fn cat(store: &Store, path: &Path) -> anyhow::Result<()> {
    let root = nix::fcntl::open(
        store.root(),
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .with_context(|| format!("open {}", store.root().display()))?;
    let rel = expand_prefix(store, path.strip_prefix("/").unwrap_or(path))?;
    let handle = openat2(
        Some(root.as_fd()),
        &rel,
        nix::fcntl::OFlag::O_PATH,
        nix::sys::stat::Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )
    .with_context(|| format!("open {} inside the store", rel.display()))?;
    if rustlet_sys::fs::fstatx(handle.as_fd())?.file_type() != libc::S_IFREG {
        anyhow::bail!("{} is not a regular file", rel.display());
    }
    let file = rustlet_sys::fs::reopen(handle.as_fd(), nix::fcntl::OFlag::O_RDONLY)?;
    match std::io::copy(&mut std::fs::File::from(file), &mut std::io::stdout().lock()) {
        // `images cat … | head`: the reader has all it wanted.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        r => r.map(drop).map_err(Into::into),
    }
}

/// Removes every `containers/<id>`. One whose rootfs is still mounted (a
/// running `image-run`) is skipped: `safe_remove_tree` refuses to delete
/// anything with a mount below it.
fn prune_containers(store: &Store) -> anyhow::Result<()> {
    let dir = store.containers_dir().canonicalize()?;
    let mut removed = 0;
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        match rustlet_sys::tree::safe_remove_tree(&path) {
            Ok(()) => {
                println!("removed  {}", path.display());
                removed += 1;
            }
            Err(e) => println!("skipped  {} ({e})", path.display()),
        }
    }
    println!("{removed} container director{} removed", if removed == 1 { "y" } else { "ies" });
    Ok(())
}

fn list(store: &Store) -> anyhow::Result<()> {
    let refs = store.content().refs()?;
    if refs.is_empty() {
        println!("(no images in {}; try `cargo xtask image-run alpine`)", store.root().display());
        return Ok(());
    }
    println!("{:<44} {:<14} {:<14} {:>6} {:>10}", "NAME", "MANIFEST", "REPO DIGEST", "LAYERS", "SIZE");
    for r in refs {
        let manifest = r.manifest_digest()?;
        let repo = r.repo_digest.as_ref().map_or("-".to_owned(), |d| d.short().to_owned());
        match Image::from_manifest(store.content(), &manifest, Some(r.name.clone()), r.repo_digest.clone()) {
            Ok(image) => println!(
                "{:<44} {:<14} {:<14} {:>6} {:>10}",
                r.name,
                manifest.short(),
                repo,
                image.layers.len(),
                size(image.compressed_size())
            ),
            Err(e) => println!("{:<44} {:<14} {:<14} (unreadable: {e})", r.name, manifest.short(), repo),
        }
    }
    Ok(())
}

fn inspect(store: &Store, name: &str, json: bool) -> anyhow::Result<()> {
    let image = Image::load(store.content(), name)?;
    if json {
        let manifest = store.content().read_blob(&image.manifest_digest, MAX_MANIFEST_BYTES)?;
        let config = store.content().read_blob(&image.config_digest, MAX_CONFIG_BYTES)?;
        println!("# manifest {}", image.manifest_digest);
        println!("{}", pretty(&manifest)?);
        println!("# config {}", image.config_digest);
        println!("{}", pretty(&config)?);
        return Ok(());
    }
    println!("name         {}", image.display_name());
    println!(
        "manifest     {}  ({})",
        image.manifest_digest,
        store.content().blob_path(&image.manifest_digest).display()
    );
    if let Some(repo) = &image.repo_digest
        && repo != &image.manifest_digest
    {
        println!("repo digest  {repo}  (the index the manifest was chosen from)");
    }
    println!("config       {}", image.config_digest);
    println!("platform     {}", image.config.platform());
    if let Some(created) = image.config.oci.created() {
        println!("created      {created}");
    }
    if let Some(c) = image.config.config() {
        let show = |v: &Option<Vec<String>>| v.as_ref().map_or("-".to_owned(), |v| format!("{v:?}"));
        println!("entrypoint   {}", show(c.entrypoint()));
        println!("cmd          {}", show(c.cmd()));
        println!("user         {}", c.user().as_deref().unwrap_or("-"));
        println!("workdir      {}", c.working_dir().as_deref().unwrap_or("-"));
        for e in c.env().iter().flatten() {
            println!("env          {e}");
        }
        if let Some(sig) = c.stop_signal() {
            println!("stop signal  {sig}");
        }
    }
    println!("\nlayers (bottom first)");
    println!("  {:<3} {:<14} {:>10} {:<14} {:<14} SNAPSHOT", "#", "BLOB", "SIZE", "DIFF ID", "CHAIN ID");
    for (i, l) in image.layers.iter().enumerate() {
        let snap = match store.snapshots().get(&l.chain_id)? {
            Some(s) => format!("{} entries, {}", s.info.entries, size(s.info.size)),
            None => "not unpacked".to_owned(),
        };
        println!(
            "  {:<3} {:<14} {:>10} {:<14} {:<14} {snap}",
            i,
            l.blob.short(),
            size(l.size),
            l.diff_id.short(),
            l.chain_id.short()
        );
    }
    Ok(())
}

fn pretty(bytes: &[u8]) -> anyhow::Result<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    Ok(serde_json::to_string_pretty(&v)?)
}

fn ls(store: &Store, path: &Path, recursive: bool) -> anyhow::Result<()> {
    let root = nix::fcntl::open(
        store.root(),
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .with_context(|| format!("open {}", store.root().display()))?;
    let rel = expand_prefix(store, path.strip_prefix("/").unwrap_or(path))?;
    let rel = if rel.as_os_str().is_empty() { Path::new(".") } else { rel.as_path() };
    let fd = openat2(
        Some(root.as_fd()),
        rel,
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )
    .with_context(|| format!("open {} inside the store", rel.display()))?;
    // Through the fd's magic link: the directory just resolved, and only it.
    let dir = PathBuf::from(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&fd)));
    list_dir(&dir, rel, recursive, 0)
}

/// `snapshots/49049a42a1d2/fs` → the snapshot whose chain ID starts with
/// that (the short IDs `inspect` prints); likewise `containers/<prefix>`.
fn expand_prefix(store: &Store, rel: &Path) -> anyhow::Result<PathBuf> {
    let mut parts = rel.components();
    let (Some(top), Some(id)) = (parts.next(), parts.next()) else { return Ok(rel.to_owned()) };
    let (top, id) = (top.as_os_str(), id.as_os_str().to_string_lossy().into_owned());
    if !(top == "snapshots" || top == "containers") || store.root().join(top).join(&id).exists() {
        return Ok(rel.to_owned());
    }
    let matches: Vec<String> = std::fs::read_dir(store.root().join(top))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with(&id))
        .collect();
    match matches.as_slice() {
        [one] => Ok(Path::new(top).join(one).join(parts.as_path())),
        [] => anyhow::bail!("nothing in {} starts with {id}", top.to_string_lossy()),
        _ => anyhow::bail!("{id} is ambiguous in {}: {}", top.to_string_lossy(), matches.join(", ")),
    }
}

fn list_dir(dir: &Path, shown: &Path, recursive: bool, depth: usize) -> anyhow::Result<()> {
    if depth > 0 {
        println!();
    }
    println!("{}:", shown.display());
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("list {}", shown.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("list {}", shown.display()))?;
    entries.sort_by_key(|e| e.file_name());
    let mut subdirs = Vec::new();
    for e in &entries {
        let path = e.path();
        let m = std::fs::symlink_metadata(&path)?;
        let ft = m.file_type();
        let (kind, extra) = if ft.is_dir() {
            let opaque = rustlet_sys::xattr::lget(&path, "trusted.overlay.opaque").is_ok_and(|v| v == b"y");
            subdirs.push(e.file_name());
            ('d', if opaque { "  [opaque: hides the lower layers' entries]".to_owned() } else { String::new() })
        } else if ft.is_symlink() {
            ('l', format!(" -> {}", std::fs::read_link(&path)?.display()))
        } else if std::os::unix::fs::FileTypeExt::is_char_device(&ft) {
            let (major, minor) = (libc_major(m.rdev()), libc_minor(m.rdev()));
            let label = match (major, minor) {
                // Overlay keeps one whiteout in work/work and links new
                // ones to it; that one deletes nothing itself.
                (0, 0) if shown.ends_with("work/work") => "  [overlay's shared whiteout]",
                (0, 0) => "  [whiteout: deletes it from the lower layers]",
                _ => "",
            };
            ('c', label.to_owned())
        } else if std::os::unix::fs::FileTypeExt::is_block_device(&ft) {
            ('b', String::new())
        } else if std::os::unix::fs::FileTypeExt::is_fifo(&ft) {
            ('p', String::new())
        } else if std::os::unix::fs::FileTypeExt::is_socket(&ft) {
            ('s', String::new())
        } else {
            ('-', String::new())
        };
        let size = if matches!(kind, 'c' | 'b') {
            format!("{}, {}", libc_major(m.rdev()), libc_minor(m.rdev()))
        } else {
            m.len().to_string()
        };
        println!(
            "{kind}{:04o} {:>7}:{:<7} {:>10}  {}{extra}",
            m.mode() & 0o7777,
            m.uid(),
            m.gid(),
            size,
            String::from_utf8_lossy(e.file_name().as_bytes())
        );
    }
    if recursive {
        for name in subdirs {
            list_dir(&dir.join(&name), &shown.join(&name), recursive, depth + 1)?;
        }
    }
    Ok(())
}

fn libc_major(dev: u64) -> u64 {
    ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0xfff)
}

fn libc_minor(dev: u64) -> u64 {
    ((dev >> 12) & 0xffff_ff00) | (dev & 0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers_split_like_glibc() {
        let dev = nix::sys::stat::makedev(136, 300);
        assert_eq!((libc_major(dev), libc_minor(dev)), (136, 300));
        assert_eq!((libc_major(0), libc_minor(0)), (0, 0));
    }
}
