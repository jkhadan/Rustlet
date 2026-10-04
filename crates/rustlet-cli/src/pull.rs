//! Pull progress, the way `docker pull` shows it.
//!
//! ```text
//! latest: Pulling from library/alpine
//! 9824c27679d3: Downloading 1.2MB/3.62MB      ← redrawn in place on a terminal
//! Digest: sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d
//! Status: Downloaded newer image for alpine:latest
//! docker.io/library/alpine:latest
//! ```
//!
//! One line per layer, named by the first 12 hex digits of the layer's
//! blob digest. The daemon's events come in two phases that name layers
//! differently: downloads by blob digest, unpacks by chain ID. An
//! `unpacking` event says which blob it unpacks, so from then on the chain
//! ID finds its line; a `layer_exists` (the snapshot was already there)
//! says only the chain ID, and since its blob was either already stored
//! ("Already exists") or just downloaded, its line is left as it is.
//!
//! On a terminal the lines are redrawn in place with cursor movements, and
//! downloads show their byte counts. Anywhere else each layer prints a
//! line per state change (progress counts would be noise in a log), as
//! Docker does. The config blob is part of the pull but has no line.
//!
//! A pull that is only a step of something else (a build's base image, a
//! compose service's image) is condensed to one line ([`PullLine`]): the
//! layers summed while it goes, the `Status:` line once it is done.

use std::collections::HashMap;
use std::io::{self, Write};

use anyhow::bail;
use futures::StreamExt;
use rustlet_client::Client;
use rustlet_spec::image::{BlobKind, PullEvent, PullPolicy};

use crate::format::{bytes_si, familiar_repo, short_digest};

/// Draws the layer lines of one pull.
#[derive(Debug)]
pub struct Progress {
    /// Redraw in place.
    tty: bool,
    /// Blob digest and status, in the order the layers first appeared.
    layers: Vec<(String, String)>,
    /// Chain ID → blob digest, from `unpacking` events.
    chains: HashMap<String, String>,
    summary: Pulled,
}

/// What a finished pull did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pulled {
    /// The daemon's name for it (`docker.io/library/alpine:latest`).
    pub reference: String,
    /// The registry's digest for the reference, if it was asked.
    pub repo_digest: Option<String>,
    /// The manifest stored.
    pub manifest: String,
    /// Anything was downloaded: "Downloaded newer image" rather than
    /// "Image is up to date".
    pub downloaded: bool,
}

impl Progress {
    pub fn new(tty: bool) -> Progress {
        Progress { tty, layers: Vec::new(), chains: HashMap::new(), summary: Pulled::default() }
    }

    /// Shows `event`; returns what was pulled once it is `ready`.
    pub fn show(&mut self, out: &mut dyn Write, event: &PullEvent) -> io::Result<Option<Pulled>> {
        match event {
            PullEvent::Resolving { reference } => {
                let r = Reference::parse(reference);
                writeln!(out, "{}: Pulling from {}", r.tag_or_digest(), r.path)?;
            }
            PullEvent::Resolved { repo_digest, .. } => self.summary.repo_digest = Some(repo_digest.clone()),
            PullEvent::Exists { kind: BlobKind::Layer, digest, .. } => self.set(out, digest, "Already exists")?,
            PullEvent::Downloading { kind, digest, current, total } => {
                self.summary.downloaded = true;
                if *kind == BlobKind::Layer {
                    let status = if !self.tty || *current == 0 {
                        "Pulling fs layer".to_owned()
                    } else if *total > 0 {
                        format!("Downloading {}/{}", bytes_si(*current), bytes_si(*total))
                    } else {
                        format!("Downloading {}", bytes_si(*current))
                    };
                    self.set(out, digest, &status)?;
                }
            }
            PullEvent::Downloaded { kind, digest, .. } => {
                self.summary.downloaded = true;
                if *kind == BlobKind::Layer {
                    self.set(out, digest, "Download complete")?;
                }
            }
            PullEvent::Unpacking { chain_id, blob, .. } => {
                self.chains.insert(chain_id.clone(), blob.clone());
                // Docker leaves extraction progress out of plain output too.
                if self.tty {
                    self.set(out, blob, "Extracting")?;
                }
            }
            PullEvent::Unpacked { chain_id, .. } => {
                if let Some(blob) = self.chains.get(chain_id).cloned() {
                    self.set(out, &blob, "Pull complete")?;
                }
            }
            PullEvent::Ready { reference, manifest } => {
                self.summary.reference = reference.clone();
                self.summary.manifest = manifest.clone();
                return Ok(Some(self.summary.clone()));
            }
            PullEvent::Exists { kind: BlobKind::Config, .. }
            | PullEvent::Done { .. }
            | PullEvent::LayerExists { .. }
            | PullEvent::Error { .. } => {}
        }
        Ok(None)
    }

    /// Sets the status of `digest`'s line, adding the line if it is new.
    fn set(&mut self, out: &mut dyn Write, digest: &str, status: &str) -> io::Result<()> {
        let short = short_digest(digest);
        match self.layers.iter().position(|(d, _)| d == digest) {
            Some(i) if self.layers[i].1 == status => return Ok(()),
            Some(i) => {
                self.layers[i].1 = status.to_owned();
                if self.tty {
                    // Up to the line, rewrite it, back down below the block.
                    let up = self.layers.len() - i;
                    write!(out, "\x1b[{up}A\r\x1b[2K{short}: {status}\x1b[{up}B\r")?;
                } else {
                    writeln!(out, "{short}: {status}")?;
                }
            }
            None => {
                self.layers.push((digest.to_owned(), status.to_owned()));
                writeln!(out, "{short}: {status}")?;
            }
        }
        out.flush()
    }
}

/// Pulls `reference`, drawing progress on `out` unless `quiet`, and
/// returns what was pulled.
pub async fn pull(
    client: &Client,
    out: &mut dyn Write,
    tty: bool,
    reference: &str,
    policy: PullPolicy,
    quiet: bool,
) -> anyhow::Result<Pulled> {
    let mut events = client.pull(reference, policy).await?;
    let mut progress = Progress::new(tty);
    while let Some(event) = events.next().await {
        let event = event?;
        if quiet {
            if let PullEvent::Ready { reference, manifest } = event {
                return Ok(Pulled { reference, manifest, ..Pulled::default() });
            }
        } else if let Some(pulled) = progress.show(out, &event)? {
            return Ok(pulled);
        }
    }
    bail!("the pull of {reference} ended before the image was ready")
}

/// The closing lines: `Digest:` and `Status:`. `name` is what the user
/// asked for, as Docker words it (`alpine:latest`).
pub fn summary(out: &mut dyn Write, pulled: &Pulled, name: &str) -> io::Result<()> {
    writeln!(out, "Digest: {}", pulled.repo_digest.as_deref().unwrap_or(&pulled.manifest))?;
    writeln!(out, "{}", status(pulled, name))
}

/// The `Status:` line of a pull.
pub fn status(pulled: &Pulled, name: &str) -> String {
    if pulled.downloaded {
        format!("Status: Downloaded newer image for {name}")
    } else {
        format!("Status: Image is up to date for {name}")
    }
}

/// A pull shown as one line, for the pulls a build or `compose up` does
/// on the way: `python:3-slim: Downloading 12.3MB/41.2MB` while it goes,
/// redrawn by whoever shows it, and its [`status`] line once it is done.
#[derive(Debug)]
pub struct PullLine {
    /// The image as Docker words it: `python:3-slim`.
    pub name: String,
    /// Keeps the account of what the pull did.
    progress: Progress,
    /// Each layer blob: bytes there so far, of how many.
    layers: Vec<(String, u64, u64)>,
    unpacking: bool,
}

impl PullLine {
    /// A pull of `reference`.
    pub fn new(reference: &str) -> PullLine {
        PullLine {
            name: Reference::parse(reference).familiar(),
            progress: Progress::new(false),
            layers: Vec::new(),
            unpacking: false,
        }
    }

    /// Takes `event` into account; returns what was pulled once it is
    /// `ready`.
    pub fn update(&mut self, event: &PullEvent) -> Option<Pulled> {
        match event {
            PullEvent::Downloading { kind: BlobKind::Layer, digest, current, total } => {
                self.layer(digest, *current, *total);
            }
            PullEvent::Downloaded { kind: BlobKind::Layer, digest, size }
            | PullEvent::Exists { kind: BlobKind::Layer, digest, size } => self.layer(digest, *size, *size),
            PullEvent::Unpacking { .. } => self.unpacking = true,
            _ => {}
        }
        // Nothing is written to a sink; only the account is wanted.
        self.progress.show(&mut io::sink(), event).ok().flatten()
    }

    /// The `Status:` line for a pull that is done, if it asked a registry
    /// anything: an image that was already there (and pulled only if
    /// missing) gets none, as Docker shows nothing for it.
    pub fn status(&self, pulled: &Pulled) -> Option<String> {
        (pulled.downloaded || pulled.repo_digest.is_some()).then(|| status(pulled, &self.name))
    }

    /// What the line says now.
    pub fn text(&self) -> String {
        let (current, total) = self.layers.iter().fold((0, 0), |(c, t), (_, current, total)| (c + current, t + total));
        if self.unpacking {
            format!("{}: Extracting", self.name)
        } else if total > 0 {
            format!("{}: Downloading {}/{}", self.name, bytes_si(current), bytes_si(total))
        } else {
            format!("{}: Pulling", self.name)
        }
    }

    fn layer(&mut self, digest: &str, current: u64, total: u64) {
        match self.layers.iter_mut().find(|(d, _, _)| d == digest) {
            Some(layer) => (layer.1, layer.2) = (current, total.max(current)),
            None => self.layers.push((digest.to_owned(), current, total.max(current))),
        }
    }
}

/// An image reference split the way Docker reads one: a registry host only
/// if the first component looks like one (has a `.` or `:`, or is
/// `localhost`), else Docker Hub, where a one-component path is an
/// official image under `library/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub domain: String,
    pub path: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    pub fn parse(s: &str) -> Reference {
        let (domain, rest) = match s.split_once('/') {
            Some((d, rest)) if d.contains('.') || d.contains(':') || d == "localhost" => (d, rest),
            _ => ("docker.io", s),
        };
        let (rest, digest) = match rest.split_once('@') {
            Some((name, digest)) => (name, Some(digest.to_owned())),
            None => (rest, None),
        };
        let (path, tag) = match rest.rsplit_once(':') {
            Some((path, tag)) if !tag.contains('/') => (path, Some(tag.to_owned())),
            _ => (rest, None),
        };
        let path =
            if domain == "docker.io" && !path.contains('/') { format!("library/{path}") } else { path.to_owned() };
        Reference { domain: domain.to_owned(), path, tag, digest }
    }

    /// What `docker pull` prints before "Pulling from".
    fn tag_or_digest(&self) -> &str {
        self.tag.as_deref().or(self.digest.as_deref()).unwrap_or("latest")
    }

    /// The name as Docker shows it to people: `alpine:latest`,
    /// `user/app:1`, `ghcr.io/o/n@sha256:…`, with `latest` filled in.
    pub fn familiar(&self) -> String {
        let repo = format!("{}/{}", self.domain, self.path);
        let repo = familiar_repo(&repo);
        match (&self.tag, &self.digest) {
            (Some(tag), _) => format!("{repo}:{tag}"),
            (None, Some(digest)) => format!("{repo}@{digest}"),
            (None, None) => format!("{repo}:latest"),
        }
    }

    /// Neither a tag nor a digest: `latest` is implied.
    pub fn is_untagged(&self) -> bool {
        self.tag.is_none() && self.digest.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "sha256:aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111";
    const B: &str = "sha256:bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222";

    fn events() -> Vec<PullEvent> {
        let layer = BlobKind::Layer;
        vec![
            PullEvent::Resolving { reference: "docker.io/library/alpine:latest".into() },
            PullEvent::Resolved {
                reference: "docker.io/library/alpine:latest".into(),
                manifest: "sha256:m".into(),
                repo_digest: "sha256:r".into(),
                platform: "linux/amd64".into(),
                layers: 2,
                size: 3_000_000,
            },
            PullEvent::Downloading { kind: BlobKind::Config, digest: "sha256:c".into(), current: 0, total: 1500 },
            PullEvent::Downloaded { kind: BlobKind::Config, digest: "sha256:c".into(), size: 1500 },
            PullEvent::Exists { kind: layer, digest: A.into(), size: 10 },
            PullEvent::Downloading { kind: layer, digest: B.into(), current: 0, total: 3_400_000 },
            PullEvent::Downloading { kind: layer, digest: B.into(), current: 1_200_000, total: 3_400_000 },
            PullEvent::Downloaded { kind: layer, digest: B.into(), size: 3_400_000 },
            PullEvent::Done { reference: "docker.io/library/alpine:latest".into(), manifest: "sha256:m".into() },
            PullEvent::LayerExists { chain_id: "sha256:chain-a".into() },
            PullEvent::Unpacking { chain_id: "sha256:chain-b".into(), blob: B.into(), size: 3_400_000 },
            PullEvent::Unpacked {
                chain_id: "sha256:chain-b".into(),
                entries: 5,
                bytes: 9,
                whiteouts: 0,
                opaque_dirs: 0,
                skipped_devices: 0,
            },
            PullEvent::Ready { reference: "docker.io/library/alpine:latest".into(), manifest: "sha256:m".into() },
        ]
    }

    fn render(tty: bool) -> (String, Pulled) {
        let mut out = Vec::new();
        let mut progress = Progress::new(tty);
        let mut pulled = None;
        for e in events() {
            pulled = progress.show(&mut out, &e).unwrap().or(pulled);
        }
        (String::from_utf8(out).unwrap(), pulled.unwrap())
    }

    #[test]
    fn plain_output_prints_each_state_once() {
        let (text, pulled) = render(false);
        assert_eq!(
            text,
            "latest: Pulling from library/alpine\n\
             aaaaaaaaaaaa: Already exists\n\
             bbbbbbbbbbbb: Pulling fs layer\n\
             bbbbbbbbbbbb: Download complete\n\
             bbbbbbbbbbbb: Pull complete\n"
        );
        assert_eq!(
            pulled,
            Pulled {
                reference: "docker.io/library/alpine:latest".into(),
                repo_digest: Some("sha256:r".into()),
                manifest: "sha256:m".into(),
                downloaded: true,
            }
        );
        let mut out = Vec::new();
        summary(&mut out, &pulled, "alpine:latest").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Digest: sha256:r\nStatus: Downloaded newer image for alpine:latest\n"
        );
    }

    #[test]
    fn terminals_redraw_lines_in_place() {
        let (text, _) = render(true);
        let up1 = |s: &str| format!("\x1b[1A\r\x1b[2Kbbbbbbbbbbbb: {s}\x1b[1B\r");
        let expected = [
            "latest: Pulling from library/alpine\n".to_owned(),
            "aaaaaaaaaaaa: Already exists\n".to_owned(),
            "bbbbbbbbbbbb: Pulling fs layer\n".to_owned(),
            up1("Downloading 1.2MB/3.4MB"),
            up1("Download complete"),
            up1("Extracting"),
            up1("Pull complete"),
        ]
        .concat();
        assert_eq!(text, expected);
    }

    #[test]
    fn an_image_that_was_there_is_up_to_date() {
        let mut progress = Progress::new(false);
        let mut out = Vec::new();
        let ready =
            PullEvent::Ready { reference: "docker.io/library/alpine:latest".into(), manifest: "sha256:m".into() };
        let pulled = progress.show(&mut out, &ready).unwrap().unwrap();
        assert!(!pulled.downloaded);
        let mut out = Vec::new();
        summary(&mut out, &pulled, "alpine:latest").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Digest: sha256:m\nStatus: Image is up to date for alpine:latest\n"
        );
    }

    #[test]
    fn a_pull_shown_in_one_line_sums_its_layers() {
        let mut line = PullLine::new("docker.io/library/alpine:latest");
        assert_eq!(line.text(), "alpine:latest: Pulling");
        let mut texts = Vec::new();
        let mut pulled = None;
        for e in events() {
            match line.update(&e) {
                Some(p) => pulled = Some(p),
                None => texts.push(line.text().replace("alpine:latest: ", "")),
            }
        }
        // The config blob isn't a layer; an existing layer counts as there.
        assert_eq!(
            texts,
            [
                "Pulling",
                "Pulling",
                "Pulling",
                "Pulling",
                "Downloading 10B/10B",
                "Downloading 10B/3.4MB",
                "Downloading 1.2MB/3.4MB",
                "Downloading 3.4MB/3.4MB",
                "Downloading 3.4MB/3.4MB",
                "Downloading 3.4MB/3.4MB",
                "Extracting",
                "Extracting",
            ]
        );
        let pulled = pulled.unwrap();
        assert_eq!(line.status(&pulled).unwrap(), "Status: Downloaded newer image for alpine:latest");

        // Already there, and only pulled if missing: no registry was asked,
        // and there is nothing to say.
        let all = events();
        let (resolving, resolved, exists, ready) = (&all[0], &all[1], &all[4], &all[all.len() - 1]);
        let mut line = PullLine::new("alpine");
        assert!(line.update(resolving).is_none());
        let pulled = line.update(ready).unwrap();
        assert_eq!(line.status(&pulled), None);
        // Asked (--pull), but nothing new.
        let mut line = PullLine::new("alpine");
        let pulled = [resolving, resolved, exists, ready].into_iter().find_map(|e| line.update(e)).unwrap();
        assert_eq!(line.status(&pulled).unwrap(), "Status: Image is up to date for alpine:latest");
    }

    #[test]
    fn references() {
        let r = Reference::parse("alpine");
        assert_eq!((r.domain.as_str(), r.path.as_str(), r.is_untagged()), ("docker.io", "library/alpine", true));
        assert_eq!(r.familiar(), "alpine:latest");
        assert_eq!(Reference::parse("docker.io/library/alpine:3.20").familiar(), "alpine:3.20");
        assert_eq!(Reference::parse("user/app:1").familiar(), "user/app:1");
        let r = Reference::parse("localhost:5000/app");
        assert_eq!((r.domain.as_str(), r.path.as_str()), ("localhost:5000", "app"));
        assert_eq!(r.familiar(), "localhost:5000/app:latest");
        let r = Reference::parse("ghcr.io/o/n@sha256:abc");
        assert_eq!((r.tag_or_digest(), r.familiar().as_str()), ("sha256:abc", "ghcr.io/o/n@sha256:abc"));
    }
}
