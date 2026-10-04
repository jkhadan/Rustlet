//! `save` and `load`: the daemon's side of `rustlet_image::archive`.
//!
//! Both run the archive code on a blocking thread, with garbage collection
//! held off (a save streams blobs that a collection mustn't delete
//! meanwhile; a load stores blobs before the names that keep them). A save
//! streams as it writes ([`crate::pipe`]); a load reads the request body as
//! it arrives, then unpacks each image (in a worker, as a pull does) before
//! it reports the image loaded, so that `rustlet load` means runnable.

use std::io::Read;
use std::sync::Arc;

use axum::body::Body;
use rustlet_image::archive::{self, LoadProgress};
use rustlet_spec::event::EventKind;
use rustlet_spec::image::LoadEvent;
use tokio::sync::mpsc;

use crate::daemon::Daemon;
use crate::error::ApiResult;

impl Daemon {
    /// The archive of `names`, as a response body. The images are resolved
    /// first (a name that doesn't exist is an error response); a failure
    /// after that ends the body without its last chunk.
    pub fn save_images(self: &Arc<Self>, names: &[String]) -> ApiResult<Body> {
        let images = self.images.for_save(names)?;
        let (writer, stream) = crate::pipe::channel();
        let d = self.clone();
        tokio::spawn(async move {
            let _pin = d.images.pin().await;
            let content = d.images.store().content().clone();
            let saved = tokio::task::spawn_blocking(move || {
                let mut writer = writer;
                match archive::save(&content, &images, &mut writer) {
                    Ok(report) => {
                        let _ = writer.finish();
                        Ok(report)
                    }
                    Err(e) => {
                        writer.abort(std::io::Error::other(e.to_string()));
                        Err(e)
                    }
                }
            })
            .await;
            match saved {
                Ok(Ok(r)) => tracing::info!(images = r.images, blobs = r.blobs, bytes = r.bytes, "saved"),
                Ok(Err(e)) => tracing::info!("save: {e}"),
                Err(e) => tracing::warn!("save: {e}"),
            }
        });
        Ok(Body::from_stream(stream))
    }

    /// Loads the archive `input` reads, reporting to `events`; the stream
    /// ends with an `error` line if it fails.
    pub async fn load_images(self: Arc<Self>, input: impl Read + Send + 'static, events: mpsc::Sender<LoadEvent>) {
        let _pin = self.images.pin().await;
        let content = self.images.store().content().clone();
        let progress = events.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            let mut input = input;
            archive::load(&content, &mut input, &mut |p| match p {
                LoadProgress::Blob { digest, size, existed } => {
                    let _ = progress.blocking_send(LoadEvent::Blob { digest: digest.to_string(), size, existed });
                }
            })
        })
        .await;
        let loaded = match loaded {
            Ok(Ok(loaded)) => loaded,
            Ok(Err(e)) => {
                let _ = events.send(LoadEvent::Error { message: e.to_string() }).await;
                return;
            }
            Err(e) => {
                let _ = events.send(LoadEvent::Error { message: format!("the load failed: {e}") }).await;
                return;
            }
        };
        for l in loaded {
            let id = l.image.manifest_digest.to_string();
            if let Err(e) = self.images.ensure_unpacked(&l.image).await {
                let _ = events.send(LoadEvent::Error { message: format!("unpack {id}: {}", e.message) }).await;
                return;
            }
            if l.names.is_empty() {
                self.events.emit(EventKind::Image, "load", &id, [("id".to_owned(), id.clone())].into());
                let _ = events.send(LoadEvent::Loaded { id, name: None }).await;
                continue;
            }
            for name in l.names {
                self.events.emit(EventKind::Image, "tag", &name, [("id".to_owned(), id.clone())].into());
                let _ = events.send(LoadEvent::Loaded { id: id.clone(), name: Some(name) }).await;
            }
        }
    }

    /// `builder prune`: forgets the build cache, then collects what only it
    /// kept. Returns the cache entries' images (and what the collection
    /// deleted).
    pub async fn prune_build_cache(self: &Arc<Self>) -> ApiResult<rustlet_spec::network::PruneResponse> {
        let content = self.images.store().content();
        let entries = content.remove_cache_entries()?;
        let mut deleted: Vec<String> = entries.iter().map(ToString::to_string).collect();
        deleted.dedup();
        deleted.extend(self.images.collect_garbage(|| self.image_users().into_keys().collect()).await?);
        let count = deleted.len().to_string();
        self.events.emit(EventKind::Image, "prune", "build cache", [("deleted".to_owned(), count)].into());
        Ok(rustlet_spec::network::PruneResponse { deleted, space_reclaimed: 0 })
    }
}
