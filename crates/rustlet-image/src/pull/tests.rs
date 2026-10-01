//! Pulls against a fake registry. [`Fake`] serves just enough of the
//! distribution API (`/v2/`, manifests, blobs, a token endpoint) on
//! 127.0.0.1, from images built here in code, and counts every request so a
//! test can say what was, and wasn't, fetched. No network, no root.
//!
//! (reqwest honours `HTTP_PROXY`: with a proxy set, `NO_PROXY` must cover
//! 127.0.0.1.)

use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use bytes::Bytes;
use serde_json::json;

use super::*;

// ---- test content -------------------------------------------------------

/// A layer: a gzip'd tar, with both of its digests.
#[derive(Clone)]
struct TestLayer {
    blob: Vec<u8>,
    digest: Digest,
    diff_id: Digest,
}

impl TestLayer {
    fn size(&self) -> u64 {
        self.blob.len() as u64
    }
}

/// A layer holding `files`.
fn layer(files: &[(&str, &[u8])]) -> TestLayer {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        tar.append_data(&mut header, path, *data).unwrap();
    }
    let tar = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    let blob = gz.finish().unwrap();
    TestLayer { digest: Digest::of(&blob), diff_id: Digest::of(&tar), blob }
}

/// Bytes gzip can't shrink (xorshift), so a layer of them stays as big.
fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Dialect {
    Oci,
    Docker,
}

/// An image as a registry serves it.
struct TestImage {
    config: Vec<u8>,
    config_digest: Digest,
    manifest: Vec<u8>,
    digest: Digest,
    media_type: &'static str,
    layers: Vec<TestLayer>,
}

/// An image for linux/`arch` made of `layers`; the config's diff IDs are
/// the digests of the uncompressed tars.
fn image(dialect: Dialect, arch: &str, layers: &[&TestLayer]) -> TestImage {
    let (media_type, config_type, layer_type) = match dialect {
        Dialect::Oci => (media::OCI_MANIFEST, media::OCI_CONFIG, media::OCI_LAYER_GZIP),
        Dialect::Docker => (media::DOCKER_MANIFEST, media::DOCKER_CONFIG, media::DOCKER_LAYER_GZIP),
    };
    let diff_ids: Vec<&Digest> = layers.iter().map(|l| &l.diff_id).collect();
    let config = serde_json::to_vec(&json!({
        "architecture": arch,
        "os": "linux",
        "config": {"Cmd": ["/bin/sh"]},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }))
    .unwrap();
    let descriptors: Vec<_> =
        layers.iter().map(|l| json!({"mediaType": layer_type, "digest": l.digest, "size": l.size()})).collect();
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": media_type,
        "config": {"mediaType": config_type, "digest": Digest::of(&config), "size": config.len()},
        "layers": descriptors,
    }))
    .unwrap();
    TestImage {
        config_digest: Digest::of(&config),
        config,
        digest: Digest::of(&manifest),
        manifest,
        media_type,
        layers: layers.iter().map(|&l| l.clone()).collect(),
    }
}

/// An OCI index or Docker manifest list as a registry serves it.
struct TestIndex {
    bytes: Vec<u8>,
    digest: Digest,
    media_type: &'static str,
}

/// An index of `entries`: each image with its platform, `os/arch[/variant]`.
fn index(dialect: Dialect, entries: &[(&TestImage, &str)]) -> TestIndex {
    let manifests: Vec<_> = entries
        .iter()
        .map(|(img, platform)| {
            let parts: Vec<&str> = platform.split('/').collect();
            let mut p = json!({"os": parts[0], "architecture": parts[1]});
            if let Some(variant) = parts.get(2) {
                p["variant"] = json!(variant);
            }
            json!({"mediaType": img.media_type, "digest": img.digest, "size": img.manifest.len(), "platform": p})
        })
        .collect();
    let media_type = match dialect {
        Dialect::Oci => media::OCI_INDEX,
        Dialect::Docker => media::DOCKER_MANIFEST_LIST,
    };
    let bytes =
        serde_json::to_vec(&json!({"schemaVersion": 2, "mediaType": media_type, "manifests": manifests})).unwrap();
    TestIndex { digest: Digest::of(&bytes), bytes, media_type }
}

// ---- the fake registry --------------------------------------------------

const TOKEN: &str = "t0k";

/// `(repository, tag or digest)`.
type Key = (String, String);

/// A manifest as served: its media type and bytes.
type Served = (String, Vec<u8>);

/// A registry running in a tokio task. Tests stock it and set its knobs
/// through the fields.
#[derive(Default)]
struct Fake {
    manifests: Mutex<HashMap<Key, Served>>,
    /// The bytes served for each blob, right or wrong.
    blobs: Mutex<HashMap<Key, Vec<u8>>>,
    /// `"GET /v2/…"` → how many such requests arrived.
    seen: Mutex<HashMap<String, usize>>,
    /// The query strings the token endpoint got.
    token_queries: Mutex<Vec<String>>,
    /// Require `Authorization: Bearer t0k` under `/v2/`.
    auth: AtomicBool,
    /// Refuse to hand out tokens.
    deny_tokens: AtomicBool,
    /// Send blobs chunked, without a `Content-Length`.
    chunked: AtomicBool,
    /// Hold every blob response back this many milliseconds.
    blob_delay_ms: AtomicU64,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    /// `127.0.0.1:<port>`.
    host: OnceLock<String>,
}

impl Fake {
    async fn start() -> Arc<Fake> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake = Arc::new(Fake::default());
        fake.host.set(listener.local_addr().unwrap().to_string()).unwrap();
        let app = axum::Router::new().fallback(handle).with_state(Arc::clone(&fake));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        fake
    }

    fn host(&self) -> &str {
        self.host.get().unwrap()
    }

    /// `<host>/<path>`, parsed.
    fn reference(&self, path: &str) -> ImageRef {
        ImageRef::parse(&format!("{}/{path}", self.host())).unwrap()
    }

    fn puller(&self) -> Puller {
        self.puller_with(PullOptions::default().max_concurrent_downloads)
    }

    fn puller_with(&self, max_concurrent_downloads: usize) -> Puller {
        Puller::new(PullOptions {
            max_concurrent_downloads,
            insecure_registries: vec![self.host().to_owned()],
            ..PullOptions::default()
        })
    }

    fn manifest(&self, repo: &str, reference: &str, media_type: &str, bytes: &[u8]) {
        let key = (repo.to_owned(), reference.to_owned());
        self.manifests.lock().unwrap().insert(key, (media_type.to_owned(), bytes.to_vec()));
    }

    fn blob(&self, repo: &str, digest: &Digest, bytes: &[u8]) {
        self.blobs.lock().unwrap().insert((repo.to_owned(), digest.to_string()), bytes.to_vec());
    }

    /// Serves `img` from `repo`: the manifest by digest (and by `tag`), the
    /// config and the layers.
    fn image(&self, repo: &str, tag: Option<&str>, img: &TestImage) {
        self.manifest(repo, &img.digest.to_string(), img.media_type, &img.manifest);
        if let Some(tag) = tag {
            self.manifest(repo, tag, img.media_type, &img.manifest);
        }
        self.blob(repo, &img.config_digest, &img.config);
        for l in &img.layers {
            self.blob(repo, &l.digest, &l.blob);
        }
    }

    /// Requests so far with this method whose path contains `path`.
    fn requests(&self, method: &str, path: &str) -> usize {
        let method = format!("{method} ");
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(&method) && k.contains(path))
            .map(|(_, n)| n)
            .sum()
    }

    fn total_requests(&self) -> usize {
        self.seen.lock().unwrap().values().sum()
    }
}

/// Routes by hand: repository names contain slashes, so a path is split at
/// its last `/manifests/` or `/blobs/`.
async fn handle(State(fake): State<Arc<Fake>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().to_owned();
    *fake.seen.lock().unwrap().entry(format!("{method} {path}")).or_default() += 1;

    if path == "/token" {
        fake.token_queries.lock().unwrap().push(uri.query().unwrap_or_default().to_owned());
        if fake.deny_tokens.load(SeqCst) {
            return oci_error(StatusCode::FORBIDDEN, "DENIED", "requested access to the resource is denied");
        }
        return respond(StatusCode::OK, "application/json", format!(r#"{{"token":"{TOKEN}"}}"#));
    }
    let Some(rest) = path.strip_prefix("/v2/") else {
        return oci_error(StatusCode::NOT_FOUND, "NOT_FOUND", "not a registry route");
    };
    let bearer = headers.get("authorization").and_then(|v| v.to_str().ok());
    if fake.auth.load(SeqCst) && bearer != Some(format!("Bearer {TOKEN}").as_str()) {
        let mut challenge = oci_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "authentication required");
        let realm = format!(r#"Bearer realm="http://{}/token",service="fake""#, fake.host());
        challenge.headers_mut().insert("www-authenticate", realm.parse().unwrap());
        return challenge;
    }
    if rest.is_empty() {
        return respond(StatusCode::OK, "application/json", "{}");
    }
    if let Some((repo, reference)) = rest.rsplit_once("/manifests/") {
        let found = fake.manifests.lock().unwrap().get(&(repo.to_owned(), reference.to_owned())).cloned();
        let Some((media_type, bytes)) = found else {
            return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest unknown");
        };
        let digest = Digest::of(&bytes).to_string();
        let body = if method == Method::HEAD { Body::empty() } else { Body::from(bytes) };
        return Response::builder()
            .header("content-type", media_type)
            .header("docker-content-digest", digest)
            .body(body)
            .unwrap();
    }
    if let Some((repo, digest)) = rest.rsplit_once("/blobs/") {
        let now = fake.in_flight.fetch_add(1, SeqCst) + 1;
        fake.max_in_flight.fetch_max(now, SeqCst);
        let delay = fake.blob_delay_ms.load(SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        fake.in_flight.fetch_sub(1, SeqCst);
        let found = fake.blobs.lock().unwrap().get(&(repo.to_owned(), digest.to_owned())).cloned();
        let Some(bytes) = found else {
            return oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob unknown to registry");
        };
        let body = if fake.chunked.load(SeqCst) {
            Body::from_stream(futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from(bytes))]))
        } else {
            Body::from(bytes)
        };
        return Response::builder()
            .header("content-type", "application/octet-stream")
            .header("docker-content-digest", digest)
            .body(body)
            .unwrap();
    }
    oci_error(StatusCode::NOT_FOUND, "NOT_FOUND", "not a registry route")
}

fn respond(status: StatusCode, content_type: &str, body: impl Into<Body>) -> Response {
    Response::builder().status(status).header("content-type", content_type).body(body.into()).unwrap()
}

/// An error the way the distribution spec words them.
fn oci_error(status: StatusCode, code: &str, message: &str) -> Response {
    respond(status, "application/json", json!({"errors": [{"code": code, "message": message}]}).to_string())
}

// ---- helpers --------------------------------------------------------------

fn store() -> (tempfile::TempDir, ContentStore) {
    let dir = tempfile::tempdir().unwrap();
    let s = ContentStore::open(dir.path().join("content"), dir.path().join("ingest"), dir.path().join("lock")).unwrap();
    (dir, s)
}

/// A progress callback that keeps every event.
fn recorder(events: &Mutex<Vec<Progress>>) -> impl Fn(&Progress) + Send + Sync + '_ {
    move |p: &Progress| events.lock().unwrap().push(p.clone())
}

fn quiet(_: &Progress) {}

/// After a failed pull: no name, no partial download, none of `absent`
/// in the store.
fn assert_nothing_kept(dir: &Path, s: &ContentStore, absent: &[&Digest]) {
    assert!(s.refs().unwrap().is_empty(), "a name was set");
    let partials: Vec<_> = std::fs::read_dir(dir.join("ingest")).unwrap().collect();
    assert!(partials.is_empty(), "partial downloads left behind: {partials:?}");
    for d in absent {
        assert_eq!(s.blob_size(d).unwrap(), None, "{d} is in the store");
    }
}

/// How many blobs the store has.
fn stored_blobs(s: &ContentStore) -> usize {
    std::fs::read_dir(s.dir().join("blobs/sha256")).unwrap().count()
}

// ---- tests ----------------------------------------------------------------

#[tokio::test]
async fn pulls_a_single_platform_image() {
    let big = layer(&[("big.bin", &noise(3 << 20))]);
    let small = layer(&[("etc/motd", b"hello\n")]);
    let img = image(Dialect::Oci, "amd64", &[&big, &small]);
    let fake = Fake::start().await;
    fake.image("test/app", Some("v1"), &img);
    let (_dir, s) = store();
    let reference = fake.reference("test/app:v1");
    let events = Mutex::new(Vec::new());

    let pulled = fake.puller().pull(&s, &reference, &recorder(&events)).await.unwrap();

    // Every blob is stored and the name points at the manifest; for a
    // single-platform image the repo digest is the manifest's own.
    for (digest, size) in [
        (&img.digest, img.manifest.len()),
        (&img.config_digest, img.config.len()),
        (&big.digest, big.blob.len()),
        (&small.digest, small.blob.len()),
    ] {
        assert!(s.has_blob(digest, size as u64).unwrap(), "{digest} is not stored");
    }
    let entry = s.resolve(&reference.name()).unwrap().unwrap();
    assert_eq!(entry.manifest_digest().unwrap(), img.digest);
    assert_eq!(entry.repo_digest.as_ref(), Some(&img.digest));
    assert_eq!(entry.target.media_type().to_string(), media::OCI_MANIFEST);
    let loaded = Image::load(&s, &reference.name()).unwrap();
    assert_eq!(loaded.manifest_digest, pulled.manifest_digest);
    assert_eq!(loaded.repo_digest, pulled.repo_digest);
    let diff_ids: Vec<&Digest> = loaded.layers.iter().map(|l| &l.diff_id).collect();
    assert_eq!(diff_ids, [&big.diff_id, &small.diff_id]);

    let events = events.into_inner().unwrap();
    assert_eq!(events[0], Progress::Resolving { reference: reference.name() });
    assert_eq!(
        events[1],
        Progress::Resolved {
            reference: reference.name(),
            manifest: img.digest.clone(),
            repo_digest: img.digest.clone(),
            platform: "linux/amd64".into(),
            layers: 2,
            size: (img.config.len() + big.blob.len() + small.blob.len()) as u64,
        }
    );
    assert_eq!(events.last(), Some(&Progress::Done { reference: reference.name(), manifest: img.digest.clone() }));
    // The config is downloaded first, then each layer once.
    let downloaded: Vec<(BlobKind, &Digest)> = events
        .iter()
        .filter_map(|e| match e {
            Progress::Downloaded { kind, digest, .. } => Some((*kind, digest)),
            _ => None,
        })
        .collect();
    assert_eq!(downloaded.len(), 3, "{downloaded:?}");
    assert_eq!(downloaded[0], (BlobKind::Config, &img.config_digest));
    assert!(
        downloaded.contains(&(BlobKind::Layer, &big.digest)) && downloaded.contains(&(BlobKind::Layer, &small.digest))
    );
    // The big layer's progress: from 0, about every MiB, up to its size.
    let steps: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            Progress::Downloading { digest, current, total, .. } if *digest == big.digest => {
                assert_eq!(*total, big.size());
                Some(*current)
            }
            _ => None,
        })
        .collect();
    assert_eq!(steps.first(), Some(&0), "{steps:?}");
    assert_eq!(steps.last(), Some(&big.size()), "{steps:?}");
    assert!(steps.windows(2).all(|w| w[0] < w[1]), "{steps:?}");
    assert!(steps.len() >= 4 && steps.len() as u64 <= big.size() / PROGRESS_STEP + 2, "{steps:?}");
}

/// Pulls from an index in `dialect` and checks that the linux/amd64 image,
/// and only it, was fetched.
async fn pulls_the_amd64_image_from(dialect: Dialect) {
    let amd64 = image(dialect, "amd64", &[&layer(&[("arch", b"x86_64")])]);
    let arm64 = image(dialect, "arm64", &[&layer(&[("arch", b"aarch64")])]);
    // Docker lists build attestations as platform unknown/unknown.
    let attestation = image(dialect, "unknown", &[]);
    let idx = index(dialect, &[(&arm64, "linux/arm64/v8"), (&amd64, "linux/amd64"), (&attestation, "unknown/unknown")]);
    let fake = Fake::start().await;
    for img in [&amd64, &arm64, &attestation] {
        fake.image("test/multi", None, img);
    }
    fake.manifest("test/multi", "latest", idx.media_type, &idx.bytes);
    let (_dir, s) = store();
    let reference = fake.reference("test/multi");
    let puller = fake.puller();
    let events = Mutex::new(Vec::new());

    let pulled = puller.pull(&s, &reference, &recorder(&events)).await.unwrap();

    // The name points at the amd64 manifest; the repo digest is the index's.
    assert_eq!(pulled.manifest_digest, amd64.digest);
    assert_eq!(pulled.repo_digest.as_ref(), Some(&idx.digest));
    let entry = s.resolve(&reference.name()).unwrap().unwrap();
    assert_eq!(entry.manifest_digest().unwrap(), amd64.digest);
    assert_eq!(entry.repo_digest.as_ref(), Some(&idx.digest));
    assert_eq!(entry.target.media_type().to_string(), amd64.media_type);
    let events = events.into_inner().unwrap();
    assert!(
        matches!(&events[1], Progress::Resolved { manifest, repo_digest, platform, .. }
            if *manifest == amd64.digest && *repo_digest == idx.digest && platform == "linux/amd64"),
        "{:?}",
        events[1]
    );
    // Nothing of the other entries was asked for.
    for other in [&arm64, &attestation] {
        assert_eq!(fake.requests("GET", &other.digest.to_string()), 0);
        assert_eq!(fake.requests("GET", &other.config_digest.to_string()), 0);
    }
    // The index itself isn't stored, but the name remembers its digest, so
    // `Always` recognizes it from a HEAD alone.
    assert_eq!(s.blob_size(&idx.digest).unwrap(), None);
    let gets = fake.requests("GET", "/v2/test/");
    let again = ensure(&s, &puller, &reference, PullPolicy::Always, &quiet).await.unwrap();
    assert_eq!(again.manifest_digest, amd64.digest);
    assert_eq!(fake.requests("HEAD", "/v2/test/multi/manifests/latest"), 1);
    assert_eq!(fake.requests("GET", "/v2/test/"), gets);
}

#[tokio::test]
async fn pulls_the_amd64_image_from_an_oci_index() {
    pulls_the_amd64_image_from(Dialect::Oci).await;
}

#[tokio::test]
async fn pulls_the_amd64_image_from_a_docker_manifest_list() {
    pulls_the_amd64_image_from(Dialect::Docker).await;
}

#[tokio::test]
async fn an_index_without_linux_amd64_is_not_found() {
    let arm64 = image(Dialect::Oci, "arm64", &[&layer(&[("arch", b"aarch64")])]);
    let s390x = image(Dialect::Oci, "s390x", &[&layer(&[("arch", b"s390x")])]);
    let idx = index(Dialect::Oci, &[(&arm64, "linux/arm64/v8"), (&s390x, "linux/s390x")]);
    let fake = Fake::start().await;
    fake.image("test/multi", None, &arm64);
    fake.image("test/multi", None, &s390x);
    fake.manifest("test/multi", "latest", idx.media_type, &idx.bytes);
    let (dir, s) = store();

    let err = fake.puller().pull(&s, &fake.reference("test/multi"), &quiet).await.unwrap_err();

    let message = err.to_string();
    assert!(matches!(err, Error::NotFound(_)), "{message}");
    assert!(message.contains("linux/arm64/v8") && message.contains("linux/s390x"), "{message}");
    assert_nothing_kept(dir.path(), &s, &[]);
    assert_eq!(stored_blobs(&s), 0);
    assert_eq!(fake.requests("GET", "/blobs/"), 0);
}

#[tokio::test]
async fn answers_a_bearer_token_challenge() {
    let img = image(Dialect::Oci, "amd64", &[&layer(&[("f", b"x")])]);
    let fake = Fake::start().await;
    fake.auth.store(true, SeqCst);
    fake.image("test/app", Some("v1"), &img);
    let (_dir, s) = store();

    let pulled = fake.puller().pull(&s, &fake.reference("test/app:v1"), &quiet).await.unwrap();

    assert_eq!(pulled.manifest_digest, img.digest);
    // One anonymous token for the whole pull, from the realm the challenge
    // named, scoped to pulling this repository.
    let queries = fake.token_queries.lock().unwrap().clone();
    assert_eq!(queries.len(), 1, "{queries:?}");
    assert!(queries[0].contains("service=fake"), "{queries:?}");
    assert!(queries[0].contains("scope=repository%3Atest%2Fapp%3Apull"), "{queries:?}");

    // A registry that hands out no token can't be pulled from, and says so.
    fake.deny_tokens.store(true, SeqCst);
    let (dir, s) = store();
    let err = fake.puller().pull(&s, &fake.reference("test/app:v1"), &quiet).await.unwrap_err();
    assert!(matches!(&err, Error::Registry(m) if m.contains("test/app:v1")), "{err}");
    assert_nothing_kept(dir.path(), &s, &[&img.digest]);
}

#[tokio::test]
async fn refuses_a_corrupted_layer() {
    let good = layer(&[("good", b"good")]);
    let bad = layer(&[("bad", &noise(64 << 10))]);
    let img = image(Dialect::Oci, "amd64", &[&good, &bad]);
    let fake = Fake::start().await;
    fake.image("test/app", Some("v1"), &img);
    // The right length with one byte flipped: only the digest can tell.
    let mut corrupted = bad.blob.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 0xff;
    fake.blob("test/app", &bad.digest, &corrupted);
    let (dir, s) = store();

    let err = fake.puller().pull(&s, &fake.reference("test/app:v1"), &quiet).await.unwrap_err();

    assert!(matches!(&err, Error::DigestMismatch { expected, .. } if *expected == bad.digest.to_string()), "{err}");
    assert_nothing_kept(dir.path(), &s, &[&bad.digest, &img.digest]);
}

#[tokio::test]
async fn refuses_a_blob_of_the_wrong_length() {
    let l = layer(&[("f", &noise(64 << 10))]);
    let img = image(Dialect::Oci, "amd64", &[&l]);
    let fake = Fake::start().await;
    fake.image("test/app", Some("v1"), &img);
    let longer = [l.blob.as_slice(), b"!"].concat();
    let shorter = &l.blob[..l.blob.len() - 1];
    // With a Content-Length the size is wrong before the body arrives;
    // chunked, it turns out while (longer) or after (shorter) it streams.
    for (chunked, served) in [(false, &longer[..]), (false, shorter), (true, &longer[..]), (true, shorter)] {
        fake.chunked.store(chunked, SeqCst);
        fake.blob("test/app", &l.digest, served);
        let (dir, s) = store();

        let err = fake.puller().pull(&s, &fake.reference("test/app:v1"), &quiet).await.unwrap_err();

        let case = format!("chunked: {chunked}, {} bytes served for {}", served.len(), l.size());
        assert!(matches!(&err, Error::DigestMismatch { what, .. } if what.contains("size of blob")), "{case}: {err}");
        assert_nothing_kept(dir.path(), &s, &[&l.digest, &img.digest]);
    }
}

#[tokio::test]
async fn refuses_manifests_that_do_not_match_their_digest() {
    let img = image(Dialect::Oci, "amd64", &[&layer(&[("f", b"x")])]);
    let other = image(Dialect::Oci, "amd64", &[&layer(&[("f", b"y")])]);
    let fake = Fake::start().await;
    // Pinned by digest, and served something else.
    fake.image("test/pinned", None, &img);
    fake.manifest("test/pinned", &img.digest.to_string(), other.media_type, &other.manifest);
    // An index entry whose manifest is served as something else...
    let idx = index(Dialect::Oci, &[(&img, "linux/amd64")]);
    fake.image("test/swapped", None, &img);
    fake.manifest("test/swapped", &img.digest.to_string(), other.media_type, &other.manifest);
    fake.manifest("test/swapped", "latest", idx.media_type, &idx.bytes);
    // ...and one with the wrong size.
    let mut resized: serde_json::Value = serde_json::from_slice(&idx.bytes).unwrap();
    resized["manifests"][0]["size"] = json!(img.manifest.len() + 1);
    fake.image("test/resized", None, &img);
    fake.manifest("test/resized", "latest", idx.media_type, &serde_json::to_vec(&resized).unwrap());

    for path in [format!("test/pinned@{}", img.digest), "test/swapped".into(), "test/resized".into()] {
        let (dir, s) = store();

        let err = fake.puller().pull(&s, &fake.reference(&path), &quiet).await.unwrap_err();

        assert!(matches!(err, Error::DigestMismatch { .. }), "{path}: {err}");
        assert_nothing_kept(dir.path(), &s, &[]);
        assert_eq!(stored_blobs(&s), 0, "{path}");
    }
    assert_eq!(fake.requests("GET", "/blobs/"), 0);
}

#[tokio::test]
async fn skips_blobs_the_store_already_has() {
    let base = layer(&[("etc/os-release", b"ID=test\n")]);
    let a = image(Dialect::Oci, "amd64", &[&base, &layer(&[("a", b"a")])]);
    let b = image(Dialect::Oci, "amd64", &[&base, &layer(&[("b", b"b")])]);
    let fake = Fake::start().await;
    fake.image("test/a", Some("v1"), &a);
    fake.image("test/b", Some("v1"), &b);
    let (_dir, s) = store();
    let puller = fake.puller();
    puller.pull(&s, &fake.reference("test/a:v1"), &quiet).await.unwrap();

    // b shares a's bottom layer: reported as existing, never asked for.
    let events = Mutex::new(Vec::new());
    puller.pull(&s, &fake.reference("test/b:v1"), &recorder(&events)).await.unwrap();
    let events = events.into_inner().unwrap();
    let exists = Progress::Exists { kind: BlobKind::Layer, digest: base.digest.clone(), size: base.size() };
    assert!(events.contains(&exists), "{events:#?}");
    assert_eq!(fake.requests("GET", &format!("/v2/test/b/blobs/{}", base.digest)), 0);
    assert_eq!(fake.requests("GET", &format!("/v2/test/b/blobs/{}", b.layers[1].digest)), 1);

    // Pulling a again asks for its manifest and nothing else.
    let blob_gets = fake.requests("GET", "/blobs/");
    let again = puller.pull(&s, &fake.reference("test/a:v1"), &quiet).await.unwrap();
    assert_eq!(again.manifest_digest, a.digest);
    assert_eq!(fake.requests("GET", "/blobs/"), blob_gets);
}

#[tokio::test]
async fn ensure_follows_the_pull_policy() {
    let v1 = image(Dialect::Oci, "amd64", &[&layer(&[("version", b"1")])]);
    let fake = Fake::start().await;
    fake.image("test/app", Some("v1"), &v1);
    let (_dir, s) = store();
    let puller = fake.puller();
    let reference = fake.reference("test/app:v1");

    // Never, with nothing stored: not found, and the registry isn't asked.
    let err = ensure(&s, &puller, &reference, PullPolicy::Never, &quiet).await.unwrap_err();
    assert!(matches!(&err, Error::NotFound(m) if m.contains("test/app:v1")), "{err}");
    assert_eq!(fake.total_requests(), 0);

    // Missing, with nothing stored: a pull.
    let got = ensure(&s, &puller, &reference, PullPolicy::Missing, &quiet).await.unwrap();
    assert_eq!(got.manifest_digest, v1.digest);
    assert!(fake.requests("GET", "/blobs/") > 0);

    // Missing or Never, with the name stored: no request at all.
    let before = fake.total_requests();
    for policy in [PullPolicy::Missing, PullPolicy::Never] {
        let got = ensure(&s, &puller, &reference, policy, &quiet).await.unwrap();
        assert_eq!(got.manifest_digest, v1.digest);
    }
    assert_eq!(fake.total_requests(), before);

    // Always, with the tag unchanged: one HEAD, nothing downloaded, and
    // every blob reported as existing.
    let gets = fake.requests("GET", "/v2/test/");
    let events = Mutex::new(Vec::new());
    let got = ensure(&s, &puller, &reference, PullPolicy::Always, &recorder(&events)).await.unwrap();
    assert_eq!(got.manifest_digest, v1.digest);
    assert_eq!(fake.requests("HEAD", "/v2/test/app/manifests/v1"), 1);
    assert_eq!(fake.requests("GET", "/v2/test/"), gets);
    let events = events.into_inner().unwrap();
    assert_eq!(events.first(), Some(&Progress::Resolving { reference: reference.name() }));
    assert!(
        matches!(events.get(1), Some(Progress::Resolved { manifest, .. }) if *manifest == v1.digest),
        "{events:#?}"
    );
    assert_eq!(events.iter().filter(|e| matches!(e, Progress::Exists { .. })).count(), 2, "{events:#?}");
    assert!(!events.iter().any(|e| matches!(e, Progress::Downloading { .. } | Progress::Downloaded { .. })));
    assert_eq!(events.last(), Some(&Progress::Done { reference: reference.name(), manifest: v1.digest.clone() }));

    // Always, after the tag moved: the new image is pulled, the name follows.
    let v2 = image(Dialect::Oci, "amd64", &[&layer(&[("version", b"2")])]);
    fake.image("test/app", Some("v1"), &v2);
    let got = ensure(&s, &puller, &reference, PullPolicy::Always, &quiet).await.unwrap();
    assert_eq!(got.manifest_digest, v2.digest);
    assert_eq!(s.resolve(&reference.name()).unwrap().unwrap().manifest_digest().unwrap(), v2.digest);

    // Always, for a new tag on a manifest the store has: one HEAD, and
    // only the name is new.
    fake.manifest("test/app", "stable", v2.media_type, &v2.manifest);
    let stable = fake.reference("test/app:stable");
    let gets = fake.requests("GET", "/v2/test/");
    let got = ensure(&s, &puller, &stable, PullPolicy::Always, &quiet).await.unwrap();
    assert_eq!(got.manifest_digest, v2.digest);
    assert_eq!(fake.requests("GET", "/v2/test/"), gets);
    let entry = s.resolve(&stable.name()).unwrap().unwrap();
    assert_eq!(entry.manifest_digest().unwrap(), v2.digest);
    assert_eq!(entry.repo_digest, Some(v2.digest.clone()));
}

#[tokio::test]
async fn refuses_an_artifact() {
    // A Helm chart: an OCI manifest whose config isn't an image config.
    let config = br#"{"name":"chart","version":"1.0.0"}"#;
    let chart = b"not a root filesystem";
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": media::OCI_MANIFEST,
        "config": {
            "mediaType": "application/vnd.cncf.helm.config.v1+json",
            "digest": Digest::of(config),
            "size": config.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
            "digest": Digest::of(chart),
            "size": chart.len(),
        }],
    }))
    .unwrap();
    let fake = Fake::start().await;
    fake.manifest("test/chart", "1.0.0", media::OCI_MANIFEST, &manifest);
    fake.blob("test/chart", &Digest::of(config), config);
    fake.blob("test/chart", &Digest::of(chart), chart);
    let (dir, s) = store();

    let err = fake.puller().pull(&s, &fake.reference("test/chart:1.0.0"), &quiet).await.unwrap_err();

    assert!(matches!(err, Error::Unsupported(_)), "{err}");
    assert_nothing_kept(dir.path(), &s, &[]);
    assert_eq!(stored_blobs(&s), 0);
    assert_eq!(fake.requests("GET", "/blobs/"), 0);
}

#[tokio::test]
async fn refuses_another_platform_before_fetching_layers() {
    let arm = image(Dialect::Oci, "arm64", &[&layer(&[("arch", b"aarch64")])]);
    let fake = Fake::start().await;
    fake.image("test/arm", Some("v1"), &arm);
    let (_dir, s) = store();

    let err = fake.puller().pull(&s, &fake.reference("test/arm:v1"), &quiet).await.unwrap_err();

    assert!(matches!(&err, Error::Unsupported(m) if m.contains("linux/arm64")), "{err}");
    // The config alone gave it away.
    assert_eq!(fake.requests("GET", &arm.config_digest.to_string()), 1);
    assert_eq!(fake.requests("GET", &arm.layers[0].digest.to_string()), 0);
    assert!(s.refs().unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_tag_is_a_registry_error() {
    let fake = Fake::start().await;
    let (dir, s) = store();

    let err = fake.puller().pull(&s, &fake.reference("test/app:nope"), &quiet).await.unwrap_err();

    assert!(
        matches!(&err, Error::Registry(m) if m.contains("test/app:nope") && m.contains("manifest unknown")),
        "{err}"
    );
    assert_nothing_kept(dir.path(), &s, &[]);
}

#[tokio::test]
async fn downloads_at_most_max_concurrent_downloads_blobs_at_once() {
    let layers: Vec<TestLayer> = (0..6).map(|i| layer(&[("n", i.to_string().as_bytes())])).collect();
    let img = image(Dialect::Oci, "amd64", &layers.iter().collect::<Vec<_>>());
    let fake = Fake::start().await;
    fake.image("test/app", Some("v1"), &img);
    fake.blob_delay_ms.store(100, SeqCst);
    let (_dir, s) = store();

    fake.puller_with(2).pull(&s, &fake.reference("test/app:v1"), &quiet).await.unwrap();

    assert_eq!(fake.max_in_flight.load(SeqCst), 2);
}

#[test]
fn progress_events_are_ndjson_lines() {
    let line = |p: Progress| serde_json::to_string(&p).unwrap();
    assert_eq!(
        line(Progress::Resolving { reference: "docker.io/library/alpine:latest".into() }),
        r#"{"status":"resolving","reference":"docker.io/library/alpine:latest"}"#
    );
    let d = Digest::of(b"layer");
    assert_eq!(
        line(Progress::Downloading { kind: BlobKind::Layer, digest: d.clone(), current: 1, total: 2 }),
        format!(r#"{{"status":"downloading","kind":"layer","digest":"{d}","current":1,"total":2}}"#)
    );
}

#[test]
fn pulls_can_run_on_any_thread() {
    fn assert_send(_: impl Send) {}
    let (_dir, s) = store();
    let puller = Puller::new(PullOptions::default());
    let reference = ImageRef::parse("alpine").unwrap();
    assert_send(puller.pull(&s, &reference, &quiet));
    assert_send(ensure(&s, &puller, &reference, PullPolicy::Always, &quiet));
}

/// The real thing: busybox from Docker Hub, a multi-platform index. Needs
/// the network, and Docker Hub rate-limits anonymous pulls, so it only runs
/// when asked: `cargo test -p rustlet-image -- --ignored live_pull`.
#[tokio::test]
#[ignore = "pulls from Docker Hub: needs the network, and pulls are rate-limited"]
async fn live_pull_from_docker_hub() {
    let (_dir, s) = store();
    let reference = ImageRef::parse("docker.io/library/busybox:latest").unwrap();
    let events = Mutex::new(Vec::new());

    let pulled = Puller::new(PullOptions::default()).pull(&s, &reference, &recorder(&events)).await.unwrap();

    assert_eq!(pulled.config.platform(), "linux/amd64");
    assert!(!pulled.layers.is_empty());
    for l in &pulled.layers {
        assert!(s.has_blob(&l.blob, l.size).unwrap(), "{} is not stored", l.blob);
    }
    let entry = s.resolve(&reference.name()).unwrap().unwrap();
    assert_eq!(entry.manifest_digest().unwrap(), pulled.manifest_digest);
    // busybox is multi-platform: the repo digest is the index's.
    assert!(entry.repo_digest.as_ref().is_some_and(|d| *d != pulled.manifest_digest), "{entry:?}");
    let events = events.into_inner().unwrap();
    assert!(matches!(events.last(), Some(Progress::Done { .. })), "{events:#?}");
}
