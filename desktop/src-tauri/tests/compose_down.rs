//! Desktop stack removal through the real client, over a temporary Unix
//! socket. The fixture represents resources made by an earlier compose up.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustlet_client::Client;
use rustlet_compose::{LABEL_CONFIG_FILES, LABEL_NUMBER, LABEL_PROJECT, LABEL_SERVICE, LABEL_WORKING_DIR};
use rustlet_desktop::compose;
use rustlet_spec::container::{ContainerState, ContainerStatus, ContainerSummary};
use rustlet_spec::network::Network;
use rustlet_spec::volume::Volume;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

#[derive(Default)]
struct State {
    containers: Vec<ContainerSummary>,
    networks: Vec<Network>,
    volumes: Vec<Volume>,
    changes: Vec<String>,
}

struct Fixture {
    client: Client,
    state: Arc<Mutex<State>>,
    server: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn start(file: Option<&Path>) -> Fixture {
        let mut labels: BTreeMap<String, String> =
            BTreeMap::from([(LABEL_PROJECT.into(), "shop".into()), (LABEL_NUMBER.into(), "1".into())]);
        if let Some(file) = file {
            labels.insert(LABEL_CONFIG_FILES.into(), file.display().to_string());
            labels.insert(LABEL_WORKING_DIR.into(), file.parent().unwrap().display().to_string());
        }
        let containers = ["web", "debug", "obsolete"]
            .into_iter()
            .map(|service| ContainerSummary {
                id: service.into(),
                name: format!("shop-{service}-1"),
                state: ContainerState { status: ContainerStatus::Running, ..Default::default() },
                labels: labels
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .chain([(LABEL_SERVICE.into(), service.into())])
                    .collect(),
                ..Default::default()
            })
            .collect();
        let resources = BTreeMap::from([(LABEL_PROJECT.into(), "shop".into())]);
        let state = Arc::new(Mutex::new(State {
            containers,
            networks: vec![Network {
                id: "network".into(),
                name: "shop_default".into(),
                labels: resources.clone(),
                ..Default::default()
            }],
            volumes: vec![Volume { name: "shop_data".into(), labels: resources, ..Default::default() }],
            ..Default::default()
        }));
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let serving = state.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut bytes = [0; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let read = socket.read(&mut bytes).await.unwrap();
                    assert!(read > 0, "request ended before its headers");
                    request.extend_from_slice(&bytes[..read]);
                }
                let request = String::from_utf8(request).unwrap();
                let mut words = request.lines().next().unwrap().split_whitespace();
                let method = words.next().unwrap();
                let path = words.next().unwrap().split('?').next().unwrap();
                let body = {
                    let mut state = serving.lock().unwrap();
                    match (method, path) {
                        ("GET", "/v1/containers") => serde_json::to_vec(&state.containers).unwrap(),
                        ("GET", "/v1/networks") => serde_json::to_vec(&state.networks).unwrap(),
                        ("GET", "/v1/volumes") => serde_json::to_vec(&state.volumes).unwrap(),
                        ("POST", path) if path.ends_with("/stop") => {
                            state.changes.push(format!("stop {path}"));
                            Vec::new()
                        }
                        ("DELETE", path) => {
                            state.changes.push(format!("remove {path}"));
                            if let Some(id) = path.strip_prefix("/v1/containers/") {
                                state.containers.retain(|c| c.id != id);
                            } else if path.starts_with("/v1/networks/") {
                                state.networks.clear();
                            } else if path.starts_with("/v1/volumes/") {
                                state.volumes.clear();
                            } else {
                                panic!("unexpected request: {method} {path}");
                            }
                            Vec::new()
                        }
                        _ => panic!("unexpected request: {method} {path}"),
                    }
                };
                let status = if body.is_empty() { "204 No Content" } else { "200 OK" };
                let response =
                    format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        Fixture { client: Client::new(socket), state, server, _dir: dir }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn down(fixture: &Fixture) -> rustlet_desktop::error::CommandResult<Vec<String>> {
    tokio::time::timeout(Duration::from_secs(5), compose::down(&fixture.client, "shop", true)).await.expect("down hung")
}

const CURRENT: &str = "name: shop\nservices:\n  web:\n    image: alpine\n  debug:\n    image: alpine\n    profiles: [debug]\nnetworks:\n  default:\n    external: true\n    name: shop_default\nvolumes:\n  data:\n    external: true\n    name: shop_data\n";

#[tokio::test]
async fn current_external_declarations_protect_previously_managed_resources() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("compose.yaml");
    std::fs::write(&file, CURRENT).unwrap();
    let fixture = Fixture::start(Some(&file));
    down(&fixture).await.unwrap();
    let state = fixture.state.lock().unwrap();
    assert!(state.containers.is_empty(), "all stack containers go, including profiled and removed services");
    assert_eq!(state.networks.len(), 1, "a network declared external stays despite its old project label");
    assert_eq!(state.volumes.len(), 1, "a volume declared external stays despite its old project label");
}

#[tokio::test]
async fn known_files_that_are_missing_or_invalid_fail_before_teardown() {
    for text in [None, Some("services: [invalid]")] {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("compose.yaml");
        if let Some(text) = text {
            std::fs::write(&file, text).unwrap();
        }
        let fixture = Fixture::start(Some(&file));
        assert!(down(&fixture).await.is_err());
        let state = fixture.state.lock().unwrap();
        assert!(state.changes.is_empty(), "the file must be validated before stopping or removing anything");
        assert_eq!(state.containers.len(), 3);
        assert_eq!((state.networks.len(), state.volumes.len()), (1, 1));
    }
}

#[tokio::test]
async fn stacks_without_recorded_files_can_still_be_removed_by_their_labels() {
    let fixture = Fixture::start(None);
    down(&fixture).await.unwrap();
    let state = fixture.state.lock().unwrap();
    assert!(state.containers.is_empty() && state.networks.is_empty() && state.volumes.is_empty());
}
