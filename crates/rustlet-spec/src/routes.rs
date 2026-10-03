//! The paths of the API (see the table in the crate docs), so that client
//! and server spell them the same way. Query parameters are the `*Query`
//! structs, URL-encoded (`serde_urlencoded`; `true`/`false` for booleans).

/// `/v1` + `rest`.
fn v1(rest: &str) -> String {
    format!("/{}{rest}", crate::API_VERSION)
}

pub fn ping() -> String {
    v1("/_ping")
}
pub fn version() -> String {
    v1("/version")
}
pub fn info() -> String {
    v1("/info")
}
pub fn events() -> String {
    v1("/events")
}

/// `GET` (list) and `POST` (create).
pub fn containers() -> String {
    v1("/containers")
}
/// `GET` (inspect) and `DELETE`.
pub fn container(id: &str) -> String {
    v1(&format!("/containers/{id}"))
}
/// `/v1/containers/{id}/{action}`, `action` one of [`action`]'s.
pub fn container_action(id: &str, action: &str) -> String {
    v1(&format!("/containers/{id}/{action}"))
}

/// The last path segment of the per-container routes.
pub mod action {
    pub const START: &str = "start";
    pub const STOP: &str = "stop";
    pub const KILL: &str = "kill";
    pub const RESTART: &str = "restart";
    pub const PAUSE: &str = "pause";
    pub const UNPAUSE: &str = "unpause";
    pub const WAIT: &str = "wait";
    pub const LOGS: &str = "logs";
    pub const STATS: &str = "stats";
    pub const ATTACH: &str = "attach";
    pub const EXEC: &str = "exec";
    pub const ISOLATION: &str = "isolation";
    pub const ALL: [&str; 12] =
        [START, STOP, KILL, RESTART, PAUSE, UNPAUSE, WAIT, LOGS, STATS, ATTACH, EXEC, ISOLATION];
}

/// `GET` (inspect).
pub fn exec(id: &str) -> String {
    v1(&format!("/exec/{id}"))
}
/// `GET` + WebSocket upgrade (attached), or `POST` (detached).
pub fn exec_start(id: &str) -> String {
    v1(&format!("/exec/{id}/start"))
}

/// `GET` (list) and `DELETE` (`?name=`).
pub fn images() -> String {
    v1("/images")
}
pub fn image_pull() -> String {
    v1("/images/pull")
}
pub fn image_inspect() -> String {
    v1("/images/inspect")
}
/// `POST` (`?source=&target=`).
pub fn image_tag() -> String {
    v1("/images/tag")
}
/// `POST`: [`crate::image::ImageSaveRequest`] → a tar archive.
pub fn image_save() -> String {
    v1("/images/save")
}
/// `POST`: a tar archive → NDJSON [`crate::image::LoadEvent`].
pub fn image_load() -> String {
    v1("/images/load")
}

/// `POST` (`?options=`): a build context → NDJSON [`crate::build::BuildEvent`].
pub fn build() -> String {
    v1("/build")
}
/// `POST`: forget the build cache.
pub fn build_prune() -> String {
    v1("/build/prune")
}
/// `POST`: [`crate::build::CommitRequest`].
pub fn commit() -> String {
    v1("/commit")
}

/// `GET` (list) and `POST` (create).
pub fn networks() -> String {
    v1("/networks")
}
/// `GET` (inspect) and `DELETE`.
pub fn network(id: &str) -> String {
    v1(&format!("/networks/{id}"))
}
pub fn network_prune() -> String {
    v1("/networks/prune")
}
/// `POST`: [`crate::network::NetworkConnect`].
pub fn network_connect(id: &str) -> String {
    v1(&format!("/networks/{id}/connect"))
}
/// `POST`: [`crate::network::NetworkDisconnect`].
pub fn network_disconnect(id: &str) -> String {
    v1(&format!("/networks/{id}/disconnect"))
}

/// `GET` (list) and `POST` (create).
pub fn volumes() -> String {
    v1("/volumes")
}
/// `GET` (inspect) and `DELETE`.
pub fn volume(name: &str) -> String {
    v1(&format!("/volumes/{name}"))
}
pub fn volume_prune() -> String {
    v1("/volumes/prune")
}

/// The same routes in axum's syntax, for the server.
pub mod pattern {
    pub const PING: &str = "/v1/_ping";
    pub const VERSION: &str = "/v1/version";
    pub const INFO: &str = "/v1/info";
    pub const EVENTS: &str = "/v1/events";
    pub const CONTAINERS: &str = "/v1/containers";
    pub const CONTAINER: &str = "/v1/containers/{id}";
    /// `/v1/containers/{id}/<action>`.
    pub fn container_action(action: &str) -> String {
        format!("/v1/containers/{{id}}/{action}")
    }
    pub const EXEC: &str = "/v1/exec/{id}";
    pub const EXEC_START: &str = "/v1/exec/{id}/start";
    pub const IMAGES: &str = "/v1/images";
    pub const IMAGE_PULL: &str = "/v1/images/pull";
    pub const IMAGE_INSPECT: &str = "/v1/images/inspect";
    pub const IMAGE_TAG: &str = "/v1/images/tag";
    pub const IMAGE_SAVE: &str = "/v1/images/save";
    pub const IMAGE_LOAD: &str = "/v1/images/load";
    pub const BUILD: &str = "/v1/build";
    pub const BUILD_PRUNE: &str = "/v1/build/prune";
    pub const COMMIT: &str = "/v1/commit";
    pub const NETWORKS: &str = "/v1/networks";
    pub const NETWORK: &str = "/v1/networks/{id}";
    pub const NETWORK_PRUNE: &str = "/v1/networks/prune";
    pub const NETWORK_CONNECT: &str = "/v1/networks/{id}/connect";
    pub const NETWORK_DISCONNECT: &str = "/v1/networks/{id}/disconnect";
    pub const VOLUMES: &str = "/v1/volumes";
    pub const VOLUME: &str = "/v1/volumes/{name}";
    pub const VOLUME_PRUNE: &str = "/v1/volumes/prune";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_match_the_patterns() {
        assert_eq!(containers(), pattern::CONTAINERS);
        assert_eq!(container("web"), pattern::CONTAINER.replace("{id}", "web"));
        for a in action::ALL {
            assert_eq!(container_action("web", a), pattern::container_action(a).replace("{id}", "web"));
        }
        assert_eq!(exec_start("e1"), pattern::EXEC_START.replace("{id}", "e1"));
        assert_eq!(image_pull(), pattern::IMAGE_PULL);
        assert_eq!(
            [image_tag(), image_save(), image_load(), build(), build_prune(), commit()],
            [
                pattern::IMAGE_TAG,
                pattern::IMAGE_SAVE,
                pattern::IMAGE_LOAD,
                pattern::BUILD,
                pattern::BUILD_PRUNE,
                pattern::COMMIT
            ]
        );
        assert_eq!(ping(), pattern::PING);
        assert_eq!(network("n1"), pattern::NETWORK.replace("{id}", "n1"));
        assert_eq!(network_prune(), pattern::NETWORK_PRUNE);
        assert_eq!(network_connect("n1"), pattern::NETWORK_CONNECT.replace("{id}", "n1"));
        assert_eq!(network_disconnect("n1"), pattern::NETWORK_DISCONNECT.replace("{id}", "n1"));
        assert_eq!(volume("v"), pattern::VOLUME.replace("{name}", "v"));
        assert_eq!(
            (networks(), volumes(), volume_prune()),
            (pattern::NETWORKS.into(), pattern::VOLUMES.into(), pattern::VOLUME_PRUNE.into())
        );
    }
}
