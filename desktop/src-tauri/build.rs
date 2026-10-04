//! Tauri's build step: checks `tauri.conf.json` and the capabilities, and
//! generates the context `tauri::generate_context!` embeds.
//!
//! Listing the commands here makes Tauri generate a permission for each
//! (`allow-container-list`, …) and refuse any command that no capability
//! grants: the webview can call what `capabilities/main.json` lists and
//! nothing else. Keep the list in step with `generate_handler!` in lib.rs.

const COMMANDS: &[&str] = &[
    "daemon_socket",
    "daemon_version",
    "daemon_info",
    "daemon_watch",
    "daemon_start",
    "parse_run_options",
    "container_list",
    "container_inspect",
    "container_create",
    "container_start",
    "container_stop",
    "container_restart",
    "container_kill",
    "container_pause",
    "container_unpause",
    "container_remove",
    "container_isolation",
    "container_logs",
    "container_stats",
    "container_commit",
    "stream_cancel",
    "terminal_open",
    "terminal_input",
    "terminal_resize",
    "terminal_close",
    "image_list",
    "image_inspect",
    "image_remove",
    "image_pull",
    "image_tag",
    "image_save",
    "image_load",
    "image_build",
    "build_prune",
    "stack_list",
    "compose_up",
    "compose_down",
    "network_list",
    "network_inspect",
    "network_create",
    "network_remove",
    "network_connect",
    "network_disconnect",
    "network_prune",
    "volume_list",
    "volume_inspect",
    "volume_create",
    "volume_remove",
    "volume_prune",
];

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest)).expect("tauri build step");
}
