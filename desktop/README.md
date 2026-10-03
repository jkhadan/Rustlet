# Rustlets Desktop

The GUI for `rustletd`: a [Tauri v2](https://tauri.app) app whose window is a
WebKitGTK webview running a React + TypeScript frontend (`src/`), with a Rust
side (`src-tauri/`, the crate `rustlet-desktop`) that talks to the daemon
through `rustlet-client`. How it fits together, and why, is
[chapter 17](../docs/learn/17-tauri-ipc.md) and
[architecture.md §2.8](../docs/architecture.md#28-rustlets-desktop-tauri-v2--reactts).

```
src/
  bindings/      the API's types, generated from crates/rustlet-spec (cargo xtask gen-ts)
  lib/           ipc.ts (every command, typed), events.ts (daemon events → stale queries),
                 daemon.tsx (the connection), streams of logs/stats/pulls, terminal input,
                 the pure logic the tests cover (stats, ANSI, pull progress, topology, formats)
  components/    the shell (sidebar, connection indicator) and a small UI kit
  views/         dashboard, containers (+ run dialog, the detail tabs), images, networks, volumes
src-tauri/
  src/           commands.rs, streams.rs, terminal.rs, error.rs
  build.rs       the command list (each gets a permission)
  capabilities/  what the window may invoke: exactly those commands
e2e/             a WebDriver client and the lifecycle scenario
```

## Develop

You need what Tauri needs on Linux (`libwebkit2gtk-4.1-dev libxdo-dev libssl-dev
libayatana-appindicator3-dev librsvg2-dev`), Node 22 or later, and pnpm.

```sh
pnpm install
pnpm tauri dev        # Vite on :1420 with hot reload, and the app
pnpm test             # Vitest
pnpm typecheck        # tsc
cargo nextest run -p rustlet-desktop
```

After changing a type in `crates/rustlet-spec`, run `cargo xtask gen-ts` (CI runs
`gen-ts --check`).

**A daemon the app may use.** The app runs as you, and the daemon's socket is
root's unless the `rustlet` group exists (membership is root-equivalent):

```sh
sudo groupadd --system rustlet && sudo usermod -aG rustlet $USER
sudo systemctl restart rustletd     # it picks the group up at start; then log in again
```

For development, a daemon of the current build with the socket in your own group
works too (the installed service must be stopped; they share `/var/lib/rustlet`):

```sh
T=$PWD/target/debug
sudo systemd-run --unit=rustletd-dev -p Type=notify -p Delegate=yes -p DelegateSubgroup=daemon \
  -p KillMode=process -p OOMScoreAdjust=-500 --collect \
  $T/rustletd --socket-group $(id -gn) --runtime $T/rustlet-runc --shim $T/rustlet-shim
```

`RUSTLET_HOST` points the app at another socket, as it does the CLI.

## Build

```sh
pnpm tauri build      # ../target/release/bundle/{deb,appimage}/ (the workspace's target/)
```

## End-to-end

`e2e/run.sh` builds the app, starts `tauri-driver`, and runs `e2e/lifecycle.mjs`:
a container's whole life driven through the GUI while the `rustlet` CLI acts on
the same daemon, each checking what the other did.

```sh
cargo install tauri-driver --locked
sudo apt install webkit2gtk-driver          # WebKitWebDriver
desktop/e2e/run.sh
```

Without root, `apt-get download webkit2gtk-driver xvfb` and `dpkg-deb -x` give
the two binaries (their libraries are installed with WebKitGTK and X); point
`WEBKIT_WEBDRIVER` and `XVFB` at them. `E2E_XVFB=:99` runs the app on a private
virtual display, `E2E_SHOTS=dir` saves a screenshot after each step, and
`E2E_RESTART='<command>'` adds a daemon restart to the scenario.
