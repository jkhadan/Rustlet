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
                 the pure logic the tests cover (stats, ANSI, pull, build and compose
                 progress, stacks, health, topology, formats)
  components/    the shell (sidebar, connection indicator) and a small UI kit
  views/         dashboard, containers (+ run dialog, the detail tabs), stacks, images
                 (+ tag, save, load), build, networks, volumes
src-tauri/
  src/           commands.rs, streams.rs, terminal.rs, error.rs; builder.rs (a build's
                 context, packed as it is sent), compose.rs (projects, client-side),
                 archive.rs (save and load files), paths.rs (paths typed in a form)
  build.rs       the command list (each gets a permission)
  capabilities/  what the window may invoke: exactly those commands
e2e/             a WebDriver client and the lifecycle scenario
```

## Views

- **Dashboard**, **Containers** (with each one's Overview, Logs, Terminal, Stats,
  Inspect and Isolation tabs), **Images**, **Networks**, **Volumes**, as in Phase 6.
  A container's healthcheck shows as a badge beside its status while it runs, and
  in a Health section of its Overview (the check, its settings, the last five
  results). A build runs each `RUN` step in a container of its own (label
  `io.rustlet.build`): the lists hide those unless asked to show them.
- **Stacks**: the compose projects the daemon has containers of, found by their
  labels (the daemon knows no projects), live from the daemon's events: what runs,
  each service's containers, health and ports. *Down* removes a project's
  containers and networks (and, if asked, its volumes); *Up* brings it up again
  from the files its labels name; *Up from file* takes a compose file's path.
- **Build**: a context directory, its Containerfile, names, build args, target;
  the steps as rustletd runs them, with each `RUN`'s output. Leaving the view
  doesn't stop a build; *Stop* does.
- Images also *Tag*, *Save* to a new file, *Load* a file, and *Prune build cache*;
  a container's actions menu has *Commit*.

The app is the client for what the CLI does client-side: it packs a build's context
(less what `.dockerignore` excludes, sent as it is packed) and runs compose
projects with `rustlet-compose`, as the CLI does. An up runs to its end in the app
whether or not its dialog stays open. A path typed into a form must be absolute or
start at `~/` (a Containerfile's may be relative to the context): the app has no
working directory of yours. Compose files are interpolated with the app's
environment, which is the session's when it was started from a launcher, not a
shell's.

| command | what |
|---|---|
| `image_build` | build from a context directory; `BuildEvent`s on a channel |
| `image_tag`, `image_save`, `image_load` | tag; save into a new file; load a file, `LoadEvent`s on a channel |
| `build_prune`, `container_commit` | forget the build cache; a container's changes as an image |
| `stack_list`, `compose_up`, `compose_down` | the projects; `compose up -d` with its progress on a channel; `compose -p NAME down` |

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
