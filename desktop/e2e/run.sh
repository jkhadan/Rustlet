#!/bin/sh
# Builds the app and the CLI, starts tauri-driver (and, with E2E_XVFB, a
# virtual display), and runs the lifecycle scenario (lifecycle.mjs).
#
#   desktop/e2e/run.sh                      on the current display
#   E2E_XVFB=:99 desktop/e2e/run.sh         on a private Xvfb display
#   E2E_SHOTS=/tmp/shots desktop/e2e/run.sh  a screenshot after each step
#   E2E_RESTART='…' desktop/e2e/run.sh      also restart the daemon (a shell command)
#
# WebKitWebDriver comes from the webkit2gtk-driver package; without it
# installed, set WEBKIT_WEBDRIVER to a copy (see desktop/README.md). The
# daemon must be one this user may use (RUSTLET_HOST, else the default
# socket) and have the alpine image.
set -eu

desktop=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$desktop/.." && pwd)
driver=${WEBKIT_WEBDRIVER:-$(command -v WebKitWebDriver || true)}
[ -x "$driver" ] || { echo "WebKitWebDriver not found: install webkit2gtk-driver or set WEBKIT_WEBDRIVER" >&2; exit 1; }
command -v tauri-driver >/dev/null || { echo "tauri-driver not found: cargo install tauri-driver --locked" >&2; exit 1; }

(cd "$desktop" && pnpm tauri build --debug --no-bundle)
cargo build --quiet --manifest-path "$root/Cargo.toml" -p rustlet-cli

pids=""
trap 'for p in $pids; do kill "$p" 2>/dev/null || true; done' EXIT INT TERM
if [ -n "${E2E_XVFB:-}" ]; then
    ${XVFB:-Xvfb} "$E2E_XVFB" -screen 0 1280x820x24 -nolisten tcp >/dev/null 2>&1 &
    pids="$pids $!"
    export DISPLAY="$E2E_XVFB"
    sleep 1
fi
tauri-driver --native-driver "$driver" --port 4444 --native-port 4445 >/dev/null 2>&1 &
pids="$pids $!"
sleep 1
[ -n "${E2E_SHOTS:-}" ] && mkdir -p "$E2E_SHOTS"
node "$desktop/e2e/lifecycle.mjs" "$root/target/debug/rustlets-desktop" "$root/target/debug/rustlet" ${E2E_SHOTS:+"$E2E_SHOTS"}
