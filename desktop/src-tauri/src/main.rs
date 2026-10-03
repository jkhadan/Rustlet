//! `rustlets-desktop`: the Rustlets GUI. Everything is in the library
//! (`rustlet_desktop::run`), so its tests can reach it.
#![forbid(unsafe_code)]

fn main() {
    rustlet_desktop::run();
}
