//! # rustlet-build: Containerfiles and build contexts
//!
//! ```text
//!  client (CLI, compose, desktop)            rustletd
//!  ─────────────────────────────            ────────────────────────────────────────────
//!  context::pack: a directory, less    ──►  parser::parse: the Containerfile's instructions
//!  what .dockerignore excludes                plan::plan: which stages, in what order
//!  (ignore), as a tar archive                 op::Op: an instruction with its variables
//!                                             expanded (expand), as the step will run it
//!                                             config::ImageConfigState: what ENV, CMD, USER…
//!                                             do to the image's config
//! ```
//!
//! Everything here is plain computation over text and files: no
//! containers, no store. The daemon's builder (`rustletd`'s `build` module)
//! runs the steps: `RUN` in a container, `COPY` and `ADD` into a mounted
//! root filesystem (`rustlet_image::copy`), each step's changes committed as
//! a layer (`rustlet_image::diff`).
//!
//! The syntax is Docker's, as its documentation and BuildKit's parser
//! define it, with the instructions of the classic builder: `FROM … [AS
//! name]`, `RUN`, `CMD`, `ENTRYPOINT`, `COPY [--from] [--chown] [--chmod]`,
//! `ADD` (local files and archives), `ENV`, `ARG`, `LABEL`, `WORKDIR`,
//! `USER`, `EXPOSE`, `VOLUME`, `STOPSIGNAL`, `HEALTHCHECK`, `SHELL`,
//! `ONBUILD` (recorded, not run) and `MAINTAINER`. BuildKit's own
//! additions (`RUN --mount`, heredocs, `COPY --link`…) are refused with the
//! line they are on, never ignored.
#![forbid(unsafe_code)]

pub mod config;
pub mod context;
pub mod expand;
pub mod ignore;
pub mod op;
pub mod parser;
mod path;
pub mod plan;

pub use op::Op;
pub use parser::{Containerfile, Instruction, InstructionKind, ParseError, Stage, parse};
