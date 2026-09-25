# profiles/

Security profiles that Rustlets ships, vendored verbatim from upstream.

## `seccomp-default.json`

Docker's default seccomp profile, in Docker's own format (OCI `linux.seccomp`
plus `archMap` and per-rule `includes`/`excludes` on capabilities,
architectures and kernel versions).

| | |
|---|---|
| Source | <https://github.com/moby/profiles>, file `seccomp/default.json` |
| Commit | `85e237f1fe229a0c61c9c7d8e743fa780d3b97ca` |
| sha256 | `785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334` |
| License | Apache-2.0 (the same as Rustlets) |

It is compiled into the runtime (`include_str!` in
`crates/rustlet-runtime/src/seccomp/docker.rs`), which resolves the
`includes`/`excludes` for each container's capabilities and the running
kernel (`seccomp::docker::resolve`) and then compiles the result to BPF.

To see what it turns into:

```sh
cargo xtask seccomp            # summary for the default capabilities
cargo xtask seccomp --disasm   # ... and the BPF program
cargo xtask seccomp --json     # the resolved OCI linux.seccomp
```

### Updating

1. Download `seccomp/default.json` of the new commit:
   `curl -fsSLo profiles/seccomp-default.json https://raw.githubusercontent.com/moby/profiles/<commit>/seccomp/default.json`
2. Update the commit and `sha256sum profiles/seccomp-default.json` above.
3. Run `cargo test -p rustlet-runtime seccomp`. The tests pin down the
   behavior that matters (what the default capabilities may and may not do);
   a failure there means the profile's policy changed, so read the upstream
   diff before adjusting a test.
4. If the profile names syscalls newer than
   `crates/rustlet-runtime/src/seccomp/syscall_64.tbl`, update that table
   too (see `seccomp/syscalls.rs`): names the table doesn't know are skipped,
   so those syscalls get the default action (or ENOSYS, above the highest
   syscall the table does know from the profile).
