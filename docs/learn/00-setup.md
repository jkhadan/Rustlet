# 00 — Setup and safety nets

Rustlets runs code as root that creates namespaces, rewrites mount tables, makes cgroups and, later, changes the
firewall. A bug in that kind of code doesn't just crash a process: it can damage the machine it runs on. So before
any container code, Phase 0 builds the workbench and the safety nets.

By the end of this chapter you will have:

- a Rust toolchain, plus `runc` and `strace` as reference tools to compare against;
- a Cargo workspace where `unsafe` code can only exist in one crate, enforced by the compiler and by CI;
- the safety nets: VM snapshots, a narrow sudo setup, a resource-capped scope for privileged tests, a one-command
  cleanup script and (optionally) a dedicated filesystem for Rustlets' data;
- `cargo xtask check-host`, one read-only command that confirms all of the above.

The design itself is in [docs/architecture.md](../architecture.md); this chapter follows its "Host facts", §3, §4 and
the Phase 0 row of §5.

## 1. The machine, and why it's a VM

| Fact | This machine | Why it matters |
|---|---|---|
| Virtualization | KVM guest (`systemd-detect-virt` prints `kvm`) | The hypervisor can snapshot and roll back the whole VM |
| Distro | Linux Mint 22.3, Ubuntu 24.04 ("noble") base | Packages come from Ubuntu's archive |
| systemd | 255 | The daemon's unit uses `DelegateSubgroup=`, which needs 254 or newer |
| Kernel | 7.0.0-34 running; 6.14 still installed | The design needs nothing newer than 6.8 |
| cgroups | v2 only ("unified"); root `cgroup.subtree_control` is `cpu memory pids` | Our cgroups must live in a subtree systemd delegates to us |
| Disk | `/`, `/home` and `/var/lib` are all one ext4 filesystem, `/dev/sda3` | A runaway write fills everything; bind mounts can't be told apart by device |
| Memory | 7.8 GB RAM + 2 GB swap | Why privileged tests are capped at 4 GB |

**Why a VM.** A container runtime's worst bugs happen *outside* the container. If the runtime mounts something
before it has switched to a new mount namespace, the mount lands on the host. If it detaches "/" while still in the
host's namespace, the host loses its root filesystem. A hypervisor snapshot is taken from outside the guest, so
nothing that root does inside the guest can damage it. Rolling back takes a minute; debugging a half-broken host can
take a day.

**Why 6.8.** The newest kernel feature the design uses is `fsconfig(..., "lowerdir+", ...)` for overlayfs (Phase 3),
added in 6.8. That is also the kernel Ubuntu 24.04 shipped with, so Rustlets should run on a stock 24.04 install. This
VM runs 7.0, well above the minimum. If something behaves strangely, boot the 6.14 entry from GRUB and compare; that is
why it stays installed, and why `cargo xtask itest` prints the kernel version before every run.

**Why cgroups need delegation.** systemd owns the root of the cgroup tree, and only `cpu`, `memory` and `pids` are
enabled there (`io` and `cpuset` are not). Creating our own cgroups directly under `/sys/fs/cgroup` would mean fighting
systemd for the tree. Instead we ask systemd to *delegate* a subtree: during tests, a `systemd-run` scope (§5.3); from
Phase 4, the `rustletd.service` unit ([packaging/rustletd.service](../../packaging/rustletd.service)).

You can check these yourself, read-only:

```sh
systemd-detect-virt                         # kvm
uname -r                                    # 7.0.0-34-generic
cat /sys/fs/cgroup/cgroup.subtree_control   # cpu memory pids
stat -c '%d %n' / /home /var/lib            # "2051" three times: device 8:3, which is /dev/sda3
```

That last line is the reason for one of the guardrails in §5.4, so remember it.

## 2. Toolchains

**Rust.** `rustup` manages the stable toolchain (rustc 1.98.1 at the time of writing) with the `clippy` and `rustfmt`
components. The workspace declares `rust-version = "1.88"` as its minimum; 1.88 is the release that stabilized
let-chains (`if a && let Some(x) = b`), which [xtask/src/itest.rs](../../xtask/src/itest.rs) uses.

rustup puts `cargo` and friends in `~/.cargo/bin` and adds `. "$HOME/.cargo/env"` to `~/.profile` and `~/.bashrc`.
A shell that reads neither (some editor task runners, `ssh host cmd`) won't find cargo; fix that with
`. "$HOME/.cargo/env"` or `export PATH=$HOME/.cargo/bin:$PATH`. Note that sudo's `secure_path` does not include
`~/.cargo/bin`, so `sudo cargo` fails with "command not found". That is fine: you should never run it (§5.2).

**cargo-nextest** runs every test in its own process, where the built-in `cargo test` runs tests as threads of one
process. That matters here. After `fork()` in a multithreaded process, only async-signal-safe operations are allowed
until `exec`, and some namespace calls (`unshare(CLONE_NEWUSER)`, `setns` into a user namespace) fail outright unless
the caller is single-threaded. One process per test means a test that forks or changes namespaces can't trip over its
neighbours.

**C toolchain and desktop libraries.** `build-essential` provides `cc`, which Rust uses as its linker, and which later
dependencies (rusqlite's bundled SQLite, zstd) use to compile C code. `libwebkit2gtk-4.1-dev`, `libxdo-dev`,
`libssl-dev`, `libayatana-appindicator3-dev` and `librsvg2-dev` are the Linux libraries Tauri v2 builds against. Only
the desktop app (Phase 6) needs them; they are installed now so Phase 0 is the only time you install system packages.

**Reference tools.** `runc` 1.3.4 is the reference OCI runtime. Because `rustlet-runc` speaks runc's command line, you
can run the same bundle under both and diff what the container sees, or swap runc in to tell a daemon bug from a runtime
bug. `strace` 6.8 shows every system call a process makes; `strace -f` on both runtimes is the most direct way to see
how they differ.

**Pending: Node LTS and pnpm.** These are not installed yet, and nothing needs them until the desktop app in Phase 6.
Install them as your user, not system-wide: a version manager such as nvm (`nvm install --lts`), then pnpm
(`npm install -g pnpm`, or pnpm's standalone installer). Skip Ubuntu's `nodejs` package; on 24.04 it is Node 18, which
is past end of life.

## 3. The repo layout

```
Rustlet/
├─ Cargo.toml            workspace: members, shared lints, dependency versions
├─ .cargo/config.toml    the `cargo xtask` alias
├─ rustfmt.toml          max_width = 120, use_small_heuristics = "Max"
├─ .github/workflows/ci.yml
├─ crates/
│  ├─ rustlet-sys/       the only crate allowed `unsafe`: syscalls and kernel ABIs (+ examples/hello_ns.rs)
│  ├─ rustlet-runtime/   the OCI runtime library (Phase 1 code is already here)
│  ├─ rustlet-runc/      bin: runc-compatible CLI over rustlet-runtime
│  ├─ rustlet-spec/      API types shared with the GUI            (skeleton)
│  ├─ rustlet-image/     registry, content store, overlay          (skeleton, Phase 3)
│  ├─ rustlet-shim/      bin: one supervisor per container         (skeleton, Phase 4)
│  ├─ rustlet-client/    typed API client                          (skeleton, Phase 4)
│  ├─ rustletd/          bin: the daemon                           (skeleton, Phase 4)
│  ├─ rustlet-cli/       bin: `rustlet`                            (skeleton, Phase 4)
│  ├─ rustlet-net/       bridge, veth, nftables, DNS               (skeleton, Phase 5)
│  ├─ rustlet-build/     Containerfile builder                     (skeleton, Phase 7)
│  └─ rustlet-compose/   compose                                   (skeleton, Phase 7)
├─ tests/                package `rustlet-itests`: privileged integration tests
├─ xtask/                `cargo xtask ...` development tasks
├─ scripts/cleanup.sh    one-command host restore
├─ packaging/            rustletd.service, NetworkManager drop-in, dev/sudoers-rustlet-dev
└─ docs/                 architecture.md, learn/ (this series)
```

A few choices in [Cargo.toml](../../Cargo.toml) are worth knowing:

- **Edition 2024 and resolver 3.** Crates inherit their package metadata (`version`, `edition`, ...) from
  `[workspace.package]`, and dependency versions from `[workspace.dependencies]` (a crate writes
  `libc.workspace = true`), so each version is chosen in exactly one place.
- **`default-members`.** It lists every current member. The desktop app's Rust side will join `members` in Phase 6
  but stay out of `default-members`, so a plain `cargo build` never needs webkit2gtk.
- **`.rustlet-dev/`** (git-ignored) holds the Alpine download and the test bundle that `cargo xtask rootfs` creates.

## 4. The `unsafe` boundary

A container runtime lives on raw system calls, and many of them (`clone3`, the new mount API, `seccomp`, `bpf`) have no
safe wrapper in `std` or `nix`. Calling them means `unsafe` Rust. The project's rule is that all of it
lives in **one crate**, [crates/rustlet-sys](../../crates/rustlet-sys/src/lib.rs), behind safe function signatures.
Everything else, from the runtime to the daemon, can only reach the kernel through those signatures. If there is ever
a memory-safety bug in our code, there is exactly one crate to audit.

The module docs in `rustlet-sys/src/lib.rs` spell out the rules:

1. Every `unsafe` block has a `// SAFETY:` comment saying why it is sound, and each block holds a single unsafe
   operation.
2. File descriptors cross the boundary as `OwnedFd` (closes itself on drop) or `BorrowedFd` (the compiler proves the
   fd stays open for the call). This is Rust's "I/O safety".
3. Flags are typed with `bitflags`, so mount flags can't be passed where mount-attribute flags are expected.
4. Errors are the raw kernel `Errno`; higher layers add context.

A typical block, from the same file:

```rust
// SAFETY: `raw` was just returned by the kernel as a new file descriptor,
// so nothing else owns it; `OwnedFd` becomes its unique owner.
unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as libc::c_int) }
```

**How it's enforced.** Three layers, each catching what the others miss:

- **The workspace lint `unsafe_code = "forbid"`.** Every crate except `rustlet-sys` has `[lints] workspace = true` in
  its Cargo.toml, so it inherits this. `forbid` is stronger than `deny`: a `deny` can be switched off locally with
  `#[allow(unsafe_code)]`, but under `forbid` that `#[allow]` is itself a compile error.
- **`#![forbid(unsafe_code)]` at every crate root.** The Cargo lint only applies if a crate's manifest opts in; forget
  that one line in a new crate and it silently allows `unsafe`. The attribute lives in the source, independent of the
  manifest. CI checks it: the "unsafe stays inside rustlet-sys" step greps every `crates/*/src/lib.rs` and
  `crates/*/src/main.rs` (plus [xtask](../../xtask/src/main.rs) and [tests](../../tests/src/lib.rs)) except
  `rustlet-sys`'s and fails if the attribute is missing. It finds them with `git ls-files`, so it only sees tracked
  files: run locally before the first commit, it checks nothing.
- **Clippy lints inside `rustlet-sys`.** [Its Cargo.toml](../../crates/rustlet-sys/Cargo.toml) has its own lint table
  instead of the workspace one. `clippy::undocumented_unsafe_blocks = "deny"` rejects any `unsafe` block without a
  `// SAFETY:` comment. `clippy::multiple_unsafe_ops_per_block = "deny"` rejects a block with more than one unsafe
  operation, so one vague comment can't cover five calls. `unsafe_op_in_unsafe_fn = "deny"` means the body of an
  `unsafe fn` isn't one big implicit `unsafe` block: each operation inside still needs its own block and comment.

The example `crates/rustlet-sys/examples/hello_ns.rs` sits inside `rustlet-sys` but starts with
`#![forbid(unsafe_code)]`: it shows that the safe API is enough to build a namespace demo. The rule has a design
consequence too: because `rustletd` forbids `unsafe`, it can't use `CommandExt::pre_exec` (an `unsafe` API), so the shim
calls `setsid()` on itself instead (architecture §2.3).

## 5. Guardrails

Each guardrail below exists because of a specific way this project could hurt the host.

### 5.1 Hypervisor snapshots

Take a snapshot **before Phase 1, Phase 2 and Phase 5**, and before any experiment you're unsure of. Those phases are
where the danger changes. Phase 1 is the first time our code creates mount namespaces and calls `pivot_root` and
`umount2` as root. Phase 2 writes cgroup limits, uses `cgroup.kill` and attaches eBPF device filters; pointed at the
wrong cgroup, any of these can kill or cripple your desktop session. Phase 5 changes host networking (`ip_forward`,
nftables, a bridge), which can cut the VM off from the network.

### 5.2 Least privilege: build as you, run as root

**Never `sudo cargo`, never `sudo -E`.** A build as root leaves root-owned files in `target/` (and, with `sudo -E`,
in your `~/.cargo`), and your next normal build fails with "permission denied". Worse, a build runs code you didn't
write: every dependency's `build.rs` and proc macros. As root, that code owns the machine. `sudo -E` keeps your whole
environment, including `HOME`, so a root process writes into your home directory and is steered by variables you may
not know are set.

So the rule is: **compile as your user; run only the finished binaries as root.** `cargo xtask itest` does exactly
that (§6).

**The dev sudoers file.** [packaging/dev/sudoers-rustlet-dev](../../packaging/dev/sudoers-rustlet-dev) is installed as
`/etc/sudoers.d/rustlet-dev` with `sudo install -m 0440 -o root -g root ...` (the command is in the file's header;
`sudo visudo -cf <file>` checks the syntax first, since a broken sudoers file can lock you out of sudo). It lets `james`
run a fixed list of commands as root **without a password**:

| Alias | Allows |
|---|---|
| `RUSTLET_BUILD` | anything in `target/debug/`, `target/debug/deps/` (test binaries), `target/debug/examples/`, `target/release/`; `scripts/cleanup.sh` with or without arguments |
| `RUSTLET_SCOPE` | `/usr/bin/systemd-run` (listed without arguments, which in sudoers means *any* arguments) |
| `RUSTLET_SERVICE` | `systemctl daemon-reload`, `start`/`stop`/`restart`/`status rustletd`, `journalctl -u rustletd ...` |
| `RUSTLET_TOOLS` | `nft`, `ip`, `runc`, `strace`, `losetup` with any arguments; `cat` of files under `/run/rustlet/` and `/var/lib/rustlet/` |

The three `target/debug` lines are separate because a `*` in a sudoers command path never matches a `/`:
`target/debug/*` covers `target/debug/rustlet-runc` but not `target/debug/deps/...`.

**The honest caveat**, stated in the file itself: everything under `target/` is writable by `james`, so "may run
`target/debug/*` as root" means "may run *anything* as root". The same goes for `scripts/cleanup.sh`, and for
`systemd-run`, `strace` and `ip netns exec`, which all run arbitrary commands. And a `*` in *arguments* matches `/`
and `..` too, so `cat /run/rustlet/../../etc/shadow` fits the `cat` rule. In practice this file is passwordless root
for this account: any program running as `james`, including a malicious dependency's build script, can use it. That is
acceptable on a throwaway, snapshotted VM and nowhere else. Remove it with `sudo rm /etc/sudoers.d/rustlet-dev`.

So why bother with a list? It keeps the privileged actions to a known, auditable set; no script ever needs a password
typed into it; and some things are deliberately *not* on it. `mkfs`, `mount` and `truncate` are missing, so
`cargo xtask dev-storage` has to ask for your password: formatting a filesystem should be a conscious act.

**`sudo -n`** (non-interactive) never prompts. If the command is on the NOPASSWD list it runs; if it would need a
password, sudo prints `sudo: a password is required` and exits with status 1. Scripts and automated tools (including
an AI assistant driving the terminal) should use it, so that anything outside the list fails immediately instead of
hanging at a password prompt nobody will answer. `sudo -n -l` lists your rules without prompting.

### 5.3 The limited systemd scope for privileged tests

Privileged tests never run bare. Each test binary runs inside:

```sh
sudo systemd-run --scope -p Delegate=yes -p TasksMax=4096 -p MemoryMax=4G -- <test binary>
```

- `--scope` registers the command as a transient systemd unit with its **own cgroup**, but runs it in the foreground,
  in your terminal, instead of handing it to systemd as a background service.
- `TasksMax=4096` becomes `pids.max` on that cgroup: a fork bomb stops at 4096 tasks instead of exhausting the host's
  process table.
- `MemoryMax=4G` becomes `memory.max`: the scope's RAM is capped at about half the VM's 7.8 GB, and when nothing more
  can be reclaimed the kernel's OOM killer picks a victim *inside the scope*, not somewhere on the host. (The scope can
  still use swap, which is why OOM tests will set the container's swap limit to 0, so the kill comes promptly.)
- `Delegate=yes` tells systemd that the processes inside own everything below this cgroup, so from Phase 2a tests can
  create container cgroups there without systemd interfering (the reason given in §1).

Fork-bomb tests will also assert that `pids.max` exists before they start. The test harness
([tests/src/lib.rs](../../tests/src/lib.rs)) also compares the host's `/proc/self/mountinfo` before and after every
container run and fails if anything changed: nothing a container mounts may ever appear on the host.

### 5.4 `scripts/cleanup.sh` and deleting safely

Every host resource Rustlets can create has a recognizable name: `/var/lib/rustlet`, `/run/rustlet`,
`system.slice/rustletd.service/...` and `rustlet-*` cgroups, the nft table `inet rustlet`, links `rustlet0` and `rlv*`.
That makes a complete undo possible. [scripts/cleanup.sh](../../scripts/cleanup.sh) does it in seven steps, in an order
where each step removes what the next one would trip over:

1. **Stop `rustletd`**, so it can't restart containers (restart policies) or recreate anything while we clean.
2. **Kill the shims** (`SIGKILL`), for the same reason one level down.
3. **Kill container cgroups**: write `1` to each `cgroup.kill`, which kills every process in the subtree at once, even
   ones forking right now; then wait for `populated 0` in `cgroup.events` (the kill is asynchronous), then `rmdir`
   deepest-first, because a cgroup with children or live processes can't be removed.
4. **Unmount everything under `/run/rustlet` and `/var/lib/rustlet`**, deepest-first, with `umount -l` (a lazy detach
   that can't fail just because something is busy). The dev-storage mount at `/var/lib/rustlet` itself stays unless you
   purge.
5. **Delete network state**: netns pin files (their bind mounts went in step 4), the `rustlet0` bridge and `rlv*`
   veths.
6. **`nft delete table inet rustlet`.** Because all our rules live in one dedicated table, this removes them without
   touching anyone else's firewall rules.
7. **Restore sysctls** such as `ip_forward` from `/run/rustlet/host-sysctl.orig` (the daemon will record the originals
   there in Phase 5; the file is read at the start, because `/run/rustlet` is deleted afterwards).

It then removes `/run/rustlet`, runs a leftover check (mounts, links, nft table, container cgroups), prints
`host is clean` and exits 0, or lists what remains and exits 1. It deliberately doesn't use `set -e`: a cleanup script
should push on past one failed step and report at the end. Run as your user without `--dry-run`, it re-executes itself
with `sudo` (allowed without a password by the sudoers file).

- `--dry-run` prints `would: ...` instead of making each change. As your user it can't see everything (`nft` needs
  root), and it says so in the leftover check; use `sudo scripts/cleanup.sh --dry-run` for a complete answer.
- `--purge` also unmounts `/var/lib/rustlet`, detaches the dev-storage loop device and deletes its image, deletes
  `/var/lib/rustlet` (images, volumes, state) and removes the NetworkManager drop-in.

**Why the purge checks mountinfo before `rm -rf`.** The classic container-cleanup disaster: a volume bind-mounted from
`/home/you` is still mounted inside the container directory when it gets deleted, and `rm -rf` recurses into your home.
`rm --one-file-system` doesn't help, because it compares `st_dev`, and a bind mount has the `st_dev` of the filesystem
it came from. On this host `/home` and `/var/lib` are both `/dev/sda3` (the `2051` from §1), so they look identical.
The script therefore refuses to delete `/var/lib/rustlet` while `/proc/self/mountinfo` lists anything under it.

The Rust side has the same rule, stricter: `safe_remove_tree` in
[crates/rustlet-sys/src/tree.rs](../../crates/rustlet-sys/src/tree.rs), which the daemon will use to remove container
directories. It refuses if mountinfo lists any mount under the path; walks with
`openat2(RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, so it never follows a symlink or crosses a mount;
compares each entry's `statx` **mount ID**, which is unique per mount even for two bind mounts of the same filesystem;
and deletes with `unlinkat` relative to directory fds it already holds, so a path can't be swapped under it.

### 5.5 Dedicated dev storage

`cargo xtask dev-storage` ([xtask/src/devstorage.rs](../../xtask/src/devstorage.rs)) gives `/var/lib/rustlet` its own
filesystem: a sparse ext4 image at `/var/lib/rustlet-dev-storage.img`, loop-mounted on `/var/lib/rustlet`. It runs:

```sh
sudo truncate -s 25G /var/lib/rustlet-dev-storage.img     # sparse: allocates nothing yet
sudo chmod 600 /var/lib/rustlet-dev-storage.img           # the raw image holds every container's files
sudo mkfs.ext4 -q -L rustlet-dev -m 0 /var/lib/rustlet-dev-storage.img   # no root-reserved blocks on a data disk
sudo mkdir -p /var/lib/rustlet
sudo mount -o loop,noatime /var/lib/rustlet-dev-storage.img /var/lib/rustlet
```

Why: a runaway image pull or container write can fill 25 GB and no more, instead of filling `/` and taking journald,
apt and the desktop down with it. Only the blocks actually written cost disk. A bind mount of something from `/home`
inside it now shows a different device, so even `st_dev` checks catch it (a second layer, not a replacement for
mount IDs). And a full wipe is one command, `scripts/cleanup.sh --purge`.

`--size` changes the size (default `25G`); `--dry-run` prints the commands without running them. The task does nothing
if `/var/lib/rustlet` is already a mount point, and refuses if the image exists unmounted or if `/var/lib/rustlet`
already has contents (mounting over them would hide them, not remove them). It doesn't edit `/etc/fstab`; it prints
the line to add, with `nofail` so a missing image can't stop the VM from booting. This is **optional until Phase 3**:
nothing is stored in `/var/lib/rustlet` before image pulls, since test bundles live in `.rustlet-dev/` in the repo.

## 6. xtask

`cargo xtask` is a common Rust pattern: the development tasks are an ordinary binary crate
([xtask/](../../xtask/src/main.rs)) and [.cargo/config.toml](../../.cargo/config.toml) defines the alias
`xtask = "run --quiet --package xtask --"`. No Makefile, no install step, and the tasks can use workspace crates:
`rootfs` writes `config.json` with `rustlet_runtime::spec::default_spec()`, the same function behind
`rustlet-runc spec`, so the generated bundle matches what this build of the runtime expects.

| Task | What it does |
|---|---|
| `rootfs [--force]` | Downloads the Alpine 3.24.2 minirootfs, checks it against a pinned sha256, extracts it **as you** (setuid/setgid bits stripped) into `.rustlet-dev/bundles/alpine/rootfs`, and writes `config.json` next to it. Cached; an edited `config.json` is kept; `--force` re-extracts and regenerates. |
| `itest [ARGS]...` | Builds `rustlet-runc` and the `rustlet-itests` test binaries as you, then runs each binary with `--include-ignored` via `sudo systemd-run --scope ...` (§5.3). `ARGS` go to the test binaries, e.g. a name filter. |
| `dev-storage [--size S] [--dry-run]` | §5.5. |
| `check-host` | Read-only report of the host facts the design depends on. |
| `image-run`, `gen-ts` | Stubs: they exit with an error naming Phase 3 (images) and Phase 6 (desktop app). |

Two details of `itest` show the guardrails at work. Test binaries have hashed names in `target/debug/deps/`, so it reads
their paths from cargo's JSON output (`cargo test --no-run --message-format=json-render-diagnostics`); that directory
is why the sudoers file allows `target/debug/deps/*`. And sudo resets the environment (`env_reset`), so the command
ends in `/usr/bin/env RUST_BACKTRACE=1 <binary>` to put back the one variable worth having without extra sudo rights.
Each scope is named `rustlet-itest-<pid>-<n>`, which `cleanup.sh`'s search for `rustlet-*` cgroups also finds.

The privileged tests in [tests/tests/runtime.rs](../../tests/tests/runtime.rs) are marked
``#[ignore = "needs root: run with `cargo xtask itest`"]``, so an ordinary test run (yours, or CI's unprivileged job)
skips them, and only `itest` includes them.

`check-host` on this machine, today:

```text
$ cargo xtask check-host
ok   kernel >= 6.8              7.0.0-34-generic
ok   cgroup v2 (unified)        cpuset cpu io memory hugetlb pids rdma misc dmem
ok   root subtree_control       cpu memory pids
ok   systemd >= 254             255
ok   tool: runc                 /usr/sbin/runc
ok   tool: strace               /usr/bin/strace
ok   tool: nft                  /usr/sbin/nft
ok   tool: ip                   /usr/sbin/ip
ok   tool: curl                 /usr/bin/curl
ok   ip_forward                 0
ok   dev sudoers installed      /etc/sudoers.d/rustlet-dev
ok   alpine test rootfs         present
info dev storage                not set up (optional: cargo xtask dev-storage)
```

The second line lists every controller available on the v2 hierarchy; the third lists what the root cgroup hands
down to its children, which is the list that matters (§1). `ip_forward` is 0: the host doesn't route packets yet,
and nothing in Rustlets changes that before Phase 5. Any `FAIL` line makes the command exit non-zero; `info` never does.

## 7. Everyday commands

```sh
cargo build                                        # the default members, as you
cargo nextest run --workspace                      # unprivileged tests; the privileged ones show as skipped
cargo clippy --workspace --all-targets -- -D warnings   # as CI runs it: any warning fails
cargo fmt --all                                    # CI runs `cargo fmt --all --check`
cargo xtask rootfs                                 # once, before itest or the demo
cargo xtask itest                                  # privileged tests: build as you, run as root in the scope
cargo xtask check-host                             # anything drifted?
sudo scripts/cleanup.sh --dry-run                  # what would a cleanup do?
```

`cargo nextest run --workspace` should end with every test passed and the privileged ones counted as skipped.
[CI](../../.github/workflows/ci.yml) mirrors this: a `check` job runs fmt, clippy, nextest and the `unsafe` grep, and an
`itest` job installs runc and strace, then runs `cargo xtask rootfs` and `cargo xtask itest` (GitHub's Ubuntu 24.04
runners have passwordless sudo).

## Check yourself

1. `/home` and `/var/lib` share `/dev/sda3`. Why does that make `rm -rf --one-file-system` unsafe for deleting a
   container directory, and what does `safe_remove_tree` compare instead?
2. The dev sudoers file only lists a handful of commands. Why is it still effectively root for `james`, and what does
   `sudo -n` add for scripts?
3. `cargo xtask itest` compiles as you and only uses sudo for the finished test binaries. Name two things that would
   go wrong if the whole build ran as root.
4. Which two properties of the `systemd-run` scope turn a fork bomb and a memory leak into ordinary test failures, and
   which cgroup files do they become?
5. A new crate is added and its Cargo.toml forgets `[lints] workspace = true`. What still stops it from containing
   `unsafe`, and where is that checked?
