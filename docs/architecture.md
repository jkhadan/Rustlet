# Rustlets — Architecture & Roadmap

## Context

Rustlets is a greenfield Docker alternative written in Rust. It covers:
- full namespace control (fully isolated, share with the host, share with another container)
- cgroups v2 resource limits and stats
- dropping capabilities, seccomp syscall filtering, filesystem isolation
- pulling and running OCI-compliant images
- a Docker-Desktop-style Tauri GUI

It has two goals of equal weight: **an impressive, working product**, and **a way to learn** Linux namespaces, Unix internals, and Rust.

**Decisions made:**

| Topic | Decision |
|---|---|
| Privilege model | Rootful daemon first. Keep the seams for rootless later: driver traits for cgroups, networking, ID mapping, paths. |
| Depth | Hand-write the runtime core (namespaces, mounts, cgroups, caps, seccomp BPF, eBPF device filter, netlink) over `libc`/`nix`. Use crates only for plumbing: HTTP, JSON, tar, registry, OCI spec types. |
| GUI | Tauri v2 + React + TypeScript |
| Scope | Pull and run images, **plus** image building, compose, named volumes and networks with DNS, live stats |
| Who writes code | Claude writes the code and explains it in detail: module docs, `// SAFETY:` notes, `docs/learn/` chapters, and a walkthrough after each phase. |
| Dev environment | Directly on this machine, with the guardrails in §4 |

**Host facts** (checked read-only; the design depends on them):
- **This machine is a KVM guest** (`ens18`, `systemd-detect-virt` = kvm), so hypervisor snapshots are the safety net.
- Linux Mint 22.3 (Ubuntu 24.04 base), systemd 255. Kernel 7.0 is running (6.14 kept in GRUB as a fallback); every feature used needs ≤ 6.8.
- cgroup2 unified, mounted with `nsdelegate`. systemd owns the tree and enables controllers at the root as units need them (at design time only `cpu memory pids`; later also `cpuset io hugetlb …`), so container cgroups must live in a systemd-delegated subtree (§2.2.3).
- `/`, `/home` and `/var/lib` are all one ext4 filesystem (`/dev/sda3`, 45 GB free). RAM is 7.8 GB, plus a 2 GB swapfile.
- `ip_forward=0`. ufw is disabled but configured with `DEFAULT_FORWARD_POLICY=DROP`. NetworkManager is active. The LAN is `192.168.50.0/24`; nothing overlaps `10.89.0.0/16`.
- subuid/subgid: `james:100000:65536`. Rustlets will get its **own** range and won't reuse this one.
- At design time no Rust or Node toolchain was installed. Phase 0 installed Rust (rustup stable, nextest), runc, strace and the Tauri libraries; Node + pnpm are still pending (needed from Phase 6).

---

## 1. System architecture

```
 ┌──────────────┐        ┌──────────────────────────────┐
 │ rustlet (CLI)│        │ Rustlets Desktop (Tauri v2)  │
 │ clap         │        │ React/TS ⇄ Rust cmds/Channels│
 └──────┬───────┘        └──────────────┬───────────────┘
        │   rustlet-client: HTTP/1.1 + JSON, NDJSON streams, WebSocket
        └─────────────┬─────────────────┘   over /run/rustlet/rustlet.sock
                      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ rustletd (root, tokio + axum; systemd unit, Delegate=yes)   │
 │ ContainerMgr · ImageStore · Snapshotter · NetworkMgr(IPAM,  │
 │ nft, DNS) · VolumeMgr · Builder · Stats · EventBus · SQLite │
 └──────┬──────────────────────────────────────────────────────┘
        │ spawn (shim setsid()s itself), talks over shim.sock
        ▼
 ┌──────────────────────┐  one per container; child subreaper; owns PTY/pipes,
 │ rustlet-shim         │  writes logs, serves attach/exec/resize, reports exit
 └──────┬───────────────┘
        │ exec: rustlet-runc create|start|kill|delete|exec|state   (runc-compatible CLI)
        ▼
 ┌──────────────────────┐  single-threaded OCI runtime; re-execs from sealed memfd;
 │ rustlet-runc         │  input = OCI bundle (config.json + rootfs)
 └──────┬───────────────┘
        │ clone3(CLONE_NEW* | CLONE_INTO_CGROUP | CLONE_PIDFD)
        ▼
   container init → mounts → pivot_root → drop privileges → seccomp → execve(user cmd)
```

**Key choices, and why:**
1. **The low-level runtime is a standalone OCI runtime (runc-compatible CLI).** The daemon translates "image config + user flags" into a standard OCI `config.json`, and the runtime executes it. Because the interface is standard:
   - you can swap in `runc` to tell whether a bug is in the daemon or the runtime
   - you can run differential tests against runc
   - you can run youki's `contest` conformance suite

   Docker uses the same split (dockerd → containerd → runc).
2. **One shim per container.** Containers survive a daemon restart or crash. The shim uses `PR_SET_CHILD_SUBREAPER`, so container init is re-parented to it when `rustlet-runc` exits.
3. **The runtime is single-threaded; the daemon never forks container processes itself.** Only async-signal-safe work is allowed between `fork` and `exec` in a multithreaded (tokio) process, and `setns(CLONE_NEWUSER)` requires a single-threaded caller. The runtime asserts `Threads: 1` before any `setns` or `unshare`.
4. **Network namespaces are created and pinned by the daemon.** The daemon makes `/run/rustlet/netns/<id>` (the same approach as `ip netns add`) and configures it before start. The OCI spec just says "join this path". The runtime needs no networking code, and `--net=container:X` and compose-style shared namespaces come almost for free.

---

## 2. Components

### 2.1 `rustlet-sys` — the safety boundary ("safe function calls")
- **The only crate that allows `unsafe`.** Every other crate has `#![forbid(unsafe_code)]`.
- Each `unsafe` block carries a `// SAFETY:` justification. Public APIs take and return `OwnedFd`/`BorrowedFd` (I/O safety), typed `bitflags`, and `Result<T, Errno>`.
- Hand-written wrappers:
  - process: `clone3` (with `CLONE_INTO_CGROUP`/`CLONE_PIDFD`), `pidfd_open`/`pidfd_send_signal`/`waitid(P_PIDFD|P_ALL)`, `setns` (including pidfd + multiple flags)
  - mounts: the new mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`/`mount_setattr`), `pivot_root`
  - files and fds: `openat2` (`RESOLVE_IN_ROOT`/`BENEATH`/`NO_XDEV`/`NO_MAGICLINKS`), `statx` (mount ID), `close_range`, `memfd_create` + seals
  - privileges: `capget`/`capset` (v3), prctl helpers
  - `seccomp()`, `bpf()`
  - `SCM_RIGHTS` fd passing
  - a minimal rtnetlink encoder/decoder
- Uses `nix` where it already has a good wrapper (fork, basic mount, unshare, termios, signals).

### 2.2 `rustlet-runtime` (library) + `rustlet-runc` (binary) — the OCI runtime
Commands follow the OCI runtime spec: `create`, `start`, `state`, `kill`, `delete`, plus `exec` and `run`. State lives in `/run/rustlet/runtime/<id>/state.json`. It records the pid and the start time from `/proc/<pid>/stat`, which guards against PID reuse.

**`create` sequence:**
0. **Preflight.**
   - Re-exec from a sealed `memfd` copy of the runtime binary (`F_SEAL_SEAL|SHRINK|GROW|WRITE`) to mitigate CVE-2019-5736. `PR_SET_DUMPABLE=0` alone doesn't stop this attack.
   - Set `PR_SET_DUMPABLE=0` in the parent before any `setns`/`clone3`; children inherit it.
   - Assert the process is single-threaded.
1. **Parse and validate `config.json`** (types from `oci-spec`). Reject:
   - joining a **mount** namespace by path
   - `root.path` resolving to `/`
   - sysctls that aren't namespaced (`kernel.core_pattern`, `vm.*`, …)
   - user mount targets under `/proc` or `/sys`
   - joining a **user** namespace by path (§2.2.1)
   - with a new user namespace (`userns.rs`, `sysctl.rs`): maps the kernel would refuse, or that map host uid or gid 0; uid/gid 0, the process's ids or a filesystem's `uid=`/`gid=` left unmapped; no new PID namespace; mqueue, cgroup2 or sysctls in a namespace the user namespace doesn't own; `kernel.domainname`
   - device rules or `linux.devices` without `linux.cgroupsPath`; `CAP_MKNOD` in any capability set without either a device filter or a new user namespace
   - device nodes outside `/dev`, unclean or conflicting paths, invalid types or numbers, or a default device path with different type/numbers (`dev.rs`)
2. **Cgroup.** Create the cgroup at `linux.cgroupsPath`, which the daemon places inside its delegated subtree. Write the limits and open the cgroup dirfd for `CLONE_INTO_CGROUP`. Before `clone3`, attach the eBPF device filter through that fd, even when the spec has no device rules. Save its program id in `state.rustlet.device_filter`. The attachment belongs to the cgroup, not the runtime process; deleting the cgroup releases it, including after a failed `create`.
3. **Sync channels.** Create a `socketpair(SOCK_SEQPACKET)` for sync messages. Create `exec.fifo` and open it `O_PATH`; the child inherits the fd because the path is unreachable after `pivot_root`.
4. **Namespaces, in this order:**
   0. **Open the host side of every mount** (`rootfs::HostTrees`) while the parent is still only in the host's namespaces. The rootfs becomes a detached recursive copy (`open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)`, with `nodev` on every mount of it), and each bind source a detached copy of its own. Init inherits the fds and only attaches them. There are three reasons. In a user namespace, init is host uid 1000000 and may not even be able to reach the bundle (a `0750` home directory). Only a detached mount can be idmapped. And each host path is resolved exactly once, by the privileged side, before any container process exists. The parent also reads its own and host init's mount-namespace ids here, for step 5.1.
   1. `setns` into every namespace given by path (a user namespace given by path is refused, §2.2.1). This happens in the parent; for pid, it sets the namespace that children are born into.
   2. `clone3` with the new namespaces **except cgroup**, plus `CLONE_INTO_CGROUP | CLONE_PIDFD`. When `CLONE_NEWUSER` is combined with other `CLONE_NEW*` flags, the kernel creates the user namespace first.
   3. **The parent's part of init's setup**, done for every container while init waits for a `Proceed` message:
      - With a new user namespace, write `uid_map`/`gid_map` through the `IdMapper` trait (§2.10), leaving `setgroups` at `allow`. Then idmap the bind trees that ask for it (`idmap`/`ridmap`, `mount_setattr(MOUNT_ATTR_IDMAP)` with init's user namespace).
      - Send `Proceed`. If init has a user namespace, the first thing it does is `become_root`: `setgroups([])`, `setresgid(0)`, `setresuid(0)`.
      - Later, when init's setup as root is done (step 5.8), init sends `SetLimits`. The parent sets init's rlimits (`prlimit`) and `oom_score_adj`, then sends `Proceed` again. In a user namespace, init could not raise a hard limit or lower its OOM score itself, because both need `CAP_SYS_RESOURCE` in the initial user namespace. Not earlier, so that init's own setup (an fd per mount, …) doesn't run under the container's limits; runc sets them at the same point (`procReady`). Not later, because `RLIMIT_NPROC` is checked when the uid changes.
   4. The child closes the cgroup dirfd, then calls `unshare(CLONE_NEWCGROUP)`, rooting the namespace at the cgroup it was placed in. (The original reasoning was that passing the flag to `clone3` would root it at the *parent's* cgroup, because namespaces are copied before placement. On kernel 7.0 a combined `clone3` gets it right too, as measured in chapter 04. Unsharing after placement is correct on every kernel.) **Test:** `/proc/self/cgroup` reads `0::/`.
5. **Container init:**
   1. **Hard safety check (release builds too):** `/proc/self/ns/mnt` must differ from both the parent's mount namespace and host init's (`/proc/1/ns/mnt`), compared as dev + inode, or init aborts. The parent reads both in step 4.0 and passes them to init, because in a user namespace init may not look at PID 1's namespaces.
   2. `mount("/", MS_REC|MS_PRIVATE)` **first**. Then parse mountinfo and verify nothing is still shared.
   3. **Mounts are fd-based:** attach the parent's rootfs tree (step 4.0) on top of `/` with `move_mount`. That makes it the mount point `pivot_root` needs, without init ever looking up the rootfs's host path. For every other mount (a new filesystem from `fsopen`/`fsmount`, or the parent's tree for a bind mount), resolve the target with `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)` and attach with `move_mount(…, MOVE_MOUNT_T_EMPTY_PATH)`. The path is never resolved a second time, which closes the race class behind CVE-2019-19921, CVE-2021-30465, and runc's 2025 CVEs.
      - `/proc`: a new instance via `fsopen("proc")`.
      - `/sys`: sysfs read-only. Under a user namespace with a host-owned netns (only the netns's owner may mount sysfs), use a read-only rbind of the host `/sys` instead. Init makes the rbind itself, so the kernel keeps its submounts locked.
      - `/sys/fs/cgroup`: cgroup2 **read-only** unless privileged. With `nsdelegate` (as on this host), the kernel already refuses writes to the namespace root's own limit files (`EPERM`). The read-only mount is a second barrier, and it covers hosts mounted without `nsdelegate`, where container root could raise its own `memory.max` or `pids.max`.
      - `/dev`: a tmpfs holding null, zero, full, random, urandom and tty, plus validated `linux.devices` entries (`dev.rs`). It is populated after every other mount, through the fd of that tmpfs mount, and only while the path `/dev` still leads to it; a symlinked `/dev` is refused. Rootful nodes are made with `mknodat` → `fchownat` → `fchmodat` (default mode `0666`, uid/gid 0; chmod last restores requested setid bits). In a user namespace, character/block nodes are bind-mounted from the same host `/dev` path after type and device-number checks; their mode/owner come from the host. FIFOs are created inside, with mapped owners. Defaults and filter rules share one table.
      - `/dev/pts`: devpts `newinstance`, `ptmxmode=0666`, `mode=0620`, `gid=5`. Under a user namespace, the `gid=` (or any filesystem's `uid=`/`gid=`) must be mapped, or `create` refuses.
      - Symlinks: `/dev/ptmx → pts/ptmx`, `/dev/fd`, `/dev/std{in,out,err}`.
      - `/dev/shm`: its own tmpfs, or a bind of container X's shm for `--ipc=container:X`.
      - `/dev/mqueue` (under a user namespace, only with a new IPC namespace), user volumes, and the generated `/etc/{hosts,hostname,resolv.conf}`.
   4. **Sysctls:** written through a private proc handle (checked with `fstatfs` = `PROC_SUPER_MAGIC`), *before* `/proc/sys` becomes read-only.
   5. **Switch root:**
      - `pivot_root(".", ".")`, then `umount2(".", MNT_DETACH)`; the `pivot_root(2)` man-page trick needs no put_old directory.
      - (`chdir(process.cwd)` comes later, after the identity switch in step 10, so it runs as the container user; then the working directory is verified to be inside the new root, CVE-2024-21626.)
   6. **TTY** (when `terminal: true`):
      - open `/dev/ptmx`
      - bind the slave onto `/dev/console`
      - `setsid` + `TIOCSCTTY`
      - `dup2` the slave onto stdio
      - send the master to the shim over `--console-socket` with `SCM_RIGHTS` (the OCI console-socket protocol)
      - Without a terminal, a foreground process (`run`, `exec`) **in a user namespace** gets three pipes of its own instead of `rustlet-runc`'s stdio, chowned to its mapped user, and the parent relays them (`stdio.rs`, as runc's `setupProcessPipes`). Inherited host pipes belong to host root, which the namespace doesn't map, so reopening `/dev/stdout` or `/dev/stderr` (nginx's `error.log`) failed with `EACCES`.
   7. **Masked and read-only paths:**
      - Masked paths (`/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/sys/firmware`, …) get a bind of `/dev/null`, after `fstat` confirms it is char device 1:3; masked directories get a read-only tmpfs.
      - Read-only paths: `/proc/sys`, `/proc/sysrq-trigger`, `/proc/irq`, `/proc/bus`.
      - Optionally, remount the rootfs read-only.
   8. **Process setup:** `sethostname` (and `setdomainname`). Then init sends `SetLimits` and waits while the parent sets its rlimits and `oom_score_adj` (step 4.3). Then `close_range(3 + preserved, ~0, CLOSE_RANGE_CLOEXEC)`, before any seccomp filter is loaded (a profile may not allow `close_range`); the runtime's own fds are all close-on-exec from birth.
   9. If `noNewPrivileges` is false, load seccomp **now**, while `CAP_SYS_ADMIN` is still held.
   10. **Switch identity**, in this order:
       1. drop the bounding set
       2. set `PR_SET_KEEPCAPS`
       3. `setgroups` / `setresgid` / `setresuid`
       4. `capset` effective/permitted/inheritable
       5. raise ambient capabilities
   11. `chdir(process.cwd)` and the cwd check, the `$PATH` lookup, and `PR_SET_PDEATHSIG` for a foreground `run` (after the credential change, which clears it).
   12. Tell the parent "created". Reopen `/proc/self/fd/N` (the exec.fifo) `O_WRONLY`; this blocks until `start` opens the read end.
   13. If `noNewPrivileges` is true: `PR_SET_NO_NEW_PRIVS`, then load seccomp **last**, so only `execve` still needs to be allowed. (As built, NNP is set here, after the gate, rather than before it; the effect is the same.)
   14. `execve`, with `args` resolved through the container's `PATH`.
6. **`exec`** (as built in Phase 2b):
   1. Lock the container; it must be `created` or `running` (`paused` only with `--ignore-paused`). The process is built from the copy of `config.json` kept in the state directory at `create`, plus the CLI's overrides. With a user namespace, the process's ids must be mapped in it. `CAP_MKNOD` from `--cap` or a process JSON needs the saved device-filter id or a new user namespace; an old state with no id does not imply a filter exists.
   2. Open the container's cgroup dirfd (or, without `cgroupsPath`, the cgroup init was born in), and a pidfd for init.
   3. Compare init's namespace inodes with the caller's. The **parent** joins only the PID namespace with `setns(pidfd, …)`. That only affects children, so `rustlet-runc` itself never enters the container's filesystem. (A time namespace switches the caller's own clocks too, so the child joins that one.) Never pass `CLONE_NEWUSER` for the caller's own user namespace; that returns EINVAL.
   4. `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)`: the child is born in the PID namespace and the cgroup. The lock is released as soon as the child is placed.
   5. In the child, still on the host's filesystem: rlimits, and `oom_score_adj` through a private procfs. Then `setns(pidfd, USER|MNT|UTS|IPC|NET|CGROUP|TIME)` (the ones init doesn't share) in one call; the kernel enters the user namespace first. With a user namespace, the child then calls `become_root`, as init did. Only after that does it join the session keyring by name, because keyring names are per user namespace and the container's keyring belongs to container root. From the `setns` on, no container path is trusted and `/proc` isn't used.
   6. The same identity, caps, NNP and seccomp setup as init, then `execve`. The child stays non-dumpable until then (CVE-2016-9962).

#### 2.2.1 Namespace modes (translated to OCI `namespaces` by the daemon)

| NS | Default | `host` | `container:<id>` | Notes |
|---|---|---|---|---|
| mnt | new | — | — | always new; joining by path is rejected |
| pid | new, init = PID 1 | `--pid=host` | `--pid=container:X` | join = setns in the parent before clone |
| net | new (pinned by daemon) | `--net=host` | `--net=container:X` | `none` = new netns with only `lo` |
| ipc | new | `--ipc=host` | `--ipc=container:X` | `/dev/shm` is separate; bind X's shm for sharing |
| uts | new | `--uts=host` | — | hostname is set only when new |
| cgroup | new (unshared after placement) | `--cgroupns=host` | — | container sees its own cgroup as `/` |
| user | off (rootful default) | — | — | `--userns=remap` uses a dedicated `rustlet` subordinate range (e.g. 1000000:65536) and needs a new pid ns; joining by path is refused (the parent would have to `setns` into it before `clone3`, losing its host privileges for the rest of `create`) |
| time | off | — | — | stretch: `--timens` |

#### 2.2.2 Security defaults
- **Capabilities:** use Podman's safer default set (CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT). Docker's set also includes MKNOD, NET_RAW and AUDIT_WRITE. Support `--cap-add`/`--cap-drop` (including `ALL`).
- **Per-netns sysctls:** the daemon writes `ip_unprivileged_port_start=0` and `ping_group_range=0 2147483647` into every netns it pins, as Docker does. `ping` then works without NET_RAW, and ports below 1024 work under a user namespace.
- **Devices:**
  - The rootfs is mounted `nodev`; layer unpack skips device nodes.
  - Every container cgroup gets a hand-assembled **eBPF cgroup device filter** (`BPF_PROG_TYPE_CGROUP_DEVICE`), before init exists. `BPF_PROG_ATTACH` + `BPF_F_ALLOW_MULTI` makes the attachment live with the cgroup; a transient `BPF_LINK_CREATE` link would disappear when `rustlet-runc` exits.
  - **Default deny; last matching rule wins per access bit.** The allowed mask starts at zero; an allow ORs bits in, a deny clears them, and every requested bit must remain allowed. Thus denying `w` also denies `rw`. Rule order: spec `linux.resources.devices` → defaults → an implicit `m` allow for each rootful character/block spec node. Defaults come last relative to spec rules, so a spec deny cannot remove them. A node entry permits its creation, not its use: `r`/`w` still need a rule.
  - **Defaults, all `rwm`:** character devices `1:3`, `1:5`, `1:7`, `1:8`, `1:9`, `5:0`, `5:2`, `136:*` (null, zero, full, random, urandom, tty, ptmx, pty slaves). No blanket character/block `m` permission, no tun `10:200`, no console `5:1`: `/dev/console` is a bind of a pty slave.
  - Device rules and nodes need `linux.cgroupsPath`. `CAP_MKNOD` needs a filter **or a new user namespace** (device mknod is denied there independently). `spec::add_host_device` translates a host node into a node entry and an access rule; the demo exposes `--device PATH[:rwm]`.
  - **Boundary:** the filter depends on confinement to the cgroup. The ordinary setup uses a cgroup namespace, `nsdelegate` and a read-only cgroupfs. Host-root capabilities sufficient to change BPF attachments (notably `CAP_SYS_ADMIN`/`CAP_BPF`) defeat this boundary; a privileged-shaped spec is not a promise of isolation from host root.
  - **Daemon unit:** never set `DevicePolicy=` or `DeviceAllow=` on `rustletd.service`. Ancestor `ALLOW_MULTI` programs also run, and every applicable program must allow; a container's allow-all cannot override systemd's ancestor deny.
- **Seccomp:** hand-written compiler from OCI `linux.seccomp` to classic BPF (§2.2.4). Ships Docker's default profile (Apache-2.0, vendored in `profiles/`). The daemon resolves the profile's capability-conditional `includes`/`excludes` rules. **Known difference from Docker:** Docker allows i386/x32 binaries; Rustlets initially kills any non-x86_64 arch (i386 support is a stretch goal).
- **Privileged-shaped specs (Phase 2c):** `spec::privileged` and `cargo xtask demo --privileged`: all supported caps in bounding/effective/permitted (not inheritable/ambient), no seccomp or masked/read-only paths, host devices, allow-all filter, `/sys` and cgroupfs read-write. NNP is left to the caller (the demo retains it). Host enumeration skips symlinks and submounts, including `/dev/pts`; this is development tooling, not yet a daemon/CLI feature.

#### 2.2.3 cgroups v2
- **Location:** under the daemon's **systemd-delegated subtree**, not directly under `/sys/fs/cgroup`. systemd owns the root, and `io`/`cpuset` aren't enabled there on this host.
  - `/sys/fs/cgroup/system.slice/rustletd.service/daemon`: the daemon (via `DelegateSubgroup=daemon`)
  - `/sys/fs/cgroup/system.slice/rustletd.service/containers/<id>`: container leaves
  - Before the daemon exists (Phases 1–3), tests run in `systemd-run --scope -p Delegate=yes`. The harness moves itself into a leaf and nests container cgroups beside it.
  - The runtime honors whatever `linux.cgroupsPath` it is given.
- **OCI → v2 mapping** (the OCI spec is v1-shaped, which is itself a lesson):

  | OCI setting | v2 file |
  |---|---|
  | `memory.limit` | `memory.max` |
  | `memory.swap` (v1 counts memory+swap) | `memory.swap.max`; defaults to the memory limit (Docker behavior), 0 in tests |
  | `cpu.quota` / `cpu.period` | `cpu.max` |
  | `cpu.shares` | `cpu.weight`, via runc's newer log-scale formula (1024 → 100); the old linear one gives 39 |
  | `pids.limit` | `pids.max` |
  | `blockIO` | `io.max` / `io.weight` |
  | `cpuset` | `cpuset.cpus` / `cpuset.mems` |
  | `unified` | raw v2 keys, passed through |

- **Lifecycle:**
  - pause/unpause: `cgroup.freeze`
  - kill everything atomically: `cgroup.kill`, then wait for `populated 0` in `cgroup.events` before `rmdir`
  - OOM detection: `memory.events` (`oom_kill`)
- **Stats:** `cpu.stat`, `memory.current`/`memory.stat`, `io.stat`, `pids.current`, PSI `*.pressure`, and network counters from `/proc/<pid>/net/dev`.

#### 2.2.4 Seccomp BPF compiler (hand-written)
- **Syscall table:** vendor the kernel's `syscall_64.tbl`. A `build.rs` keeps only `common` and `64` rows (x32 rows 512–547 would map wrongly) and generates the name ↔ number table.
- **Program shape:**
  1. Check `arch`; anything else → `KILL_PROCESS`.
  2. Reject x32 (`nr & __X32_SYSCALL_BIT`).
  3. Load `nr` and dispatch to per-syscall rule blocks.
  4. Each 64-bit argument comparison is split into hi/lo 32-bit halves.
  5. **An ENOSYS stub for syscall numbers above the highest the profile knows**, as runc does. Returning EPERM for unknown newer syscalls breaks glibc fallbacks such as clone3 → clone.
  6. Fall through to `defaultAction`.
- **Rule fields supported:** `errnoRet`, `minKernel`, `includes.arches`/`caps`, and the args ops (`EQ`, `NE`, `LT`, `LE`, `GT`, `GE`, `MASKED_EQ`).
- **Gotchas:** `jt`/`jf` offsets are u8, so emit long `BPF_JA` jumps; the program is capped at 4096 instructions.
- Include a small disassembler for tests and for the learn chapter.

### 2.3 `rustlet-shim`
- The shim `setsid()`s and sets `PR_SET_CHILD_SUBREAPER` itself. The daemon can't use `pre_exec`, which is unsafe, and the daemon forbids unsafe code.
- It runs `rustlet-runc create`, reports the pid, then runs `start` when told to.
- **Reaping:** one SIGCHLD handler → a `waitid(P_ALL, WNOHANG)` loop reaps everything (container init, exec processes, runc invocations). No `tokio::process` child handles, because they conflict with a subreaper's reaping.
- **I/O:** a PTY master (received over the console socket) or stdout/stderr pipes. For a container with a user namespace, the pipes are chowned to the container's mapped user before `create`, as containerd's shim does (`IoUID`/`IoGID`), so the container can reopen `/dev/stdout`. Logs are JSON-lines (`{ts, stream, log}`) in `/var/lib/rustlet/containers/<id>/container.log`, with size-based rotation.
- **Control socket `/run/rustlet/shims/<id>/shim.sock`:** length-prefixed serde messages: `Start`, `Kill{sig}`, `Exec{spec, tty}`, `Resize`, `Attach`, `Wait`, `Shutdown`.
- On exit it writes `exit.json` (code, signal, OOM flag from `memory.events`) and notifies the daemon. After a daemon restart, the daemon finds shims again through their sockets.
- Runtime: tokio `current_thread`.

### 2.4 `rustlet-image` — OCI images, storage, snapshots
- **Pull** (`pull/mod.rs`; the registry protocol, bearer tokens and HTTP are `oci-client`'s):
  - Normalize references (`alpine` → `docker.io/library/alpine:latest`; `reference.rs`).
  - Fetch the manifest's exact bytes (`pull_manifest_raw`, accepting OCI and Docker schema-2 indexes and manifests); the digest of that first response is the *repo digest*. From an index, pick `linux/amd64` ourselves (the baseline build over `v2`/`v3` variants; attestation entries never match).
  - Stream the config and layers (`pull_blob_stream`, up to 3 at once) into an `Ingest`, which checks size and sha256 before the rename into `blobs/`. Blobs already stored are skipped, so shared layers download once. Never `Client::pull`, which holds every layer in memory.
  - Progress events serialize to the NDJSON the daemon will stream. Manifests are capped at 4 MiB, configs at 8 MiB.
  - Policies `missing` (default), `always` (a `HEAD` first: nothing is downloaded if the tag still points at a stored manifest, and Docker Hub doesn't count a `HEAD` against its anonymous limit), `never`. Anonymous access only.
- **Content store** (`content.rs`): `/var/lib/rustlet/content/` is a plain **OCI image layout** (`oci-layout`, `index.json`, `blobs/sha256/…`). **Image names live in that `index.json`**, as `org.opencontainers.image.ref.name` annotations plus `io.rustlet.image.repo-digest`, not in SQLite as first planned: the directory stays readable by `skopeo` or `umoci`, and `save`/`load` become copies. `index.json` is replaced atomically, under an open-file-description lock (`store.lock`) that excludes threads as well as processes. Partial downloads live in `ingest/`.
- **Unpack** (`unpack.rs`; the `tar` crate is only an entry iterator, every file is written by our code):
  1. compressed → sha256 → gzip, zstd or nothing → sha256 → tar entries. Both streams are read to their very end, end-of-archive padding included, because both digests cover every byte.
  2. Names are checked as text (`..` refused, a leading `/` dropped), then each parent is resolved with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS)`, so a symlink planted by an earlier entry resolves *inside* the layer. (First planned as `RESOLVE_BENEATH`, which refuses absolute symlinks outright; `IN_ROOT` gives the semantics of Docker's chroot'ed unpack, and never leaves the layer either.) The final component is never followed; whatever was there is replaced (directories merge). A symlink to a directory the layer doesn't have is refused, as by Docker.
  3. Owner, then mode (chown clears setuid), then xattrs (chown clears `security.capability`), then times; directory times last. Xattrs come from PAX `SCHILY.xattr.*`, **except** `trusted.overlay.*` and `user.overlay.*`, which are dropped. Hard links must point into the same layer and are made from an fd (`linkat(AT_EMPTY_PATH)`), never to a directory or whiteout. Device nodes are skipped.
  4. `.wh.<name>` becomes an overlay whiteout (char 0:0), `.wh..wh..opq` the opaque xattr; a directory that meets its own layer's whiteout is opaque too. Other `.wh..wh.*` (AUFS) entries are skipped.
  5. **The blob digest and the uncompressed stream's digest are checked against the manifest and the config's `diff_id`** before the atomic rename into `snapshots/<chainID>`. Otherwise one malicious image could poison a snapshot that other images share.
- **Snapshots and rootfs:**
  - `snapshots/<chainID>/{fs/,snapshot.json}` (`snapshot.rs`): one directory per layer, keyed by chain ID; shared layers are unpacked once, and concurrent unpacks of one layer converge on a single snapshot (the first rename wins).
  - Container rootfs (`rootfs.rs`) = overlayfs at `containers/<id>/rootfs`, with `upper/` and `work/` beside it, built with the new mount API: one `fsconfig("lowerdir+")` per layer (6.8+). `fsconfig` takes string values of at most 255 bytes, so the classic `lowerdir=a:b:c` (which also needs `:` escaped) doesn't fit three snapshot paths. `metacopy=off`, `index=off` and `redirect_dir=nofollow` are set explicitly so a container's changes stay a self-contained diff (`nofollow` rather than `off`, which would still *follow* a redirect it found; no layer should have one, and unpacking drops `trusted.overlay.*`). Mounted `nodev`, with the source name `rustlet`.
  - For `--userns=remap`: **idmapped lower layers**. A parked helper process (`rustlet_sys::process::UsernsHolder`, sound even in a multithreaded caller) holds a user namespace with the container's maps, written through `IdMapper`; each layer becomes `open_tree(CLONE)` + `mount_setattr(MOUNT_ATTR_IDMAP)`, so on-disk uid 0 is seen as container root (host 1000000). Before 6.15, overlay only takes layers *attached* in the mounter's namespace, so the idmapped trees sit under a 0700 `lower/` only until the overlay exists (it keeps private clones). Upper is owned by the mapped root.
- **Image config → OCI spec** (`runspec.rs`, `user.rs`):
  - merge Entrypoint/Cmd with overrides (an overridden entrypoint drops the image's Cmd, as in Docker)
  - merge Env; apply WorkingDir; StopSignal and ExposedPorts become OCI `conversion.md` annotations; Volumes (anonymous) and Healthcheck wait for Phases 4–5
  - resolve `USER` via the image's `/etc/passwd` and `/etc/group`, read through `RESOLVE_IN_ROOT` from the mounted rootfs, with runc's `GetExecUser` rules (supplementary groups in the implicit form)
  - covered by `insta` snapshot tests
- **Import** (`import.rs`): local tar layers → blobs, config, manifest and a name: the pull pipeline backwards. Used by tests, by `cargo xtask image-run --local-alpine` (offline), and by the builder later.
- **Commit/diff:** walk the upperdir and convert whiteouts and opaque xattrs back into `.wh.` entries, producing a deterministic tar layer. Used by the builder and `commit` (Phase 7). Found while writing chapter 12: skip `work/`; skip overlay's own attributes (`trusted.overlay.uuid`, `origin`, `impure`); overlay makes whiteouts as hard links to one in `work/work`, so they must not become tar hard links of each other; and a remapped container's upper holds *host* ids (1000000 + n), which must be mapped back.

### 2.5 `rustlet-net` — host-side networking
- **Modes:** `bridge` (default), `none`, `host`, `container:<id>`, and user-defined networks.
- **Pinned netns:**
  - A **dedicated `std::thread`** calls `unshare(CLONE_NEWNET)`, bind-mounts `/proc/thread-self/ns/net` onto `/run/rustlet/netns/<id>`, and exits.
  - Network namespaces are per-thread, so this must never run on a tokio or `spawn_blocking` pool thread: the pooled thread would stay in the wrong namespace.
  - `/run/rustlet/netns` is a shared bind mount, as iproute2 sets it up.
  - A setns'd thread writes the per-netns sysctls (§2.2.2).
- **Bridge setup (hand-written rtnetlink):**
  - bridge `rustlet0` at `10.89.0.1/16`
  - veth pair `rlv<id8>` ↔ peer, with the peer moved in using `IFLA_NET_NS_FD`
  - a setns'd thread renames the peer to `eth0`, assigns the address, brings up `eth0` and `lo`, and adds the default route
  - NetworkManager is told to leave `rustlet*` and `rlv*` alone (`/etc/NetworkManager/conf.d/rustlet.conf`, `unmanaged-devices`)
- **IPAM:** per-network subnet with allocations persisted in SQLite. Each container gets generated hosts, hostname, and resolv.conf files. Upstream resolvers come from `/run/systemd/resolve/resolv.conf` (192.168.50.1 on this host), never the 127.0.0.53 stub.
- **Firewall:** a dedicated nftables table **`inet rustlet`**, generated as JSON and applied through `nft -j -f -` (plumbing; a hand-written nfnetlink backend is a stretch goal).
  - `postrouting`: masquerade traffic from the subnet that leaves through anything other than `rustlet0`.
  - `prerouting` + `output`: DNAT for `-p host:container`.
  - `forward`: **drop traffic to container subnets** unless `ct state established,related` or `ct status dnat`. Without this, enabling `ip_forward` would turn the host into a router onto 10.89/16 for the LAN.
  - `raw prerouting`: drop traffic addressed to container IPs that doesn't arrive on `rustlet0`, as Docker 28 does.
  - Published ports on `127.0.0.1` use a **tokio userland proxy** (like docker-proxy) rather than `route_localnet`, because of CVE-2020-8558.
  - The original `ip_forward` value is recorded and restored on cleanup.
  - **ufw:** an nft `accept` can't override another table's `drop`. When ufw is active, the daemon warns and adds `ufw route allow in/out on rustlet0`. ufw is disabled today, but its forward policy is already DROP.
- **Embedded DNS** on user-defined networks: listens on **`127.0.0.11:53` inside each container's netns**, using a socket created by a setns'd thread and served by the daemon's tokio runtime, the same approach as Docker. It answers container names and aliases and forwards everything else upstream. `hickory-proto` is used only for message parsing.
- Everything sits behind a `NetworkBackend` trait. Rootless later: a pasta backend.

### 2.6 `rustletd` — the daemon
- **Socket:** tokio + axum on `/run/rustlet/rustlet.sock` (mode 0660, group `rustlet`, so the CLI and GUI work without sudo). Docs will say plainly that this group is root-equivalent.
- **API `/v1/...`**, shaped after the Docker Engine API:
  - containers: create / start / stop / kill / restart / pause / unpause / rm / json / inspect
  - `logs` (NDJSON follow), `attach` and `exec` (WebSocket), `stats` (NDJSON)
  - images: pull (NDJSON progress) / json / inspect / rm / save / load / build
  - networks, volumes, and `/events` (WebSocket)
- **State:** SQLite via `rusqlite` (bundled): containers, images and tags, networks, IP allocations, volumes, build cache. Volatile state lives in `/run`.
- **Container state machine:** Created → Running ⇄ Paused → Exited(code, oomKilled) → Removed, plus Restarting. Restart policies: `no`, `on-failure[:N]`, `always`, `unless-stopped`, with backoff. Healthchecks run through shim exec.
- **Stop:** send StopSignal (default SIGTERM) → wait for the timeout → `cgroup.kill`.
- **Start/remove flow:**
  - **start** (the daemon's part, then the shim's):
    1. mount the overlay
    2. pin the netns, set up veth/IP/sysctls/DNS
    3. write `config.json`
    4. spawn the shim; the shim runs `create`
    5. add nft DNAT rules
    6. the shim runs `start`
    7. emit an event
  - **remove:** runtime `delete` → unmount → release the IP → unpin the netns → drop nft rules → `safe_remove_tree` (§4).
- **Startup reconciliation:** reconnect to live shims, mark dead containers exited, re-apply nft rules and sysctls, restart `always` containers.
- **EventBus:** a `tokio::sync::broadcast` feeding `/events`; the GUI updates live from it.
- **systemd unit `packaging/rustletd.service`:**
  - `Delegate=yes`, `DelegateSubgroup=daemon` (systemd ≥ 254; this host has 255)
  - `KillMode=process`, so shims and containers survive `systemctl restart rustletd`
  - `TasksMax=infinity`; the default 15% cap would also count shims
  - `OOMScoreAdjust=-500`
  - **No** `PrivateTmp`, `ProtectSystem`, `ProtectHome` or `PrivateMounts`. Overlay mounts and netns pins must land in the host mount namespace, where the host and `cleanup.sh` can see them.

### 2.7 `rustlet` — the CLI (clap)
Docker-like UX, for example: `rustlet run -it --rm --name web -p 8080:80 -v data:/data --memory 512m --cpus 1.5 --pids-limit 100 --cap-drop ALL --net host --security-opt seccomp=unconfined alpine sh`.

Commands: `ps`, `images`, `pull`, `logs -f`, `exec -it`, `stop`, `rm`, `rmi`, `inspect`, `stats`, `network …`, `volume …`, `build`, `compose up/down/ps/logs`, `save/load`, `commit`.

Raw terminal mode and SIGWINCH → resize are handled with `crossterm`.

### 2.8 Rustlets Desktop (Tauri v2 + React/TS)
- **Rust side (`desktop/src-tauri`):** holds a `rustlet-client`. Tauri commands handle request/response calls; **`tauri::ipc::Channel`** carries streams (logs, stats, pull progress, events, terminal I/O). Tauri capabilities restrict the frontend to our own commands.
- **Shared types:** API DTOs in `rustlet-spec` derive `ts-rs`, which generates TypeScript types (no drift between the two sides).
- **Frontend stack:** Vite, React, TS, TanStack Query (cache invalidated by daemon events), React Router, shadcn/ui + Tailwind, xterm.js, uPlot (stats), React Flow (network topology).
- **Views:**
  - **Dashboard**
  - **Containers:** list with actions
  - **Container detail**, with tabs:
    - Logs: virtualized, follow mode
    - Terminal: exec -it through xterm.js
    - Stats: CPU %, memory, IO, network, PSI
    - Inspect: JSON
    - **Isolation inspector:** a signature feature. It shows, per namespace, whether it is shared with the host or another container (ns inode comparison), `uid_map`, decoded CapEff/CapBnd, seccomp mode and profile, and cgroup limits vs usage.
  - **Images:** pull with per-layer progress, layer list with sizes
  - **Volumes**
  - **Networks:** topology graph
  - **Compose stacks**
  - **Build:** streamed build log
  - A daemon connection indicator, with "start daemon" via `pkexec systemctl start rustletd`.
- Packaging: `.deb` and AppImage via the Tauri bundler; the daemon ships as its own `.deb` with the systemd unit.

### 2.9 Builder and compose
- **`rustlet-build`** (runs in the daemon; the context arrives as a tar stream; `.dockerignore` is respected):
  - Parser: hand-written Containerfile parser (FROM/AS, RUN, COPY `--from`, ADD, ENV, ARG, WORKDIR, USER, EXPOSE, CMD, ENTRYPOINT, LABEL, VOLUME, HEALTHCHECK; multi-stage).
  - `RUN`: an ephemeral container on the current snapshot; the upperdir diff becomes a layer.
  - `COPY`: a new layer built from the context.
  - Metadata instructions only change the config.
  - Cache key = parent chainID + instruction + COPY source digests.
  - Output: an OCI manifest and config in the store.
  - Stretch: reproducible builds, `push`.
- **`rustlet-compose`** (a library used by the CLI and the Tauri side; client-side like Compose v2):
  - Compose YAML subset: services (image/build, command, env, ports, volumes, networks, depends_on + `service_healthy`, restart, healthcheck), plus networks and volumes.
  - Creates the project network, labels containers with `io.rustlet.compose.{project,service}`, and orders startup by topological sort.
  - YAML parsing via `serde_yaml_ng` or `serde_norway`. `serde_yaml` is archived and `serde_yml` is flagged as unsound.

### 2.10 Rootless-ready seams (defined now, implemented in Phase 8)
- `trait CgroupDriver`: `SystemdDelegated` now; `SystemdUser` later, via D-Bus transient scopes (`zbus`).
- `trait NetworkBackend`: `Bridge` now; `Pasta` later.
- `trait IdMapper`: direct `uid_map` writes now; `newuidmap` later.
- `struct Paths`: `/var/lib` + `/run` now; XDG directories later.

---

## 3. Repo layout and host paths

```
Rustlet/
├─ Cargo.toml                 # workspace (edition 2024), shared lints: forbid(unsafe_code) except rustlet-sys
├─ crates/
│  ├─ rustlet-sys/            # all unsafe: syscalls & kernel ABIs
│  ├─ rustlet-spec/           # oci-spec re-exports + API DTOs (serde, ts-rs)
│  ├─ rustlet-runtime/        # OCI runtime library (ns, rootfs, cgroups, security, seccomp, state)
│  ├─ rustlet-runc/           # bin: runc-compatible CLI
│  ├─ rustlet-shim/           # bin
│  ├─ rustlet-image/          # registry, content store, unpack, snapshots, image→spec, diff
│  ├─ rustlet-net/            # netns, bridge/veth, IPAM, nftables, DNS, userland proxy
│  ├─ rustlet-build/          # Containerfile parser + builder
│  ├─ rustlet-compose/        # compose model + orchestration
│  ├─ rustlet-client/         # typed async API client
│  ├─ rustletd/               # bin: daemon
│  └─ rustlet-cli/            # bin: `rustlet`
├─ desktop/                   # Tauri v2 (src-tauri/ + React src/)
├─ profiles/seccomp-default.json
├─ packaging/                 # rustletd.service/.socket, NM unmanaged conf, deb metadata
├─ scripts/cleanup.sh         # one-command host restore (see §4)
├─ xtask/                     # cargo xtask itest | rootfs | demo | image-run | images | gen-ts | dev-storage
├─ tests/                     # privileged integration tests
└─ docs/architecture.md, docs/learn/NN-*.md
```

Host resources, all prefixed so they're easy to find and remove:
- data: `/var/lib/rustlet/{content,ingest,snapshots,containers,volumes,state.db,build-cache,store.lock}`
- runtime: `/run/rustlet/{rustlet.sock,runtime,shims,netns}`
- cgroups: `system.slice/rustletd.service/…`
- firewall: nft table `inet rustlet`
- network devices: `rustlet0`, `rlv*`
- config: `/etc/rustlet/daemon.toml`

**Plumbing crates:**

| Area | Crates |
|---|---|
| Syscalls | `libc`, `nix`, `bitflags` |
| Async & API | `tokio`, `axum`, `hyper`/`hyper-util`, `tokio-tungstenite` |
| Serialization & OCI | `serde`, `serde_json`, `oci-spec`, `oci-client` |
| Layers | `sha2`, `tar`, `flate2`, `zstd` |
| CLI & terminal | `clap`, `crossterm` |
| Storage | `rusqlite` |
| DNS | `hickory-proto` |
| Types & errors | `ts-rs`, `thiserror` (libs), `anyhow` (bins) |
| Logging | `tracing` |
| YAML | `serde_yaml_ng` |
| Tests | `insta`; run with `cargo-nextest` (process per test, so forking in tests is safe) |

---

## 4. Host-protection guardrails (development happens on this machine)
1. **Hypervisor snapshots.** This is a KVM guest: snapshot it before Phase 1, Phase 2, and Phase 5, and before any risky experiment. Rolling back beats debugging a broken host.
2. **Mount-namespace invariants, enforced in release builds:**
   - init aborts unless it is in a new mount namespace
   - specs that join a mount namespace are rejected, and a rootfs of `/` is refused
   - `MS_REC|MS_PRIVATE` comes first, then a mountinfo check, before any `umount2(MNT_DETACH)`
3. **`safe_remove_tree`.** Comparing `st_dev` does **not** catch same-filesystem bind mounts, and `/home` and `/var/lib` share `/dev/sda3`. So:
   - walk with `openat2(RESOLVE_NO_XDEV|RESOLVE_NO_SYMLINKS)` + `unlinkat`
   - compare `statx` mount IDs
   - refuse outright if `/proc/self/mountinfo` lists any mount under the path
   - unmount first, deepest path first
4. **Dedicated dev storage (recommended).** `cargo xtask dev-storage` creates `/var/lib/rustlet` as a loop-mounted ext4 image (e.g. 25 GB). It caps disk usage, gives storage its own filesystem, and makes a full wipe trivial.
5. **Namespaced host resources** (see §3). `scripts/cleanup.sh`:
   1. stop `rustletd`
   2. kill shims
   3. `cgroup.kill` and wait for `populated 0`, then `rmdir` deepest-first
   4. unmount everything under `/var/lib/rustlet` and `/run/rustlet`, deepest-first
   5. delete the netns pins, `rustlet0`, and `rlv*`
   6. `nft delete table inet rustlet`
   7. restore `ip_forward` and the other sysctls
6. **Tests run inside a limited scope:** `systemd-run --scope -p Delegate=yes -p TasksMax=4096 -p MemoryMax=4G`. Assert that `pids.max` exists before any fork-bomb test, and use swap 0 in OOM tests.
7. **Least privilege for tooling:**
   - build as your user; `cargo xtask itest` builds, then runs just the test binaries as root, each in the §4.6 scope (`sudo systemd-run --scope … /usr/bin/env RUST_BACKTRACE=1 <binary>`; `env` restores the one variable worth having without needing sudo `SETENV` rights)
   - never `sudo cargo`, never `sudo -E`, which would leave root-owned files in `target/` and `$HOME`
8. **No host networking changes until Phase 5.** Phases 1–4 use only `none` or a new netns.
9. **Record `uname -r`** in test output (kernel 7.0 boots next). Keep the 6.14 entry in GRUB as a fallback.

---

## 5. Roadmap. Each phase ends with a demo, a `docs/learn` chapter, and a walkthrough.

**Status (2026-10-01):** Phases 0 to 2c are built, and Phase 3 (images) is built: `cargo xtask image-run` pulls `alpine`, `nginx` and `python:3-slim` from Docker Hub and runs them, rootful and with `--userns`. `cargo xtask itest` passes all 243 checks (240 privileged tests plus 3 harness unit tests); `cargo nextest run --workspace` passes 306 unit tests. Phase 3's independent review is done (below). Phase 2c part 2's independent review is also done; its one P1 filesystem finding is fixed, with regression tests (below). [Chapter 08](learn/08-runtime-cves.md) has been checked against its sources and the current code, edited for accuracy and clarity, and describes the finding and its fix.

Phase 3, as built (images; [chapter 11](learn/11-oci-images.md), [chapter 12](learn/12-overlayfs.md)):
- **Crate:** `rustlet-image` (§2.4): `reference` → `pull` → `content` → `unpack`/`snapshot` → `rootfs` → `runspec`/`user`, plus `import` (local tars into the store). Pulling needs only write access to the store; unpacking and mounting need root.
- **Pull:** `oci-client` 0.18 for the protocol, everything else ours: exact manifest bytes, platform selection, the config checked (parses, one diff ID per layer, `linux/amd64`) before any layer is fetched, up to 3 blobs at once, each through an `Ingest` that only renames a blob into `blobs/` once size and digest match, the manifest stored after everything it names and the name last. Policies `missing`/`always` (one `HEAD`)/`never`. NDJSON-serializable progress events. 14 tests against an in-process fake registry (OCI and Docker indexes, bearer tokens, corrupted, short or long blobs, mismatched manifests, shared layers, the policies, artifacts, the concurrency limit), two more for the event format and for pulls running on any thread, and one ignored live pull.
- **Store:** a plain OCI image layout. **Deviation:** image names are `org.opencontainers.image.ref.name` annotations in its `index.json` (plus `io.rustlet.image.repo-digest`), written atomically and byte-stably under an OFD lock, not SQLite rows; other OCI tools can read the store as it is.
- **Unpack:** both digests over every byte, a snapshot renamed into place only once both match and everything in it, `snapshot.json` included, is on disk (`syncfs`, then an fsync of `snapshots/`); a chain-ID directory a crash left without usable metadata is replaced. An empty numeric tar field reads as 0, as in Go's `archive/tar`. **Deviation:** parents resolve with `RESOLVE_IN_ROOT` (Docker's chroot semantics), not `RESOLVE_BENEATH`, with `..` refused as text; a symlink to a directory the layer doesn't have is refused. Whiteouts and opaque markers become overlay's; a directory meeting its own layer's whiteout is opaque. Unprivileged unpacks (unit tests) keep the caller as owner and use `user.overlay.opaque`, the attribute of an overlay mounted with `userxattr`.
- **Rootfs:** overlay through `lowerdir+` (an `fsconfig` string can't hold three snapshot paths), `metacopy`/`index` off and `redirect_dir=nofollow`, `nodev`, source `rustlet`. With `--userns` the layers are idmapped through a parked helper's user namespace and staged under `containers/<id>/lower/` only until the overlay exists; upper belongs to the mapped root.
- **Spec:** `default_spec()` plus the image's command, environment, working directory, user and OCI `conversion.md` annotations (labels win over the implicit ones, as conversion.md says). USER follows runc's `GetExecUser`, except that malformed passwd lines are skipped instead of read as uid 0, and the primary gid comes first in `additionalGids`, as in Docker, Podman and containerd since CVE-2022-36109. Volumes, Healthcheck and ExposedPorts are recorded, not acted on, until Phases 4–5.
- **Runtime fixes the milestone found:**
  - nginx under `--userns` couldn't reopen `/dev/stderr` (§2.2 step 5.6): foreground `run` and `exec` now give user-namespace processes stdio pipes chowned to their mapped user, and relay them without ever waiting on the process (`stdio.rs`);
  - `process.user` ids of 4294967295 (`(uid_t)-1`, "leave unchanged" to `setresuid`) are refused at `create` and `exec`.
- **Tooling:** `cargo xtask image-run [--userns] [--pull P] [-t] [-e] [-u] [-w] [--entrypoint] [--read-only] [--memory/--pids/--cpus] [--keep] [--json-progress] [--local-alpine] IMAGE [ARGS…]` (builds as you, then runs the rest as root through sudo, in a delegated scope like `demo`); `cargo xtask images [inspect IMAGE [--json] | ls [-R] PATH | cat PATH | prune-containers]` to look inside the root-only store.
- **Milestone:** `alpine` (pull, unpack and run in about 3 s; `id` shows Docker's group list), `nginx` (serves its page over loopback in the container's own network namespace; master as root, workers as uid 101), `python:3-slim` (sharing its Debian base layer and snapshot with nginx), each also with `--userns` (`uid_map` `0 1000000 65536`, image owners intact through the idmapped layers), and an interactive TTY shell.
- **Tests:** 10 `im_` tests (owners, modes and file capabilities as root; confinement; whiteouts, opaque directories and copy-up through a real overlay; digest mismatches leave nothing; shared and concurrent snapshots; imported Alpine images run rootful and remapped) and 3 `us_` stdio tests; the `im_` tests take turns, because they mount on the host. Host mountinfo stays at 24 lines.
- **Not yet:** no garbage collection or `rmi` (a failed pull can leave verified blobs). Whatever decides which snapshots are in use must keep its own record: for a `--userns` container, mountinfo still names the staged `lower/<n>` paths long after they are gone. Anonymous registry access only; images without layers are refused; the host-side overlay mounts sit under the shared `/` and propagate into other mount namespaces until unmounted (the daemon may make `containers/` a private mount); a supplementary gid of 65536 or more is refused under `--userns`. Cosmetic, for the daemon's CLI: `image-run` says "1 layers", and names a layer by blob digest when unpacking but by chain ID when it was already unpacked.
- **Independent review** (2026-10-01): no high-severity findings, and the build matches the plan apart from the deviations recorded above. Fixed:
  - the stdio relay (`stdio.rs`) stopped altogether once a process had closed both its stdout and stderr, so input arriving after that never reached it: a process that ran `exec >log 2>&1` and then read its stdin waited forever. The relay now keeps going while input can still be delivered;
  - nothing tested the blob-digest check. The `im_` case meant to do it flipped a byte that gzip's own checks catch first, and with the check deleted every test still passed. The stored blob is now replaced with the same tar, recompressed: valid gzip, the right diff ID, and only the blob digest tells;
  - a directory listed twice in one layer got its times from the first entry but its other metadata from the last. Times now follow archive order too;
  - an old-style (V7) directory entry, typeflag NUL with a name ending in `/`, became a file; Docker (Go's `archive/tar`) and GNU tar make it a directory.

  `rr_userns_input_outlives_closed_output` and new unit tests in `stdio.rs` and `unpack/tests.rs` cover them. **Inputs for Phase 4**, where pulls and unpacks run in the long-lived daemon:
  - Two places read untrusted input whole, without a size limit. The `tar` crate (0.4.46) reads GNU long-name and PAX extension headers into memory, where Go caps them at 1 MiB, so a small gzipped layer can make the unpacker allocate gigabytes. And `oci-client`'s `pull_manifest_raw` buffers a manifest response whole before the 4 MiB check.
  - Unpacking in a child process confined to a memory-limited cgroup would bound both, as well as the unpacker's per-entry bookkeeping.
  - Serializing the unpacks of one chain ID would also close a narrow race: `publish` can move aside a crash-damaged snapshot directory that a concurrent unpack of the same layer has just replaced with a good one.

Phase 2c part 2, as built (eBPF devices; [chapter 10](learn/10-ebpf-devices.md)):
- **Compiler:** `cgroups/devices/` validates rules, optimises resets/no-ops, emits eBPF and checks it with a small interpreter. A separate reference evaluator implements the per-bit rule semantics (§2.2.2). Defaults compile to 89 instructions; a privileged allow-all to `w0 = 1; exit` (2).
- **Verifier cost:** comparing the persistent major/minor registers directly made path states accumulate quadratically (895,269 processed instructions at 1,000 rules). Scratch-register comparisons let paths merge again: the recorded 2,000-rule case is 20,012 instructions and 46,008 processed. `MAX_RULES = 2000` applies **after optimisation**: up to three conditional comparisons per rule must fit the verifier's 8,192 pending-branch limit, as well as its instruction-processing budget.
- **Attachment/lifetime:** `create` loads and attaches before `clone3`, saves the program id, then closes the program fd. Default devices, foreground TTYs and `exec -t` work under the filter. `exec` is born in the same filtered cgroup. Tests query the one `ALLOW_MULTI` program and poll its id to `ENOENT` after delete or failed create (release is asynchronous).
- **Nodes:** `dev.rs` owns the shared defaults and `/dev` population. `linux.devices` supports character (`c` or `u`), block (`b`) and FIFO (`p`) entries, nested paths, mode and ownership. Default paths may be replaced only with the same type/numbers. Non-default existing paths, duplicates, ancestor/descendant node conflicts, symlink/console paths and mount conflicts are refused. `/dev` must be a tmpfs. User-namespace character/block nodes bind the checked host node and retain host metadata; FIFOs are created locally with mapped owners.
- **Capability gate:** `CAP_MKNOD` in any of the five sets needs a filter or a new user namespace, both at create and exec; rules/nodes always need a cgroup. The milestone is now real: `mknod b 8 0` gets `EPERM` despite effective `CAP_MKNOD`, while `mknod c 1 3` succeeds.
- **Tooling:** `cargo xtask devices [--bundle DIR] [--disasm]` lists rule origins, optimiser results and the program; `--bundle` uses the actual runtime plan, including node/mount validation and implicit creation rules. `spec::{add_host_device,host_devices,privileged}` builds device/privileged-shaped specs, exercised by `xtask demo`. User-namespace `add_host_device` requires the same host/container path.
- **Deliberate differences from runc 1.3.4:**
  - no default `c *:* m`, `b *:* m` or tun access;
  - ordered, per-bit decisions, including a partial deny against an `rw` request; wildcard allows can have later holes;
  - type `a` rules must be exactly wildcard numbers plus full `rwm`; out-of-range numbers and negatives other than wildcard `-1` are refused;
  - no implicit cgroup when `cgroupsPath` is absent: nodes/rules are refused, as is `CAP_MKNOD` unless a new user namespace makes device creation impossible;
  - device paths must be clean and strictly under `/dev`, with the conflicts above refused;
  - FIFOs in a user namespace are created rather than bound from the host.

  Shared behaviour: defaults follow spec rules, default nodes are replaced by path, absent metadata means `0666`/uid 0/gid 0, `u` means character, user-namespace devices use host binds, and empty access is refused. `df_devices_match_runc` asserts the common node metadata/access results and explicitly checks the default and partial-deny differences.
- **Tests:** 21 `dv_` tests, two added `us_` tests, updated capability/exec refusal tests and the device differential test. Random programs agree with the reference evaluator and the real kernel; largest-program and verifier-cost tests load successfully. Full suite, fmt, clippy and unit tests pass; device, privileged and privileged-userns demos run. Host mountinfo remains 24 lines.
- **Independent review (2026-10-01):** the existing 227 integration checks and 215 unit tests passed, as did fmt and clippy. One **P1 finding, now fixed**: image aliases `/dev -> /mnt` or `/mnt -> /dev` let a later writable bind mount on `/mnt` replace the fresh `/dev` tmpfs. If the host bind source was also tmpfs, `dev::populate`'s filesystem-type check passed and node/symlink creation wrote into the host source, including requested node ownership and mode. Both cases were reproduced with disposable fixtures; a later failed `create` did not undo the writes. The fix: `rootfs::setup` keeps the fd of the `/dev` tmpfs mount, `dev::populate` writes only through it and first checks that `/dev` in the rootfs still resolves to the root of that mount (mount ID, device, inode), and a symlinked `/dev` destination is refused like a symlinked `/proc` or `/sys`. `rr_dev_symlink_cannot_redirect_device_population` and `rr_mount_through_a_symlink_cannot_cover_dev` fail without the fix and pass with it. Chapter 08 §5 tells the story.

Phase 2c part 1, as built (user namespaces; chapter 09):
- **Maps:** a new user namespace comes from `linux.uidMappings`/`gidMappings` (`userns.rs`). The remap range is `0 1000000 65536` (`spec::REMAP_HOST_ID`, `REMAP_SIZE`), so container root is host uid 1000000. The parent writes the maps through the `IdMapper` trait (`DirectIdMapper` now, `newuidmap` in Phase 8).
- **The parent opens the host side of every mount** (`rootfs::HostTrees`, §2.2 step 4.0): the rootfs and each bind source, as detached `open_tree` copies. Init attaches the rootfs tree on top of `/` and pivots into it. This is done for every container, not only those with a user namespace, so there is one code path.
- **The parent's part** (step 4.3): the maps and idmaps before the first `Proceed`, after which init's first act is `become_root`; rlimits and `oom_score_adj` when init asks for them (`SetLimits`), once its setup as root is done.
- **In a user namespace:**
  - `/dev` character/block nodes are bind mounts of the host's, since device `mknod` is never allowed there (part 2 adds locally created FIFOs).
  - `/sys` is a locked, read-only rbind of the host's when the network namespace isn't the container's own.
  - `exec` joins the user namespace in its one `setns` and becomes root before joining the session keyring.
- **Refused at `create`:**
  - unmapped process ids or devpts `gid=`;
  - a shared PID namespace;
  - mqueue, cgroup2 or sysctls in namespaces the user namespace doesn't own;
  - `kernel.domainname` (the spec's `domainname` field works);
  - joining a user namespace by path;
  - proc/sysfs flags the kernel refuses in a user namespace: an atime option on a new proc or sysfs, and `suid`/`dev`/`exec` or an atime option on the host's sysfs copy (its mounts' flags are locked);
  - a map of a page (4096 bytes) or more of text.
- **Deliberate difference from runc:** maps that put host uid or gid 0 in the container are refused, although OCI allows them. Container root would be host root to everything that checks ids rather than capabilities.
- **Mounts** accept `idmap`/`ridmap`, with the container's own mappings only.
- **Tooling:** `cargo xtask rootfs --remap` builds `bundles/alpine-remap`, a copy of the Alpine rootfs owned by host ids 1000000 and up. The chown needs root, so it re-runs itself under sudo. `cargo xtask demo --userns` runs a shell in it.
- **Tests:** the part 1 milestone passed 203 itest checks and 195 unit tests, with 20 `us_` tests. Part 2 adds checked spec-device binds and FIFO metadata, bringing `us_` to 22.
- **Known nit:** `/dev/mqueue` shows as owned by `nobody` (65534) inside. `clone3` creates the IPC namespace, and with it the mqueue superblock, while init is still host uid 0, which the namespace doesn't map.
- **Independent review:** no high-severity findings. The medium one: the parent set init's rlimits before init had mounted anything, so init's own setup ran under the container's limits (`RLIMIT_NOFILE` 8 failed with `EMFILE`). Init now asks for them once its setup as root is done. Also fixed:
  - proc/sysfs flags and maps the kernel refuses, which used to fail halfway through init, are refused at `create`;
  - the sync socket now outlives the create guard, so a failed create can't also print init's "rustlet-runc went away";
  - an idmapped mount's own mappings are compared after merging, not line by line;
  - a read-only-paths test that couldn't fail now checks mountinfo.

  `tests/tests/review_regressions.rs` covers each finding, and CI's itest job now builds the remap rootfs.

Phase 2b, as built:
- **Defaults** (`rustlet-runc spec`, the dev bundle): Podman's 11 capabilities (`CapBnd` = `800405fb`, inheritable and ambient empty), `noNewPrivileges`, Docker's seccomp profile resolved for those capabilities, and Docker's masked and read-only paths. A spec without `process.capabilities` is refused; Phase 2c now gates `CAP_MKNOD` on a filter or new user namespace (§2.2.2).
- **Seccomp:** a hand-written compiler (`crates/rustlet-runtime/src/seccomp/`). It does an arch and x32 check, an ENOSYS stub above the profile's highest syscall, and a binary search over ranges of syscall numbers into shared rule blocks, with 64-bit arguments compared as hi/lo halves. Docker's profile compiles to 140 instructions, at most 7 comparisons deep. It is tested with an interpreter plus a reference evaluator, and in real filtered child processes. `cargo xtask seccomp --disasm` prints the program.
- **exec:** the parent joins only the container's PID namespace; the child joins the rest through init's pidfd (see §2.2 step 6). `-t`, `-d`, `--pid-file`, `-u`, `-e`, `--cwd`, `--cap`, `--no-new-privs`, `--preserve-fds`, `--cgroup` and `--ignore-paused` are supported.
- **Also:**
  - sealed-memfd self re-exec and `PR_SET_DUMPABLE=0`;
  - sysctls, validated against the container's namespaces and written through a private, detached procfs;
  - masked paths bind `/dev/null` only after checking it is the real char device 1:3;
  - mount destinations are refused under `/proc` and `/sys`, both as written and after resolving symlinks in the rootfs;
  - a session keyring per container, and `lo` brought up in a new network namespace;
  - `HOME` from the container's `/etc/passwd`;
  - `--preserve-fds`;
  - runc's recursive mount options (`rro`, `rnosuid`, …).
- **Verified against runc 1.3.4** (`tests/tests/differential.rs`): the same bundle gives the same capabilities, NNP, seccomp, signal masks, mounts and per-mount options, `/dev`, ulimits, cgroup, identity, masked and read-only behaviour, namespaces and fds. The deliberate differences:
  - read-only is a mount attribute, never a superblock flag, since superblocks can be shared with the host;
  - the rootfs is `nodev`;
  - no `/dev/core`.
- **youki `contest` v0.7.0** (the Phase 2b subset: lifecycle, exec, caps, rlimits, masked/read-only paths, sysctl, seccomp, pidfile, fds, recursive mounts, …, against the release build): 78 ok, 6 skipped (CRIU), 6 not ok. Two groups also stop the harness: `exec::cgroup_test` and `ns_itype`. Everything that fails is out of scope:
  - user namespaces (Phase 2c);
  - hooks and `--no-pivot` (not planned);
  - sharing the host's mount namespace (never allowed);
  - relative `readonlyPaths` (the OCI spec requires absolute paths);
  - an inconsistent capability set, which is rejected at `create` rather than by the kernel;
  - tests that assume the runtime creates a cgroup when `cgroupsPath` is absent. Rustlets doesn't, so `pause` and `exec --cgroup` into a fresh domain need a `cgroupsPath`.

  The recursive-mount tests ran with `CAP_MKNOD` removed from contest's spec (Phase 2c). Run contest against the release build: it waits a fixed second between `create` and `start`, and the 70 MB debug binary's memfd copy, done by many creates at once, can overrun that and make tests pass without running. Afterwards, check the host's `/proc/self/mountinfo`. Some of contest's own fixtures mount under `/tmp/.tmp*` on the host and don't always unmount: `root_readonly_true_test` binds its rootfs onto itself every time, and the recursive-mount tests leave their tmpfs mounts if a run is cut short.
- **Independent review:** no high-severity findings. The medium one: an `exec` whose process was killed before `execve` reported success; it now checks `/proc/<pid>/exe` and the zombie's `comm`. Five low ones were fixed as well; `tests/tests/review_regressions.rs` covers them.

Phase 2a, as built:
- **Commands:** `create`/`start`/`state`/`kill`/`delete`, runc-compatible, plus `pause`/`resume`, `ps`, `list`, `events --stats` and `run --detach`. Foreground `run` is create + start + wait + delete.
- **cgroups:** a container cgroup is only ever created *strictly below* a cgroup carrying systemd's `trusted.delegate` xattr (set on `Delegate=yes` units); anything else is refused before any file is touched.
- **Terminals:** the PTY is created inside the container, and its master is passed out over the console socket (`--console-socket`, or an internal socketpair plus a raw-mode relay for foreground `run`).
- **Code review (independent):** found two serious bugs, both now fixed and covered by `tests/tests/review_regressions.rs`. `delete --force` could orphan a half-created container; state is now written provisionally before anything is created, and unreadable state is an error. And container cgroups could nest, so deleting the outer container killed the inner one; container cgroups are now tagged with `user.rustlet.container`, nesting is refused, and the cgroup's inode is checked before every kill, freeze or rmdir. State operations are serialized with a POSIX record lock on `<dir>/.lock`. An `flock` turned out to be wrong: init inherits the fd across `clone3`, and after a SIGKILLed `create` it would hold the lock forever.
- **Host-specific limits:** on this host, `hugepageLimits` and per-device `blockIO.weightDevice` fail with clear errors (systemd doesn't delegate hugetlb; per-device `io.weight` needs iocost).

Phase 1 notes:
Phase 1 went slightly beyond its row below, in places where doing it right from the start cost little:
- mounts are fd-based already (`fsopen`/`open_tree` → `move_mount` onto `openat2(RESOLVE_IN_ROOT)` fds), originally a 2b item;
- init already sets rlimits, `oom_score_adj`, uid/gid/supplementary groups, `noNewPrivileges` and umask, marks fds CLOEXEC with `close_range`, checks the cwd (CVE-2024-21626), and resets signal dispositions (Rust's ignored SIGPIPE);
- spec fields that aren't implemented yet (capabilities, seccomp, terminal, resources, …) are **rejected** with the phase that adds them, never silently ignored.

Differential check: the same bundle under `runc` 1.3.4 gives identical namespaces, mounts, signal masks, caps and NNP; the only difference is runc's extra `/dev/core` symlink, which Rustlets omits.

| Phase | Build | Milestone / demo | Learn chapters |
|---|---|---|---|
| **0 Foundations** | Install rustup, cargo-nextest, Node LTS + pnpm, Tauri Linux deps (`libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev`), `runc` + `strace` (reference/diff tools). `git init`, workspace skeleton, lints, CI, xtask, `cleanup.sh`, dev-storage. | `hello-ns`: `clone3` (or `unshare` + **fork**, since `CLONE_NEWPID` affects only children) shows PID 1 and its own hostname | 00-setup, 01-namespaces-intro |
| **1 Minimal runtime** | `rustlet-sys` basics, `clone3` with all namespaces new, the mount invariants, bind rootfs + `pivot_root`, `/proc` `/dev` `/sys` `/dev/pts`, hostname, execve. `rustlet-runc run` in the foreground over a bundle from `xtask rootfs` (Alpine minirootfs + generated `config.json`). | Shell in Alpine over inherited stdio (no job control yet); PID 1; separate hostname and mount table | 02-mounts-pivot-root, 03-proc-dev-sys |
| **2a Lifecycle and resources** | create/start with the exec.fifo fd, state/kill/delete, cgroups v2 (delegated path, limits, freeze, kill, events, stats, OOM), cgroupns unshare, console socket + PTY + `/dev/console`. | `-t` shell with job control; fork bomb contained; `--memory` OOM detected; `/proc/self/cgroup` = `0::/` | 04-cgroups-v2, 05-ptys-fd-passing |
| **2b Hardening** | memfd self re-exec + dumpable, fd-based mounts via `move_mount`, masked/ro paths, sysctls, caps, NNP, rlimits, `close_range`, cwd check, seccomp compiler + Docker profile, **then** `exec`. | CapEff matches the default mask; `unshare -U` gets EPERM; differential probe matches `runc`; youki `contest` subset passes | 06-capabilities, 07-seccomp-bpf, 08-runtime-cves |
| **2c User namespaces and devices** | `--userns=remap` (dedicated subordinate range; chowned test rootfs), the netns-ownership workarounds, eBPF device filter → unlocks `--device`, `MKNOD`, `--privileged`. | `uid_map` = `0 1000000 65536`; `mknod` of a block device is denied even with MKNOD | 09-user-namespaces, 10-ebpf-devices |
| **3 Images** | Streaming pulls, OCI-layout store, safe unpack + whiteouts + diff_id check, chainID snapshots, overlay via `lowerdir+`, idmapped layers for remap, image config → spec, USER resolution. A temporary `xtask image-run` driver wires pull → snapshot → spec → `rustlet-runc`. | `xtask image-run alpine\|nginx\|python:3-slim` from Docker Hub, with and without `--userns=remap` | 11-oci-images, 12-overlayfs |
| **4 Daemon, shim, CLI** | rustletd (UDS, SQLite, state machine, events, restart policies, reconciliation, systemd unit), shim (reaper loop, logs, attach, exec, exit/OOM), client, CLI core. | `rustlet run -it --rm alpine sh`, `run -d`, `logs -f`, `exec -it`, `stats`; containers survive `systemctl restart rustletd` | 13-daemon-shim-architecture |
| **5 Networking and volumes** | Pinned netns + sysctls, hand-written rtnetlink, IPAM, nftables (NAT, DNAT, forward and raw guards), userland proxy, `host`/`none`/`container:` modes, hosts/resolv.conf, named networks + 127.0.0.11 DNS, named/bind/tmpfs volumes (copy-up), NM unmanaged, ufw integration. | `run -d -p 8080:80 nginx` → `curl localhost:8080` works and the LAN **cannot** reach 10.89/16 directly; name resolution between containers; `--net=container:X` shares localhost | 14-veth-bridges-netlink, 15-nat-nftables, 16-dns |
| **6 Desktop app** (can overlap Phase 5) | Tauri v2 scaffold, ts-rs types, the views in §2.8, live events, xterm terminal, uPlot stats, isolation inspector, topology graph. | Full lifecycle driven from the GUI, and it stays in sync with CLI actions in real time | 17-tauri-ipc |
| **7 Build and compose** | Containerfile parser, builder with cache and multi-stage, `commit`, `save`/`load`; compose up/down/ps/logs; healthchecks and `service_healthy`. | Build a small web app, then `rustlet compose up` web + redis; view the stack in the GUI | 18-building-images, 19-compose |
| **8 Rootless and stretch** | Rootless mode (newuidmap, systemd user scopes over D-Bus, pasta), Docker API compatibility (`DOCKER_HOST` → rustletd), push, i386 seccomp, AppArmor, seccomp user-notify, CRIU, aarch64. | `rustlet run` as an unprivileged user; the `docker` CLI talking to rustletd | 20-rootless |

---

## 6. Verification strategy
- **Unit tests (as your user, with nextest):**
  - the seccomp compiler (forked child loads the filter; assert EPERM, ENOSYS for unknown-new syscalls, and a kill on a wrong arch)
  - the eBPF device compiler: random rule lists checked against the reference evaluator and interpreter, optimisation equivalence, validation and disassembly snapshots
  - device-node path/mount conflicts and the create/exec `CAP_MKNOD` gate
  - disassembly snapshots
  - OCI → cgroup v2 mapping, including shares → weight
  - image config → spec (insta snapshots of the parts it sets; the rest must equal the runtime default), USER resolution against image passwd/group files
  - pulls against an in-process fake registry: OCI and Docker indexes and platform selection, bearer tokens, corrupted, short or long blobs and mismatched manifests leave nothing behind, shared layers, pull policies, the download concurrency limit
  - unpacking without root: names with `..` refused, symlinked parents and hard links kept inside the layer, whiteout and opaque conversion, replacement rules (a directory listed twice keeps the later entry's metadata), old-style (V7) directories, overlay xattrs dropped, both digests over every byte for gzip, zstd and plain tar
  - the stdio relay: input and EOF still reach a process that has closed its outputs, and unread input never stalls output
  - the content store: verified ingest, names in `index.json`, concurrent writers, byte-stable rewrites
  - IPAM, Containerfile and compose parsers, DTO round-trips
- **Privileged integration tests** (`cargo xtask itest`, inside the limited systemd scope), probes run inside containers:
  - namespace inodes differ from the host by default and match under `--net=host`/`--pid=host`
  - PID 1
  - `/proc/self/cgroup` = `0::/`
  - `CapEff`/`CapBnd` masks
  - `Seccomp: 2`
  - `unshare -U` gets EPERM
  - OOM → `OOMKilled=true`
  - fork bomb contained
  - cgroupfs read-only
  - masked paths unreadable
  - read-only rootfs
  - `uid_map` under remap
  - the eBPF verifier accepts random and maximum-size device programs, with linear processing cost
  - block/other-character mknod denied despite `CAP_MKNOD`; defaults remain usable, including TTY run and exec
  - per-bit read/write/combined access, node metadata, nested paths and checked user-namespace host binds/FIFOs
  - exactly one attached device program, freed after delete and failed create; exec inherits filtering
  - privileged rootful/userns specs inspected with read-only probes, never sysfs writes
  - image layers unpacked as root (owners, setuid bits, file capabilities, symlink owners, skipped devices), confined writes, whiteouts/opaque/copy-up through a real overlay, digest mismatches leaving no snapshot, shared and concurrent snapshots
  - imported Alpine images run rootful and with `--userns` (idmapped layers: image owners inside, mapped owners for the container's writes), USER/WorkingDir from the image, `-u` overrides
  - user-namespace stdio: `/dev/stdout`/`/dev/stderr` reopenable in `run` and `exec`, including as non-root; unread input never stalls the relay; input still arrives after the process has closed its outputs
  - the host mount table is unchanged after each test (diff of `/proc/self/mountinfo`)
- **Differential testing:** the same bundle under `runc` and `rustlet-runc`, with a probe binary that dumps namespaces, caps, mounts, cgroup, and rlimits. The outputs are diffed.
- **Conformance:** youki's `contest` suite run against `rustlet-runc`. It is maintained and cgroup-v2-aware; OCI `runtime-tools` is stale and cgroup-v1-oriented.
- **End-to-end:** `scripts/smoke.sh` covers:
  - pull, run, logs, exec, stop, rm
  - a published port reachable with curl, while direct LAN access to the subnet is blocked
  - DNS between containers
  - volume persistence
  - daemon restart survival
  - build + compose app
  - `cleanup.sh`, after which a diff shows no leftover mounts, cgroups, nft table, links, or sysctls
- **GUI:** manual checklist per view, plus Vitest for the event → query-invalidation logic.

## 7. First implementation step, after approval
Phase 0:
1. Take a VM snapshot.
2. Install the toolchains and prerequisites (commands will be shown for approval first).
3. `git init`, then create the workspace skeleton (all crates compiling but empty), shared lints, `xtask` (itest, rootfs, dev-storage), `scripts/cleanup.sh`, `packaging/rustletd.service`, `docs/architecture.md` (this design), and `docs/learn/00-setup.md`.
4. Build the `hello-ns` experiment with a line-by-line walkthrough of `clone3`, namespaces, and why the PID namespace needs a fork.
