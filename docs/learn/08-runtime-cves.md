# 08 — Runtime CVEs: what went wrong in runc, and the rules Rustlets took from it

Several Phase 2b details have specific security reasons: a copy of our own
binary in memory, paths resolved by the kernel under a directory fd, a
`/dev/null` whose device number we check before using it, a `/proc` of our own
that is mounted nowhere. These choices respond to published vulnerabilities
in runc, the reference OCI runtime. This chapter goes through them
as lessons. For each: what kind of mistake it was, the rule that prevents it,
where Rustlets applies the rule, and a run on this machine that exercises the
protection. Section 5 also records a known gap found during independent review.

The bug descriptions follow the linked public advisories and describe the
failure mechanisms. **Reviewed 2026-10-01:** citations and code references were
checked against the current implementation. The original transcripts come from
kernel 7.0.0-34-generic, with `R="sudo ./target/debug/rustlet-runc --root
/run/rustlet/doc-08"` and bundles made from the default `config.json` as in
chapter 05's "Try it" (long scratch paths are shortened to `$D`). Pids, fd numbers,
binary sizes and timestamps vary between runs; the executable recipe below
does not depend on those values. These examples cover the default security
configuration, not a privileged spec that grants host-level capabilities.

Code: [`reexec.rs`](../../crates/rustlet-runtime/src/reexec.rs), [`exec.rs`](../../crates/rustlet-runtime/src/exec.rs),
[`init.rs`](../../crates/rustlet-runtime/src/init.rs), [`rootfs.rs`](../../crates/rustlet-runtime/src/rootfs.rs),
[`inroot.rs`](../../crates/rustlet-runtime/src/inroot.rs), [`mounts.rs`](../../crates/rustlet-runtime/src/mounts.rs),
[`paths.rs`](../../crates/rustlet-runtime/src/paths.rs), [`proc_handle.rs`](../../crates/rustlet-runtime/src/proc_handle.rs),
[`console.rs`](../../crates/rustlet-runtime/src/console.rs), [`caps.rs`](../../crates/rustlet-runtime/src/caps.rs),
[`dev.rs`](../../crates/rustlet-runtime/src/dev.rs).
Tests: [`hardening.rs`](../../tests/tests/hardening.rs) (`cargo xtask itest -- hd_`),
[`exec.rs`](../../tests/tests/exec.rs) (`-- ex_`), [`review_regressions.rs`](../../tests/tests/review_regressions.rs) (`-- rr_`).

## 1. Why the runtime is the target

In rootful operation, `rustlet-runc create` runs as **root on the host**, with
the privileges needed to set up namespaces and mounts. It acts on things the
container can influence:

* **the image's files**: every mount target, `/dev`, `/etc/passwd` for `HOME`;
* **processes in the container's namespaces**: `exec` walks one in;
* **its own file descriptors**, which init inherits across `clone3`.

A container can shape the things the runtime is about to touch and let the
runtime's privileges do the rest. These CVEs illustrate mistakes in the
runtime's handling of container-controlled state, rather than bugs in the
kernel itself. They suggest five rules:

| rule | CVEs | Rustlets |
|---|---|---|
| 1. Keep runtime internals out of the container | 2019-5736, 2016-9962, 2024-21626 | sealed memfd, `PR_SET_DUMPABLE=0`, close-on-exec runtime fds, cwd check |
| 2. Resolve a path once, inside the root, into an fd; then act on the fd | 2019-19921, 2021-30465, 2024-45310, 2026-41579 | `openat2(RESOLVE_IN_ROOT)` + `move_mount` onto the fd |
| 3. Restrict mounts over kernel interfaces | 2019-16884, 2023-28642 | allowlisted kernel-filesystem targets, checked as written *and* as resolved |
| 4. Verify what you got, not what it's called | 2025-31133, 2025-52565, 2025-52881 | `/dev/null` must be 1:3; PTYs through `TIOCGPTPEER`; a private procfs |
| 5. Grant only configured capabilities | 2022-24769, 2022-29162 | empty inheritable set by default; `exec --cap` never adds to it |

## 2. Rule 1: the runtime binary, CVE-2019-5736

The [CVE-2019-5736 record](https://www.cve.org/CVERecord?id=CVE-2019-5736)
describes host-runtime overwrite through `/proc/self/exe`, affecting runc
through 1.0.0-rc6. The upstream [fix](https://github.com/opencontainers/runc/commit/6635b4f0c6af3810594d2770f662f34ddc15b40d)
executes a protected copy of the runtime before entering the container.

The mistake: a process that runc starts *inside* a container is, until it
`execve`s, a copy of runc, and for such a process `/proc/self/exe` is the runc
binary **on the host**. A container that gets runc to execute itself in there
can reach that file through `/proc` and, once runc has exited, write to it.
The next `runc` anyone ran on the host was then the container's program.

The rule: the binary a container might see must be one nobody can change.
[`reexec::ensure_sealed_binary`](../../crates/rustlet-runtime/src/reexec.rs)
runs first thing in `create`, `run` and `exec`. It copies `/proc/self/exe` into
a **memfd**, seals it (`F_SEAL_SEAL | SHRINK | GROW | WRITE`), and re-executes
from it with `fexecve`. "Already sealed?" is asked of the kernel (`F_GET_SEALS`),
not of an environment variable, which the caller could set. A created
container's init, from the host:

```text
$ pid=$($R state c1 | jq .pid); sudo readlink /proc/$pid/exe
/memfd:rustlet-runc (deleted)
$ sudo python3 -c '…fcntl(os.open("/proc/%s/exe" % pid, os.O_RDONLY), F_GET_SEALS)…'
15 ['SEAL', 'SHRINK', 'GROW', 'WRITE']
$ sudo python3 -c '…os.open("/proc/%s/exe" % pid, os.O_WRONLY)…'
[Errno 26] Text file busy: '/proc/365530/exe'
```

It's not the host file, and even the copy can't be changed. The `ETXTBSY`
error above only proves that a running executable cannot be opened for writing;
the seals prevent changes after that execution ends too. `PR_SET_DUMPABLE=0`
alone would not protect the host binary: ordinary `execve` makes the new
program dumpable again. The cost is memory: the copy lives as long
as a process runs from it, so deploy the release build (6.5 MB here) rather than
the debug one (75 MB). Tests: `hd_created_init_runs_from_a_sealed_memfd`,
`hd_foreground_run_runs_from_a_sealed_memfd`,
`ex_foreground_exec_runs_from_a_sealed_memfd`.

## 3. Rule 1: processes joining a container, CVE-2016-9962

The [CVE-2016-9962 record](https://www.cve.org/CVERecord?id=CVE-2016-9962)
describes container root inspecting new `runc exec` processes during setup,
exposing their file descriptors and runtime state. The upstream
[fix](https://github.com/opencontainers/runc/commit/50a19c6ff828c58e5dab13830bd3dacde268afe5)
makes the initialization process non-dumpable before it enters the container.

The lesson: a process entering a container is at its most exposed between
joining the container's namespaces and `execve`. It is inside, but it still
holds the runtime's fds and memory. Rustlets does three things (see the
`exec.rs` module docs):

* the runtime is **non-dumpable** (`PR_SET_DUMPABLE=0`, set before any
  `setns` or `clone3`), and its children inherit that until they `execve`. A
  non-dumpable process's `/proc/<pid>` files belong to root, and `ptrace` or
  following its `/proc/<pid>/fd` links needs ptrace permission. The default
  container lacks `CAP_SYS_PTRACE` in the user namespace needed to override
  the non-dumpable check;
* the parent never enters the container's mount namespace: it joins only the
  PID namespace (which affects only its children), and the child joins the rest;
* everything the child does with procfs happens *before* it joins the mount
  namespace, through a private procfs (§8).

The same protection covers init while it waits at the start gate, still a copy
of `rustlet-runc`. From an `exec` into a created container:

```text
$ $R exec c1 sh -c 'cat /proc/1/environ; ls /proc/1/fd | tr "\n" " "; readlink /proc/1/fd/7 || echo "readlink failed: $?"; cat /proc/1/fd/7'
cat: can't open '/proc/1/environ': Permission denied
0 1 2 5 7
readlink failed: 1
cat: can't open '/proc/1/fd/7': Permission denied
```

Root in the container may list the fd *numbers*: the directory belongs to root,
and root is who we are. But it can't see where they lead or open them. Fd 5 is
`exec.fifo` and 7 the sync socket. Test:
`ex_a_created_init_cannot_be_inspected_from_inside`.

## 4. Rule 1: leaked file descriptors, CVE-2024-21626

The advisory ("Leaky Vessels",
[GHSA-xr7r-f8xq-vfvv](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)):
an internal fd for the host's `/sys/fs/cgroup` leaked into `runc init`, and
nothing checked that the working directory ended up inside the container after
`chdir`. Setting `process.cwd` to a path through that fd put the container's
program in the host's filesystem. It affected runc 1.0.0-rc93 to 1.1.11. The
fix: close internal fds before `execve`, mark them `O_CLOEXEC`, and verify the
cwd.

Rustlets makes the same two moves, and has made them since Phase 1:

* **every fd the runtime opens is close-on-exec from birth**: `O_CLOEXEC`,
  `SOCK_CLOEXEC`, `SFD_CLOEXEC`, `MFD_CLOEXEC`, `FSOPEN_CLOEXEC`,
  `FSMOUNT_CLOEXEC`, `OPEN_TREE_CLOEXEC`, and pidfds are born that way. On top
  of that, init and the exec child call `close_range(3 + N, UINT_MAX,
  CLOSE_RANGE_CLOEXEC)` for anything inherited from the caller. The child also
  drops the parent-only fds (the cgroup directory, the lock, the signalfd) right
  after `clone3`;
* **`chdir(cwd)`, then `getcwd()`**: for a directory outside the process's root
  the kernel reports "(unreachable)", which comes back as `ENOENT` or a relative
  path, and init refuses both
  ([`process::enter_cwd`](../../crates/rustlet-runtime/src/process.rs)).

What the program sees:

```text
$ $R run --bundle $D/fds f1        # args: ls -l /proc/self/fd
lrwx------    1 root     root            64 Sep 25 23:08 0 -> socket:[622557]
l-wx------    1 root     root            64 Sep 25 23:08 1 -> …/binttqdmn.output
l-wx------    1 root     root            64 Sep 25 23:08 2 -> …/binttqdmn.output
ls: /proc/self/fd/3: cannot read link: No such file or directory
lr-x------    1 root     root            64 Sep 25 23:08 3
```

That's stdio (inherited from whoever ran us), and fd 3, which is `ls`'s own
handle on `/proc/self/fd`: it was gone by the time `ls` read its link. Tests:
`ex_leaks_no_fds`, `rr_init_holds_no_lock_or_state_dir_fd`,
`hd_preserve_fds_never_passes_the_runtimes_own_fds`.

## 5. Rule 2: paths that change under you

Four advisories, one mistake: **a path resolved with ordinary string
operations in a directory the container can write to.** Every lookup follows
whatever symlinks are there *at that moment*, and a path used twice (check,
then act) can mean two different files.

| CVE | what happened (from the advisory) |
|---|---|
| [2019-19921](https://github.com/opencontainers/runc/security/advisories/GHSA-fh74-hm69-rqjw) | with `/proc` a symlink into a volume shared with another container, a race let the other side redirect runc's procfs mounts and bypass security labels |
| [2021-30465](https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r) | mount destinations could be swapped for symlinks between check and use (via shared volumes), so a mount landed outside the rootfs |
| [2024-45310](https://github.com/opencontainers/runc/security/advisories/GHSA-jfvp-7x6p-h2pv) | a race in `os.MkdirAll` (creating missing mount points) could create empty files or directories on the host |
| [2026-41579](https://github.com/opencontainers/runc/security/advisories/GHSA-xjvp-4fhw-gc47) | with `/dev` a symlink in the image, `/dev` setup deleted a host file named `ptmx` or created runc's `/dev` symlinks in a host directory; runc ≤ 1.3.5 (this host's 1.3.4 included) |

The rule, from chapter 02: resolve once, inside the root, and act on what you
resolved. Mount-target lookups go through
`openat2(rootfs_fd, path, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`. The kernel
then treats the rootfs as `/` for the whole walk: `..` stops there, and an
absolute symlink restarts there. The result is an `O_PATH` fd, and the mount is
attached to *that fd* with `move_mount`, so the path is never looked up again.
Missing mount points are created one component at a time, each relative to an
fd resolved the same way ([`inroot::mkdir_all`](../../crates/rustlet-runtime/src/inroot.rs)).
`/dev` is populated with `mknodat`/`symlinkat` relative to an fd for the
resolved `/dev` ([`dev::populate`](../../crates/rustlet-runtime/src/dev.rs)).
It checks that the filesystem is tmpfs, but does **not yet verify that this is
the fresh tmpfs the runtime mounted**; that distinction matters below.
runc's fix for 2026-41579 is the same move: "fd-based" `/dev` setup.

A demonstration. Take a copy of the Alpine rootfs and replace its `dev` with
`dev -> /tmp/rustlet-ch08-host`, add `data -> /tmp/rustlet-ch08-host2`, and
create both of those host directories, empty. The spec mounts a tmpfs on
`/data/sub`:

```text
$ $R run --bundle $D/devlink d1
rustlet-runc: error: container init failed: open /dev/null (for masked paths): ELOOP: Too many symbolic links encountered
$ ls -A /tmp/rustlet-ch08-host /tmp/rustlet-ch08-host2       # on the host
/tmp/rustlet-ch08-host:
/tmp/rustlet-ch08-host2:
$ ls -A $D/rootfs-devlink/tmp/rustlet-ch08-host2              # in the copy
sub
```

The absolute symlinks were followed, but *inside* the rootfs: the tmpfs for
`/dev` and the `sub` mount point went into the copy's own
`tmp/rustlet-ch08-host*`, and the host directories stayed empty. Then the
container refused to start: masking a file needs a `/dev/null` reached without
any symlink (§7), and a symlinked `/dev` can't provide one. This example checks
lookup confinement; it does not prove that every symlink and mount combination
is safe. Tests:
`hd_mount_destinations_are_checked_after_following_symlinks`, the `inroot`
unit tests.

**Finding from the Phase 2c part 2 review (2026-10-01), now fixed:** an image
could make `/mnt -> /dev`, so a later writable bind mount on `/mnt` covered the
runtime's `/dev` tmpfs. The reverse alias, `/dev -> /mnt`, also worked: the
tmpfs followed the link to `/mnt`, and the bind mount covered it there. When
the bind source was a host tmpfs directory, the filesystem-type check passed,
and device population created nodes and symlinks in that host directory. A
disposable fixture acquired a requested character 1:3 node with mode `0640`,
uid 12 and gid 34, plus the default devices and symlinks, and a later `create`
failure did not undo those writes. Lexical mount/device conflict checks could
not catch the aliases, and every lookup had stayed inside the rootfs: the
problem was *which mount* the path reached, not where it went.

The fix keeps the fd of the tmpfs mount that `rootfs::setup` made for `/dev`
and populates `/dev` through that fd, never through the path. Before writing
anything, `dev::populate` checks that `/dev` in the rootfs still leads to the
root of that very mount (same mount ID, device and inode), and the mount of
`/dev` refuses a symlinked destination, as `/proc` and `/sys` do. Tests:
`rr_dev_symlink_cannot_redirect_device_population` and
`rr_mount_through_a_symlink_cannot_cover_dev`, each of which fails without the
fix. The lesson stands: fd-based path confinement alone is not a complete
proof of host-filesystem protection; what an fd refers to must be checked too.

## 6. Rule 3: restrict mounts over kernel interfaces

[CVE-2019-16884](https://www.cve.org/CVERecord?id=CVE-2019-16884) affected
runc through 1.0.0-rc8: incorrect checks allowed an image-defined mount over
`/proc` to bypass AppArmor. The upstream [issue](https://github.com/opencontainers/runc/issues/2128)
records the mount-target problem.
[CVE-2023-28642](https://github.com/opencontainers/runc/security/advisories/GHSA-g2j6-57v7-gm8c):
AppArmor and SELinux bypass when the image's `/proc` is a symlink. runc 1.1.5
refused symlinked `/proc`.

`/proc` and `/sys` are an API into the kernel. A file mounted on top of one of
theirs replaces the API. That can mean a fake `/proc/self/attr/*` (where security
labels are written), a writable copy of something `readonlyPaths` protects,
or a second, unmasked procfs somewhere else. Rustlets refuses all three, twice:

* **as written**, at plan time ([`mounts::check_pseudo_fs_targets`](../../crates/rustlet-runtime/src/mounts.rs)):
  no destination under `/proc/` or `/sys/` except runc's lxcfs list of files
  (`/proc/meminfo`, `/proc/uptime`, …), bound from regular host files. procfs
  and sysfs are allowed only at `/proc` and `/sys`. Init also checks that
  their destinations are real directories rather than symlinks:

  ```text
  $ $R run --bundle $D/attr a1         # a bind mount onto /proc/self/attr
  rustlet-runc: error: invalid config.json: mount bind $D/fakedir on /proc/self/attr is not allowed: user mounts inside /proc could replace kernel files (a writable /proc/sys, a fake /proc/self/attr) and would defeat maskedPaths/readonlyPaths; the only exceptions are bind mounts of regular files onto /proc/cpuinfo, …
  $ $R run --bundle $D/proclink p1     # an image whose proc is a symlink
  rustlet-runc: error: container init failed: invalid config.json: proc must be mounted on ordinary directory: /proc is a symlink in the rootfs
  ```

* **as resolved**, in init, just before `move_mount`
  ([`rootfs::check_resolved_target`](../../crates/rustlet-runtime/src/rootfs.rs)):
  for destinations outside the kernel-filesystem allowlist, the fd it resolves
  to must not be on procfs, sysfs or cgroupfs. This one comes from our own
  tester, not from runc's history. Alpine ships `/etc/mtab -> ../proc/mounts`,
  so a harmless-looking volume on `/etc/mtab` used to cover `/proc/1/mounts`:

  ```text
  $ $R run --bundle $D/mtab m1         # a bind mount onto /etc/mtab
  rustlet-runc: error: container init failed: invalid config.json: mount bind $D/fake-mounts on /etc/mtab: the destination resolves (through a symlink in the rootfs) to a file on procfs; mounts may not cover the kernel's files
  ```

Tests: `hd_mounts_under_proc_and_sys_are_refused`,
`hd_proc_and_sysfs_elsewhere_are_refused`,
`hd_mount_destinations_are_checked_after_following_symlinks`.

## 7. Rule 4: trusting a file because of its name

[CVE-2025-31133](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2):
masked files are hidden by bind-mounting `/dev/null` over them, and runc did not
adequately verify that the source inode was the real null device. A racing
process could substitute a symlink (making the mask a
writable bind of something else) or delete it (making the mask silently not
happen).
[CVE-2025-52565](https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r)
is the same mistake with `/dev/console`: runc bind-mounted `/dev/pts/$n` there
by name, before masked and read-only paths were in place. Both were fixed in
runc 1.2.8, 1.3.3 and 1.4.0-rc.3.

A name in a filesystem the container can touch says nothing about what the
file is. So Rustlets opens the thing once and checks the inode it got:

* **`/dev/null`**: opened `O_PATH | O_NOFOLLOW` with
  `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, then `fstatx`. It must be a character
  device 1:3, or the container doesn't start. Each file mask is
  a bind *of that fd* (`open_tree(fd, "", AT_EMPTY_PATH)`), so no name is looked
  up again ([`paths::open_dev_null`](../../crates/rustlet-runtime/src/paths.rs)).
  A spec that binds a regular file onto `/dev/null`:

  ```text
  $ $R run --bundle $D/devnull n1
  rustlet-runc: error: container init failed: /dev/null is not the null device (file type 0o100000, device 0:0); refusing to bind it over masked paths
  ```

* **the console**: the PTY slave is never opened by name. It comes from the
  master with `TIOCGPTPEER`, and the bind onto `/dev/console` goes from that fd
  onto an `O_PATH` fd for the target (chapter 05). For `exec -t`, the master
  comes from `/dev/pts/ptmx` opened with `RESOLVE_NO_SYMLINKS` and
  `O_NONBLOCK`, and it must be on devpts. Whatever the container has put at
  `/dev/ptmx` by then doesn't matter (`rr_exec_tty_ignores_a_replaced_dev_ptmx`).

Test: `hd_a_fake_dev_null_fails_the_create`.

## 8. Rule 4: writing to `/proc`, CVE-2025-52881

[GHSA-cgrx-mc8f-2prm](https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm):
runc wrote to procfs files (LSM labels, sysctls, …) without checking that the
target was still the procfs file it meant. With shared mounts, those writes
could be redirected to *other* procfs files. A write of a label or a sysctl
value landing on, say, `/proc/sys/kernel/core_pattern` is a host-wide change.
runc's fix moved to fd-based, verified procfs access (`filepath-securejoin`'s
procfs API).

Rustlets' sysctl writes and the exec child's `oom_score_adj` write use a
private procfs handle rather than paths through the container's mounted `/proc`.
[`ProcHandle`](../../crates/rustlet-runtime/src/proc_handle.rs) is a procfs
instance of our own (`fsopen("proc")` + `fsmount`): a **detached** mount,
attached to no directory, so there is nowhere to mount anything over or inside
it. Every lookup starts at its root fd with `RESOLVE_BENEATH | RESOLVE_NO_XDEV
| RESOLVE_NO_SYMLINKS`, and the result must be on procfs (`fstatfs`). For init,
the parent sets `oom_score_adj` through its own host `/proc/<pid>` after init
requests its limits; that path is outside the container's mount namespace.

With `net.ipv4.ip_forward=1` in the spec, the container receives the value and
its `/proc/sys` is read-only when the program runs:

```text
$ $R run --bundle $D/sysctl s1   # sh -c 'cat /proc/sys/net/ipv4/ip_forward; grep " /proc/sys " /proc/self/mountinfo | cut -d" " -f5,6'
1
/proc/sys ro,nosuid,nodev,noexec,relatime
$ cat /proc/sys/net/ipv4/ip_forward     # the host's own
0
```

Those outputs verify namespace isolation and the final read-only mount. They
do not by themselves prove which path the earlier write used: init applies
sysctls before read-only paths. The `ProcHandle` code and the trace experiment
below establish that the write uses the detached procfs handle.

Tests: `hd_net_sysctls_are_applied_inside_only`,
`hd_sysctl_keys_cannot_escape_their_subtree`.

## 9. Rule 5: capabilities nobody asked for

[CVE-2022-24769](https://github.com/moby/moby/security/advisories/GHSA-2mm7-x5h6-5pvq)
(Docker) and [CVE-2022-29162](https://github.com/opencontainers/runc/security/advisories/GHSA-f3fp-gc8g-vw66)
(runc): containers were started, and `runc exec --cap` added capabilities,
with a **non-empty inheritable set**. This could let a program gain a capability
that appeared in both its process inheritable set and a binary's inheritable
file capabilities, even when its own permitted set was empty. Both advisories
describe a privilege-separation problem inside the container, not an expansion
beyond the container's configured bounding set. The fixes:
inheritable is empty by default, and `runc spec` and `exec --cap` never add to it.
Chapter 06 §2 reproduces the effect with a file-capability `nc`.

Rustlets' default spec has an empty inheritable set. Since Phase 2c, `CAP_MKNOD`
is allowed only with a device filter or a new user namespace that independently
blocks character/block device creation (chapter 10). Rustlets' own first
`exec --cap` added the capability to inheritable and ambient for non-root
users; adding to inheritable repeated the pre-1.1.2 runc mistake. That was
found while checking these advisories for this chapter, and fixed (commit
`edd0ea9`). `--cap` now adds to bounding, effective and permitted, and to ambient
only where the spec's inheritable set already has it:

```text
$ $R exec -u 1000 --cap NET_BIND_SERVICE web sh -c 'grep -E "CapInh|CapAmb" /proc/self/status; nc -l -p 80'
CapInh:	0000000000000000
CapAmb:	0000000000000000
nc: bind: Permission denied
```

A non-root process that needs a capability gets it through an explicit
`process.json` with inheritable and ambient set (chapter 06 §3). Test:
`ex_cap_never_adds_inheritable_so_a_non_root_user_gains_nothing`.

The lesson from Rustlets' own bug: rules like these are easy to state and easy
to miss in another code path. Each defence in this chapter has a
test that exercises it. The `/dev` finding in §5 shows why passing those tests
still needs independent review of combinations they do not cover.

## 10. The same thinking, without a CVE

A few more Phase 2b defaults come from the same rules, though nothing
announced a vulnerability for them:

* **a session keyring per container** (`_ses.<id>`): a session keyring is
  inherited across `fork` and `execve`; namespace creation does not give a
  container a fresh one automatically. Init joins its named keyring and exec
  joins the same one (`hd_each_container_gets_its_own_session_keyring`;
  [kernel keyring documentation](https://docs.kernel.org/security/keys/core.html));
* **seccomp and `no_new_privs` on by default**, which shrink what a container
  can ask of the kernel in the first place (chapter 07);
* **`HOME` from the container's `/etc/passwd`**: that file belongs to the image,
  so it is opened non-blocking, only read if it's a regular file, and at most
  1 MiB (`rr_fifo_passwd_does_not_hang`);
* **the exec parent sets the name `rustlet-exec` before cloning**, so the child
  inherits it until `execve`. A child killed during setup is reported as a
  failure, not as a program that ran
  (`rr_exec_killed_before_execve_fails`).

## Try it

Run this Bash recipe from the project root after `cargo xtask rootfs`. It
creates scratch configurations, uses the existing Alpine rootfs read-only,
and demonstrates the sealed binary, fd handling and rejected mounts. The
intentional failures are expected to return nonzero.

```sh
cargo build -p rustlet-runc
project_dir=$PWD
scratch_dir=$(mktemp -d /tmp/rustlet-ch08.XXXXXX)
R() { sudo "$project_dir/target/debug/rustlet-runc" --root /run/rustlet/doc-08 "$@"; }
jq --arg r "$project_dir/.rustlet-dev/bundles/alpine/rootfs" \
   '.root.path = $r | .process.terminal = false | .process.args = ["sleep", "300"]' \
   "$project_dir/.rustlet-dev/bundles/alpine/config.json" > "$scratch_dir/config.json"
R create --bundle "$scratch_dir" c1
pid=$(R state c1 | jq .pid); sudo readlink "/proc/$pid/exe"            # sealed copy
R exec c1 sh -c 'cat /proc/1/environ'                                  # permission denied
R exec c1 ls -l /proc/self/fd                                        # stdio and ls's own fd
R delete --force c1
mkdir "$scratch_dir/mtab" "$scratch_dir/null"
jq '.process.args = ["true"] | .mounts += [{"destination": "/etc/mtab",
   "type": "bind", "source": "/etc/hostname", "options": ["bind", "ro"]}]' \
   "$scratch_dir/config.json" > "$scratch_dir/mtab/config.json"
R run --bundle "$scratch_dir/mtab" m1                                 # resolves to procfs: refused
jq '.process.args = ["true"] | .mounts += [{"destination": "/dev/null",
   "type": "bind", "source": "/etc/hostname", "options": ["bind"]}]' \
   "$scratch_dir/config.json" > "$scratch_dir/null/config.json"
R run --bundle "$scratch_dir/null" n1                                 # not the null device: refused
rm "$scratch_dir/config.json" "$scratch_dir/mtab/config.json" "$scratch_dir/null/config.json"
rmdir "$scratch_dir/mtab" "$scratch_dir/null" "$scratch_dir"
```

## Check yourself

1. Why is `PR_SET_DUMPABLE=0` not enough to stop CVE-2019-5736, and why does
   the sealed memfd also have to be *sealed*, not just a copy?
2. The exec child is non-dumpable, so a root process in the container can't
   read its fds. Why does the parent still stay out of the container's mount
   namespace?
3. With every runtime fd close-on-exec from birth, what is
   `close_range(CLOSE_RANGE_CLOEXEC)` still for?
4. `RESOLVE_IN_ROOT` confines a lookup to the rootfs. Why also mount onto the
   resulting fd instead of the path it resolved to?
5. Rustlets checks mount destinations as written *and* as resolved. Give a spec
   that only the second check catches, using nothing but Alpine's own files.
6. What does the sysctl demo verify, and why does its final read-only mount
   not prove which path the earlier write used? What evidence does establish it?
7. Why can a tmpfs filesystem-type check pass even when `/dev` is no longer
   the fresh mount the runtime created? How does the review finding in §5
   differ from a path escaping `RESOLVE_IN_ROOT`?

## Experiments

- **Watch the fd-based mounts.** `sudo strace -f -e trace=openat2,open_tree,fsopen,fsmount,move_mount
  ./target/debug/rustlet-runc --root /run/rustlet/doc-08 run --bundle DIR x`
  (with `args: ["true"]`) shows every mount built detached, every target
  resolved with `RESOLVE_IN_ROOT`, and `move_mount(…, MOVE_MOUNT_F_EMPTY_PATH |
  MOVE_MOUNT_T_EMPTY_PATH)` joining the two fds. How many `openat2` calls use
  `RESOLVE_NO_SYMLINKS`, and what are they for? Replace `DIR` with a scratch
  bundle directory; the recipe above deletes its scratch bundles when done.
- **Find the private procfs.** In the same trace, find the `fsopen("proc")`
  whose mount is never attached. Which writes use it, and which `openat2` flags
  do they carry?
- **Break the /dev/null check yourself.** Replace the bind of `/etc/hostname`
  in the "Try it" `null` bundle with one of `/dev/zero` (another character
  device). Which part of the check refuses it, and why would a check on "is a
  character device" alone not be enough?
