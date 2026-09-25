# 03 — `/proc`, `/dev`, `/sys`, and the last mile to `execve`

Chapter 02 built the container's mount table and switched into it. This
chapter covers the pseudo-filesystems every Linux program expects to find
there, and the final steps container init takes before it becomes the user's
program. It ends with the parent's side: how `rustlet-runc` learns whether
`execve` worked, and what it does with signals while the container runs.

Code: [`rootfs.rs`](../../crates/rustlet-runtime/src/rootfs.rs) (`populate_dev`),
[`process.rs`](../../crates/rustlet-runtime/src/process.rs),
[`init.rs`](../../crates/rustlet-runtime/src/init.rs),
[`run.rs`](../../crates/rustlet-runtime/src/run.rs),
[`sync.rs`](../../crates/rustlet-runtime/src/sync.rs).

## Pseudo-filesystems are views of namespaces

The kernel generates `/proc`, `/sys` and `/sys/fs/cgroup` on demand, and
**each mount instance is bound to a namespace, chosen when it is mounted**.
That's why the container can't simply inherit the host's copies: they would
keep showing the host. Each one is a fresh `fsopen` from *inside* the new
namespaces:

| mount | tied to | the container sees |
|---|---|---|
| `proc` at `/proc` | the PID namespace of the process calling `fsopen("proc")` | only its own processes |
| `sysfs` at `/sys` | the network namespace of the caller | only its own network devices |
| `cgroup2` at `/sys/fs/cgroup` | the cgroup namespace of the caller | its own cgroup as the root |
| `mqueue` at `/dev/mqueue` | the IPC namespace of the caller | only its own POSIX message queues |
| `devpts` at `/dev/pts` | nothing: `newinstance` gives a private instance | only PTYs opened inside the container |

That's also why the namespaces must exist *before* the mounts. The steps in
`init.rs` go "unshare cgroup ns → assert new mount ns → rootfs setup", and
`clone3` has already created the rest.

## `/proc`

```sh
/ # ls /proc | grep -E '^[0-9]+$'
1
```

With `ls` itself as PID 1, it is the only process in the container's PID
namespace, and a procfs mounted from inside that namespace lists nothing else.
`/proc/self` resolves to PID 1.

The generated spec mounts it `nosuid,noexec,nodev`. runc's default spec uses
no options at all; Docker adds all three, and there's never a reason to execute
or honour setuid bits on procfs.

What Phase 1 does **not** do yet is hide the dangerous parts of `/proc`. With
full root capabilities (see below), the container can still write
`/proc/sysrq-trigger` (for example, to reboot the host), read `/proc/kcore`
(kernel memory), or change `/proc/sys/*`. Phase 2b masks those
(`linux.maskedPaths` / `readonlyPaths`) and drops the capabilities that make
them usable.

## `/sys` and `/sys/fs/cgroup`

```sh
/ # ls /sys/class/net
lo
```

sysfs was mounted from inside the new network namespace, so it only shows that
namespace's devices: a loopback nobody has brought up yet. (Phase 5 moves a
veth into it.) The mount is read-only: a container has no business changing
kernel objects.

```sh
/ # cat /proc/self/cgroup
0::/
```

That line is the cgroup namespace at work. On the host, the same process is at
something like `0::/user.slice/…`. The container sees its cgroup as the root,
and the cgroup2 mount at `/sys/fs/cgroup` shows only that subtree, read-only.
If it were writable, root in the container could raise its own `memory.max`.

Why does init call `unshare(CLONE_NEWCGROUP)` itself instead of passing the
flag to `clone3`? A cgroup namespace is rooted at the cgroup the process is in
*when the namespace is created*, so creating it only after the process has
been placed in its cgroup is correct on every kernel. The usual argument
(runc's) is that `clone3` would create namespaces before applying
`CLONE_INTO_CGROUP`, rooting the namespace at the *parent's* cgroup. Chapter
04 tests that claim on this host's 7.0 kernel and finds a combined `clone3`
gets it right too. The order still costs nothing, so it stays.

## `/dev`: a tmpfs we fill ourselves

`/dev` is a small tmpfs (`mode=755,size=65536k`), **not** the host's
devtmpfs. devtmpfs is a single global instance listing every device the
kernel has, disks included.
[`populate_dev`](../../crates/rustlet-runtime/src/rootfs.rs) creates the six
devices the OCI spec guarantees, plus the standard symlinks:

```text
/ # ls -l /dev
lrwxrwxrwx  1 root root      13 fd -> /proc/self/fd
crw-rw-rw-  1 root root  1,   7 full
drwxrwxrwt  2 root root      40 mqueue
crw-rw-rw-  1 root root  1,   3 null
lrwxrwxrwx  1 root root       8 ptmx -> pts/ptmx
drwxr-xr-x  2 root root       0 pts
crw-rw-rw-  1 root root  1,   8 random
drwxrwxrwt  2 root root      40 shm
lrwxrwxrwx  1 root root      15 stderr -> /proc/self/fd/2
lrwxrwxrwx  1 root root      15 stdin -> /proc/self/fd/0
lrwxrwxrwx  1 root root      15 stdout -> /proc/self/fd/1
crw-rw-rw-  1 root root  5,   0 tty
crw-rw-rw-  1 root root  1,   9 urandom
crw-rw-rw-  1 root root  1,   5 zero
```

- A device node is just an inode holding a type (`c`/`b`) and a
  (major, minor) number. `1:3` means "the `mem` driver, minor 3", i.e.
  `/dev/null`. The file itself grants nothing: what matters is whether the
  mount allows device access (`nodev`) and, from Phase 2c on, the cgroup
  device filter.
- `populate_dev` **refuses unless `/dev` is a tmpfs** (checked with
  `fstatfs`). It never writes device nodes into the image's own `dev/`
  directory, which is shared, and useless anyway because the rootfs is
  mounted `nodev`.
- The mode is exactly `0666` because init runs with `umask(0)` until just
  before `execve`.
- `/dev/pts` is a **private devpts instance** (`newinstance,ptmxmode=0666,mode=0620,gid=5`).
  PTYs opened in the container appear there and nowhere else. `/dev/ptmx` is
  a symlink to `pts/ptmx`, so programs that open `/dev/ptmx` get *this*
  instance's multiplexer, not the host's.
- `/dev/shm` (its own tmpfs) and `/dev/mqueue` (the IPC namespace's queues)
  complete the set.

Running the same bundle under real `runc` gives an identical `/dev`, except
that runc adds `core -> /proc/kcore`. We leave that out: it's kernel memory,
and Phase 2b masks `/proc/kcore` anyway.

### Why `tty` says "not a tty"

Run an interactive shell and try it:

```text
/ # tty
not a tty
```

stdin *is* a terminal: the shell prints a prompt and reads lines. But it is the
host's `/dev/pts/N`, inherited through `rustlet-runc`. `tty` asks
`ttyname(0)`, which looks the device up under `/dev/pts`, and the container's
private devpts instance has never heard of it. This is the "inherited stdio,
no proper terminal yet" limitation of Phase 1. In Phase 2a, init opens a PTY
*in its own devpts*, makes it the controlling terminal, and hands the master
to the caller over a Unix socket.

## The last mile: from init to `execve`

After `pivot_root`, container init still runs `rustlet-runc`'s code, as root,
in the new namespaces. It has to turn itself into the user's program without
leaking anything of the runtime. The order below is the design; each step can
take away something a later step needs.

### Signals first (`init.rs`)

Two inherited signal properties survive `execve`, and both would be wrong:

- **The blocked mask.** The parent blocks the signals it forwards *before*
  `clone3` (so none can arrive between `clone3` and its `signalfd`; see
  below). The child inherits that mask, and a blocked mask survives `execve`.
  So init restores the original mask first thing.
- **Ignored signals.** On `execve` the kernel resets *caught* signals to
  default (the handler code is about to vanish), but *ignored* ones stay
  ignored. Rust's standard library sets `SIGPIPE` to `SIG_IGN` before `main`,
  so that writing to a closed pipe returns `EPIPE` instead of killing the
  program. `std::process::Command` quietly undoes that in its children. Our
  `clone3` spawn doesn't use `Command`, so without
  [`rustlet_sys::signal::reset_all_to_default`](../../crates/rustlet-sys/src/signal.rs)
  every container would start with SIGPIPE ignored, and `yes | head -1`
  would leave `yes` spinning on `EPIPE`. The integration test
  `nothing_leaks_into_the_container` checks that `SigIgn` and `SigBlk` in
  `/proc/self/status` are all zeros.

`reset_all_to_default` is a nice `unsafe` lesson too. `nix` marks `signal()`
and `sigaction()` `unsafe` because the handler you install runs in signal
context, where only async-signal-safe code is allowed. `SIG_DFL` installs no
code at all, so a wrapper that *only* ever sets `SIG_DFL` is sound as a safe
function. That is precisely the kind of narrowing `rustlet-sys` exists for.

### Process attributes and identity (`process.rs`)

```text
sethostname("rustlet")
setrlimit(...)                      needs CAP_SYS_RESOURCE to *raise* a hard limit
write /proc/self/oom_score_adj      needs CAP_SYS_RESOURCE to *lower* it
setgroups([...])                    always, even as root: drops rustlet-runc's own groups
setresgid(gid, gid, gid)            needs CAP_SETGID
setresuid(uid, uid, uid)            leaving uid 0 clears every capability
chdir(cwd); getcwd()                as the container user; must be inside the root
close_range(3, ~0, CLOSE_RANGE_CLOEXEC)
prctl(PR_SET_PDEATHSIG, SIGKILL)
prctl(PR_SET_NO_NEW_PRIVS, 1)
umask(0022); execve(...)
```

- **Groups, then gid, then uid.** Both group calls need `CAP_SETGID`, and
  switching the uid away from 0 drops all capabilities (without
  `PR_SET_KEEPCAPS`). So uid goes last. The test
  `user_switch_drops_all_capabilities` runs as 1000:1000 and checks that
  `CapEff` is all zeros. Phase 2b inserts `PR_SET_KEEPCAPS` and `capset` in
  the middle of this sequence, to keep a chosen set.
- **The cwd check** exists because of CVE-2024-21626. runc leaked an fd for a
  host directory into container init, and a `cwd` of `/proc/self/fd/7` put
  the container's working directory *outside* its root. If the cwd is
  unreachable from the root, the kernel reports it as `(unreachable)/…`,
  which glibc's `getcwd` turns into `ENOENT`, and init refuses to go on.
- **`close_range(…, CLOSE_RANGE_CLOEXEC)`** marks every fd above stderr
  close-on-exec. Nothing is closed *now*, so no `OwnedFd` in init is pulled
  out from under Rust (which is why the `rustlet-sys` wrapper only offers
  this mode). At `execve`, the kernel closes them all. The test checks that
  the container sees only fds 0, 1 and 2.
- **`PR_SET_PDEATHSIG(SIGKILL)`**: in foreground `run`, if `rustlet-runc`
  dies, the container dies with it rather than lingering as an orphan (test:
  `container_dies_with_rustlet_runc`). It is set late on purpose, because the
  kernel clears it when credentials change.
- **`$PATH` lookup** happens inside the container, with the container's
  `PATH` (or the usual default), because `execve` itself doesn't search.
  If the program isn't found, `rustlet-runc` exits 127, and 126 if it can't
  be executed, the same convention as a shell.

## The parent's side

### Knowing whether `execve` worked: the CLOEXEC trick

Init reports failures to `rustlet-runc` over a
`socketpair(AF_UNIX, SOCK_SEQPACKET)` ([`sync.rs`](../../crates/rustlet-runtime/src/sync.rs)).
`SEQPACKET` is message-oriented: every `send` arrives as exactly one `recv`.
But how does the parent learn about *success*? After `execve`, the user's
program certainly won't say anything.

The child's end of the socket is `O_CLOEXEC`. The kernel closes it at the
instant `execve` succeeds, so the parent's `recv` returns 0 (end of file).
Either the parent reads an error message, or it reads EOF, meaning the program
is running. There's no timeout and no polling. Rust's `std::process::Command`
reports exec failures the same way, through a close-on-exec pipe.

Errors cross the socket as JSON (`{"type":"error","message":…,"errno":2}`), so
you get a message with context, not just a number:

```text
rustlet-runc: error: cannot run the program: executable file not found in $PATH: "no-such-program" (PATH=/usr/local/sbin:…)
```

`MSG_NOSIGNAL` on `send` matters here: init has just reset SIGPIPE to its
default action, so writing to a socket whose reader has died would otherwise
kill init with a confusing status.

### Signals while the container runs

`rustlet-runc` and the container share a terminal and, in Phase 1, a process
group. Signals come from two directions ([`run.rs`](../../crates/rustlet-runtime/src/run.rs)):

- **The terminal driver** sends Ctrl-C (`SIGINT`), Ctrl-\ (`SIGQUIT`) and
  window-size changes (`SIGWINCH`) to the whole *foreground process group*,
  so the container gets them directly. Forwarding them again would deliver
  them twice. They arrive with `si_code == SI_KERNEL`, which is how
  `rustlet-runc` tells them apart.
- **Everyone else** (`kill <pid of rustlet-runc>`, systemd stopping a unit)
  signals only `rustlet-runc`. Those are forwarded to container init with
  `pidfd_send_signal`, which, unlike `kill(pid)`, can't hit an unrelated
  process that happened to reuse the PID.

The parent blocks these signals, reads them from a `signalfd`, and `poll`s it
together with the container's pidfd. A pidfd becomes readable when its
process exits, so a single `poll` waits for both.

### PID 1 is special

```sh
$ sudo rustlet-runc run … # with args: sh -c 'kill -TERM $$; kill -KILL $$; echo still-here'
still-here
```

Inside its PID namespace, init only receives signals **it has installed a
handler for**. The kernel protects init from its own namespace, and that
includes `SIGKILL`. From an *ancestor* namespace (the host), `SIGKILL` and
`SIGSTOP` always get through, but everything else is still dropped unless
there's a handler. So `sleep 100` as PID 1 ignores `docker stop`'s SIGTERM,
and the container runtime's escalation to SIGKILL is what finally ends it.
That's the reason `docker run --init` (tini) exists, and it's why
`sigterm_to_runc_is_forwarded_to_init` uses a shell with a `trap`.

The exit status comes back shell-style: the exit code, or 128 + the signal
number (`kill -KILL` from the host gives 137).

## Phase 1's honest limits

Everything so far is **isolation of views**: its own processes, hostname,
network devices, mount table, IPC. It is **not yet a security boundary**.
Container root keeps all of host root's capabilities: it could load a kernel
module, `mknod` a node for `/dev/sda` in `/dev` (a tmpfs without `nodev`), or
write `/proc/sysrq-trigger`. `rustlet-runc` prints a warning on every run to
keep that in view. The next phases close these gaps:

| phase | adds |
|---|---|
| 2a | cgroups (limits, freeze, kill, OOM), create/start/state/kill/delete, a real PTY + console socket |
| 2b | capabilities, seccomp, masked and read-only `/proc` paths, sysctls, memfd self-re-exec, `exec` |
| 2c | user namespaces, the eBPF device filter (after which `--device` and `MKNOD` become safe) |

`config.json` fields for those features are **refused** now, not ignored:

```text
rustlet-runc: error: config.json uses features this build does not support yet:
  - linux.seccomp (Phase 2b)
```

Silently skipping `linux.seccomp` would run a container with less isolation
than its author asked for. That is a worse failure than not running it at all.

## Check yourself

1. Why can't the container simply keep the host's `/proc` mount? What would
   `ls /proc` show, and what would `/proc/self` point to?
2. `populate_dev` refuses to run unless `/dev` is a tmpfs. Name two things
   that would go wrong if it created the nodes in the image's `dev/` instead.
3. Why must `setresuid` come after `setgroups` and `setresgid`? What happens to
   the capability sets when a process with uid 0 switches all its uids to 1000?
4. The parent treats EOF on the sync socket as "execve succeeded". What would
   break if the child's end of the socket were *not* close-on-exec?
5. Ctrl-C in a foreground container: who sends SIGINT to whom, and why doesn't
   `rustlet-runc` forward it?

## Experiments

- Compare `grep -E '^(SigIgn|SigBlk|CapEff|NoNewPrivs)' /proc/self/status`
  in your host shell, inside the container, and inside `sudo runc run` of the
  same bundle.
- In the container: `readlink /proc/self/fd/0` shows a host path that doesn't
  exist in the container. Then `ls /dev/pts` (empty apart from `ptmx`). Why?
- Remove the `/dev` tmpfs mount from `config.json` and run it. Read the error,
  then find the check in `rootfs.rs`.
- Start `sh -c 'trap "echo got TERM; exit 7" TERM; while :; do sleep 1; done'`
  as the container's args, then `kill -TERM` and `kill -INT` the
  `rustlet-runc` process from another terminal. Now press Ctrl-C in the
  container's own terminal instead: why does the shell ignore it?
