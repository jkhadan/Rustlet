# 01 — Namespaces: a first look

To the kernel, a container is just an ordinary process with a narrowed view of the system: its own PIDs, its own hostname, its own mount table, its own network. Namespaces provide that narrowed view. This chapter introduces them through the Phase 0 experiment, [`hello_ns.rs`](../../crates/rustlet-sys/examples/hello_ns.rs), which starts a child in new PID, UTS and mount namespaces. It also shows the rule that surprises everybody: `unshare(CLONE_NEWPID)` does not move the process that calls it.

The experiment contains no `unsafe` (`#![forbid(unsafe_code)]`). Everything goes through the wrappers in `rustlet-sys`, and the second half of this chapter looks at why those wrappers can be safe at all.

Build as your user, then run as root from the repo root:

```sh
cargo build -p rustlet-sys --example hello_ns
sudo ./target/debug/examples/hello_ns             # variant A: clone3
sudo ./target/debug/examples/hello_ns --unshare   # variant B: unshare, then fork
```

All output below is real, captured on this machine (kernel `7.0.0-34-generic`).

## 1. What a namespace is

Many things in Linux are global: one hostname, one table of mounts, one sequence of PIDs, one set of network interfaces. A namespace turns one of those global resources into a per-group resource. Every process belongs to exactly one namespace of each kind, and when it asks about that resource it sees its own namespace's copy. Two processes in different UTS namespaces can have different hostnames, and two processes in different PID namespaces can both be PID 1.

There are eight kinds:

| Kind | Flag | What becomes per-namespace |
|---|---|---|
| `mnt` | `CLONE_NEWNS` | the mount table: which filesystem is mounted where |
| `uts` | `CLONE_NEWUTS` | hostname and NIS domain name (what `uname(2)` reports) |
| `ipc` | `CLONE_NEWIPC` | System V IPC objects and POSIX message queues |
| `pid` | `CLONE_NEWPID` | process ID numbers |
| `net` | `CLONE_NEWNET` | interfaces, addresses, routes, firewall rules, ports |
| `user` | `CLONE_NEWUSER` | UIDs/GIDs and what capabilities mean |
| `cgroup` | `CLONE_NEWCGROUP` | which cgroup directory looks like the root `/` |
| `time` | `CLONE_NEWTIME` | offsets for `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` (Linux 5.6) |

The mount flag is called `CLONE_NEWNS`, "new namespace", because mount namespaces came first and nobody expected there to be others. The same eight flags, as typed values, are `CloneFlags::NEW*` in [process.rs](../../crates/rustlet-sys/src/process.rs).

Every process shows its memberships under `/proc/<pid>/ns/`. Here `/proc/self` is the `ls` process itself, on the host:

```text
$ ls -l /proc/self/ns
total 0
lrwxrwxrwx 1 james james 0 Sep 25 04:08 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 ipc -> ipc:[4026531839]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 mnt -> mnt:[4026531832]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 net -> net:[4026531833]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 pid -> pid:[4026531836]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 pid_for_children -> pid:[4026531836]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 time -> time:[4026531834]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 time_for_children -> time:[4026531834]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 user -> user:[4026531837]
lrwxrwxrwx 1 james james 0 Sep 25 04:08 uts -> uts:[4026531838]
```

These are "magic links". `readlink` returns a label like `mnt:[4026531832]`, but `open` doesn't follow that text. It gives you a file descriptor for the namespace itself, which is what `setns` takes. The files live on an internal filesystem, nsfs (`stat -f` reports `nsfs`, device `0,5` here). **A namespace's identity is the (device, inode) pair of its nsfs file**, and the number in brackets is the inode. Two processes share a namespace exactly when their links `stat` to the same pair. `rustlet-sys` wraps this as [`procfs::ns_id`](../../crates/rustlet-sys/src/procfs.rs):

```rust
/// Identity of a namespace: (device, inode) of its nsfs file.
pub fn ns_id(pid: Option<Pid>, kind: &str) -> Result<(u64, u64)> {
    // ...
    let m = std::fs::metadata(p).map_err(io_errno)?;
    Ok((m.dev(), m.ino()))
}
```

`std::fs::metadata` is `stat`, not `lstat`, so it follows the magic link to the namespace. `hello_ns` prints only the inode (`.1`) to keep its lines short, but its safety check compares the whole pair.

`pid_for_children` and `time_for_children` are the two odd ones out: for those kinds, a process's future children can be in a different namespace from the process itself. Section 4 explains why.

Two practical notes. On this kernel the initial namespaces have fixed numbers just below 4026531840 (`0xF0000000`), and namespaces created later get numbers from a pool above that, so a `40265318xx` number means "a host namespace". Also, a namespace lives as long as something refers to it: a member process, an open fd on its nsfs file, or a bind mount of that file. That last trick is how `ip netns add` works, and how `rustletd` will pin network namespaces under `/run/rustlet/netns/` ([architecture.md](../architecture.md) §1, choice 4).

## 2. Three ways in

| Call | Who ends up in the namespace |
|---|---|
| `clone`/`clone3` with `CLONE_NEW*` | the new child, which is *born* inside, before its first instruction |
| `unshare(CLONE_NEW*)` | the *caller* moves into fresh namespaces (for `pid` and `time`, only its future children) |
| `setns(fd, nstype)` | the caller *joins an existing* namespace, given as an fd |

`setns` takes either an fd from opening `/proc/<pid>/ns/<kind>` (one namespace), or, since Linux 5.8, a **pidfd**. With a pidfd, `nstype` can hold several `CLONE_NEW*` bits, and the caller joins all of those namespaces of the target process in one atomic step. Phase 2b's `exec` uses exactly this ([architecture.md](../architecture.md) §2.2, step 6). Like `unshare`, `setns` into a PID namespace affects only the caller's future children. Joining a mount or user namespace requires a single-threaded caller.

In `rustlet-sys` the last two are:

```rust
pub fn unshare(flags: CloneFlags) -> Result<()>
pub fn setns(fd: BorrowedFd<'_>, flags: CloneFlags) -> Result<()>
```

Both pass the flags through `CloneFlags::ns_bits`, which returns `EINVAL` if anything other than namespace bits is set. That way a clone3-only flag like `PIDFD` can't slip into `unshare`.

## 3. Why `clone3`

`fork()` creates a child in the parent's namespaces. `clone()` is `fork` with flags, and `clone3()` (Linux 5.3) is `clone` with a struct. `rustlet-sys` uses `clone3` for three reasons.

**`CLONE_PIDFD`: a handle instead of a number.** A PID is a number, and numbers get reused. The PID of your own child stays valid until you reap it (the zombie holds the number). But anything that keeps the PID for later, such as a state file, another process, or a `SIGCHLD` handler that already reaped the child, can end up signalling a stranger that was given the recycled number. A pidfd is a file descriptor that refers to one specific process. Once that process is gone, operations on the pidfd fail with `ESRCH` instead of hitting someone else. A pidfd also becomes readable when the process exits, so it can sit in `poll` next to other fds. `hello_ns` waits on it with `waitid(P_PIDFD, …)` (Linux 5.4). The old `clone()` has `CLONE_PIDFD` too (5.2), but it has to reuse the `parent_tid` argument for it. `clone3` gives it a dedicated field.

**`CLONE_INTO_CGROUP` (5.7): limits before the first instruction.** Without it, you fork and then write the child's PID into `cgroup.procs`. In between, the child runs, and can fork, with no limits. With `CLONE_INTO_CGROUP` the child starts inside the cgroup. Rustlets uses this from Phase 2a (`Clone3::into_cgroup`).

**A struct-based API.** The old `clone()` packs the exit signal into the low byte of its flags word, and the kernel reads only the low 32 bits of that word. Both new flags are therefore clone3-only: `CLONE_NEWTIME` is `0x80`, inside the exit-signal byte, and `CLONE_INTO_CGROUP` is `0x2_0000_0000`, bit 33. `clone3` takes a `struct clone_args` plus its size, and the size tells the kernel which version of the struct the caller speaks: 64 bytes (5.3), 80 (5.5, adds `set_tid`), or 88 (5.7, adds `cgroup`). The Rust mirror is `#[repr(C)]` so the compiler can't reorder the fields:

```rust
/// `struct clone_args` from `<linux/sched.h>` (size version 2, 88 bytes).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
```

A unit test pins the size: `assert_eq!(size_of::<CloneArgs>(), 88); // CLONE_ARGS_SIZE_VER2 == 88`. `Clone3::spawn` fills the struct and calls `libc::syscall(libc::SYS_clone3, &raw mut args, size_of::<CloneArgs>())`. `strace -f` shows the call that `hello_ns` makes (strace's own messages removed):

```text
clone3({flags=CLONE_PIDFD|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWPID, pidfd=0x7ffdb0639c34, exit_signal=SIGCHLD, stack=NULL, stack_size=0} => {pidfd=[3]}, 88) = 32274
```

`88` is the size argument, `=> {pidfd=[3]}` is the fd the kernel wrote back, and `stack=NULL` means the child continues on its copy of the parent's stack, exactly as after `fork`. That call comes from one line of `hello_ns`:

```rust
Clone3::new().flags(flags | CloneFlags::PIDFD).spawn().expect("clone3")
```

## 4. The two runs, line by line

### Variant A: `clone3`

```text
parent: pid 32071 hostname "james-mint"
parent:  pid ns inode 4026531836
parent:  uts ns inode 4026531838
parent:  mnt ns inode 4026531832
parent: child has pid 32072 in *my* PID namespace
  child: getpid() = 1
  child:  pid ns inode 4026532473
  child:  uts ns inode 4026532470
  child:  mnt ns inode 4026532469
  child: hostname is now "hello-ns"
  child: my /proc lists 1 process(es): [1]
  child: /proc/self/status NSpid: 1
parent: child finished: Exited { pid: Pid(32072), code: 0 }
parent: my hostname is still "james-mint"
parent: host /proc still lists 217 processes (the child's /proc mount never reached us)
```

- **Lines 1–4:** the parent is in the host namespaces. The inodes match the `ls -l` listing above.
- **`child has pid 32072`:** `clone3` returned 32072 to the parent. This line comes out before the child's lines only because of scheduling. Nothing orders the two processes' output.
- **`getpid() = 1`:** the same process asks for its own PID and gets 1. A process has one PID in each PID namespace, from its own up to the root: 1 in the new namespace and 32072 in the host's. `getpid()` returns the one from the caller's own namespace.
- **Three child inodes:** all three differ from the parent's. One `clone3` call created three namespaces.
- **`hostname is now "hello-ns"`:** `sethostname` changed the new UTS namespace's copy.
- **`/proc lists 1 process(es): [1]` and `NSpid: 1`:** these come after the child mounted its own `/proc` (section 5). `NSpid` is explained below.
- **`child finished`:** `waitid` on the pidfd. The kernel reports the child's PID as the waiter sees it, 32072.
- **Last two lines:** the host is untouched. The child's hostname and its `/proc` mount lived in namespaces that disappeared when it exited.

### Variant B: `--unshare`

```text
parent: pid 32079 hostname "james-mint"
parent:  pid ns inode 4026531836
parent:  uts ns inode 4026531838
parent:  mnt ns inode 4026531832
parent: after unshare my pid is still 32079 (the new PID ns is for my children)
parent: but I am already in the new uts ns 4026532470 and mnt ns 4026532469
parent: child has pid 32080 in *my* PID namespace
  child: getpid() = 1
  child:  pid ns inode 4026532473
  child:  uts ns inode 4026532470
  child:  mnt ns inode 4026532469
  child: hostname is now "hello-ns"
  child: my /proc lists 1 process(es): [1]
  child: /proc/self/status NSpid: 1
parent: child finished: Exited { pid: Pid(32080), code: 0 }
parent: my hostname is now "hello-ns" too: unshare moved me into the new UTS ns
parent: and I see the child's /proc (0 processes left in that PID ns)
```

- **`after unshare my pid is still 32079`:** `unshare(CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNS)` succeeded, but the caller's PID and PID namespace did not change.
- **`already in the new uts ns … and mnt ns …`:** for UTS and mount, `unshare` moved the caller immediately.
- **The child's inodes:** its UTS and mount inodes are *the same* numbers the parent just printed. `fork` copies the parent's memberships, so the child simply shares the parent's new UTS and mount namespaces. Only its PID namespace, 4026532473, differs from the parent's. `unshare` created that namespace, and the child is the first process in it.
- **`my hostname is now "hello-ns" too`:** parent and child share one UTS namespace, so the child's `sethostname` changed it for both. The host keeps `james-mint` because the parent had already left the host's UTS namespace.
- **`0 processes left`:** parent and child also share one mount namespace, so the parent's `/proc` is now the child's procfs. That procfs shows the child's PID namespace, whose only process has exited.

About the numbers: yours will differ, and they can differ between runs on the same machine too. A namespace's number is freed when the namespace dies and handed out again later. That is why both runs above show 4026532473 for the child's PID namespace, and why a later `--unshare` run here got 4026532474. Only compare numbers taken at the same moment.

### Why the PID namespace is different

Swapping most namespace memberships is harmless: the kernel just follows a different pointer the next time the process asks about hostnames or mounts. A PID is different. It is allocated when the process is created, one number for each level of PID namespace, and the parent's `wait`, PID files and other processes' `kill` all depend on it staying the same. So the kernel never changes a running process's PID namespace. `unshare(CLONE_NEWPID)` instead changes `pid_for_children`, the namespace the caller's *future* children are born into. Until the first child exists, `readlink /proc/self/ns/pid_for_children` fails with `ENOENT`, because the namespace has no PID 1 yet. Time namespaces follow the same pattern (`time_for_children`).

The first process born into a new PID namespace becomes its PID 1, the namespace's init. That role is special. Orphans in the namespace are re-parented to it. Signals it has no handler for are ignored, except `SIGKILL` and `SIGSTOP` sent from an ancestor namespace (Phase 1's [run.rs](../../crates/rustlet-runtime/src/run.rs) notes the consequence). **When it exits, the kernel kills every other process in the namespace, and any later `fork(2)` into the namespace fails with `ENOMEM`.** This is why `unshare --pid` from util-linux needs `--fork`: without it, the shell's first external command becomes PID 1, exits, and the shell cannot start anything else (see the experiments). Variant B forks exactly once and needs nothing more in that namespace, so it never runs into this.

`NSpid` in `/proc/<pid>/status` lists a process's PID in every namespace, starting from the one that *this `/proc` belongs to* and going down to the process's own. The child printed `NSpid: 1` because by then it was reading its own fresh procfs, which knows only the new namespace. Read through the host's `/proc`, the same process would show two numbers. A quick check (`--user --map-root-user` only lets it run without sudo; user namespaces get their own chapter):

```text
$ unshare --user --map-root-user --pid --fork grep NSpid /proc/self/status
NSpid:	37858	1
$ unshare --user --map-root-user --pid --fork --mount-proc grep NSpid /proc/self/status
NSpid:	1
```

## 5. Why a fresh `/proc`

procfs is not a view of one global process table. Each procfs instance is bound to the PID namespace of the process that created it, and it lists that namespace's processes with the PIDs as seen from there. A new mount namespace starts as a copy of its parent's mounts, so until the child mounts its own, its `/proc` is still the host's procfs, and `ps` would list every host process. The same rule explains why the *child* mounts `/proc` even in variant B: the parent is still in the host PID namespace, so a procfs it created would show host processes.

The child uses the new mount API from [mount.rs](../../crates/rustlet-sys/src/mount.rs):

```rust
let proc = FsContext::open("proc").expect("fsopen proc");
let mnt = proc.mount(MountAttr::NOSUID | MountAttr::NODEV | MountAttr::NOEXEC).expect("fsmount");
move_mount(Some(std::os::fd::AsFd::as_fd(&mnt)), Path::new(""), None, Path::new("/proc"), MoveMountFlags::F_EMPTY_PATH)
```

`strace -f` shows what the child does after it confirms it is in a new mount namespace:

```text
mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) = 0
sethostname("hello-ns", 8)  = 0
fsopen("proc", FSOPEN_CLOEXEC) = 3
fsconfig(3, FSCONFIG_CMD_CREATE, NULL, NULL, 0) = 0
fsmount(3, FSMOUNT_CLOEXEC, MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV|MOUNT_ATTR_NOEXEC) = 4
move_mount(4, "", AT_FDCWD, "/proc", MOVE_MOUNT_F_EMPTY_PATH) = 0
```

`fsopen` creates a filesystem context, which is where procfs records the caller's PID namespace. `FSCONFIG_CMD_CREATE` creates the superblock. `fsmount` returns a *detached* mount: a mount fd that isn't attached anywhere in the tree yet. If that fd were closed now, the mount would simply vanish. `move_mount` with `F_EMPTY_PATH` ("the source is the fd itself") attaches it at `/proc`. The classic `mount(2)` does all of this in one call on paths. Chapter 02 explains why doing it through fds matters.

**Propagation.** The first line of that trace matters more than it looks. On this host:

```text
$ findmnt -no TARGET,PROPAGATION /
/      shared
$ findmnt -no TARGET,PROPAGATION /proc
/proc  shared
```

The kernel's default is `private`, but systemd remounts `/` recursively as `shared` at boot. A shared mount belongs to a *peer group* (`/proc` is `shared:12` in `/proc/self/mountinfo`), and a mount made on one peer is copied to all the others. A new mount namespace copies mounts *together with* their peer groups. Without the first line, the child's copy of `/proc` would still be a peer of the host's `/proc`, so its new procfs would propagate back and cover the host's `/proc` with one that shows only the child's PID namespace. `mount("/", MS_REC|MS_PRIVATE)` takes every mount in the child's namespace out of its peer group, first. Before even that, the child checks that it really is in a new mount namespace, by comparing `ns_id(None, "mnt")` with the `host_mnt` pair the parent recorded before creating anything:

```rust
// Guardrail: never touch mounts unless we really are in a new mount ns.
if procfs::ns_id(None, "mnt").unwrap() == host_mnt {
```

Phase 1's runtime keeps both steps and adds a mountinfo check that nothing is still shared ([architecture.md](../architecture.md) §4). Chapter 02 goes deep on all of this.

## 6. Why `fork` is `unsafe`, and how `rustlet-sys` makes it safe

In `nix`, `fork` is `pub unsafe fn fork()`, and its safety note says: "In a multithreaded program, only async-signal-safe functions like `pause` and `_exit` may be called by the child … until a call of `execve(2)`."

The reason is that `fork` copies the whole address space but only the *calling* thread. Suppose another thread was inside `malloc`, holding the allocator's lock, when you forked. In the child, that lock is a copied, locked mutex whose owner doesn't exist. The child's first allocation waits for it forever, or finds half-updated allocator state. The same goes for the stdout lock and every other `Mutex`. The async-signal-safe functions listed in `signal-safety(7)` are the ones that take no such locks, the same property a signal handler needs, since a handler can also interrupt a thread mid-lock. `Clone3::spawn` has the same problem, because without `CLONE_VM` it is a fork.

`rustlet-sys` removes the precondition instead of passing it on to the caller. Both `Clone3::spawn` and `fork` begin with:

```rust
/// Returns `EDEADLK` unless the caller is the only thread in its process.
pub fn ensure_single_threaded() -> Result<()> {
    match thread_count()? {
        1 => Ok(()),
        _ => Err(Errno::EDEADLK),
    }
}
```

`thread_count` parses the `Threads:` line of `/proc/self/status`. `EDEADLK`, "resource deadlock would occur", names the failure it prevents.

Why a runtime check is enough:

- **The danger comes from other threads.** Locks and half-finished updates belonging to threads that won't exist in the child are the problem. With `Threads: 1`, there are no other threads.
- **None can appear between the check and the syscall.** Only a running thread can create a thread, and the only running thread is executing our check. A signal handler would run on this same thread, and creating threads isn't async-signal-safe anyway.
- **The calling thread's own state is at a known point.** It is inside our function, not halfway through `malloc` or `println!`.
- **The child shares no memory with the parent.** `CloneFlags` has no `CLONE_VM` or `CLONE_THREAD`, and `Clone3` has no stack parameter, so the child gets a copy-on-write copy, as after `fork`.

The argument rests on two assumptions worth knowing. First, `/proc/self/status` must be the real procfs of the caller's own PID namespace. If it can't be read, `thread_count` returns `EIO` and the wrapper refuses, so it fails closed. Second, `CloneFlags` doesn't *name* `CLONE_VM`, but bitflags' public `from_bits_retain` can build a value with any bits. An early version of `spawn` passed `self.flags.bits()` through unfiltered, so "never passes `CLONE_VM`" held by convention, not by construction. `spawn` now returns `EINVAL` unless `CloneFlags::all().contains(self.flags)`, and the unit test `spawn_rejects_unnamed_flags` keeps it that way. The lesson generalizes: a type that *doesn't name* a dangerous value doesn't prove that no such value exists.

This check is also why the architecture keeps `rustlet-runc` single-threaded, and why the multithreaded tokio daemon never forks container processes itself ([architecture.md](../architecture.md) §1, choice 3).

## 7. `_exit`, not `exit`, in the child

```rust
Forked::Child => process::exit_now(child(host_mnt)),
```

```rust
pub fn exit_now(code: i32) -> ! {
    // SAFETY: `_exit` is always safe to call; it never returns.
    unsafe { libc::_exit(code) }
}
```

The child is a copy of the parent, including everything the parent prepared for its own exit: `atexit(3)` handlers registered by C libraries, and whatever sits in stdio buffers. `exit(3)`, which Rust's `std::process::exit` ends up calling, runs those handlers and flushes those buffers. So bytes the parent had buffered at the moment of the fork would be written twice, once by each process, and cleanup meant for the parent would also run in the child. `_exit(2)` ends the process at once: the kernel closes its fds, and that's all (strace shows it as `exit_group(0)`). Rust's stdout is line-buffered even when it goes into a pipe, so each `println!` is written out at its `\n`. That is why the captured output above has no doubled lines. A `print!` without a newline just before the fork would have ended up in both copies of the buffer.

Simply returning would be worse still: the child would carry on with whatever the parent's code does next, and then leave through `exit(3)` anyway. The `-> !` return type means that match arm cannot fall through. Phase 1's `run.rs` goes one step further and wraps the child's work in `catch_unwind`, so a panic can't unwind into parent code either.

## 8. Rust notes

- **I/O safety: `OwnedFd` and `BorrowedFd<'a>`.** A function that creates an fd returns an `OwnedFd`, which closes itself on drop. A function that uses an fd takes a `BorrowedFd<'_>`, and the lifetime proves the fd stays open for the call. The pidfd arrives as `Forked::Parent { pidfd: Option<OwnedFd>, .. }` and is closed automatically at the end of the match arm. `WaitTarget::PidFd(BorrowedFd<'fd>)` can't outlive it. The C bug this rules out is using an fd number after `close`, when some later `open` may already have reused the number. The one place a raw number becomes an `OwnedFd` is the private `owned_fd` helper in [lib.rs](../../crates/rustlet-sys/src/lib.rs).
- **`bitflags`.** `CloneFlags`, `MountAttr` and `MoveMountFlags` are distinct types, so `MS_*` bits can't be passed where `MOUNT_ATTR_*` bits are expected. They support set operations: `flags | CloneFlags::PIDFD`, a `const` `ALL_NAMESPACES` built with `.union(...)`, and `self.flags |= flags - CloneFlags::INTO_CGROUP` in `Clone3::flags`. That last one means `INTO_CGROUP` can only be set through `into_cgroup(fd)`, which also supplies the fd.
- **`// SAFETY:` comments.** Every `unsafe` block says why it is sound, and each block holds exactly one unsafe operation. Clippy enforces both (`undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` are `deny` in `rustlet-sys`'s `Cargo.toml`). The `clone3` block, for example, justifies the struct layout, the one pointer inside it, the absence of `CLONE_VM`, and the single-thread check.
- **`Forked` instead of "returns 0 in the child".** C's `fork` returns one `int` with three meanings: -1 for an error, 0 in the child, the child's PID in the parent. A classic bug is to skip the -1 check and later call `kill(pid, SIGKILL)` with it, and `kill(-1, …)` signals every process you're allowed to signal. Here the error lives in the `Result`, `match` forces you to handle both sides, `Parent` carries the PID and the pidfd, and `Child` carries nothing, so the child has no PID to misuse.

## 9. Where this leads

Phase 1's `rustlet-runc run` ([run.rs](../../crates/rustlet-runtime/src/run.rs)) makes the same call: `Clone3::new().flags(plan.namespaces.clone_flags | CloneFlags::PIDFD).spawn()`. There the flags come from `config.json`: a new namespace for every type listed without a path, and a mandatory new mount namespace (cgroup is handled separately, see [namespaces.rs](../../crates/rustlet-runtime/src/namespaces.rs)). The child repeats `hello_ns`'s guardrail and `MS_REC|MS_PRIVATE`, then builds a whole root filesystem instead of only `/proc`: it bind-mounts the rootfs onto itself, mounts what `config.json` lists (a new `/proc`, `/dev`, `/sys`, …), calls `pivot_root(".", ".")`, and finally `execve`s the container's command. The parent supervises through the pidfd: it `poll`s it for exit and forwards signals with `pidfd_send_signal`. The next chapter, [02 — mounts and `pivot_root`](02-mounts-pivot-root.md), covers the filesystem half.

## Check yourself

1. Right after `unshare(CLONE_NEWUTS | CLONE_NEWPID)`, which of the caller's `/proc/self/ns/*` links have changed, and what does `readlink` on `pid_for_children` return?
2. In variant B, why does the parent end up with hostname `hello-ns` and a `/proc` that lists 0 processes? What would a `fork(2)` into that PID namespace return now?
3. Why must the child, not the parent, mount the new `/proc`, even in variant B where both share a mount namespace?
4. On this host, what exactly would go wrong if the child skipped `MS_REC|MS_PRIVATE`?
5. A program starts a tokio runtime and later calls `Clone3::new().spawn()`, planning to call `execve` immediately in the child. It gets `EDEADLK`. Why is refusing still right?

<details>
<summary>Answers</summary>

1. `uts` points to a new namespace, and `pid` is unchanged. `pid_for_children` fails with `ENOENT` until the first child exists.
2. It shares the child's UTS and mount namespaces, so it sees the child's hostname and the child's procfs, whose PID namespace lost its only process, PID 1. A fork into it fails with `ENOMEM`.
3. A procfs instance belongs to the PID namespace of the process that creates it, and the parent is still in the host PID namespace.
4. `/proc` is `shared` on the host. The new procfs would propagate to the host's `/proc` and cover it with a view of the child's PID namespace.
5. Even getting to `execve` runs Rust code (building `CString`s allocates). A lock held by a tokio worker, malloc's for example, would never be released in the child. The wrapper can't know what the caller will do in the child, so it refuses.
</details>

## Experiments

**1. PID 1 and `--fork`.** util-linux's `--mount-proc` implies a new mount namespace, and `unshare` makes it private by default.

```sh
sudo unshare --pid --fork --mount-proc sh
  echo $$                          # 1
  ps -ef                           # just sh and ps
  grep NSpid /proc/self/status     # one number
  exit
sudo unshare --pid sh
  echo $$                          # an ordinary host PID: the shell did not move
  ls                               # works: ls is the namespace's PID 1, and exits
  ls                               # "sh: N: Cannot fork": init is gone, fork gets ENOMEM
  exit
```

**2. Find and join a namespace.** In one terminal run `sudo unshare --uts sh -c 'hostname demo; exec sleep 300'`. The caller moves, so no `--fork` is needed. In a second terminal:

```sh
hostname                                                    # james-mint
sudo nsenter --target "$(pgrep -nx sleep)" --uts hostname   # demo: nsenter is setns
sudo lsns -t uts                                            # the new namespace, with sleep in it
```

As a normal user on this machine (util-linux 2.39.3, kernel 7.0), `lsns` stopped with `lsns: Unsupported ioctl NS_GET_USERNS`. If yours does the same, `sudo sh -c 'readlink /proc/[0-9]*/ns/uts' | sort | uniq -c` gives the same census.

**3. Watch the syscalls.** The dev sudoers file allows `strace`:

```sh
sudo strace -f -e trace=clone3,clone,unshare,mount,fsopen,fsconfig,fsmount,move_mount,waitid ./target/debug/examples/hello_ns
sudo strace -f -e trace=clone3,clone,unshare,waitid ./target/debug/examples/hello_ns --unshare
```

In the second trace, look for `unshare(CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWPID) = 0`, then glibc's `fork` showing up as `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, …)`. `SIGCHLD` sits *inside* the flags there, which is the exit-signal byte that `clone3` moved into its own field. The wait also changes from `waitid(P_PIDFD, 3, …)` to `waitid(P_PID, <pid>, …)`.
