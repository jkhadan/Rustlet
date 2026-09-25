# 02 — Mounts, propagation and `pivot_root`

By the end of Phase 1, `rustlet-runc run` gives you a shell in Alpine that has
its own PID 1, hostname and **mount table**. This chapter covers the mount
half: how a container gets a root filesystem of its own without disturbing the
host's. Chapter 03 covers `/proc`, `/dev`, `/sys` and the final steps before
`execve`.

Everything here happens inside [`rootfs.rs`](../../crates/rustlet-runtime/src/rootfs.rs),
called from container init ([`init.rs`](../../crates/rustlet-runtime/src/init.rs)).

## Try it first

```sh
cargo xtask rootfs                  # downloads Alpine, writes .rustlet-dev/bundles/alpine
cargo build -p rustlet-runc
sudo ./target/debug/rustlet-runc run --bundle .rustlet-dev/bundles/alpine demo
```

Inside, `cat /proc/self/mountinfo` prints exactly eight mounts:

```text
480 419 8:3 /home/james/…/bundles/alpine/rootfs / ro,nodev,relatime - ext4 /dev/sda3 rw,errors=remount-ro
481 480 0:54 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
482 480 0:56 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
483 482 0:61 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
484 482 0:62 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
485 482 0:52 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
486 480 0:63 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
487 486 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
```

On the host, the same file lists dozens of mounts, and none of these eight.
That is the goal. The rest of the chapter explains how we get there, and why
each step is the way it is.

## 1. A new mount namespace starts as a copy

`clone3(CLONE_NEWNS)` gives the child a new mount namespace, but not an empty
one: it starts as a **copy of the parent's mount table**. Every host mount is
still there, at the same paths. Each line of `/proc/self/mountinfo` describes
one mount:

```text
32 2 8:3 / / rw,relatime shared:1 - ext4 /dev/sda3 rw,errors=remount-ro
│  │ │   │ │ │           │          │ │    │         └ superblock options
│  │ │   │ │ │           │          │ │    └ source
│  │ │   │ │ │           │          │ └ filesystem type
│  │ │   │ │ │           │          └ separator
│  │ │   │ │ │           └ optional fields: propagation (shared:1)
│  │ │   │ │ └ per-mount options
│  │ │   │ └ mount point
│  │ │   └ root: which directory of the filesystem is mounted here
│  │ └ device major:minor
│  └ parent mount ID
└ mount ID
```

[`mountinfo.rs`](../../crates/rustlet-sys/src/mountinfo.rs) parses this format, including
the `\040` octal escapes for spaces in paths. In the container's first line
above, the *root* field is `/home/james/…/rootfs`. The container's `/` is that
directory of `/dev/sda3`, bind-mounted, which is the mount we build in step 3.

## 2. Propagation: the reason `/` must be made private first

That `shared:1` on the host's `/` is the most dangerous thing in this chapter.

Mount **propagation** (see `mount_namespaces(7)`) lets a mount event in one
place be replayed in others. Every mount has one of four types:

| type | meaning |
|---|---|
| `shared:N` | member of peer group N: mount/unmount events here are replayed in every peer, and vice versa |
| `master:N` (slave) | receives events from peer group N, sends none back |
| private | neither sends nor receives |
| unbindable | private, and can't be bind-mounted |

systemd makes every mount `shared` at boot, so that services with private
mount namespaces still see a USB stick mounted later. When `clone3` copies the
mount table, **the copies join the same peer groups**. If container init
mounted `/proc` on a shared mount under the rootfs, the host would get a
container procfs mounted inside its own tree. If it ran
`umount2(".", MNT_DETACH)` on a shared old root (step 6), the unmount could
propagate to the host. Real runtimes have had exactly this bug.

So the very first mount call of container init is:

```rust
// rootfs.rs, make_private()
mount::mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
```

`MS_REC|MS_PRIVATE` on `/` makes every mount in *our* namespace private, and
only ours: changing propagation is itself never propagated. We don't take that
on faith. `make_private` re-reads `/proc/self/mountinfo` and refuses to
continue if any mount still has a `shared:` or `master:` field.

That check has an even earlier companion. Before the first mount call,
`namespaces::assert_new_mount_ns` compares the (device, inode) of
`/proc/self/ns/mnt` with the namespace `rustlet-runc` started in and with PID
1's. If they are the same, init aborts. This runs in release builds too: it is
the last line of defence if something upstream ever got the namespace flags
wrong. (Upstream, [`namespaces.rs`](../../crates/rustlet-runtime/src/namespaces.rs)
already refuses any spec that lacks a new mount namespace or asks to join one.)

## 3. The new mount API, and why paths are the enemy

Classic `mount(2)` takes *paths*:

```c
mount("proc", "/path/to/rootfs/proc", "proc", MS_NOSUID, NULL);
```

The runtime checks that `/path/to/rootfs/proc` is a harmless directory, then
the kernel resolves the path *again* inside `mount`. In between, anything that
can write to the rootfs (a malicious image, or another container sharing a
volume) can swap `proc` for a symlink to `/`. The mount then lands on the host.
This check-then-use race (TOCTOU) is behind CVE-2019-19921, CVE-2021-30465 and
several of runc's 2025 CVEs.

Linux 5.2 added a mount API built on file descriptors:

```text
fsopen("tmpfs")                 -> fs context fd  (a filesystem being configured)
fsconfig(fd, SET_STRING, k, v)  -> configure it, one option per call
fsconfig(fd, CMD_CREATE)        -> create the superblock
fsmount(fd, attrs)              -> a *detached* mount: exists, but attached nowhere
open_tree(path, CLONE)          -> detached copy of an existing mount (a bind mount)
mount_setattr(fd, ...)          -> ro/nosuid/nodev/propagation on a mount fd
move_mount(mnt, target)         -> attach it; the target can itself be an fd
```

The recipe for every container mount is: **build it detached, resolve the
target once, safely, into an fd, and attach onto that fd.** Nothing is ever
resolved twice. Here is what that looks like for real (`strace -f` of
`rustlet-runc run`, lightly trimmed):

```text
clone3({flags=CLONE_PIDFD|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWNET, …}, 88) = 31969
unshare(CLONE_NEWCGROUP)    = 0
mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) = 0
open_tree(AT_FDCWD, "/home/…/bundles/alpine/rootfs", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE) = 3
mount_setattr(3, "", AT_EMPTY_PATH|AT_RECURSIVE, {attr_set=MOUNT_ATTR_NODEV, …, propagation=MS_PRIVATE}, 32) = 0
move_mount(3, "", 5, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) = 0
fsopen("tmpfs", FSOPEN_CLOEXEC) = 5
fsconfig(5, FSCONFIG_SET_STRING, "source", "tmpfs", 0) = 0
fsconfig(5, FSCONFIG_SET_STRING, "mode", "755", 0) = 0
fsconfig(5, FSCONFIG_SET_STRING, "size", "65536k", 0) = 0
fsconfig(5, FSCONFIG_CMD_CREATE, NULL, NULL, 0) = 0
fsmount(5, FSMOUNT_CLOEXEC, MOUNT_ATTR_NOSUID|MOUNT_ATTR_STRICTATIME) = 6
move_mount(6, "", 5, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) = 0
…
fchdir(3)                   = 0
pivot_root(".", ".")        = 0
umount2(".", MNT_DETACH)    = 0
```

Both paths passed to `move_mount` are `""`, with `F_EMPTY_PATH|T_EMPTY_PATH`:
"the source is this fd, the target is that fd". (The fd numbers get reused as
earlier fds are closed; the `5` in `move_mount` is the target's `O_PATH` fd,
opened just before.) The wrappers live in
[`rustlet-sys/src/mount.rs`](../../crates/rustlet-sys/src/mount.rs). One nice
detail: when `fsconfig` fails, the kernel writes an explanation into the
context's log, and `FsContext` prints it in debug builds (`fsconfig(tmpfs):
kernel says: …`), which beats a bare `EINVAL`.

## 4. Finding a path *inside* the rootfs: `openat2(RESOLVE_IN_ROOT)`

Mounting onto an fd only helps if the fd was found safely. Container init has
to find `dev/pts` inside a tree the image author controls, and that tree could
contain `dev -> /`. Joining strings (`rootfs + "/dev/pts"`) and letting the
kernel follow symlinks would walk straight out onto the host.

`openat2(2)` (5.6) takes resolution flags. With `RESOLVE_IN_ROOT` the kernel
treats the dirfd as `/` **for the whole walk**. An absolute symlink restarts at
the dirfd, not at the real root, and `..` stops there: exactly the semantics a
process chrooted into the rootfs would see.
[`inroot.rs`](../../crates/rustlet-runtime/src/inroot.rs) builds on it:

- `open_dir(root, path)`: `openat2(root, path, O_PATH|O_DIRECTORY, RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`.
  `NO_MAGICLINKS` refuses `/proc/<pid>/fd/*`-style links, which can point anywhere.
- `mkdir_all(root, path)`: `mkdir -p`, creating one component at a time with
  `mkdirat(parent_fd, name)`. Before each step, it resolves the prefix *again
  from the root*, so a symlink planted halfway down still can't lead out.
- `ensure_mount_target(root, dest, dir)`: finds or creates the mount point and
  checks it has the right type (a directory for most mounts, a file for bind
  mounts of files). A missing mount point is created in the rootfs itself,
  as root, before the read-only remount, just as runc does. From Phase 3 the
  rootfs is an overlay, so such directories land in the container's own upper
  layer. Today they land in your checkout, which is why the integration tests
  mount onto directories Alpine already has (`/mnt`, `/tmp`).

The unit test `mkdir_all_stays_inside_through_absolute_symlinks` plants a
symlink to a real host directory inside a fake rootfs. It shows that the link
dangles (and fails) until its target exists *inside* the root, and that it is
then followed there, never outside.

## 5. Making the rootfs a mount point

`pivot_root` has several requirements. The one that bites first: **`new_root`
must be a mount point**, and a directory in your checkout is not one. The fix is
to bind-mount it onto itself (`bind_rootfs`):

```rust
let tree = open_tree(None, root, OpenTreeFlags::CLONE | OpenTreeFlags::RECURSIVE)?; // detached rbind
mount_setattr(tree.as_fd(), true, &SetAttr { set: MountAttr::NODEV, propagation: Some(Propagation::Private), .. })?;
let target = open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW)?;
move_mount_fd(tree.as_fd(), target.as_fd())?;
Ok(tree)   // <- the root of the *new* mount
```

Three details:

- **Recursive** (`AT_RECURSIVE`): a rootfs may contain mounts of its own, and
  they come along, as with runc's `rbind`.
- **`nodev`**: device nodes that ship inside an image are never honoured.
  Whatever is under `rootfs/dev` in the image can't become a raw disk. The
  container's real `/dev` is a separate tmpfs (chapter 03).
- **Which fd to keep**: after `move_mount`, the `open_tree` fd refers to the
  root of the now-attached mount. The `target` fd still refers to the
  directory *underneath* it. Every later lookup uses `tree` as the root; get
  this wrong and all the mounts land on the hidden directory below.

## 6. Parsing OCI mounts

`config.json` describes mounts in `mount(8)` vocabulary:

```json
{ "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
  "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] }
```

The `options` list mixes three different kinds of thing, which the new API
keeps apart. [`mounts.rs`](../../crates/rustlet-runtime/src/mounts.rs) sorts
them **in the parent, before anything is created**. A typo becomes a clear
error from `rustlet-runc`, not an `EINVAL` from deep inside init.

| kind | examples | goes to |
|---|---|---|
| per-mount attributes | `ro`, `rw`, `nosuid`, `nodev`, `noexec`, `relatime`, `strictatime` | `fsmount(attrs)` or `mount_setattr` |
| the operation | `bind`, `rbind` | `open_tree(OPEN_TREE_CLONE [| AT_RECURSIVE])` |
| filesystem options | `mode=755`, `size=65536k`, `newinstance`, `gid=5` | one `fsconfig` call each |

A few rules worth knowing:

- Later options win (`ro,rw` is read-write), as with `mount(8)`.
- The atime options are a 2-bit field (`MOUNT_ATTR__ATIME`), so setting one
  clears the others. `relatime` has the value 0, so it means "clear the field".
- `type: cgroup` becomes `cgroup2`. runc's default spec still says `cgroup`,
  but this host (like every modern distro) only has the unified hierarchy.
- Propagation options other than `private` are refused, as are `/` as a
  destination and `..` in destinations.
- **Mounts under `/proc` and `/sys` are refused**, except procfs at `/proc`,
  sysfs at `/sys` and cgroup2 at `/sys/fs/cgroup`. Mounting over parts of
  those kernel interfaces was the mechanism of several escapes (for example,
  shadowing `/proc/self/attr` or `/proc/sys/kernel/core_pattern`).

For bind mounts, the clone inherits the source mount's flags, and `set`/`clear`
adjust them with `mount_setattr`. As with `mount(8)`, `ro` on an `rbind` makes
the top mount read-only, not the submounts.

## 7. `pivot_root(".", ".")` and why not `chroot`

`chroot(dir)` changes one thing: the directory the calling process resolves
`/` against. The old root is still mounted and reachable. A root process can
escape with the classic trick: `chroot` into a subdirectory while keeping an
fd to a directory outside it, then `fchdir` to that fd and walk up.

`pivot_root(new_root, put_old)` works on the mount table instead: it makes
`new_root` the root mount of the whole mount namespace, and moves the old
root mount to `put_old`. After unmounting `put_old`, the host's filesystem
isn't hidden, it's *gone* from this namespace.

The traditional recipe needs a `put_old` directory inside the rootfs
(`mkdir rootfs/.oldroot`). The `pivot_root(2)` man page documents a neater
trick, which `rootfs::pivot` uses:

```rust
mount::fchdir(root.as_fd())?;                                  // cwd = new root
mount::pivot_root(Path::new("."), Path::new("."))?;            // old root now stacked on top of "."
mount::umount2(Path::new("."), MntFlags::MNT_DETACH)?;         // peel the old root off
nix::unistd::chdir("/")?;
```

With the new root as the working directory, `pivot_root(".", ".")` mounts the
old root *on top of* the new one, at the same place. `umount2(".",
MNT_DETACH)` then detaches the top mount (the old root), which lazily takes
all the host's mounts with it. This is also the moment step 2 pays off: had
the old root been `shared`, this unmount would have propagated.

Afterwards `pivot` checks that `/` has the same (device, inode, mount ID) as
the rootfs mount we built. A cheap assertion, but it turns "the kernel did
something unexpected" into an error rather than a container running on the
wrong root.

## 8. Read-only root

`root.readonly: true` (the default in the generated `config.json`, as in runc)
is applied last, after `pivot_root`, with `mount_setattr(RDONLY)` on `/`
alone, not recursively. `/proc`, `/dev`, `/dev/shm` and the rest keep their
own flags, so `/dev/null` stays writable while `touch /x` fails:

```text
/ # touch /x
touch: /x: Read-only file system
```

It's read-only by default for two reasons. An image's rootfs is shared state
(Phase 3 will share one extracted layer among many containers). And in this
phase the rootfs lives in your checkout, so a writable root would leave
root-owned files there.

## 9. Proving the host is untouched

The design has three layers of protection for the host's mount table:

1. **Refuse** specs that could touch it: no new mount namespace, joining one by
   path, a `root.path` that is the host's `/` (compared by device and inode, so
   `/proc/1/root` or a bind of `/` can't sneak through), or mounts over `/proc`
   and `/sys` internals.
2. **Assert** in init before the first mount: a different mount namespace,
   and nothing shared after `MS_PRIVATE`.
3. **Test**: every integration test (`tests/tests/runtime.rs`, run with `cargo
   xtask itest`) snapshots the host's mountinfo before and after the
   container runs, and fails if anything was added or removed.

A container's mounts need no cleanup at all. They exist only in its mount
namespace, and the kernel destroys that namespace when the last process in it
exits.

## Check yourself

1. Why does `make_private` run *before* the rootfs bind mount, and what exactly
   could go wrong if the two were swapped?
2. `bind_rootfs` returns the `open_tree` fd rather than reopening the rootfs
   path. What would you get if you reopened `root` by path *before*
   `move_mount`? And after?
3. Why is `open_in_root` + `move_mount` onto an fd safer than resolving
   `rootfs.join(dest)` yourself and calling `mount(2)` on the string?
4. After `pivot_root(".", ".")`, which mount is at `.`, and which one does
   `umount2(".", MNT_DETACH)` remove?
5. `root.readonly` is applied non-recursively. What would break if it were
   recursive?

## Experiments

- `findmnt -o TARGET,PROPAGATION` on the host, then the same inside `sudo
  unshare -m --propagation unchanged sh` and `sudo unshare -m sh` (whose
  default is `--propagation private`). Mount a tmpfs in each and watch what the
  host sees.
- Trace your own run:
  `sudo strace -f -e trace=%file,mount,move_mount,fsopen,fsconfig,fsmount,open_tree,pivot_root ./target/debug/rustlet-runc run --bundle .rustlet-dev/bundles/alpine demo`.
  Add `openat2` to see every in-root lookup.
- In `config.json`, add a mount with destination `/proc/sys` and watch
  `rustlet-runc` refuse it before anything is created. Then add an `rbind` of a
  host directory with `ro` and check that writes fail inside but reads work.
