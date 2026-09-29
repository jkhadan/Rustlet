# 09 — User namespaces: a root that is nobody on the host

Chapters 06 and 07 limited what root in a container may *do*: eleven
capabilities, a seccomp filter, no new privileges. It was still uid 0,
though. Anything on the host that checks ids rather than capabilities saw
root: the owner of a file, a sysctl file writable by uid 0, a process
table where the container's processes show up as `root`. Phase 2c part 1
changes who the process *is*. A container can get a user namespace of
its own, and container root is then host uid 1000000, a user that owns
nothing on the host. The milestone: `uid_map` reads `0 1000000 65536`.

This chapter covers how the maps work and what capabilities mean once
they are relative to a namespace. It then follows the order of events
between `rustlet-runc` and init, and explains why the parent now opens
the rootfs. After that come `/dev` without `mknod`, the mounts that need
a namespace the container owns, idmapped mounts, `exec`, and what
`create` refuses. The device filter, part 2 of Phase 2c, gets chapter 10.

Code: [`userns.rs`](../../crates/rustlet-runtime/src/userns.rs) (maps, checks, `become_root`),
[`rootfs.rs`](../../crates/rustlet-runtime/src/rootfs.rs) (`HostTrees`, `attach_rootfs`, `populate_dev`, `host_sysfs`),
[`create.rs`](../../crates/rustlet-runtime/src/create.rs) (`prepare_init`), [`init.rs`](../../crates/rustlet-runtime/src/init.rs),
[`exec.rs`](../../crates/rustlet-runtime/src/exec.rs), [`sysctl.rs`](../../crates/rustlet-runtime/src/sysctl.rs),
[`namespaces.rs`](../../crates/rustlet-runtime/src/namespaces.rs), [`sync.rs`](../../crates/rustlet-runtime/src/sync.rs), and
[`xtask/src/rootfs.rs`](../../xtask/src/rootfs.rs) (`--remap`). Tests: [`userns.rs`](../../tests/tests/userns.rs)
(`cargo xtask itest -- us_`, 20 tests). Design: [architecture.md §2.2](../architecture.md#22-rustlet-runtime-library--rustlet-runc-binary--the-oci-runtime)
steps 4.0, 4.3, 5.1, 5.3 and exec step 5, and [§2.2.1](../architecture.md#221-namespace-modes-translated-to-oci-namespaces-by-the-daemon).

All transcripts are real runs on this host (kernel 7.0.0-34-generic). `$R`
is `sudo ./target/debug/rustlet-runc --root /run/rustlet/doc-09`. The
bundles are copies of `.rustlet-dev/bundles/alpine-remap/config.json`
(from `cargo xtask rootfs --remap`) with the rootfs path made absolute,
`terminal: false`, `root.readonly` left `true`, and `sh -c <script>` as
the process, plus the changes stated (§10 has the jq). `$S` is a scratch
directory of mine whose parent is mode `0700`. Long paths are shortened
with `…`. After all the runs, the host's `/proc/self/mountinfo` was the
same 24 lines as before.

## 1. Two numbers for every id

The kernel stores every uid and gid as the host's number (a `kuid_t`). A
user namespace is a translation table between those numbers and the ones
its processes use. Syscalls translate on the way in, and `stat`, `id` and
`/proc` translate on the way out. The table is `/proc/<pid>/uid_map` (and
`gid_map`), one range per line:

```text
  /proc/<init>/uid_map:   0 1000000 65536
                          │ │       └ this many ids
                          │ └ are host ids 1000000…
                          └ container ids 0…
```

`65536` covers every 16-bit id an image can use. `1000000` is far above the
regular users and above the ranges `useradd` hands out in `/etc/subuid`
(100000 onwards, 65536 each); both numbers are
[`spec.rs`](../../crates/rustlet-runtime/src/spec.rs)'s `REMAP_HOST_ID`
and `REMAP_SIZE`. The remapped rootfs from `cargo xtask rootfs --remap` is
the Alpine minirootfs with every owner shifted by 1000000. That's
a root job, so the task re-runs itself under sudo. Inside and outside:

```text
$ $R run --bundle ./ids u1     # cat /proc/self/uid_map /proc/self/gid_map; id; stat -c "%u:%g %n" / /bin/busybox /etc/shadow; ls -lnd …
         0    1000000      65536
         0    1000000      65536
uid=0(root) gid=0(root)
0:0 /
0:0 /bin/busybox
0:42 /etc/shadow
drwxrwxrwt    2 65534    65534           40 Sep 29 06:01 /dev/mqueue
drwxr-xr-x    2 0        0                0 Sep 29 06:01 /dev/pts
drwxrwxrwt    2 0        0               40 Sep 29 06:01 /dev/shm
-rw-r--r--    1 0        0                0 Sep 29 06:01 /proc/sys/kernel/shmmni
-rw-r--r--    1 0        0                0 Sep 29 06:01 /proc/sys/net/ipv4/ip_forward
-rw-r--r--    1 65534    65534            0 Sep 29 06:01 /proc/sys/vm/swappiness
$ stat -c '%u:%g %n' …/alpine-remap/rootfs …/alpine-remap/rootfs/etc/shadow     # on the host
1000000:1000000 …/alpine-remap/rootfs
1000000:1000042 …/alpine-remap/rootfs/etc/shadow
```

`/etc/shadow`'s group is Alpine's `shadow`, 42, stored as host gid
1000042. Nothing is chowned at run time: the translation does it all. An
id the map doesn't contain has no number inside, so the kernel shows the
**overflow id**, 65534 (`/proc/sys/kernel/overflowuid`), called `nobody`
and `nogroup`. `vm.swappiness` is a global knob owned by host root, and
host uid 0 is not in the map. §6 explains `/dev/mqueue`.

From the host, the same process is simply user 1000000. With `exec -u
1000:1000` it's 1001000:

```text
$ $R create --bundle ./sleeper web && $R start web          # exec sleep 3600
$ pid=$($R state web | jq .pid); ps -o user,pid,cmd -p $pid
USER         PID CMD
1000000   540220 sleep 3600
$ grep -E '^(Uid|Gid|Groups)' /proc/$pid/status
Uid:	1000000	1000000	1000000	1000000
Gid:	1000000	1000000	1000000	1000000
Groups:	 
$ $R exec -d -u 1000:1000 --pid-file $S/exec.pid web sleep 3600; ps -o user,uid,gid,pid,cmd -p $(cat $S/exec.pid)
USER       UID   GID     PID CMD
1001000  1001000 1001000 540239 sleep 3600
```

## 2. Capabilities, relative to an owner

Every other kind of namespace has an **owner**: the user namespace its
creator was in. `clone3(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | …)`
creates the user namespace first and the others inside it, so the
container's user namespace owns its mount, UTS, IPC, network and PID
namespaces. A process in a user namespace can hold every capability, but a
capability check is always asked *relative to* a namespace. The
kernel checks `ns_capable(owner, CAP_…)` for an object that belongs to a
namespace. For the machine itself (loading a module, creating a device
node, raising a hard limit) it checks `capable(CAP_…)`, which means the
initial user namespace, where container root has nothing. As myself, with
util-linux's `unshare`:

```text
$ unshare -Ur sh -c 'id; cat /proc/self/uid_map; grep CapEff /proc/self/status; mknod ./null c 1 3; …; mkfifo ./fifo …'
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
         0       1000          1
CapEff:	000001ffffffffff
mknod: ./null: Operation not permitted
mknod: 1
fifo-ok
prw-rw-r-- 1 0 0 0 Sep 29 02:09 ./fifo
```

All 41 capabilities (chapter 06), root of the namespace, and still no
device node, because `mknod` of a device checks `CAP_MKNOD` in the
initial user namespace. A FIFO needs no capability. `nogroup` is my
host supplementary groups, none of them mapped. §3 explains why this
process can't drop them, and why Rustlets' init can.

Files follow a second rule. A capability such as `CAP_DAC_OVERRIDE` or
`CAP_CHOWN` only applies to a file if the file's owner and group are
mapped in the process's namespace. The ids a process hands the kernel
must be mapped too. In the container, `touch /dev/shm/f` and then:

```text
$ $R run --bundle ./chown c1   # chown 1000:1000 /dev/shm/f && stat …; chown 70000 /dev/shm/f; …; cat 2 sysctls; hostname; cat /proc/sys/kernel/domainname
1000:1000 /dev/shm/f
chown: /dev/shm/f: Invalid argument
chown 70000: 1
80
1234
rustlet
example.org
$ cat /proc/sys/net/ipv4/ip_unprivileged_port_start /proc/sys/kernel/shmmni /proc/sys/kernel/domainname    # host
1024
4096
(none)
```

70000 has no host id to be stored as, so `chown` gets `EINVAL`. The same
rule is behind §1's `/proc/sys` owners. `kernel.shmmni` belongs to the
container's IPC namespace, and `net.ipv4.ip_forward` to its network
namespace. Their files are owned by the root of the namespace's owner, so
they show as `0:0`. `vm.swappiness` is global and shows as `nobody`. The
bundle set `linux.sysctl` = `{"net.ipv4.ip_unprivileged_port_start": "80",
"kernel.shmmni": "1234"}` and the spec's `domainname` field. Init wrote
them into namespaces its user namespace owns, and the host's values didn't
move. `kernel.domainname` as a *sysctl* is refused (§9): UTS sysctl files
check for host root. The `domainname` field works, because it is a
syscall, `setdomainname`, checked against the UTS namespace's owner.

The capability sets themselves don't change. `CapEff` is still
`00000000800405fb`, `NoNewPrivs` 1, `Seccomp` 2
(`us_capabilities_seccomp_and_nnp_are_unchanged`). The same eleven
capabilities now only work on what the container owns.

## 3. Who writes the map, and when

A user namespace starts with empty maps, and until they're written every
id in it is the overflow id. That's the state init is born in. Here is a
namespace made without `-r`:

```text
$ unshare -U sh -c 'id; cat /proc/self/uid_map | wc -c'
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
0
```

The maps are written from *outside*, once each, all lines in one
`write(2)`. The kernel only lets a writer map host ids it could become,
which means holding `CAP_SETUID` (`CAP_SETGID` for `gid_map`) in the
*parent* user namespace. An unprivileged writer may map only its own id.
It may write `gid_map` only after writing `deny` to `/proc/<pid>/setgroups`,
which switches `setgroups(2)` off in the namespace for good. The reason is
a group that is used to *deny* access (a file mode like `0604`): a process
that could drop that group would get the access. As myself, against an
`unshare -U sleep 30` in the background:

```text
$ echo '0 1000000 1' > /proc/$P/uid_map          # a host id that isn't mine
bash: echo: write error: Operation not permitted
$ echo '0 1000 1' > /proc/$P/gid_map             # setgroups is still "allow"
bash: echo: write error: Operation not permitted
$ echo deny > /proc/$P/setgroups; echo '0 1000 1' > /proc/$P/gid_map && echo gid-ok
gid-ok
$ echo '0 1000 1' > /proc/$P/uid_map && echo uid-ok
uid-ok
$ echo '0 1000 1' > /proc/$P/uid_map             # a second time
bash: echo: write error: Operation not permitted
```

So `rustlet-runc`, which is host root, writes the maps itself. It does this
behind the `IdMapper` trait, with `DirectIdMapper` today. In rootless mode
(Phase 8) the job goes to the setuid helpers `newuidmap`/`newgidmap`,
which check `/etc/subuid` first. A privileged writer doesn't have to deny
`setgroups`, so the container's supplementary groups work.
`us_process_user_is_mapped_into_the_range` gives the process `additionalGids`
`[2000]`, and the host sees `Groups: 1002000`.

**The handshake.** Init must not do anything until the parent has written
the maps, so every container's init waits for a `Proceed` message on the
sync socket (chapter 05) before it starts. Later it asks the parent for
a second thing only the parent can do, its rlimits and `oom_score_adj`,
and waits for a second `Proceed`. Here is `sudo strace -f -s 80 -e
trace=clone3,open_tree,mount_setattr,openat,write,prlimit64,sendto,recvfrom,setgroups,setresgid,setresuid,unshare,execve`
of `$R run` on a bundle that adds `RLIMIT_RTPRIO` 5/5 and `oomScoreAdj:
-500` (647377 is `rustlet-runc`, 647378 is init):

```text
647377 open_tree(AT_FDCWD, "/home/james/…/alpine-remap/rootfs", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE) = 8
647377 mount_setattr(8, "", AT_EMPTY_PATH|AT_RECURSIVE, {attr_set=MOUNT_ATTR_NODEV, attr_clr=0, propagation=MS_PRIVATE, userns_fd=0}, 32) = 0
647377 clone3({flags=CLONE_PIDFD|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET, …} => {pidfd=[9]}, 88) = 647378
…                                                       (state.json: init's pid and start time)
647377 openat(AT_FDCWD, "/proc/647378/uid_map", O_WRONLY|O_CLOEXEC) = 7
647377 write(7, "0 1000000 65536\n", 16) = 16
647377 openat(AT_FDCWD, "/proc/647378/gid_map", O_WRONLY|O_CLOEXEC) = 7
647377 write(7, "0 1000000 65536\n", 16) = 16
647377 sendto(4, "{\"type\":\"proceed\"}", 18, MSG_NOSIGNAL, NULL, 0) = 18
647378 recvfrom(5, "{\"type\":\"proceed\"}", 65536, 0, NULL, NULL) = 18
647378 setgroups(0, [])                 = 0
647378 setresgid(0, 0, 0)               = 0
647378 setresuid(0, 0, 0)               = 0
647378 unshare(CLONE_NEWCGROUP)         = 0
…                                                       (init's mounts, pivot_root, sysctls, masked paths)
647378 sendto(5, "{\"type\":\"set_limits\"}", 21, MSG_NOSIGNAL, NULL, 0) = 21
647378 recvfrom(5,  <unfinished ...>
647377 recvfrom(4, "{\"type\":\"set_limits\"}", 65536, 0, NULL, NULL) = 21
647377 prlimit64(647378, RLIMIT_NOFILE, {rlim_cur=1024, rlim_max=1024}, NULL) = 0
647377 prlimit64(647378, RLIMIT_RTPRIO, {rlim_cur=5, rlim_max=5}, NULL) = 0
647377 openat(AT_FDCWD, "/proc/647378/oom_score_adj", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 7
647377 write(7, "-500", 4)              = 4
647377 sendto(4, "{\"type\":\"proceed\"}", 18, MSG_NOSIGNAL, NULL, 0) = 18
647378 <... recvfrom resumed>"{\"type\":\"proceed\"}", 65536, 0, NULL, NULL) = 18
647378 setgroups(0, [])                 = 0
647378 setresgid(0, 0, 0)               = 0
647378 setresuid(0, 0, 0)               = 0
```

The four lines after the first `Proceed` are `become_root`, then the
cgroup namespace (chapter 04). Until `setresuid`, init is host uid 0, which
the namespace doesn't map. A file it created would have an owner the
kernel can't write down (`EOVERFLOW`). The namespace's capabilities, which
`clone3` gave it, allow switching to ids that *are* mapped. Becoming the
namespace's root keeps them. `setgroups([])` drops the host's
supplementary groups, which aren't mapped either. The last three lines are
the identity switch to `process.user` (chapter 06), uid 0 here. Without a
user namespace, init skips `become_root`, but it still waits for the parent
at both points: one code path.

**Why the parent sets rlimits and `oom_score_adj`.** Raising a hard limit
and lowering an OOM score both need `CAP_SYS_RESOURCE` in the *initial*
user namespace. Init doesn't have that, and adding the capability to the
container's sets doesn't help, because it would be a capability in the
wrong namespace. With the parent setting 5/5 and -500, and
`CAP_SYS_RESOURCE` added to all of the spec's sets (`CapEff` gains bit
24):

```text
$ $R run --bundle ./sysres sr   # grep CapEff …; ulimit -Hr 6; echo …; echo -600 > /proc/self/oom_score_adj; echo …
CapEff:	00000000810405fb
sh: error setting limit: Operation not permitted
ulimit -Hr 6: 1
sh: write error: Permission denied
-600: 1
```

Raising the score is still allowed from inside: in the same bundle
without the extra capability, `echo 0 > /proc/self/oom_score_adj`
succeeded. My own shell's `RTPRIO` hard limit is 0, and inside it was 5,
so the parent really raised it.

**When.** The parent sets them for every container, when init asks with
`set_limits`: after init's setup as root, before its identity switch. The
first version set them before the first `Proceed`, and the independent
review of this phase found what that broke. All of init's setup then ran
under the container's limits, and every mount costs init an fd, so
`RLIMIT_NOFILE` 8 failed at `mount devpts` with `EMFILE`
(`rr_rlimits_are_set_after_init_setup`). It is also where runc sets them
(`procReady`). Before the identity switch still matters for
`RLIMIT_NPROC`, which the kernel checks against the new user's process
count when the uid changes.

## 4. The rootfs, opened by the parent

`/home/james` is `0750`. Every path lookup checks search permission on
each directory on the way, so host uid 1000000 can't even reach the
bundle:

```text
$ stat -c '%A %U:%G %n' /home/james …/alpine-remap/rootfs
drwxr-x--- james:james /home/james
drwxr-xr-x UNKNOWN:UNKNOWN /home/james/…/alpine-remap/rootfs
$ sudo systemd-run -q --pipe --wait /usr/bin/setpriv --reuid=1000000 --regid=1000000 --clear-groups /usr/bin/ls …/alpine-remap/rootfs
/usr/bin/ls: cannot access '/home/james/…/alpine-remap/rootfs': Permission denied
```

(`setpriv` switches ids without asking `/etc/passwd`, which has no user
1000000.) Before Phase 2c, init bound the rootfs onto itself by path. As
host uid 1000000 it can't. So the parent opens the host side of every mount itself, before
`clone3` (`rootfs::HostTrees`, architecture step 4.0): the rootfs as a
detached, recursive copy with `nodev` on every mount (the first two lines
of §3's trace), and each bind source as a detached copy of its own. A
*detached* mount is attached nowhere. Nothing can be mounted onto or
below it, and the fd is the only way to reach it. Init inherits the fds
through `clone3` and only attaches them. They are close-on-exec, so none
reaches the container's program. There are three reasons for this, from
`HostTrees`' docs:

- **Init may not be able to reach the sources.** That's the transcript
  above. `$S` sits under a `0700` directory, and §7's bind mounts from it
  still worked.
- **Idmapped mounts need it.** Only a mount that isn't attached anywhere
  yet may be idmapped, and only by someone privileged over the
  filesystem's user namespace, the host's (§7).
- **Each host path is resolved once**, by the privileged side, before any
  container process exists to race with it.

Every container does it this way, with or without a user namespace, so
there is one code path. Init's side, from the same trace:

```text
540141 move_mount(6, "", AT_FDCWD, "/", MOVE_MOUNT_F_EMPTY_PATH) = 0
540141 move_mount(7, "", 3, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) = 0     7 times: the spec's mounts
…                                                                                        /dev nodes (§5)
540141 fchdir(6)                        = 0
540141 pivot_root(".", ".")             = 0
540141 umount2(".", MNT_DETACH)         = 0
540141 openat(AT_FDCWD, "/", O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY) = 3
540141 mount_setattr(3, "", AT_EMPTY_PATH, {attr_set=MOUNT_ATTR_RDONLY, …}, 32) = 0
```

The rootfs tree goes **on top of `/`**. That's the one place init can
always name, so it never looks up the rootfs's host path. Mounting over
`/` doesn't change what init sees as `/` yet. A process's root is a
(mount, directory) pair that stays the *lower* mount, so host paths such
as `/dev/null` still resolve on the host until the pivot. The new mount
is a child of the old root, which is exactly what `pivot_root` wants. Then
chapter 02's trick: `fchdir` into the tree, `pivot_root(".", ".")` stacks
the old root on top of the new one, and `umount2(".", MNT_DETACH)` peels
it off.

That last step works for a less obvious reason. When a mount namespace
owned by a less privileged user namespace gets a copy of the host's
mounts, the kernel **locks** them. They can't be unmounted one by one,
because that would uncover what the host hid underneath. The old root is
one of those mounts. `pivot_root` hands the lock from the old root to the
new one, so the old root can be detached. After the pivot, `rootfs::pivot`
checks with `statx` that `/` is exactly the tree the parent opened. Then
`root.readonly` makes it read-only. The first line of the container's
mountinfo:

```text
469 471 8:3 /home/james/…/alpine-remap/rootfs / ro,nodev,relatime - ext4 /dev/sda3 rw,errors=remount-ro
```

## 5. `/dev` without `mknod`

§2 showed that `mknod` of a device fails in a user namespace, whatever the
capabilities. A node on a filesystem mounted from inside one couldn't
be opened anyway: the kernel marks such superblocks "no devices". So in a
user namespace, `populate_dev` makes each default node a **bind mount of
the host's**. It takes an `open_tree` of `/dev/null` from init's copy of
the host's mount table, which is possible because this runs before the
pivot, while `/dev` is still the host's devtmpfs. It checks that the copy
is character device 1:3, and attaches it onto an empty file it creates in
the container's `/dev` tmpfs:

```text
540141 open_tree(AT_FDCWD, "/dev/null", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW) = 7
540141 openat(3, "null", O_RDONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0666) = 9
540141 move_mount(7, "", 9, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) = 0
…                                                   zero, full, random, urandom, tty
```

In the container's mountinfo (`$R exec web cat /proc/self/mountinfo`),
the six nodes are mounts of the host's devtmpfs (`0:7`, `udev`). They
inherited its `nosuid`, which is locked too:

```text
538 469 0:71 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,uid=1000000,gid=1000000,inode64
539 538 0:72 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=1000005,mode=620,ptmxmode=666
541 538 0:54 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
628 538 0:7 /null /dev/null rw,nosuid,relatime - devtmpfs udev rw,size=3377004k,nr_inodes=844251,mode=755,inode64
634 538 0:7 /zero /dev/zero rw,nosuid,relatime - devtmpfs udev …
…
638 538 0:7 /tty /dev/tty rw,nosuid,relatime - devtmpfs udev …
489 537 0:7 /null /proc/kcore rw,nosuid,relatime - devtmpfs udev …
```

Three details stand out:

- **Masked paths** such as `/proc/kcore` are bound from the container's
  `/dev/null`, so they're the host's node too (`0:7 /null`), after a
  check that it is character device 1:3.
- **The tmpfs and devpts options print host ids.** The spec's devpts
  `gid=5` shows as `gid=1000005`, and the tmpfs, made by init after
  `become_root`, as `uid=1000000`. Those filesystems format their options
  in the initial user namespace's numbers.
- **devpts `gid=5` has to be mapped.** Otherwise `create` refuses (§9).

`us_dev_nodes_are_bind_mounts_of_the_hosts` checks the six are the right
devices and work: `/dev/null` swallows, `/dev/zero` reads zeros,
`/dev/urandom` gives bytes, `/dev/full` says `ENOSPC`. With a terminal,
the PTY comes from the container's own devpts and belongs to the
container's user (`us_terminal_belongs_to_the_container_user`).

## 6. Namespaces the user namespace must own

Some filesystems and knobs belong to a namespace, and the kernel lets only
that namespace's owner touch them. For a container with a user
namespace, the one it owns has to be a *new* one:

| what | the kernel wants | Rustlets |
|---|---|---|
| procfs | the PID namespace's owner | a user namespace requires a new PID namespace |
| sysfs | the network namespace's owner | new netns → new sysfs; otherwise a locked rbind of the host's `/sys` |
| mqueue | the IPC namespace's owner | refused without a new IPC namespace |
| cgroup2 | the cgroup namespace's owner | refused without a new cgroup namespace |
| `net.*`, IPC sysctls | that namespace's owner | refused for joined (`path`) or shared namespaces |
| `kernel.domainname` sysctl | host root | refused; the `domainname` field works |

The kernel also mounts a new proc or sysfs in a user namespace only if
the mount namespace already shows one that nothing is hiding. So init
makes both before the old root (the host's `/proc` and `/sys`) is
detached. [`userns::check_mounts`](../../crates/rustlet-runtime/src/userns.rs)
and [`sysctl::plan`](../../crates/rustlet-runtime/src/sysctl.rs) check the
table at plan time, so none of it fails halfway through init.

**sysfs with and without a network namespace.** With its own netns, the
container gets a new sysfs, which lists that namespace's devices. Without
one (`--net=host`), init makes a recursive copy of the host's `/sys` from
its copy of the host's mount table (`MountKind::HostSysfs`), read-only on
every mount. It does this in init rather than in the parent, so that the
kernel locks the host's submounts. The second run removes the network
namespace and, to show that only the lock stops the `umount`, adds
`CAP_SYS_ADMIN` and drops the seccomp profile:

```text
== own netns                 # ls /sys/class/net; grep " /sys " /proc/self/mountinfo
lo
556 469 0:74 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
== host netns, CAP_SYS_ADMIN, no seccomp
ens18 lo 
556 469 0:24 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
565 556 0:8 / /sys/kernel/security ro,nosuid,nodev,noexec,relatime - securityfs securityfs rw
628 556 0:30 /../../../../.. /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
640 628 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
umount: can't unmount /sys/kernel/security: Invalid argument
umount: 1
== host
27 32 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
33 27 0:8 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:8 - securityfs securityfs rw
```

`0:24` is the host's own sysfs superblock: read-write and shared on the
host, read-only and private in the container. The rbind brought the host's
cgroup2 mount along, and its root reads `/../../../../..` because it is
shown relative to the container's cgroup namespace. The spec's own
cgroup2 mount goes on top of it. `EINVAL` from `umount` is the lock
(`us_sysfs_falls_back_to_the_hosts_without_a_network_namespace`).

**`/dev/mqueue` belongs to `nobody`.** An IPC namespace's mqueue
superblock is created *with* the namespace, and its root directory gets
the creator's fsuid. `clone3` creates the IPC namespace while init is
still host uid 0, before the maps exist. Every mqueue mount in that
namespace shows that superblock, owned by an id the map doesn't
contain: §1's `65534 65534` for `/dev/mqueue`. Its mode is `1777`, so
container processes can still create queues. It's a known nit (see
Experiments), not a leak: host uid 0 owning the directory gives the
container nothing.

## 7. Idmapped mounts

A plain bind mount shows the host's owners through the container's map.
A directory of mine (uid 1000) shows as `nobody`, and container root's
`CAP_DAC_OVERRIDE` doesn't apply to an unmapped owner. An **idmapped**
mount (`mount_setattr(MOUNT_ATTR_IDMAP)` with a user namespace fd)
translates the owners *on that mount* through the namespace's map: on-disk
id *k* reads as container id *k*. In OCI, a bind mount asks for it with the
option `idmap`, or `ridmap` for the mounts below it too. Rustlets takes
the mapping from the container's own maps. The parent does it between
writing the maps and `Proceed` (`HostTrees::idmap`, on an fd of
`/proc/<init>/ns/user`), because only a detached mount can be idmapped.
Two scratch directories, each with a file `f` of mine, `/mnt` with
`idmap` and `/opt` without:

```text
$ $R run --bundle ./idmap m2    # stat -c "%u:%g %n" /mnt /mnt/f /opt /opt/f; echo y > /opt/new; grep -E " /(mnt|opt) " /proc/self/mountinfo
1000:1000 /mnt
1000:1000 /mnt/f
65534:65534 /opt
65534:65534 /opt/f
sh: can't create /opt/new: Permission denied
470 469 8:3 $S/idm /mnt rw,nosuid,nodev,relatime,idmapped - ext4 /dev/sda3 rw,errors=remount-ro
471 469 8:3 $S/plain /opt rw,nosuid,nodev,relatime - ext4 /dev/sda3 rw,errors=remount-ro
```

Writes translate the other way. In a running container with the same
`/mnt`, root and uid 1000 each write a file:

```text
$ $R exec box sh -c '…; echo root > /mnt/by-root'
$ $R exec -u 1000:1000 box sh -c 'id; echo 1000 > /mnt/by-1000; ls -ln /mnt'
uid=1000 gid=1000
total 12
-rw-r--r--    1 1000     1000             5 Sep 29 06:08 by-1000
-rw-r--r--    1 0        0                5 Sep 29 06:08 by-root
-rw-rw-r--    1 1000     1000             2 Sep 29 06:06 f
$ ls -ln $S/idm                 # on the host (the container's clock is UTC)
-rw-r--r-- 1 1000 1000 5 Sep 29 02:08 by-1000
-rw-r--r-- 1    0    0 5 Sep 29 02:08 by-root
-rw-rw-r-- 1 1000 1000 2 Sep 29 02:06 f
```

Container root's file is stored as host root's, and container uid 1000's
as mine. That's the point of an idmap: the files' owners come out on disk
as if there were no remap, so the same directory works with and without
one. It also means an idmapped mount should only ever be of something the
container is meant to own. Phase 3 will use the same mechanism for image
layers under `--userns=remap`. `create` refuses the two variants it can't
honour:

```text
rustlet-runc: error: invalid config.json: mount bind $S/idm on /mnt: `idmap` needs a new user namespace (the mount is idmapped with the container's uidMappings/gidMappings)
rustlet-runc: error: config.json uses features this build does not support yet:
  - mount bind $S/idm on /mnt: uidMappings/gidMappings other than the container's own (not planned)
```

## 8. `exec` into a user namespace

Phase 2b's `exec` (architecture §2.2 step 6) leaves the parent on the
host, and the child joins the container with one `setns` on init's
pidfd. The user namespace is now part of that same call,
`setns(pidfd, USER|MNT|UTS|IPC|NET|CGROUP|TIME)`, minus whatever init
shares with us. The kernel handles the user namespace first and checks
the others with the credentials that gives. The container's user
namespace owns them all, so that's enough. Then the child calls
`become_root`, like init. Only after that does it join the container's
session keyring, which init created at `create` as `_ses.<id>`, by name.
The order matters. Keyring names are per user
namespace, and the container's keyring belongs to container root. A
child that looked it up while still host uid 0 wouldn't find it, and
would silently get a new, empty keyring of the same name.
`us_exec_joins_the_containers_session_keyring` compares the serial
numbers that init and `exec` print. The rlimits and `oom_score_adj` are
set before the `setns`, while the child is still host root on the host's
filesystem.

```text
$ $R exec box sh -c 'id; readlink /proc/self/ns/user; readlink /proc/1/ns/user; …'
uid=0(root) gid=0(root)
user:[4026532530]
user:[4026532530]
$ readlink /proc/self/ns/user                   # the host's
user:[4026531837]
$ $R exec -d -u 65535:0 --pid-file $S/e.pid lim sleep 60; ps -o user= -p $(cat $S/e.pid)
1065535
$ $R exec -d -u 65536:0 --pid-file $S/e.pid lim sleep 60
rustlet-runc: error: invalid config.json: process.user.uid 65536 is not mapped in the container's user namespace (linux.uidMappings: 0 1000000 65536)
```

`exec` checks the process's ids against the container's maps before it
does anything, as `create` does. The kernel would refuse the `setresuid`
with a bare `EINVAL`.

## 9. Refused at `create`, and what's different

Each of these fails before anything exists, with a reason, and leaves
nothing behind (`$R list` was empty afterwards):

```text
== hostroot     .linux.uidMappings = [{"containerID": 0, "hostID": 0, "size": 65536}]
rustlet-runc: error: invalid config.json: linux.uidMappings: `0 0 65536` maps host id 0, the host's root, into the container; map unused host ids instead (e.g. `0 1000000 65536`)
== unmapped     .process.user.uid = 70000
rustlet-runc: error: invalid config.json: process.user.uid 70000 is not mapped in the container's user namespace (linux.uidMappings: 0 1000000 65536)
== devpts       .linux.gidMappings = [{"containerID": 0, "hostID": 1000000, "size": 1}]
rustlet-runc: error: invalid config.json: mount devpts on /dev/pts: option `gid=5`: gid 5 is not mapped in the container's user namespace (map it, or drop the option)
== nopid        no pid namespace
rustlet-runc: error: invalid config.json: a new user namespace needs a new `pid` namespace too: only the owner of a PID namespace may mount its procfs, and the container's /proc must be one
== noipc        no ipc namespace
rustlet-runc: error: invalid config.json: mount mqueue on /dev/mqueue: with a user namespace, mqueue can only be mounted in a new `ipc` namespace (the kernel wants the IPC namespace's owner)
== bypath       {"type": "user", "path": "/proc/1/ns/user"}
rustlet-runc: error: config.json uses features this build does not support yet:
  - linux.namespaces: joining a user namespace by path (not planned)
== netsysctl    no network namespace, .linux.sysctl = {"net.ipv4.ip_forward": "1"}
rustlet-runc: error: invalid config.json: sysctl net.ipv4.ip_forward needs a new network namespace: with a user namespace, container root may only change sysctls of namespaces created with it (add {"type": "network"} to linux.namespaces, without a path)
== domain       .linux.sysctl = {"kernel.domainname": "example.org"}
rustlet-runc: error: invalid config.json: sysctl kernel.domainname can't be set in a container with a user namespace: the kernel only lets host root write UTS sysctls (set the spec's `domainname` field instead)
== nouserns     maps, but no user namespace
rustlet-runc: error: invalid config.json: linux.uidMappings/gidMappings are set, but linux.namespaces has no new `user` namespace to apply them to (add {"type": "user"})
== overlap      .linux.uidMappings += [{"containerID": 5, "hostID": 2000000, "size": 1}]
rustlet-runc: error: invalid config.json: linux.uidMappings: `0 1000000 65536` and `5 2000000 1` overlap on the container side
== longmap      .linux.uidMappings += [range(199) | {"containerID": (1000000000 + 2*.), "hostID": (2000000000 + 2*.), "size": 1}]
rustlet-runc: error: invalid config.json: linux.uidMappings: the map is 4792 bytes as text; the kernel takes at most 4095 (fewer lines, or smaller numbers)
== noatime      /proc's options += ["noatime"]
rustlet-runc: error: invalid config.json: mount proc on /proc: with a user namespace the kernel refuses `noatime`, `strictatime` and `nodiratime` (a new proc or sysfs must keep the host's atime mode)
== hostsysexec  no network namespace, /sys's options += ["exec"]
rustlet-runc: error: invalid config.json: mount rbind of the host's /sys on /sys: with a user namespace the kernel refuses `suid`, `dev` and `exec` (the host's sysfs mounts keep their flags, locked)
```

`userns::validate` checks a map the way the kernel will: at most 340
lines, less than a page (4096 bytes) of text in all, since the whole map
is one `write`, no size 0, nothing reaching `u32::MAX` (which means "no
id"), no overlap on either side. That way a bad map fails with a reason
rather than an `EINVAL` from writing `uid_map`. The two mount refusals come
from how the kernel treats proc and sysfs in a user namespace (§6): a new
instance may not show more than the host's visible one, and the kernel
compares their flags, atime mode included. The host's `/sys` copied in
without a network namespace was copied into a less privileged mount
namespace, and that locks every flag its mounts have, so `exec` (clearing
`noexec`) fails. **Joining a user namespace by
path** is refused because the parent would have to `setns` into it before
`clone3`, and would then have lost its host privileges for everything it
still has to do after that: the state files, and init's rlimits and
`oom_score_adj`. The daemon never
shares user namespaces, so nothing needs it.

**Deliberate differences:**

- **Host id 0 in a map is refused.** OCI allows it, and runc accepts it.
  Container root would then be host root to everything that checks
  *ids* rather than capabilities. Sysctl files are one example: they're
  writable by host uid 0, and a read-only `/proc/sys` is one mount option
  away for a container with `CAP_SYS_ADMIN`. The point of the remap is
  that container root isn't host root.
- **Every container gets its rootfs from the parent's tree**, and waits
  for the parent at the same two points, with or without a user namespace.
- **`/dev/mqueue` shows as `nobody`** (§6).

**Tests.** [`tests/tests/userns.rs`](../../tests/tests/userns.rs) has 20
black-box tests. They cover the maps as seen inside and from the host,
the rootfs owners, unchanged caps and seccomp, and rlimits and
`oom_score_adj` set from outside. Also: the `/dev` binds, masked and
read-only paths, sysctls, both sysfs cases, the idmapped mount and the
flags of the parent's trees once attached. Then `exec`'s user namespace
and keyring, the terminal, `exec -u` with an unmapped uid, and the
refusals above. The review's findings each have an `rr_` test in
[`review_regressions.rs`](../../tests/tests/review_regressions.rs). Here:

```text
$ cargo xtask itest -- us_
itest: kernel 7.0.0-34-generic (11 test binaries)
…
running 20 tests
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s
```

The full suite is 203 privileged tests and 195 unit tests, and all pass.

## 10. Try it

```sh
cargo build -p rustlet-runc
cargo xtask rootfs --remap          # once: bundles/alpine-remap, owned by host ids 1000000+ (re-runs itself under sudo)
cargo xtask demo --userns           # an interactive shell in it: try id, ls -ln /, cat /proc/self/uid_map
mkdir -p /tmp/un
jq --arg r "$PWD/.rustlet-dev/bundles/alpine-remap/rootfs" \
   '.root.path = $r | .process.terminal = false | .process.args = ["sleep", "3600"]' \
   .rustlet-dev/bundles/alpine-remap/config.json > /tmp/un/config.json
R="sudo ./target/debug/rustlet-runc"
$R create --bundle /tmp/un web && $R start web
pid=$($R state web | jq .pid); ps -o user,pid,cmd -p $pid; cat /proc/$pid/uid_map
$R exec web sh -c 'id; ls -ln / | head -3; ls -lnd /dev/mqueue /proc/sys/vm/swappiness /proc/sys/kernel/shmmni'
$R exec web cat /proc/self/mountinfo          # the rootfs on /, /dev binds from udev
$R exec -d -u 1000:1000 web sleep 3600; ps -o user,pid,cmd -u 1001000
$R exec -u 70000 web true                     # not mapped
$R delete -f web
mkdir -m 755 /tmp/un/idm && echo x > /tmp/un/idm/f
jq --arg s /tmp/un/idm '.process.args = ["sh", "-c", "ls -ln /mnt; echo y > /mnt/by-root"]
    | .mounts += [{"destination": "/mnt", "type": "bind", "source": $s, "options": ["bind", "idmap"]}]' \
   /tmp/un/config.json > /tmp/un/c.json && mkdir -p /tmp/un/i && mv /tmp/un/c.json /tmp/un/i/config.json
$R run --bundle /tmp/un/i i1; ls -ln /tmp/un/idm        # by-root is host root's
unshare -Ur sh -c 'grep CapEff /proc/self/status; mknod /tmp/un/n c 1 3'   # every capability, still EPERM
grep -c . /proc/self/mountinfo                          # the same number as before you started
```

The refusals of §9 each take one `jq` edit of `/tmp/un/config.json`,
shown next to each one.

## Check yourself

1. A host directory of uid 1000, mode `0755`, is bind-mounted into a
   remapped container. What owner does container root see, and why can't
   it write there despite `CAP_DAC_OVERRIDE`? With `idmap`, what owner
   does it see, and whose file does its write create on disk?
2. Why must the maps be written by the parent, not by init? What do
   `unshare -Ur`'s `groups=…65534(nogroup)` and its `setgroups` file tell
   you, and why do Rustlets' containers not have that problem?
3. Init waits for the parent twice, even without a user namespace. What
   does the parent do each time? Why couldn't init set its own limits in a
   user namespace, even with `CAP_SYS_RESOURCE` in all its sets, and why
   does the parent wait until init's mounts are done?
4. Why is the rootfs opened by the parent and attached on top of `/`,
   rather than bound onto itself by init as in Phase 1? Why may init
   detach the old root after `pivot_root`, although the kernel locked it?
5. With `--net=host` and a user namespace, why can't init mount a new
   sysfs? What does it mount instead, and why is that copy made by init
   and not by the parent?
6. Why must `exec` call `become_root` before joining the session keyring?
   What would go wrong, and why wouldn't anything report an error?
7. OCI allows `0 0 65536`. Name one thing container root could do with
   that map that it can't with `0 1000000 65536`, even with the same
   capabilities.

## Experiments

- **Map a namespace as root.** Start `sudo unshare -U sleep 600 &` and
  write `0 1000000 65536` to its `uid_map` with `sudo tee`. That's what §3's
  unprivileged write couldn't do. Which of §3's rules still apply to root:
  one write, only once, `setgroups` first? Look at `sudo nsenter -t
  <pid> -U id` before and after you write `gid_map`.
- **Who owns `/dev/mqueue`?** As yourself, `unshare -Urmi sh -c 'mount -t
  mqueue none /mnt && ls -lnd /mnt'` prints `drwxrwxrwt 2 0 0 …`. Why
  `0 0` here, when the container's shows `65534`? Sketch the change that
  would fix Rustlets: which flag leaves `clone3`, where in `init.rs`
  would init create that namespace instead, and is the new IPC namespace
  still owned by the container's user namespace?
- **The same limits without a user namespace.** Repeat §3's `sysres` run
  on `.rustlet-dev/bundles/alpine` (no user namespace, so no maps). With
  `CAP_SYS_RESOURCE` added, does `ulimit -Hr 6` work now? Without it? Which
  of the two runs tells you about capabilities, and which about user
  namespaces?
