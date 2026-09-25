# 04 — cgroups v2: limits, freezing, killing, counting

Chapters 01–03 were about what a container can *see*. This one is about how
much it can *use*. A process in its own PID namespace can still fork until the
host runs out of PIDs, or allocate until the host's OOM killer picks a victim,
possibly outside the container. **Control groups** are the kernel's answer:
put processes in a group, then meter and limit the group. Phase 2a adds them,
with the commands that need them: `pause`, `resume`, `kill --all`, `ps`,
`events --stats`.

Code: [`cgroups/mod.rs`](../../crates/rustlet-runtime/src/cgroups/mod.rs), [`resources.rs`](../../crates/rustlet-runtime/src/cgroups/resources.rs),
[`stats.rs`](../../crates/rustlet-runtime/src/cgroups/stats.rs), [`create.rs`](../../crates/rustlet-runtime/src/create.rs),
[`init.rs`](../../crates/rustlet-runtime/src/init.rs), [`ops.rs`](../../crates/rustlet-runtime/src/ops.rs),
[`run.rs`](../../crates/rustlet-runtime/src/run.rs). Privileged tests:
[`cgroups.rs`](../../tests/tests/cgroups.rs) (`cargo xtask itest -- cgroup_`)
and [`cgroup_limits.rs`](../../tests/tests/cgroup_limits.rs) (`-- cg_`).

The payoff: a container limited to 32 MiB, and no swap, tries to fill a 64 MiB buffer.

```text
$ rustlet-runc run --bundle … c1        # args: dd if=/dev/zero of=/dev/null bs=64M count=1
rustlet-runc: warning: the OOM killer killed 1 process(es) in the container (memory.max = 33554432)
$ echo $?
137
```

All transcripts are real runs on this host (kernel 7.0, systemd 255) in a
throwaway delegated scope (§9), minus the usual "full root privileges" warning.

## 1. A cgroup is a directory

cgroup v2 is a filesystem, `cgroup2`, mounted at `/sys/fs/cgroup`, and
nearly everything is a file operation. `mkdir` creates a cgroup, writing a
PID to `cgroup.procs` moves a process in, writing `memory.max` limits it,
reading `memory.current` meters it, `rmdir` removes it once it's empty. You
never create files: the kernel fills a new directory itself. A container's
cgroup, grouped by prefix:

```text
cgroup.   controllers events freeze kill max.depth max.descendants pressure procs stat
          stat.local subtree_control threads type
cpu.      idle max max.burst pressure stat stat.local uclamp.max uclamp.min weight weight.nice
io.       pressure
memory.   current events events.local high low max min numa_stat oom.group peak pressure
          reclaim stat swap.current swap.events swap.high swap.max swap.peak zswap.current
          zswap.max zswap.writeback
pids.     current events events.local max peak
```

`cgroup.*` is the core, present everywhere. The rest belongs to the
**controllers** enabled here: `cpu`, `memory`, `pids`. The `*.pressure`
files come from the core too, which is why `io.pressure` exists without the
`io` controller.

**One tree.** v1 had a hierarchy per controller, so a process could sit in
`/a` for memory and `/b/c` for CPU. v2 has one *unified* hierarchy: a process
is in exactly one cgroup, hence the single `0::` line in `/proc/self/cgroup`.

**Controllers are enabled top-down.** `cgroup.controllers` lists what a
cgroup's parent offers it. `cgroup.subtree_control` lists what it passes on
to its own children, which can only be what it was offered:

```text
/sys/fs/cgroup                         controllers: cpuset cpu io memory hugetlb pids rdma misc dmem
system.slice/rustlet-itest-doc-3.scope controllers: cpuset cpu io memory pids
                                       subtree_control: (empty until rustlet-runc writes "+cpu +io +memory +pids")
…/c1 (the container)                   controllers: cpu io memory pids
```

`Cgroup::create` walks from the delegated root (§2) down to the container's
parent. At each level `enable_controllers` checks what's offered and enables
what's missing, in one write. It always asks for `cpu io memory pids`
(`DEFAULT_CONTROLLERS`), limits or not: without them there would be no
`memory.current` or `io.stat` to report and no `memory.events` to reveal an
OOM kill.

### The "no internal processes" rule

A non-root cgroup may contain processes *or* hand domain controllers such as
`memory` and `io` to its children, never both. Otherwise the kernel would have
to referee between a parent's own processes and its children. Here a process
sits in the scope, which has a child `x`:

```text
# echo +memory > $scope/cgroup.subtree_control
/usr/bin/echo: write error: Device or resource busy
# echo +pids > $scope/cgroup.subtree_control        # accepted…
# cat $scope/x/cgroup.type
domain invalid
```

`cpu`, `cpuset` and `pids` are *threaded* controllers, allowed next to
processes. But enabling one here turns the children into `domain invalid`,
and moving a process into `x` then fails with `EOPNOTSUPP`. Rustlets always
enables `memory`, so the rule holds in full, and `enable_controllers` turns
the `EBUSY` into a sentence about it (`cgroup_create_refuses_internal_processes`).

That's why the harness and `cargo xtask demo` first leave the scope's own
cgroup, where systemd started them, for a leaf: `mkdir $cg/runtime; echo $$ >
$cg/runtime/cgroup.procs` in [`demo.rs`](../../xtask/src/demo.rs), `<scope>/harness`
in `itest_scope()` ([`tests/src/lib.rs`](../../tests/src/lib.rs)).

## 2. Who owns the tree: systemd

On a systemd host, PID 1 treats itself as the single writer of the cgroup
tree. It creates a cgroup per unit, and it may rewrite `subtree_control` or
remove cgroups it doesn't know. A program that wants a subtree asks for one
with a unit that says `Delegate=yes`. systemd then leaves everything *below*
the unit's cgroup alone, and marks that cgroup:

```text
# getfattr -n trusted.delegate /sys/fs/cgroup/system.slice/rustlet-itest-doc-3.scope
trusted.delegate="1"
# getfattr -n trusted.delegate /sys/fs/cgroup/system.slice
/sys/fs/cgroup/system.slice: trusted.delegate: No such attribute
$ getfattr -d -m - /sys/fs/cgroup/system.slice/rustlet-itest-doc-36.scope     # as james
user.delegate="1"
```

`trusted.*` needs `CAP_SYS_ADMIN` to read or write (to anyone else the kernel
pretends it doesn't exist), so `SystemdDelegated` trusts that one: nobody
unprivileged can forge it. Before a cgroup handle (which can freeze and kill)
is created or opened, `find_delegated_root` walks up from the path's
**parent** to the nearest marked ancestor, so the container is **strictly
below** the delegated root. The delegated cgroup itself is the unit's: a
container there would break the rule above, and `delete --force` would
`cgroup.kill` the whole unit, in the tests the test binary itself
(`cg_refuses_the_delegated_scope_itself`). A path under a scope that had gone:

```text
rustlet-runc: error: invalid config.json: refusing to manage cgroup /system.slice/rustlet-itest-doc-11.scope/c1: it is not
inside a subtree that systemd delegated to us (no ancestor carries the xattr trusted.delegate=1). Run under a unit …
```

`CgroupPath::parse` first does the lexical part. It accepts absolute paths
only, with no empty, `.` or `..` components: a string-prefix check would wave
`<scope>/../elsewhere` through. runc's `slice:prefix:name` syntax is refused,
since it needs D-Bus. Layouts that pass:

```text
cargo xtask itest    system.slice/rustlet-itest-<pid>-<n>.scope/   (-p Delegate=yes -p TasksMax=4096 -p MemoryMax=4G)
                     ├── harness/                                  the test binary
                     └── cg-oom-run-<n>/ …                         container cgroups
cargo xtask demo     system.slice/rustlet-demo-<pid>.scope/{runtime,demo}
Phase 4 (rustletd)   system.slice/rustletd.service/                packaging/rustletd.service: Delegate=yes
                     ├── daemon/                                   DelegateSubgroup=daemon
                     └── containers/<id>/                          intermediate made on demand by Cgroup::create
```

## 3. Placement: born inside

The classic way is `fork()`, then the parent writes the child's PID into
`cgroup.procs`. In between, the child runs in the *parent's* cgroup,
unlimited, and the damage outlasts the window. The write moves one process
(all its threads), not children it has already forked. And memory the child
touched stays charged to the old cgroup (§8). Making the child wait on a pipe
until it's been moved shrinks the window without closing it.

Linux 5.7 added `CLONE_INTO_CGROUP`: `clone3` takes a directory fd of the
target cgroup, and the child is in it before it runs a single instruction.
`create.rs` creates the cgroup and writes its limits first, then:

```rust
let mut clone = Clone3::new().flags(plan.namespaces.clone_flags | CloneFlags::PIDFD);
if let Some(fd) = &cgroup_fd {
    clone = clone.into_cgroup(fd.as_fd());
}
```

`strace -f` of a run with 32 MiB and 64 PIDs (trimmed):

```text
write(3, "+cpu +memory +pids", 18)      = 18       # <scope>/cgroup.subtree_control
mkdir("…/rustlet-itest-doc-32.scope/c1", 0755) = 0
write(3, "33554432", 8)                 = 8        # c1/memory.max
write(3, "0", 1)                        = 1        # c1/memory.swap.max
write(3, "64", 2)                       = 2        # c1/pids.max
openat(AT_FDCWD, "…/rustlet-itest-doc-32.scope/c1", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3
clone3({flags=CLONE_PIDFD|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWNET|CLONE_INTO_CGROUP, …, cgroup=3}, 88) = 215296
[pid 215296] unshare(CLONE_NEWCGROUP)   = 0
```

The child first drops its copy of that fd (a host directory fd inside a
container is the CVE-2024-21626 leak). Limits without `linux.cgroupsPath` are
refused; with neither, the container stays in the caller's cgroup.

### The cgroup namespace

After placement, init calls `unshare(CLONE_NEWCGROUP)`, and its current
cgroup becomes its root:

```text
host:      /proc/214993/cgroup   0::/system.slice/rustlet-itest-doc-20.scope/c1
host:      rustlet-runc itself   0::/system.slice/rustlet-itest-doc-20.scope/runtime
container: /proc/self/cgroup     0::/
```

A cgroup namespace is rooted wherever the process is **when the namespace
is created**, and the root never moves. Unshare before the move and it's
wrong for good. Worse, the host mounts cgroup2 with `nsdelegate`, which makes
namespaces delegation boundaries: a process that unshared in `runtime` and
then tried to move itself to a sibling got `ENOENT` from `cgroup.procs`.

Why not `CLONE_NEWCGROUP` in the `clone3` flags? The architecture doc (§2.2
step 4.4) and chapter 03 say `clone3` copies namespaces before placing the
child, so the namespace would be rooted at the parent's cgroup. A small
ctypes program on this kernel says otherwise:

```text
A clone3(NEWCGROUP|INTO_CGROUP): child sees '0::/'; host sees '0::/system.slice/rustlet-itest-doc-34.scope/n1'
B clone3(INTO_CGROUP)+unshare:   child sees '0::/'; host sees '0::/system.slice/rustlet-itest-doc-34.scope/n1'
```

On 7.0 the kernel re-roots a namespace created by the same `clone3` at the
child's new cgroup. Unsharing after placement is correct either way, so the
code stands; only the stated reason was wrong. Test kernel claims.

### A read-only `/sys/fs/cgroup`

Init mounts a fresh cgroup2 instance from inside the namespace, so the
container sees its own cgroup as the root, with its own limits:

```text
/ # cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max
67108864
64
/ # echo 1000000 > /sys/fs/cgroup/pids.max
sh: can't create /sys/fs/cgroup/pids.max: Read-only file system
/ # mkdir /sys/fs/cgroup/escape
mkdir: can't create directory '/sys/fs/cgroup/escape': Read-only file system
/ # grep ' /sys/fs/cgroup ' /proc/self/mountinfo
487 486 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
```

Two independent barriers keep container root from raising its own limits.
One is the `ro` mount. The other is `nsdelegate`: through the host's
*writable* mount, a process in a namespace rooted at `x` still got `EPERM`
writing `x/memory.max`. The `ro` mount doesn't depend on how the host mounted
cgroup2, and it also stops the container from creating cgroups.

## 4. The OCI → v2 mapping

OCI's `linux.resources` was designed for cgroup v1, so `settings_for` in
[`resources.rs`](../../crates/rustlet-runtime/src/cgroups/resources.rs)
translates. It is a pure function from the spec to an ordered list of
`(file, value)` writes, unit-tested without root:

| OCI | v2 file | conversion |
|---|---|---|
| `memory.limit` | `memory.max` | bytes; `-1` → `max` |
| `memory.swap` | `memory.swap.max` | `swap − limit` (v1 counted memory+swap) |
| `memory.reservation` | `memory.low` | protection from reclaim below this |
| `cpu.shares` | `cpu.weight` | log-scale formula, 1024 → 100 |
| `cpu.quota`, `cpu.period` | `cpu.max` | `"<quota\|max> <period>"`, period defaults to 100000 |
| `cpu.burst`, `cpu.idle` | `cpu.max.burst`, `cpu.idle` | order matters (§8) |
| `cpu.cpus`, `cpu.mems` | `cpuset.cpus`, `cpuset.mems` | as is |
| `pids.limit` | `pids.max` | `≤ 0` → `max` |
| `blockIO.weight`, `weightDevice` | `io.weight` | `default N` / `MAJ:MIN N`; 10–1000 → 1–10000 linearly |
| `blockIO.throttle*Device` | `io.max` | `MAJ:MIN rbps=N`, one write per device and key |
| `hugepageLimits` | `hugetlb.<size>.max` | size checked strictly: it becomes a file name |
| `unified` | any `<controller>.<name>` | passed through, sorted, written last |

**shares → weight.** v1 shares run from 2 to 262144 with a default of 1024;
v2 weights from 1 to 10000 with a default of 100. The obvious linear map,
`1 + (shares − 2) · 9999 / 262142`, gets the ends right and the middle wrong:

| shares | 2 | 512 | **1024** | 2048 | 262144 |
|---|---|---|---|---|---|
| linear | 1 | 20 | **39** | 79 | 10000 |
| log-scale (runc 1.3, from crun) | 1 | 59 | **100** | 174 | 10000 |

With the linear map every container that asks for nothing special gets
weight 39, not 100: under contention, well under half the CPU of an
unconfigured sibling. The fix is a quadratic in log space through all three
anchor points:

```rust
let l = (shares as f64).log2();
let exponent = (l * l + 125.0 * l) / 612.0 - 7.0 / 34.0;   // l=1 → 0, l=10 → 2, l=18 → 4
10f64.powf(exponent).ceil() as u64
```

**Swap.** v1's `memory.memsw.limit_in_bytes`, and so OCI's `swap`, limits
memory **plus** swap; v2's `memory.swap.max` limits swap alone. Limit 64M with
swap 96M means 32M of swap, and **swap = limit means none**, as the tests and
the demo use. A swap below the limit, or with no memory limit, is an error. Omit it and,
like runc, `memory.swap.max` stays `max`: on this host (2 GiB swapfile) a
container over its limit would swap rather than be OOM-killed promptly.
Docker's "as much swap again" default is for the daemon (Phase 4).

**`cpu.max`** holds two numbers: at most `quota` µs of CPU per `period` µs, so
`50000 100000` is half a CPU. A quota alone gets the kernel's default 100 ms
period. A period alone gets `max`, no limit.

**0 means unset, as in runc**, whose Go structs use 0 for "not set":
`"limit": 0` is *no* memory limit, not a 0-byte one, under both runtimes.

**v1-only fields are errors, not no-ops.** `memory.kernel`, `kernelTCP`,
`swappiness`, `disableOOMKiller`, `cpu.realtime*`, `blockIO.leafWeight` and
`network` have no v2 file. Skipping them silently would run a container
without limits its author believes are in place:

```text
rustlet-runc: error: invalid config.json: linux.resources.memory.swappiness only exists in cgroup v1; this host uses cgroup v2 (remove it from config.json)
```

`unified` passes raw v2 keys through (`memory.high`, …), except the six that
control the cgroup rather than limit it: `cgroup.procs`, `.threads`, `.kill`,
`.freeze`, `.subtree_control` and `.type`.

## 5. Lifecycle: freeze, kill, remove

### `pause` and `resume`: `cgroup.freeze`

```text
$ rustlet-runc pause c1
$ rustlet-runc state c1 | grep status
  "status": "paused",
$ cat c1/cgroup.events
populated 1
frozen 1
$ grep State /proc/<init>/status
State:	S (sleeping)
$ rustlet-runc delete c1
rustlet-runc: error: cannot delete container "c1": it is paused (stop it first, or use --force)
$ rustlet-runc resume c1
$ cat c1/cgroup.events
populated 1
frozen 0
```

The write to `cgroup.freeze` returns at once, but freezing **is
asynchronous**: every task has to notice and park itself. With eight busy
loops in a cgroup:

```text
right after the write: populated 1 frozen 0; frozen 1 after 2984 us (163 extra reads)
right after the write: populated 1 frozen 0; frozen 1 after 820 us (26 extra reads)
```

So `Cgroup::freeze` polls `cgroup.events` every 10 ms until `frozen 1` (`thaw`
until `frozen 0`), failing with `ETIMEDOUT` after `pause`'s 10 s. A frozen
task shows `S (sleeping)`, not SIGSTOP's `T (stopped)`. `status` is derived,
never trusted from `state.json`: `paused` *means* "init alive, cgroup frozen".

### `kill --all`: `cgroup.kill`

Killing PID by PID is a race you lose against a fork bomb: between reading
`cgroup.procs` and calling `kill()`, new children appear. `cgroup.kill`
(Linux 5.14) SIGKILLs every process in the subtree at once. The kernel
handles concurrent forks and migrations, and frozen processes die too
(`cgroup_lifecycle_freeze_thaw_kill_remove`). `kill --all c1 KILL` uses it;
other signals still loop over `cgroup.procs`. A container at 64 processes:

```text
$ cat c1/pids.current c1/pids.events
64
max 63
$ rmdir c1
/usr/bin/rmdir: failed to remove '/sys/fs/cgroup/system.slice/rustlet-itest-doc-41.scope/c1': Device or resource busy
$ rustlet-runc kill --all c1 KILL          # cgroup.events said populated 0 some 4.5 ms later
$ cat c1/cgroup.events c1/pids.current
populated 0
frozen 0
0
```

(Init here was `sleep`, which never reaps: the orphans stayed zombies, which
keep their `pids` charge. A rerun showed `pids.current 64` with one process
in `cgroup.procs`. One more reason for a real init, chapter 03.)

Killing is asynchronous too: the processes still have to exit, and `rmdir`
says `EBUSY` until `cgroup.events` shows `populated 0` (per `remove`'s
comment, briefly after too). So teardown is always `kill → wait_empty →
remove`, with a few `EBUSY` retries. It also undoes a failed `create`: a
cgroup whose settings fail removes itself, and `CreateGuard` kills init and
removes the cgroup and state directory on every later error path. After these
failing creates (and one refused at validation), the scope held only `runtime`:

```text
rustlet-runc: error: cannot run the program: executable file not found in $PATH: "no-such-program" (PATH=…)
rustlet-runc: error: write "lots" to /system.slice/rustlet-itest-doc-45.scope/c2/memory.high (the kernel rejected the value): EINVAL: Invalid argument
rustlet-runc: error: write "30000" to /system.slice/rustlet-itest-doc-45.scope/c4/cpu.max.burst (the kernel rejected the value): EINVAL: Invalid argument
$ ls $scope | grep -v '\.'
runtime
```

### Never someone else's cgroup

`cgroup.kill` and `populated` are *recursive*. So if a container's cgroup
could sit inside another container's, deleting the outer one, even a
*stopped* one, would kill the inner one. An independent review of this
phase found exactly that. The fixes, all in
[cgroups/mod.rs](../../crates/rustlet-runtime/src/cgroups/mod.rs):

- Every container cgroup is tagged with the xattr `user.rustlet.container=<id>`.
  `Cgroup::create` refuses to create below a tagged cgroup ("container
  cgroups can't be nested"), and `Cgroup::remove_tree` refuses to remove a
  tree that contains one.
- `state.json` records the cgroup directory's **inode**. A cgroup removed and
  re-created at the same path gets a new inode, so a stale state file can
  never freeze, kill or remove its successor: `State::cgroup` checks the inode
  first.
- `remove_tree` kills, waits for `populated 0`, then removes any child
  cgroups the container made itself, deepest first, and finally the
  container's own.

The regression tests are in
[review_regressions.rs](../../tests/tests/review_regressions.rs).

## 6. OOM: the kill says nothing, `memory.events` says why

At `memory.max` the kernel reclaims, and when that fails it runs the OOM
killer *inside the cgroup*. Its weapon is plain SIGKILL, so the exit status
(137 = 128 + 9) is exactly what `kill -9` gives. The reason lives only in the
cgroup's counters. Here is the same `dd`, run with `create`/`start` so the
cgroup could be read before teardown:

```text
before:  low 0  high 0  max 0   oom 0  oom_kill 0  oom_group_kill 0  sock_throttled 0
after:   low 0  high 0  max 70  oom 2  oom_kill 1  oom_group_kill 0  sock_throttled 0
```

`max` counts hits on the limit, `oom` the times reclaim couldn't help,
`oom_kill` the processes killed. The kernel log names the victim:

```text
kernel: Memory cgroup out of memory: Killed process 66003 (dd) total-vm:67172kB, anon-rss:32616kB, …
```

When a foreground container exits, `report_oom` (`run.rs`) reads
`memory.events` before the cgroup goes, and warns if `oom_kill > 0`. The
victim is usually the biggest process, not necessarily init: under the demo's
64M, `dd bs=64M` in a shell dies (`Killed`, 137), the shell carries on and
exits normally, and the warning still appears. `memory_events()` errors
without the memory controller rather than claim "no OOM". Detached
containers show the count in `events --stats`; from Phase 4 the shim reports it.

## 7. Counting: `events --stats`

One runc-style envelope, from the paused-and-resumed container above (two
`sleep`s and a counter loop; 64 MiB, 64 PIDs, half a CPU), trimmed:

```json
{"type": "stats", "id": "c1", "data": {
  "cpu": {"usage_usec": 9077, "user_usec": 907, "system_usec": 8170,
          "nr_periods": 6, "nr_throttled": 0, "throttled_usec": 0, "nr_bursts": 0, …},
  "memory_current": 1257472, "memory_max": 67108864, "memory_peak": 1593344, "swap_current": 0,
  "memory_stat": {"anon": 212992, "file": 4096, "kernel": 364544, "shmem": 4096, "pgfault": 630, …},
  "memory_events": {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0, "oom_group_kill": 0},
  "pids_current": 4, "pids_max": 64,
  "io": {"8:0": {"rbytes": 36864, "rios": 3, "wbytes": 0, "wios": 0, "dbytes": 0, "dios": 0}},
  "pressure": {"cpu": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total": 592},
                       "full": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total": 588}}, …},
  "network": [{"name": "lo", "rx_bytes": 0, "tx_bytes": 0, …}]}}
```

- **`cpu.stat`**: `usage_usec = user_usec + system_usec` (907 + 8170);
  `nr_periods`/`nr_throttled`/`throttled_usec` show `cpu.max` at work.
- **`memory.current`** is everything charged: anonymous memory, page cache
  (`file`) and kernel memory (stacks, page tables, slab), itemised in
  `memory.stat` (70 keys here). `memory.peak` is the high-water mark.
- **`io.stat`**: bytes and operations per block device (major:minor), read
  (`r`), written (`w`) and discarded (`d`). Only devices the container touched
  appear. (This sample comes from a container that read `/bin/busybox`
  once. An earlier build didn't enable `io` by default and always showed `{}`.)
- **PSI** (pressure stall information): `some` is the share of time in which
  *at least one* task was stalled on the resource, `full` the share in which
  *all* non-idle tasks were, averaged over 10, 60 and 300 s (`total` in µs).
  `memory some avg10=40`: for 40% of the last 10 s something waited for
  memory, say in direct reclaim. A container slow "for no reason" shows here.
- **`network`** is `/proc/<init>/net/dev`: the *network namespace*.

The parsers skip lines they don't know: kernels keep adding keys (`zswpwb`, 6.8).

## 8. Kernel surprises

Each of these came up while building Phase 2a, and each was verified here.

1. **With `O_CREAT`, a missing file gives `EACCES`, not `ENOENT`.** The
   shell's `>` uses `O_CREAT`:
   ```text
   # echo "8:0 rbps=1048576" > io.max                 # io not enabled here
   /bin/sh: 1: cannot create io.max: Permission denied
   # echo "8:0 rbps=1048576" | dd of=io.max conv=nocreat
   dd: failed to open 'io.max': No such file or directory
   ```
   cgroupfs directories can't create files, and the VFS reports that as
   `EACCES`, a baffling message for root. So `write_file` opens `O_WRONLY`
   only (not `std::fs::write`), and writes the value in one `write(2)`: the
   kernel parses each write as a whole.
2. **Write order matters in `cpu`.** Once `cpu.idle` is 1, `cpu.weight`
   refuses writes (`EINVAL`) and reads 1, so the weight goes first. The kernel
   checks `cpu.max.burst ≤ quota` whenever *either* file is written, though a
   quota of `max` accepts a burst. So `cpu.max` goes first, and a bad burst
   fails on the burst (the `c4` error in §5), not on an innocent `cpu.max`.
3. **`io.max` refuses 0** (`ERANGE`): v1's "0 = no limit" is `max` in v2.
   It also merges: `8:0 rbps=1048576` reads back with `wbps=max riops=max wiops=max`.
4. **Per-device `io.weight` needs iocost.** `default 500` works; `8:0 500`
   gives `EOPNOTSUPP` here (no iocost on `sda`), and `write_hint` says so.
5. **systemd doesn't delegate `hugetlb`.** The root offers it and the scope
   doesn't. A spec with `hugepageLimits` gets `…needs the hugetlb controller,
   but cgroup /system.slice/rustlet-itest-doc-49.scope doesn't offer it (it
   has: cpu cpuset io memory pids); the systemd unit must delegate it`.
6. **An empty cgroup freezes instantly**: `populated 0 | frozen 1` 49 µs after
   the write. And it stays "frozen" after its last process dies, so
   `State::refresh` must ask "is init alive?" *before* "is it frozen?".
7. **Memory is charged when it's allocated, not when a process moves in.**
   Here a process allocated 64 MiB in `runtime`, then moved to `a`:
   ```text
   before the move: runtime = 67 MiB, a = 0 MiB
   after the move:  runtime = 68 MiB, a = 0 MiB
   moved first:     b = 67 MiB
   after both exit: runtime = 1 MiB, a = 0 MiB, b = 0 MiB
   ```
   Pages stay charged where they were first touched. That's one more argument
   for `CLONE_INTO_CGROUP`, and why the stats test's `charged_sleeper` moves
   itself in *before* it execs.

## 9. Try it

```sh
cargo xtask demo --memory 64M --pids 64          # also: --cpus 0.5
```

This writes `.rustlet-dev/bundles/demo/config.json` (memory = swap = 64M,
`pids.max` 64, a PTY), then runs `sudo systemd-run --scope -p Delegate=yes
--unit=rustlet-demo-<pid>`, moves into `runtime`, and starts an Alpine shell
in `/sys/fs/cgroup/system.slice/rustlet-demo-<pid>.scope/demo`. Inside, try:

- `cat /proc/self/cgroup /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max`
  (`0::/`, 67108864, 64), then `echo max > /sys/fs/cgroup/memory.max`.
- `dd if=/dev/zero of=/dev/null bs=64M count=1`: `Killed`, and `echo $?`
  says 137. Then `grep oom /sys/fs/cgroup/memory.events`. On `exit`,
  `rustlet-runc` prints the OOM warning.
- A fork bomb: `bomb() { bomb | bomb & }; bomb` (`can't fork: Resource
  temporarily unavailable`). From the host, watch `…/demo/pids.current`
  (never above 64) and `pids.events`. This one burns out within a second;
  `bomb() { while :; do bomb & done; }; bomb &` keeps going until you exit.
  (In a *script*, ash treats a failed fork as fatal: exit status 2.)

The manual lifecycle, in a scope of your own (`scripts/cleanup.sh` sweeps up
if anything goes wrong):

```sh
mkdir -p /tmp/cg-demo && jq --arg r "$PWD/.rustlet-dev/bundles/alpine/rootfs" \
  '.root.path=$r | .process.terminal=false | .process.args=["sh","-c","while :; do sleep 1; done"]
   | .linux.cgroupsPath="/system.slice/rustlet-manual.scope/c1"
   | .linux.resources={"memory":{"limit":67108864,"swap":67108864},"pids":{"limit":64}}' \
  .rustlet-dev/bundles/alpine/config.json > /tmp/cg-demo/config.json
sudo systemd-run --scope --quiet --collect --unit=rustlet-manual -p Delegate=yes -- /bin/sh -c '
  cg=/sys/fs/cgroup/system.slice/rustlet-manual.scope
  mkdir $cg/runtime; echo $$ > $cg/runtime/cgroup.procs
  R="./target/debug/rustlet-runc --root /run/rustlet/manual"
  $R create --bundle /tmp/cg-demo c1; cat /proc/$($R state c1 | jq .pid)/cgroup; $R start c1
  $R pause c1; $R state c1 | grep status; cat $cg/c1/cgroup.events; $R resume c1
  $R events --stats c1 | jq .data.pids_current
  $R kill --all c1 KILL; $R delete --force c1'
```

## Check yourself

1. Why must `rustlet-runc` leave the scope's own cgroup before creating a
   container cgroup? Why was `+pids` accepted, and what did it break?
2. Why trust `trusted.delegate` rather than `user.delegate`? Why must a
   container cgroup be *strictly* below the delegated one?
3. Name two effects of fork-then-write-`cgroup.procs` that outlast the
   unlimited window. Why can't `CLONE_INTO_CGROUP` have either?
4. `shares: 1024`, `limit: 64M`, `swap: 96M`: what gets written where? What
   would the linear shares formula have written, and who loses?
5. Why is `kill --all c1 KILL` race-free while `kill --all c1 TERM` isn't?
   Why is `rmdir` right after `cgroup.kill` still wrong?
6. A container exited with 137. How do you tell an OOM kill from `kill -9`?

## Experiments

- Reproduce §3's `clone3` finding. A Python ctypes program can call
  `syscall(435, clone_args, 88)` with `CLONE_INTO_CGROUP` (`0x200000000`) and
  a cgroup dirfd in the last field, with and without `CLONE_NEWCGROUP`
  (`0x02000000`). Compare the child's `/proc/self/cgroup` with the host's
  view. Then `unshare` *before* moving, and read the errno.
- `cargo xtask demo --cpus 0.5`, then start `while :; do :; done &` twice.
  From the host, watch `nr_throttled` in `cpu.stat` and `cpu.pressure`.
  Which of `some` and `full` moves, and why?
- In the manual recipe, drop `"swap"` and make the args `dd if=/dev/zero
  of=/dev/null bs=64M count=1`. What happens, and what do `memory.swap.peak`
  and `memory.events` say?
