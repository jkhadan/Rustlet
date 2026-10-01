# 10 — eBPF devices: a node is not permission to use it

`/dev` is a tmpfs inside the container's mount namespace. That gives it
its own names, not its own devices: a character or block node's major and
minor numbers still identify a driver in the host kernel. A private
`/dev` and a `nodev` image rootfs do not make `CAP_MKNOD` safe by themselves.
Phase 2c part 2 puts a device filter on every container cgroup, before
init is born. The milestone is `mknod b 8 0` failing with `EPERM` even
with effective `CAP_MKNOD`, while `mknod c 1 3` still works.

Code: [`cgroups/devices/`](../../crates/rustlet-runtime/src/cgroups/devices/mod.rs)
(rules, reference evaluator, attachment),
[`compile.rs`](../../crates/rustlet-runtime/src/cgroups/devices/compile.rs),
[`interp.rs`](../../crates/rustlet-runtime/src/cgroups/devices/interp.rs),
[`dev.rs`](../../crates/rustlet-runtime/src/dev.rs) (node planning/population),
[`plan.rs`](../../crates/rustlet-runtime/src/plan.rs) (`check_mknod`),
[`create.rs`](../../crates/rustlet-runtime/src/create.rs),
[`exec.rs`](../../crates/rustlet-runtime/src/exec.rs),
[`spec.rs`](../../crates/rustlet-runtime/src/spec.rs) (host-device helpers), and
[`xtask/src/devices.rs`](../../xtask/src/devices.rs).
Tests: [`devices.rs`](../../tests/tests/devices.rs),
[`userns.rs`](../../tests/tests/userns.rs) and
[`differential.rs`](../../tests/tests/differential.rs).
Design: [architecture.md §2.2.2](../architecture.md#222-security-defaults).

The transcripts were recorded on 2026-09-30, kernel 7.0.0-34-generic.
`R` invokes `target/debug/rustlet-runc --root /run/rustlet/doc-10` as root
inside a systemd-delegated `rustlet-doc-10.scope`. Each bundle has an
absolute rootfs path, `terminal: false`, a read-only image rootfs and its
own `linux.cgroupsPath` below that scope. §10 gives the setup. Bundle
paths are shortened; program ids and mount ids vary between runs.
The host's mountinfo stayed at the same 24 lines.

## 1. cgroup v2 has no devices.allow

In cgroup v1, a devices controller had `devices.allow` and `devices.deny`
files. In v2 there are no device-controller interface files. Instead,
the kernel invokes an attached `BPF_PROG_TYPE_CGROUP_DEVICE` program for
device access and creation checks. Returning zero denies the operation
with `EPERM`; nonzero allows it. See the kernel's
[device-controller documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#device-controller).

The context is three 32-bit words:

```text
offset 0   access_type = (access << 16) | type
offset 4   major
offset 8   minor

type:    block = 1, character = 2
access:  mknod = 1, read = 2, write = 4
```

Names aren't in this context. `/dev/fuse` and `/dev/another-name` with
the same type and numbers get the same decision. Conversely, a renamed
block node cannot become `/dev/null` by taking its name. The filter
applies to the task's cgroup, including descendant cgroups, whatever
mount or pathname the task uses to reach the node.

An `O_RDWR` open asks for both read and write in one check. A successful
filter check is not a promise that an open succeeds: permissions, a
`nodev` mount, seccomp and the driver can still refuse it. FIFO creation
is not a character/block device check.

## 2. CAP_MKNOD is necessary, not sufficient

The milestone bundle adds `CAP_MKNOD` to bounding, effective and
permitted. It removes seccomp for this experiment, so the error cannot
be the default profile denying `mknod`. Its script prints CapEff, tries
a block node, then a second null node:

```text
$ R run --bundle milestone milestone
CapEff: 00000000880405fb
mknod: /dev/disk: Operation not permitted
block-rc=1
null-rc=0
character special file 1:3
```

The extra `0x08000000` bit is `CAP_MKNOD`. The filter denies block 8:0
and allows character 1:3. No host block device was opened or used.

`plan::check_mknod` checks **all five capability sets**, not just the
effective one. Without a filter, create refuses it with a message to
set `linux.cgroupsPath`. A new user namespace is the exception: device
`mknod` is already denied there, even to namespace root. Rules and spec
device nodes still need a cgroup in that case. Exec applies the same
gate to both `--cap CAP_MKNOD` and a process JSON, using the saved
filter id or the saved config's new user namespace. An old state file
without a filter id is not treated as proof of attachment.

Adding a capability does not rewrite a supplied seccomp profile. A
caller that needs `mknod` must also choose a profile that permits it.

## 3. linux.devices creates names; resources.devices grants access

These two OCI fields do different jobs:

```json
"devices": [{"path": "/dev/fuse", "type": "c", "major": 10, "minor": 229}]
```

That `linux.devices` entry creates a node. Init is already in the
filtered cgroup, so the plan also appends an implicit **m-only** allow
for its numbers. It does not grant read or write. With no access rule:

```text
$ R run --bundle fuse-node fuse-node
character special file a:e5 666 0:0
access:/dev/fuse:r EPERM
access:/dev/fuse:w EPERM
access:/dev/fuse:rw EPERM
```

The `a:e5` from `stat` is hexadecimal 10:229. The access lines come from
`rustlet-probe` calling `faccessat`; it does not open the driver. A
BusyBox `test -r` can use mode bits without exercising the device hook,
so it is not a useful proof of device filtering.

Add this `linux.resources.devices` rule:

```json
[{"allow": true, "type": "c", "major": 10, "minor": 229, "access": "rw"}]
```

```text
$ R run --bundle fuse-rw fuse-rw
access:/dev/fuse:r ok
access:/dev/fuse:w ok
access:/dev/fuse:rw ok
```

Now append the same rule with `allow: false, access: "w"`:

```text
$ R run --bundle fuse-deny-w fuse-deny-w
access:/dev/fuse:r ok
access:/dev/fuse:w EPERM
access:/dev/fuse:rw EPERM
access:/dev/fuse:f ok
```

The last line is `F_OK`: existence, with no requested device-access
bits. Device filtering allows that empty request; filesystem checks
still apply. The key line is `rw EPERM`. Rules are ordered, and the
last match wins **separately for each bit**:

| Request | Last read decision | Last write decision | Result |
|---|---|---|---|
| r | allow | not requested | allow |
| w | not requested | deny | deny |
| rw | allow | deny | deny |

The emitted program accumulates an allowed mask. An allow does
`allowed |= rule.access`, a deny does `allowed &= ~rule.access`.
At the end, `(requested & allowed) == requested` must hold. It starts
with no allowed bits unless the optimiser has folded a full reset.

## 4. Defaults are appended, not an initial policy

`DeviceFilter::build` assembles three groups, in this order:

1. Spec `linux.resources.devices` rules, in their given order.
2. The eight built-in defaults, all `rwm`.
3. Creation-only `m` rules for rootful character/block `linux.devices`.

The defaults are:

| Device | Type and numbers |
|---|---|
| null, zero, full | c 1:3, c 1:5, c 1:7 |
| random, urandom | c 1:8, c 1:9 |
| tty | c 5:0 |
| ptmx | c 5:2 |
| pty slaves | c 136:* |

The six ordinary nodes and their rules share `dev::DEFAULT_DEVICES`.
`/dev/ptmx` is a symlink into a new devpts mount. `/dev/console` is a
bind of a pty slave, so no separate c 5:1 permission is needed.

Like runc, defaults are appended after spec rules: a leading `deny a`
does not break null or a terminal. This also means **a spec cannot deny
a default device**. An implicit creation rule likewise takes precedence
over a spec deny of `m` for that node; it does not restore denied `r`/`w`.

Rustlets deliberately has no blanket `c *:* m` or `b *:* m`, and no tun
10:200 default. Merely adding `CAP_MKNOD` cannot create arbitrary host
device numbers. A caller can opt in with explicit rules.

Rules accept types `a`, `b`, `c` (absent means `a`), nonempty access
made of `rwm`, and numbers in the kernel's major/minor ranges:
0–4095 and 0–1048575. Missing numbers or `-1` mean wildcard. A type `a`
rule must be exactly wildcard numbers and full `rwm`, because accepting
a partial or numbered all-types rule would be ambiguous. Invalid rules
fail during planning, before any cgroup is created.

## 5. Creating nodes without trusting container paths

`dev::plan` validates paths against the mount plan. They must be clean
absolute paths strictly under `/dev`: no `..`, `.`, repeated slash or
trailing slash. No duplicate paths, node below another node, mount at/
above/below a node (except the `/dev` mount), or standard symlink/console
path is accepted. `/dev` must be a tmpfs. Replacing `/dev/null` is allowed
only if it remains character 1:3; masking depends on that identity.

For rootful nodes, population walks from the `/dev` fd, makes parent
directories, then uses `mknodat` → `fchownat` → `fchmodat`. Absent
metadata means `0666`, uid 0, gid 0. Chmod comes after chown because
chown can clear the requested setid bits. An existing non-default node
is an error, not silently reused. `u` means character; `p` means FIFO.

The metadata bundle specifies `/dev/net/tun` as `u`, 10:200, mode
`02640` (JSON 1440), uid 12, gid 34; and `/dev/events` as a FIFO, mode
`0640` (JSON 416), with the same owner. Only their metadata is inspected:

```text
$ R run --bundle metadata metadata
character special file a:c8 2640 12:34
fifo 0:0 640 12:34
```

Inside a new user namespace, character/block nodes cannot be mknod'ed.
Instead, `bind_host_device` opens a detached copy of the **same host
`/dev` path**, checks its type and rdev, then attaches it to the target.
Mode and ownership are the host node's, not the requested metadata.
Here `/dev/fuse` was requested as `0600`, uid 123, gid 456; the host node
is actually `0666`, host root-owned:

```text
$ R run --bundle userns-fuse userns-fuse
character special file a:e5 666 65534:65534
639 538 0:7 /fuse /dev/fuse rw,nosuid,relatime - devtmpfs udev rw,size=3377004k,nr_inodes=844251,mode=755,inode64
```

Host root is not mapped, so the owner displays as 65534. The mountinfo
line proves this is a bind of the host devtmpfs node, not a new node on
the container's tmpfs. FIFOs are different: they can be created locally,
and their requested owners must be mapped.

Bad plans explain the missing prerequisite rather than failing halfway
through init:

```text
$ R create --bundle no-cgroup no-cgroup
rustlet-runc: error: invalid config.json: linux.resources.devices needs a device filter: set linux.cgroupsPath
$ R create --bundle bad-path bad-path
rustlet-runc: error: invalid config.json: linux.devices[0] (/mnt/fuse): path must be absolute and clean, strictly under /dev
```

## 6. Read the actual eBPF program

`cargo xtask devices --disasm` shows the defaults: 8 rules, 8 compiled,
89 instructions. `--bundle DIR` uses the runtime's `Plan::new`, not a
second approximation: it includes node validation and implicit `m` rules.
The fuse partial-deny bundle gives 11 rules (2 spec, 8 defaults, 1 node)
and 119 instructions.

For the live default container, the kernel's listing was the same as
the xtask listing. Here is its prologue, first rule and epilogue; the
middle seven rules are omitted:

```text
$ bpftool prog dump xlated id 33442
   0: (61) r2 = *(u32 *)(r1 +0)
   1: (bc) w3 = w2
   2: (74) w3 >>= 16
   3: (54) w2 &= 65535
   4: (61) r4 = *(u32 *)(r1 +4)
   5: (61) r5 = *(u32 *)(r1 +8)
   6: (b4) w6 = 0
   7: (bc) w7 = w2
   8: (a4) w7 ^= 2
   9: (56) if w7 != 0x0 goto pc+7
  10: (bc) w7 = w4
  11: (a4) w7 ^= 1
  12: (56) if w7 != 0x0 goto pc+4
  13: (bc) w7 = w5
  14: (a4) w7 ^= 3
  15: (56) if w7 != 0x0 goto pc+1
  16: (44) w6 |= 7
  …
  83: (44) w6 |= 7
  84: (5c) w6 &= w3
  85: (b4) w0 = 0
  86: (5e) if w6 != w3 goto pc+1
  87: (b4) w0 = 1
  88: (95) exit
```

`r1` is the context, never overwritten. `w2` is the type, `w3` the
requested bits, `w4`/`w5` the numbers, `w6` the accumulated allowed bits,
and `w7` a scratch comparison register. Each failed comparison skips to
the next rule. For character 1:3 the first rule ORs in all three bits.
The epilogue keeps only requested bits and tests that none is missing.
ALU operations and conditional comparisons are 32-bit (`w`), avoiding
64-bit sign-extension surprises in immediate constants.

Before emission, the optimiser drops everything before the last
`a *:* rwm` reset and folds its initial allowed mask. It also drops
allows that cannot add a bit and denies that cannot remove one. A
privileged allow-all with only later allows needs no context reads at
all: `w0 = 1; exit`, two instructions.

## 7. The verifier cost was the surprising part

The obvious comparison, `if w4 != 136 goto next`, taught the verifier
that `w4` was exactly 136 on its fall-through path. That information
survived through later rules, keeping otherwise mergeable states apart.
More rules meant more distinct paths through the remaining program:
the work grew quadratically. The early implementation recorded **895,269
processed instructions at 1,000 rules**, near the million-instruction
processing budget (see the recorded finding in `compile.rs`).

The replacement is three instructions:

```text
w7 = w4
w7 ^= 136
if w7 != 0 goto next
```

It tests the same value, but only refines scratch `w7`. That register
is overwritten at the next comparison, letting states merge instead
of preserving a rule-specific fact about `w4`. The current test loads
distinct alternating allow/deny rules with all three comparisons and
asks the kernel for `BPF_LOG_STATS`:

```text
$ cargo xtask itest -- dv_verifier_cost_stays_linear --nocapture
…
rules, instructions, processed: [(100, 1012, 2308), (500, 5012, 11508), (1000, 10012, 23008), (2000, 20012, 46008)]
test dv_verifier_cost_stays_linear ... ok
```

| Surviving rules | Program instructions | Verifier processed |
|---|---|---|
| 100 | 1,012 | 2,308 |
| 500 | 5,012 | 11,508 |
| 1,000 | 10,012 | 23,008 |
| 2,000 | 20,012 | 46,008 |

The processing budget is **not the only limit**. The verifier also
holds deferred branch states on a stack; Linux v7.0 caps that at
8,192 (`BPF_COMPLEXITY_LIMIT_JMP_SEQ`, enforced by `push_stack` in
[verifier.c](https://github.com/torvalds/linux/blob/v7.0/kernel/bpf/verifier.c)).
Each rule has up to three conditional comparisons, so 2,000 rules
leave room below that ceiling, including the epilogue. This is why
`MAX_RULES = 2000` remains even though processed instructions are now
far below a million. The cap counts rules **after optimisation**, not
raw OCI entries. It is a conservative bound, not a claim that every
kernel could accept the same maximum.

Loading first uses no verifier log. If it fails, `rustlet-sys` repeats
the load with a growable diagnostic buffer; the runtime includes that
log in the error. This avoids making a successful load depend on the
size of a verbose log buffer. Tests request stats explicitly.

## 8. An attachment that outlives create

The parent creates the cgroup, opens its dirfd, loads the program and
attaches it with `BPF_PROG_ATTACH | BPF_F_ALLOW_MULTI`. Only then does
it call `clone3(CLONE_INTO_CGROUP)`. Init's own node creation is filtered.
The parent saves the id and closes the program fd. It does **not** use
a transient BPF link whose last fd would vanish when `create` exits.

```text
$ R create --bundle live live
$ jq .rustlet.device_filter /run/rustlet/doc-10/live/state.json
33442
$ bpftool cgroup show /sys/fs/cgroup/system.slice/rustlet-doc-10.scope/live
ID       AttachType      AttachFlags     Name
33442    cgroup_device   multi           rustlet_devices
$ R start live; R exec live sh -c "cat /proc/self/cgroup"
0::/
$ R delete --force live
$ bpftool prog show id 33442
Error: get by id (33442): No such file or directory
```

There was a short poll before the last command: release after cgroup
removal is asynchronous. A program fd held by an inspector would also
keep the program alive. Lifecycle tests drop all such references before
polling `prog_fd_by_id` for `ENOENT`. Failed creates are covered both
before clone and during init, and exec's independent access probes show
it is filtered too. No program needs to be reattached for exec.

`ALLOW_MULTI` does not mean a child allow overrides an ancestor deny.
Every applicable ancestor program must allow too. **The future
`rustletd.service` must never set `DevicePolicy=` or `DeviceAllow=`**, or
systemd's device program would constrain every container beneath it.

The filter also relies on the task staying in its cgroup. Ordinary
containers use a cgroup namespace, `nsdelegate` and read-only cgroupfs.
A deliberately host-privileged process with capabilities sufficient to
change BPF attachments (notably host `CAP_SYS_ADMIN`/`CAP_BPF`) is outside
this boundary. A writable ancestor cgroupfs without confinement is not
an isolation policy. These caveats are documented, not a capability gate
that pretends an allow-all spec is unprivileged.

## 9. Privileged-shaped specs, and differences from runc

`spec::add_host_device` checks a host character/block node and translates
it into both a node entry (type, numbers, metadata) and an access rule.
`cargo xtask demo --device /dev/fuse:rw` uses it. It accepts an alternate
container path in rootful specs; a new user namespace requires the same
path because population binds that host path.

`spec::host_devices` walks `/dev` in sorted order without following
symlinks or crossing submounts. It skips console, ptmx, core and the
standard symlink names. `spec::privileged` adds those nodes, allows all
devices, gives all supported kernel capabilities in bounding/effective/
permitted (inheritable and ambient stay empty), removes seccomp and
masked/read-only paths, and makes `/sys` and cgroupfs read-write. It
requires a cgroup and leaves NNP to the caller. The demo retains NNP:

```text
$ cargo xtask demo --privileged
…
/ # grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/self/status
CapEff: 000001ffffffffff
NoNewPrivs: 1
Seccomp: 0
/ # stat -c '%F %t:%T' /dev/fuse
character special file a:e5
```

The same read-only inspection worked with `--privileged --userns`, with
`uid_map` still `0 1000000 65536`. No sysfs write was attempted.
These are spec-building helpers and a development demo; there is no
daemon `--privileged` command yet.

The differential test uses runc 1.3.4. Shared behaviour includes defaults
following spec rules, replacing default nodes by path, metadata defaults,
`u` as character and host-device binds in a user namespace. The runc
[default-device source](https://github.com/opencontainers/runc/blob/v1.3.4/libcontainer/specconv/spec_linux.go)
also makes its broader creation/tun defaults explicit.
Rustlets' deliberate differences, asserted or validated locally, are:

- No blanket character/block `m` or tun permission by default.
- Ordered per-bit decisions: a later `w` deny blocks `rw`, and can punch
  a hole in a wildcard allow. runc's cgroup-v1 emulation has different
  partial-deny/wildcard behaviour.
- Ambiguous all-types rules, impossible numbers and negatives other than
  wildcard `-1` are refused. Empty access is refused in both runtimes.
- Rules/nodes need an explicit `cgroupsPath`; Rustlets never invents one.
  `CAP_MKNOD` without it needs the new-user-namespace exception.
- Node paths must be clean and under `/dev`; duplicate, existing and
  mount/node-conflicting paths are refused, and default numbers must stay
  unchanged.
- FIFOs in a user namespace are created locally rather than host-bound.

Verification has three independent checks: random rule lists against a
reference evaluator and eBPF interpreter; real kernel loads/access checks;
and the common-case differential against runc with explicit differences.
There are 21 `dv_` tests, plus userns, exec and capability coverage.
The full run passed 227 checks (224 privileged and 3 harness units),
and workspace unit tests passed 215. The independent review on 2026-10-01
re-ran those gates successfully, but found a P1 in `/dev` population: an
image symlink could redirect a later bind mount over the fresh `/dev` mount,
and a host tmpfs bind source passed the filesystem-type check. Device nodes
and symlinks were then created in that host directory. Both `/dev -> /mnt` and
`/mnt -> /dev` were reproduced with disposable fixtures. It is fixed: `/dev` is
now populated through the fd of the tmpfs mount itself, only while the path
`/dev` still leads to that mount, and a symlinked `/dev` is refused. Two `rr_`
regression tests cover the aliases; see [Chapter 08 §5](08-runtime-cves.md#5-rule-2-paths-that-change-under-you).

## 10. Try it

From the repository, as your normal user:

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo build -p rustlet-runc
cargo build -p rustlet-itests --bin rustlet-probe
cargo xtask rootfs
cargo xtask devices --disasm
cargo xtask itest -- dv_
cargo xtask demo --device /dev/fuse:rw       # /dev/fuse must exist on the host
cargo xtask demo --privileged               # inspect only; exit when done
```

For the recorded bundles, enter a **root shell in a delegated scope**,
not a container shell. Adjust the project path below for your checkout:

```sh
sudo -n systemd-run --scope --quiet --collect --unit=rustlet-doc-10 \
  -p Delegate=yes -p TasksMax=4096 -p MemoryMax=4G -- /bin/bash
```

Inside that shell, move it to a leaf, leaving the scope free for sibling
container cgroups. Use a fresh scratch directory and the chapter's own
runtime-state root:

```sh
project=/home/james/Documents/projects/Rustlet
cd "$project"
S=$(mktemp -d)
cg=/sys/fs/cgroup/system.slice/rustlet-doc-10.scope
mkdir "$cg/runtime"
echo 0 > "$cg/runtime/cgroup.procs"
R() { "$project/target/debug/rustlet-runc" --root /run/rustlet/doc-10 "$@"; }
trap 'R delete --force live >/dev/null 2>&1 || true' EXIT
make_bundle() {
  local name=$1 script=$2
  mkdir "$S/$name"
  jq --arg r "$project/.rustlet-dev/bundles/alpine/rootfs" \
     --arg cg "/system.slice/rustlet-doc-10.scope/$name" --arg script "$script" \
     '.root.path = $r | .process.terminal = false
      | .process.args = ["sh", "-c", $script] | .linux.cgroupsPath = $cg' \
     .rustlet-dev/bundles/alpine/config.json > "$S/$name/config.json"
}

make_bundle milestone 'grep CapEff /proc/self/status;
  mknod /dev/disk b 8 0; echo block-rc=$?;
  mknod /dev/n c 1 3; echo null-rc=$?; stat -c "%F %t:%T" /dev/n'
jq '.process.capabilities.bounding += ["CAP_MKNOD"]
    | .process.capabilities.effective += ["CAP_MKNOD"]
    | .process.capabilities.permitted += ["CAP_MKNOD"] | del(.linux.seccomp)' \
   "$S/milestone/config.json" > "$S/milestone/next.json"
mv "$S/milestone/next.json" "$S/milestone/config.json"
R run --bundle "$S/milestone" milestone
```

For the three access cases, bind the debug probe and its host loader/
libraries read-only (this checkout builds a glibc probe; Alpine is musl):

```sh
probe_script='PROBE="/opt/ld-linux-x86-64.so.2 --library-path /opt /mnt/rustlet-probe";
  stat -c "%F %t:%T %a %u:%g" /dev/fuse;
  $PROBE access:/dev/fuse:r access:/dev/fuse:w access:/dev/fuse:rw access:/dev/fuse:f'
for name in fuse-node fuse-rw fuse-deny-w; do
  make_bundle "$name" "$probe_script"
  jq --arg p "$project" '
    .linux.devices = [{path:"/dev/fuse",type:"c",major:10,minor:229}]
    | .linux.resources.devices = []
    | .mounts += [
        {destination:"/mnt",type:"bind",source:($p+"/target/debug"),options:["bind","ro","nosuid","nodev"]},
        {destination:"/opt",type:"bind",source:"/usr/lib/x86_64-linux-gnu",options:["bind","ro","nosuid","nodev"]}]' \
    "$S/$name/config.json" > "$S/$name/next.json"
  mv "$S/$name/next.json" "$S/$name/config.json"
done
for name in fuse-rw fuse-deny-w; do
  jq '.linux.resources.devices = [{allow:true,type:"c",major:10,minor:229,access:"rw"}]' \
    "$S/$name/config.json" > "$S/$name/next.json"
  mv "$S/$name/next.json" "$S/$name/config.json"
done
jq '.linux.resources.devices += [{allow:false,type:"c",major:10,minor:229,access:"w"}]' \
  "$S/fuse-deny-w/config.json" > "$S/fuse-deny-w/next.json"
mv "$S/fuse-deny-w/next.json" "$S/fuse-deny-w/config.json"
for name in fuse-node fuse-rw fuse-deny-w; do R run --bundle "$S/$name" "$name"; done
```

Inspect a live attachment, then delete and wait for its id to disappear:

```sh
make_bundle live 'exec sleep 3600'
R create --bundle "$S/live" live
program_id=$(jq -r .rustlet.device_filter /run/rustlet/doc-10/live/state.json)
/usr/sbin/bpftool cgroup show "$cg/live"
/usr/sbin/bpftool prog dump xlated id "$program_id"
R start live
R exec live sh -c 'cat /proc/self/cgroup'
R delete --force live
for attempt in {1..100}; do
  /usr/sbin/bpftool prog show id "$program_id" >/dev/null 2>&1 || break
  sleep 0.02
done
/usr/sbin/bpftool prog show id "$program_id"   # expected ENOENT
wc -l /proc/self/mountinfo
exit                                          # leaves the delegated scope
```

Back as your normal user, `cargo xtask devices --bundle DIR --disasm`
inspects any readable copy of these configs without loading BPF. To
repeat the userns example, build `cargo xtask rootfs --remap`, start from
that bundle's config/maps/rootfs, and add the fuse node/rw rule from §3.
After development, `sudo -n scripts/cleanup.sh` removes Rustlets runtime
state and host resources (not images/volumes unless `--purge` is given).
The recorded run finished with `24 /proc/self/mountinfo`.

## Check yourself

1. Why can a node named `/dev/null` still identify a block device, and
   which two checks prevent that replacement here?
2. After `allow c 10:229 rw; deny c 10:229 w`, why must `rw` fail?
   What would a later `allow c 10:229 w` do?
3. Why does a spec node need an implicit `m` rule even though the final
   process does not have `CAP_MKNOD`?
4. Why can a spec's deny of `/dev/null` not take effect? Which rule comes
   last, and what would changing that order break?
5. Why does a direct comparison of `w4` cost the verifier more than a
   comparison of scratch `w7`? Why isn't the million-instruction budget
   enough to choose `MAX_RULES`?
6. Why does closing the program fd after attach not remove the filter?
   Why must an inspector close its own fd before testing release?
7. Can a child allow-all undo a systemd ancestor deny? Why should the
   daemon unit avoid `DevicePolicy=` even for unprivileged containers?

## Experiments

- Reverse the fuse allow/deny order and inspect both `xtask devices` and
  the access probes. Add a wildcard character allow followed by a
  specific deny: the hole should remain denied.
- Give a rootful `/dev/net/tun` entry a mode/owner, but no read/write
  rule; inspect its metadata and access only. Do not use the driver.
- Repeat the fuse entry in a remapped bundle with deliberately different
  requested metadata. Check that the host bind keeps host metadata,
  while a FIFO with mapped owners gets the requested values.
- Run `cargo xtask itest -- dv_verifier_cost_stays_linear --nocapture`,
  compare its counts to §7, and inspect the compiled comparison blocks.
- Create a sleeper, inspect its one program, run exec access probes,
  delete it, and poll for release. Keep this inside a delegated scope,
  and finish by checking the host mount table.
