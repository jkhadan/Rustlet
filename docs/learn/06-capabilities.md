# 06 — Capabilities: what's left of root

Chapter 03 ended with Phase 1's honest limits: root in a container kept every
privilege of root on the host, so it could load a kernel module or `mknod` the
host's disk. Phase 2b takes most of that away. Linux doesn't treat root as one
privilege but as about forty **capabilities**, and a container's root keeps
eleven of them. This chapter covers what those capabilities are, how the kernel
carries them across `execve`, the order in which init gives them up, and what
`create` refuses. The seccomp filter, the other half of the hardening, has
chapter 07.

Code: [`caps.rs`](../../crates/rustlet-runtime/src/caps.rs), [`process.rs`](../../crates/rustlet-runtime/src/process.rs)
(`switch_identity`, `exec`), [`init.rs`](../../crates/rustlet-runtime/src/init.rs), [`plan.rs`](../../crates/rustlet-runtime/src/plan.rs),
[`spec.rs`](../../crates/rustlet-runtime/src/spec.rs), [`exec.rs`](../../crates/rustlet-runtime/src/exec.rs), and in `rustlet-sys`
[`caps.rs`](../../crates/rustlet-sys/src/caps.rs) and [`prctl.rs`](../../crates/rustlet-sys/src/prctl.rs). Design:
[architecture.md](../architecture.md) §2.2 step 5.10 and §2.2.2. Tests:
[`hardening.rs`](../../tests/tests/hardening.rs) and [`exec.rs`](../../tests/tests/exec.rs).
`cargo xtask itest -- capabilit ambient bounding _cap_ no_new_privs` runs the
22 tests about capabilities.

All transcripts are real runs on this host (kernel 7.0.0-34-generic), as root in
a `sudo systemd-run --scope`. `$R` is `./target/debug/rustlet-runc --root
/run/rustlet/doc-06`, and the bundles are the default `config.json` with
`terminal: false` plus the changes stated (§8 has the jq).

## 1. Root, split into 41 pieces

Traditional Unix has a single test: effective uid 0 passes every permission
check. Since Linux 2.2, the kernel asks a narrower question at each check,
`capable(CAP_…)`: may this process chown files? bind a low port? load a module?
Root simply starts out with all of them. The kernel says how many there are:

```text
$ cat /proc/sys/kernel/cap_last_cap
40
# grep Cap /proc/self/status             root on the host
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
```

The capabilities are numbered 0 to 40, and each is one bit of a 64-bit mask:
`0x1ffffffffff` is 41 one-bits. `rustlet-sys` names them in `CAP_NAMES`.
`process_plan` reads `cap_last_cap` in the parent while it builds the plan
(`strace` shows the `openat`), because inside the container `/proc` is no longer
a source init can trust. Some capabilities are much worse than others:

| capability | lets its holder | in a container, that means |
|---|---|---|
| `SYS_ADMIN` | mount, `pivot_root`, `setns`, `sethostname`, swapon, many ioctls: the catch-all | remounting and entering other namespaces: most escapes start here |
| `NET_ADMIN` | configure interfaces, addresses, routes, firewall rules | only its own netns, but every netfilter and tc code path in the kernel |
| `SYS_MODULE` | `init_module`, `delete_module` | code in the host kernel: there is only one module list |
| `SYS_PTRACE` | ptrace any process, `process_vm_readv` | read or rewrite the memory of any process it can see |
| `MKNOD` | create device nodes | `mknod /dev/sda b 8 0`, then read the host's disk (§6) |
| `NET_RAW` | raw and packet sockets | forge any packet on the bridge; the AF_PACKET bug CVE-2020-14386 needed only this |
| `DAC_READ_SEARCH` | skip read checks, `open_by_handle_at` | the 2014 "Shocker" escape opened host files by handle |

In a default container `c` they are all gone, even for root:

```text
$ $R exec c mknod /dev/shm/n c 1 3
mknod: /dev/shm/n: Operation not permitted
$ $R exec c ip link set lo down
ip: ioctl 0x8914 failed: Operation not permitted
$ $R exec c hostname other
hostname: sethostname: Operation not permitted
$ $R exec c rmmod dummy
rmmod: can't unload module 'dummy': Operation not permitted
```

(`0x8914` is `SIOCSIFFLAGS`.) Two layers refuse most of these. Docker's seccomp
profile (chapter 07) allows `mount`, `sethostname`, `unshare` and
`delete_module` only to a process that holds the matching capability. To see
which layer said no, run the same commands in a container without a filter,
`n` (`del(.linux.seccomp)`, so its status says `Seccomp: 0`). They fail the same
way, so capabilities alone are enough. `exec --cap` hands a single process one
capability back, which shows what each one unlocks:

```text
$ $R exec --cap SYS_ADMIN n sh -c 'mount -t tmpfs none /mnt && grep " /mnt " /proc/self/mountinfo; hostname other && hostname'
763 837 0:69 / /mnt rw,relatime - tmpfs none rw,inode64
other
$ $R exec --cap SYS_MODULE n rmmod dummy
rmmod: can't unload module 'dummy': No such file or directory
```

The last one is the frightening one. The permission check passed, and only the
missing module stopped it: there is no module called `dummy` in the **host's**
kernel. Given a real module name, the host would have lost that module.

### The eleven that stay

`caps::DEFAULT` is Podman's set (architecture.md §2.2.2):

| capability | bit | what root in the container uses it for |
|---|---|---|
| `CHOWN` | 0 | `chown` any file: package managers unpack files that other users own |
| `DAC_OVERRIDE` | 1 | ignore permission bits (root reading a 0600 file that belongs to `postgres`) |
| `FOWNER` | 3 | owner-only operations on any file: `chmod`, `utime`, deleting in a sticky `/tmp` |
| `FSETID` | 4 | keep setuid/setgid bits when a file is modified |
| `KILL` | 5 | signal other users' processes |
| `SETGID`, `SETUID` | 6, 7 | change identity: `su`, and daemons that start as root and then drop to a user |
| `SETPCAP` | 8 | drop from its own bounding set; move bounding caps into its inheritable set |
| `NET_BIND_SERVICE` | 10 | bind ports below 1024 |
| `SYS_CHROOT` | 18 | `chroot`, which some build tools and daemons use |
| `SETFCAP` | 31 | set file capabilities (`setcap`, or a package that ships them) |

Nothing on this list reaches beyond the container's own files, processes and
namespaces. As a mask:

```text
$ capsh --decode=800405fb
0x00000000800405fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_sys_chroot,cap_setfcap
```

To read the hex by hand: bits 0–8 without bit 2 make `0x1fb`, bit 10 adds
`0x400` (giving `0x5fb`), bit 18 is `0x40000` and bit 31 is `0x80000000`. The
unit test `default_mask_is_podmans` pins the number. Docker's default set has
three more:

```text
$ capsh --decode=a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

`MKNOD` has to wait for the device filter (§6), and few container programs
write to the kernel's audit log (`AUDIT_WRITE`). `NET_RAW` is in Docker's set
mostly for `ping`. Without it, the default container's `ping` says `ping:
permission denied (are you root?)`. The kernel has unprivileged ICMP sockets,
but a new netns starts with `ping_group_range` at `1 0`, so no group may use
them. Add `"linux.sysctl": {"net.ipv4.ping_group_range": "0 2147483647"}` and
the same container pings, with `CapEff` still `00000000800405fb`. From Phase 5,
the daemon writes that sysctl into every netns it creates (§2.2.2).

## 2. Five sets, and what `execve` does with them

A capability isn't simply held or not held. Each thread has five sets
(`capabilities(7)`), and the `Cap*` lines of `/proc/<pid>/status` are their
masks:

| set | line | meaning |
|---|---|---|
| effective | `CapEff` | what the kernel checks right now |
| permitted | `CapPrm` | the ceiling for effective: only a permitted bit can be made effective |
| inheritable | `CapInh` | kept across `execve`; becomes permitted only for binaries whose *file* inheritable set has it |
| bounding | `CapBnd` | limits what `execve` can ever add; bits can only be removed |
| ambient | `CapAmb` | (4.3+) carried into permitted and effective across `execve` of ordinary binaries (§3) |

`capset(2)` writes the first three and enforces the kernel's rules: effective
⊆ permitted, permitted can only shrink, and new inheritable bits must come from
the bounding set (and, without `SETPCAP`, from permitted).
`prctl(PR_CAPBSET_DROP)` shrinks the bounding set, and `PR_CAP_AMBIENT` manages
ambient. At `execve` the kernel then computes new sets from the old ones (`P`)
and the file's (`F`: the `security.capability` xattr that `setcap` writes):

```text
P'(ambient)     = (setuid/setgid or file caps) ? 0 : P(ambient)
P'(permitted)   = (P(inheritable) & F(inheritable)) | (F(permitted) & P(bounding)) | P'(ambient)
P'(effective)   = F(effective) ? P'(permitted) : P'(ambient)
P'(inheritable) = P(inheritable)        P'(bounding) = P(bounding)
```

**A non-root user** running an ordinary binary has `F = 0`, so every term
cancels except ambient: whatever init put into permitted and effective is gone
after `execve`. **Root** is the special case. If the real or effective uid is 0,
the kernel treats every binary as if its file inheritable and permitted sets
were full, and for euid 0 as if the file effective bit were set. The formulas
reduce to permitted = bounding | inheritable and effective = permitted: for
root, `execve` *refills* permitted from the bounding set. That's why the
bounding set is the one that counts for a root container. The default
container's `grep Cap /proc/self/status`, as root and with `process.user` 1000
(`hd_root_gets_exactly_the_default_capabilities`,
`hd_non_root_user_has_only_the_bounding_set`):

| line | root | uid 1000 |
|---|---|---|
| `CapInh` | `0000000000000000` | `0000000000000000` |
| `CapPrm` | `00000000800405fb` | `0000000000000000` |
| `CapEff` | `00000000800405fb` | `0000000000000000` |
| `CapBnd` | `00000000800405fb` | `00000000800405fb` |
| `CapAmb` | `0000000000000000` | `0000000000000000` |

### Surprise: `no_new_privs` changes the root case

If `execve` refills root's permitted set from bounding, then the spec's
permitted list shouldn't matter for root. To test that, I set bounding to
`CHOWN KILL NET_RAW` (`0x2021`) and permitted and effective to `KILL NET_RAW`
(`0x2020`), and ran `grep` and then `chown` as root:

| `noNewPrivileges` | `CapPrm` | `CapEff` | `chown` | runc 1.3.4, same bundle |
|---|---|---|---|---|
| true (the default) | `0000000000002020` | `0000000000002020` | `Operation not permitted` | `2020` / `2020` |
| false | `0000000000002021` | `0000000000002021` | works | `2021` / `2021` |

With NNP off, root gets `CHOWN` back at the first `execve`, as the formula
says. With NNP on, it doesn't. The kernel's `cap_bprm_creds_from_file`
(`security/commoncap.c`) checks whether the new permitted set would *gain*
bits. If it would and no_new_privs is set, the kernel intersects the new set
with the old one ("they get no more than they had"). So a root container's
permitted list counts under NNP. Its effective list never counts: with
effective `["CAP_KILL"]` alone and the default permitted, the program still
started with `CapEff: 00000000800405fb`, because the file effective bit is
treated as set for euid 0. For root:

| spec set | how far it limits the program |
|---|---|
| bounding | always: the hard ceiling, for setuid binaries and file capabilities too |
| permitted | only with `noNewPrivileges: true` |
| effective | not past the first `execve`, which sets effective = permitted |

`hd_custom_capabilities_replace_the_defaults` passes because the default spec
sets NNP. With NNP off, the same sets would hand root its `CHOWN` back. The
module comment in `caps.rs` gives only the NNP-off half of this.

### Why inheritable stays empty: CVE-2022-24769

Look at the first term of P'(permitted), `P(inheritable) & F(inheritable)`.
Until 2022, runc and Docker filled the inheritable set with the default
capabilities, so a *non-root* user in the container could gain any of them by
running a binary with inheritable file capabilities. This was no escape, since
the bounding set still applied, but a uid-1000 process ended up with more
privilege than its author intended. Docker 20.10.14 and runc 1.1.2 fixed it
by making inheritable empty, and `spec.rs` does the same. The demonstration
uses a copy of busybox called `nc` with `sudo setcap
cap_net_bind_service=ei` (file inheritable and effective, no file permitted),
bind-mounted at `/opt` without `nosuid`, because a `nosuid` mount ignores file
capabilities. The container runs as uid 1000 with NNP off, starts `/opt/nc -l
-p 80`, and reads that process's `/proc/$!/status`:

```text
-- inheritable = the 11 defaults (the pre-2022 behaviour)
CapInh:	00000000800405fb
CapPrm:	0000000000000400
CapEff:	0000000000000400
tcp        0      0 :::80                   :::*                    LISTEN
punt!
```

With inheritable `[]` (the fix), and separately with the 11 but NNP on, the
same run printed `nc: bind: Permission denied`, then the `grep` found no
process and `not listening`. NNP would have stopped it alone, because it
ignores file capabilities (§5). Stray inheritable bits do exist in practice: on
this desktop, every process of the login session has `CapInh:
0000000800000000` (`cap_wake_alarm`, from the session's `lightdm`). Init never
relies on the caller's sets, because `capset` writes all three, inheritable
included.

## 3. Ambient capabilities: keeping one as non-root

A web server that runs as uid 1000 but must listen on port 80 needs one
capability. Putting `NET_BIND_SERVICE` in its permitted and effective sets
achieves nothing, since `execve` of a binary without file caps clears both.
Before Linux 4.3 the options were `setcap` on the binary (which changes the
image, and stops working under NNP or on a `nosuid` mount) or starting as root
and dropping privileges in the program.

**Ambient** capabilities (4.3) are the third way: for an ordinary binary
P'(ambient) = P(ambient), and it is added to both permitted and effective. The
kernel keeps one invariant: a capability can be ambient only while it is
**both permitted and inheritable**. Raising one that isn't fails, and dropping
it from either set drops it from ambient. `execve` of a setuid or
file-capability binary clears the set, and so does a uid switch away from 0
(§4). Ambient doesn't come from the file, so NNP leaves it alone. It is the only
way for a non-root process under NNP to keep a capability.

`exec -u 1000 --cap NET_BIND_SERVICE` puts the capability in all five sets
(`exec_process` adds inheritable and ambient only for non-root users). In a
running default container `web`, with `L='grep Cap /proc/self/status; nc -l -p
80 </dev/null & sleep 0.3; netstat -ltn | grep :80 || echo "not listening";
kill $!'`:

```text
$ $R exec -u 1000 web sh -c "$L"
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	00000000800405fb
CapAmb:	0000000000000000
nc: bind: Permission denied
not listening
$ $R exec -u 1000 --cap NET_BIND_SERVICE web sh -c "$L"
CapInh:	0000000000000400
CapPrm:	0000000000000400
CapEff:	0000000000000400
CapBnd:	00000000800405fb
CapAmb:	0000000000000400
tcp        0      0 :::80                   :::*                    LISTEN
```

(After that, busybox `nc` announces its SIGTERM with `punt!`.) The exec child
had made the container's eleven capabilities permitted, and none of them
survived `execve`: ambient held one bit, and that one bit is all that came out. From the
host, `getpcaps` shows such a process as `339918: cap_net_bind_service=eip`.
Its text format has no field for ambient, so check `CapAmb` in
`/proc/339918/status`. In `config.json` the same thing is `"user": {"uid":
1000}` with effective, permitted, inheritable and ambient all
`["CAP_NET_BIND_SERVICE"]` (`hd_ambient_capabilities_reach_a_non_root_user`,
with `hd_capabilities_without_ambient_are_lost_by_a_non_root_user` as the
control).

## 4. The order in init, and what breaks if you change it

`switch_identity` takes init from root with every capability to the
container's user with the container's sets, in the order that architecture.md
§2.2 step 5.10 fixes. Here is `strace -f` of a uid-1000 container with ambient
`NET_BIND_SERVICE`, init's lines only, with the pid column removed:

```text
prctl(PR_CAPBSET_DROP, CAP_DAC_READ_SEARCH) = 0
…                                                   one per capability not in the bounding set
prctl(PR_CAPBSET_DROP, CAP_CHECKPOINT_RESTORE) = 0
prctl(PR_CAPBSET_DROP, 0x29 /* CAP_??? */) = -1 EINVAL (Invalid argument)
…                                                   up to 0x3f
prctl(PR_SET_KEEPCAPS, 1)        = 0
setgroups(0, [])                 = 0
setresgid(1000, 1000, 1000)      = 0
setresuid(1000, 1000, 1000)      = 0
capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_NET_BIND_SERVICE, permitted=1<<CAP_NET_BIND_SERVICE, inheritable=1<<CAP_NET_BIND_SERVICE}) = 0
prctl(PR_SET_KEEPCAPS, 0)        = 0
prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) = 0
prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0) = 0
chdir("/")                       = 0
prctl(PR_SET_PDEATHSIG, SIGKILL) = 0
sendto(7, "{\"type\":\"ready\"}", 16, MSG_NOSIGNAL, NULL, 0) = 16
…                                                   the gate (chapter 05)
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0
seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=140, filter=0x5ec35e50a950}) = 0
execve("/bin/grep", ["grep", "Cap", "/proc/self/status"], 0x5ec35e4e5b10 /* 3 vars */) = 0
```

`drop_bounding` covers all 64 bits, not just up to `cap_last_cap`, so a wrong
`last` (an unreadable file falls back to 40) can't let a newer kernel's extra
capabilities survive. `bounding_drop` counts the kernel's `EINVAL` for unknown
numbers as "already gone". Every other step sits where it does because moving it
breaks something. `capsh` applies its arguments in order, so as root on the host
it can replay each mistake.

**1. Drop the bounding set before the uid switch.** `PR_CAPBSET_DROP` needs
`CAP_SETPCAP` in the effective set, and a change of euid away from 0 empties
effective, keepcaps or not. The same goes for `setgroups` and `setresgid`,
which need `CAP_SETGID`: groups go first.

```text
# capsh --uid=1000 --drop=cap_sys_admin -- -c true
unable to raise CAP_SETPCAP for BSET changes: Operation not permitted
# capsh --drop=cap_sys_admin --uid=1000 -- -c 'grep CapBnd /proc/self/status'
CapBnd:	000001ffffdfffff
```

**2. Set `PR_SET_KEEPCAPS` before `setresuid`.** When every uid leaves 0, the
kernel clears permitted as well: the classic "drop root" behaviour. After that
`capset` can't raise anything, because permitted can only shrink:

```text
# capsh --uid=1000 --caps=cap_net_bind_service+eip -- -c true
Unable to set capabilities [--caps=cap_net_bind_service+eip]
```

With `--keep=1` the `capset` succeeds, and bash's `execve` then empties both
sets again, which is §3 happening on the host. `apply` switches keepcaps back
off, so the program can't keep permitted capabilities across a setuid of its
own.

**3. Call `capset` after the switch, and raise ambient after `capset`.**
`capset` restores the effective set that the switch emptied. Ambient needs the
inheritable bit to be there already, and a uid switch clears ambient even with
keepcaps, so raising it as root first doesn't help either:

```text
# capsh --inh=cap_net_bind_service --addamb=cap_net_bind_service --keep=1 --uid=1000 -- -c 'grep -E "CapInh|CapPrm|CapAmb" /proc/self/status'
CapInh:	0000000000000400
CapPrm:	0000000000000000
CapAmb:	0000000000000000
# capsh --keep=1 --uid=1000 --addamb=cap_net_bind_service -- -c true
failed to raise ambient [cap_net_bind_service=10]
# capsh --keep=1 --uid=1000 --caps=cap_net_bind_service+eip --addamb=cap_net_bind_service -- -c 'grep -E "CapPrm|CapEff|CapAmb" /proc/self/status'
CapPrm:	0000000000000400
CapEff:	0000000000000400
CapAmb:	0000000000000400
```

**4. Set `PR_SET_PDEATHSIG` after the switch.** The kernel clears the
parent-death signal whenever the effective uid or gid changes (`prctl(2)`). Set
any earlier, foreground `run` would silently lose "if `rustlet-runc` dies, so
does the container". A Python `ctypes` check as root (Experiments):

```text
after PR_SET_PDEATHSIG: 9
after setresgid:        0
after setresuid:        0
```

**5. Load seccomp first or last, never in between.** A thread may install a
filter only with no_new_privs set or `CAP_SYS_ADMIN` held. Otherwise it could
make a syscall fail inside a setuid program that never expected it to fail
(sendmail's bug of 2000, done with capabilities: its `setuid()` failed, and it
carried on as root). A ctypes script that dropped to the default set as root
got `-1 EACCES` from `seccomp(SECCOMP_SET_MODE_FILTER)` with an allow-all
filter, and `0` once it had set `PR_SET_NO_NEW_PRIVS`. So with
`noNewPrivileges: false`, `switch_identity` loads the filter first,
while init still holds everything (`hd_without_no_new_privs_the_filter_is_still_loaded`,
uid 0 and 1000). The cost is that the filter then judges init's own `capset`,
`setresuid` and `prctl` too. Docker's profile allows them; one that denies
`capset` (default allow, `capset` → `EPERM`) shows the difference:

```text
-- noNewPrivileges: true
CapEff:	00000000800405fb
NoNewPrivs:	1
Seccomp:	2
-- noNewPrivileges: false
rustlet-runc: error: container init failed: capset: EPERM: Operation not permitted
```

With NNP on, `process::exec` sets the flag after the gate and loads the filter
last, so the profile only has to allow `execve` itself. (Architecture.md lists
`PR_SET_NO_NEW_PRIVS` as step 11, before the gate; the code sets it just before
the filter. Nothing in between executes a program, so the effect is the same.)
Outside `switch_identity`, rlimits and `oom_score_adj` come first
(`set_limits`), because raising a hard limit needs `CAP_SYS_RESOURCE`.
`enter_cwd` comes after it, as the container user but with the container's
effective set until `execve` (last Experiment).

## 5. `no_new_privs`

`prctl(PR_SET_NO_NEW_PRIVS, 1)` sets a one-way flag. Every child inherits it,
and it survives `execve`. From then on, `execve` "promises not to grant
privileges to do anything that could not have been done without the execve
call" (`prctl(2)`): setuid and setgid bits stop working, and so do file
capabilities. (It also restricts LSM transitions on exec, which will matter
for AppArmor in Phase 8.) The default spec sets it, as `runc spec` does; Docker
and Podman leave it off unless asked (`--security-opt no-new-privileges`). On
the host, with a file-capability binary (Ubuntu's `ping` has `cap_net_raw=ep`)
and a setuid one:

```text
$ setpriv --no-new-privs ping -c1 -W1 127.0.0.1
ping: socktype: SOCK_RAW
ping: socket: Operation not permitted
ping: => missing cap_net_raw+p capability or setuid?
$ setpriv --no-new-privs sudo -n true
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
sudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.
```

Without the flag, the same `ping` works as james. Inside a container, the
attacker's route is a setuid-root binary in the image. Container `u` has NNP off
and a tmpfs on `/tmp` without `nosuid`, and `ids` is a small static C program
that prints its uids and capability lines (Experiments). Container root makes a
setuid-root copy, and uid 1000 runs it:

```text
$ $R exec u sh -c 'cp /mnt/ids /tmp/ids && chmod 4755 /tmp/ids && ls -l /tmp/ids'
-rwsr-xr-x    1 root     root        785480 Sep 25 18:12 /tmp/ids
$ $R exec -u 1000 u /tmp/ids
uid: real 1000, effective 0, saved 0
CapPrm:	00000000800405fb
CapEff:	00000000800405fb
NoNewPrivs:	0
$ $R exec -u 1000 --no-new-privs u /tmp/ids
uid: real 1000, effective 1000, saved 1000
CapPrm:	0000000000000000
CapEff:	0000000000000000
NoNewPrivs:	1
```

The first run is §2's root special case reached through a setuid bit: euid 0,
so permitted = bounding. The bounding set held, so this isn't host root, but
inside the container uid 1000 had just become root. That's the realistic
attack: an image with a setuid binary that has a hole (Alpine's official images
once shipped root with an empty password, CVE-2019-5021, which made any setuid
`su` a free upgrade). A setuid busybox `su` shows the split less clearly: under
NNP it says `su: must be suid to work properly`; without, it gets as far as the
password check, and this Alpine's busybox refuses blank passwords off a secure
terminal.

## 6. Refused at `create`

`CapsPlan::from_spec` (called from `plan::process_plan`, for `create` and for
every `exec`) checks the five sets before anything exists. The real messages:

```text
rustlet-runc: error: invalid config.json: process.capabilities is missing: list the capabilities the container keeps (`rustlet-runc spec` writes a safe default set)
rustlet-runc: error: config.json uses features this build does not support yet:
  - process.capabilities: CAP_MKNOD (Phase 2c)
rustlet-runc: error: invalid config.json: process.capabilities: effective has CAP_NET_RAW which are not in permitted (the kernel requires effective ⊆ permitted)
rustlet-runc: error: invalid config.json: process.capabilities: ambient has CAP_NET_RAW which are not in both permitted and inheritable
rustlet-runc: error: invalid config.json: process.capabilities: inheritable has CAP_NET_RAW which are not in bounding
```

runc 1.3.4 handled the same bundles like this:

| bundle | runc |
|---|---|
| no `process.capabilities` | runs, with `CapEff: 000001ffffffffff`: all 41 |
| `CAP_MKNOD` in bounding | runs (`CapBnd: 00000000880405fb`); runc relies on the cgroup device filter |
| effective ⊄ permitted | `error during container init: unable to apply caps: can't apply capabilities: operation not permitted` |
| ambient ⊄ inheritable | `level=warning msg="can't raise ambient capability CAP_NET_RAW: operation not permitted"`, then runs without it |
| inheritable ⊄ bounding | the same `unable to apply caps` error |

**A missing list** means *keep everything* in runc, and meant the same in
Rustlets before this phase (the comment in `process_plan`). Every other choice
would be a guess, so `create` refuses and names the tool that writes a safe
default (`hd_missing_capabilities_are_refused`).

**`CAP_MKNOD`** is refused until Phase 2c, even when it's only in the bounding
set (`hd_cap_mknod_is_refused_until_phase_2c`). The rootfs is mounted `nodev`,
but `/dev` can't be, because it holds the real `null`, `zero` and friends
(chapter 03):

```text
841 758 8:3 /home/james/…/rootfs / ro,nodev,relatime - ext4 /dev/sda3 rw,errors=remount-ro
843 841 0:65 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
```

With `MKNOD`, root could `mknod /dev/sda b 8 0` in there and read the host's
disk. Bounding-only isn't enough, since bounding is what `execve` refills root's
permitted set from, with NNP off or through a setuid binary (§2, §5). runc and
Docker can allow `MKNOD` because on cgroup v2 an eBPF device program in the
container's cgroup refuses `open()` of any device not on its list. Rustlets
gets that program in Phase 2c. A `process.json` with it gets the same message,
and `exec --cap MKNOD` a similar one that names the flag: `rustlet-runc:
error: exec --cap MKNOD: not supported until Phase 2c (the eBPF device filter
that makes it safe)` (`ex_cap_mknod_is_refused`,
`ex_process_json_with_cap_mknod_is_refused`).

**Inconsistent sets** are the one deliberate difference from runc here. runc
hands them to the kernel inside init, after namespaces and mounts are built,
and gets either a generic `operation not permitted` that names no capability
or, for ambient, a warning and a container with less than it asked for. A
uid-1000 container asking for ambient `NET_RAW` that way ran with `CapEff:
0000000000000000`. `validate` applies the kernel's rules (effective ⊆
permitted, inheritable ⊆ bounding, ambient ⊆ permitted ∩ inheritable) in the
parent and names the set and the capabilities. youki's `contest` notices:
`bounding_unset_with_other_caps_fails_test` is one of the six tests that
architecture.md §5 lists as not ok, because the refusal comes from `create`,
not from the kernel. (With bounding `[]` and the defaults everywhere else, the
message is `inheritable has CAP_CHOWN, CAP_DAC_OVERRIDE, … which are not in
bounding`.) Capabilities newer than the running kernel are left out with a
warning, as in runc, so a spec from a newer kernel still runs
(`caps_newer_than_the_kernel_are_left_out`).

## 7. `exec`: the container's sets, plus `--cap`

`exec` builds its process from the copy of `config.json` stored at `create`,
and the exec child runs the same `switch_identity` after its `setns`. So `$R
exec web grep Cap /proc/self/status` prints init's five lines from §2, and NNP
and the filter come along too (`ex_inherits_capabilities_no_new_privs_and_seccomp`).
`--cap` adds to bounding, effective and permitted, and for a non-root user to
inheritable and ambient too (§3):

```text
$ $R exec --cap NET_RAW web sh -c 'grep -E "CapEff|CapBnd" /proc/self/status; ping -c1 -W1 127.0.0.1'
CapEff:	00000000800425fb
CapBnd:	00000000800425fb
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=64 time=0.037 ms
…
$ $R exec --cap SYS_ADMIN web sh -c 'grep CapEff /proc/self/status; mount -t tmpfs none /mnt'
CapEff:	00000000802405fb
mount: permission denied (are you root?)
```

`--cap` can reach beyond the container's bounding set: the exec child is cloned
from `rustlet-runc`, root on the host with every capability, and gets the
container's bounding set plus the additions. It's the operator's command, as
with `runc exec --cap`. Even so, `mount` fails with `SYS_ADMIN` effective: the
seccomp filter is the one compiled at `create`, resolved for the default
capabilities. The two layers are independent, and a spec that lists
`SYS_ADMIN` with the default profile gets the same result
(`hd_seccomp_blocks_mount_even_with_cap_sys_admin`). A `process.json` without
`capabilities` gets the container's sets, not none or all
(`ex_process_json_without_capabilities_gains_nothing`).

## 8. Try it

```sh
cargo build -p rustlet-runc
mkdir -p /tmp/caps
jq --arg r "$PWD/.rustlet-dev/bundles/alpine/rootfs" \
   '.root.path = $r | .process.terminal = false | .process.args = ["sleep", "3600"]' \
   .rustlet-dev/bundles/alpine/config.json > /tmp/caps/config.json
R="sudo ./target/debug/rustlet-runc"
$R create --bundle /tmp/caps web && $R start web
$R exec web grep Cap /proc/self/status; capsh --decode=800405fb
getpcaps $($R state web | jq .pid)
$R exec web sh -c 'mknod /dev/shm/n c 1 3; ip link set lo down; hostname x'    # three EPERMs
$R exec -u 1000 web nc -l -p 80                                                 # Permission denied
$R exec -u 1000 --cap NET_BIND_SERVICE web sh -c \
   'nc -l -p 80 </dev/null & sleep 0.3; netstat -ltn; grep Cap /proc/$!/status; kill $!'
$R exec --cap NET_RAW web ping -c1 127.0.0.1
$R exec --cap SYS_ADMIN web mount -t tmpfs none /mnt        # still denied: seccomp
$R exec --cap MKNOD web true                                # refused until Phase 2c
$R delete --force web
mkdir -p /tmp/bad
jq '.process.capabilities.inheritable = ["CAP_NET_RAW"]' /tmp/caps/config.json > /tmp/bad/config.json
$R create --bundle /tmp/bad bad                             # inheritable ⊄ bounding
setpriv --no-new-privs sudo true
```

The other refusals of §6 work the same way (`del(.process.capabilities)`, or
`"CAP_MKNOD"` added to the bounding set), and `sudo capsh` replays §4 in any
order you like.

## Check yourself

1. A root container has the default bounding set, `"permitted": []`,
   `"effective": []`, and `noNewPrivileges: false`. What will `CapPrm` say in
   its program, and what changes when NNP is on?
2. A uid-1000 process has `NET_BIND_SERVICE` in effective and permitted, and
   loses it at `execve`. Why? Name two ways to keep it, and explain why only one
   of them works under NNP.
3. `drop_bounding` runs before `setresuid`, and `capset` after it. What would
   each call get in the other's place, and why?
4. Why is the default inheritable set empty? Which other default would also
   have stopped the CVE-2022-24769 escalation, and why?
5. Why can an unprivileged thread load a seccomp filter only with
   no_new_privs? What does loading the filter early (NNP off) cost the runtime?
6. `CAP_MKNOD` is refused even when it's only in the bounding set. How could
   root get it into its permitted set anyway? What makes runc safe with it?

## Experiments

- **The setuid demo.** Build `ids` as yourself with `gcc -static -O2 -o ids
  ids.c`:

  ```c
  #define _GNU_SOURCE
  #include <stdio.h>
  #include <string.h>
  #include <unistd.h>

  int main(void) {
      uid_t r, e, s;
      getresuid(&r, &e, &s);
      printf("uid: real %u, effective %u, saved %u\n", r, e, s);
      FILE *f = fopen("/proc/self/status", "r");
      char line[256];
      while (f && fgets(line, sizeof line, f))
          if (!strncmp(line, "CapPrm", 6) || !strncmp(line, "CapEff", 6) || !strncmp(line, "NoNewPrivs", 10))
              fputs(line, stdout);
      return 0;
  }
  ```

  Put it in `/tmp/nnp/tools`, and make a bundle with `jq --arg t /tmp/nnp/tools
  '.process.noNewPrivileges = false | .mounts += [{"destination": "/tmp",
  "type": "tmpfs", "source": "tmpfs", "options": ["mode=1777", "size=16m"]},
  {"destination": "/mnt", "type": "bind", "source": $t, "options": ["bind",
  "ro", "nosuid", "nodev"]}]' /tmp/caps/config.json > /tmp/nnp/config.json`.
  Then run §5's three `exec`s. What does `ids` print when you copy and `chmod`
  it as uid 1000 instead of root?
- **CVE-2022-24769 by hand.** `mkdir -p /tmp/cve/fcap && cp
  .rustlet-dev/bundles/alpine/rootfs/bin/busybox /tmp/cve/fcap/nc`, then `sudo
  setcap cap_net_bind_service=ei /tmp/cve/fcap/nc`. Make a bundle from `/tmp/caps/config.json` with
  `.process.user = {"uid": 1000, "gid": 1000}`, `.process.noNewPrivileges =
  false`, `.process.capabilities.inheritable = .process.capabilities.bounding`,
  args `sh -c '/opt/nc -l -p 80 </dev/null & sleep 0.3; grep Cap
  /proc/$!/status; netstat -ltn; kill $!'`, and a bind of `/tmp/cve/fcap` on
  `/opt` with options `["bind", "ro"]`. `run` it, then flip inheritable back to
  `[]`, then NNP back on, then add `"nosuid"` to the bind. Which of the four
  runs listens on port 80?
- **The parent-death signal.** §4's check is a dozen lines of Python, run with
  `sudo python3`: `libc = ctypes.CDLL(None)`, then `libc.prctl(1, 9, 0, 0, 0)`
  (`PR_SET_PDEATHSIG`, SIGKILL), and `libc.prctl(2, ctypes.byref(sig), 0, 0,
  0)` (`PR_GET_PDEATHSIG` into a `ctypes.c_int`) before and after
  `os.setresgid(1000, 1000, 1000)`, setting it again before
  `os.setresuid(1000, 1000, 1000)`. Write it, then try `os.setresgid(0, 0, 0)`
  as root instead. Is the signal cleared? Why not?
- **Where does the `chdir` check happen?** In the `nnp` container, run `mkdir
  -m 700 /dev/shm/private` as root, then `exec -u 1000 --cwd /dev/shm/private u
  sh -c 'pwd; ls .'`. Here it printed `/dev/shm/private` and then `ls: .:
  Permission denied`, and runc 1.3.4's `exec --user 1000 --cwd` did the same.
  Which capability let the `chdir` through, and which step of §4 decides that
  it's still effective at that point? (runc goes further and tries the `chdir`
  as root first.)
