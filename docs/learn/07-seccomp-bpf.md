# 07 — Seccomp: a syscall filter, compiled by hand

Namespaces decide what a container can see, cgroups how much it can use, and
capabilities (chapter 06) which privileged operations the kernel will do for
it. All of those are checked *inside* the kernel, in code the syscall has
already reached. Seccomp stops a syscall at the door: before the kernel runs
it, a small program decides whether it runs at all. Phase 2b compiles OCI
`linux.seccomp` into that program by hand, without libseccomp, and ships
Docker's default profile. The milestone is `unshare -U` failing with `EPERM`
in a container. Nothing but seccomp could refuse it, because creating a user
namespace needs no capability.

Code: [`seccomp/mod.rs`](../../crates/rustlet-runtime/src/seccomp/mod.rs) (the program's shape),
[`compile.rs`](../../crates/rustlet-runtime/src/seccomp/compile.rs), [`asm.rs`](../../crates/rustlet-runtime/src/seccomp/asm.rs),
[`disasm.rs`](../../crates/rustlet-runtime/src/seccomp/disasm.rs), [`interp.rs`](../../crates/rustlet-runtime/src/seccomp/interp.rs),
[`docker.rs`](../../crates/rustlet-runtime/src/seccomp/docker.rs), [`syscalls.rs`](../../crates/rustlet-runtime/src/seccomp/syscalls.rs),
[`build.rs`](../../crates/rustlet-runtime/build.rs), [`rustlet-sys/src/seccomp.rs`](../../crates/rustlet-sys/src/seccomp.rs),
[`process.rs`](../../crates/rustlet-runtime/src/process.rs) (where the filter is loaded),
[`profiles/`](../../profiles/README.md). Tests: [`seccomp/tests.rs`](../../crates/rustlet-runtime/src/seccomp/tests.rs)
(`cargo test -p rustlet-runtime seccomp`) and [`hardening.rs`](../../tests/tests/hardening.rs)
(`cargo xtask itest -- hd_`). Design: [architecture.md §2.2.4](../architecture.md#224-seccomp-bpf-compiler-hand-written)
and [§2.2](../architecture.md#22-rustlet-runtime-library--rustlet-runc-binary--the-oci-runtime) steps 5.9 and 5.13.

All transcripts are real runs on this host (kernel 7.0.0-34-generic, x86_64).
The containers ran from root scripts in a `systemd-run --scope`, with `--root
/run/rustlet/doc-07`, on bundles made from the default one as in §10. runc
1.3.4 (libseccomp 2.5.5) was run for comparison.

## 1. A filter in front of every syscall

Once a thread has a filter, every syscall it makes first runs the filter, a
program in **classic BPF** (the 1992 packet-filter language, not eBPF). Its
only input is `struct seccomp_data`:

| offset | field | notes |
|---|---|---|
| 0 | `int nr` | the syscall number, in the numbering of the ABI used |
| 4 | `__u32 arch` | `AUDIT_ARCH_X86_64` = `0xc000003e`; `AUDIT_ARCH_I386` for `int 0x80` |
| 8 | `__u64 instruction_pointer` | where the call came from |
| 16 | `__u64 args[6]` | the argument registers, raw: low word at 16+8i, high at 20+8i |

The filter only sees register values. A pointer is just a number, so a
filter can't inspect a path, a struct or a buffer. It returns a 32-bit
verdict, with the action in the high 16 bits and data in the low 16. From
most to least severe:

| action | value | effect |
|---|---|---|
| `KILL_PROCESS` | `0x80000000` | the process dies of SIGSYS (and dumps core) |
| `KILL_THREAD` | `0x00000000` | only the calling thread dies; OCI's `SCMP_ACT_KILL` means this |
| `TRAP` | `0x00030000` | a SIGSYS the process may catch |
| `ERRNO` | `0x00050000` + errno | the call doesn't run and returns `-errno` |
| `USER_NOTIF` | `0x7fc00000` | a supervisor decides (rejected until Phase 8) |
| `TRACE` | `0x7ff00000` + data | a ptrace tracer decides; with no tracer, `ENOSYS` |
| `LOG` | `0x7ffc0000` | runs, and is logged |
| `ALLOW` | `0x7fff0000` | runs |

**Filters stack, and they stay.** There is no way to remove a filter.
Children inherit it, and `execve` keeps it. If there are several, they all
run and the most severe action wins. For two of the same action, the errno
of the filter installed last wins. I ran three containers inside a systemd
unit whose own filter refuses `setpriority` with `EACCES` (`sudo systemd-run
--wait --pipe -p SystemCallFilter=~setpriority -p
SystemCallErrorNumber=EACCES -- /bin/sh run.sh`). Each ran `grep
Seccomp_filters /proc/self/status; nice -n 5 true`:

```text
Seccomp_filters:	3                        the unit's own shell
== stack-none                                container without linux.seccomp
Seccomp_filters:	3
nice: setpriority(5): Permission denied
== stack-docker                              Docker's profile: setpriority allowed
Seccomp_filters:	4
nice: setpriority(5): Permission denied
== stack-enoent                              setpriority → ERRNO, errnoRet 2
Seccomp_filters:	4
nice: setpriority(5): No such file or directory
```

Outside the unit, the three print `nice: 0`, `nice: 0` and `No such file or
directory`. systemd's filters went from the unit's shell through
`rustlet-runc`, `clone3` and `execve` into a container that asked for no
filter at all. `ERRNO` beats Docker's `ALLOW`, and between two `ERRNO`s the
newer filter, the container's, decides. Why does systemd install three? I
read them back with `PTRACE_SECCOMP_GET_FILTER` (see Experiments). There is
one per ABI, 6, 8 and 9 instructions long, and ours has 140. The i386 one is
`ld [4]; jeq #0x40000003; ld [0]; jeq #97` → `ret 0x0005000d`, else `ret
0x7fff0000`. That's `ERRNO(13)` for `setpriority`, which is 97 on i386. The
x32 filter matches `0x4000008d`, and the x86_64 one 141.

**Why loading needs `no_new_privs` or `CAP_SYS_ADMIN`.** A filter survives
the `execve` of a setuid program, which then runs with privileges the
filter's author doesn't have. The example in seccomp(2) is a filter that
makes `setuid()` return 0 without doing anything: the program believes it
dropped root, and keeps it. With `no_new_privs` set, `execve` never grants
privileges, so the attack doesn't work. As uid 1000, a Python script loading
a one-instruction `ret ALLOW` filter gets:

```text
uid 1000 seccomp without no_new_privs: Permission denied
uid 1000 seccomp with no_new_privs:    0
['NoNewPrivs:\t1\n', 'Seccomp:\t2\n', 'Seccomp_filters:\t1\n']
```

(`Seccomp:` is 0 for none, 1 for strict mode, 2 for filters.)

## 2. Classic BPF, the machine

An instruction is 8 bytes: `struct sock_filter { __u16 code; __u8 jt; __u8
jf; __u32 k; }`. The machine has a 32-bit accumulator `A`, an index register
`X` and 16 scratch words, all starting at 0. Seccomp permits aligned 32-bit
loads from `seccomp_data`, constants, arithmetic, scratch memory,
`tax`/`txa`, jumps and `ret`. Rustlets uses six instructions:

| instruction | meaning |
|---|---|
| `ld [k]` | `A` = the word at offset `k` of `seccomp_data` |
| `and #k` | `A &= k` |
| `jeq`/`jgt`/`jge`/`jset #k, jt, jf` | compare `A` with `k` (unsigned; `jset`: `A & k != 0`), then skip `jt` or `jf` instructions |
| `ja k` | skip `k` instructions (32-bit offset) |
| `ret #k` | the verdict |

**Jumps only go forward.** The offsets are unsigned, so there are no loops.
A program ends after at most one step per instruction. It can also be
checked in one pass, because everything that leads to an instruction comes
before it. At load time the kernel (`bpf_check_classic`,
`seccomp_check_filter`) requires allowed opcodes only, loads inside
`seccomp_data`, jumps inside the program, a final `ret`, no division by a
constant 0, and no scratch word read before every path has written it.
[`interp.rs`](../../crates/rustlet-runtime/src/seccomp/interp.rs)'s `check`
does the same checks. [`disasm.rs`](../../crates/rustlet-runtime/src/seccomp/disasm.rs)
uses the same one-pass idea to track what `A` holds, which is how it knows to
write `; openat` next to `jge #257`.

**Two limits.** A program has at most 4096 instructions, and `jt`/`jf` are
`u8`, so a conditional jump skips at most 255. The compiler therefore jumps to
labels, and [`asm.rs`](../../crates/rustlet-runtime/src/seccomp/asm.rs) turns
them into offsets. It assembles **backwards**. A jump's distance depends only
on the code after it, which is already final when the assembler reaches the
jump. If the target is out of reach, it puts a **trampoline** right behind
the jump: a copy of the target if the target is a `ret`, otherwise a `ja`. A
profile giving each of the 385 x86_64 syscalls its own rule (`arg0 == nr`)
compiled to 2713 instructions with 393 trampolines. Its first comparison,
`0009 jge #193`, has `jt 0010`, and 0010 is `ja 0396`, because 0396 was out
of reach for `jt`. The default `ret ERRNO(1)` appears 8 times, the original
and 7 copies.

## 3. The shape of a program

A small profile first: `ERRNO` by default; `read`, `write`, `close` and
`exit_group` allowed; `socket` only for `AF_UNIX` (1). `cargo xtask seccomp
--bundle DIR --disasm` compiles a bundle's `linux.seccomp`, reports 21
instructions, and lists them:

```text
0000  ld    [4]                             ; arch
0001  jeq   #0xc000003e  jt 0003  jf 0002   ; AUDIT_ARCH_X86_64
0002  ret   KILL_PROCESS
0003  ld    [0]                             ; nr
0004  jset  #0x40000000  jt 0005  jf 0007   ; __X32_SYSCALL_BIT
0005  jeq   #0xffffffff  jt 0007  jf 0006   ; nr == -1 (skipped by a tracer)
0006  ret   KILL_PROCESS
0007  jgt   #231         jt 0008  jf 0009   ; exit_group
0008  ret   ERRNO(38)                       ; ENOSYS
0009  jge   #4           jt 0011  jf 0010   ; stat
0010  jeq   #2           jt 0019  jf 0020   ; open
0011  jge   #42          jt 0013  jf 0012   ; connect
0012  jge   #41          jt 0014  jf 0019   ; socket
0013  jge   #231         jt 0020  jf 0019   ; exit_group
0014  ld    [20]                            ; args[0] hi
0015  jeq   #0           jt 0016  jf 0019
0016  ld    [16]                            ; args[0] lo
0017  jeq   #1           jt 0018  jf 0019
0018  ret   ALLOW
0019  ret   ERRNO(1)                        ; EPERM
0020  ret   ALLOW
```

Targets are absolute. When `A` holds `nr`, the comment names the syscall a
number stands for, so `jge #4 ; stat` asks "is nr at least 4 (`stat`)?".

1. **Architecture (0–2).** Through `int 0x80`, 11 is `execve`; on x86_64
   it's `munmap`. Everything after this check assumes x86_64 numbers, so
   other ABIs are killed. i386 calls do reach this kernel
   (`CONFIG_IA32_EMULATION=y`).
2. **x32 (3–6).** x32 calls come with x86_64's `arch` and bit 30 set in
   `nr`. They're killed too, though this kernel has no x32
   (`# CONFIG_X86_X32_ABI is not set`). `-1` is let through: a tracer writes
   it to skip a syscall, and the kernel then runs the filter again.
3. **ENOSYS stub (7–8)**, for numbers above the profile's highest syscall
   (§4).
4. **Dispatch (9–13).** A binary search on `nr` over **ranges** with the
   same verdict: 0–1 allowed, 2 (`open`) denied, 3 allowed, 4–40 denied, 41
   has rules, 42–230 denied, 231 allowed. 0010 is a `jeq` chain. For a few
   single numbers against a common background, up to three `jeq`s beat a
   subtree.
5. **Rule blocks (14–18).** Argument rules in spec order, with the first
   match winning and each 64-bit comparison done in halves (§5).
6. **Verdicts (19–20).** These go last, because jumps only go forward.
   Syscalls with identical rules share one **block**, and a block that is only
   a `ret` needs no code.

Docker's profile, resolved for the default capabilities (`cargo xtask seccomp`):

```text
Docker's default profile for CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_SETFCAP (kernel 7.0)
…
  instructions    140 (the kernel's limit is 4096)
  syscalls        310 with rules of their own
  skipped         61 names that aren't x86_64 syscalls: chown32, clock_adjtime64, clock_getres_time64, clock_gettime64, clock_nanosleep_time64, fadvise64_64, …
  ENOSYS above    466 (removexattrat)
  dispatch        65 ranges of syscall numbers, at most 7 comparisons deep
  blocks          6 distinct (syscalls with the same rules share one)
  trampolines     0 (for jumps farther than 255 instructions)
…
```

The 140 instructions are a 9-instruction header, 64 dispatch comparisons (a
tree over 65 ranges has 64 inner nodes), 64 instructions of rules for
`socket`, `clone` and `personality`, and 3 verdicts. From `--disasm`:

```text
0009  jge   #273         jt 0041  jf 0010   ; set_robust_list
0010  jge   #157         jt 0026  jf 0011   ; prctl
…
0029  jge   #163         jt 0137  jf 0138   ; acct
…
0038  jge   #257         jt 0040  jf 0039   ; openat
…
0040  jge   #272         jt 0137  jf 0138   ; unshare
…
0137  ret   ERRNO(1)                        ; EPERM
0138  ret   ALLOW
0139  ret   ERRNO(38)                       ; ENOSYS
```

`openat` (257) passes 0009, 0010, 0026, 0034, 0038 and 0040 and reaches
`ALLOW`: six comparisons, 12 instructions in all. `mount` (165) ends at
0029, which denies all of 163–185 (`acct` to `security`, 23 syscalls).
Docker's allowlist comes in runs like that, so 310 syscalls fit in 65 ranges.

**Compared with the alternatives.** A linear chain would need 310 `jeq`s,
and a denied `mount` would pass all of them. libseccomp does better. I ran
the same resolved profile under runc and read both programs back from the
kernel, which also confirmed that ours has 140 instructions there. Then a
Python BPF interpreter ran each program for every `nr` from 0 to 499,
arguments 0:

| | instructions | `jeq` | `jgt`/`jge` | executed per syscall: min / mean / max |
|---|---|---|---|---|
| Rustlets | 140 | 25 | 67 | 6 / 11.6 / 16 |
| runc, profile limited to `SCMP_ARCH_X86_64` | 428 | 321 | 79 | 6 / 20.6 / 33 |
| runc, Docker's three architectures | 1269 | 979 | 243 | 7 / 21.3 / 34 |

libseccomp 2.5.5 builds a tree over single syscalls, with a `jeq` per number
at the leaves: numbers 0 to 21 alone take 22 `jeq`s (instructions 0400–0424).
On rules, libseccomp is faster, because ours are linear: `socket(45)` runs 40
instructions against its 23. But dispatch runs on every syscall, and there
the ranges win: `read` takes 12 against 19, `openat` 12 against 21.

## 4. The ENOSYS stub

A profile is an allowlist written at one point in time. A syscall added to the
kernel later isn't on it, so it gets the default, `EPERM`. But libcs try new
syscalls and fall back to old ones **only on `ENOSYS`** ("this kernel doesn't
have it"). `EPERM` ("you may not") gets reported as an error. So numbers
above the highest syscall the profile names return `ENOSYS`, and everything
below keeps the default (`compile::stub_wanted`). A default that already lets
calls run (`ALLOW`, `LOG`, `TRACE`) or is already `ENOSYS` needs no stub.

`clone3` (435) is below the stub, but Docker's profile gives it `ENOSYS`
explicitly unless the container has `CAP_SYS_ADMIN`. `clone`'s flags are in
a register, so the filter can check them for namespace bits (§5). `clone3`'s
flags are in a struct in memory, which it can't read. So the profile says
`ENOSYS`, and glibc falls back to `clone`. Busybox is built on musl, and
tracing `sh -c 'ls / …'` showed a plain `fork() = 2` and no `clone3`. So I
used the glibc
[`rustlet-probe`](../../tests/src/bin/rustlet-probe.rs), set up as in the
hardening tests: the binary at `/mnt`, the host's `/usr/lib/x86_64-linux-gnu`
at `/opt`, started through the host's loader. `fork` is glibc's `fork()`;
`spawn` is Rust's `Command`, which uses `posix_spawn`. `strace -f -e
trace=clone,clone3,execve`, container lines only:

```text
339474 execve("/opt/ld-linux-x86-64.so.2", ["/opt/ld-linux-x86-64.so.2", "--library-path", "/opt", "/mnt/probe", "fork", "spawn"], 0x5d0250be7fb0 /* 3 vars */) = 0
339474 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x706317060a50) = 2
339474 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---
339474 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0x706317054000, stack_size=0x9000}, 88) = -1 ENOSYS (Function not implemented)
339474 clone(child_stack=0x70631705cff0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
339476 execve("/bin/true", ["/bin/true"], 0x7ffe13489da8 /* 3 vars */ <unfinished ...>
339474 <... clone resumed>)             = 3
339476 <... execve resumed>)            = 0
```

`posix_spawn` got `ENOSYS` from `clone3` and retried with `clone`, minus the
clone3-only `CLONE_CLEAR_SIGHAND`. `clone` returned 3, the child's PID in the
container, and strace labels the child by its host PID, 339476. With
`clone3`'s `errnoRet` changed from 38 to 1, the probe printed `clone3 EPERM`,
`fork ok`, `spawn EPERM`: every `posix_spawn`, and so every
`std::process::Command`, now fails. That's the failure the stub prevents.

**Newer than the profile.** This kernel's syscalls go up to 471. Rustlets'
table knows all of them, and the profile names up to 466. To make raw calls
with every argument 0, I ran the host's `python3` in the container, set up
like the probe (host `/usr` at `/opt`, `PYTHONHOME=/opt`, `-S`):

| nr | syscall | host, no filter | Rustlets | runc |
|---|---|---|---|---|
| 435 | `clone3` | `EINVAL` | `ENOSYS` | `ENOSYS` |
| 457 | `statmount` | `EFAULT` | `EFAULT` | `ENOSYS` |
| 461 | `lsm_list_modules` | `EFAULT` | `EPERM` | `ENOSYS` |
| 462 | `mseal` | 0 | 0 | `ENOSYS` |
| 467 | `open_tree_attr` | `EFAULT` | `ENOSYS` | `ENOSYS` |
| 470 | `listns` | `EFAULT` | `ENOSYS` | `ENOSYS` |

`EFAULT` means the call reached the kernel, which then rejected the null
pointer. 461 is in the profile, for `CAP_SYS_ADMIN` only, so it gets
`EPERM`. 467 and 470 aren't in it, so the program sees `ENOSYS`, as if the
kernel were older than they are. runc was the surprise. Its stub starts
lower (instruction 0005 is `jgt #456` → `ret 0x00050026`), because its
libseccomp evidently can't resolve the newer names. For runc on this host,
`statmount`, `mseal` and the `*xattrat` calls get `ENOSYS` although Docker
allows them. A compiler can
only allow the syscalls its table knows. Rustlets' table is the kernel's own
[`syscall_64.tbl`](../../crates/rustlet-runtime/src/seccomp/syscall_64.tbl)
from v7.0. `build.rs` keeps the `common` and `64` rows and drops the `x32`
ones (512–547), which would map `rt_sigaction` to 512, its x32 variant.

## 5. 64-bit arguments on a 32-bit machine

`A` holds 32 bits and arguments have 64, so the compiler compares halves.
Equality needs both to match. For ordered comparisons the high words decide
unless they're equal, and only then the low words, like comparing two-digit
numbers. Docker's `socket` rules are `arg0 < 38`, then `== 39`, `== 41`, …
`== 45`:

```text
0073  ld    [20]                            ; args[0] hi
0074  jgt   #0           jt 0078  jf 0075
0075  ld    [16]                            ; args[0] lo
0076  jge   #38          jt 0078  jf 0077
0077  ret   ALLOW
0078  ld    [20]                            ; args[0] hi
0079  jeq   #0           jt 0080  jf 0083
0080  ld    [16]                            ; args[0] lo
0081  jeq   #39          jt 0082  jf 0083
…
0106  jeq   #45          jt 0107  jf 0137
```

A nonzero high word means the value is at least 2³², so `< 38` fails at
0074. If the high word is zero, the low word decides. A failed rule jumps to
the next rule, and the last to the default, 0137. `clone`'s rule is
`SCMP_CMP_MASKED_EQ`, `(flags & 0x7E020000) == 0`, meaning none of
`CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET` is set. The mask's
high word is 0, so that half is skipped:

```text
0108  ld    [16]                            ; args[0] lo
0109  and   #0x7e020000
0110  jeq   #0           jt 0111  jf 0137
0111  ret   ALLOW
```

**Why the high word matters.** `socket`'s `domain` is an `int`, so the kernel
ignores the register's upper 32 bits, but the filter sees all 64. Try a
*deny* rule: default `ALLOW`, and `socket` → `ERRNO` if `arg0 == 40`
(`AF_VSOCK`), which compiles to `ld [20]; jeq #0; ld [16]; jeq #40`. Raw
`socket(domain, SOCK_STREAM, 0)` calls, with `SO_DOMAIN` read back:

```text
== sock-deny
                 41:40:1 -> -1 EPERM
        41:0x100000028:1 -> 3 (SO_DOMAIN 40)
…
== sock-docker
…
                  41:2:1 -> 3 (SO_DOMAIN 2)
        41:0x100000002:1 -> -1 EPERM
```

To the filter, `0x1_0000_0028` isn't 40. To the kernel it is, so the deny
rule was bypassed. Docker's allow rules fail safe: a stray high word misses
every rule, so even `AF_INET` in disguise gets `EPERM`. OCI comparisons are
64-bit, as in libseccomp, and the compiler can't fix that for you. For `int`
arguments, write allowlists. `every_operator_at_every_edge` tests every
operator around 0, 2³² and 2⁶⁴. `compiled_programs_agree_with_the_reference`
checks 400 random profiles against a direct evaluation of the OCI rules, in
over 100 000 cases.

## 6. Docker's profile, resolved per container

[`profiles/seccomp-default.json`](../../profiles/seccomp-default.json) is moby's
file, vendored unchanged. Besides OCI's fields it has `archMap`, which lists
the ABIs that go with the host (`SCMP_ARCH_X86_64` brings `X86` and `X32`).
Any entry can also have `includes`/`excludes` with `caps`, `arches` (Go's
names, `amd64`) and `minKernel`:

```text
$ jq -c '.syscalls[] | select(.includes.caps == ["CAP_SYS_ADMIN"] or .names == ["clone"]
    or .names == ["clone3"] or .includes.minKernel) | select(.includes.arches == null)
    | .names |= (if length > 4 then .[0:4] + ["…"] else . end)' profiles/seccomp-default.json
{"names":["process_vm_readv","process_vm_writev","ptrace"],"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"4.8"}}
{"names":["bpf","clone","clone3","fanotify_init","…"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}
{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}],"excludes":{"caps":["CAP_SYS_ADMIN"],"arches":["s390","s390x"]}}
{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38,"excludes":{"caps":["CAP_SYS_ADMIN"]}}
```

(2114060288 is `0x7E020000`, and the second entry lists 26 names.)
`docker::resolve` evaluates these conditions once, for the container's
bounding set and the running kernel, as moby does. The runtime only ever
sees plain OCI. For the default caps, 19 of the 37 entries survive. The first
allows 361 names unconditionally, and the conditional entries leave `clone`
with its mask and `clone3` with `ENOSYS`. Today `spec::default_spec` resolves
the profile when `cargo xtask rootfs` writes the bundle. From Phase 4 on, the
daemon does it for each container.

**Why tie syscalls to capabilities?** Without `CAP_SYS_ADMIN`, `mount`
fails anyway. Blocking it in seccomp as well keeps the kernel's mount code,
and any bug in it, out of reach. A container given `CAP_SYS_ADMIN` is meant
to mount, so for it the profile allows `mount`. The same goes for `reboot`
with `CAP_SYS_BOOT`, the `ptrace` family with `CAP_SYS_PTRACE`, and so on. In
the table, the columns are `unshare -U true`, `unshare -m true`, `mount -t
tmpfs t /mnt` and `hostname other`:

| container | `-U` | `-m` | `mount` | `hostname` |
|---|---|---|---|---|
| default caps, Docker's profile | EPERM | EPERM | EPERM | EPERM |
| default caps, no `linux.seccomp` | **ok** | EPERM | EPERM | EPERM |
| + `CAP_SYS_ADMIN`, profile resolved for the default caps | EPERM | EPERM | EPERM | EPERM |
| + `CAP_SYS_ADMIN`, no `linux.seccomp` | ok | ok | ok | ok |
| + `CAP_SYS_ADMIN`, profile resolved *with* it (`--caps …,SYS_ADMIN --json`) | ok | ok | ok | ok |

Row 2 is why the milestone matters. Creating a user namespace needs no
capability, so without a filter, root in a default container can do it
(`kernel.apparmor_restrict_unprivileged_userns` is 0 here). Row 3 shows the
filter refusing by itself, which is what
`hd_seccomp_blocks_mount_even_with_cap_sys_admin` tests. Resolved with
`CAP_SYS_ADMIN`, the program actually gets *smaller*:

```text
$ cargo xtask seccomp --caps CHOWN,DAC_OVERRIDE,FOWNER,FSETID,KILL,SETGID,SETUID,SETPCAP,NET_BIND_SERVICE,SYS_CHROOT,SETFCAP,SYS_ADMIN --disasm
…
  instructions    110 (the kernel's limit is 4096)
…
  dispatch        51 ranges of syscall numbers, at most 6 comparisons deep
  blocks          4 distinct (syscalls with the same rules share one)
…
0013  jeq   #41          jt 0048  jf 0109   ; socket
…
0021  jge   #165         jt 0109  jf 0108   ; mount
```

More allowed syscalls make longer runs: 51 ranges instead of 65. The `clone`
block and the `clone3` verdict disappear, leaving 4 blocks instead of 6.
From 0 to 133, everything except `socket` is allowed, and one `jeq` handles
it (0013). The skipped count rises from 61 to 62 because of `umount`, which
x86_64 doesn't have (it only has `umount2`).

## 7. Where the filter is loaded

`plan.rs` compiles `linux.seccomp` in the parent, before anything exists, so
a bad profile fails `create` immediately, for example with `invalid
config.json: linux.seccomp.defaultErrnoRet 5000 is larger than the largest
errno (4095)`, or with `linux.seccomp.architectures [SCMP_ARCH_X86] doesn't
include SCMP_ARCH_X86_64 (or SCMP_ARCH_NATIVE), the only architecture this
runtime runs`. Init loads the filter (and so does `exec`'s child). When it does so depends
on `noNewPrivileges` ([`process.rs`](../../crates/rustlet-runtime/src/process.rs)).
Here is `strace -f` of init in two runs:

```text
noNewPrivileges: true (the default)
337755 capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_CHOWN|1<<CAP_DAC_OVERRIDE|…
…
337755 openat(AT_FDCWD, "/proc/self/fd/5", O_WRONLY|O_CLOEXEC <unfinished ...>
337755 <... openat resumed>)            = 3
337755 prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0
337755 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=140, filter=0x5aa02ba1b9c0}) = 0
337755 execve("/bin/true", ["true"], 0x5aa02b9ef800 /* 3 vars */) = 0

noNewPrivileges: false
337760 seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=140, filter=0x6303f0d5da20}) = 0
337760 prctl(PR_CAPBSET_DROP, CAP_DAC_READ_SEARCH) = 0
…
337760 execve("/bin/grep", ["grep", "-E", "^(NoNewPrivs|Seccomp)", "/proc/self/status"], 0x6303f0d31800 /* 3 vars */) = 0
```

- **With `no_new_privs`**, the filter is the last thing before `execve`. It
  comes after the `exec.fifo` gate (the blocked `openat`, chapter 05), the
  byte written to the FIFO and the umask, so the filter only has to allow
  `execve`.
- **Without `no_new_privs`**, loading needs `CAP_SYS_ADMIN`, which the
  bounding-set drop is about to take away. So the filter goes in first, and
  everything init does afterwards runs under it. That container printed
  `NoNewPrivs: 0` and `Seccomp: 2`. With a profile that allows everything
  except `capset` (→ `ERRNO`), the difference shows:

  ```text
  $ $R run --bundle ./nocapset-nnp k1       # noNewPrivileges: true; args: grep -E '^(NoNewPrivs|CapEff)' /proc/self/status
  CapEff:	00000000800405fb
  NoNewPrivs:	1
  $ $R run --bundle ./nocapset-nonnp k2     # noNewPrivileges: false
  rustlet-runc: error: container init failed: capset: EPERM: Operation not permitted
  ```

  runc's init behaved the same way under strace. With `false` it called
  `seccomp(…, {len=1269, …})` before `capset`; with `true` the order was
  `prctl(PR_SET_NO_NEW_PRIVS)`, `capset`, `seccomp`, `execve`. The early
  load is also why init runs `close_range(CLOSE_RANGE_CLOEXEC)` before the
  identity switch: a profile without `close_range` mustn't break the
  container.

## 8. In a real container

In the default bundle, `grep -E '^(NoNewPrivs|Seccomp)' /proc/self/status`
prints `NoNewPrivs: 1`, `Seccomp: 2` and `Seccomp_filters: 1`. The host
shell that started it has 0 for all three. This is what busybox prints when
the filter refuses (each command is followed by `echo "<name>: $?"`):

```text
unshare: unshare(0x10000000): Operation not permitted
unshare -U: 1
unshare: unshare(0x20000): Operation not permitted
unshare -m: 1
mount: permission denied (are you root?)
mount: 1
hostname: sethostname: Operation not permitted
hostname: 1
rustlet
nsenter: setns(): can't reassociate to namespace 'net': Operation not permitted
nsenter: 1
chroot: 0
```

`0x10000000` is `CLONE_NEWUSER` and `0x20000` is `CLONE_NEWNS`. The process
*is* root, so busybox's "are you root?" misleads: the `EPERM` came from the
filter. `chroot` works because `CAP_SYS_CHROOT` is a default capability, and
the profile includes `chroot` for it. Under Docker's profile, the glibc probe
printed `EPERM` for `vsock`, `alg`, `unshare-user` and
`personality-no-randomize`, and `ENOSYS` for `clone3` and `clone3-newuser`.
It printed `ok` for `fork`, `spawn`, `unix`, `inet`, `personality-query` and
`personality-linux`. Without a profile, all twelve were `ok`. `AF_VSOCK`
(40) talks to the hypervisor, and no namespace isolates it. `AF_ALG` (38)
exposes the kernel's crypto API. `personality` is allowed for five exact
values: 0, 8 (`PER_LINUX32`), `0x20000`, `0x20008` and the query
`0xffffffff`. `ADDR_NO_RANDOMIZE` (`0x40000`), which turns off address-space
randomization, is not among them.

**A profile of your own.** This one is `ALLOW` by default, with `mkdir` and
`mkdirat` → `ERRNO` and `errnoRet` 13. `--disasm` shows 11 instructions: the
header, then `jeq #83` (`mkdir`) and `jeq #258` (`mkdirat`) in front of `ret
ALLOW`, with `ret ERRNO(13)` last. It reports `no stub (permissive default
action, or no rules)`. The rootfs is read-only, so the test writes to
`/dev/shm`:

```text
$ $R run --bundle ./custom c1      # args: sh -c 'mkdir /dev/shm/d; echo "mkdir: $?"; touch /dev/shm/f; …'
mkdir: can't create directory '/dev/shm/d': Permission denied
mkdir: 1
touch: 0
f
Seccomp:	2
```

Under `strace -f -e trace=mkdir,mkdirat`, init's own call for `/dev`,
`mkdirat(9, "pts", 0755) = 0`, still succeeds, because the filter doesn't
exist yet. The container's call is refused:
`mkdir("/dev/shm/d", 0777) = -1 EACCES (Permission denied)`.

## 9. Deliberate differences, and how it's tested

| | Rustlets | runc / Docker |
|---|---|---|
| i386 and x32 syscalls | `KILL_PROCESS` | allowed (Docker lists `SCMP_ARCH_X86`, `X32`); i386 is a Phase 8 stretch goal |
| a conditional rule followed by an unconditional one | first match wins | the unconditional rule wins |
| `SCMP_ACT_NOTIFY`, `listenerPath` | rejected until Phase 8 | supported |
| newest syscall it can name | 471 (the v7.0 table) | what its libseccomp knows (456 here, §4) |
| filter flags | only the profile's (none for Docker's) | runc also passed `SECCOMP_FILTER_FLAG_SPEC_ALLOW` |

I didn't demonstrate the i386 kill in a container, because `KILL` and `TRAP`
make the kernel dump core, and here that runs `systemd-coredump`. The unit
test `i386_syscalls_are_killed` makes a real `int 0x80` `getpid` after
loading Docker's profile. It makes itself non-dumpable first, and passes when
the child dies of `SIGSYS`. In the Python interpreter, runc's 1269-instruction
program answers that call with `ALLOW`, and its x86_64-only program with
`0x00000000` (`KILL_THREAD`). `SPEC_ALLOW` keeps the kernel from forcing the
Spectre v4 mitigation on the process. That matters only on affected CPUs,
and this one reports `Not affected`.

**Precedence.** Take default `ALLOW` with two rules: `personality` →
`ALLOW` if `arg0 == 8`, then `personality` → `ERRNO`. The container runs `sh
-c 'linux32 uname -m; …; linux64 uname -m; …'`:

```text
== rustlet-runc
i686
linux32: 0
linux64: personality(0x0): Operation not permitted
…
== runc
linux32: personality(0x8): Operation not permitted
linux32: 1
…
```

In libseccomp, an unconditional rule replaces the conditional ones for the
same syscall, so runc refuses `personality(8)` too. Rustlets compiles the
rules as written, in order. Docker's profile never mixes actions for one
syscall, so it behaves the same under both runtimes. A profile that does mix
them is ambiguous: order its rules the way you mean them. `SCMP_ACT_NOTIFY`
fails with `config.json uses features this build does not support yet:`,
followed by `- linux.seccomp.syscalls[0]: SCMP_ACT_NOTIFY (Phase 8)`.

**The interpreter.** A test can't unload a filter, and it can't try 100 000
syscalls on itself, so [`interp.rs`](../../crates/rustlet-runtime/src/seccomp/interp.rs)
runs programs the way the kernel does: `check` performs §2's load-time
checks, and `run` returns the raw verdict. Docker's profile goes through it
(about 40 calls, `socket(0x1_0000_0002)` and `nr == -1` among them), and so do
the random profiles and the trampoline test. The two tests that load real
filters run the test binary again as a child, because a filter would stay on
the test process and the multithreaded harness can't `fork`. Here: `test
result: ok. 46 passed`, and the 11 seccomp tests among `cargo xtask itest`'s
`hd_` tests passed too.

## 10. Try it

```sh
cargo build -p rustlet-runc
cargo xtask seccomp                 # summary; --disasm for the program, --json for the resolved OCI profile
cargo xtask seccomp --caps CHOWN,DAC_OVERRIDE,FOWNER,FSETID,KILL,SETGID,SETUID,SETPCAP,NET_BIND_SERVICE,SYS_CHROOT,SETFCAP,SYS_ADMIN
mkdir -p /tmp/sc
jq --arg r "$PWD/.rustlet-dev/bundles/alpine/rootfs" \
   '.root.path = $r | .process.terminal = false
    | .process.args = ["sh", "-c", "grep Seccomp /proc/self/status; unshare -U true; mkdir /dev/shm/d"]' \
   .rustlet-dev/bundles/alpine/config.json > /tmp/sc/config.json
R="sudo ./target/debug/rustlet-runc"
$R run --bundle /tmp/sc t1          # unshare: … Operation not permitted
jq '.linux.seccomp = {"defaultAction": "SCMP_ACT_ALLOW",
      "syscalls": [{"names": ["mkdir", "mkdirat"], "action": "SCMP_ACT_ERRNO", "errnoRet": 13}]}' \
   /tmp/sc/config.json > /tmp/sc/c.json && mv /tmp/sc/c.json /tmp/sc/config.json
cargo xtask seccomp --bundle /tmp/sc --disasm
$R run --bundle /tmp/sc t2          # now unshare works, and mkdir says Permission denied
```

In an interactive container (`sudo ./target/debug/rustlet-runc run --bundle
.rustlet-dev/bundles/alpine demo`), try `linux32 uname -m`, `nsenter -t 1 -n
true`, `swapon /dev/null` and `chroot / true`. Predict each result from the
`--disasm` listing first.

## Check yourself

1. Why must the `arch` check come before anything that reads `nr`? What
   could an i386 program do with syscall 11 if a filter written for x86_64
   numbers let it through?
2. A profile whose default is `EPERM` runs on a kernel newer than itself.
   Why does `posix_spawn` break? Why does the stub start above the highest
   syscall *the profile* names, not the kernel's highest? Why is there no
   stub when the default is `ALLOW`?
3. One filter returns `ERRNO(EACCES)` for a call, and a filter installed
   later returns `ERRNO(ENOENT)`. What does the program see? What if the
   later one said `ALLOW`, or the earlier one `KILL_PROCESS`?
4. Why can a classic-BPF program be checked in one pass? What does the
   assembler do with a conditional jump to a target 300 instructions away,
   and why does it start from the end of the program?
5. A profile denies `socket` when `arg0 == 40`. How did a process still get
   an `AF_VSOCK` socket? Why doesn't Docker's `socket` rule have that hole?
6. With `noNewPrivileges: false`, why is the filter loaded before the
   capabilities are dropped? Why did a profile that denies `capset` then
   break the container, when it didn't with `true`?

## Experiments

- **Read the kernel's copy.** Run this as root on a container's PID. From
  inside a filtered unit the same call got `EACCES`, because the kernel
  refuses a tracer that has filters of its own. Each instruction is 8
  little-endian bytes: `code` (u16), `jt` and `jf` (u8), `k` (u32).

  ```python
  import ctypes, os, sys
  libc = ctypes.CDLL(None, use_errno=True)
  libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
  pid = int(sys.argv[1])
  libc.ptrace(0x4206, pid, None, None)                  # PTRACE_SEIZE
  libc.ptrace(0x4207, pid, None, None)                  # PTRACE_INTERRUPT
  os.waitpid(pid, 0x40000000)                           # __WALL
  i = 0
  while (n := libc.ptrace(0x420c, pid, i, None)) > 0:   # PTRACE_SECCOMP_GET_FILTER
      buf = ctypes.create_string_buffer(8 * n)
      libc.ptrace(0x420c, pid, i, buf)
      open(f"filter.{i}", "wb").write(buf.raw)
      print(f"filter {i}: {n} instructions")
      i += 1
  ```

  On §1's stacked container it printed `filter 0: 6 instructions`, then 8,
  9, and `filter 3: 140 instructions`, so index 0 is the *oldest* filter.
  Write a 20-line interpreter for §2's six instructions, and count what
  `read` executes.
- **Break glibc on purpose.** In a probe bundle, set `clone3`'s `errnoRet` to
  1 (`jq '.linux.seccomp.syscalls |= map(if .names == ["clone3"] then
  .errnoRet = 1 else . end)'`). Then resolve the profile with
  `CAP_SYS_ADMIN` and grant that capability. What do `clone3-newuser` and
  `unshare-user` print now, and why?
- **Stack filters.** Under §1's `systemd-run` unit, give the container a
  profile with `setpriority` → `SCMP_ACT_TRACE`. Which verdict wins? What
  would the container get without the unit's filter? Then swap §9's two
  `personality` rules: do Rustlets and runc agree now?
