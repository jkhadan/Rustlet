# 05 — PTYs, passing file descriptors, and the create/start split

Phase 2a gives the container a terminal of its own and splits `run` into the
OCI's `create` and `start`. Both come down to getting a file descriptor to the
right process at the right moment. The PTY master is made *inside* the
container and passed *out* over a Unix socket. The `exec.fifo` fd is passed
*in*, so that init can wait at a gate the host controls. (cgroups, the other
half of Phase 2a, have their own chapter.)

Code: [`console.rs`](../../crates/rustlet-runtime/src/console.rs), [`init.rs`](../../crates/rustlet-runtime/src/init.rs),
[`create.rs`](../../crates/rustlet-runtime/src/create.rs), [`run.rs`](../../crates/rustlet-runtime/src/run.rs),
[`ops.rs`](../../crates/rustlet-runtime/src/ops.rs), [`state.rs`](../../crates/rustlet-runtime/src/state.rs),
[`sync.rs`](../../crates/rustlet-runtime/src/sync.rs), [`term.rs`](../../crates/rustlet-sys/src/term.rs),
[`socket.rs`](../../crates/rustlet-sys/src/socket.rs). Tests: [`terminal.rs`](../../tests/tests/terminal.rs)
(`cargo xtask itest -- tty_`) and [`lifecycle.rs`](../../tests/tests/lifecycle.rs) (`-- lc_`).

## 1. Terminals from first principles

A pseudoterminal (`pty(7)`) is two character devices wired back to back.
Bytes written to the **master** arrive at the **slave** as if typed. Bytes
written to the slave come out of the master as screen output. Terminal
emulators, `sshd` and `tmux` hold masters, and now so does `rustlet-runc
run`. Shells get the slave as fds 0–2. To them it is a real terminal:
`isatty()` is true, and it has a name, `/dev/pts/N`.

```text
 keys    ──► master ──► line discipline ────► slave ──► read() in the shell
 screen  ◄── master ◄── output processing ◄── slave ◄── write() in the shell
```

The **line discipline** (`n_tty`) is the kernel code that makes a terminal act
like one. Its settings are the termios flags that `stty -a` prints:

| flag | effect |
|---|---|
| `ICANON` | canonical mode: input is held until the line is complete, with backspace and Ctrl-U editing. Without it ("raw"), `read()` returns bytes as they come |
| `ECHO` | the kernel echoes input back out through the master |
| `ISIG` | Ctrl-C, Ctrl-\ and Ctrl-Z become SIGINT, SIGQUIT and SIGTSTP for the terminal's **foreground process group** |
| `OPOST`, `ONLCR` | output `\n` goes out as `\r\n` |

The EOF character (`VEOF`, Ctrl-D) is not a signal, and the program never sees
it: at the start of a line in canonical mode, it makes `read()` return 0.

Signals need an address, and **sessions** provide it (`credentials(7)`). A
**process group** is a job: `sleep 100 | wc` is one group, so Ctrl-C reaches
both. A **session** is a set of groups. `setsid()` starts one with the caller as
**session leader**, which can adopt one **controlling terminal** (ctty) with
`ioctl(fd, TIOCSCTTY)`. The terminal has one **foreground group**, which alone
gets the keyboard's signals and may read (a background reader gets SIGTTIN).
**Job control** is the shell giving each job a group (`setpgid`) and moving the
foreground with `tcsetpgrp()`, i.e. `ioctl(TIOCSPGRP)`. The kernel allows that
only on your own ctty and for groups of your own session, so a job-control shell
must live in a session whose ctty is the terminal it reads. `/proc/<pid>/stat`
fields 5–8 show it all: `pgrp`, `session`, `tty_nr` (the ctty's device number,
0 if none) and `tpgid` (that terminal's foreground group).

### Phase 1 revisited: "not a tty"

In Phase 1, init inherited `rustlet-runc`'s stdio, session and process group.
In that shell (`"terminal": false`, typed on a terminal), `tty` says `not a
tty`, as chapter 03 explained, and `cut -d" " -f5-8 /proc/1/stat` prints `1 0
34818 5`. `tty_nr` 34818 is 136:2, the host's `/dev/pts/2` (sudo's PTY: sudo
runs with `use_pty` on this machine). The session is **0**, because its leader
is a host process with no PID in this namespace. And yet busybox does job
control. `strace -f` shows how (fd 10 is its copy of `/dev/tty`):

```text
ioctl(10, TIOCGPGRP, [0])  = 0          who's in front? a group we can't name
setpgid(0, 1)              = 0          a group of my own
ioctl(10, TIOCSPGRP, [1])  = 0          and now it's in front
ioctl(10, TIOCSPGRP, [0])  = -1 ESRCH   (at exit) hand it back to "0": impossible
```

Seen from the host, `rustlet-runc` (`217312 … 34818 217313`) had become a
background process on its own terminal, and the foreground was the container's
shell, host PID 217313 (`NSpid: 217313 1`). The container was doing job
control on a host terminal, in a session it couldn't see, with no way to hand
the terminal back. The fix is a terminal of the container's own.

## 2. A PTY made inside the container

With `"terminal": true`, init makes the PTY after `pivot_root` and before it
gives up root (`setup_container_tty`). From `strace -f` of `rustlet-runc run`,
init only:

```text
openat(AT_FDCWD, "/dev/ptmx", O_RDWR|O_NOCTTY|O_CLOEXEC) = 3
ioctl(3, TIOCSPTLCK, [0])        = 0
ioctl(3, TIOCGPTPEER, 0x80102)   = 6
openat(AT_FDCWD, "/dev/console", O_RDONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0666) = 8
openat(AT_FDCWD, "/dev/console", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH) = 8
open_tree(6, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH) = 10
move_mount(10, "", 8, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) = 0
setsid()                         = 1
ioctl(6, TIOCSCTTY, 0)           = 0
dup2(6, 0)                       = 0
dup2(6, 1)                       = 1
dup2(6, 2)                       = 2
sendmsg(7, {msg_iov=[{iov_base="/dev/ptmx", iov_len=9}], msg_control=[{…, cmsg_type=SCM_RIGHTS, cmsg_data=[3]}], …}, MSG_NOSIGNAL) = 9
```

- **`/dev/ptmx`** is chapter 03's symlink to `pts/ptmx`, so the pair comes
  from the container's private devpts and the slave is `/dev/pts/0` *in
  there*. That alone fixes "not a tty". (Every devpts mount has been its own
  instance since Linux 4.7. `ptmxmode=0666` matters, because an instance's
  `ptmx` starts at 0000.) `TIOCSPTLCK` unlocks the slave, like `unlockpt(3)`.
- **`TIOCGPTPEER`** (4.13) opens the slave *through the master fd*. The
  textbook `open(ptsname(master))` resolves a path in a tree the container
  controls, where something may be mounted over `/dev/pts`; that is chapter
  02's lesson again. `0x80102` is `O_RDWR|O_NOCTTY|O_CLOEXEC`.
- **`/dev/console`** gets the slave bind-mounted onto it (fd onto fd, over an
  empty file in the `/dev` tmpfs), as the runtime spec requires for `terminal:
  true`. Init systems and `getty` open it by name. It's never the host's
  console (5:1).
- **`setsid()` + `TIOCSCTTY`**: only a session leader without a ctty may adopt
  one, and init inherited `rustlet-runc`'s session. `setsid()` fails only for a
  process-group leader, which init isn't (`clone3` put it in `rustlet-runc`'s
  group), and returns 1, the new session's ID. The `0` means "don't steal".
- **`dup2`** onto 0–2 clears close-on-exec on the copies, so they survive
  `execve`. **`sendmsg`** passes the master out (section 3); then init closes
  its master, slave and socket.

With `consoleSize` 30×100 and args `tty; stty size; ls -l /dev/console
/dev/ptmx; cut -d" " -f1-8 /proc/1/stat`:

```text
/dev/pts/0
30 100
crw--w----    1 root     tty       136,   0 Sep 25 09:42 /dev/console
lrwxrwxrwx    1 root     root             8 Sep 25 09:42 /dev/ptmx -> pts/ptmx
1 (sh) S 0 1 1 34816 1
```

Init leads session 1, its ctty is 34816 = 136:0 = `/dev/pts/0`, and it's in
the foreground (`tpgid` 1). The slave is root's, mode 0620, group `tty` (devpts
`mode=0620,gid=5`). For a non-root `process.user`, `switch_user` first calls
`fchown(0, uid, -1)` while still root, as runc does. Otherwise the user
couldn't reopen its own terminal by name, as `sudo`, `ssh` and `script` do. With
uid 1000, `ls -ln /dev/pts/` shows `crw--w---- 1 1000 5 136, 0 … 0`, and
`exec 3<>$(tty)` works.

## 3. Passing file descriptors: `SCM_RIGHTS`

An fd number is only an index into one process's fd table. The entry points to
an **open file description**, which holds the offset, the status flags (such as
`O_NONBLOCK`) and the file. A Unix socket can carry a reference to one as
`SCM_RIGHTS` ancillary data. The kernel installs a *new* fd in the receiver
pointing to the same open file: "equivalent to duplicating (dup(2)) a file
descriptor into the file descriptor table of another process" (`unix(7)`).

```text
init:          sendmsg(7, {…cmsg_type=SCM_RIGHTS, cmsg_data=[3]}, MSG_NOSIGNAL) = 9
rustlet-runc:  recvmsg(6, {…cmsg_type=SCM_RIGHTS, cmsg_data=[7]}, MSG_CMSG_CLOEXEC) = 9
```

Init's fd 3 arrives as fd 7. The message in flight holds its own reference, so
init can close its copy at once. Nothing is checked on arrival, because
holding the fd *is* the access: in the experiments, a script running as uid
1000 reads from a master that root created. The open file is shared, flags
included (the relay makes it `O_NONBLOCK`). `MSG_CMSG_CLOEXEC` makes the new
fd close-on-exec from its first instant.

**The console socket.** Whoever holds the master owns the terminal. A container
process holding its own master could type into its own terminal and keep it
alive after its real owner let go. So init keeps only the slave. When the last
master fd closes, the kernel hangs up the slave and init, the session leader,
gets SIGHUP (a `trap … HUP` in init ran as soon as a receiver closed its
master). The master's destination follows runc's console-socket convention,
which containerd's shim and Podman's `conmon` also speak. The caller listens on
a Unix socket and passes `--console-socket PATH`. The runtime connects, and init
sends one message: payload `/dev/ptmx` (just a name), plus the master as
`SCM_RIGHTS`. `rustlet-runc` connects **on the host, before `clone3`**, so the
path is resolved in the host's mount namespace and init inherits a connected fd.

| command, `terminal: true` | the master goes to |
|---|---|
| `run` (foreground) | an internal `socketpair`: `rustlet-runc` stays and relays |
| `run --console-socket P` | `P` (no relay) |
| `create`, `run -d` | `--console-socket` is required: `process.terminal is true but no --console-socket was given (…)` |

`create` exits once init is ready, and a master it held would die with it and
hang up the container. So a detached container needs a receiver that stays
(from Phase 4, `rustlet-shim`), as in runc.

## 4. The foreground relay

In a foreground `run`, `rustlet-runc` copies stdin to the master and the master
to stdout. `supervise` (`run.rs`) polls the signalfd, init's pidfd, stdin and
the master, and calls `Relay::pump` after every `poll`.

**Raw mode, restored on drop.** Two line disciplines are now on the path,
yours and the container's. Only the container's should handle Ctrl-C,
backspace and echo, because that's where the shell and its jobs live. So if
stdin is a terminal, `Relay::new` saves its settings and applies `cfmakeraw`:
`ioctl(9, TCSETS, {c_iflag=, …, c_lflag=ECHOE|ECHOK|ECHOCTL|ECHOKE})` on a dup
of stdin. With no `ICANON`, `ECHO`, `ISIG`, `ICRNL` or `OPOST` left, every key
travels as a byte, and output needs no work (the slave already sent `\r\n`).
`Drop for Relay` restores the settings on every path that returns or unwinds,
though not after SIGKILL or `std::process::exit` (`reset` fixes that).

On a terminal, `sleep 100` then Ctrl-C prints `^C`, and `echo $?` says 130. The
byte 0x03 passed through untouched, the container's line discipline made it
SIGINT for its foreground group, and `rustlet-runc` saw no signal. Job control
works the same way. With piped input, `\x1a` is Ctrl-Z:

```text
/ # sleep 100
^Z[1]+  Stopped                    sleep 100
/ # cut -d" " -f1-8 /proc/1/stat
1 (sh) S 0 1 1 34816 3
/ # bg
[1] sleep 100
/ # cut -d" " -f1-8 /proc/self/stat
4 (cut) R 1 4 1 34816 4
/ # fg
sleep 100
^C
```

Each job has its own group (`sleep` is 2, the `cut`s 3 and 4), all in session
1. `tpgid` follows whichever job is in the foreground.

**Window size.** `TIOCSWINSZ` stores a terminal's size and, if it changed,
sends SIGWINCH to its foreground group, which tells full-screen programs to
redraw. Done on a master, it applies to the slave. The relay copies your size
to the master at the start and on every SIGWINCH it receives. `stty size` said
`24 80`, then `40 120` after a resize. A `trap "echo got WINCH; stty size"
WINCH` printed `got WINCH` and `50 132` on the next resize.
`process.consoleSize` is applied by init before anything runs
(`tty_console_size_is_applied`).

**End of input.** A terminal has no "close the write end". When the relay's
input ends (a script piped into `run`), it types the container's EOF character
once, as a user would, and stops reading. In the trace, `read(9, "", 65536) =
0` is followed by `ioctl(7, TCGETS, {… c_lflag=ISIG|ICANON|ECHO|…})` and
`write(7, "\4", 1)`. fd 7 is the *master*, yet `TCGETS` returns the *slave's*
settings: termios ioctls on a PTY master act on its slave (the kernel's
`tty_mode_ioctl` redirects them). So `veof()` sends the container's own `VEOF`,
not a hard-coded Ctrl-D (`veof_is_the_containers_own`). `cat` then reads 0,
and busybox's line editor treats Ctrl-D on an empty line as the end
(`tty_stdin_eof_sends_end_of_file`).

**Back-pressure.** The kernel buffers little between master and slave: 17 to
21 KiB each way on this 7.0 kernel, depending on direction and mode (measured
with Python's `pty.openpty()` and a non-blocking write loop; the code says
"about 18 KiB"). If the container doesn't read, a blocking write to the master
waits. If the container is itself blocked writing output that only the relay
reads (paste a big file into `cat`), both sides wait forever. So the master is
`O_NONBLOCK`; stdin and stdout stay blocking, since their open files are shared
with your shell. Input the master won't take stays in `pending`, and nothing
new is read until it's delivered (at most one 64 KiB chunk plus the EOF byte).
While the relay waits for room, at most 50 ms per `pump` so that signals still
get handled, it keeps copying output (`big_transfers_do_not_deadlock`).

**When the container exits**, with every slave fd closed (checked with a
Python PTY pair, and at the end of the `run` trace):

| on the master | result |
|---|---|
| `poll` | `POLLHUP`, plus `POLLIN` while output is still buffered |
| `read` | the buffered output, then `EIO` (not 0) |
| `write` | **succeeds** until the buffer is full, then `EAGAIN` |

A write never tells you the container is gone. `copy_output` treats `EIO` as
the end, and `flush_input` watches for `POLLHUP`. Once `pump` has returned
`false`, `supervise` stops polling the relay's fds, since a dead master stays
`POLLHUP` and `poll` would return at once, forever. After reaping init,
`drain()` reads until `EAGAIN` or `EIO` (at most 4 MiB).

**Signals.** Chapter 03's rule was "don't forward what the terminal delivered
itself" (`si_code == SI_KERNEL`), which assumed a shared process group. A
container with its own PTY is in another session, so `forward` changes:

| `rustlet-runc` receives | no PTY (shared terminal) | own PTY |
|---|---|---|
| SIGINT, SIGQUIT, SIGHUP from the terminal | dropped: the container got it too | forwarded to init |
| SIGWINCH | dropped if from the terminal | never forwarded; the relay resizes the PTY |
| anything from `kill`, systemd, … | forwarded via the pidfd | forwarded via the pidfd |

In raw mode, Ctrl-C is only a byte. But pipe a script in and your terminal
stays cooked: its Ctrl-C and hangup reach only `rustlet-runc`'s side.

## 5. `create`, `start` and `exec.fifo`

`create` builds everything and leaves init just before `execve`; `start` lets
it go. In between, a higher layer does its part (from Phase 4, the shim reports
init's PID and runs `start` when told to). A session with a `sleep 1000`
bundle, trimmed (`R="sudo ./target/debug/rustlet-runc --root /run/rustlet/doc"`):

```text
$ $R create --bundle ./sleeper web
$ $R state web
{ "ociVersion": "1.2.0", "id": "web", "status": "created", "pid": 227645, … }
$ sudo ls -l /run/rustlet/doc/web
prw--w--w- 1 root root   0 Sep 25 06:01 exec.fifo
-rw-r--r-- 1 root root 440 Sep 25 06:01 state.json
$ $R start web; $R state web | grep status; sudo ls /run/rustlet/doc/web
  "status": "running",
state.json
$ $R kill web KILL; $R state web | grep status
  "status": "stopped",
$ $R delete web; $R state web
rustlet-runc: error: container "web" does not exist
```

While `created`, init sleeps in `wait_for_partner` (`/proc/<pid>/wchan`), the
`fs/pipe.c` function where opening a FIFO waits for the other side. Besides
0–2 it holds `…/exec.fifo` (the `O_PATH` handle) and `socket:[…]` (the sync
socket), both close-on-exec. `ps` still calls it `rustlet-runc … create …`.
(An earlier build also leaked `create`'s lock fd into init. Section 7 has the
story; `rr_init_holds_no_lock_or_state_dir_fd` now checks that it's gone.)

**The gate.** `create` makes the FIFO (`mknod` 0600, then `chmod` 0622, so the
umask can't interfere) and opens it **`O_PATH`**. That handle can't read or
write and bypasses the FIFO machinery, so the open neither blocks nor wakes
anyone. Init inherits it across `clone3`. After `pivot_root` the path is
unreachable, but the fd still works. Once setup is done, init sends `Ready` and
runs `wait_for_start`:

```rust
let w = rustlet_sys::fs::reopen(fifo.as_fd(), OFlag::O_WRONLY).context("open exec.fifo for writing")?;
let mut f = std::fs::File::from(w);
f.write_all(b"0").context("write exec.fifo")
```

Opening a FIFO for writing blocks until someone opens it for reading
(`fifo(7)`), and that blocked open *is* the gate. `reopen` opens
`/proc/self/fd/5`, a "magic link": the open goes straight to the file behind
the fd, without walking the unreachable path or the 0700 state directory. A
process may always open its own fd links, even after `setresuid` has made it
non-dumpable (which shuts *other* processes out of its `/proc/<pid>/fd`). The
FIFO's mode is still checked, against whatever user init is by then. Hence
0622: anyone may write, only root may read. A uid 1000 container under
`strace -f` (`run` calls the same `release` as `start`; `unfinished`/`resumed`
pairs merged):

```text
init    setresuid(1000, 1000, 1000)                          = 0
init    sendto(7, "{\"type\":\"ready\"}", 16, MSG_NOSIGNAL, NULL, 0) = 16
init    openat(AT_FDCWD, "/proc/self/fd/5", O_WRONLY|O_CLOEXEC …        blocks
parent  write(7, "{\n  \"ociVersion\": \"1.2.0\",\n  \"id"..., 440) = 440   .state.json.tmp
parent  openat(AT_FDCWD, "/run/rustlet/doc/u3/exec.fifo", O_RDONLY|O_NONBLOCK|O_CLOEXEC) = 7
init    … openat resumed                                     = 3
parent  unlink("/run/rustlet/doc/u3/exec.fifo")              = 0
init    write(3, "0", 1)                                     = 1
parent  poll([{fd=7, events=POLLIN}, {fd=8, events=POLLIN}], 2, 9999) = 1 ([{fd=7, revents=POLLIN}])
parent  read(7, "0", 1)                                      = 1
init    execve("/bin/true", ["true"], 0x650e3b9baf00 /* 2 vars */)
parent  recvfrom(6, "", 65536, 0, NULL, NULL)                = 0
```

`start`'s side is `release` in `create.rs`. It opens `O_RDONLY|O_NONBLOCK`,
because a blocking read-open waits for a writer and would hang forever if init
were dead. This open returns at once, and it is what wakes init. `start` then
unlinks the FIFO immediately. The missing FIFO is what makes the status
`running`, so even if `start` died now, nobody would take the program for a
created container, and a second `start` has nothing to open. It polls the FIFO
together with init's pidfd (fd 8): data means init got through; a readable
pidfd, or EOF, means init died first; 10 s of neither is an error. The byte
matters because the open only proves that `start` got there, while the `"0"`
(runc writes the same byte) proves that init's open returned. `start` refuses
anything but `created` (`cannot start container "web": it is running`), and
`delete` without `--force` refuses a running container but kills a `created`
one, as runc does.

## 6. The sync socket, with a gate in the middle

Chapter 03's `SOCK_SEQPACKET` pair now carries `{"type":"ready"}` after all
setup, then EOF when `execve` closes init's CLOEXEC end (the `recvfrom` = 0
above), or else `{"type":"error",…}` wherever init fails. `create` waits for
`Ready`, an error, or EOF without either ("container init exited during setup
without saying why"), and a SIGTERM or Ctrl-C meanwhile aborts it. `run` also
waits for the verdict after `release`. After `create` + `start`, nobody is
listening any more: init's `send` fails with `EPIPE` (no SIGPIPE, thanks to
`MSG_NOSIGNAL`), so init prints the error on the container's own stderr. Most
bad programs fail `create` already (see below), but a script whose `#!`
interpreter doesn't exist passes that check (the file is there and
executable) and only fails in `execve`. With `args: ["/script"]`, bound from a
host file containing `#!/no/such/interpreter`, `start` exits 0, the state
becomes `stopped`, and create's inherited stderr says `rustlet-runc: error:
cannot run the program: execve /script: ENOENT: No such file or directory`.
Under `run`, the error comes back over the socket and `run` exits 127.

**Why the `$PATH` lookup comes before `Ready`.** `prepare_exec` resolves
`args[0]` in the container's root, as the container user, before init reports
`Ready`. A typo then fails `create` itself with a shell's 127, instead of
producing a container that dies at `start`. runc does the same (`exec.LookPath`
before its FIFO wait):

```text
$ $R create --bundle ./missing m1; echo $?
rustlet-runc: error: cannot run the program: executable file not found in $PATH: "no-such-program" (PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)
127
```

A name containing `/` isn't checked yet, so only `start` notices that
`/etc/passwd` can't be executed. runc's `create` already rejects it.

## 7. `state.json`

`/run/rustlet/runtime/<id>/` (0700, root; `--root` changes the prefix) holds
`state.json` (written as temp file + rename) and, from `create` until `start`,
`exec.fifo`. `state.json` has the OCI fields (`ociVersion`, `id`, `status`,
`pid`, `bundle`, `annotations`), runc's `rootfs` and `created`, and a private
`rustlet` section. `create` writes it *first*, as `creating` with pid 0, then
after each step (cgroup, init's PID and start time, finally `created`), so
`delete` can always find what a killed `create` left behind. Commands that
change a container hold its lock, so they never interleave.

That lock is a POSIX record lock (`fcntl(F_SETLKW)` on `<dir>/.lock`), not
an `flock`, and the difference turned out to matter. An `flock` belongs to
the *open file*, and after `clone3` container init holds a copy of `create`'s
fd, so init shared the lock. Normally `create` unlocked explicitly and nobody
noticed. But when `create` was SIGKILLed between `Ready` and its final state
write, init kept the lock while it waited at the gate, and every later
`delete` or `start` blocked in `flock(LOCK_EX)` forever. (Found while writing
this chapter, by injecting a SIGKILL into `create`'s third `rename` with
`strace -e inject=rename:signal=SIGKILL:when=3`.) A record lock belongs to
the *process*: a child never inherits it, and it disappears the moment its
owner dies. With it, the same experiment ends with a plain `delete` removing
the half-created container in milliseconds.
Apart from `creating`, the stored `status` is never trusted: `State::refresh`
derives it on every read, top to bottom:

| status | condition |
|---|---|
| `stopped` | init was spawned but is gone, a zombie, or its PID has another start time now |
| `creating` | the file still says `creating`: `create` hasn't seen `Ready` |
| `paused` | the cgroup is frozen |
| `created` | `exec.fifo` exists |
| `running` | otherwise |

After `start`, `sudo cat …/state.json` still says `"status": "created"`, but
`state` says `"running"`. A crash between two steps can't leave a stale answer.

**The PID-reuse guard.** PID numbers get recycled. Once a detached container's
init has exited and been reaped by whoever inherited it, `pid` may belong to a
stranger, and `kill` must never signal a stranger. So `create` records init's
**start time** (field 22 of `/proc/<pid>/stat`, in clock ticks since boot)
right after `clone3`. For `web`, `cut -d" " -f22 /proc/$pid/stat` printed
`1417748`, and `state` showed `"init_start_time": 1417748`. The same PID with a
different start time is a different process (`status_is_derived_not_trusted`
fakes exactly that), and like runc, `state` shows `"pid": 0` once a container
is stopped. Everything that acts on init goes through `open_init`, which calls
`pidfd_open(pid)` first and `init_alive()` second. A pidfd names one process
for good: if that process dies its number can be reused, but the pidfd doesn't
follow the number (signals through it get `ESRCH`). Checking first would leave
a window for the PID to change hands, and you'd hold a pidfd for the stranger.
Opening first, a matching start time proves the pidfd is ours, because the only
process that ever had this PID *and* this start time is our init.

**`CreateGuard`.** If anything fails after the `mkdir`, a drop guard in
`spawn` kills init (the whole cgroup via `cgroup.kill`, if there is one), reaps
it, and removes the cgroup and the directory. Only `keep()` disarms it:
`create` calls it once init is ready, `run` after teardown (or, with `-d`, once
the program runs). After the failed `no-such-program` create, `/run/rustlet/doc`
was empty again (`lc_failed_create_leaves_nothing_behind`). One Rust subtlety:
`clone3` without `CLONE_VM` copies the whole address space, guard included, so
the child disarms its copy (`in_parent = false`) at once. A failing init can
never tear down its own container.

## 8. Try it

```sh
cargo build -p rustlet-runc
grep '"terminal"' .rustlet-dev/bundles/alpine/config.json     # should say true
sudo ./target/debug/rustlet-runc run --bundle .rustlet-dev/bundles/alpine demo
```

If it says `false`, your `config.json` predates Phase 2a, and `cargo xtask
rootfs` keeps it ("differs from this build's default"): delete it and run
`cargo xtask rootfs` again. Inside, try `tty` and `ls -l /dev/console
/dev/pts`; `sleep 100`, then Ctrl-Z, `jobs`, `bg`, `fg`, Ctrl-C; `cut -d" "
-f5-8 /proc/self/stat` versus `sleep 100 & cut -d" " -f5-8 /proc/$!/stat`; and
`stty size` after resizing the window. Every key goes to the container, so
there's no escape key like ssh's `~.`. From another terminal, `sudo
./target/debug/rustlet-runc kill demo KILL` ends it (`run` exits 137). The
separate steps need a bundle without a terminal (this uses `jq`):

```sh
mkdir -p /tmp/web
jq --arg r "$PWD/.rustlet-dev/bundles/alpine/rootfs" \
   '.root.path = $r | .process.terminal = false | .process.args = ["sleep", "1000"]' \
   .rustlet-dev/bundles/alpine/config.json > /tmp/web/config.json
R="sudo ./target/debug/rustlet-runc"
$R create --bundle /tmp/web web; $R state web; sudo ls -l /run/rustlet/runtime/web
$R start web; $R state web; sudo ls -l /run/rustlet/runtime/web
$R kill web KILL; $R state web; $R delete web
```

## Check yourself

1. Init calls `setsid()` before `TIOCSCTTY`. Why would `TIOCSCTTY` fail
   without it, and why can't `setsid()` itself fail with `EPERM` here?
2. What would `tty` print if init opened the *host's* `/dev/ptmx` before
   `pivot_root`? Why is `TIOCGPTPEER` safer than `open(ptsname(master))`?
3. Init closes its master right after `sendmsg`. Name two things that would
   go wrong if a process in the container kept a copy.
4. Why does `create` refuse `terminal: true` without `--console-socket`, while
   a foreground `run` doesn't need one?
5. Writing to the master of a PTY whose slave is closed succeeds. How does the
   relay find out that the container is gone?
6. `start` opens `exec.fifo` with `O_NONBLOCK` and polls init's pidfd. What
   would a blocking open do if init had died while `created`? Why does
   `open_init` open the pidfd *before* comparing start times?

## Experiments

- **Be the shim.** Run this as yourself, from a short directory (the socket path
  must fit in `sun_path`, 107 bytes): `python3 recv-console.py c.sock &`.

  ```python
  import os, socket, sys
  srv = socket.socket(socket.AF_UNIX)
  srv.bind(sys.argv[1])
  srv.listen(1)
  conn, _ = srv.accept()
  msg, fds, _, _ = socket.recv_fds(conn, 64, 1)
  print("payload", msg, "fds", fds, "uid", os.getuid(), flush=True)
  while True:
      try:
          data = os.read(fds[0], 4096)
      except OSError as e:
          print(e)
          break
      print(data, flush=True)
  ```

  Then `create --console-socket c.sock` a `terminal: true` bundle whose args
  are `sh -c 'tty; echo hello from $(hostname)'`, and `start` it. Here it
  printed `payload b'/dev/ptmx' fds [5] uid 1000`, then `b'/dev/pts/0\r\n'`
  and `b'hello from rustlet\r\n'`, and finally `[Errno 5] Input/output error`.
- **See the kernel echo.** `printf 'echo one\nexit 4\n' | sudo
  ./target/debug/rustlet-runc run --bundle … q` prints every line twice: the
  line discipline echoes it (the slave is still canonical with `ECHO`), then
  busybox's editor does when it reads the line. The status is 4. (`ESC[6n` is
  busybox asking for the cursor position; nobody answers.)
- **Kill it at the gate.** `create` a container, read `sudo cat
  /proc/<pid>/wchan`, then `sudo kill -KILL <pid>` and `start`. Which message
  do you get, and which check produced it?
