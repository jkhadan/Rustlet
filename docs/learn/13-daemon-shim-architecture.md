# 13 — The daemon and the shim: who holds a running container

Until Phase 4 a container lived exactly as long as the program that
started it. `rustlet-runc run` (or `cargo xtask image-run`) held the
container's terminal, waited for it and deleted it. Close that terminal
and the container went with it. Docker works differently: `docker run -d
nginx` returns at once, `docker logs` shows what nginx printed an hour
ago, and `systemctl restart docker` doesn't stop it. Three programs make
that possible, and Rustlets now has all three: a **daemon** that decides
and remembers (`rustletd`), a **shim** per container that holds it
(`rustlet-shim`), and a **CLI** (`rustlet`). The runtime underneath is
unchanged. This chapter follows a container through them: who is whose
parent, what the shim keeps, how the daemon's state survives the daemon,
what goes over the API, and why image work now happens in a cage.

Code: the shim, [`crates/rustlet-shim/src/`](../../crates/rustlet-shim/src/): [`main.rs`](../../crates/rustlet-shim/src/main.rs)
(`detach`, `handshake`), [`server.rs`](../../crates/rustlet-shim/src/server.rs) (`prepare`, `pump`,
`attach`, `exec`, `watch_init`), [`reaper.rs`](../../crates/rustlet-shim/src/reaper.rs),
[`runc.rs`](../../crates/rustlet-shim/src/runc.rs), [`stdio.rs`](../../crates/rustlet-shim/src/stdio.rs) and the library half,
[`protocol.rs`](../../crates/rustlet-shim/src/protocol.rs), [`paths.rs`](../../crates/rustlet-shim/src/paths.rs),
[`client.rs`](../../crates/rustlet-shim/src/client.rs), [`logfile.rs`](../../crates/rustlet-shim/src/logfile.rs).
The daemon, [`crates/rustletd/src/`](../../crates/rustletd/src/): [`daemon.rs`](../../crates/rustletd/src/daemon.rs) (startup),
[`lifecycle.rs`](../../crates/rustletd/src/lifecycle.rs), [`container.rs`](../../crates/rustletd/src/container.rs),
[`db.rs`](../../crates/rustletd/src/db.rs), [`attach.rs`](../../crates/rustletd/src/attach.rs), [`exec.rs`](../../crates/rustletd/src/exec.rs),
[`logs.rs`](../../crates/rustletd/src/logs.rs), [`images.rs`](../../crates/rustletd/src/images.rs),
[`worker.rs`](../../crates/rustletd/src/worker.rs), [`spec.rs`](../../crates/rustletd/src/spec.rs),
[`api.rs`](../../crates/rustletd/src/api.rs), [`notify.rs`](../../crates/rustletd/src/notify.rs). The API as types:
[`rustlet-spec`](../../crates/rustlet-spec/src/lib.rs). The client and CLI:
[`rustlet-client`](../../crates/rustlet-client/src/lib.rs), [`rustlet-cli`](../../crates/rustlet-cli/src/main.rs)
([`run.rs`](../../crates/rustlet-cli/src/run.rs), [`relay.rs`](../../crates/rustlet-cli/src/relay.rs)). The unit:
[`packaging/rustletd.service`](../../packaging/rustletd.service), installed by
[`xtask/src/daemon.rs`](../../xtask/src/daemon.rs). Tests: [`shim.rs`](../../tests/tests/shim.rs) (`sh_`, 8),
[`daemon.rs`](../../tests/tests/daemon.rs) (`dm_`, 14) and [`cli.rs`](../../tests/tests/cli.rs) (`cl_`, 5), all run by
`cargo xtask itest`. Design: [architecture.md §2.3, §2.6, §2.7](../architecture.md#23-rustlet-shim).

The transcripts were recorded on 2026-10-01 (UTC 2026-10-02) against the
installed service (`cargo xtask daemon install`), kernel 7.0.0-34-generic.
The API socket is root's (there is no `rustlet` group on this host, §8), so
every `rustlet` below is really `sudo target/debug/rustlet`, and root's
`curl` runs through `sudo systemd-run --pipe --wait`. Ids are 64 hex
digits; the shim and `ps` show their first 12. Terminal escape sequences
are left out of the interactive transcripts.

## 1. Three programs for one container

Here is nginx, started with `rustlet run -d --name web nginx`, in the
service's cgroup tree:

```text
$ systemd-cgls --no-pager -u rustletd.service
Unit rustletd.service (/system.slice/rustletd.service):
├─shims
│ └─114821 /usr/local/bin/rustlet-shim --id 64f2b0366d06894762ca8106b7682874fc0…
├─containers
│ └─64f2b0366d06894762ca8106b7682874fc06a8259657ea3cf865e3b667979880
│   ├─114823 nginx: master process nginx -g daemon off;
│   ├─114848 nginx: worker process
│   ├─114849 nginx: worker process
│   ├─114850 nginx: worker process
│   └─114851 nginx: worker process
└─daemon
  └─114737 /usr/local/bin/rustletd
```

Each holds something the others can't:

| process | lives | holds |
|---|---|---|
| `rustletd` | as long as the service | the containers' records (`state.db`), the API socket, the decisions: when to start, stop, restart, remove |
| `rustlet-shim` | as long as its container, and a little longer | the container's stdio (pipes, or the master of its terminal), its log file, its exit status: it is init's **parent** |
| `rustlet-runc` | a moment per command | nothing: it builds the namespaces, mounts and cgroup (chapters 02–10) and exits |

Docker splits the same way: dockerd, then containerd, then a
`containerd-shim` per container, then runc. The split buys three things.
The container doesn't depend on the daemon: the daemon can crash, be
upgraded or restart while its containers run on. The daemon never forks
a container process itself: it is multithreaded (tokio), and only the
single-threaded runtime may call `setns` and `clone3`
([architecture.md §1](../architecture.md#1-system-architecture), key choice 3). And the runtime keeps its
runc-compatible command line, so `runc` can still stand in for it.

## 2. Whose child is init?

`rustlet-runc create` makes container init with `clone3`, so init starts
life as rustlet-runc's child. Then rustlet-runc exits, init is
orphaned, and its new parent decides who will ever learn its exit
status. Normally that is PID 1 (systemd), which reaps it and tells no
one. The shim prevents that by declaring itself a **child subreaper**
before it starts anything (`prctl(PR_SET_CHILD_SUBREAPER, 1)`, in
`detach` in `main.rs`). In the words of prctl(2), an orphaned process
"will be reparented to the nearest still living ancestor subreaper".
rustlet-runc is the shim's child, so its orphans come to the shim:

```text
$ rustlet run -d --name tree alpine sleep 300
$ rustlet exec -d tree sleep 200
$ ps -o pid,ppid,sid,comm --ppid $(pgrep -x rustlet-shim) -p $(pgrep -x rustlet-shim)
    PID    PPID     SID COMMAND
 115556  115462  115556 rustlet-shim
 115558  115556  115556 sleep
 115567  115556  115556 sleep
$ rustlet exec tree sh -c 'ps -o pid,ppid,args'
PID   PPID  COMMAND
    1     0 sleep 300
    2     0 sleep 200
    3     0 ps -o pid,ppid,args
```

Both `sleep`s, init (`sleep 300`, 115558) and the `exec -d` one (115567),
are the shim's children on the host. In the container's PID namespace
their parent doesn't exist, so `ps` there shows 0. A process *inside* the
container that orphans its children leaves them to the container's
init, not to the shim: the kernel looks for a subreaper only among the
dying parent's ancestors in the dying parent's own PID namespace, and
the shim is outside it. That is also what lets the container's init be
an init.

**One loop reaps everything.** On `SIGCHLD` the shim calls
`waitid(P_ALL, WNOHANG)` until no exited child is left (`reaper.rs`):
rustlet-runc processes, init, exec'd processes. Whoever waits first gets
a status, and nobody gets it twice, so the shim never uses
`tokio::process` or `std::process::Child::wait`, which would wait for the
same pids. Each spawn registers its pid right away, and a status that
arrives before anyone asked is kept until someone does. The shim runs on
one thread (a tokio `LocalSet`), so "right away" is exact: between
`spawn()` and `reaper.watch(pid)` there is no `.await`, and the reaping
loop only runs when the caller yields.

## 3. Leaving the daemon behind

The daemon starts each shim with an ordinary `Command::spawn()` (it
forbids `unsafe`, so there is no `pre_exec` to run code in the child).
The shim's first acts are its own:

1. `setsid()`: a session of its own, without a controlling terminal, so
   nothing addressed to the daemon's session or process group (a
   terminal hangup, a `kill -- -PGID`) reaches it. In §2's `ps`, the
   shim's SID is its own pid.
2. `PR_SET_CHILD_SUBREAPER` (§2).
3. A move into `<cgroup parent>/shims`, by writing `0` to that cgroup's
   `cgroup.procs`, before it starts anything that would inherit the
   daemon's cgroup.

Its stderr is `shims/<short id>/shim.log`, a file the daemon opened, so
a shim that outlives the daemon still has somewhere to write. Its stdout
is a pipe to the daemon, for one line: `{"ready":{"init_pid":…,
"shim_pid":…}}` once `rustlet-runc create` has succeeded, or
`{"failed":{"message":…,"exit_code":127}}`. Then stdout becomes
`/dev/null`: a pipe whose reader may be long gone is no place to write.

**Why `daemon`, `shims` and `containers` are siblings.** systemd
delegates `rustletd.service` to the daemon (`Delegate=yes`), and
`DelegateSubgroup=daemon` puts the daemon's own process in a leaf
called `daemon`. cgroup v2's "no internal processes" rule (chapter 04)
lets a cgroup either hold processes or enable controllers for its
children, not both. Container cgroups need `memory`, `cpu` and `pids`
enabled all the way down, so the unit's own cgroup must stay empty, and
everything lives in leaves: the daemon in `daemon`, the shims in
`shims`, image workers in `workers/<n>` (§9), containers in
`containers/<id>`. The daemon finds its cgroup parent by removing
`/daemon` from its own cgroup.

**What the daemon does about the shim.** It reads the handshake, keeps a
task that reaps the shim if it exits while the daemon lives, and talks
to it over `shim.sock`. After a daemon restart the shim is nobody's
child but PID 1's (§7), and the new daemon only ever talks to its
socket.

## 4. The container's stdio

Without a terminal, the shim creates two pipes (three with `-i`) and
gives their container ends to `rustlet-runc create` as its stdin, stdout
and stderr. Init inherits the runtime's stdio (chapter 03, "inherited
stdio"), so those are the container's. Each pipe is then **chowned to the process's
user as the host sees it** (`stdio.rs`): for nginx that is root, for a
`--userns` container's root it is host uid 1000000, for container user
101 under `--userns` it is 1000101. The reason is `/dev/stderr`. It is a
symlink to `/proc/self/fd/2`, and opening it opens the pipe again, with a
permission check against the pipe's owner. nginx logs to `/dev/stderr`;
a pipe owned by host root is somebody else's `0600` file to a container
process that isn't root on the host (chapter 09 §8 met the same problem
in the foreground). containerd's shim does the same for user namespaces
(`IoUID`/`IoGID`). `sh_stdio_pipes_belong_to_the_process_user` and
`dm_user_namespace_container` check it, rootful and remapped.

With a terminal there are no pipes. The PTY is created *inside* the
container, by init, from the container's own devpts (chapter 05 §2), and its
master arrives over a **console socket**: a Unix socket the shim listens
on (`tty.sock`), named to rustlet-runc with `--console-socket`, which
init connects to and sends the master over with `SCM_RIGHTS`. Whoever
sits on the other end decides what arrives, so the shim checks it is a
PTY master (`TIOCGPTN` works only on a master) before it reads a byte.

**The log.** Whatever the container prints, the shim cuts into lines and
appends to `containers/<id>/container.log` as JSON lines
(`logfile.rs`). Lines longer than 16 KiB become several entries;
output that isn't UTF-8 is stored with U+FFFD. With a terminal,
everything is `stdout` and lines end in `\r\n`, because the PTY turns
`\n` into `\r\n` (chapter 05). One container, made through the API (§8):

```text
$ sudo cat /var/lib/rustlet/containers/d7bea92313ba…/container.log
{"ts":"2026-10-02T00:19:02.127292768Z","stream":"stdout","log":"from the API\n"}
```

An entry that would take the file past 10 MiB starts a new one: the file
is renamed `container.log.1` (`.1` to `.2`, and so on, three files at
most) and a new one begun. The daemon reads these files itself for
`rustlet logs` (`logs.rs`). Following one (`logs -f`) polls the current
file and tells files apart by inode, never by name. After a rotation it
reads its own file to the end once more (the shim may have written one
last entry just before renaming it), then every newer file in order: a
slow reader may be more than one rotation behind. The first version
went straight to the new `container.log`, and the review lost entries
both ways.

**Attach** is the same output, live: every chunk read from the pipes or
the master also goes to every attached client through a broadcast
channel. Input from attached clients goes through one queue to the
container's stdin. `run -i` sets *stdin-once*: when the first client's
input ends, the container's does too, which is how `echo hi | rustlet run
-i alpine cat` ends.

## 5. Talking to a shim

`shim.sock` carries frames: a length, a kind and a payload. Kind 0 is a
JSON message, 1–3 raw stdin, stdout and stderr bytes (`protocol.rs`).
Most requests get one answer: `Status`, `Start`, `Kill{signal, all}`,
`Pause`, `Resume`, `Resize`, `Delete{force}`, `Shutdown`. `Wait` gets its
answer when the container exits, possibly hours later. `Attach` and
`Exec` turn the connection into a stream: output frames from the shim,
stdin frames and `Resize`/`CloseStdin` from the daemon, until the shim
sends `Exited` and closes.

`Start` is `rustlet-runc start`. Each rustlet-runc call gets its own
`--log` file with `--log-format json`, because without a terminal the
runtime's stderr *is* the container's: its error would end up in the
container's log, and the shim reads it from the log file's last `ERROR`
line instead (`runc.rs`).

**Attach before start.** `rustlet run alpine echo hi` prints and exits in
milliseconds. If the CLI attached after starting the container, the
output would be gone by the time it was listening. So the CLI attaches
first, to a container that is only *created* and has no shim yet, and
then calls start. The daemon keeps that attach waiting with the
container; `start` spawns the shim, opens a shim attach stream for each
waiting client, applies the terminal size the client sent meanwhile
(`Resize` before `Start`, so the program never sees another size), and
only then sends `Start` (`attach_and_start` in `lifecycle.rs`). The
waiting attach is registered while the daemon handles the HTTP request,
before it answers `101 Switching Protocols`: the CLI sends the start as
soon as it has that answer, perhaps before the upgraded connection is
served. A start that fails ends the attaches waiting for it with its
error.

**The exit, in order.** When init exits, the shim waits briefly for the
pipes to drain (they close once every process holding them is gone),
reads the container cgroup's `memory.events` (`oom_kill` above zero means
the kernel's OOM killer struck), writes `exit.json`, and answers `Wait`.
The daemon then cleans up: `Delete` (the runtime's state and cgroup go),
`Shutdown` (the shim exits), unmount the overlay. Only then does the
container count as exited. The first version sent the attached client
its `exit` as soon as the shim did, and a test failed: `rustlet rm` right
after an attached run found the container still "running". Now the
daemon tells an attached client about the exit only once it has handled
it (the bridge's `before_exit` in `attach.rs`), so whatever the client
does next sees an exited container.

## 6. The daemon's state machine

```text
 created ──start──► running ⇄ paused        (removing, dead: during rm, after a failed cleanup)
    │                  │ exits (or stop, kill)
    │                  ▼
    └──── start ── exited ──(restart policy)──► restarting ──(delay)──► running
                       │
                       ▼ rm
                    (gone)
```

Each container's state lives in a tokio `watch` channel
(`container.rs`): one place to read it, and every change wakes whoever
waits on it (`wait`, `stop` waiting for its exit, `logs -f` noticing the
end). Every change is written to `state.db` before anyone is woken
(`db.rs`: one row per container, the create-time record and the changing
state as JSON columns, a unique name). Image names stay in the store's
`index.json` (chapter 11); which images are in use is derived from the
rows.

Operations that change a container (start, stop, restart, pause, rm)
hold a per-container lock for their whole length, `.await`s included, so
they never interleave. What happens *to* a container doesn't take the
lock: the exit monitor (a `Wait` on the shim) cleans up and publishes
the exit, and only then hands the restart policy to a task that takes
the lock like any operation. `stop` holds the lock while it waits for the
exit its signal caused; if the monitor needed the lock too, they would
wait for each other forever.

An operation also runs to its end when the client that asked for it
hangs up. hyper drops the handler of a connection that closes, so a
`start` cut short by Ctrl-C stopped at whatever `.await` it had reached.
In the review's test that left a shim and a created container that
nothing watched, the overlay still mounted, and a container that said
`created`. So every lifecycle request runs in a task of its own, and the
handler only waits for it (`to_the_end` in `api.rs`).

**Stop** sends the stop signal (the container's `--stop-signal`, else the
image's `StopSignal`, else `SIGTERM`), waits for the timeout (10 s by
default), then kills every process in the cgroup (`kill --all KILL`, which
is `cgroup.kill`). A container's init is PID 1 of its namespace, and the
kernel delivers to it only signals it has a handler for (and, from
outside the namespace, `SIGKILL` and `SIGSTOP`; pid_namespaces(7)). A shell without
a `trap` doesn't stop on `TERM`; it is killed after the timeout, `Exited
(137)`. (`dm_stop_restart_pause_kill` once failed for that reason: it
stopped a container before its shell had reached the `trap` line.)

**Restart policies** follow Docker: `no`, `on-failure[:N]`, `always`,
`unless-stopped`. A stop or a kill with the stop signal or `KILL` counts
as a manual stop, which policies leave alone. The delay starts at 100 ms
and doubles up to a minute, back to 100 ms after a run that lasted 10 s.
The events of `rustlet run -d --name flaky --restart on-failure:2 alpine
sh -c 'echo try; exit 1'`, as `GET /v1/events` streamed them (§8),
show the delay doubling (attributes shortened):

```text
00:29:14.953630386Z create  flaky
00:29:15.025409928Z start   flaky
00:29:15.043878865Z die     flaky exit_code=1
00:29:15.149163768Z restart flaky        ← 105 ms after the die
00:29:15.208031042Z start   flaky
00:29:15.225688108Z die     flaky exit_code=1
00:29:15.429810320Z restart flaky        ← 204 ms
00:29:15.491708396Z start   flaky
00:29:15.507164432Z die     flaky exit_code=1   (two restarts done: it stays exited)
$ rustlet logs flaky
try
try
try
```

## 7. Surviving `systemctl restart rustletd`

`KillMode=process` in the unit tells systemd to signal only the main
process when the service stops. The shims and containers in the unit's
cgroup are left alone (systemd notes them on the next start: "Found
left-over process … in control group while starting unit. Ignoring.").
The new daemon finds its containers in `state.db` and asks each one's
shim for its `Status` (`reconcile` in `lifecycle.rs`). It asks even when
the database says the container isn't running. A daemon that died
between the shim's `Start` and recording it would otherwise leave a
running container recorded as `created`. Such a run is taken over like
any other, and a shim whose container never got its `Start` is shut
down. Image workers a killed daemon left behind (§9) are stopped too:

```text
$ ps -o pid,ppid,user,args -p 114823
    PID    PPID USER     COMMAND
 114823  114821 root     nginx: master process nginx -g daemon off;
$ sudo systemctl restart rustletd
$ rustlet ps
CONTAINER ID   IMAGE     COMMAND                  CREATED          STATUS          NAMES
64f2b0366d06   nginx     "/docker-entrypoint.…"   10 seconds ago   Up 10 seconds   web
$ rustlet inspect web | python3 -c 'import json,sys; s=json.load(sys.stdin)[0]["state"]; print(s["status"], s["pid"])'
running 114823
$ sudo journalctl -u rustletd -n 4 -o cat
Starting rustletd.service - Rustlets container daemon...
… INFO rustletd::lifecycle: took over the running container id=64f2b0366d06…
… INFO rustletd: rustletd ready socket=/run/rustlet/rustlet.sock cgroup=/system.slice/rustletd.service containers=2
Started rustletd.service - Rustlets container daemon.
```

The same init (114823) before and after. A container that **exits while
there is no daemon** is no harder: its shim writes `exit.json`, answers
nobody, and waits. Here `late` ran `sleep 3; exit 42` across a stopped
daemon:

```text
$ rustlet run -d --name late alpine sh -c 'sleep 3; exit 42'
$ sudo systemctl stop rustletd
$ sudo ls /run/rustlet/shims/d9e3e497b730
exit.json  init.pid  shim.log  shim.sock
$ sudo cat /run/rustlet/shims/d9e3e497b730/exit.json
{"code":42,"signal":null,"oom_killed":false,"finished_at":"2026-10-02T00:29:23.572559056Z"}
$ ps -o pid,ppid,sid,args -C rustlet-shim
    PID    PPID     SID COMMAND
 115375       1  115375 /usr/local/bin/rustlet-shim --id d9e3e497b730… --bundle /var/lib/rustlet/containers/d9e3e497b730… …
$ sudo systemctl start rustletd
$ rustlet ps -a
CONTAINER ID   IMAGE     COMMAND                  CREATED          STATUS                       NAMES
d9e3e497b730   alpine    "sh -c sleep 3; exit…"   23 seconds ago   Exited (42) 20 seconds ago   late
```

With its daemon gone, the shim's parent is PID 1. The new daemon's
`Status` came back `exited`, with the status from before; the daemon
cleaned up as after any exit, and the shim went. If the shim itself is
gone (a host reboot empties `/run`), the daemon reads `exit.json` if it
is there, and otherwise records exit status 255 with an error saying the
shim was gone. Then the restart policies apply, and the daemon starts
the stopped `always` containers, and the `unless-stopped` ones not
stopped by hand, as Docker's does.

`dm_containers_survive_the_daemon` does all of this with a `SIGKILL`ed
daemon: the same init after the restart, `exec` into it, and a container
that ended while there was no daemon reported with its own status.

## 8. The API

The daemon serves HTTP/1.1 with JSON bodies on a Unix socket (axum), and
`rustlet-spec` defines every route and type once for both sides. curl
speaks it as well as the CLI does:

```text
$ curl -s --unix-socket /run/rustlet/rustlet.sock http://localhost/v1/version
{"version":"0.1.0","api_version":"v1","os":"linux","arch":"x86_64","kernel":"7.0.0-34-generic"}
$ curl -s -X POST --unix-socket /run/rustlet/rustlet.sock -H 'Content-Type: application/json' \
    -d '{"image":"alpine","name":"api-demo","cmd":["sh","-c","echo from the API; exit 7"]}' \
    http://localhost/v1/containers
{"id":"d7bea92313ba483e528b60a3e673a0adc58dcc5a361ef14e424197c79fe04b35","name":"api-demo","warnings":[]}
$ curl -s -X POST --unix-socket /run/rustlet/rustlet.sock http://localhost/v1/containers/api-demo/start -w '%{http_code}'
204
$ curl -s -X POST --unix-socket /run/rustlet/rustlet.sock http://localhost/v1/containers/api-demo/wait
{"status_code":7,"oom_killed":false,"error":null}
$ curl -s --unix-socket /run/rustlet/rustlet.sock http://localhost/v1/containers/api-demo/logs
{"ts":"2026-10-02T00:19:02.127292768Z","stream":"stdout","log":"from the API\n"}
$ curl -s -X POST --unix-socket /run/rustlet/rustlet.sock http://localhost/v1/containers/nosuch/start
{"message":"no such container: nosuch","kind":"no_such_container"}
```

Three shapes of response:

- **JSON**, read whole.
- **NDJSON** for streams that only go one way (`logs`, `stats`, `events`,
  `pull`): one value per line, sent as it happens. The `logs` lines are
  the log file's own entries. A stream that fails after it has begun
  can't change its HTTP status any more, so it ends with an `{"error": …}`
  line. (`/events` was planned as a WebSocket; it needs only one
  direction, and curl can follow NDJSON.)
- **WebSockets** for attach and exec, which go both ways: binary
  messages are `[stream id][bytes]` (0 stdin, 1 stdout, 2 stderr), text
  messages JSON controls (`resize`, `stdin_eof` from the client; `exit`,
  `error` from the daemon). A client that just closes the socket
  detaches, as Docker's does, and the process runs on; since Phase 6 an
  exec client can first send `hangup`, and the process gets `SIGHUP`,
  as a shell does when its terminal window closes ([chapter
  17](17-tauri-ipc.md) §7).

Errors carry a kind besides the message, and the kind gives a CLI its
exit code, as Docker's does: 125 when Rustlets fails ("no such image"),
127 when the program wasn't found, 126 when it can't be executed,
otherwise the container's own status. `cl_exit_codes_say_whose_fault`
checks all three.

```text
$ rustlet run -it --rm alpine sh        # on a terminal
/ # cat /etc/alpine-release; tty; ps -o pid,user,args; exit 3
3.24.2
/dev/pts/0
PID   USER     COMMAND
    1 root     sh
    4 root     ps -o pid,user,args
$ echo $?
3
```

**Who may connect.** The socket is `0660` and belongs to the group
`rustlet` if that group exists, else it is `0600`, root's only. Whoever
can talk to the socket can run a `--privileged` container, which is root
on the host (and, once Phase 5 brings volumes, bind the host's `/` into
one): membership of the group is root by another name, as membership of
Docker's `docker` group is.

## 9. Image work in a cage

A pull reads what a registry sends, and an unpack reads what an image's
layers contain. Both can be made to allocate a lot. Phase 3's review
found two such places: the `tar` crate reads a GNU long-name or PAX
extension header into memory whole (Go's `archive/tar` caps those at
1 MiB), and `oci-client` buffers a manifest response whole before our 4
MiB check sees it. A small, hostile layer could make the long-lived
daemon allocate gigabytes. So the daemon doesn't do this work itself. It
starts `rustletd worker pull …` or `rustletd worker unpack …`
(`worker.rs`), which first moves itself into a cgroup of its own,
`workers/<n>`, with `memory.max` 1 GiB, `memory.swap.max` 0 and
`pids.max` 256, and only then reads anything. Its progress comes back as
NDJSON on its stdout, the same lines `rustlet pull` shows. A worker that
blows its budget is OOM-killed, and the pull fails; the daemon is
unharmed.

```text
$ rustlet pull alpine:3.20
3.20: Pulling from library/alpine
25f1d6b1951a: Pulling fs layer
25f1d6b1951a: Download complete
25f1d6b1951a: Pull complete
Digest: sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
Status: Downloaded newer image for alpine:3.20
docker.io/library/alpine:3.20
```

Two unpacks of one layer could now come from two processes at once.
They take turns: each holds an exclusive lock on
`snapshots/.locks/<chain ID>` from its check for the snapshot until the
snapshot is in place (chapter 12's snapshotter). That closes a race the
review found too, in which an unpack replacing a crash-damaged directory
could move aside the good snapshot a concurrent unpack had just put
there.

`rustlet rmi` removes a name. Then it deletes the blobs and snapshots
that nothing in `index.json` (named or not) and no container reaches,
along with the half-written files of killed workers. It never does this
while a pull, an unpack or a create is running: a pull stores its blobs
before the name that makes them reachable, and a create has looked up
its image before its container is recorded. Rather than wait in line for
its turn, it polls for it, because tokio's lock is fair: a collection
queued behind a long pull would make every later pull, unpack and create
queue behind it. What it can't read, it keeps. A manifest that doesn't
load as an image (an artifact, or a config it can't read just now) keeps
whatever its JSON names, and every snapshot unless its config says which
layers are its own. The first version kept only the manifest itself, and
could delete the layers under a running container.

A container keeps its image's layers even after the name is gone (`rmi
--force`); they go with its last container, collected in the background.
A worker dies with the operation that started it. If the whole daemon
was killed (`KillMode=process` leaves its children), the next daemon
stops what is left in `workers/` before it touches the store.

## 10. Keeping mounts to ourselves

The overlay of a running container is mounted on the host, below
`containers/<id>/rootfs` (chapter 12). Under systemd's shared `/`, a
mount event is passed on to every mount namespace that is `/`'s peer
or slave: other services' private namespaces would collect every
container's overlay. At startup the daemon makes `containers/` a private
bind mount of itself (`private_mount` in `daemon.rs`), so what is
mounted below it stays in the host's namespace:

```text
$ grep -E ' / | /var/lib/rustlet/containers' /proc/self/mountinfo | cut -d' ' -f4-7,9-10
/ / rw,relatime shared:1 ext4 /dev/sda3
…
/var/lib/rustlet/containers /var/lib/rustlet/containers rw,relatime - /dev/sda3 rw,errors=remount-ro
/ /var/lib/rustlet/containers/6d15228ff7e5…/rootfs rw,nodev,relatime - rustlet rw,lowerdir+=/var/lib/rustlet/snapshots/74d97c428c51…/fs,upperdir=…/upper,workdir=…/work,redirect_dir=nofollow,uuid=on,nouserxattr
```

Every host mount has a `shared:N` tag; the bind and the overlay below it
have none (`-` ends the optional fields). The bind outlives the daemon,
as the overlays may: it is made once, and `scripts/cleanup.sh` removes it
with the rest. The overlays themselves are mounted when a container
starts and unmounted when it stops, so a stopped container holds no
mount at all, and a restart mounts its old `upper/` again.

## 11. Ready means ready

The unit is `Type=notify`. systemd hands the daemon a datagram socket in
`$NOTIFY_SOCKET` (an abstract one, its name starting with `@`, which std
spells `SocketAddr::from_abstract_name`), and `systemctl start rustletd`
returns only once the daemon sends `READY=1` (`notify.rs`). Rustlets sends
it after reconciliation and after the API socket accepts connections, so
a script that starts the service can use it at once. `Restart=on-failure`
starts a crashed daemon again, which then reconciles as after any
restart. The daemon also refuses to run twice on one run root or data
root: it holds an OFD lock on `rustletd.lock` in each.

## 12. Limits, and differences from Docker

- **No network yet.** Containers have their own network namespace with
  only `lo` (`NET I/O 0B / 0B` in `stats`), and no generated
  `/etc/hostname`, `hosts` or `resolv.conf` (`cat /etc/hostname` in
  nginx says `debuerreotype`, the image's; `hostname` says the short id).
  Phase 5 brings both, and `-p`, `-v` and `--net`.
- **One cgroup tree.** Containers live below the daemon's unit, as with
  Docker's `cgroupfs` driver, hence systemd's "left-over process"
  notices on restart. Docker's `systemd` driver puts each container in a
  scope of its own instead.
- **A shim already running keeps the binary it started from**: installing
  a new `rustlet-shim` changes only the next starts.
- **Logs** are JSON lines in one format; there are no log drivers.
- **A busy root filesystem** (something outside the container still
  using it when the container stops) is unmounted lazily, as Docker's
  overlay driver does, and a later start mounts a new overlay on the same
  `upper/` and `work/` while the old one may live on.
- **`/events`** is NDJSON (§8); `--format` and filters are not
  implemented in the CLI; healthchecks wait for Phase 7.

## 13. Try it

As your normal user, from the repository (the CLI needs `sudo` while
there is no `rustlet` group; `target/debug/rustlet` is in the dev
sudoers):

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo xtask daemon install                     # binaries to /usr/local/bin, the unit, (re)start
systemctl status rustletd
R="sudo target/debug/rustlet"
$R run -it --rm alpine sh                      # exit with `exit 3`; `echo $?` says 3
$R run -d --name web nginx && $R ps
systemd-cgls -u rustletd.service               # daemon, shims, containers/<id>
$R logs web; $R exec -it web sh; $R stats web  # Ctrl-C ends stats
sudo systemctl restart rustletd && $R ps       # still up, same pid ($R inspect web)
$R stop web && $R rm web
cargo xtask itest -- sh_ dm_ cl_ rr_           # the tests behind this chapter (rr_: the reviews')
sudo systemctl stop rustletd                   # or `cargo xtask daemon uninstall`
```

## Check yourself

1. `rustlet-runc create` exits right after making init. Who would init's
   parent be without `PR_SET_CHILD_SUBREAPER`, and what would be lost?
   Who is the parent of a process that an `exec`'d shell inside the
   container forks and then abandons?
2. Why may the shim not use `tokio::process` to run `rustlet-runc start`?
   What would go wrong, and when?
3. The shim registers each child's pid "before the next `.await`". Why is
   that enough on one thread, and what would it take with several?
4. Why are the daemon, the shims and the containers in sibling cgroups
   `daemon`, `shims` and `containers`, rather than the daemon in the
   unit's cgroup itself?
5. A container runs as uid 101 with `--userns`. Who owns its stdout pipe
   on the host, and what fails if the shim leaves it to host root?
6. `rustlet run alpine echo hi` attaches before it starts. What would it
   miss otherwise? Why does the daemon apply a waiting client's terminal
   size before `Start`, not after?
7. `stop` waits, holding the container's lock, for the exit its signal
   caused. Why doesn't the exit monitor take that lock? What did the
   first version of the attach bridge get wrong about the order of
   events?
8. `docker stop` on `sh -c 'while :; do sleep 1; done'` takes ten
   seconds and ends in exit 137. Why, and what one line in the script
   would make it stop at once with 0?
9. After `systemctl restart rustletd`, how does the new daemon learn that
   a container exited while there was no daemon, and with what status?
   What if the host rebooted instead?
10. Why does the daemon unpack layers in a child with a memory limit
    rather than in a thread of its own? What is still parsed in the daemon?

## Experiments

- **Be the daemon.** With the service stopped, start a shim by hand (its
  arguments are in `ps` output above, or in `TestShim::start` in
  `tests/src/shim.rs`) for a bundle of your own, read its handshake, and
  speak the protocol: a frame is a big-endian `u32` length, a kind byte
  (0) and JSON such as `{"type":"start"}`. Send `wait` on a second
  connection before `start` on the first.
- **Orphans.** In a container started with `rustlet run -d alpine sleep
  300`, run `rustlet exec -d … sh -c 'sleep 100 & exit'`. Who is the
  `sleep 100`'s parent on the host and inside? Compare with §2.
- **A slow stop.** `rustlet run -d --name t alpine sh -c 'trap "sleep 3;
  exit 0" TERM; while :; do sleep 1; done'`, then time `rustlet stop -t 1
  t` and `rustlet stop -t 10 t` (after a `start`). What does each exit
  status say?
- **Propagation.** Start a container, then look for its overlay in
  another service's mount namespace (`sudo nsenter -t <pid of, say,
  systemd-logind> -m grep rustlet /proc/self/mountinfo`). Unmount the
  private bind with no containers running, stop and start the daemon,
  and look again while one runs.
