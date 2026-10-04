# 18 — Building images: every change becomes a layer

[Chapter 11](11-oci-images.md) took images as a registry serves them: a
manifest, a config and layers that are tar archives, each named by its
digest. [Chapter 12](12-overlayfs.md) stacked the layers under a container
and caught everything the container changes in an upper directory: files
copied up, a whiteout for each deletion, opaque directories.
[Chapter 13](13-daemon-shim-architecture.md) put all of it behind the
daemon. Phase 7 closes the loop: Rustlets makes images. `rustlet build`
reads a Containerfile and runs its steps, each `RUN` in a container of the
image so far, each `COPY` straight into a mounted root filesystem, and
turns every step's upper directory back into a layer. `rustlet commit`
does the same for one container's changes, and `save` and `load` carry
images to and from a tar archive. This chapter follows a build from the
client packing the context to the layer blobs in the store, then the
build cache that makes a second build run nothing, multi-stage builds,
commit, save and load, and a bug in reading tar archives that the new
code found. [Chapter 19](19-compose.md) runs §1's image with compose.

Code: in `rustlet-build`, plain computation over text and files that the
daemon and the clients share: [`parser.rs`](../../crates/rustlet-build/src/parser.rs)
(`parse`, `logical_lines`, `extract_flags`, `json_array`),
[`expand.rs`](../../crates/rustlet-build/src/expand.rs) (`word`, `words`),
[`op.rs`](../../crates/rustlet-build/src/op.rs) (`Op::new`),
[`config.rs`](../../crates/rustlet-build/src/config.rs) (`ImageConfigState::apply`, `created_by`),
[`plan.rs`](../../crates/rustlet-build/src/plan.rs) (`plan`, `ArgScope`, `platform_args`, `resolve_from`),
[`ignore.rs`](../../crates/rustlet-build/src/ignore.rs) (`IgnoreRules`, `ignore_file`) and
[`context.rs`](../../crates/rustlet-build/src/context.rs) (`pack`). In the daemon,
[`build.rs`](../../crates/rustletd/src/build.rs) (`Daemon::build`, `Build::stage`, `run`, `copy`,
`cached`, `add_layer`, `write_image`, `next_key`, `remove_build_leftovers`),
[`commit.rs`](../../crates/rustletd/src/commit.rs) (`commit`, `commit_config`, `container_options`,
`mount_points`), [`archive.rs`](../../crates/rustletd/src/archive.rs) (`save_images`, `load_images`,
`prune_build_cache`) and [`pipe.rs`](../../crates/rustletd/src/pipe.rs). In `rustlet-image`,
[`diff.rs`](../../crates/rustlet-image/src/diff.rs) (`diff`, `DiffOptions::lowers`, `Differ::finish_dir`,
`as_made`, `below`, `commit_layer`, `unmap_remap`, `TarWriter`),
[`copy.rs`](../../crates/rustlet-image/src/copy.rs) (`copy`, `digest`),
[`archive.rs`](../../crates/rustlet-image/src/archive.rs) (`save`, `load`),
[`content.rs`](../../crates/rustlet-image/src/content.rs) (`keep`, `cache_entry`, `set_cache_entry`,
`remove_cache_entries`, `BlobWriter`), [`import.rs`](../../crates/rustlet-image/src/import.rs)
(`write_image`) and [`unpack/extensions.rs`](../../crates/rustlet-image/src/unpack/extensions.rs)
(`Extensions`, `parse_records`). The CLI's [`build.rs`](../../crates/rustlet-cli/src/build.rs)
(`build`, `BuildProgress`, `prune`, `commit`). Tests: [`build.rs`](../../tests/tests/build.rs)
(`cargo xtask itest -- bd_ cm_ sl_`: 9 builds, 2 commits, a save and load),
`rustlet-build`'s 164 unit tests, those of `diff.rs` (18), `copy.rs` (31) and
`archive.rs` (15), and the unpacker's PAX tests in
[`unpack/tests.rs`](../../crates/rustlet-image/src/unpack/tests.rs). Design:
[architecture.md §2.4](../architecture.md#24-rustlet-image--oci-images-storage-snapshots)
(Commit/diff, COPY and ADD, Save and load, Store entries without names,
Extension headers) and [§2.9](../architecture.md#29-builder-and-compose).

The transcripts were recorded on 2026-10-04, between 17:40 and 17:47 UTC,
against the installed service (`rustletd.service`, this phase's debug
build at commit `f659ddc`), kernel 7.0.0-34-generic, as my normal user in
the repository's root. `rustlet` is `sudo target/debug/rustlet`, which the
dev sudoers allows; `cargo xtask images` ran as its binary, `sudo
target/debug/xtask images`; the commands shown with `sudo` ran through
`sudo systemd-run --pipe --wait`. `$S` is a scratch directory of mine,
where the chapter's small contexts (`forms/`, `vars/`…) live. The store had
alpine, alpine:3.20, busybox, python:3-slim, redis:7-alpine, nginx and
hello-world, and no build cache (`rustlet builder prune -f` had emptied
it); then `rustlet compose build` in `examples/hits` (chapter 19) built
the `hits` project's image, `hits-web`, and no container was running.
Digests and ids are cut to 12 hex digits and `…`, omitted lines are `…`.
Times are UTC, except in `ls -l` listings on the host and in `tar -tv` of
an archive I made (`copy/data.tar.gz`), which are EDT, four hours behind.

## 1. A build, end to end

`examples/hits` is a web page that counts its visitors in Redis. Its
Containerfile:

```text
$ cat examples/hits/Containerfile
# The hits web app: Python's standard HTTP server and the redis client.
FROM python:3-slim

WORKDIR /app
RUN pip install --no-cache-dir --root-user-action=ignore "redis>=5,<6"
COPY app.py .

ENV REDIS_HOST=redis PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --start-interval=1s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

USER nobody
CMD ["python", "app.py"]
```

A build needs the Containerfile and a **context**: the directory whose
files `COPY` can take. The context travels to the daemon, less what
`.dockerignore` excludes:

```text
$ ls -A examples/hits; cat examples/hits/.dockerignore
app.py
compose.yaml
Containerfile
.dockerignore
README.md
# Only what the image needs goes to the daemon.
*
!app.py
!Containerfile
```

`*` excludes everything, and the two `!` lines take `app.py` and the
Containerfile back: the last pattern that matches a path decides. The
store's build cache already held every step of this file (§7 says why),
so a plain build would have run nothing. `--no-cache` runs them all:

```text
$ rustlet build --no-cache -t ch18-hits examples/hits
Sending build context to rustletd  1.9kB
Step 1/9 : FROM python:3-slim
Step 2/9 : WORKDIR /app
Step 3/9 : RUN pip install --no-cache-dir --root-user-action=ignore "redis>=5,<6"
 ---> Running in 5c2290ddf4b1
Collecting redis<6,>=5
  Downloading redis-5.3.1-py3-none-any.whl.metadata (9.2 kB)
…
Installing collected packages: PyJWT, redis

Successfully installed PyJWT-2.15.1 redis-5.3.1
 ---> Removed intermediate container 5c2290ddf4b1
 ---> 74750aeebec3
Step 4/9 : COPY app.py .
 ---> d13db2413152
Step 5/9 : ENV REDIS_HOST=redis PORT=8000
Step 6/9 : EXPOSE 8000
Step 7/9 : HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --start-interval=1s     CMD ["python", "-c", "import urllib.request; …"]
Step 8/9 : USER nobody
Step 9/9 : CMD ["python", "app.py"]
Successfully built e48844cda9f8
Successfully tagged ch18-hits:latest
```

While step 3 ran, from another terminal:

```text
$ rustlet ps -a
CONTAINER ID   IMAGE                  COMMAND                  CREATED                  STATUS                  PORTS   NAMES
5c2290ddf4b1   sha256:75a1a46bf917…   "/bin/sh -c pip inst…"   Less than a second ago   Up Less than a second           build-786bf6a6bc93-3
$ sudo ls -la --time-style=+%F /var/lib/rustlet/builds/786bf6a6bc93/context
total 20
drwx------ 2 root root 4096 2026-10-04 .
drwx------ 3 root root 4096 2026-10-04 ..
-rw-rw-r-- 1 root root 1358 2026-10-03 app.py
-rw-rw-r-- 1 root root  469 2026-10-03 Containerfile
-rw-rw-r-- 1 root root   73 2026-10-03 .dockerignore
```

What happened, in order:

1. **The client packed the context.** `context::pack` walked
   `examples/hits` in byte order of names and wrote a tar archive of what
   the ignore file lets through, straight into the request's body: a
   blocking thread writes, the request streams, so the daemon has the
   first files while the last are still being read. The request is `POST
   /v1/build` with the archive as its body and the options as one JSON
   value in the query (`rustlet -D build` prints them:
   `{"tags":["ch18-hits"],"dockerfile":"Containerfile","build_args":{},"target":null,"no_cache":false,"pull":"missing","network":"bridge","labels":{}}`).
   In the archive, owners are 0:0 without names (the client's ids mean
   nothing in an image), modes and modification times are kept, symlinks
   are symlinks, and FIFOs, sockets and devices are left out. The
   Containerfile and the ignore file always go, whatever the patterns say.
   What is excluded is never opened, so a `target/` of gigabytes, `.git`
   or a key file never leaves the client. The ignore file is
   `<Containerfile>.dockerignore` beside the Containerfile if there is one,
   else `.containerignore`, else `.dockerignore`, with
   `moby/patternmatcher`'s rules (`**`, `!` exceptions, a matching parent
   directory excludes what is below it).
2. **The daemon unpacked it** into `builds/<build id>/context/` (`0700`,
   root's) with chapter 11's unpacker in its plain mode: confined to that
   directory, and a file named `.wh.x` is a file there, not a whiteout.
   The CLI's "Sending build context" line comes when the daemon says it
   has the context: here 3 files, 1,900 bytes of data. The daemon read the
   Containerfile through the context (`openat2` with `RESOLVE_IN_ROOT`, so
   a Containerfile that is a symlink can't lead out of it; 1 MiB at most),
   parsed all of it (§2), and planned the stages (§8).
3. **FROM**: python:3-slim was in the store. The default pull policy is
   `missing`; `--pull` asks the registry for a newer image. The stage
   starts with the base's four layers and its config.
4. **WORKDIR, ENV, EXPOSE, HEALTHCHECK, USER, CMD** only change the
   image's config: no layer, no ` ---> ` line.
5. **RUN** ran in a container of the image so far (§4),
   `build-786bf6a6bc93-3`: the build's id and the step's number. Its image
   is an unnamed one the daemon had just written, python:3-slim plus
   `WORKDIR /app`. pip's output streamed back as it came. When pip exited
   0, the container's upper directory became a layer (§5), `74750aeebec3`
   being its blob's digest, and the container was removed.
6. **COPY** ran no process: the daemon mounted an overlay of the image so
   far, wrote `app.py` into `/app` (the working directory), and made a
   layer of the overlay's upper directory (§6).
7. **The image**: a config (the base's, with a new `config`,
   `rootfs.diff_ids` and `history`), a manifest naming it and the six
   layers, and the name `ch18-hits:latest` in `index.json` (chapter 11).
   Its id, `e48844cda9f8`, is the digest of its manifest (Docker's classic
   image store uses the config's). Then the context directory went, as it
   goes after a failure too.

The client shows the events as Docker's classic builder shows a build,
except that a ` ---> ` line names the layer a step added: there are no
intermediate images to name, and a step that only changes the config has
no such line. The image:

```text
$ rustlet run --rm ch18-hits sh -c 'id -un; pwd; ls -l; python -c "import redis; print(redis.__version__)"'
nobody
/app
total 4
-rw-rw-r-- 1 root root 1358 Oct  3 18:03 app.py
5.3.1
```

It runs as `nobody` in `/app`, with the redis client that step 3
installed. `app.py` is root's, with the mode and modification time it had
on the client.

## 2. The Containerfile's syntax

The syntax is Docker's as BuildKit's parser reads it (`parser.rs`), with
the classic builder's instructions. Reading a file goes in layers.

**Lines.** A line that ends with the escape character (spaces or tabs may
follow it) goes on in the next, which is appended as it is, indentation
included: hence the five spaces in step 7 above, the one before the `\`
and the next line's four of indentation. A line whose first non-blank
character is `#` is a comment, inside a continuation too; an empty line
inside one is dropped with a warning, as Docker warns. A `#` anywhere else
is part of the instruction: `RUN make # all` gives the shell a comment.

**Parser directives** are comments `# key=value` at the very top:
`escape` (`\`, the default, or `` ` ``), and `syntax` and `check`, which
are accepted and ignored, as there is one parser. The first line that
isn't a directive, even an empty one, ends them.

**Instructions.** A logical line's first word names it, in any case:
`FROM`, `RUN`, `CMD`, `ENTRYPOINT`, `COPY`, `ADD`, `ENV`, `ARG`, `LABEL`,
`WORKDIR`, `USER`, `EXPOSE`, `VOLUME`, `STOPSIGNAL`, `HEALTHCHECK`,
`SHELL`, `ONBUILD` and the deprecated `MAINTAINER` (it works, with a
warning). Only `ARG` can come before the first `FROM`. The rest of the
line is kept as written; variables are expanded, and quotes removed, when
the step runs (§3).

**Flags** are the words at the start of the arguments that begin with
`--`: `COPY --chown=app:app --chmod=640 a b`. Each needs its `=`, quotes
in them are removed, a lone `--` ends them. Each instruction has its own:
`FROM --platform`, `COPY --from --chown --chmod`, `ADD --chown --chmod`,
five for `HEALTHCHECK`. Anything else is an error, and BuildKit's own
flags are refused by name rather than as unknown.

**Exec and shell forms.** `RUN`, `CMD`, `ENTRYPOINT` and `HEALTHCHECK`'s
command take a JSON array of strings, the **exec form**, or anything
else, the **shell form**, which runs as one string under `SHELL`
(`["/bin/sh", "-c"]` unless changed). Docker's rule decides: arguments
that parse as a JSON array of strings are the exec form, an array holding
anything else is an error, and text that isn't valid JSON is the shell
form, silently:

```text
$ cat forms/Containerfile
# escape=`
FROM alpine:3.20
ENV GREETING="hello there"
RUN echo "shell form: $GREETING" `
    && echo "a continued line"
RUN ["echo", "exec form: $GREETING"]
CMD ['echo', 'single quotes are not JSON']
$ rustlet build -t ch18-forms forms
Sending build context to rustletd  201B
Step 1/5 : FROM alpine:3.20
Step 2/5 : ENV GREETING="hello there"
Step 3/5 : RUN echo "shell form: $GREETING"     && echo "a continued line"
 ---> Running in d4629a078ee9
shell form: hello there
a continued line
 ---> Removed intermediate container d4629a078ee9
 ---> 29cd657a8417
Step 4/5 : RUN ["echo", "exec form: $GREETING"]
 ---> Running in ed8a7cb66663
exec form: $GREETING
 ---> Removed intermediate container ed8a7cb66663
 ---> 29cd657a8417
Step 5/5 : CMD ['echo', 'single quotes are not JSON']
Successfully built 64fae31203b1
Successfully tagged ch18-forms:latest
$ rustlet inspect ch18-forms | jq -c '.[0].config.config | {Cmd, Env}'
{"Cmd":["/bin/sh","-c","['echo', 'single quotes are not JSON']"],"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GREETING=hello there"]}
$ rustlet run --rm ch18-forms; echo "exit $?"
/bin/sh: [echo,: not found
exit 127
```

- Step 3's shell expanded `$GREETING`. Step 4's exec form ran `echo`
  itself, which printed `$GREETING` as it was. The builder never expands
  `RUN`, `CMD` or `ENTRYPOINT`: the shell does, inside the container, or
  nothing does.
- The `` ` `` ending step 3's first line continued it, because of
  `` # escape=` ``. With the default escape character it would be an
  ordinary character, and the next line an instruction named `&&`.
- `CMD ['echo', …]` isn't JSON (JSON strings take double quotes), so it is
  the shell form, and the shell looked for a program named `[echo,`.
- Both `RUN`s printed the same layer, `29cd657a8417`: `echo` writes no
  file, and a step that changes nothing adds an empty layer (§5).

The difference goes beyond quoting. In the shell form the program runs
under `/bin/sh`, which must exist in the image, and the container's first
process is the shell, unless the shell replaces itself with a lone
command, which not every shell does. `rustlet stop` signals that first
process, and the first process of a PID namespace gets only the signals it
has a handler for (`pid_namespaces(7)`, chapter 13 §6): `sh` ignores the
SIGTERM, and the program is killed when the grace period ends. A
shell-form `ENTRYPOINT` also swallows `CMD` and `run`'s arguments: they
become the shell's `$0`, `$1`…, never the program's. The exec form runs
the program itself, as the first process, with exactly the arguments
given.

The whole file is parsed before anything runs, and an error names the
line its instruction starts on:

```text
$ cat bad1/Containerfile; rustlet build bad1
FROM alpine:3.20
RUN echo fine
FROBNICATE x
Sending build context to rustletd  44B
rustlet: error: Containerfile: line 3: unknown instruction: FROBNICATE
$ cat bad2/Containerfile; rustlet build bad2
FROM alpine:3.20
CMD ["sleep", 5]
Sending build context to rustletd  34B
rustlet: error: Containerfile: line 2: when using JSON array syntax, arrays must be comprised of strings only
$ cat bad3/Containerfile; rustlet build bad3
FROM python:3-slim
RUN --mount=type=cache,target=/root/.cache \
    pip install redis
Sending build context to rustletd  86B
rustlet: error: Containerfile: line 2: RUN --mount is a BuildKit feature Rustlets doesn't support
$ cat bad4/Containerfile; rustlet build bad4
FROM alpine:3.20
RUN <<EOF
echo hi
EOF
Sending build context to rustletd  39B
rustlet: error: Containerfile: line 2: RUN with a heredoc (<<EOF) is a BuildKit feature Rustlets doesn't support: put the text in a file in the context
```

`RUN echo fine` never ran, and each build exited 1. BuildKit's additions
are refused where they stand rather than ignored: heredocs, `RUN
--mount`, `--network` and `--security`, `COPY --link`, `--parents` and
`--exclude`, `ADD --checksum` and `--keep-git-dir`, and a `--platform`
other than `linux/amd64`. Ignoring `--mount=type=secret` would build an
image that silently lacks what the step needed.

## 3. Variables: ENV and ARG

`ENV NAME=value` sets a variable in the image's config (`Env`): the
instructions after it see it, and so does every container of the image.
`ARG NAME[=default]` declares a variable of the build: the instructions
after it in its stage see it, `RUN` gets it in its environment, and the
image doesn't keep it. Where both have a name, `ENV` wins.

**Scopes.** An `ARG` before the first `FROM` is **global**, and only
`FROM` lines see it (and `COPY --from`, which is planned before anything
runs). Each stage starts with no `ARG`s; it sees a global one once it
declares it again, without a value. A declared `ARG`'s value is the build
arg (`--build-arg NAME=VALUE`, or a bare `--build-arg NAME` taking the
client's environment), else its default, else the global's. Two kinds
exist without an `ARG` in the file. BuildKit's **platform args**
(`TARGETPLATFORM=linux/amd64`, `TARGETOS=linux`, `TARGETARCH=amd64`,
`TARGETVARIANT` empty, and the `BUILD…` ones with the same values) are
predefined global ones: `FROM` lines see them, and a stage declares `ARG
TARGETARCH` to see one. Docker's **proxy args** (`HTTP_PROXY`,
`https_proxy`, `NO_PROXY`… in both cases) reach every `RUN` from the build
args alone, and stay out of the cache key and the history. A build arg
that nothing declares is warned about.

**Expansion.** The builder expands the arguments of `FROM` (with the
global `ARG`s), `ENV`, `ARG` defaults, `LABEL`, `WORKDIR`, `USER`,
`EXPOSE`, `VOLUME`, `STOPSIGNAL`, and `COPY` and `ADD` (sources,
destination and flags), as Docker does (`expand.rs`, after BuildKit's
`shell.Lex`). `$V` and `${V}` are the value, nothing if unset;
`${V:-word}` is `word` if `V` is unset or empty, `${V-word}` only if
unset; `${V:+word}` is `word` if `V` is set and not empty, `${V+word}` if
set; `${V:?message}` and `${V?message}` fail with the message. Single
quotes keep everything literal, double quotes keep whitespace, the escape
character makes the next character literal. `ENV`, `LABEL` and
`WORKDIR` make one string of their argument; `COPY`, `EXPOSE` and
`VOLUME` split it into words at unquoted whitespace, in what a variable
expands to as well, as a shell does. One rule surprises: all the pairs of
one `ENV` are expanded against the variables as they were before it.

```text
$ cat vars/Containerfile
ARG BASE=alpine:3.20
FROM ${BASE}
RUN echo "before ARG BASE: [$BASE]"
ARG BASE
ARG TARGETARCH GREETING=hello
ENV WHO=world DIR=/srv/${WHO:-nobody}
WORKDIR $DIR
COPY note.txt .
RUN echo "after: [$BASE] $TARGETARCH; $GREETING, $WHO, in $(pwd); ${UNSET:-a default}; proxy $HTTP_PROXY"
$ rustlet build -t ch18-vars --build-arg GREETING=hey --build-arg HTTP_PROXY=http://proxy.example:3128 --build-arg COLOR=blue vars
Sending build context to rustletd  289B
[Warning] one or more build args were not consumed: COLOR
Step 1/8 : FROM alpine:3.20
Step 2/8 : RUN echo "before ARG BASE: [$BASE]"
 ---> Running in f6b4565a60e3
before ARG BASE: []
 ---> Removed intermediate container f6b4565a60e3
 ---> 29cd657a8417
Step 3/8 : ARG BASE
Step 4/8 : ARG TARGETARCH GREETING=hello
Step 5/8 : ENV WHO=world DIR=/srv/${WHO:-nobody}
Step 6/8 : WORKDIR $DIR
Step 7/8 : COPY note.txt .
 ---> 6864fc832cbd
Step 8/8 : RUN echo "after: [$BASE] $TARGETARCH; $GREETING, $WHO, in $(pwd); ${UNSET:-a default}; proxy $HTTP_PROXY"
 ---> Running in 81192edc4f49
after: [alpine:3.20] amd64; hey, world, in /srv/nobody; a default; proxy http://proxy.example:3128
 ---> Removed intermediate container 81192edc4f49
 ---> 29cd657a8417
Successfully built b66ecf484c1d
Successfully tagged ch18-vars:latest
$ rustlet run --rm ch18-vars sh -c 'echo "GREETING=[$GREETING] WHO=[$WHO] HTTP_PROXY=[$HTTP_PROXY]"; pwd'
GREETING=[] WHO=[world] HTTP_PROXY=[]
/srv/nobody
$ rustlet inspect ch18-vars | jq -c '.[0].config.config | {Env, WorkingDir}'
{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","WHO=world","DIR=/srv/nobody"],"WorkingDir":"/srv/nobody"}
```

- Step 1 is `FROM alpine:3.20`: the `FROM` line saw the global `BASE`.
  The first `RUN` didn't: the stage hadn't declared it yet. After `ARG
  BASE` it is the global's value, and `TARGETARCH` is `amd64`.
- `DIR` is `/srv/nobody`, not `/srv/world`: `${WHO:-nobody}` read `WHO`
  as it was before its own `ENV`.
- The `Step` lines show instructions as written (`WORKDIR $DIR`); the
  image's history has them expanded (`ENV WHO=world DIR=/srv/nobody`,
  `WORKDIR /srv/nobody`). `ARG`s leave no history entry, and a `RUN`'s
  doesn't list the values it got.
- `GREETING` and the proxy reached the `RUN`s, not the image. `COLOR`,
  declared nowhere, was warned about.
- `${UNSET:-a default}` in a `RUN` is the shell's, which has the same
  syntax.

A value that must be given:

```text
$ cat req/Containerfile
FROM alpine:3.20
ARG VERSION
ENV APP_VERSION="${VERSION:?give one with --build-arg VERSION=...}"
$ rustlet build req
…
Step 3/3 : ENV APP_VERSION="${VERSION:?give one with --build-arg VERSION=...}"
rustlet: error: Containerfile line 3: ENV: failed to process "\"${VERSION:?give one with --build-arg VERSION=...}\"": VERSION: give one with --build-arg VERSION=...
$ rustlet build --build-arg VERSION=1.2 -t ch18-req req
…
Successfully tagged ch18-req:latest
$ rustlet inspect ch18-req | jq -c '.[0].config.config.Env'
["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","APP_VERSION=1.2"]
```

The quotes matter, and not for the shell: `ENV`'s pairs are split at
whitespace before anything is expanded, so without them the message's
spaces cut the instruction into `APP_VERSION=${VERSION:?give`,
`--build-arg` and `VERSION=...}`, and the parser refuses the second for
having no `=` (BuildKit's parser splits the same way). Where `expand.rs`
departs from BuildKit, it says so: `$1`, `$$` and a final `$` stay as
written (BuildKit reads them as the shell's special parameters, always
empty), the other `${V…}` forms (`#`, `%`, `/`) are refused rather than
applied, and a default keeps its own quoting (`${V:-"a b"}` is one word,
as in a shell).

## 4. A RUN is a container

A `RUN` step runs in an ordinary container of the daemon's, created the
way `rustlet create` creates one, with a config the builder fills in. To
look at one, a step that sleeps:

```text
$ cat step/Containerfile
FROM alpine:3.20
ARG STAGE=demo
ENV APP_HOME=/srv
USER nobody
WORKDIR /tmp
RUN echo "uid=$(id -u) cwd=$(pwd) STAGE=$STAGE APP_HOME=$APP_HOME"; sleep 4
$ rustlet build -t ch18-step step > step.log &
$ rustlet ps -a | grep -E 'NAMES|build-'
CONTAINER ID   IMAGE                  COMMAND                   CREATED                  STATUS                  PORTS   NAMES
3c68e7302b1b   sha256:6bb7acd0a12a…   "/bin/sh -c echo \"ui…"   Less than a second ago   Up Less than a second           build-3635eaf057e4-6
$ rustlet inspect build-3635eaf057e4-6 | jq -c '.[0].config | {image, entrypoint, cmd}'
{"image":"sha256:6bb7acd0a12a…","entrypoint":[],"cmd":["/bin/sh","-c","echo \"uid=$(id -u) cwd=$(pwd) STAGE=$STAGE APP_HOME=$APP_HOME\"; sleep 4"]}
$ rustlet inspect build-3635eaf057e4-6 | jq -c '.[0].config | {env, user, workdir, labels, network, healthcheck: .healthcheck.test}'
{"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","APP_HOME=/srv","STAGE=demo"],"user":"nobody","workdir":"/tmp","labels":{"io.rustlet.build":"3635eaf057e4"},"network":"bridge","healthcheck":["NONE"]}
$ wait; cat step.log
…
Step 6/6 : RUN echo "uid=$(id -u) cwd=$(pwd) STAGE=$STAGE APP_HOME=$APP_HOME"; sleep 4
 ---> Running in 3c68e7302b1b
uid=65534 cwd=/tmp STAGE=demo APP_HOME=/srv
 ---> Removed intermediate container 3c68e7302b1b
 ---> 29cd657a8417
…
```

Field by field (`Build::run`):

- **image**: the image so far, alpine:3.20 with the config of steps 2 to
  5, written to the store as an unnamed image just for this container
  (`write_image`). Nothing names or keeps it, so the next garbage
  collection takes it, unless a cache entry (§7) is the same image.
- **name** `build-<build id>-<step>`, and the **label**
  `io.rustlet.build=<build id>`. They are how the step shows in `ps -a`
  while it runs, as the classic builder's do, and how a daemon that died
  mid-build finds the leftovers at its next start
  (`remove_build_leftovers`: step containers, `builds/<id>`, scratch
  root filesystems).
- **entrypoint** cleared: an image's `ENTRYPOINT` is for its containers,
  not for its build's steps. **cmd**: the `SHELL` and the string, or the
  exec form as it is.
- **env**: the image's `Env`, then the stage's declared `ARG`s with
  values, then the proxy build args. An `ARG` with the name of an `ENV`
  isn't added.
- **user** and **workdir** as the config says so far: `nobody` resolves
  to uid 65534 through the image's own `/etc/passwd`, as for any container
  (chapter 11).
- **network**: the build's, `--network` (`bridge` by default, so `apk
  add` and `pip install` reach the internet through NAT; `host`, `none`
  or a network's name work too, another container's doesn't).
- **healthcheck** `NONE`: a base image's `HEALTHCHECK` doesn't run
  during a step.

Everything else is a container's default: capabilities, seccomp, its own
namespaces, `/etc/resolv.conf` and `hosts` mounted by the daemon. The
image's `VOLUME`s get anonymous volumes, as in any container, so what a
`RUN` writes below a `VOLUME` is lost with them, as with Docker's classic
builder (BuildKit keeps it; `bd_users_volumes_and_healthchecks` checks
the loss).

The step's output comes back as `output` events while it runs, both
streams shown on stdout. If the client goes away, the build kills the
step's container and stops ("the build's client went away"). Exit 0, and
the upper directory becomes a layer (§5); the container is removed either
way, with its anonymous volumes. Anything else fails the build:

```text
$ cat fail/Containerfile
FROM alpine:3.20
RUN echo trying; ls /nowhere; exit 3
RUN echo never
$ rustlet build -t ch18-fail fail; echo "exit $?"
Sending build context to rustletd  69B
Step 1/3 : FROM alpine:3.20
Step 2/3 : RUN echo trying; ls /nowhere; exit 3
 ---> Running in 8246fc44332c
trying
ls: /nowhere: No such file or directory
rustlet: error: step 2: the command '/bin/sh -c echo trying; ls /nowhere; exit 3' returned a non-zero code: 3
exit 1
$ rustlet ps -a | grep -c build-; sudo ls -A /var/lib/rustlet/builds
0
```

No image, no container, no context left. The message is the classic
builder's ("The command … returned a non-zero code"), with the step's
number in front.

## 5. From an upper directory to a layer

Chapter 12 left a container's changes in its overlay's upper directory:
whole files copied up, a character device 0:0 for each deletion,
`trusted.overlay.opaque=y` on a directory deleted and made again. A
layer says the same in the OCI image spec's words, `.wh.<name>` for a
deletion and `.wh..wh..opq` for an opaque directory. `rustlet_image::diff`
translates, the other way round from chapter 11's unpacker. `ch18-trim`
deletes a file of alpine's and remakes one of its directories:

```text
$ cat trim/Containerfile
FROM alpine
RUN rm /etc/motd && rm -r /etc/apk && mkdir /etc/apk && echo new > /etc/apk/only
$ rustlet build -t ch18-trim trim
…
Step 2/2 : RUN rm /etc/motd && rm -r /etc/apk && mkdir /etc/apk && echo new > /etc/apk/only
 ---> Running in 533d30abab26
 ---> Removed intermediate container 533d30abab26
 ---> d98159f5bbdc
Successfully built febcd3cb0392
Successfully tagged ch18-trim:latest
$ mkdir trim-saved && cd trim-saved && rustlet save ch18-trim | tar -x
$ jq -r '.[0].Layers[-1]' manifest.json
blobs/sha256/d98159f5bbdc79448edf6f4820e14f92eab393e355d24aa5445e95324a295693
$ tar -tvzf blobs/sha256/d98159f5bbdc…
drwxr-xr-x 0/0               0 2026-10-04 17:42 etc/
drwxr-xr-x 0/0               0 2026-10-04 17:42 etc/apk/
-rw------- 0/0               0 1970-01-01 00:00 etc/apk/.wh..wh..opq
-rw-r--r-- 0/0               4 2026-10-04 17:42 etc/apk/only
-rw------- 0/0               0 1970-01-01 00:00 etc/.wh.motd
```

That is the whole layer: 191 bytes gzipped, 4,096 as a tar (five 512-byte
headers, one block of data, two zero blocks). The rules (`diff.rs`):

- **Deterministic.** Depth first, each directory's entries in byte order
  of their names in upper: `etc/apk/` comes before `etc/.wh.motd`, whose
  name in upper is `motd`. A directory's entry comes first, then its
  opaque marker, then its contents. Ustar headers with whole-second times
  and no user or group names; PAX records, sorted, for what a header
  can't hold (names or link targets over 100 bytes, ids over 2097151,
  sizes over 8 GiB, attributes). The markers have no metadata of their
  own: empty, `0600`, 0:0, from the epoch. The same upper directory always
  makes the same bytes.
- **Never followed.** Each entry is examined from its parent's fd with
  `AT_SYMLINK_NOFOLLOW`; a file is opened `O_NOFOLLOW | O_NONBLOCK`,
  checked to be the inode examined, and must still have its size when
  read, or the commit fails rather than write a wrong header. FIFOs are
  never opened.
- **Attributes** are kept as PAX `SCHILY.xattr.<name>` records, except
  overlay's own (`trusted.overlay.*`, `user.overlay.*`: the opaque mark,
  `origin`, `impure`, `uuid`), which are read only to find `opaque=y`.
- **Hard links** among the container's files stay hard links: the first
  name written is the file, later ones are links to it.
- **Left out**: `work/`, device nodes and sockets, any entry the
  container itself named `.wh.<something>` (in a layer that name is a
  whiteout), and the mount points, with the directories that only held
  them if they are unchanged (below).

**Whiteouts are hard links.** A container that deletes two files:

```text
$ rustlet run --name ch18-box -e GREETING=hi -w /root alpine sh -c 'echo hello > /hello; rm /etc/motd /etc/issue'
$ ID=$(rustlet inspect ch18-box | jq -r '.[0].id')
$ sudo sh -c "cd /var/lib/rustlet/containers/$ID && stat -c '%i %h %F %n' upper/etc/motd upper/etc/issue && ls -lia work/work && find upper | sort"
4460185 3 character special file upper/etc/motd
4460185 3 character special file upper/etc/issue
total 8
4460176 d--------- 2 root root 4096 Oct  4 13:42 .
4460174 drwx------ 3 root root 4096 Oct  4 13:42 ..
4460185 c--------- 3 root root 0, 0 Oct  4 13:42 #21f
upper
upper/etc
upper/etc/issue
upper/etc/motd
upper/etc/resolv.conf
upper/hello
```

The two whiteouts are one inode with three names. Overlay keeps one
whiteout of its own in `work/work` (`#21f`) and makes every other one a
hard link to it, to save inodes. That link count is overlay's
bookkeeping, not something the container did, so the diff never treats a
whiteout as a link. Written as tar links, `etc/.wh.motd` would be a link
to `etc/.wh.issue`: two deletions tied together for no reason, and a
plain `tar -x` of the layer would make the two markers one file. §9
commits this container, and its layer has two markers of their own:

```text
$ tar -tvzf <ch18-committed's last layer>
drwxr-xr-x 0/0               0 2026-10-04 17:42 etc/
-rw------- 0/0               0 1970-01-01 00:00 etc/.wh.issue
-rw------- 0/0               0 1970-01-01 00:00 etc/.wh.motd
-rw-r--r-- 0/0               6 2026-10-04 17:42 hello
```

**Mount points are left out.** `upper/etc/resolv.conf` is the empty file
the runtime made to bind-mount the daemon's resolver configuration over
([chapter 16](16-dns.md)): alpine has `/etc/hosts` and `/etc/hostname`,
but no `/etc/resolv.conf`. It was never the container's to change, and
what is below a mount point was hidden by the mount. The last run's
`config.json` lists every mount's destination (`/proc`, `/dev`, `/etc/hosts`,
a volume's target…), and the diff leaves those paths out, with everything
below them, matched as written (not through the image's symlinks).

That leaves the directories that hold them. Overlay copied `/etc` up to
make `resolv.conf` in it; for a volume at `/var/lib/app/data`, the runtime
makes `app` and `data` where the image has neither. A directory that held
nothing but mount points (and directories of nothing else) is left out
too, if it is **unchanged** (`Differ::finish_dir`, `as_made`): it has the
mode, owner and extended attributes that the image's layers show at its
path, or, where they show nothing, it is `0755`, root's and without
attributes, as the runtime makes one. Its modification time doesn't count:
making the mount point in it changed that. The daemon passes the image's
layer directories, top first (`DiffOptions::lowers`), and `below` reads
them as overlay merges them: the first layer that has the path decides,
and a whiteout or an opaque directory hides the layers under it. A copy-up
keeps mode, owner and attributes, so `/etc`, copied up for `resolv.conf`,
is unchanged. A `chown` or `chmod` of such a directory is the container's
change, and the directory stays. ch18-vars's two `RUN`s in §3 wrote no
file; its layers above alpine's, saved after §7 had built it again:

```text
$ mkdir vars-saved && cd vars-saved && rustlet save ch18-vars | tar -x
$ for l in $(jq -r '.[0].Layers[1:][]' manifest.json); do echo "${l:13:12}…:"; tar -tvzf $l; done
29cd657a8417…:
cb35ea7385d4…:
drwxr-xr-x 0/0               0 2026-10-04 17:45 srv/
drwxr-xr-x 0/0               0 2026-10-04 17:45 srv/nobody/
-rw-rw-r-- 0/0               7 2026-10-04 17:42 srv/nobody/note.txt
29cd657a8417…:
```

The `COPY`'s layer has `note.txt` and the directories it made for it. Each
`RUN`'s is empty, an archive of nothing but its two zero blocks: 1,024
bytes, 41 gzipped, diff ID `5f70bf18a086…`. Every `RUN` of this chapter
that wrote no file printed that layer, `29cd657a8417` (both of §2's, both
of §3's, §4's): the same bytes each time. A step that changes a directory
holding a mount point:

```text
$ cat keep/Containerfile
FROM alpine
VOLUME /var/lib/app/data
RUN chown nobody /var/lib/app
RUN true
$ rustlet build -t ch18-keep keep
…
Step 3/4 : RUN chown nobody /var/lib/app
 ---> Running in deba00aae5d7
 ---> Removed intermediate container deba00aae5d7
 ---> 57ee9443a820
Step 4/4 : RUN true
 ---> Running in b421288a4a85
 ---> Removed intermediate container b421288a4a85
 ---> 29cd657a8417
Successfully built b6829486aa18
Successfully tagged ch18-keep:latest
$ mkdir keep-saved && cd keep-saved && rustlet save ch18-keep | tar -x
$ for l in $(jq -r '.[0].Layers[1:][]' manifest.json); do echo "${l:13:12}…:"; tar -tvzf $l; done
57ee9443a820…:
drwxr-xr-x 0/0               0 2026-09-17 17:32 var/
drwxr-xr-x 0/0               0 2026-10-04 17:42 var/lib/
drwxr-xr-x 65534/0           0 2026-10-04 17:42 var/lib/app/
29cd657a8417…:
$ rustlet inspect ch18-keep | jq -c '.[0].config.rootfs.diff_ids | map(.[7:19])'
["74d97c428c51","8d26843554d8","5f70bf18a086"]
$ rustlet run --rm ch18-keep stat -c '%U %a %n' /var/lib/app /var/lib/app/data /etc
nobody 755 /var/lib/app
root 755 /var/lib/app/data
root 755 /etc
```

The `chown`'s layer has `var/lib/app/`, now nobody's (65534), and the two
directories above it, which the diff writes before anything in them; the
volume's target and `etc/` are gone. In the `RUN true`, the runtime made
`data` in `/var/lib/app` again, and overlay copied `/var/lib/app` up as
the layer below has it, nobody's: unchanged, so left out, and the layer is
empty. `bd_changes_beside_mount_points_stay_and_mount_points_go` checks
both, with a `chmod 700 /etc` besides.

Docker's classic builder keeps such paths out another way: its step
containers, like all of Docker's on a graph driver, get an "init" layer of
their own, between the image and the container's writable layer, holding
what the runtime mounts over in every container (`/etc/resolv.conf`,
`/etc/hosts`, `/etc/hostname`, `/dev/pts`, `/dev/shm`, `/proc`, `/sys`…),
so those never reach
the container's changes. Rustlets' containers have no init layer, so the
diff compares with the layers below instead. What becomes of an empty
diff differs too: Docker's commit, which its classic builder's steps go
through, adds no layer for it (`image.NewChildImage` checks for the diff
ID `5f70bf18a086…`) and marks the history entry `empty_layer`; Rustlets
adds the empty layer.

**Remapped owners are mapped back.** A `--userns=remap` container's upper
directory holds host ids (chapter 12 §9). `unmap_remap` turns host
1000000 + *n* back into *n*, and anything outside the range into 65534,
the id the container saw as `nobody`; the ids inside a version 3
`security.capability` and inside POSIX ACLs too. §9 shows it.

The archive is gzipped into the store as it is written (`commit_layer`,
through a `BlobWriter`: a blob whose digest is known only at its end,
renamed into `blobs/sha256/` under it then). The uncompressed archive's
digest is the layer's diff ID. Every `RUN`, `COPY` and `ADD` and every
`commit` goes through it.

## 6. COPY and ADD

`COPY` and `ADD` run no process. The daemon mounts an overlay of the
image so far with an empty upper directory, under
`containers/build-<id>-<step>-to` (and, for `--from`, the source's under
`…-from`), writes into it with `rustlet_image::copy`, unmounts it, and
makes a layer of the upper directory as §5 does, with nothing to skip.
Both sides are untrusted, each in its own way, and the daemon is root: the
destination is an image's tree, whose symlinks its author chose, and the
source is a user's directory, whose symlinks may point anywhere on the
host. So, as in chapter 11's unpacker, both are resolved **inside their
root** with `openat2(RESOLVE_IN_ROOT)`:

```text
$ cat copy/Containerfile
FROM alpine
RUN mkdir -p /srv/data && ln -s /srv/data /app
COPY --chown=nobody:nogroup --chmod=640 f.txt /app/
COPY hostpw /hostpw-copy
COPY site/ /var/www/
ADD data.tar.gz /opt/
RUN ls -l /app/ /srv/data/; cat /hostpw-copy; find /var/www /opt | sort
$ ls -l copy; cat copy/etc/passwd; tar -tvzf copy/data.tar.gz
total 20
-rw-rw-r-- 1 james james  251 Oct  4 13:43 Containerfile
-rw-rw-r-- 1 james james  162 Oct  4 13:43 data.tar.gz
drwxrwxr-x 2 james james 4096 Oct  4 13:43 etc
-rw-r--r-- 1 james james    7 Oct  4 13:43 f.txt
lrwxrwxrwx 1 james james   11 Oct  4 13:43 hostpw -> /etc/passwd
drwxrwxr-x 3 james james 4096 Oct  4 13:43 site
the context's own etc/passwd
drwxrwxr-x james/james       0 2026-10-04 13:43 conf/
-rw-rw-r-- james/james      10 2026-10-04 13:43 conf/app.conf
$ rustlet build -t ch18-copy copy
…
Step 3/7 : COPY --chown=nobody:nogroup --chmod=640 f.txt /app/
 ---> 5f2956d0fd77
Step 4/7 : COPY hostpw /hostpw-copy
 ---> a12a4b4fb1b2
Step 5/7 : COPY site/ /var/www/
 ---> fa704afe5f0c
Step 6/7 : ADD data.tar.gz /opt/
 ---> 909d16b5e3a5
Step 7/7 : RUN ls -l /app/ /srv/data/; cat /hostpw-copy; find /var/www /opt | sort
 ---> Running in dd3db10b7d89
/app/:
total 4
-rw-r-----    1 nobody   nogroup          7 Oct  4 17:43 f.txt

/srv/data/:
total 4
-rw-r-----    1 nobody   nogroup          7 Oct  4 17:43 f.txt
the context's own etc/passwd
/opt
/opt/conf
/opt/conf/app.conf
/var/www
/var/www/css
/var/www/css/style.css
/var/www/index.html
…
$ rustlet run --rm ch18-copy ls -ln /opt/conf
total 4
-rw-rw-r--    1 1000     1000            10 Oct  4 17:43 app.conf
$ ls -l copy2; rustlet build copy2
total 4
-rw-rw-r-- 1 james james 31 Oct  4 13:43 Containerfile
lrwxrwxrwx 1 james james 11 Oct  4 13:43 hostshadow -> /etc/shadow
Sending build context to rustletd  31B
Step 1/2 : FROM alpine
Step 2/2 : COPY hostshadow /x
rustlet: error: step 2: source "hostshadow": no such file or directory
```

- **The destination `/app/`** is a symlink to `/srv/data`, an absolute
  path: resolved inside the root filesystem, it is the *image's*
  `/srv/data`, whatever the host has there. Missing directories are made
  one component at a time, each relative to the fd of the one before,
  `0755` and owned by `--chown`'s owner; a component that is a file, or a
  symlink to nothing, is an error, as for `mkdir -p` (BuildKit makes the
  directory a dangling symlink names, inside the image).
- **The source `hostpw`** is a symlink to `/etc/passwd`. Resolved inside
  the context, it is the context's own `etc/passwd`. `hostshadow` names a
  file the context doesn't have, so the step fails, and the host's
  `/etc/shadow` is never opened. The source named is followed, within its
  root; what is below it never is: a symlink inside a copied directory
  is copied as a symlink.
- **Docker's rules for what goes where**: a directory is copied by its
  contents (`site/` into `/var/www/`, merging with what is there); a file
  goes into the destination when that ends in `/` or is an existing
  directory, else onto the destination's path; several sources need a
  directory; sources may hold wildcards, matched per component as Go's
  `filepath.Match` matches them, and one that matches nothing is an
  error. A destination is absolute or relative to `WORKDIR`.
- **Metadata**: copies keep their source's mode, modification time,
  attributes (overlay's excepted) and hard links among themselves, and are
  owned by 0:0. `--chown=user[:group]` looks names up in the destination's
  own `/etc/passwd` and `/etc/group` (alpine's `nobody` is 65534, its
  `nogroup` 65533), and without a group takes the user's number again, as
  Docker does. `--chmod` replaces the mode of every file and directory
  copied.
- **`ADD`** extracts a source that is a tar archive, plain, gzip or zstd,
  told by its content rather than its name: the first 512 bytes,
  decompressed if a magic number says so, must be a tar header with a
  checksum that adds up. It goes through chapter 11's unpacker in its
  plain mode, confined to the destination directory, and keeps the
  archive's owners and modes (`app.conf` is 1000:1000, as on my side).
  bzip2 and xz archives are copied as files, and URLs and git
  repositories are refused before anything runs ("ADD from a URL is not
  supported: use RUN with curl or wget").

Told by content, so a layer blob of `busybox`, saved and stripped of its
name, makes an image from scratch:

```text
$ rustlet save busybox | tar -x -C bb-saved; jq -c '.[0].Layers' bb-saved/manifest.json
["blobs/sha256/37bb94b0940bd40749eced2b83080d1b9912f281ac499a7247e4ce7c385792cc"]
$ cp bb-saved/blobs/sha256/37bb94b0940b… scratch/rootfs; cat scratch/Containerfile
FROM scratch
ADD rootfs /
CMD ["sh", "-c", "echo from scratch: $(ls / | wc -l) entries in /; busybox | head -1"]
$ rustlet build -t ch18-scratch scratch
Sending build context to rustletd  2.226MB
Step 1/3 : FROM scratch
Step 2/3 : ADD rootfs /
 ---> 61bedd43634e
Step 3/3 : CMD ["sh", "-c", "echo from scratch: $(ls / | wc -l) entries in /; busybox | head -1"]
Successfully built a19719405f59
Successfully tagged ch18-scratch:latest
$ rustlet run --rm ch18-scratch
from scratch: 12 entries in /
BusyBox v1.38.0 (2026-05-13 02:21:49 UTC) multi-call binary.
```

`FROM scratch` is the empty filesystem, no layers, and its config starts
empty. The new layer's diff ID isn't busybox's own (`d64532c020e2…` and
`6cd030ace585…`): it was made from an upper directory, by §5's rules,
not copied.

**The digest.** Before a `COPY` from the context runs, `copy::digest`
hashes what it would copy, with the same matching: a version, the
destination, the owner (0:0 at this point: the builder puts `--chown`, as
written, into the key itself), `--chmod` and whether it is an `ADD`; then
for each source its path, and for each entry in the walk's order its
kind, its path, the mode its copy gets, and its size and the SHA-256 of
its contents, a symlink's target, or for a later name of an inode with
several, its first name. Fields are length-prefixed, so no two lists hash
alike. The sources' owners and times aren't in it: the copy sets owners
itself, and a touched file copies the same. That digest goes into the
step's cache key (§7).

## 7. The build cache

The first build of this chapter wasn't §1's. It was the same command
without `--no-cache`:

```text
$ rustlet build -t ch18-hits examples/hits
Sending build context to rustletd  1.9kB
Step 1/9 : FROM python:3-slim
Step 2/9 : WORKDIR /app
Step 3/9 : RUN pip install --no-cache-dir --root-user-action=ignore "redis>=5,<6"
 ---> Using cache
 ---> cef4417235b1
Step 4/9 : COPY app.py .
 ---> Using cache
 ---> ea2dc6184a94
…
Successfully built 987352486f0a
Successfully tagged ch18-hits:latest
```

`987352486f0a` is `hits-web`, the image `rustlet compose build` had built
from the same files a minute before. Another client, the same steps, and
this build ran nothing and made the very same image.

**The chain of keys.** Every step has a key, and a step that changes
files looks its key up before it runs. A stage's key starts at its base:
`image:<manifest digest>` for an image (its name doesn't count, its
content does: a `--pull` that finds a newer python:3-slim changes every
key after it), `scratch`, or the key of the stage it starts from. Each
instruction extends it: `next_key` is the SHA-256 of the key so far, a
newline, and the step:

| step | after the key so far |
|---|---|
| config only (`ENV`, `WORKDIR`, `CMD`…) | its history line, expanded (`EXPOSE 8000/tcp`) |
| `ARG` | `ARG` and each name with its value now (`ARG TARGETARCH=amd64 GREETING=hey`) |
| `RUN` | its history line, the command as a JSON array, the stage's `ARG` values |
| `COPY`, `ADD` | its history line, `--chown` as written, and its source: `copy::digest` of the context's files, `stage:<chain ID>` of a source stage's top layer, `image:<manifest digest>` of a source image |

So a key stands for everything before it. Step 3 of §1, by hand:

```text
$ M=$(rustlet inspect python:3-slim | jq -r '.[0].id')
$ k1=$(printf '%s\n%s' "image:$M" 'WORKDIR /app' | sha256sum | cut -c1-64)
$ cmd='pip install --no-cache-dir --root-user-action=ignore "redis>=5,<6"'
$ printf '%s\n%s\n%s\n' "$k1" "RUN /bin/sh -c $cmd" "$(jq -cn --arg c "$cmd" '["/bin/sh","-c",$c]')" | sha256sum
c4ea20fbdf5cf52e85f3032d129f51407cbe2346e21eed92e07dbc5e3d197818  -
```

(The step's text ends with the `ARG` values, one `NAME=value` a line,
after a newline; with none, it ends with that newline.) That key is in
the store:

```text
$ cargo xtask images cat content/index.json | jq -c '.manifests[] | select(.annotations["io.rustlet.build.cache-key"]) | [.annotations["io.rustlet.build.cache-key"][:12], .digest[7:19]]'
…
["10acfebaa4c7","a5ed9dbd664a"]
…
["c4ea20fbdf5c","6bf25dbf7444"]
…
$ for m in a5ed9dbd664a… 6bf25dbf7444…; do cargo xtask images cat content/blobs/sha256/$m | jq -c '[.layers[].digest[7:19]]'; done
["6b37362b3da7","5c21337b2448","8def98961a31","ad232412d02e","74750aeebec3","d13db2413152"]
["6b37362b3da7","5c21337b2448","8def98961a31","ad232412d02e","74750aeebec3"]
```

(18 entries by then, most of them from this chapter's other builds; the
full digests went into the loop.) A cache entry is an **image**: when a
`RUN`, `COPY` or `ADD` has run, the image so far is written and listed in
`index.json` with the annotation `io.rustlet.build.cache-key` instead of
a name. The
`RUN`'s entry has python:3-slim's four layers and `74750aeebec3`; the
`COPY`'s has one more. `images` never lists them, and like every
`index.json` entry they are garbage-collection roots: they keep their
layers. A key that is found counts only if the entry's layers are this
build's plus one (`Build::cached`); then that one layer is taken, with its
history entry, and nothing runs. With `--no-cache` nothing is looked up,
but every result is still recorded, replacing the entry with the same
key: §1's build replaced compose's. What is not in any key: the build's
network, the proxy args, and, for `RUN`, the files. As with Docker, the
command string is the step; the builder never asks what `apt-get update`
would fetch today.

**The same image, twice.** After §1:

```text
$ rustlet build -t ch18-hits examples/hits
…
Step 3/9 : RUN pip install --no-cache-dir --root-user-action=ignore "redis>=5,<6"
 ---> Using cache
 ---> 74750aeebec3
Step 4/9 : COPY app.py .
 ---> Using cache
 ---> d13db2413152
…
Successfully built e48844cda9f8
Successfully tagged ch18-hits:latest
$ rustlet inspect e48844cda9f8 | jq -r '.[0].config.history[-8:][] | "\(.created)  \(.empty_layer // false)  \(.created_by[0:50])"'
2026-09-19T01:03:01.901971922Z  true  WORKDIR /app
2026-10-04T17:41:42.050677884Z  false  RUN /bin/sh -c pip install --no-cache-dir --root-u
2026-10-04T17:41:43.138680602Z  false  COPY app.py .
2026-10-04T17:41:43.138680602Z  true  ENV REDIS_HOST=redis PORT=8000
2026-10-04T17:41:43.138680602Z  true  EXPOSE 8000/tcp
2026-10-04T17:41:43.138680602Z  true  HEALTHCHECK --interval=5s --timeout=3s --start-per
2026-10-04T17:41:43.138680602Z  true  USER nobody
2026-10-04T17:41:43.138680602Z  true  CMD ["python","app.py"]
```

The same image id, not merely the same layers. That needs care.
Config-only steps leave history entries and the config's `created`; dated
"now", they would make a new config at every build, so a new manifest and
a new id. They are dated as the stage's last filesystem change instead:
`WORKDIR /app` has python:3-slim's last date, the `RUN` and the `COPY`
the times they really ran (from the cache entries), everything after
the `COPY` its time, and so does the image's `created`. Docker's classic
builder gets the same result another way: there, config-only steps make
intermediate images too, and a cached step reuses them.

**What makes a step run again.** Touching `app.py` doesn't; changing it
does, from its `COPY` on, while the `RUN` before it stays cached:

```text
$ cp -a examples/hits $S/hits && touch $S/hits/app.py && rustlet build -t ch18-hits $S/hits
…
Step 4/9 : COPY app.py .
 ---> Using cache
 ---> d13db2413152
…
Successfully built e48844cda9f8
$ sed -i 's/Hello from Rustlets!/Hello from chapter 18!/' $S/hits/app.py && rustlet build -t ch18-hits $S/hits
Sending build context to rustletd  1.902kB
…
Step 3/9 : RUN pip install --no-cache-dir --root-user-action=ignore "redis>=5,<6"
 ---> Using cache
 ---> 74750aeebec3
Step 4/9 : COPY app.py .
 ---> 8a8e70bc36d9
…
Successfully built a33c6496e4ee
```

As with Docker's checksums for `COPY`, contents count and modification
times don't. A cached `COPY` gives back the layer it made then, old
modification time included.

**A build arg** is where Rustlets is stricter than Docker. §3's build
again, with another `GREETING` (and another proxy):

```text
$ rustlet build -t ch18-vars --build-arg GREETING=hi --build-arg HTTP_PROXY=http://other.example:3128 vars
…
Step 2/8 : RUN echo "before ARG BASE: [$BASE]"
 ---> Using cache
 ---> 29cd657a8417
Step 3/8 : ARG BASE
Step 4/8 : ARG TARGETARCH GREETING=hello
Step 5/8 : ENV WHO=world DIR=/srv/${WHO:-nobody}
Step 6/8 : WORKDIR $DIR
Step 7/8 : COPY note.txt .
 ---> cb35ea7385d4
Step 8/8 : RUN echo "after: [$BASE] $TARGETARCH; $GREETING, $WHO, in $(pwd); ${UNSET:-a default}; proxy $HTTP_PROXY"
 ---> Running in 02d98100af35
after: [alpine:3.20] amd64; hi, world, in /srv/nobody; a default; proxy http://other.example:3128
…
```

The `RUN` before the `ARG`s was cached, the proxy change notwithstanding.
Docker's reference says of a changed build arg that "a cache miss occurs
upon its first usage, not its definition", and a `RUN` uses every `ARG`
declared before it, so in Docker step 8 would have run again and step 7
come from the cache. Here the `ARG` step's key holds the values it gives,
so everything after it misses, the `COPY` too.

**Holding and forgetting.** A build holds garbage collection off from its
start to its name (`Images::pin`): the images it writes for its steps and
its cache entries are in the store before anything names the result. `rmi`
waits for running builds, as it waits for pulls. `rustlet builder prune`
forgets the cache: it asks first (`-f` doesn't, and with no terminal to
ask on it refuses without `-f`), removes every cache entry from
`index.json` (Docker's `builder prune --all`: none is kept as in use), and
collects garbage, which deletes the layers, configs and snapshots that
only the cache kept. It prints the forgotten manifests under "Deleted build
cache objects:", then "Total reclaimed space: 0B", since the space isn't
counted. The next build runs every step.

## 8. Multi-stage builds

A Containerfile can hold several `FROM`s, each starting a **stage**. A
build makes its **target**, the last stage unless `--target` names one
(by name or index), and only the stages the target needs: the one its
`FROM` names, and those its `COPY --from`s read, recursively. They are
built in the file's order; a stage nobody needs is skipped, as BuildKit
skips it (the classic builder built every stage before the target).

```text
$ cat multi/Containerfile
FROM alpine AS build
RUN mkdir /out && printf '#!/bin/sh\necho "hello from a two-stage build"\n' > /out/hello && chmod 755 /out/hello && echo junk > /junk

FROM alpine AS test
RUN echo "this stage is never built"

FROM busybox
COPY --from=build /out/hello /usr/local/bin/hello
CMD ["hello"]
$ rustlet build -t ch18-multi multi
Sending build context to rustletd  291B
Step 1/5 : FROM alpine AS build
Step 2/5 : RUN mkdir /out && printf '#!/bin/sh\necho "hello from a two-stage build"\n' > /out/hello && chmod 755 /out/hello && echo junk > /junk
 ---> Running in b62873f3bc1f
 ---> Removed intermediate container b62873f3bc1f
 ---> 633e52e5a7e3
Step 3/5 : FROM busybox
Step 4/5 : COPY --from=build /out/hello /usr/local/bin/hello
 ---> c79ee7828bfa
Step 5/5 : CMD ["hello"]
Successfully built f31f68029aa4
Successfully tagged ch18-multi:latest
$ rustlet run --rm ch18-multi; rustlet run --rm ch18-multi ls /junk /out
hello from a two-stage build
ls: /junk: No such file or directory
ls: /out: No such file or directory
$ rustlet build --target build -t ch18-multi-build multi
…
Step 1/2 : FROM alpine AS build
Step 2/2 : RUN mkdir /out && …
 ---> Using cache
 ---> 633e52e5a7e3
Successfully built 1eb4ae16aa42
Successfully tagged ch18-multi-build:latest
$ rustlet run --rm ch18-multi-build cat /junk
junk
```

Five steps, not seven: `test` wasn't counted, let alone built. The final
image is busybox's layer and one more, the file `COPY --from` took;
nothing else of `build` reaches it, its `/junk` and its alpine included.

- **`COPY --from=<stage>`** names an earlier stage, by name or index. The
  daemon writes that stage's state as an image, mounts it under
  `containers/build-<id>-<step>-from`, and copies from the mounted tree
  with §6's rules, so the source is resolved inside *that* root. Its
  cache key is `stage:<chain ID of the stage's top layer>`, which
  identifies the filesystem exactly. A stage copies only from earlier
  ones.
- **`COPY --from=<image>`** reads an image, pulled if missing, as a
  `FROM` would be; its key is the image's manifest digest.
- **`FROM <stage>`** starts a stage from an earlier one: its layers,
  config, history and cache key carry on, so the cache chain does too. A
  stage name is matched before an image name, in `FROM` as in `--from`
  (`--from=build` above is the stage, not an image named `build`),
  case-insensitively. `--from` is expanded with the global `ARG`s
  when the build is planned, to know which stages are needed, so a
  `--from` that only a stage's own `ARG` makes a stage's name fails
  ("stage 1 isn't built before this one") unless that stage was needed
  anyway. A stage can't be named `scratch`, which is always the empty
  image (Docker only warns, then reads `FROM scratch` as that stage).
- **`ONBUILD`** in a stage goes into its config, and stays there in an
  image of that stage (`--target`). A stage built `FROM` it doesn't keep
  the triggers: as with a base image's, they aren't run (a warning says
  so: `[Warning] base's ONBUILD triggers are not run`, for a stage named
  `base`), and its config drops them, so an image built from the result
  never sees them as its own.

## 9. commit

`rustlet commit` makes an image of one container: its image's layers, one
more for its changes, and a config of its image's with the container's
own options over it. ch18-box, from §5, is stopped:

```text
$ rustlet commit -m "hello added, motd gone" --change 'CMD ["sh", "-c", "cat /hello; echo GREETING=$GREETING; pwd; ls /etc/motd"]' ch18-box ch18-committed
sha256:58a3003be74f9a1ef647196e268122562c357d0822223c0a9bad58feec56f0a4
$ rustlet run --rm ch18-committed
hello
GREETING=hi
/root
ls: /etc/motd: No such file or directory
$ rustlet inspect ch18-committed | jq -c '.[0].config.config | {Env, Cmd, WorkingDir}'
{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GREETING=hi"],"Cmd":["sh","-c","cat /hello; echo GREETING=$GREETING; pwd; ls /etc/motd"],"WorkingDir":"/root"}
$ rustlet inspect ch18-committed | jq -c '.[0].config.history[-1]'
{"comment":"hello added, motd gone","created":"2026-10-04T17:45:34.280835915Z","created_by":"rustlet commit"}
```

- **The changes** are the upper directory as it is now, through §5's
  rules, the mount points of the container's last run left out. A running
  container is frozen while they are read (its `cgroup.freeze`, through
  the shim, without its state changing to `paused`), so that no file is
  caught half written; `--pause=false` doesn't freeze it. A stopped one
  needs nothing: its upper directory outlives the run.
- **The config** is the image's, with the container's options applied as
  the instructions that would give the same, as Docker does: `-e` over
  `Env` (`GREETING=hi`), `--entrypoint` (which drops the image's `Cmd`, as
  it does at `run`), its command, `-u`, `-w` (relative to `/`, as at run:
  `WorkingDir` `/root`), labels, its published ports as `ExposedPorts`,
  its stop signal and healthcheck options. Then each `--change`, parsed and
  applied as a Containerfile line would be (`CMD`, `ENTRYPOINT`, `ENV`,
  `EXPOSE`, `LABEL`, `ONBUILD`, `USER`, `VOLUME`, `WORKDIR`, `STOPSIGNAL`,
  `HEALTHCHECK`: the instructions Docker's commit takes). The history
  gains one entry, with `-m` as its comment and `-a` as its author.

Without a name, the image is **kept**, unnamed:

```text
$ rustlet commit ch18-box
sha256:43c8f937772a42c010a082f7ae343037cff506581bf1d6cae2b3efa6c766397c
$ rustlet images | head -3
REPOSITORY         TAG        IMAGE ID       CREATED                  SIZE
<none>             <none>     43c8f937772a   Less than a second ago   3.85MB
ch18-committed     latest     58a3003be74f   18 seconds ago           3.85MB
$ cargo xtask images cat content/index.json | jq -c '.manifests[] | select(.annotations["io.rustlet.image.kept"]) | {digest: .digest[0:19], annotations}'
{"digest":"sha256:43c8f937772a","annotations":{"io.rustlet.image.kept":"2026-10-04T17:45:52Z"}}
$ rustlet rmi 43c8f937772a
Deleted: sha256:10cc0ce7fbf5c0dd8c990a62d5af230cc7de313d65a1655b03ddf4254532eec8
Deleted: sha256:43c8f937772a42c010a082f7ae343037cff506581bf1d6cae2b3efa6c766397c
```

`index.json` holds three kinds of entries now: names, kept images
(`io.rustlet.image.kept`, with when: a build without `-t`, a `commit` or
a `load` without a name) and cache entries. A kept image is listed as
`<none>`, stays until `rmi` removes it by its id, and stops being kept
once `tag` names it. `rmi` deleted its config and its manifest; the layer
stayed, since `ch18-committed` has the very same one: the upper directory
hadn't changed, and the diff is deterministic.

A `--userns=remap` container, whose upper directory holds host ids:

```text
$ rustlet run --name ch18-remap --userns remap alpine sh -c 'adduser -D -u 4321 u && su u -c "touch /tmp/by-u" && touch /by-root && stat -c "%u:%g %n" /by-root /tmp/by-u'
0:0 /by-root
4321:4321 /tmp/by-u
$ sudo stat -c '%u:%g %n' /var/lib/rustlet/containers/9cf9bb0197f1…/upper/{by-root,tmp/by-u,etc/passwd}
1000000:1000000 /var/lib/rustlet/containers/9cf9bb0197f1…/upper/by-root
1004321:1004321 /var/lib/rustlet/containers/9cf9bb0197f1…/upper/tmp/by-u
1000000:1000000 /var/lib/rustlet/containers/9cf9bb0197f1…/upper/etc/passwd
$ rustlet commit ch18-remap ch18-unshifted
sha256:79d84f9d28b7…
$ rustlet run --rm ch18-unshifted stat -c '%u:%g %n' /by-root /tmp/by-u /etc/passwd /home/u
0:0 /by-root
4321:4321 /tmp/by-u
0:0 /etc/passwd
4321:4321 /home/u
```

The image has the ids the container saw, which is what any container of
it, remapped or not, must see.

## 10. save and load

`rustlet save` writes images as one tar archive, which is an **OCI image
layout**: the store's own format (chapter 11), holding only what was asked
for.

```text
$ rustlet save -o committed.tar ch18-committed; tar -tvf committed.tar
-rw-r--r-- 0/0              30 1970-01-01 00:00 oci-layout
-rw-r--r-- 0/0             370 1970-01-01 00:00 index.json
-rw-r--r-- 0/0             300 1970-01-01 00:00 manifest.json
-rw-r--r-- 0/0             870 1970-01-01 00:00 blobs/sha256/3ae6ba60dbb5…
-rw-r--r-- 0/0             559 1970-01-01 00:00 blobs/sha256/58a3003be74f…
-rw-r--r-- 0/0             168 1970-01-01 00:00 blobs/sha256/62814c948b16…
-rw-r--r-- 0/0         3849738 1970-01-01 00:00 blobs/sha256/e2de96513ba9…
$ cd trim-saved; jq . index.json; jq . manifest.json
{
  "manifests": [
    {
      "annotations": {
        "io.containerd.image.name": "docker.io/library/ch18-trim:latest",
        "org.opencontainers.image.ref.name": "latest"
      },
      "digest": "sha256:febcd3cb0392…",
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "size": 559
    }
  ],
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "schemaVersion": 2
}
[
  {
    "Config": "blobs/sha256/23dc2dc37d12…",
    "Layers": [
      "blobs/sha256/e2de96513ba9…",
      "blobs/sha256/d98159f5bbdc…"
    ],
    "RepoTags": [
      "ch18-trim:latest"
    ]
  }
]
```

- **Blobs** are the manifest, the config and the layers, each once (the
  config; the manifest, whose digest is the image's id; the commit's
  layer, 168 bytes; alpine's layer), streamed from the store and checked
  against their digests on the way out.
- **`index.json`** names each image as Docker 25's `docker save` does:
  `io.containerd.image.name` holds the full name and
  `org.opencontainers.image.ref.name` the tag, which is what the OCI spec
  meant it for (the store's own `index.json` puts the full name there).
  An image saved by id has no annotations.
- **`manifest.json`** is Docker's older format's index, beside it, so that
  a `docker load` from before 25 reads the same archive (`RepoTags` in
  Docker's short form).
- **Fixed order and headers**: the three metadata files, then the blobs
  by digest, every entry `0644`, 0:0, dated 0. The same images make the
  same archive, in whatever order they are asked for:

```text
$ rustlet save ch18-trim alpine | sha256sum; rustlet save alpine ch18-trim | sha256sum
4a42d7405f28973ef53ac0e27905678a3608f06bc112ad08b6a1e154ddf05418  -
4a42d7405f28973ef53ac0e27905678a3608f06bc112ad08b6a1e154ddf05418  -
```

The archive streams out as it is written
([`pipe.rs`](../../crates/rustletd/src/pipe.rs)): a blocking thread writes
it into a channel that is the response's body. Once a
response has started, its status can't change, so a failure halfway ends
the stream with an error, and hyper drops the connection without the
chunked body's last chunk: the client sees a body cut short, never a short
archive that looks whole.

`rustlet load` reads either format, entry by entry, in any order, and
every blob is checked as it streams in: an entry `blobs/sha256/<hex>` is
stored through an ingest that expects that digest, so a blob that doesn't
hash to its name never reaches the store. Removed, then loaded from a copy
with one byte changed, then from the archive as it was:

```text
$ rustlet rmi ch18-committed
Untagged: docker.io/library/ch18-committed:latest
Deleted: sha256:3ae6ba60dbb5…
Deleted: sha256:58a3003be74f…
Deleted: sha256:62814c948b16…
Deleted: snapshot sha256:1f3edb36f2e0…
$ cp committed.tar broken.tar && printf X | dd of=broken.tar bs=1 seek=$((13*512 + 20)) conv=notrunc status=none
$ rustlet load -i broken.tar; echo "exit $?"
rustlet: error: blob sha256:62814c948b169cd7bfbe0420e3387753805c836783644d715f8bf5e62a21ed71: expected sha256:62814c948b169cd7bfbe0420e3387753805c836783644d715f8bf5e62a21ed71, got sha256:e3aea8b782003f04af9f05efc7572b934aaf3fb64dd38c9a34fc1a3bdb5e9e82
exit 125
$ rustlet load -i committed.tar
Loaded image: ch18-committed:latest
```

(`tar -tvRf` gave block 12 for the commit layer's header, so its data
starts at block 13.) The broken load named nothing: `images` had no
`ch18-committed` until the second. A blob the store already has isn't
written again, and its entry's data is skipped unread. Names are set only
once the
archive has ended and every image in it loads with every blob present;
an image without a name is kept. Then the daemon unpacks each image (in a
worker, as a pull does) before it reports it loaded, so a loaded image is
a runnable one.

The other format is `docker save`'s before Docker 25: `manifest.json`
lists per image its `Config` (`<hex>.json`, stored expecting that
digest), `RepoTags` and `Layers` (`<dir>/layer.tar`, compressed or not,
a layer listed twice being a symlink to another's `layer.tar`). The loader
stores each layer under the digest it hashes to, checks its uncompressed
digest against the config's diff ID for it, as Docker's loader checks,
and writes an OCI manifest of its own for the image (`import::write_image`,
media types from the layers' first bytes). When both files are there,
`index.json` wins. Its descriptors may also be indexes, nested ones too,
from which `linux/amd64` is chosen as for a pull.

## 11. A bug the new code found: newlines in PAX records

A tar header has fixed fields: 100 bytes of name, ids in 7 octal digits,
nothing for extended attributes. PAX (POSIX.1-2001) adds an extended
header, an entry of type `x` before the one it describes, whose data is
**records**: `<length> <key>=<value>\n`, where the length counts the
whole record, its own digits and the newline included. Attributes travel
as `SCHILY.xattr.<name>` records, and an attribute's value is bytes, any
bytes. This build sets one with a newline in it, then reads it in the next
step:

```text
$ cat pax/Containerfile
FROM python:3-slim
RUN python3 -c "import os; open('/note', 'w').close(); os.setxattr('/note', 'user.note', b'line one\nline two')"
RUN python3 -c "import os; print(os.getxattr('/note', 'user.note'))"
$ rustlet build -t ch18-pax pax
…
Step 3/3 : RUN python3 -c "import os; print(os.getxattr('/note', 'user.note'))"
 ---> Running in 97ba753daed6
b'line one\nline two'
…
$ cd pax-saved && rustlet save ch18-pax | tar -x; L=$(jq -r '.[0].Layers[-2]' manifest.json)
$ zcat $L | head -c 48 | od -c | head -2
0000000   P   a   x   H   e   a   d   e   r   s   .   0   /   n   o   t
0000020   e  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0
$ zcat $L | dd bs=512 skip=1 count=1 status=none | head -c 44 | cat -A
44 SCHILY.xattr.user.note=line one$
line two$
```

The first block of step 2's layer is the PAX header for `note` (named the
way Go's `archive/tar` names them, `PaxHeaders.0/note`), and the second
its data: one record of 44 bytes, holding two lines. (`note` is the
layer's first entry: the `etc/` that held only a mount point,
`/etc/hosts`, which python:3-slim lacks, is left out, and `note` sorts
before `usr/`, where Python wrote its bytecode caches.)

Step 3 is what used to fail. Its container needed step 2's layer unpacked,
and the unpacker read archives with the `tar` crate, which splits a PAX
header's data at every newline and parses each piece as a record: `44
SCHILY.xattr.user.note=line one` is 34 bytes plus its newline, not 44, so
the crate reported "malformed pax extension", and the unpack, and so the
build, failed. A real image needs no Python for it: a value holds the
byte 0x0a whenever an ACL has an entry for uid or gid 10 (ids are
little-endian 32-bit numbers in `system.posix_acl_access`), or a file
capability set holds bits 1 and 3 (`cap_dac_override` and `cap_fowner`,
the permitted mask's first byte `0x0a`). Pulled, such a layer had failed
since Phase 3; made by `commit` or a `RUN`, since this phase's diff. That
is where it was found: the diff writes such values as Go does, and its
tests, reading them back, couldn't use the crate's records (they parse
their own, by length).

The crate's own reading had a second fault. It looks up `uid`, `gid` and
`size` in the records with a loop that gives up at the first malformed
one. Go's writer sorts the keys, and `SCHILY.xattr.*`, upper case, sorts
before `gid`, `size` and `uid`: an archive from Docker with such an
attribute on a file whose owner or size only PAX can hold would lose them
silently.

Go reads a record by its length (`parsePAXRecord`: the digits up to the
space, then exactly that many bytes, which must end with a newline; the
key is what comes before the first `=`), and caps an extended header at 1
MiB. So does Rustlets now
([`unpack/extensions.rs`](../../crates/rustlet-image/src/unpack/extensions.rs)):
the archive is read in the crate's raw mode, where extension headers come as
entries of their own; `Extensions::absorb` takes in PAX headers and GNU
long names (`L`, `K`) and parses records by their length, and the next
real entry gets them, a later record for a key winning. What the raw mode
gives up is refused rather than written wrong: GNU sparse files (no image
builder writes them; Go's writer can't) and sizes only a PAX record holds
(files over 8 GiB, whose header size Go leaves 0). Tests:
`pax_values_may_hold_newlines_and_records_after_them_still_apply` (an ACL
for gid 10, then an `mtime` record that must still apply),
`long_names_and_link_targets_come_from_extension_headers`,
`oversized_or_dangling_extension_headers_are_refused`, and
`records_are_parsed_by_length_newlines_and_all`.

## 12. Differences from Docker

Docker has two builders: the classic one, which ran each step in a
container and committed it, and BuildKit, the default since Docker 23,
which runs a graph of operations on snapshots. Rustlets' is closer to the
classic one in how it runs and shows a build, and to BuildKit in what it
reads.

- **Like the classic builder**: a `RUN` is an ordinary container,
  visible in `ps -a`; what it writes below a `VOLUME` is lost; the output
  is `Step N/M`, `Running in`, `Removed intermediate container`.
- **Like BuildKit**: the parser's rules; only the stages the target needs
  are built; the automatic platform args; `COPY --from` planned with the
  global `ARG`s.
- **The output's ` ---> `** lines name layers, not intermediate images,
  and config-only steps have none. An image's id is its manifest's digest.
- **The cache** keys a changed build arg from its `ARG` on, not from its
  first use (§7). Cache entries are images in `index.json`; `builder
  prune` removes them all and doesn't count the space.
- **`WORKDIR`** only changes the config. Docker makes the directory at
  that step; here the runtime makes it when a container starts there, so
  a `RUN` after it has it in its layer, and an image with no `RUN` after
  it gets it at each container's start.
- **Mount points** stay out of a `RUN`'s or a commit's layer, and so do
  the directories that only held them, unchanged: Docker keeps them out
  with an init layer, Rustlets by comparing with the layers below (§5).
  A `RUN` that writes nothing adds an empty layer, where Docker's classic
  builder adds none and marks the history entry `empty_layer`.
- **Not supported, refused by name**: BuildKit's own features (heredocs,
  `RUN --mount`, `--network`, `--security`, `COPY --link`, `--parents`,
  `--exclude`, `ADD --checksum`, `--keep-git-dir`), `ADD` from URLs and
  git, a `--platform` other than `linux/amd64`, a stage named `scratch`,
  `EXPOSE 8080:80` (BuildKit keeps the container port with a warning), a
  `COPY` into a symlink to nothing (BuildKit makes the directory), a
  context that is a URL, an archive or stdin, and `-f -`.
- **Not done, with a warning or as documented**: a base's `ONBUILD`
  triggers, an image's or an earlier stage's, aren't run (Docker runs a
  base image's first thing), nor passed on; bzip2 and xz
  archives are copied, not extracted; an `ADD`ed archive's `./` entry
  gives the destination its metadata, as `tar -x` does (Docker skips it);
  no reproducible timestamps (`SOURCE_DATE_EPOCH`), no `push`, no other
  platforms.
- **Expansion**: `COPY`, `ADD` and `VOLUME` in shell form split words as
  a shell does, so quotes can hold a space (`COPY "my file" /dst/`) and a
  variable can hold several sources; `$1` and `$$` stay as written;
  `${V#…}` and the other newer forms are refused.
- **The history** has no `ARG` entries, and a `RUN`'s line doesn't list
  the `ARG` values it got (Docker's builders write `RUN |1 NAME=value
  /bin/sh -c …`).
- **commit**'s history line is `rustlet commit` (Docker's is the
  container's command), and it leaves out the mount points of the
  container's last run.
- **save** writes the same bytes for the same images; **load** takes both
  formats and checks every blob as it arrives.

## 13. Try it

```sh
R="sudo target/debug/rustlet"
$R build -t hits-web examples/hits                 # from the cache, if chapter 19 ran
$R build --no-cache -t hits-web examples/hits      # every step
$R run --rm hits-web python -c 'import redis; print(redis.__version__)'
$R inspect hits-web | jq -r '.[0].config.history[] | "\(.created) \(.created_by[0:60])"'
cargo xtask images cat content/index.json | jq '.manifests[].annotations'
mkdir -p /tmp/t && $R save hits-web | tar -x -C /tmp/t
tar -tvzf /tmp/t/$(jq -r '.[0].Layers[-1]' /tmp/t/manifest.json)   # the COPY's layer
$R run --name box alpine sh -c 'rm /etc/motd; echo x > /x'; $R commit box boxed
$R save boxed | tar -t; $R rm box; $R rmi boxed
cargo xtask itest -- bd_ cm_ sl_                     # the tests behind this chapter
```

## Check yourself

1. The context of `examples/hits` holds three files although its
   `.dockerignore` starts with `*`. Which three, and why each?
   *`app.py` and the Containerfile, taken back by `!` lines (the last
   matching pattern decides), and `.dockerignore` itself, which, like the
   Containerfile, always goes.*
2. `RUN ["echo", "$HOME"]` prints `$HOME`. Why, and what prints the home
   directory?
   *Nothing expands an exec form: the builder never expands `RUN`, and
   there is no shell. `RUN echo $HOME`, whose shell expands it.*
3. A stage uses `$VERSION`, declared by a global `ARG VERSION=1`, and gets
   nothing. Why, and what fixes it?
   *Global `ARG`s are seen only by `FROM` lines until a stage declares
   them again: `ARG VERSION` in the stage, without a value, takes the
   global's.*
4. What in a `RUN` step's container differs from a container `rustlet run`
   would make of the same image?
   *Its entrypoint is cleared, its command is the `SHELL` plus the step,
   its environment has the stage's `ARG`s and the proxy args, its network
   is the build's, it has no healthcheck, and it is labelled
   `io.rustlet.build`.*
5. Why does the diff write two whiteouts that are one inode in upper as
   two separate entries, and what else of upper does it leave out?
   *The shared inode is overlay's bookkeeping (the first name is in
   `work/work`), not a hard link the container made. Also left out:
   `work/`, overlay's attributes, devices and sockets, names starting with
   `.wh.`, the mount points of the last run, and the directories that
   held only those, if they are as the layers below have them (or, where
   those have nothing, `0755` and root's).*
6. `COPY f /app/`, with `/app` a symlink to `/etc` in the image. Where
   does `f` go, and why can't a symlink in the context to `/etc/shadow`
   leak the host's file?
   *Into the image's `/etc`: both sides are resolved inside their own
   root with `RESOLVE_IN_ROOT`. The context's symlink resolves to the
   context's `etc/shadow`, which isn't there.*
7. Two builds of the same files make the same image id although the second
   ran a day later. Which dates in the config could have changed it, and
   why didn't they?
   *The `created` of config-only history entries and of the config: they
   are the date of the stage's last filesystem change, which comes from the
   cache entries, not now.*
8. You change a build arg used by the last `RUN` only. In Docker, which
   steps run again, and in Rustlets?
   *Docker: from its first use, which is every `RUN` after the `ARG` (each
   gets the declared args); a `COPY` between them stays cached. Rustlets:
   every step after the `ARG`, because the `ARG` step's key holds the
   value.*
9. Why does `load` set names only at the end, and what happens to a blob
   whose bytes don't match its name?
   *So that a load that fails halfway names nothing broken; the ingest
   expects the digest of its name and refuses it, failing the load.*
10. Why did the `tar` crate lose a PAX record whose value holds a newline,
    and why could that cost the entry's owner too?
    *It splits records at newlines instead of reading each by its
    length; its lookup of `uid`, `gid` and `size` stops at the first bad
    record, and Go's sorted keys put `SCHILY.xattr.*` before them.*

## Experiments

- **What a step sees.** Build `FROM alpine` / `RUN cat /etc/resolv.conf
  /etc/hosts; ls -la /; env` with `--network none`, then with `--network
  host`. What changed in the output, and in the cache keys (was the
  second build cached)?
- **Volumes in a build.** `VOLUME /data`, then `RUN echo x > /data/x &&
  ls /data`, then `RUN ls /data`. Watch `rustlet volume ls` while it
  builds, and explain the second `ls`.
- **Reproducible?** Build `FROM alpine` / `RUN echo hi > /hi` twice with
  `--no-cache`, a few seconds apart, and compare the layers' digests
  (with `RUN echo hi`, which writes nothing, both are the empty layer). Use
  `save` and `tar -tvzf` to find what differs, and think about what
  `SOURCE_DATE_EPOCH` would have to change.
- **Old-style archives.** Save an image, delete `index.json` and
  `oci-layout` from the archive (`tar --delete -f x.tar index.json
  oci-layout`), and load it. Which path of the loader ran? Is the loaded
  image's id the one you saved, and why might it not be?
- **A layer by hand.** In a `--userns remap` container, `setfacl` isn't
  there, but Python is in python:3-slim: give a file an ACL entry for gid
  10 (`os.setxattr(path, 'system.posix_acl_access', bytes([2,0,0,0, 1,0,6,0,
  255,255,255,255, 4,0,4,0, 255,255,255,255, 8,0,4,0, 10,0,0,0, 16,0,4,0,
  255,255,255,255, 32,0,4,0, 255,255,255,255]))`), commit the container,
  and find the record in the layer with `od -c`. Which id is in it, 10 or
  1000010?
- **Your own ignore rules.** Put a `.dockerignore` with `**/*.log`,
  `!keep.log` and `secret/` in a context with logs at several depths and a
  `secret/` directory, then `COPY . /ctx/` and `find /ctx` in a `RUN`.
  Which files went, and which were never read on your side?
