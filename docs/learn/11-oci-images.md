# 11 — OCI images: one digest vouches for every byte

Phase 2 ended with a runtime that runs a bundle: a `config.json` and a
root filesystem that something else prepared. Phase 3 prepares both from
a name. `cargo xtask image-run nginx` asks Docker Hub what `nginx` means
today, downloads what it is told and checks every byte against a digest
it already trusts. It unpacks the layers without letting any archive
entry write outside its own directory, stacks them with overlayfs, and
turns the image's config into a runtime spec for `rustlet-runc`. The
milestone: `alpine`, `nginx` and `python:3-slim` from Docker Hub, run
rootful and with `--userns`. This chapter follows an image from its name
to `config.json`; the overlay mount and its idmapped layers are
[chapter 12](12-overlayfs.md).

Code, in `crates/rustlet-image/src/`: [`lib.rs`](../../crates/rustlet-image/src/lib.rs) (the pipeline),
[`reference.rs`](../../crates/rustlet-image/src/reference.rs), [`digest.rs`](../../crates/rustlet-image/src/digest.rs),
[`media.rs`](../../crates/rustlet-image/src/media.rs), [`manifest.rs`](../../crates/rustlet-image/src/manifest.rs),
[`config.rs`](../../crates/rustlet-image/src/config.rs), [`content.rs`](../../crates/rustlet-image/src/content.rs),
[`pull/mod.rs`](../../crates/rustlet-image/src/pull/mod.rs), [`image.rs`](../../crates/rustlet-image/src/image.rs),
[`unpack.rs`](../../crates/rustlet-image/src/unpack.rs), [`snapshot.rs`](../../crates/rustlet-image/src/snapshot.rs),
[`rootfs.rs`](../../crates/rustlet-image/src/rootfs.rs) (chapter 12), [`runspec.rs`](../../crates/rustlet-image/src/runspec.rs),
[`user.rs`](../../crates/rustlet-image/src/user.rs), [`import.rs`](../../crates/rustlet-image/src/import.rs),
[`store.rs`](../../crates/rustlet-image/src/store.rs); [`xtask/src/imagerun.rs`](../../xtask/src/imagerun.rs),
[`xtask/src/images.rs`](../../xtask/src/images.rs); the runtime's [`stdio.rs`](../../crates/rustlet-runtime/src/stdio.rs).
Tests: [`pull/tests.rs`](../../crates/rustlet-image/src/pull/tests.rs) (a fake registry),
[`unpack/tests.rs`](../../crates/rustlet-image/src/unpack/tests.rs), the unit tests of `user.rs` and `runspec.rs`, and
[`images.rs`](../../tests/tests/images.rs) (`cargo xtask itest -- im_`, 10 tests).
Design: [architecture.md §2.4](../architecture.md#24-rustlet-image--oci-images-storage-snapshots).

The transcripts were recorded on 2026-10-01 against Docker Hub, kernel
7.0.0-34-generic. The store, `/var/lib/rustlet`, is root's and `0700`
below its top, so every look inside is a `cargo xtask images` command,
which reads through sudo. Digests and the 64-digit container ids are cut
to 12 hex digits and `…`, omitted lines are `…`, and tokens are
truncated. Docker Hub saw one manifest GET from curl and two new pulls
from `image-run` (busybox, hello-world); everything else came from the
store or from requests it doesn't count as pulls (HEADs, tokens, blobs).
The host's `/proc/self/mountinfo` stayed at 24 lines.

## 1. A few JSON documents and some tarballs

Every part of an image is a file named by the SHA-256 of its bytes, and
each part names the next ones by digest, so whoever trusts the first
digest can check everything below it as it arrives:

```text
 docker.io/library/alpine:latest     a tag: the registry's name for…
        ▼
 index     sha256:294b683cb724…   9218 B   …a list of manifests, one per platform
        │ linux/amd64
        ▼
 manifest  sha256:d56c381f961d…   1022 B   one config, then the layers in order
        ├─► config  sha256:320994c3b997…    611 B   how to run it; the layers' diff IDs
        └─► layer   sha256:e2de96513ba9…  3.7 MiB   the files: a tar, gzipped
```

A single-platform image has no index; its tag names the manifest. The
manifest is a list of **descriptors** (media type, digest, size), one
for the config and one per layer. The store already had three images:

```text
$ cargo xtask images
NAME                                         MANIFEST       REPO DIGEST    LAYERS       SIZE
docker.io/library/alpine:latest              d56c381f961d   294b683cb724        1    3.7 MiB
docker.io/library/nginx:latest               9c0f39aa1c46   abe47724e466        7   60.5 MiB
docker.io/library/python:3-slim              7bf6c3111fe0   51dafde81dbd        4   41.5 MiB
$ cargo xtask images inspect alpine
name         docker.io/library/alpine:latest
manifest     sha256:d56c381f961d…  (/var/lib/rustlet/content/blobs/sha256/d56c381f961d…)
repo digest  sha256:294b683cb724…  (the index the manifest was chosen from)
…
cmd          ["/bin/sh"]
…
  #   BLOB                 SIZE DIFF ID        CHAIN ID       SNAPSHOT
  0   e2de96513ba9      3.7 MiB 74d97c428c51   74d97c428c51   515 entries, 8.0 MiB
$ cargo xtask images inspect alpine --json
# manifest sha256:d56c381f961d…
{
  …
  "layers": [
    {
      "digest": "sha256:e2de96513ba9…",
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 3849738
…
$ cargo xtask images cat content/blobs/sha256/d56c381f961d… | sha256sum
d56c381f961d…  -
```

`--json` reparses and pretty-prints; the digest covers the stored bytes,
which `images cat` copies out unchanged. The config holds what the author
chose for running the image (`Env`, `Cmd`, `Entrypoint`, `User`,
`WorkingDir`, capitalized because the format was Docker's first),
`rootfs.diff_ids` (§6), and a `history` in which only `RUN`, `COPY` and
`ADD` made layers (nginx: 18 steps, 7 layers). Docker's "manifest v2,
schema 2" and OCI's, derived from it, are both accepted
([`media.rs`](../../crates/rustlet-image/src/media.rs)); schema 1, OCI
artifacts (`refuses_an_artifact`) and non-filesystem layers are refused
before any blob is fetched.

## 2. Names, tags and digests

What you type is normalized by Docker's rules
([`reference.rs`](../../crates/rustlet-image/src/reference.rs)): a first
component without a `.` or `:`, and not `localhost`, isn't a registry,
so the image is on Docker Hub; a one-component Docker Hub name lives
under `library/`; no tag and no digest means `:latest`.

```text
$ for r in alpine index.docker.io/library/alpine alpine:3.24 Alpine; do cargo xtask images inspect $r 2>&1 | head -1; done
name         docker.io/library/alpine:latest
name         docker.io/library/alpine:latest
Error: image docker.io/library/alpine:3.24 is not in the store
Error: image reference "Alpine": invalid reference format
```

`index.docker.io` is Docker Hub's old name, and still the host that
`oci-client` contacts. `alpine:3.24` fails although it is the same image
today (the manifest's annotations say `3.24.2`): a tag is only a name,
and the store knows the names it was given. A tag moves, every few weeks
for `alpine:latest`; a digest names the same bytes forever, and
`images inspect sha256:d56c381f961d…` finds the image without any name.

So a pull asks once what the tag points at now. For a multi-platform
image the answer is the index, whose digest is the **repo digest**, the
one `docker images --digests` shows and `alpine@sha256:294b683cb724…`
pins. The store keeps the manifest chosen from it (the **manifest
digest**) and records the repo digest beside the name, in the layout's
own `index.json`:

```text
$ cargo xtask images cat content/index.json
{
  "manifests": [
    {
      "annotations": {
        "io.rustlet.image.repo-digest": "sha256:294b683cb724…",
        "org.opencontainers.image.ref.name": "docker.io/library/alpine:latest"
      },
      "digest": "sha256:d56c381f961d…",
…
```

Indexes aren't stored; this annotation is their only trace, and it lets
`--pull always` tell from one HEAD whether the tag has moved (§4). A
name points at a single-platform manifest, never at an index. The file
goes through a `serde_json::Value`, whose maps are sorted, so it changes
only when its content does.

## 3. The registry protocol by hand

The distribution API is plain HTTPS. Asked without credentials, Docker
Hub says where to get some, and that realm hands out a pull token for
one repository without any: a signed JWT, valid for 300 s.

```text
$ curl -si https://registry-1.docker.io/v2/
HTTP/2 401
…
www-authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
…
$ curl -s 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull' > token.json
$ jq -r .token token.json | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -c '{iss, aud, access: [.access[] | {type, name, actions}]}'
{"iss":"auth.docker.io","aud":"registry.docker.io","access":[{"type":"repository","name":"library/alpine","actions":["pull"]}]}
```

With it, a HEAD of the tag's manifest URL gives the digest without the
body; `Accept` lists what the client understands, here Rustlets' list,
indexes first (`media::MANIFEST_TYPES`). Docker Hub counts each GET of a
manifest URL as a pull, and limits anonymous pulls per address and hour;
a HEAD isn't counted. After the HEAD, my one GET fetched the same URL:

```text
$ TOKEN=$(jq -r .token token.json)
$ A='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
$ curl -sI -H "Authorization: Bearer $TOKEN" -H "Accept: $A" https://registry-1.docker.io/v2/library/alpine/manifests/latest
HTTP/2 200
…
content-type: application/vnd.oci.image.index.v1+json
content-length: 9218
docker-content-digest: sha256:294b683cb724…
…
ratelimit-remaining: 100;w=3600
…
$ curl -s -D headers.txt -o index.json -H "Authorization: Bearer $TOKEN" -H "Accept: $A" https://registry-1.docker.io/v2/library/alpine/manifests/latest
$ grep -i '^ratelimit-remaining' headers.txt; sha256sum index.json
ratelimit-remaining: 99;w=3600
294b683cb724…  index.json
$ jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture)\(if .platform.variant then "/"+.platform.variant else "" end)  \(.digest[7:19])…  \(.size)  \(.annotations["vnd.docker.reference.type"] // "")"' index.json
linux/amd64  d56c381f961d…  1022
unknown/unknown  350f747a86e8…  838  attestation-manifest
linux/arm/v6  d3c3fda3e4d3…  1023
…
```

The bytes hash to the repo digest the store recorded, and the
`linux/amd64` entry is the stored manifest, size 1022. Each of the eight
platforms is followed by a build attestation listed as `unknown/unknown`;
`manifest::select_platform` takes only `linux/amd64` image manifests,
preferring one without a variant over `v2`/`v3` builds. Blobs come by
digest from the same repository, and aren't pulls either. A GET is a
redirect to a CDN, which curl doesn't follow without `-L`:

```text
$ curl -s -o /dev/null -D - -H "Authorization: Bearer $TOKEN" https://registry-1.docker.io/v2/library/alpine/blobs/sha256:e2de96513ba9…
HTTP/2 307
…
location: https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/e2/e2de96513ba9…/data?…
…
```

Rustlets leaves this protocol to `oci-client` (challenges, anonymous
tokens, redirects) and decides what to ask for and what to accept.

## 4. Pulling in Rustlets

[`pull/mod.rs`](../../crates/rustlet-image/src/pull/mod.rs) first
**resolves**: the tag's manifest is fetched raw and its exact bytes are
kept, since re-serialized JSON would hash differently; from an index,
the `linux/amd64` manifest is fetched by digest and must have exactly
the digest and size the index gave. **The config comes next**, and must
parse, list one diff ID per layer and be for `linux/amd64` before any
layer is fetched. **Layers** follow, 3 at a time as in Docker, skipping
blobs the store has (same digest, same size): that is how images share
layers. **The manifest is stored last**, after everything it names, and
then the name.

```text
$ /usr/bin/time -f 'elapsed %e s' cargo xtask image-run busybox sh -c 'busybox | head -1'
resolve    docker.io/library/busybox:latest
manifest   sha256:f97baa533a26… for linux/amd64, 1 layers, 2.1 MiB
index      sha256:fd7dc98638c8…
  config aaef90e06523 downloaded and verified (459 B)
  layer  37bb94b0940b downloaded and verified (2.1 MiB)
stored     docker.io/library/busybox:latest
image      docker.io/library/busybox:latest = sha256:f97baa533a26… (linux/amd64, 1 layers, 2.1 MiB)
  layer  37bb94b0940b unpacking 2.1 MiB … 448 entries, 4.2 MiB of files; diff ID verified
rootfs     /var/lib/rustlet/containers/4b957bb2b660…/rootfs (overlay of 1 layers)
run        4b957bb2b660: ["sh", "-c", "busybox | head -1"] as 0:0 in /
BusyBox v1.38.0 (2026-05-13 02:21:49 UTC) multi-call binary.
exited     4b957bb2b660: status 0
elapsed 2.60 s
```

`unpacking` names the layer by its blob digest; the next run's `already
unpacked` line by its chain ID, `6cd030ace585` (§6).

**Nothing unverified enters `blobs/`.** Each blob streams into an
[`Ingest`](../../crates/rustlet-image/src/content.rs), a new `0600` file
in `ingest/`, hashed and counted as bytes arrive. A byte past the
descriptor's size fails the write; `commit` checks size and digest,
fsyncs and renames into `blobs/sha256/<hex>`; dropped uncommitted, it
deletes its file. A failed pull sets no name and leaves no partial file;
completed blobs stay, verified, for the next try (no garbage collection
yet). The unit tests pull from `Fake`, a registry on 127.0.0.1 that
counts requests, as in `refuses_a_corrupted_layer` (one byte flipped)
and `refuses_another_platform_before_fetching_layers` (no layer GET).

**When to ask.** `--pull missing`, the default, makes no request for a
stored name (the second busybox run printed no `resolve`); `--pull never`
refuses what the store lacks (`Error: image
docker.io/library/debian:latest is not in the store, and the pull policy
is never: pull it first`); `--pull always` sends one HEAD and downloads
nothing if that is the recorded repo digest and every blob is there
(`ensure_follows_the_pull_policy`). The events are the NDJSON the daemon
will stream in Phase 4:

```text
$ cargo xtask image-run --pull always --json-progress alpine true
{"status":"resolving","reference":"docker.io/library/alpine:latest"}
{"status":"resolved","reference":"docker.io/library/alpine:latest","manifest":"sha256:d56c381f961d…","repo_digest":"sha256:294b683cb724…","platform":"linux/amd64","layers":1,"size":3850349}
{"status":"exists","kind":"config","digest":"sha256:320994c3b997…","size":611}
{"status":"exists","kind":"layer","digest":"sha256:e2de96513ba9…","size":3849738}
{"status":"done","reference":"docker.io/library/alpine:latest","manifest":"sha256:d56c381f961d…"}
…
```

A download sends `downloading` events instead of `exists`: at the start,
about every MiB, and at the end. For hello-world, the second new pull,
they ran from `"current":0,"total":2415` to `"current":2415,"total":2415`.

## 5. The content store on disk

```text
$ cargo xtask images ls content
content:
d0755       0:0             4096  blobs
-0644       0:0             1596  index.json
-0644       0:0               30  oci-layout
$ cargo xtask images ls content/blobs/sha256
content/blobs/sha256:
-0600       0:0              629  2056b40bae09…
…
-0600       0:0         29830418  6b37362b3da7…
…
```

Beside `content/`, the root holds `ingest/`, `snapshots/` (§6),
`containers/` and `store.lock`. It is `0711`, so a path below it can be
handed to another root process with nothing listable; everything below
is `0700`, since images contain setuid binaries and anything else. The
seventeen blobs, before busybox and hello-world, are alpine's three,
nginx's nine and five of python:3-slim's, whose bottom layer
`6b37362b3da7…` is nginx's, stored once. No blob is `294b683cb724…`: the
index was read, not kept.

**Why names live in `index.json`.** The plan was SQLite. Kept in the
layout's own index, under the standard `ref.name` annotation, they leave
a valid [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
that `skopeo` or `umoci` can read as it is, and make `save`/`load`
copies. The file is replaced atomically (temporary file, fsync, rename),
so readers need no lock; writers take an **open-file-description lock**
(`F_OFD_SETLKW` on `store.lock`) around their read-modify-write. A
classic POSIX lock belongs to the process, so two daemon threads
wouldn't exclude each other; an OFD lock belongs to one `open`, and each
`lock()` makes its own (`concurrent_writers_do_not_lose_names`).

## 6. Two digests per layer, and the chain ID

The manifest names a layer by its **blob digest**, of the compressed
bytes; the config names it by its **diff ID**, of the uncompressed tar:

```text
$ cargo xtask images cat content/blobs/sha256/6b37362b3da7… | sha256sum
6b37362b3da7…  -
$ cargo xtask images cat content/blobs/sha256/6b37362b3da7… | gunzip | sha256sum
a6dc765193a5…  -
```

That is nginx's bottom layer, 29830418 bytes of gzip around an
81244160-byte tar, and `a6dc765193a5…` is its config's
`rootfs.diff_ids[0]`. The blob digest proves the download is what the
manifest named, the diff ID what the decompressor produced: what ends up
on disk (gzip isn't canonical, so one tar can travel as several blobs).
Unpacking hashes on both sides of the decompressor and reads both
streams to the end, past the end-of-archive blocks where the tar parser
stops: the digests cover every byte.

A layer is a diff, and its whiteouts delete names *from the layers
below*. So an unpacked layer is keyed by its **chain ID**, which
identifies it together with all its parents (image-spec `config.md`):

```text
ChainID(L₀) = DiffID(L₀)
ChainID(Lₙ) = sha256(ChainID(Lₙ₋₁) + " " + DiffID(Lₙ))

$ printf 'sha256:a6dc765193a5… sha256:95f7d9932454…' | sha256sum
49049a42a1d2…  -
```

That is the CHAIN ID of nginx's second layer. The tables of `images
inspect nginx` and `images inspect python:3-slim` start:

```text
  #   BLOB                 SIZE DIFF ID        CHAIN ID       SNAPSHOT
  0   6b37362b3da7     28.4 MiB a6dc765193a5   a6dc765193a5   3269 entries, 75.2 MiB
  1   f1169c633cbc     32.0 MiB 95f7d9932454   49049a42a1d2   1800 entries, 79.4 MiB
  …
  0   6b37362b3da7     28.4 MiB a6dc765193a5   a6dc765193a5   3269 entries, 75.2 MiB
  1   5c21337b2448      1.2 MiB 5e09159a80ed   acc27b89f4a0   554 entries, 3.6 MiB
```

The Debian base is one blob and one snapshot, unpacked once: `images ls
snapshots` lists 11 directories for the three images' 12 layers. Every
chain ID above it differs, and would even for identical diffs. With
overlayfs a snapshot directory holds only its own layer's files, but
what they mean depends on the stack below, so a snapshot is named by the
stack it completes, and its `snapshot.json` records its parent
(`images cat snapshots/49049a42a1d2/snapshot.json`; `ls` and `cat`
expand a unique prefix).

## 7. Unpacking an untrusted archive

A layer is a tar of the files one build step added or changed:

```text
$ cargo xtask images cat content/blobs/sha256/37bb94b0940b… | tar -tvz | sed -n 1,4p
drwxr-xr-x 0/0               0 2026-05-12 22:21 ./
drwxr-xr-x 0/0               0 2026-05-12 22:21 bin/
-rwxr-xr-x 0/0         1041984 2026-05-12 22:21 bin/[
hrwxr-xr-x 0/0               0 2026-05-12 22:21 bin/[[ link to bin/[
```

Busybox's 448 entries are 20 directories, 16 files, 2 symlinks and 410
hard links to `bin/[`, hence only `4.2 MiB of files`. The `tar` crate
just iterates; [`unpack.rs`](../../crates/rustlet-image/src/unpack.rs)
writes every file. Device nodes are skipped (the rootfs is `nodev`, and
`/dev` a tmpfs), and image-spec `layer.md`'s deletion markers become
overlay's:

| in the layer | in the snapshot |
|---|---|
| `dir/.wh.name` | `dir/name` as a character device 0:0, a **whiteout** |
| `dir/.wh..wh..opq` | `trusted.overlay.opaque=y` on `dir`: lower layers' entries hidden |

A directory that meets its own whiteout in the same layer becomes
opaque. No layer of these five images has a whiteout, since a file
deleted in the same `RUN` never reaches one; the `im_` tests build layers
with them, and §9 shows overlay making one.

**Every name is the image author's choice.** So:

1. **Names are checked as text:** `..` and NUL are refused, a leading
   `/` and `.` components dropped (`/etc/x` is `etc/x`).
2. **Parents resolve with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_XDEV |
   RESOLVE_NO_MAGICLINKS)`** from an fd of the layer directory. If an
   earlier entry made `lib` a symlink to `/usr/lib` or `../../..`,
   `lib/x` lands in the layer's `usr/lib` or at its top: `IN_ROOT` walks
   as if the layer were `/`, like Docker's chroot'ed unpack. The first
   plan, `RESOLVE_BENEATH`, fails with `EXDEV` on any absolute symlink or
   `..` above the start, and would refuse images Docker accepts (the
   Debian base has `var/run -> /run`). Neither leaves the directory.
   `NO_XDEV` keeps the walk off mounts, `NO_MAGICLINKS` off `/proc`-style
   links; a symlink to a directory the layer lacks is refused.
3. **The last component is never followed:** entries are made from the
   parent's fd with `O_NOFOLLOW` or calls that don't follow, after
   `remove_tree_at` (which doesn't follow either) cleared the name.
4. **Hard links stay in the layer:** the target, resolved the same way
   and opened `O_PATH|O_NOFOLLOW`, is linked from that fd with
   `linkat(AT_EMPTY_PATH)`, never a directory or whiteout.
5. **Overlay's own attributes** (`trusted.overlay.*`, `user.overlay.*`)
   are dropped; from an image they could forge opaque directories.

**Metadata: owner, mode, attributes, times, in that order.**

```text
$ cargo xtask images ls snapshots/a6dc765193a5/fs/usr/bin | grep -E '^-[2467]'
-2755       0:42          113848  chage
-4755       0:0            70888  chfn
…
-4755       0:0            84360  su
-4755       0:0            55688  umount
```

`chown(2)` clears an executable's setuid and setgid bits even when root
calls it, so `fchmod` follows `fchown`, or `su` would lose its `4` and
`chage` its `2`. A chown also removes `security.capability` (the file
capabilities of `ping`-like programs), so attributes come after both
(`im_unpack_preserves_owners_modes_and_file_capabilities`). Directory
times come last of all, since creating entries changes a directory's
mtime. Unprivileged, as in the unit tests, the caller stays the owner and
opaque directories get `user.overlay.opaque`, for an overlay mounted with
`userxattr`.

**Both digests are checked before a snapshot exists.** A layer is
unpacked into `snapshots/.tmp-…/fs`, synced, and renamed to its chain ID
only if blob digest, size and diff ID all match, or one crafted image
could poison a snapshot others share (`im_digest_mismatches_leave_no_snapshot`).
Concurrent unpacks converge on the first rename. [`unpack/tests.rs`](../../crates/rustlet-image/src/unpack/tests.rs)
has `symlinked_parents_resolve_inside_the_layer`,
`hard_links_must_stay_inside_the_layer` and more;
`im_unpack_stays_inside_the_layer_as_root` aims symlinks at the host's
`/etc` and `/tmp`. The itest suite passed earlier today: 240 checks.

## 8. From image config to config.json

[`runspec.rs`](../../crates/rustlet-image/src/runspec.rs) turns the
image config and the `run` flags into a runtime spec, following OCI's
[`conversion.md`](https://github.com/opencontainers/image-spec/blob/main/conversion.md)
and Docker. `--keep` leaves the result to look at:

```text
$ cargo xtask image-run --keep nginx true
…
run        9f91273b291d: ["/docker-entrypoint.sh", "true"] as 0:0 in /
kept       /var/lib/rustlet/containers/9f91273b291d… (upper/ is the container's writable layer)
$ cargo xtask images cat containers/9f91273b291d/config.json | jq '.process, .annotations'
{
  "terminal": false,
  "user": {
    "uid": 0,
    "gid": 0,
    "additionalGids": [
      0
…
{
  "io.rustlet.image.name": "docker.io/library/nginx:latest",
  …
  "org.opencontainers.image.stopSignal": "SIGQUIT",
  "org.opencontainers.image.exposedPorts": "80/tcp",
  "io.rustlet.image.manifest": "sha256:9c0f39aa1c46…",
  …
  "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>",
…
```

Arguments after the image name replace `Cmd`: `true` went to nginx's
entrypoint script, which `exec`s anything but `nginx`. `--entrypoint`
replaces the entrypoint and drops `Cmd`, written as arguments for the
image's own entrypoint. Each `-e` replaces its name in place or is
appended; `PATH`, `HOSTNAME` and (with `-t`) `TERM` are added if
missing, and the runtime adds `HOME` from `/etc/passwd`, as runc does.
`image-run --entrypoint env -e NGINX_VERSION=custom -e DEBUG=1 nginx`
ran just `["env"]`, which printed the image's `Env` with
`NGINX_VERSION=custom` in its place, then `DEBUG=1`, `HOSTNAME=<id>` and
`HOME=/root`. `process.cwd` is `-w`, else `WorkingDir`, else `/`.

The annotations are conversion.md's implicit ones, then the `Labels`,
which take precedence as conversion.md requires (`maintainer`), then the
engine's own two, which no label can set: a config can't hold the digest
of the manifest that names it. `Volumes`, `Healthcheck`, `StopSignal` and
`ExposedPorts` wait for the daemon.

**User.** `User` or `-u` is `user[:group]`, names or numbers, and a name
means what the *image* says: uid 101 is `nginx` in the nginx image and
nobody in particular on the host. [`user.rs`](../../crates/rustlet-image/src/user.rs)
resolves it in the image's own `/etc/passwd` and `/etc/group`, by the
rules of runc's `GetExecUser`, which Docker uses:

```text
$ cargo xtask image-run alpine id
…
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
…
$ cargo xtask image-run -u nginx nginx id
…
uid=101(nginx) gid=101(nginx) groups=101(nginx)
…
```

Without a user the process is root, in every group that lists root, as
with `docker run alpine id`. A name brings its entry's ids and the groups
listing it: `-u daemon` gave `groups=1(bin),2(daemon),4(adm)`. A number
needs no entry: `-u 1234` ran as `1234:0`, in `groups=0(root)`. A group
replaces the supplementary ones: `-u daemon:wheel` gave only
`groups=10(wheel)`. The primary gid comes first in `additionalGids`, as
with `initgroups(3)`, and in Docker, Podman and containerd since
CVE-2022-36109: a process that ran a setgid program would otherwise lose
its primary group, and with it what a group-deny mode such as
`rw----r--` kept from it. Unlike runc, a malformed line is skipped (as
glibc skips it) rather than read with uid 0, and `4294967295`, which
`setresuid` takes as "unchanged", is refused.

The files are read by root on the host, with `openat2(RESOLVE_IN_ROOT |
RESOLVE_NO_MAGICLINKS)` from an fd of the mounted rootfs (an image's
`etc/passwd -> /etc/shadow` stays inside it), and only if they are
regular files of at most 1 MiB. A missing file reads as empty:
hello-world, built `FROM scratch`, has no `/etc` and ran as `0:0`.
Everything else in `config.json` is `default_spec()`'s, whatever the
image says: chapter 06's eleven capabilities, chapter 07's seccomp
profile, masked paths, `noNewPrivileges`, rlimits, mounts, namespaces.

## 9. Running it

`image-run` builds `rustlet-runc` as you, then reruns itself as root:
pull, unpack, mount the overlay (idmapped with `--userns`), write
`config.json`, and run `rustlet-runc run --bundle containers/<id>` in a
delegated `systemd-run --scope`, as `demo` does, for the device filter
and limits; then unmount and delete (`--keep`: only unmount). It ignores
`SIGINT` and friends meanwhile, to survive a Ctrl-C and clean up. There
is no network yet (Phase 5): the container's network namespace has only
`lo`.

```text
$ for f in "" --userns; do cargo xtask image-run $f alpine sh -c 'cat /proc/self/uid_map; stat -c "%u:%g %n" /bin/busybox /etc/shadow'; done
…
         0          0 4294967295
0:0 /bin/busybox
0:42 /etc/shadow
…
         0    1000000      65536
0:0 /bin/busybox
0:42 /etc/shadow
…
```

The same owners, though the second time container root is host uid
1000000: the layers on disk say 0 and 42, and the idmapped mounts
translate. The container's writes go to its upper layer, owned by host
1000000, and a deleted lower file becomes overlay's whiteout:

```text
$ cargo xtask image-run --keep --userns alpine sh -c 'touch /new; rm /etc/motd'
…
$ cargo xtask images ls -R containers/029c8ca1b3d1/upper
containers/029c8ca1b3d1…/upper:
d0755 1000000:1000000       4096  etc
-0644 1000000:1000000          0  new

containers/029c8ca1b3d1…/upper/etc:
c0000       0:0             0, 0  motd  [whiteout: deletes it from the lower layers]
```

nginx, serving its page over loopback in its own network namespace:

```text
$ cargo xtask image-run nginx bash -c '/docker-entrypoint.sh nginx -g "daemon off;" & sleep 2; exec 3<>/dev/tcp/127.0.0.1/80; printf "GET / HTTP/1.0\r\n\r\n" >&3; head -1 <&3; awk "/^Name/{n=\$2} /^Uid/{if (n==\"nginx\") print n, \$2}" /proc/[0-9]*/status | sort | uniq -c; nginx -s quit; wait'
…
/docker-entrypoint.sh: Configuration complete; ready for start up
…
127.0.0.1 - - [01/Oct/2026:15:53:28 +0000] "GET / HTTP/1.0" 200 896 "-" "-" "-"
HTTP/1.1 200 OK
      1 nginx 0
      4 nginx 101
…
```

The image has no `User`: the master starts as root and switches its
workers to 101 itself (`user  nginx;` in `nginx.conf`), which is what
`CAP_SETUID` and `CAP_SETGID` are for among the default eleven. Its logs
come through the symlinks `/var/log/nginx/access.log -> /dev/stdout` and
`error.log -> /dev/stderr`.

With `--userns` and `cat /proc/self/uid_map; ls -l /var/log/nginx
/proc/self/fd/2` in front, the run printed `0 1000000 65536`, fd 2 as a
`pipe:`, those two symlinks, and then the same as above. Before this
phase's fix it stopped at `error.log`. **Opening `/dev/stderr` opens the
pipe behind fd 2 afresh**, permission check included, and an inherited
pipe belongs to a host user the container's namespace doesn't map,
beyond container root's `CAP_DAC_OVERRIDE`: writing to fd 2 worked, the
open got `EACCES`. Now, like runc, `rustlet-runc` gives a foreground
user-namespace process without a terminal pipes of its own and relays
them ([`stdio.rs`](../../crates/rustlet-runtime/src/stdio.rs)), chowned
to the process's own user (runc's belong to container root, which leaves
a non-root process with `EACCES`):

```text
$ cargo xtask image-run --userns -u nginx nginx sh -c 'id -u; stat -L -c "%u:%g %a %F" /proc/self/fd/2; echo reopened > /dev/stderr'
…
101
101:101 600 fifo
reopened
…
```

The pipes belong to host 1000101. The same `stat` rootful showed my
shell's pipe, `1000:1000 600 fifo`, which container root, being host
root, may reopen. Last, python:3-slim on nginx's Debian snapshot; with
`--userns`, `os.stat` of its interpreter gave `0 0 0o755` under the map
`0 1000000 65536`:

```text
$ cargo xtask image-run python:3-slim python3 -c 'import sys, ssl, sqlite3; print(sys.version); print(ssl.OPENSSL_VERSION, "| sqlite", sqlite3.sqlite_version)'
…
  layer  a6dc765193a5 already unpacked
…
3.14.7 (main, Sep 19 2026, 01:01:59) [GCC 14.2.0]
OpenSSL 3.5.7 9 Jun 2026 | sqlite 3.46.1
…
```

## 10. Try it

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo xtask image-run alpine id                  # the first run pulls from Docker Hub
cargo xtask image-run nginx true
cargo xtask image-run python:3-slim python3 -V   # its Debian base layer is nginx's
cargo xtask images inspect nginx --json | less
cargo xtask image-run --pull always --json-progress alpine true   # one HEAD, nothing downloaded
cargo xtask image-run --keep nginx true          # note the id on the "kept" line
cargo xtask images cat containers/<id>/config.json | jq '.process.args, .process.env, .annotations'
cargo xtask image-run --userns -u nginx nginx id
cargo xtask images prune-containers              # what --keep left
cargo test -p rustlet-image                      # fake registry, unpack, user, runspec: no root
cargo xtask itest -- im_                         # the privileged image tests
```

From a name to every chain ID, to compare with `images inspect nginx`:

```sh
blob() { cargo xtask images cat "content/blobs/sha256/${1#sha256:}"; }
manifest=$(cargo xtask images cat content/index.json |
  jq -r '.manifests[] | select(.annotations["org.opencontainers.image.ref.name"] == "docker.io/library/nginx:latest") | .digest')
config=$(blob "$manifest" | jq -r .config.digest)
chain=
for diff in $(blob "$config" | jq -r '.rootfs.diff_ids[]'); do
  if [ -z "$chain" ]; then chain=$diff; else chain=sha256:$(printf '%s %s' "$chain" "$diff" | sha256sum | cut -d' ' -f1); fi
  echo "${chain:7:12}"
done
```

§3's curl session needs no privileges; every manifest GET counts against
the limit. `sudo -n scripts/cleanup.sh` unmounts anything left under
`/var/lib/rustlet`; only `--purge` deletes the store. The recorded runs
ended with `24 /proc/self/mountinfo`.

## Check yourself

1. Today `alpine:3.24` and `alpine:latest` are one index. Why does
   `images inspect alpine:3.24` fail? What would `--pull always
   alpine:3.24` fetch, and what would it skip?
2. Which digest of a layer does the manifest give, which the config, and
   which says what ends up on disk? Why check both, to the last byte?
3. Compute nginx's third chain ID by hand. Which snapshots would an image
   with nginx's diff IDs in another order share with nginx?
4. Unpacking a layer gives the same directory whatever lies below it.
   What does keying snapshots by chain ID cost, and what does it buy?
5. A layer holds `etc -> /srv/etc`, then `etc/passwd`. Where does the
   file go if the layer has `srv/etc/`, and if it hasn't? What would
   `RESOLVE_BENEATH` have done?
6. `-u daemon` gives three groups, `-u daemon:wheel` one. Why? What does
   the primary gid in `additionalGids` protect?
7. Under `--userns`, nginx could write to fd 2 but not open its
   `error.log`. Why? Why chown the new pipes to the process's own user
   rather than to container root?

## Experiments

- Pull a second tag of a stored image (`cargo xtask image-run alpine:3.24
  true`, a pull from Docker Hub). Which blobs does it download? Compare
  `images` and `images cat content/index.json` before and after: two
  names, one manifest, and the other entries unchanged byte for byte.
- In a kept container, `rm /etc/motd; rm -r /etc/apk; mkdir /etc/apk`,
  then `images ls -R containers/<id>/upper/etc`: a whiteout and an opaque
  directory, overlay's forms of `.wh.motd` and `.wh..wh..opq` (chapter
  12). Finish with `prune-containers`.
- Predict `id` in alpine for `-u nobody`, `-u 405`, `-u guest:wheel` and
  `-u 0:4242` from `images cat snapshots/74d97c428c51/fs/etc/group`, then
  run them.
- `cargo xtask image-run --local-alpine local/mini id` imports the cached
  minirootfs offline ([`import.rs`](../../crates/rustlet-image/src/import.rs),
  the pull pipeline backwards). Compare its manifest and config with
  Docker Hub's alpine. Why has it no repo digest?
