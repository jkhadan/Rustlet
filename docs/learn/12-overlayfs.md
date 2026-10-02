# 12 — overlayfs: one image, many writable roots

[Chapter 11](11-oci-images.md) left an image in the store, its layers
unpacked into snapshots, one verified directory per layer. This chapter
builds containers on them. Every container of an image gets a root filesystem
made of the same snapshot directories, shared and never written, plus an
empty directory of its own for its changes, and overlayfs merges them
into one tree. Nothing is copied when a container starts, and nothing it
does reaches the image. With `--userns`, the same snapshots, owned by
uid 0 on disk, appear as the container's own through idmapped mounts.
And what must outlive a container lives outside its layers: volumes,
bind mounts and tmpfs mounts (§10, added in Phase 5).

Code: [`rootfs.rs`](../../crates/rustlet-image/src/rootfs.rs) (`ContainerRootfs`,
`mount_overlay`, `stage_idmapped`), [`snapshot.rs`](../../crates/rustlet-image/src/snapshot.rs),
[`unpack.rs`](../../crates/rustlet-image/src/unpack.rs) (whiteouts and opaque markers),
[`process.rs`](../../crates/rustlet-sys/src/process.rs) (`UsernsHolder`),
[`mount.rs`](../../crates/rustlet-sys/src/mount.rs) (`FsContext`), the runtime's
[`rootfs.rs`](../../crates/rustlet-runtime/src/rootfs.rs) (`HostTrees`, `open_rootfs`),
[`xtask/src/imagerun.rs`](../../xtask/src/imagerun.rs) and [`xtask/src/images.rs`](../../xtask/src/images.rs).
Volumes (§10): the daemon's [`volumes.rs`](../../crates/rustletd/src/volumes.rs) (`resolve_mounts`,
`prepare_volumes`, `create_volume`, `remove_volume`) and [`spec.rs`](../../crates/rustletd/src/spec.rs)
(`add_mounts`, `oci_mount`), [`copyup.rs`](../../crates/rustlet-image/src/copyup.rs) (`copy_up`, `is_empty`), and the
mount syntaxes in [`rustlet-spec`'s `volume.rs`](../../crates/rustlet-spec/src/volume.rs).
Tests: [`images.rs`](../../tests/tests/images.rs) (`cargo xtask itest -- im_`, 10 tests;
the overlay ones are `im_overlay_applies_whiteouts_and_opaque_directories`,
`im_container_writes_go_to_the_upper_layer` and `im_userns_idmapped_layers_show_container_root`)
and the unpack unit tests in [`unpack/tests.rs`](../../crates/rustlet-image/src/unpack/tests.rs); for volumes the three
`vol_` tests in [`daemon_network.rs`](../../tests/tests/daemon_network.rs) and copy-up's 14 unit tests.
Design: [architecture.md §2.4](../architecture.md#24-rustlet-image--oci-images-storage-snapshots).

The transcripts were recorded on 2026-10-01, kernel 7.0.0-34-generic, as
my normal user, without a terminal, with alpine, nginx and python:3-slim
already in the store. `cargo xtask image-run` and `cargo xtask images`
re-run themselves through `sudo`: the store, `/var/lib/rustlet`, is
root's. `$S` is a scratch directory of mine. Container ids, chain IDs and
digests (64 hex digits) are shortened to 12 characters plus `…`, which
`images ls` and `images cat` accept as prefixes; yours will differ. The host's
`/proc/self/mountinfo` had 24 lines before the first run and 24 after
the last, with every container gone and the kept ones pruned. §2, §9 and
§11 were recorded again later that day, after the mount gained a `source`
name and `redirect_dir=nofollow` (§3). §10's were recorded on 2026-10-02,
against the installed daemon of Phase 5 (`rustlet` is `sudo
target/debug/rustlet`).

## 1. One image, many writable roots

A python:3-slim container sees the files of four layers: 5,768 archive
entries, 114 MiB of data once unpacked. Copying them for each container
would cost that much disk and time at every start. overlayfs stacks
directories instead. The snapshots are read-only **lower** layers, one
writable **upper** directory per container sits on top, and the
container sees the **merged** view. Four names, and the layers that have
them:

```text
                          /etc/ld.so.cache  /etc/services  /etc/debian_version  /usr/local/bin/python
  upper    (rw)           ·                 ·              ·                    ·
  layer 3  c988b37db6e3…  ·                 ·              ·                    -> python3
  layer 2  48a931cab5ae…  4751 bytes        ·              ·                    ·
  layer 1  acc27b89f4a0…  ·                 12990 bytes    ·                    ·
  layer 0  a6dc765193a5…  4095 bytes        ·              5 bytes              ·
```

A lookup asks the layers from the top, and the first that has the name
wins: layer 2's `ld.so.cache` hides the Debian base's. A directory found
in several layers is **merged**, so `/etc` lists layers 0, 1 and 2
together. In the words of the kernel's overlayfs documentation
([Documentation/filesystems/overlayfs.rst](https://docs.kernel.org/filesystems/overlayfs.html)):
"If both actual lookups find directories, both are stored and a merged
directory is created, otherwise only one is stored: the upper if it
exists, else the lower." From inside:

```text
$ cargo xtask image-run python:3-slim sh -c 'stat -c "%s %n" /etc/ld.so.cache /etc/debian_version /etc/services /etc/adduser.conf; ls -l /usr/local/bin/python'
…
4751 /etc/ld.so.cache
5 /etc/debian_version
12990 /etc/services
3981 /etc/adduser.conf
lrwxrwxrwx 1 root root 7 Sep 19 01:03 /usr/local/bin/python -> python3
exited     611e03dbc24b: status 0
```

Writes only ever go to upper. No container can change a byte of a
snapshot, so any number of them can share one.

## 2. What a running container's root is

Start a container that prints the first line of its own mountinfo and
sleeps, and meanwhile read the host's, which needs no root. The `sed`
puts each option after the third comma on a line of its own:

```text
$ cargo xtask image-run python:3-slim sh -c 'head -1 /proc/self/mountinfo | sed "s/,/\n    /3g"; sleep 20' > $S/runA.log 2>&1 &
$ grep f828139c7122 /proc/self/mountinfo | sed 's/,/\n    /3g'
573 32 0:56 / /var/lib/rustlet/containers/f828139c7122…/rootfs rw,nodev,relatime shared:472 - overlay rustlet rw
    lowerdir+=/var/lib/rustlet/snapshots/c988b37db6e3…/fs
    lowerdir+=/var/lib/rustlet/snapshots/48a931cab5ae…/fs
    lowerdir+=/var/lib/rustlet/snapshots/acc27b89f4a0…/fs
    lowerdir+=/var/lib/rustlet/snapshots/a6dc765193a5…/fs
    upperdir=/var/lib/rustlet/containers/f828139c7122…/upper
    workdir=/var/lib/rustlet/containers/f828139c7122…/work
    redirect_dir=nofollow
    uuid=on
    nouserxattr
$ wait; cat $S/runA.log
…
652 654 0:56 / / rw,nodev,relatime - overlay rustlet rw
    lowerdir+=/var/lib/rustlet/snapshots/c988b37db6e3…/fs
    …                                            the same eight options
exited     f828139c7122: status 0
```

With [chapter 02](02-mounts-pivot-root.md)'s field guide:

- **`0:56`** is the overlay superblock's device number. The container's
  `/` has the same one: the same filesystem, not a second overlay (§8).
- **The mount point** is below mount 32, the host's `/`. `shared:472`
  says the overlay joined a peer group, because it was attached below a
  shared mount (§11). The container's root is private: no such field.
- **`nodev`** comes from `fsmount` (§3). **`rustlet`** is the source: an
  overlay has no device behind it, so the name is only a label, which
  `mount_overlay` sets to tell its mounts apart.
- **The superblock options** list the layers top first, then upper and
  work. `uuid=on` is the kernel's own choice for a new overlay, and
  `nouserxattr` means overlay keeps its markers in `trusted.overlay.*`.

Rustlets also sets `metacopy=off`, `index=off` and `redirect_dir=nofollow`.
Overlay prints an option only when it differs from the kernel's default.
Here `metacopy` and `index` are off by default, so they don't show, and
`redirect_dir`'s default is `off`, not `nofollow`; §3 explains all three.

The container's line shows host paths: the store, its layers' chain
IDs, its own id. That is information, not access. None of those paths
exists in its mount namespace, since the old root went at `pivot_root`
(chapter 02), and on the host they are below `0700` directories.

## 3. Building the mount

`ContainerRootfs::mount` creates `containers/<id>/` with `upper/` (0755),
`work/` (0700) and `rootfs/` (0755), then calls `mount_overlay`, chapter
02's fd-based mount API all the way:

```rust
// rootfs.rs, mount_overlay (error handling trimmed)
let ctx = FsContext::open("overlay")?;                  // fsopen
// Each `lowerdir+` goes below the ones before it.
for lower in lowers.iter().rev() {                      // `lowers` is bottom first
    config("lowerdir+", &utf8(lower)?)?;                // fsconfig(FSCONFIG_SET_STRING)
}
config("upperdir", &utf8(upper)?)?;
config("workdir", &utf8(work)?)?;
for (key, value) in [("redirect_dir", "nofollow"), ("metacopy", "off"), ("index", "off"), ("source", "rustlet")] {
    config(key, value)?;
}
let mnt = ctx.mount(MountAttr::NODEV)?;                 // FSCONFIG_CMD_CREATE, then fsmount
move_mount(Some(mnt.as_fd()), Path::new(""), None, target, MoveMountFlags::F_EMPTY_PATH)
```

`config` is `FsContext::set_string`, with the kernel's explanation from
the context's log added to any error; after a failure,
`ContainerRootfs::mount` leaves nothing behind. `MOUNT_ATTR_NODEV` makes
even the host's view of the overlay ignore device nodes.

**Why `lowerdir+`.** The classic option is one string,
`lowerdir=/top:/middle:/bottom`. A `:` in a path must be escaped (in
`mount(2)`'s option string, a `,` too), and the string has a size limit.
`mount(2)` copies one page of options, and Docker's overlay2 driver keeps
short symlinks in `/var/lib/docker/overlay2/l/` to stay below it. The new
API is stricter: `fsconfig` copies each string value into a 256-byte
buffer, NUL included (`strndup_user(_value, 256)` in `fs/fsopen.c`).
Overlay can be configured in a user namespace, so a script can try that
without root:

```text
$ cat $S/fsconfig-limit.py
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
def fsconfig(key, value):          # a fresh fsopen("overlay") context, one fsconfig call
    fd = libc.syscall(430, b"overlay", 1)
    ret = libc.syscall(431, fd, 1, key.encode(), value.encode(), 0)   # FSCONFIG_SET_STRING
    return "ok" if ret == 0 else errno.errorcode[ctypes.get_errno()]
for n in (255, 256):
    print(f"source   = {n} bytes: {fsconfig('source', 'x' * n)}")
for n in (2, 3):
    layers = ":".join(f"/var/lib/rustlet/snapshots/{c * 64}/fs" for c in "abc"[:n])
    print(f"lowerdir = {n} layers, {len(layers)} bytes: {fsconfig('lowerdir', layers)}")
$ cd $S && unshare -Urm python3 fsconfig-limit.py
source   = 255 bytes: ok
source   = 256 bytes: EINVAL
lowerdir = 2 layers, 189 bytes: EACCES
lowerdir = 3 layers, 284 bytes: EINVAL
```

A snapshot path is 94 bytes. Two got through, and the kernel resolved
them right there, inside `fsconfig` (`EACCES`: I am not host root, and
`snapshots/` is `0700`). Three never reached overlay, so `lowerdir=`
couldn't name python:3-slim's four layers. `lowerdir+` (Linux 6.8) takes
one path per call, with nothing to escape, and adds it *below* the layers
before it: hence the reversed loop over `lowers`, which is bottom first
like the manifest. Layers as fds (`FSCONFIG_SET_FD`) would need 6.13.

**upperdir and workdir.** Upper receives every change. Work is overlay's
scratch space: copy-ups and whiteouts are prepared there, then renamed
into upper, so a half-copied file is never visible. A rename can't cross
filesystems: "the 'workdir' needs to be a directory on the same
filesystem as upperdir".

**The three switches.** Each feature, when on, lets upper keep a
*reference into the lower layers* instead of a complete entry:

| option | on: upper gets | off |
|---|---|---|
| `redirect_dir` | a renamed lower directory as an empty directory whose `trusted.overlay.redirect` names its old path; the contents still come from below | `rename(2)` of a lower directory fails with `EXDEV` (§6) |
| `metacopy` | after `chmod`, `chown` or `touch`, a copy of the metadata only; the data stays in the lower file | the whole file is copied (§4) |
| `index` | an index of copied-up inodes in `work/`, so that hard links stay linked | copying up one name of a hard link breaks the link (§6) |

With all three off (`redirect_dir`'s "off" is spelled `nofollow` here, for
the reason below), every entry in upper is complete: files have all
their data, renamed directories are real copies, nothing points into a
lower layer. Phase 7's `commit` and builder will make a layer by walking
upper (architecture §2.4), which needs that self-contained diff. The
defaults belong to whoever built the kernel (`CONFIG_OVERLAY_FS_INDEX`
and friends) or loads the module. Here, `/sys/module/overlay/parameters/`
reads `index=N`, `metacopy=N`, `redirect_dir=N` and
`redirect_always_follow=Y`. The last makes `redirect_dir=off` mean
"create none, but follow one if found". Rustlets asks for `nofollow`:
create none and follow none. No layer should hold a redirect, since
unpacking drops every `trusted.overlay.*` and `user.overlay.*` attribute
(§5); with `nofollow` the mount itself would ignore one anyway, a second
barrier rather than a single one.

## 4. Copy-up

The first time a container modifies a lower file, overlay copies it up:
it creates the containing directories in upper, then the object "with the
same metadata (owner, mode, mtime, symlink-target etc.)", then copies a
file's data. `--keep` leaves the container's directory, unmounted:

```text
$ cargo xtask image-run --keep alpine sh -c 'echo changed >> /etc/motd; touch /bin/busybox; cat /etc/os-release > /dev/null; echo hi > /root/new; tail -n 2 /etc/motd'
…

changed
kept       /var/lib/rustlet/containers/3b2ff71d602f… (upper/ is the container's writable layer)
exited     3b2ff71d602f: status 0
$ cargo xtask images ls -R containers/3b2ff71d602f/upper
containers/3b2ff71d602f…/upper:
d0755       0:0             4096  bin
d0755       0:0             4096  etc
d0700       0:0             4096  root

containers/3b2ff71d602f…/upper/bin:
-0755       0:0           804616  busybox

containers/3b2ff71d602f…/upper/etc:
-0644       0:0              292  motd

containers/3b2ff71d602f…/upper/root:
-0644       0:0                3  new
$ diff <(cargo xtask images cat snapshots/74d97c428c51/fs/etc/motd) <(cargo xtask images cat containers/3b2ff71d602f/upper/etc/motd)
10a11
> changed
$ cargo xtask images ls snapshots/74d97c428c51/fs/etc | grep motd
-0644       0:0              284  motd
```

`74d97c428c51` is alpine's chain ID, from `images inspect alpine`. The
snapshot's `motd` is still 284 bytes; the copy is 292, the original plus
`changed\n`. Each command left a different trace:

- **`echo >> /etc/motd`** copied the file up, with `etc/` around it. That
  `etc/` is not opaque, so `/etc` still merges with the lower one.
- **`touch /bin/busybox`** changed only timestamps, and all 804,616 bytes
  were copied: `metacopy=off`.
- **`cat /etc/os-release`** left nothing. Reads never copy.
- **`echo hi > /root/new`** made a new file, and `/root` was copied up
  with its mode, `0700`.

Copy-up happens once per file; later writes go to the copy. It costs the
size of the file, at the first write however small. Data that keeps
changing, such as a database, belongs in a volume (Phase 5).

## 5. Deleting: whiteouts and opaque directories

A lower file can't be deleted, so overlay records the deletion in upper:

```text
$ cargo xtask image-run --keep alpine sh -c 'rm /etc/issue; rm -r /etc/profile.d; mkdir /etc/profile.d; echo "export EDITOR=vi" > /etc/profile.d/mine.sh; ls /etc/profile.d; ls /etc/issue; echo x > /tmp/scratch; rm /tmp/scratch'
…
mine.sh
ls: /etc/issue: No such file or directory
kept       /var/lib/rustlet/containers/73ee02b8168c… (upper/ is the container's writable layer)
exited     73ee02b8168c: status 0
$ cargo xtask images ls -R containers/73ee02b8168c/upper
containers/73ee02b8168c…/upper:
d0755       0:0             4096  etc
d1777       0:0             4096  tmp

containers/73ee02b8168c…/upper/etc:
c0000       0:0             0, 0  issue  [whiteout: deletes it from the lower layers]
d0755       0:0             4096  profile.d  [opaque: hides the lower layers' entries]

containers/73ee02b8168c…/upper/etc/profile.d:
-0644       0:0               17  mine.sh

containers/73ee02b8168c…/upper/tmp:
$ cargo xtask images ls snapshots/74d97c428c51/fs/etc/profile.d
snapshots/74d97c428c51…/fs/etc/profile.d:
-0644       0:0               97  20locale.sh
-0644       0:0              249  README
-0644       0:0              447  color_prompt.sh.disabled
```

- **A whiteout** is "a character device with 0/0 device number", like
  `upper/etc/issue`. A lookup that meets one stops: the name doesn't
  exist, and the whiteout itself is hidden.
- **An opaque directory** has `trusted.overlay.opaque=y`. `rm -r` left a
  whiteout named `profile.d`, and `mkdir` over it made a new directory,
  marked opaque so that the snapshot's three files stay hidden. Unmarked,
  it would merge with the old one.
- **`/tmp/scratch`** had nothing below it to hide, so it left nothing.

`work/` holds overlay's `work/work`, mode `0000`, and here `images ls -R`
showed a whiteout in it, `#147`: overlay makes one whiteout of its own
and creates the others as hard links to it. A diff of upper must leave
`work/` out and not take whiteouts for hard links of each other.

**The same markers in image layers.** A layer tar marks deletions the OCI
image spec's way (`layer.md`): an empty `.wh.<name>` deletes `name` from
the layers below, and `.wh..wh..opq` hides everything the layers below
have in its directory. Unpacking (chapter 11) turns the first into a
character device 0:0, the same shape as `upper/etc/issue`, and the second
into `trusted.overlay.opaque=y`. An image can't supply overlay's own
markers: a 0:0 device entry is skipped like every device node, and
`trusted.overlay.*` attributes in PAX headers are dropped
(`devices_are_skipped_and_overlay_attributes_dropped`). A snapshot's
markers refer to the snapshots below it, which is why snapshots are
keyed by chain ID.

One rule needs care. A whiteout applies only to the layers below: "Files
that are present in the same layer as a whiteout file can only be hidden
by whiteout files in subsequent layers." So a layer holding `.wh.x` and
`x/new` says the old `x` is gone and this layer's `x` holds `new`. In
one directory, `x` can't be both a whiteout and a directory, and
overlay's way to say "this directory replaces the one below" is an
opaque directory. Unpacking makes `x` opaque whichever comes first in the
archive: the whiteout, the directory, or a file that creates `x`
(`a_directory_meeting_its_own_whiteout_is_opaque`).

None of the 11 snapshots in this store has either marker (`images ls -R
snapshots/<chain>/fs | grep -c whiteout` printed 0 for each), so the
tests build their own: in `im_overlay_applies_whiteouts_and_opaque_directories`,
layer L1 deletes `etc/a` and `gone` and makes `doc` opaque, and a real
overlay shows them gone and only L1's `z` in `doc`, until L2 brings
`etc/a` back. `im_container_writes_go_to_the_upper_layer` repeats §4 and
this section in code.

## 6. Renames and hard links

Two of §3's switches have visible costs:

```text
$ cargo xtask image-run --keep python:3-slim sh -c 'python3 -c "import os; os.rename(\"/etc/apt\", \"/etc/apt.old\")" 2>&1 | tail -n 1; mv /etc/apt /etc/apt.old && echo "mv: ok"; stat -c "%h %s %n" /usr/bin/perl /usr/bin/perl5.40.1; echo "# appended" >> /usr/bin/perl; stat -c "%h %s %n" /usr/bin/perl /usr/bin/perl5.40.1'
…
OSError: [Errno 18] Invalid cross-device link: '/etc/apt' -> '/etc/apt.old'
mv: ok
2 3935376 /usr/bin/perl
2 3935376 /usr/bin/perl5.40.1
1 3935387 /usr/bin/perl
2 3935376 /usr/bin/perl5.40.1
…
$ cargo xtask images ls containers/725e3fb76773/upper/etc
containers/725e3fb76773…/upper/etc:
c0000       0:0             0, 0  apt  [whiteout: deletes it from the lower layers]
d0755       0:0             4096  apt.old
```

**`redirect_dir=nofollow`**: no redirects, so renaming a lower directory fails with `EXDEV`,
the error for a move across filesystems, and `mv` falls back to copying
the tree: a whiteout for `apt` and a full `apt.old`, where `redirect_dir=on`
would leave an empty `apt.old` with a `trusted.overlay.redirect` back to
`apt`. **`index=off`**: `perl` and `perl5.40.1` are two names of one file,
python:3-slim's only hard link. After the append, `perl` is a copy of its
own in upper, and `perl5.40.1` is still the lower file, claiming a second
link: "If this feature is disabled and a file with multiple hard links is
copied up, then this will 'break' the link." Both costs are rare, and
they buy an upper that stands on its own.

## 7. Sharing snapshots

Two python:3-slim containers and one nginx container run `sleep 40` at
the same time. For each overlay, the chain IDs of its layers, top first,
then the upper directories, then nginx's bottom layer:

```text
$ cargo xtask image-run python:3-slim sleep 40 > $S/runD1.log 2>&1 &
$ cargo xtask image-run python:3-slim sleep 40 > $S/runD2.log 2>&1 &
$ cargo xtask image-run nginx sleep 40 > $S/runD3.log 2>&1 &
$ for id in 0822bb71b562 48612070be35 fbcd8a299ea2; do echo "$id: $(grep $id /proc/self/mountinfo | grep -o 'lowerdir+=[^,]*' | cut -d/ -f6 | cut -c1-12 | paste -sd' ')"; done
0822bb71b562: c988b37db6e3 48a931cab5ae acc27b89f4a0 a6dc765193a5
48612070be35: c988b37db6e3 48a931cab5ae acc27b89f4a0 a6dc765193a5
fbcd8a299ea2: a159a9f67216 a5cc515e2f65 84b204602429 2946e85fd097 16900e0bded0 49049a42a1d2 a6dc765193a5
$ grep -E '0822bb71b562|48612070be35|fbcd8a299ea2' /proc/self/mountinfo | grep -o 'upperdir=[^,]*'
upperdir=/var/lib/rustlet/containers/fbcd8a299ea2…/upper
upperdir=/var/lib/rustlet/containers/48612070be35…/upper
upperdir=/var/lib/rustlet/containers/0822bb71b562…/upper
$ cargo xtask images inspect nginx | grep -A1 'CHAIN ID'
  #   BLOB                 SIZE DIFF ID        CHAIN ID       SNAPSHOT
  0   6b37362b3da7     28.4 MiB a6dc765193a5   a6dc765193a5   3269 entries, 75.2 MiB
```

The python containers share all four snapshots, all three share the
bottom one, and each has its own upper. nginx and python:3-slim are both
built on Debian trixie-slim, and `images inspect python:3-slim` prints
the same row 0: same blob, diff ID and chain ID. That snapshot was
unpacked once, when nginx came in, and python found it there (chapter 11).

Sharing rests on one promise: **a snapshot never changes**. "Changes to
the underlying filesystems while part of a mounted overlay filesystem are
not allowed. If the underlying filesystem is changed, the behavior of the
overlay is undefined, though it will not result in a crash or deadlock."
Overlay caches lookups and merged directories, so a change below may show
or not. Rustlets' snapshots are immutable by construction: unpacked under
`snapshots/.tmp-*`, verified, renamed into place, never written again.
That leaves deletion, which is such a change while any container uses the
snapshot, so the daemon (Phase 4) will have to know which ones are in use.

## 8. How the runtime uses it

image-run's `config.json` names the overlay's mount point as `root.path`,
writable unless `--read-only`:

```text
$ cargo xtask images cat containers/3b2ff71d602f/config.json | jq .root
{
  "path": "/var/lib/rustlet/containers/3b2ff71d602f…/rootfs",
  "readonly": false
}
```

To `rustlet-runc` it is a rootfs like any other. Before `clone3` the
parent opens it (`HostTrees::open` → `open_rootfs`,
[chapter 09](09-user-namespaces.md) §4) with
`open_tree(OPEN_TREE_CLONE | AT_RECURSIVE)`, and `mount_setattr` sets
`nodev` and private propagation on the copy: a detached second mount of
the same superblock, hence §2's `0:56` inside. Init attaches it on top of
`/` and `pivot_root`s into it (chapters 02 and 09). Unless made private,
a copy of a shared mount joins its peer group (`shared:472`), and mounts
init makes on it could propagate to the host's side.

Why doesn't the `0700` store get in the way, even for host uid 1000000?
Root resolves every path into it: image-run in `fsconfig`, after which
overlay holds the layers, and `rustlet-runc`'s parent when it opens
`containers/<id>/rootfs` (the store root is `0711` for that). The
container's processes never walk these paths; their `/` is the clone.
When they open a file, overlay checks their credentials against the
overlay inode, which has the file's owner and mode, and then, per the
documentation's permission model, the credentials of "the task creating
the superblock through FSCONFIG_CMD_CREATE", stashed then, against the
real file. That task was host root.

## 9. User namespaces: idmapped layers

Snapshots keep the image's ids: `/bin/busybox` is uid 0's on disk. With
`--userns`, container root is host uid 1000000 (chapter 09), and through
a plain overlay a file of host uid 0 would be `nobody`'s inside, out of
reach of container root's capabilities (chapter 09 §2). Phase 2c's test
bundle has its owners shifted on disk (`cargo xtask rootfs --remap`); in
a store, that would mean a second copy of every image. Instead, each
snapshot is used through an **idmapped mount** (chapter 09 §7) that reads
on-disk id *k* as host id 1000000 + *k*.

An idmapped mount takes its mapping from a user namespace, and the
kernel makes user namespaces only for processes. The container doesn't
exist yet, so `mount_layers` and `stage_idmapped` use a stand-in:

1. Upper is chowned to 1000000:1000000, since the merged root is upper's.
2. `UsernsHolder::spawn` clones a child with `CLONE_NEWUSER | CLONE_PIDFD`
   that closes every fd but a pipe's read end and blocks on it.
3. `DirectIdMapper`, the runtime's `IdMapper` (chapter 09 §3), writes the
   child's maps, `0 1000000 65536`, and `open_ns` opens
   `/proc/<pid>/ns/user`. Dropping the holder lets the child exit; the
   namespace lives while the fd, and then the mounts, refer to it.
4. Each layer gets `open_tree(OPEN_TREE_CLONE)` of its `fs/`,
   `mount_setattr(MOUNT_ATTR_IDMAP)` with that namespace, and an attach
   at `containers/<id>/lower/<n>` (`0700`). The overlay is made from
   those paths, and then `Staged`'s `Drop` detaches them.

The trees are attached because overlay takes each layer through
`clone_private_mount`, which before Linux 6.15 refused a mount not
attached in the caller's mount namespace. Overlay keeps private clones,
so the staged mounts can go as soon as it exists.

`Clone3::spawn` refuses a multithreaded caller
([chapter 01](01-namespaces-intro.md) §6), because its child runs
arbitrary code. The holder's child makes only raw system calls
(`close_range`, `read`, `_exit`) on values computed before the clone,
which are async-signal-safe: POSIX's condition for the child of a fork in
a multithreaded process, such as the daemon (Phase 4). A remapped run,
with a look at the host side while it sleeps:

```text
$ cargo xtask image-run --userns --keep alpine sh -c 'stat -c "%u:%g %n" / /bin/busybox /etc/shadow; touch /made-here; stat -c "%u:%g %n" /made-here; id -u; sleep 15' > $S/runE.log 2>&1 &
$ grep 9c94de94669f /proc/self/mountinfo | sed 's/,/\n    /3g'
504 32 0:56 / /var/lib/rustlet/containers/9c94de94669f…/rootfs rw,nodev,relatime shared:550 - overlay rustlet rw
    lowerdir+=/var/lib/rustlet/containers/9c94de94669f…/lower/0
    upperdir=/var/lib/rustlet/containers/9c94de94669f…/upper
    workdir=/var/lib/rustlet/containers/9c94de94669f…/work
    redirect_dir=nofollow
    uuid=on
    nouserxattr
$ cargo xtask images ls containers/9c94de94669f
containers/9c94de94669f…/:
-0644       0:0            18366  config.json
d0755 1000000:1000000       4096  rootfs
d0755 1000000:1000000       4096  upper
d0700       0:0             4096  work
$ cargo xtask images ls containers/9c94de94669f/rootfs/bin | grep ' busybox$'
-0755 1000000:1000000     804616  busybox
                                            (and 81 symlinks to it, all 1000000:1000000)
$ wait; cat $S/runE.log
…
rootfs     /var/lib/rustlet/containers/9c94de94669f…/rootfs (overlay of 1 layers, idmapped)
run        9c94de94669f: ["sh", "-c", "stat -c \"%u:%g %n\" / /bin/busybox /etc/shadow; …"] as 0:0 in /, user namespace 0 → 1000000
0:0 /
0:0 /bin/busybox
0:42 /etc/shadow
0:0 /made-here
0
…
$ cargo xtask images ls containers/9c94de94669f/upper
containers/9c94de94669f…/upper:
-0644 1000000:1000000          0  made-here
$ cargo xtask images ls snapshots/74d97c428c51/fs/bin | grep ' busybox$'
-0755       0:0           804616  busybox
```

One file, three views: `busybox` is 0:0 on disk, 1000000:1000000 through
the overlay (for the host too, since the idmapping belongs to the mount),
and 0:0 inside, where the container's user namespace maps 1000000 back
to 0. `/` is 0:0 inside because upper is 1000000:1000000. What container
root creates is stored as host 1000000.

While the container ran, `lower/` was already gone, yet mountinfo still
says `lowerdir+=…/lower/0`: options are recorded as given, so whatever
needs to know which snapshots a container uses, such as a future
`image rm`, can't learn it from mountinfo. And copy-up stores the
idmapped owner:

```text
$ cargo xtask image-run --userns --keep alpine sh -c 'echo x >> /etc/motd; chown 5:5 /etc/issue; stat -c "%u:%g %n" /etc /etc/motd /etc/issue'
…
0:0 /etc
0:0 /etc/motd
5:5 /etc/issue
…
$ cargo xtask images ls -R containers/3968ada2b41c/upper
containers/3968ada2b41c…/upper:
d0755 1000000:1000000       4096  etc

containers/3968ada2b41c…/upper/etc:
-0644 1000005:1000005         51  issue
-0644 1000000:1000000        286  motd
```

Snapshots hold image ids, but a remapped container's upper holds host
ids, so a commit of it (Phase 7) will have to map them back.
`im_userns_idmapped_layers_show_container_root` checks this section, down
to a single new host mount with no staged layer left.

## 10. Volumes: storage outside the layers

Everything so far happens in a container's own upper layer: written by the
container, mapped to host ids under `--userns`, gone with `rm`. Data that
must outlive the container, or be shared between containers, or be
written fast and often without overlay's copy-up, belongs outside the
layers altogether: in mounts over parts of the tree, which the overlay
never sees. Phase 5 added three kinds ([`volume.rs`](../../crates/rustlet-spec/src/volume.rs) in
`rustlet-spec`, with Docker's three syntaxes `-v`, `--mount` and
`--tmpfs`):

| kind | what is mounted | lives |
|---|---|---|
| volume | `<data root>/volumes/<name>/_data`, a directory the daemon keeps | until `volume rm` (an anonymous one: until its container is removed with `--rm` or `rm -v`) |
| bind | a host directory or file | it is the host's |
| tmpfs | a new tmpfs (`nosuid,nodev,noexec` unless asked otherwise) | until the container stops |

**A volume** is a directory and a row in `state.db`
([`volumes.rs`](../../crates/rustletd/src/volumes.rs) in the daemon): `volumes/` is `0700`, root's,
`<name>/_data` is what containers see. `-v data:/var/lib/data` names one,
and creates it if it doesn't exist (Docker's rule); `-v /var/lib/data`
names none, and so does every `VOLUME` of the image that no mount covers:
those become **anonymous** volumes with 64-hex-digit names. All of this is
decided once, at `create`, and recorded with the container (its
`Record.mounts`), so every start mounts the same volumes. A volume named in
any container's record, running or not, is in use and can't be removed;
`rm -v` and `--rm` take the anonymous volumes made for a container with
it (the record lists them), never a volume it was given by name, even an
anonymous one (`volume create` without a name makes one), as Docker keeps
"named mountpoints" (`vol_rm_keeps_a_volume_given_by_name`; the
independent review found the first version deleting those too):

```text
$ rustlet run -d --name anon -v /scratch alpine sleep 60; rustlet inspect anon | grep -B2 -A6 '"mounts"'; rustlet volume ls; rustlet rm -f -v anon; rustlet volume ls
db18d39d52dc7b6dc8b26b4cc4dd08fe587c58576155838b65c06413500c0f4f
…   (first, the mount as given at create: no source)
    "mounts": [
      {
        "destination": "/scratch",
        "name": "fa36074633c968dd090da5919530b1a119f411e47a377464890b8f1451202c18",
        "read_only": false,
        "source": "/var/lib/rustlet/volumes/fa36074633c9…/_data",
        "type": "volume"
DRIVER    VOLUME NAME
local     fa36074633c968dd090da5919530b1a119f411e47a377464890b8f1451202c18
local     pgdata
anon
DRIVER    VOLUME NAME
local     pgdata
```

The image's `VOLUME`s are untrusted input like the rest of its config: one
that names a path the runtime keeps for itself (`/`, `/proc`, `/sys`,
`/dev`, …) is refused at `create`, with the same check a `-v` gets, rather
than failing every start later in the runtime. (That check was missing
until this chapter was written, and `VOLUME /sys` would have been
accepted.)

### Populating an empty volume

The name collides with §4's, so one sentence to keep them apart: §4's
*copy-up* is overlayfs copying a lower file into upper the first time a
container writes it; what follows is the daemon copying the image's files
into a new volume before the container starts. Docker's documentation
calls both copying up; this chapter calls the second **populating** the
volume.

A volume mounted over a path where the image has files would hide them:
`-v pgdata:/var/lib/postgresql/data` over an empty volume, and the program
finds an empty directory where its image put its defaults. So, as Docker
does, an **empty** volume gets a copy of what the image has at its mount
point, at each start, after the overlay is mounted and before the
container exists (`prepare_volumes`; `-v data:/x:nocopy` or
`volume-nocopy` says not to):

```text
$ rustlet run --rm -v pgdata:/etc/apk alpine ls -l /etc/apk; rustlet volume ls; rustlet volume inspect pgdata
total 20
-rw-r--r--    1 root     root             7 Sep 17 17:32 arch
drwxr-xr-x    2 root     root          4096 Sep 17 17:32 keys
drwxr-xr-x    2 root     root          4096 Sep 17 17:32 protected_paths.d
-rw-r--r--    1 root     root           103 Sep 17 17:32 repositories
-rw-r--r--    1 root     root            74 Sep 17 17:32 world
DRIVER    VOLUME NAME
local     pgdata
[
  {
    "anonymous": false,
    "containers": [],
    …
    "mountpoint": "/var/lib/rustlet/volumes/pgdata/_data",
    "name": "pgdata"
  }
]
```

The copy reads the **merged** root filesystem, the overlay: the image's
layers with the container's own changes on top, whiteouts already applied
(a deleted file isn't copied, an opaque directory hides its lower
content) and overlay's own attributes invisible. It is image content, so
untrusted, and the daemon is root, so it is made the way chapter 11's
unpacking is ([`copyup.rs`](../../crates/rustlet-image/src/copyup.rs)):

- the mount point is resolved **inside** the root filesystem
  (`openat2(RESOLVE_IN_ROOT)`): an image whose `/var/run` is a symlink to
  `/run` gets the container's `/run` copied, never the host's;
- **below it, nothing is followed**: each entry is examined with
  `AT_SYMLINK_NOFOLLOW`, only regular files and directories are opened
  (`O_NOFOLLOW`, and `O_NONBLOCK|O_NOCTTY` in case something else took
  their place), and a symlink is copied as a symlink, whatever it names;
- the volume is written only **through fds** below its directory, every
  entry created exclusively (`O_EXCL`, `mkdirat`, `symlinkat`, `mkfifoat`,
  `linkat`);
- **kept**: contents, owners, modes (after the owner, since `chown` clears
  setuid bits), extended attributes (after the owner, which clears
  `security.capability`), times (a directory's last, once its contents
  are done), hard links within the copied tree, FIFOs; **skipped**, and
  listed in the daemon's log: device nodes and sockets;
- the volume's directory takes the source directory's owner and mode
  (Docker's `copyOwnership`), and the walk uses a stack of its own, at
  most 4096 levels deep, not the daemon's.

One copy runs at a time per volume. A copy that fails halfway takes back
what it made at the top of the volume, and only that: half a copy would
count as content, and no later start would try again; but a container
already running with the volume may have written there meanwhile (which
is what usually makes the copy fail, an entry that is already there), and
its files stay. (The first version emptied the whole volume, those files
too; the independent review found it.) A daemon killed during a copy
leaves the half copy, as Docker does. A volume that isn't empty is never
touched, so a second
container mounting it elsewhere sees the first one's data:
`vol_named_volumes_copy_up_once_and_persist` writes a marker through one
container and reads it through another, with no second copy.

### Volumes under `--userns=remap`

Through §9's idmapped layers, the image's files appear as owned by
1000000 + their ids, and a remapped container's root is host uid
1000000. A volume populated as it reads, and written by that root, would
hold host ids: usable by remapped containers, owned by an unmapped
"nobody" for everyone else. Rustlets mounts volumes into a remapped
container **idmapped** instead, with the same `MOUNT_ATTR_IDMAP` as §9's
layers (the runtime's `idmap` mount option, set by
[`spec::oci_mount`](../../crates/rustletd/src/spec.rs)), so that on-disk uid 0 *is* container root,
and populating translates the shifted owners back (and the ids a file
capability or an ACL names). The same volume, used by a remapped
container:

```text
$ rustlet run --rm --userns remap -v pgdata:/etc/apk alpine sh -c 'touch /etc/apk/remapped; ls -ln /etc/apk; cat /proc/self/uid_map'
-rw-r--r--    1 0        0                7 Sep 17 17:32 arch
drwxr-xr-x    2 0        0             4096 Sep 17 17:32 keys
…
-rw-r--r--    1 0        0                0 Oct  2 08:15 remapped
…
         0    1000000      65536
$ sudo ls -ln /var/lib/rustlet/volumes/pgdata/_data
…
-rw-r--r-- 1 0 0    0 Oct  2 04:15 remapped
…
```

Container root (host uid 1000000) created `remapped`, and it is uid 0 on
disk: one volume, the same files, whichever kind of container mounts it
(`vol_userns_volumes_are_idmapped` checks both). Host directories bound
with `-v /host:/c` keep the host's owners (host root shows as `nobody`
inside, as with Docker) unless the mount says `idmap`, as Podman offers.
Docker solves the same problem differently: with `userns-remap` it keeps a
separate data root, volumes included, per remapping
(`/var/lib/docker/1000000.1000000/`).

### The mounts, as the runtime gets them

[`spec::add_mounts`](../../crates/rustletd/src/spec.rs) turns the recorded mounts into OCI mounts: a
volume is an `rbind` of its `_data`, a bind an `rbind` of the host path,
both `rprivate` (the runtime allows no other propagation), `ro` or `rw`, and
`idmap` as above; a tmpfs gets `nosuid,nodev,noexec`, then the user's
flags (the runtime takes the last word of each pair, so `exec` undoes
`noexec`), `size=` and `mode=`. They are sorted by depth, so `/data` is
mounted before `/data/cache`; a mount on a default destination (`--tmpfs
/dev/shm`) replaces the default; and the generated `/etc/hosts`,
`hostname` and `resolv.conf` ([chapter 16](16-dns.md)) are skipped where a mount
covers them. `vol_anonymous_bind_and_tmpfs_mounts` checks a read-only
bind, a host directory `-v` created, an image `VOLUME` and a tmpfs with its
options, all in one container.

## 11. Limits and gotchas

- **500 lower layers** is overlay's `OVL_MAX_STACK`. `ContainerRootfs::mount`
  refuses more, and none, before it calls the kernel.
- **Upper's filesystem** "must support the creation of trusted.* and/or
  user.* extended attributes, and must provide valid d_type in readdir
  responses, so NFS is not suitable". Snapshots need `trusted.*` too,
  which takes `CAP_SYS_ADMIN` to set: one reason unpacking runs as root.
- **The merged root is upper's**, owner and mode. Without §9's chown, `/`
  would belong to an unmapped host root, and container root couldn't
  create anything in it.
- **Propagation.** The host-side overlay is attached under `/`, which is
  `shared` on a systemd host, so it propagates to every mount namespace
  that receives events from `/`. §2's run had a companion, started just
  before it: `unshare -Urm --propagation slave sleep 90 &` (pid 93954), a
  namespace of mine that receives the host's events:

  ```text
  $ grep f828139c7122 /proc/93954/mountinfo | cut -d' ' -f1-10
  574 486 0:56 / /var/lib/rustlet/containers/f828139c7122…/rootfs rw,nodev,relatime master:472 - overlay rustlet
  $ grep -c f828139c7122 /proc/93954/mountinfo          # after the container exited
  0
  ```

  The unmount propagated too. If a copy is busy, a plain `umount2` fails
  with `EBUSY`, and `ContainerRootfs::unmount` detaches lazily instead.
- **Overlay's bookkeeping.** Besides `work/` (§5), upper collects
  attributes: `trusted.overlay.uuid` on its root (`uuid=on`), `origin` on
  copied-up entries, `impure` on directories holding them. They hold no
  content, and a diff must skip them. An unprivileged overlay shows them
  as `user.overlay.*`.
- **Cleaning up.** image-run deletes `containers/<id>` when the container
  exits; `--keep` only unmounts. `cargo xtask images prune-containers`
  deletes what `--keep` left, skipping any directory with a mount below
  it. `sudo scripts/cleanup.sh` unmounts everything under
  `/var/lib/rustlet` and `/run/rustlet`; `--purge` deletes the store too.

## 12. Try it

From the repository, as your normal user, with chapter 11's images:

```sh
export PATH=$HOME/.cargo/bin:$PATH
grep -c . /proc/self/mountinfo                     # note the number
cargo xtask images inspect python:3-slim           # layers and chain IDs, bottom first
cargo xtask image-run python:3-slim sh -c 'head -1 /proc/self/mountinfo; sleep 20' &
sleep 5; grep overlay /proc/self/mountinfo; wait   # the host's side, while it sleeps
cargo xtask image-run --keep alpine sh -c 'echo changed >> /etc/motd; rm /etc/issue; rm -r /etc/profile.d; mkdir /etc/profile.d'
cargo xtask images ls -R containers/<id>/upper     # <id> from the "kept" line; 12 characters will do
cargo xtask image-run --userns --keep alpine sh -c 'stat -c "%u:%g %n" / /bin/busybox; touch /made-here'
cargo xtask images ls containers/<id>/upper        # made-here belongs to 1000000
cargo xtask images prune-containers
grep -c . /proc/self/mountinfo                     # the number you started with
# §10, with the daemon installed (chapter 13):
R="sudo target/debug/rustlet"
$R run --rm -v apk:/etc/apk alpine ls /etc/apk     # populated from the image
sudo ls -ln /var/lib/rustlet/volumes/apk/_data
$R run --rm --userns remap -v apk:/etc/apk alpine touch /etc/apk/x && sudo ls -ln /var/lib/rustlet/volumes/apk/_data/x
$R run --rm -v /etc/apk alpine true; $R volume ls  # an anonymous volume, left behind by rm without -v
$R volume prune -f; $R volume rm apk
```

## Check yourself

1. A container appends a line to `/etc/motd`, then a second container of
   the same image reads it. What does the second see, and where is the
   first one's line? What would a `touch` have copied?
2. After `rm -r /etc/profile.d; mkdir /etc/profile.d`, why must the new
   directory be opaque? What would `ls /etc/profile.d` show if it weren't?
3. A layer tar holds `.wh.x` and then `x/new`. What is `/x` in the merged
   view, and why does unpacking make `x` opaque instead of keeping the
   whiteout?
4. `lowerdir=a:b:c:d` works with `mount(2)`, but through `fsconfig` it
   fails for python:3-slim's layers in this store. Why? What does
   `lowerdir+` change, and why does `mount_overlay`'s loop run in reverse?
5. What would `redirect_dir=on`, `metacopy=on` and `index=on` each leave
   in upper, and why does Phase 7's commit care? Why set `metacopy` and
   `index` although they are this kernel's defaults, and `redirect_dir` to
   `nofollow` rather than `off`?
6. Why are idmapped layers attached under `lower/`, and why does
   mountinfo still name `lower/0` once it is gone? Give `/bin/busybox`'s
   owner on disk, through the overlay on the host, and inside.
7. The host-side overlay was `shared:472`. Where else did it appear, and
   why must the runtime's clone of it be private?
8. A remapped container's `chown 5:5 /etc/issue` is stored as
   1000005:1000005. What must a commit of it do with owners, and why does
   a container without a user namespace need nothing?
9. §4's copy-up and §10's populating of a volume both copy files. Which
   copies what, when, and on whose behalf?
10. Why does the daemon populate a volume through the mounted overlay
    rather than from the snapshot directories, and why must it never
    follow a symlink below the mount point? What does `RESOLVE_IN_ROOT`
    still follow, and why is that safe?
11. A remapped container and a plain one share a volume. Who owns, on
    disk, a file the remapped container's root creates there, and what
    would the owner be if volumes weren't idmapped?

## Experiments

- **An overlay of your own, without root.** Make files `l0/etc/{a,keep,motd}`
  and `l0/doc/x`, a whiteout `mknod l1/etc/a c 0 0`, an opaque directory
  `l1/doc` (`setfattr -n user.overlay.opaque -v y l1/doc`) and empty `up`,
  `wk` and `m`. In an `unshare -Urm` shell, `mount -t overlay overlay -o
  userxattr,lowerdir=l1:l0,upperdir=up,workdir=wk m`, and check that
  `etc/a` and `doc/x` are hidden. Append to `m/etc/keep`, `rm m/etc/motd`,
  then read `getfattr -d -m - up up/etc/keep` and `ls -l up/etc/motd`.
  Why does mountinfo say `redirect_dir=nofollow`?
- **Propagation.** Repeat §11's companion with `--propagation private`.
  Does the overlay appear? How could a daemon keep rootfs mounts from
  propagating into every namespace on the host?
- **Read-only root.** Run `image-run --read-only --keep alpine touch /x`
  and look at upper. Which refused the write, the overlay or the
  runtime's mount of it (chapter 02 §8)?
- **Where writes go.** Run a container that writes 100 MB into a volume
  (`-v big:/big`) and 100 MB into its root filesystem, with `--rm` off.
  Compare `upper/` and the volume's `_data` (`du -sh`), then `rm` the
  container and look again.
- **Not empty, not copied.** Put one file into a new volume (`$R run --rm
  -v v:/x alpine touch /x/mine`), then mount it over `/etc/apk`. What does
  the container see in `/etc/apk`, and why? Then try `-v v2:/etc/apk:nocopy`
  on a new volume.
