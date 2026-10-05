//! Review tests (Phase 7): `diff` (upper directory → layer), the unpacker's
//! own reading of extension headers, `content`'s kept and cache entries,
//! `import::write_image` and `media::detect_compression`.
//!
//! Unprivileged, like the crate's own unit tests: everything belongs to the
//! user running them, opaque directories are marked `user.overlay.opaque`,
//! whiteouts are 0:0 character devices (`mknod` of those needs no privilege
//! since Linux 5.8).

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;
use nix::sys::stat::{Mode, SFlag};
use rustlet_image::Error;
use rustlet_image::diff::{DiffOptions, DiffReport, diff};
use rustlet_image::media::Compression;
use rustlet_image::unpack::{UnpackReport, unpack};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A directory tree being made (an upper directory, or a lower layer).
struct Tree {
    tmp: tempfile::TempDir,
}

impl Tree {
    fn new() -> Tree {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("t")).unwrap();
        Tree { tmp }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.tmp.path().join("t").join(p)
    }

    fn root(&self) -> PathBuf {
        self.tmp.path().join("t")
    }

    fn dir(&self, p: &str, mode: u32) -> &Self {
        std::fs::create_dir(self.path(p)).unwrap();
        std::fs::set_permissions(self.path(p), std::fs::Permissions::from_mode(mode)).unwrap();
        self
    }

    fn file(&self, p: &str, data: &[u8], mode: u32) -> &Self {
        std::fs::write(self.path(p), data).unwrap();
        std::fs::set_permissions(self.path(p), std::fs::Permissions::from_mode(mode)).unwrap();
        self
    }

    fn whiteout(&self, p: &str) -> &Self {
        nix::sys::stat::mknod(&self.path(p), SFlag::S_IFCHR, Mode::empty(), 0).unwrap();
        self
    }

    fn xattr(&self, p: &str, name: &str, value: &[u8]) -> &Self {
        rustlet_sys::xattr::lset(&self.path(p), name, value).unwrap();
        self
    }

    fn diff_with(&self, options: &DiffOptions<'_>) -> rustlet_image::Result<(Vec<u8>, DiffReport)> {
        let mut out = Vec::new();
        let report = diff(&self.root(), &mut out, options)?;
        Ok((out, report))
    }
}

/// The names in a tar archive, in order (the tar crate's reading, which is
/// fine for names).
fn names(tar: &[u8]) -> Vec<String> {
    let mut archive = tar::Archive::new(tar);
    archive.entries().unwrap().map(|e| String::from_utf8_lossy(&e.unwrap().path_bytes()).into_owned()).collect()
}

/// One PAX record, `<length> <key>=<value>\n`.
fn record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = [key.as_bytes(), b"=", value, b"\n"].concat();
    let mut len = body.len() + 2;
    while len.to_string().len() + 1 + body.len() != len {
        len = len.to_string().len() + 1 + body.len();
    }
    [len.to_string().as_bytes(), b" ", &body].concat()
}

/// A ustar header, as Go's archive/tar writes one.
fn ustar(name: &[u8], kind: tar::EntryType, size: u64, mode: u32) -> tar::Header {
    let mut h = tar::Header::new_ustar();
    h.as_old_mut().name[..name.len()].copy_from_slice(name);
    h.set_entry_type(kind);
    h.set_size(size);
    h.set_mode(mode);
    h.set_mtime(1_700_000_000);
    h.set_uid(u64::from(nix::unistd::geteuid().as_raw()));
    h.set_gid(u64::from(nix::unistd::getegid().as_raw()));
    h.set_cksum();
    h
}

/// Zeros to the end of the block.
fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
}

/// A PAX extended header (`x`) with `records`, padded.
fn pax_header(records: &[(&str, &[u8])]) -> Vec<u8> {
    let data: Vec<u8> = records.iter().flat_map(|(k, v)| record(k, v)).collect();
    let mut out = ustar(b"PaxHeaders.0/x", tar::EntryType::XHeader, data.len() as u64, 0o644).as_bytes().to_vec();
    out.extend_from_slice(&data);
    pad(&mut out);
    out
}

/// A regular file entry with its data, padded.
fn file_entry(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = ustar(name.as_bytes(), tar::EntryType::Regular, data.len() as u64, 0o644).as_bytes().to_vec();
    out.extend_from_slice(data);
    pad(&mut out);
    out
}

/// A directory to unpack into.
struct Dest {
    tmp: tempfile::TempDir,
}

impl Dest {
    fn new() -> Dest {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("layer")).unwrap();
        Dest { tmp }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.tmp.path().join("layer").join(p)
    }

    fn fd(&self) -> OwnedFd {
        nix::fcntl::open(&self.path(""), OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
            .unwrap()
    }

    fn unpack(&self, tar: impl Read) -> rustlet_image::Result<UnpackReport> {
        let fd = self.fd();
        unpack(tar, Compression::None, fd.as_fd())
    }
}

/// Keeps the first `limit` bytes written and fails after them: the start
/// of an archive whose whole would be too large for a test.
struct Head {
    data: Vec<u8>,
    limit: usize,
}

impl Write for Head {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = self.limit - self.data.len();
        if room == 0 {
            return Err(io::Error::other("the test keeps only the archive's start"));
        }
        let n = room.min(buf.len());
        self.data.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The archive's headers up to and including the first entry that isn't an
/// extension header (`x`, `L`, `K`): what a reader looks at before the
/// entry's data.
fn headers_of_first_entry(tar: &[u8]) -> Vec<u8> {
    let mut at = 0;
    loop {
        let h = tar::Header::from_byte_slice(&tar[at..at + 512]);
        let kind = h.entry_type();
        let size = h.entry_size().unwrap() as usize;
        at += 512;
        if matches!(kind, tar::EntryType::XHeader | tar::EntryType::GNULongName | tar::EntryType::GNULongLink) {
            at += size.div_ceil(512) * 512;
            continue;
        }
        return tar[..at].to_vec();
    }
}

// ---------------------------------------------------------------------------
// Files of 8 GiB and more
// ---------------------------------------------------------------------------

/// 8 GiB: the smallest size a ustar header's 11 octal digits can't hold.
const EIGHT_GIB: u64 = 0o77_777_777_777 + 1;

// Documented limit: raw-mode unpacking refuses PAX-only sizes of 8 GiB
// or more before writing any payload. The small, cut stream checks that
// refusal without allocating or writing a large file.
#[test]
fn review_unpack_refuses_a_go_written_entry_of_8_gib() {
    let size = EIGHT_GIB.to_string();
    let mut tar = pax_header(&[("size", size.as_bytes())]);
    tar.extend_from_slice(ustar(b"big", tar::EntryType::Regular, 0, 0o644).as_bytes());
    let stream = io::Cursor::new(tar).chain(io::repeat(0).take(1 << 16));
    let dest = Dest::new();
    let result = dest.unpack(stream);
    assert!(
        matches!(result, Err(Error::Unsupported(_))),
        "the documented PAX-only size limit was not enforced: {:?}",
        result.err().map(|e| e.to_string())
    );
}

// The writer can represent large files, while the unpacker deliberately
// refuses PAX-only sizes. Pin the documented limitation; enabling support
// requires replacing the unpacker's underlying tar reader.
#[test]
fn review_diff_layer_with_an_8_gib_file_does_not_unpack() {
    let upper = Tree::new();
    let big = std::fs::File::create(upper.path("big")).unwrap();
    big.set_len(EIGHT_GIB).unwrap();
    drop(big);
    let mut head = Head { data: Vec::new(), limit: 64 << 10 };
    // Fails once the kept start is full: only the headers are wanted.
    assert!(diff(&upper.root(), &mut head, &DiffOptions::default()).is_err());
    let headers = headers_of_first_entry(&head.data);
    let stream = io::Cursor::new(headers).chain(io::repeat(0).take(1 << 16));
    let dest = Dest::new();
    let result = dest.unpack(stream);
    assert!(
        matches!(result, Err(Error::Unsupported(_))),
        "the documented large-file limitation unexpectedly changed: {:?}",
        result.err().map(|e| e.to_string())
    );
}

// ---------------------------------------------------------------------------
// Extension headers
// ---------------------------------------------------------------------------

// Expected: of two PAX extended headers in a row, only the last describes
// the entry, as Go's archive/tar reads them (reader.go `next()`:
// `paxHdrs, err = parsePAX(tr)` replaces what an earlier one said) and as
// GNU tar 1.35 does (`tar -tvf` of this archive lists `good`, with the
// second header's mtime). The tar crate's non-raw mode, which the unpacker
// used before Phase 7, refused the archive ("two pax extensions entries
// describing the same member"). Extensions::absorb (extensions.rs:75-78)
// appends the records of both, so the entry is unpacked as `evil`: a layer
// Docker/containerd (and image scanners built on Go) read as one file is
// written here as another.
#[test]
fn review_two_pax_headers_in_a_row_are_merged_not_replaced() {
    let mut tar = pax_header(&[("path", b"evil")]);
    tar.extend(pax_header(&[("mtime", b"1600000000")]));
    tar.extend(file_entry("good", b"x"));
    tar.extend([0; 1024]);
    let dest = Dest::new();
    let result = dest.unpack(&tar[..]);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(std::fs::read(dest.path("good")).unwrap(), b"x");
    assert!(
        !dest.path("evil").exists(),
        "the first PAX header's path applied ({result:?}); Go and GNU tar name the entry `good`"
    );
}

// One maximally sized PAX header with thousands of distinct attributes
// must finish promptly. Private overlay attributes avoid filesystem calls;
// this exercises parsing and deduplication, which used to be quadratic.
#[test]
fn review_pax_xattr_records_take_quadratic_time() {
    let mut data = Vec::new();
    let mut n = 0usize;
    loop {
        let r = record(&format!("SCHILY.xattr.user.overlay.{n:07}"), b"");
        if data.len() + r.len() > (1 << 20) - 64 {
            break;
        }
        data.extend(r);
        n += 1;
    }
    let mut tar = ustar(b"PaxHeaders.0/f", tar::EntryType::XHeader, data.len() as u64, 0o644).as_bytes().to_vec();
    tar.extend(data);
    pad(&mut tar);
    tar.extend(file_entry("f", b"x"));
    tar.extend([0; 1024]);
    let dest = Dest::new();
    let fd = dest.fd();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = unpack(&tar[..], Compression::None, fd.as_fd()).map(|r| r.dropped_xattrs.len());
        let _ = tx.send(r.map_err(|e| e.to_string()));
    });
    let start = std::time::Instant::now();
    match rx.recv_timeout(std::time::Duration::from_secs(4)) {
        Ok(result) => assert_eq!(result, Ok(n), "every overlay attribute dropped"),
        Err(_) => panic!("{n} PAX attribute records (one 1 MiB header) still unpacking after {:?}", start.elapsed()),
    }
}

// Expected: a malformed PAX time is ignored or refused, never a panic (the
// unpacker reads untrusted layers; unpack.rs's docs: "Anything else that
// doesn't parse is an error"). `pax_time` (unpack.rs:289-307) strips one
// `-`, parses the rest as an i64 (which may itself be negative) and negates
// it: `--9223372036854775808` negates i64::MIN, a panic ("attempt to negate
// with overflow") with overflow checks on (debug builds, the tests), and a
// wrapped, nonsensical time without them (the release daemon). Go's
// `parsePAXTime` refuses a second sign (ParseInt of "-…" after the cut).
#[test]
fn review_pax_time_with_two_minus_signs_panics() {
    let mut tar = pax_header(&[("mtime", b"--9223372036854775808")]);
    tar.extend(file_entry("f", b"x"));
    tar.extend([0; 1024]);
    let dest = Dest::new();
    let fd = dest.fd();
    let outcome = std::panic::catch_unwind(move || {
        unpack(&tar[..], Compression::None, fd.as_fd()).map(|_| ()).map_err(|e| e.to_string())
    });
    assert!(outcome.is_ok(), "unpacking a layer with PAX mtime `--9223372036854775808` panicked");
}

// Existing tar-crate behavior, predating Phase 7: a directory's declared
// size is consumed as payload. Other readers ignore this field. Keep the
// difference explicit until the layer tar reader is replaced.
#[test]
fn review_directory_with_a_size_is_read_with_the_tar_crate_semantics() {
    let mut tar = ustar(b"d/", tar::EntryType::Directory, 512, 0o755).as_bytes().to_vec();
    tar.extend(ustar(b"smuggled", tar::EntryType::Regular, 0, 0o644).as_bytes());
    tar.extend([0; 1024]);
    let dest = Dest::new();
    let result = dest.unpack(&tar[..]);
    assert!(
        !dest.path("smuggled").exists(),
        "the documented tar-crate directory-size behavior changed: {:?} ({:?})",
        std::fs::read_dir(dest.path("")).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>(),
        result.map(|r| r.entries)
    );
}

// Expected: an empty PAX value keeps the header's own field, as Go's
// archive/tar reads it (`mergePAX`: `if v == "" { continue // Keep the
// original USTAR value }`) and as GNU tar 1.35 does (`tar -tvf` of such an
// archive lists `f`). `Extensions::path` (extensions.rs:62-64)
// returns `Some("")` for a `path=` record, which `clean` makes the layer's
// root: a file entry is refused ("the root must be a directory"), and a
// directory entry's mode, owner and attributes land on the layer's root
// directory. Layers no real writer makes; low.
#[test]
fn review_empty_pax_path_keeps_the_header_name() {
    let mut tar = pax_header(&[("path", b"")]);
    tar.extend(file_entry("f", b"x"));
    tar.extend([0; 1024]);
    let dest = Dest::new();
    let result = dest.unpack(&tar[..]);
    assert!(
        dest.path("f").exists(),
        "Go extracts `f`; unpack: {:?}",
        result.map(|r| r.entries).map_err(|e| e.to_string())
    );
}

// Rootless support remains a Phase 8 task. An unprivileged unpack cannot
// set a user attribute after applying a read-only mode and currently returns
// EACCES; the privileged daemon does not have this permission restriction.
#[test]
fn review_unprivileged_read_only_xattrs_remain_a_rootless_limitation() {
    let mut data = pax_header(&[("SCHILY.xattr.user.note", b"hi")]);
    let mut header = ustar(b"ro", tar::EntryType::Regular, 1, 0o444);
    header.set_cksum();
    data.extend(header.as_bytes());
    data.extend(*b"x");
    pad(&mut data);
    data.extend([0; 1024]);
    let dest = Dest::new();
    let result = dest.unpack(&data[..]);
    assert!(
        result.as_ref().is_err_and(|e| e.to_string().contains("EACCES")),
        "{:?}",
        result.map(|r| r.entries).map_err(|e| e.to_string())
    );
}

// ---------------------------------------------------------------------------
// Overlay's opaque attribute in a privileged diff
// ---------------------------------------------------------------------------

// Expected: only the attribute the overlay was mounted with is overlay's
// mark. rootfs.rs mounts without `userxattr`, so the kernel reads
// `trusted.overlay.opaque` and `user.overlay.opaque` is an ordinary user
// attribute (kernel docs, overlayfs.rst, "userxattr": "Use the
// `user.overlay.` xattr namespace instead of `trusted.overlay.`"; unpack.rs
// chooses by privilege: `opaque_xattr`, `if self.privileged { OPAQUE_XATTR
// } else { USER_OPAQUE_XATTR }`). `read_xattrs` (diff.rs:497-499) takes both
// as the mark, whoever the caller is: a container that runs
// `setfattr -n user.overlay.opaque -v y /dir` (any process that owns the
// directory may) makes `commit` write `dir/.wh..wh..opq`, hiding every file
// of `dir` in the image's lower layers that the container itself still saw.
// `below` reads the lower layers the same way.
//
// Run as the daemon runs: euid 0, here root of a user namespace (the test
// binary runs itself again under `unshare --user --map-root-user`; where
// that isn't allowed the test returns without checking anything).
#[test]
fn review_user_overlay_opaque_set_by_a_container_hides_lower_files_in_a_root_diff() {
    const THIS: &str = "review_user_overlay_opaque_set_by_a_container_hides_lower_files_in_a_root_diff";
    if std::env::var_os("REVIEW_DIFF_AS_ROOT").is_some() {
        assert!(nix::unistd::geteuid().is_root(), "not root in the user namespace");
        let upper = Tree::new();
        upper.dir("d", 0o755).file("d/keep", b"k", 0o644).xattr("d", "user.overlay.opaque", b"y");
        let (tar, _) = upper.diff_with(&DiffOptions::default()).unwrap();
        assert_eq!(
            names(&tar),
            ["d/", "d/keep"],
            "a root diff took the container's `user.overlay.opaque=y` for overlay's mark"
        );
        let dest = Dest::new();
        dest.unpack(&tar[..]).unwrap();
        assert_eq!(rustlet_sys::xattr::lget(&dest.path("d"), "user.overlay.opaque").unwrap(), b"y");
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "--"])
        .arg(&exe)
        .args(["--exact", THIS, "--test-threads=1"])
        .env("REVIEW_DIFF_AS_ROOT", "1")
        .output();
    let out = match out {
        Ok(out) => out,
        Err(e) => return eprintln!("no unshare: {e}"),
    };
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.code() == Some(1) && stderr.starts_with("unshare:") {
        return eprintln!("no user namespace here: {stderr}");
    }
    assert!(out.status.success(), "in a user namespace as root:\n{stdout}\n{stderr}");
}

// Expected: an attribute name a PAX record can't carry gets the clear
// refusal an `=` in a name gets (diff.rs:502-505: "a tar archive can't hold
// it"), or is written as the bytes it is. `split_names` (rustlet-sys
// xattr.rs:88-90) decodes the kernel's list with `from_utf8_lossy`, so the
// name comes out with U+FFFD in it, and `read_xattrs` (diff.rs:495) asks for
// the attribute by that name: the commit of a container that set
// `user.caf\xe9` (a Latin-1 name, any process may) fails with a bare
// "read attribute user.caf\u{fffd}: ENODATA". Docker's writer reads only
// `security.capability` (moby/go-archive `ReadSecurityXattrToTarHeader`) and
// so never meets it.
#[test]
fn review_an_attribute_with_a_non_utf8_name_gets_a_clear_answer_from_diff() {
    use std::os::unix::ffi::OsStrExt;
    let upper = Tree::new();
    upper.file("f", b"x", 0o644);
    let name = std::ffi::OsStr::from_bytes(b"user.caf\xe9");
    match std::process::Command::new("setfattr").arg("-n").arg(name).args(["-v", "1"]).arg(upper.path("f")).status() {
        Ok(status) if status.success() => {}
        other => return eprintln!("no setfattr that does it: {other:?}"),
    }
    match upper.diff_with(&DiffOptions::default()) {
        Ok(_) => {}
        Err(e) => assert!(e.to_string().contains("can't hold"), "{e}"),
    }
}

// ---------------------------------------------------------------------------
// Directories that held only mount points
// ---------------------------------------------------------------------------

// Expected (diff.rs `as_made`/`below` docs: a directory that held only
// mount points is compared with "what the layers below show at its path,
// as overlay merges them ... an opaque directory on the way hides the
// layers below it"): when the *upper* directory's own ancestor is opaque,
// the lower layers show nothing at the path, so the directory is compared
// with what the runtime makes (0755, root's). `below` (diff.rs:528-568)
// only looks at the lowers and so compares with the hidden lower
// directory: here a 0700 directory the container made itself (after
// deleting and making `opq` again) matches the hidden lower `opq/m` and is
// dropped from the layer, losing the directory and its mode.
#[test]
fn review_upper_opaque_ancestor_is_ignored_when_comparing_with_lowers() {
    let lower = Tree::new();
    lower.dir("opq", 0o755).dir("opq/m", 0o700);
    let upper = Tree::new();
    upper.dir("opq", 0o755).xattr("opq", "user.overlay.opaque", b"y").dir("opq/m", 0o700).file("opq/m/x", b"", 0o644);
    let lowers = [lower.root()];
    let skip = [PathBuf::from("/opq/m/x")];
    let identity = |uid, gid| (uid, gid);
    let options = DiffOptions { skip: &skip, map_owner: &identity, lowers: &lowers, userxattr: true };
    let (tar, report) = upper.diff_with(&options).unwrap();
    assert_eq!(
        names(&tar),
        ["opq/", "opq/.wh..wh..opq", "opq/m/"],
        "skipped: {:?}; the lower `opq/m` is hidden by the upper's opaque `opq`",
        report.skipped
    );
}

// ---------------------------------------------------------------------------
// write_image
// ---------------------------------------------------------------------------

fn store() -> (tempfile::TempDir, rustlet_image::content::ContentStore) {
    let dir = tempfile::tempdir().unwrap();
    let s = rustlet_image::content::ContentStore::open(
        dir.path().join("content"),
        dir.path().join("ingest"),
        dir.path().join("lock"),
    )
    .unwrap();
    (dir, s)
}

// Expected: the same config and layers make the same manifest, so the same
// image id. architecture.md §5 (Phase 7): "a build entirely from the cache
// is the same image"; content.rs writes index.json through a `Value`
// because "annotations are a HashMap in oci-spec, and the file should only
// change when its content does". `write_image` (import.rs:101-110)
// serializes the manifest straight from oci-spec's types, so the layer
// descriptors' annotations come out in HashMap order, which differs from
// one parse to the next. The builder (`state_of`) and `commit` pass the
// base image's own layer descriptors, so a base whose layers carry two or
// more annotations (zstd:chunked layers have three, eStargz two) makes a
// new image id on every build or load of the same content. Here the same
// annotations are put into a fresh map each time, as each parse of the
// base manifest does.
#[test]
fn review_write_image_manifest_depends_on_annotation_order() {
    let (_dir, content) = store();
    let tar = vec![0u8; 1024];
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    let gz = gz.finish().unwrap();
    let blob = content.write_blob(&gz).unwrap();
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [rustlet_image::Digest::of(&tar).to_string()]},
    }))
    .unwrap();
    let annotations = [
        ("io.github.containers.zstd-chunked.manifest-checksum", "sha256:aa"),
        ("io.github.containers.zstd-chunked.manifest-position", "1:2:3:4"),
        ("io.github.containers.zstd-chunked.tarsplit-position", "5:6:7"),
        ("org.opencontainers.image.title", "layer"),
    ];
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let mut layer =
            rustlet_image::content::descriptor(rustlet_image::media::OCI_LAYER_GZIP, &blob, gz.len() as u64);
        let mut map = std::collections::HashMap::new();
        for (k, v) in annotations {
            map.insert(k.to_owned(), v.to_owned());
        }
        layer.set_annotations(Some(map));
        let target = rustlet_image::import::write_image(&content, &config, &[layer]).unwrap();
        ids.insert(target.digest().to_string());
    }
    assert_eq!(ids.len(), 1, "one config and one layer made {} different manifests: {ids:?}", ids.len());
}

// Sanity (content.rs): kept images, cache entries and names written from
// many threads at once all end up in index.json, and GC's roots are all
// of them.
#[test]
fn review_concurrent_kept_cache_and_named_entries_are_all_kept() {
    let (_dir, s) = store();
    let mut targets = Vec::new();
    for i in 0..24 {
        let d = s.write_blob(format!("{{\"m\":{i}}}").as_bytes()).unwrap();
        let size = s.blob_size(&d).unwrap().unwrap();
        targets.push(rustlet_image::content::manifest_descriptor(rustlet_image::media::OCI_MANIFEST, &d, size));
    }
    std::thread::scope(|scope| {
        for (i, t) in targets.iter().enumerate() {
            let s = &s;
            scope.spawn(move || match i % 3 {
                0 => s.keep(t).unwrap(),
                1 => s.set_cache_entry(&format!("key-{i}"), t).unwrap(),
                _ => s
                    .set_ref(&rustlet_image::content::RefEntry {
                        name: format!("docker.io/library/r{i}:latest"),
                        target: t.clone(),
                        repo_digest: None,
                    })
                    .unwrap(),
            });
        }
    });
    assert_eq!(s.kept().unwrap().len(), 8);
    assert_eq!(s.cache_entries().unwrap().len(), 8);
    assert_eq!(s.refs().unwrap().len(), 8);
    assert_eq!(s.index_digests().unwrap().len(), 24);
}

// ---------------------------------------------------------------------------
// Sanity checks that held (kept as tests: they pin what was checked)
// ---------------------------------------------------------------------------

/// A name of exactly `len` bytes.
fn name_of(first: char, len: usize) -> String {
    format!("{first}{}", "x".repeat(len - 1))
}

/// An archive's entries as the tar crate reads them: name, type, data, link.
fn entries_of(tar: &[u8]) -> Vec<(String, tar::EntryType, Vec<u8>, Option<String>)> {
    let mut archive = tar::Archive::new(tar);
    let mut out = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        out.push((
            String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
            entry.header().entry_type(),
            data,
            entry.link_name_bytes().map(|l| String::from_utf8_lossy(&l).into_owned()),
        ));
    }
    out
}

// Expected (and found): names, directory names, symlink and hard link
// targets and whiteouts of 95..=104 bytes (around the 100 bytes of a ustar
// header's name and linkname fields, diff.rs `put_name` and the PAX `path`
// and `linkpath` records) come back as written through this crate's
// unpacker, and GNU tar lists the same names as the tar crate does.
#[test]
fn review_names_around_the_ustar_limits_round_trip() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let upper = Tree::new();
    for n in 95..=104 {
        let (file, dir, link, hard, white) =
            (name_of('a', n), name_of('b', n), name_of('c', n), name_of('h', n), name_of('w', n));
        upper.file(&file, b"data", 0o644).dir(&dir, 0o755).file(&format!("{dir}/inner"), b"in", 0o600);
        std::os::unix::fs::symlink(name_of('t', n), upper.path(&link)).unwrap();
        std::fs::hard_link(upper.path(&file), upper.path(&hard)).unwrap();
        upper.whiteout(&white);
    }
    let (tar, report) = upper.diff_with(&DiffOptions::default()).unwrap();
    assert_eq!(report.whiteouts, 10);
    let dest = Dest::new();
    dest.unpack(&tar[..]).unwrap();
    for n in 95..=104 {
        let (file, dir, link, hard, white) =
            (name_of('a', n), name_of('b', n), name_of('c', n), name_of('h', n), name_of('w', n));
        assert_eq!(std::fs::read(dest.path(&file)).unwrap(), b"data", "{n}");
        assert_eq!(std::fs::read(dest.path(&format!("{dir}/inner"))).unwrap(), b"in", "{n}");
        assert_eq!(std::fs::read_link(dest.path(&link)).unwrap(), Path::new(&name_of('t', n)), "{n}");
        let (a, b) = (std::fs::metadata(dest.path(&file)).unwrap(), std::fs::metadata(dest.path(&hard)).unwrap());
        assert_eq!((a.ino(), a.nlink()), (b.ino(), 2), "{n}: a hard link");
        let w = std::fs::symlink_metadata(dest.path(&white)).unwrap();
        assert!(w.file_type().is_char_device() && w.rdev() == 0, "{n}: a whiteout");
    }
    // Another reader: GNU tar lists the names the tar crate reads.
    let listing = upper.tmp.path().join("layer.tar");
    std::fs::write(&listing, &tar).unwrap();
    let out = std::process::Command::new("tar").arg("-tf").arg(&listing).output();
    if let Ok(out) = out {
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let mut gnu: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(str::to_owned).collect();
        let mut ours: Vec<String> = names(&tar);
        gnu.sort();
        ours.sort();
        assert_eq!(gnu, ours);
    }
}

// Expected (and found): attribute values are binary; newlines, `=` and NULs
// in them, an empty value and a value ending in a newline come back through
// diff's PAX records and the unpacker's own record parser (the Phase 7 fix
// in `unpack/extensions.rs`).
#[test]
fn review_xattr_values_with_newlines_round_trip() {
    let upper = Tree::new();
    let nl = b"a\nb=c\0d\n";
    upper
        .file("f", b"x", 0o644)
        .xattr("f", "user.nl", nl)
        .xattr("f", "user.empty", b"")
        .xattr("f", "user.last", b"\n")
        .dir("d", 0o755)
        .xattr("d", "user.dn", b"\n\n");
    let (tar, _) = upper.diff_with(&DiffOptions::default()).unwrap();
    let dest = Dest::new();
    let report = dest.unpack(&tar[..]).unwrap();
    assert!(report.dropped_xattrs.is_empty(), "{:?}", report.dropped_xattrs);
    let get = |p: &str, n: &str| rustlet_sys::xattr::lget(&dest.path(p), n).unwrap();
    assert_eq!(get("f", "user.nl"), nl);
    assert_eq!(get("f", "user.empty"), b"");
    assert_eq!(get("f", "user.last"), b"\n");
    assert_eq!(get("d", "user.dn"), b"\n\n");
}

// Expected (and found): a commit that fails halfway (an attribute name a tar
// archive can't hold) or at the start (no such upper directory) leaves
// nothing in `ingest/` and nothing in `blobs/` (content.rs `BlobWriter`:
// "Dropping it unfinished deletes what was written").
#[test]
fn review_a_failed_commit_leaves_nothing_in_the_store() {
    let upper = Tree::new();
    upper.file("a", b"first", 0o644).file("b", b"second", 0o644).xattr("b", "user.k=v", b"x");
    let (dir, content) = store();
    let err = rustlet_image::diff::commit_layer(&content, &upper.root(), &DiffOptions::default()).unwrap_err();
    assert!(err.to_string().contains("can't hold"), "{err}");
    assert!(rustlet_image::diff::commit_layer(&content, &upper.path("missing"), &DiffOptions::default()).is_err());
    let count = |sub: &str| std::fs::read_dir(dir.path().join(sub)).unwrap().count();
    assert_eq!((count("ingest"), count("content/blobs/sha256")), (0, 0));
}

// Expected (and found): when the first name of a hard-linked file is a
// mount point left out of the layer, the next name carries the data (diff.rs
// `leaf`: only names written are remembered in `links`).
#[test]
fn review_a_hard_link_whose_first_name_is_a_mount_point_keeps_the_data() {
    let upper = Tree::new();
    upper.dir("a", 0o755).file("a/x", b"data", 0o644).dir("b", 0o755);
    std::fs::hard_link(upper.path("a/x"), upper.path("b/y")).unwrap();
    let skip = [PathBuf::from("/a")];
    let identity = |uid, gid| (uid, gid);
    let (tar, _) =
        upper.diff_with(&DiffOptions { skip: &skip, map_owner: &identity, lowers: &[], userxattr: false }).unwrap();
    let entries = entries_of(&tar);
    let kinds: Vec<_> = entries.iter().map(|(n, k, d, l)| (n.as_str(), *k, d.as_slice(), l.as_deref())).collect();
    assert_eq!(
        kinds,
        [("b/", tar::EntryType::Directory, &b""[..], None), ("b/y", tar::EntryType::Regular, &b"data"[..], None)]
    );
}

// Expected (and found): a directory that held only mount points, and that
// differs from the one in the layers below only by its modification time
// (which a copy-up keeps and the runtime's `mkdir` of a mount point makes
// new), is left out (diff.rs `as_made` compares mode, owner and attributes).
#[test]
fn review_a_mount_only_directory_differing_by_mtime_is_left_out() {
    let lower = Tree::new();
    lower.dir("etc", 0o755);
    let upper = Tree::new();
    upper.dir("etc", 0o755).file("etc/resolv.conf", b"", 0o644);
    let set = |tree: &Tree, secs: i64| {
        let t = nix::sys::time::TimeSpec::new(secs, 0);
        nix::sys::stat::utimensat(
            nix::fcntl::AT_FDCWD,
            &tree.path("etc"),
            &t,
            &t,
            nix::sys::stat::UtimensatFlags::NoFollowSymlink,
        )
        .unwrap();
    };
    set(&lower, 1_000_000_000);
    set(&upper, 1_700_000_000);
    let (skip, lowers) = ([PathBuf::from("/etc/resolv.conf")], [lower.root()]);
    let identity = |uid, gid| (uid, gid);
    let (tar, report) =
        upper.diff_with(&DiffOptions { skip: &skip, map_owner: &identity, lowers: &lowers, userxattr: true }).unwrap();
    assert!(names(&tar).is_empty(), "{:?} {:?}", names(&tar), report.skipped);
}

// Expected (and found): PAX times with a fraction and a minus sign are read
// as GNU tar and Go read them: seconds and nanoseconds from a floor, so
// `-1.5` is the second before the epoch, half a second in (unpack.rs
// `pax_time`).
#[test]
fn review_negative_fractional_pax_times_are_floored() {
    use std::os::unix::fs::MetadataExt;
    let mut tar = pax_header(&[("mtime", b"-1.5"), ("atime", b"1700000000.000000001")]);
    tar.extend(file_entry("f", b"x"));
    tar.extend([0; 1024]);
    let dest = Dest::new();
    dest.unpack(&tar[..]).unwrap();
    let m = std::fs::symlink_metadata(dest.path("f")).unwrap();
    assert_eq!((m.mtime(), m.mtime_nsec()), (-2, 500_000_000));
    assert_eq!((m.atime(), m.atime_nsec()), (1_700_000_000, 1));
}

// Expected (and found): an image that is both named and kept is listed
// once as a name and once as kept; `unkeep` leaves the name, `remove_ref`
// leaves it kept, and both entries are garbage collection's roots
// (content.rs: "Every index.json entry is a root"; the daemon's
// `name_image` calls `unkeep`, so there it doesn't last).
#[test]
fn review_an_image_both_named_and_kept_has_two_entries() {
    let (_dir, s) = store();
    let m = s.write_blob(b"{\"m\":1}").unwrap();
    let size = s.blob_size(&m).unwrap().unwrap();
    let target = rustlet_image::content::manifest_descriptor(rustlet_image::media::OCI_MANIFEST, &m, size);
    s.keep(&target).unwrap();
    let name = "docker.io/library/both:1";
    s.set_ref(&rustlet_image::content::RefEntry { name: name.into(), target: target.clone(), repo_digest: None })
        .unwrap();
    assert_eq!((s.refs().unwrap().len(), s.kept().unwrap().len(), s.index_digests().unwrap().len()), (1, 1, 2));
    assert!(s.unkeep(&m).unwrap());
    assert_eq!((s.refs().unwrap().len(), s.kept().unwrap().len()), (1, 0));
    s.keep(&target).unwrap();
    assert!(s.remove_ref(name).unwrap());
    assert_eq!((s.refs().unwrap().len(), s.kept().unwrap().len()), (0, 1));
    assert_eq!(s.index_digests().unwrap(), [m]);
}
