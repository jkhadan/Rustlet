//! Unprivileged unpack tests. Owners, `trusted.*` attributes and the real
//! overlay mount are covered by the privileged `im_` tests in `tests/`.

use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

use super::*;

/// Builds a layer archive entry by entry, writing names verbatim (the tar
/// crate's own setters refuse `..`, which is exactly what the tests need).
struct Archive {
    out: tar::Builder<Vec<u8>>,
}

const MTIME: u64 = 1_700_000_000;

impl Archive {
    fn new() -> Archive {
        let mut out = tar::Builder::new(Vec::new());
        out.mode(tar::HeaderMode::Complete);
        Archive { out }
    }

    fn header(name: &[u8], kind: EntryType, size: u64, mode: u32) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        assert!(name.len() < 100, "test names must fit the header");
        h.as_old_mut().name[..name.len()].copy_from_slice(name);
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_mode(mode);
        h.set_mtime(MTIME);
        h.set_uid(u64::from(nix::unistd::geteuid().as_raw()));
        h.set_gid(u64::from(nix::unistd::getegid().as_raw()));
        h.set_cksum();
        h
    }

    fn file(mut self, name: &str, data: &[u8], mode: u32) -> Archive {
        let h = Archive::header(name.as_bytes(), EntryType::Regular, data.len() as u64, mode);
        self.out.append(&h, data).unwrap();
        self
    }

    fn dir(mut self, name: &str, mode: u32) -> Archive {
        let h = Archive::header(name.as_bytes(), EntryType::Directory, 0, mode);
        self.out.append(&h, io::empty()).unwrap();
        self
    }

    fn link(mut self, kind: EntryType, name: &str, target: &str) -> Archive {
        let mut h = Archive::header(name.as_bytes(), kind, 0, 0o777);
        h.as_old_mut().linkname[..target.len()].copy_from_slice(target.as_bytes());
        h.set_cksum();
        self.out.append(&h, io::empty()).unwrap();
        self
    }

    fn special(mut self, name: &str, kind: EntryType, major: u32, minor: u32) -> Archive {
        let mut h = Archive::header(name.as_bytes(), kind, 0, 0o644);
        h.set_device_major(major).unwrap();
        h.set_device_minor(minor).unwrap();
        h.set_cksum();
        self.out.append(&h, io::empty()).unwrap();
        self
    }

    /// A file with PAX records (attributes, ids).
    fn pax_file(mut self, name: &str, data: &[u8], records: &[(&str, &[u8])]) -> Archive {
        self.out.append_pax_extensions(records.iter().map(|(k, v)| (*k, *v))).unwrap();
        self.file_inplace(name, data);
        self
    }

    fn file_inplace(&mut self, name: &str, data: &[u8]) {
        let h = Archive::header(name.as_bytes(), EntryType::Regular, data.len() as u64, 0o644);
        self.out.append(&h, data).unwrap();
    }

    fn tar(self) -> Vec<u8> {
        self.out.into_inner().unwrap()
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 3).unwrap()
}

struct Unpacked {
    dir: tempfile::TempDir,
    result: Result<UnpackReport>,
}

impl Unpacked {
    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join("layer").join(p)
    }

    #[track_caller]
    fn report(&self) -> &UnpackReport {
        self.result.as_ref().unwrap_or_else(|e| panic!("unpack failed: {e}"))
    }

    #[track_caller]
    fn error(&self) -> String {
        match &self.result {
            Ok(r) => panic!("unpack succeeded: {r:?}"),
            Err(e) => e.to_string(),
        }
    }

    fn read(&self, p: &str) -> String {
        std::fs::read_to_string(self.path(p)).unwrap()
    }

    fn opaque(&self, p: &str) -> bool {
        xattr::lget(&self.path(p), USER_OPAQUE_XATTR).is_ok_and(|v| v == b"y")
    }

    fn is_whiteout(&self, p: &str) -> bool {
        std::fs::symlink_metadata(self.path(p)).is_ok_and(|m| m.file_type().is_char_device() && m.rdev() == 0)
    }

    /// Everything outside `layer/` in the temp dir (there must be nothing).
    fn outside(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "layer")
            .collect();
        v.sort();
        v
    }
}

fn unpack_with(blob: &[u8], compression: Compression) -> Unpacked {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("layer")).unwrap();
    let fd = nix::fcntl::open(&dir.path().join("layer"), OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
    let result = unpack(blob, compression, fd.as_fd());
    Unpacked { dir, result }
}

fn unpack_tar(tar: &[u8]) -> Unpacked {
    unpack_with(tar, Compression::None)
}

#[test]
fn unpacks_files_dirs_links_and_fifos_with_their_modes_and_times() {
    let tar = Archive::new()
        .dir("etc/", 0o755)
        .file("etc/motd", b"hello\n", 0o644)
        .file("usr/bin/tool", b"#!/bin/sh\n", 0o4755)
        .link(EntryType::Symlink, "bin", "usr/bin")
        .link(EntryType::Link, "usr/bin/tool2", "usr/bin/tool")
        .special("run/fifo", EntryType::Fifo, 0, 0)
        .dir("secret/", 0o700)
        .tar();
    let u = unpack_tar(&tar);
    let r = u.report();
    assert_eq!(r.entries, 7);
    assert_eq!(r.bytes, 16);
    assert_eq!(u.read("etc/motd"), "hello\n");
    let mode = |p: &str| std::fs::symlink_metadata(u.path(p)).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode("usr/bin/tool"), 0o4755, "setuid survives");
    assert_eq!(mode("secret"), 0o700);
    assert_eq!(mode("usr"), 0o755, "implicit parents are 0755");
    assert_eq!(std::fs::read_link(u.path("bin")).unwrap(), Path::new("usr/bin"));
    let (a, b) =
        (std::fs::metadata(u.path("usr/bin/tool")).unwrap(), std::fs::metadata(u.path("usr/bin/tool2")).unwrap());
    assert_eq!((a.ino(), a.nlink()), (b.ino(), 2), "a hard link shares the inode");
    assert!(std::fs::symlink_metadata(u.path("run/fifo")).unwrap().file_type().is_fifo());
    for p in ["etc/motd", "etc", "secret", "run/fifo"] {
        assert_eq!(std::fs::symlink_metadata(u.path(p)).unwrap().mtime(), MTIME as i64, "{p}");
    }
    assert_eq!(r.diff_id, Some(Digest::of(&tar)));
    assert_eq!(r.tar_size, tar.len() as u64);
}

#[test]
fn both_digests_cover_every_byte_in_every_compression() {
    // Trailing zero padding after the end-of-archive blocks is part of the
    // stream (tar writers pad to a record size); the diff ID must include it.
    let mut tar = Archive::new().file("a", b"a", 0o644).tar();
    tar.extend_from_slice(&[0u8; 10240]);
    for (blob, compression) in
        [(tar.clone(), Compression::None), (gzip(&tar), Compression::Gzip), (zstd(&tar), Compression::Zstd)]
    {
        let u = unpack_with(&blob, compression);
        let r = u.report();
        assert_eq!(r.diff_id, Some(Digest::of(&tar)), "{compression:?}");
        assert_eq!(r.blob_digest, Some(Digest::of(&blob)), "{compression:?}");
        assert_eq!(r.blob_size, blob.len() as u64);
        assert_eq!(u.read("a"), "a");
    }
}

#[test]
fn corrupt_input_is_an_error() {
    let tar = Archive::new().file("a", b"a", 0o644).tar();
    let mut gz = gzip(&tar);
    let n = gz.len();
    gz[n / 2] ^= 0xff;
    assert!(unpack_with(&gz, Compression::Gzip).result.is_err());
    assert!(unpack_with(b"not gzip at all", Compression::Gzip).result.is_err());
    // A tar header with a bad checksum.
    let mut bad = tar.clone();
    bad[0] ^= 1;
    assert!(unpack_tar(&bad).result.is_err());
}

#[test]
fn names_with_dotdot_are_refused_and_absolute_names_stay_inside() {
    let u = unpack_tar(&Archive::new().file("../escaped", b"x", 0o644).tar());
    assert!(u.error().contains("`..`"), "{}", u.error());
    assert!(u.outside().is_empty(), "wrote outside: {:?}", u.outside());

    let u = unpack_tar(&Archive::new().file("a/../../escaped", b"x", 0o644).tar());
    u.error();
    assert!(u.outside().is_empty());

    let u = unpack_tar(&Archive::new().file("/abs/file", b"x", 0o644).file("./dot/./file", b"y", 0o644).tar());
    u.report();
    assert_eq!(u.read("abs/file"), "x");
    assert_eq!(u.read("dot/file"), "y");
}

#[test]
fn symlinked_parents_resolve_inside_the_layer() {
    // `up` points far above the layer, `root` at the host's root, `etc` at
    // the host's /etc. Entries below them must land inside the layer.
    let tar = Archive::new()
        .link(EntryType::Symlink, "up", "../../../../../../..")
        .link(EntryType::Symlink, "root", "/")
        .dir("etc/", 0o755)
        .link(EntryType::Symlink, "hostetc", "/etc")
        .file("up/escaped-up", b"1", 0o644)
        .file("root/escaped-root", b"2", 0o644)
        .file("hostetc/escaped-etc", b"3", 0o644)
        .tar();
    let u = unpack_tar(&tar);
    u.report();
    assert_eq!(u.read("escaped-up"), "1");
    assert_eq!(u.read("escaped-root"), "2");
    assert_eq!(u.read("etc/escaped-etc"), "3", "/etc means the layer's etc");
    assert!(u.outside().is_empty(), "wrote outside: {:?}", u.outside());
    assert!(!Path::new("/etc/escaped-etc").exists());
}

#[test]
fn a_symlink_is_replaced_not_followed() {
    // A file entry over an existing symlink replaces the link; it never
    // writes through it.
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    let tar = Archive::new().link(EntryType::Symlink, "f", victim.to_str().unwrap()).file("f", b"new", 0o644).tar();
    let u = unpack_tar(&tar);
    u.report();
    assert_eq!(u.read("f"), "new");
    assert!(std::fs::symlink_metadata(u.path("f")).unwrap().is_file());
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
}

#[test]
fn hard_links_must_stay_inside_the_layer() {
    // Text-level escape.
    let u = unpack_tar(&Archive::new().link(EntryType::Link, "x", "../../etc/passwd").tar());
    assert!(u.error().contains("`..`"), "{}", u.error());
    // Through an absolute symlink: resolves to the layer's own etc/passwd,
    // which doesn't exist, so it is refused; the host's is never linked.
    let tar =
        Archive::new().link(EntryType::Symlink, "hostetc", "/etc").link(EntryType::Link, "x", "hostetc/passwd").tar();
    let u = unpack_tar(&tar);
    assert!(u.error().contains("not in this layer"), "{}", u.error());
    assert!(!u.path("x").exists());
    // To a directory, or to the root.
    let u = unpack_tar(&Archive::new().dir("d/", 0o755).link(EntryType::Link, "x", "d").tar());
    assert!(u.error().contains("directory"), "{}", u.error());
    let u = unpack_tar(&Archive::new().link(EntryType::Link, "x", "./").tar());
    u.error();
    // To a symlink: links the symlink itself.
    let tar = Archive::new().link(EntryType::Symlink, "s", "/nowhere").link(EntryType::Link, "s2", "s").tar();
    let u = unpack_tar(&tar);
    u.report();
    assert_eq!(std::fs::read_link(u.path("s2")).unwrap(), Path::new("/nowhere"));
}

#[test]
fn later_entries_replace_earlier_ones_and_directories_merge() {
    let tar = Archive::new()
        .file("a", b"file", 0o644)
        .dir("a/", 0o755) // file → directory
        .file("a/inner", b"x", 0o644)
        .dir("b/", 0o755)
        .file("b/deep/f", b"x", 0o644)
        .file("b", b"now a file", 0o644) // directory tree → file
        .dir("c/", 0o755)
        .file("c/keep", b"k", 0o644)
        .dir("c/", 0o750) // directory → directory: merged, new metadata
        .tar();
    let u = unpack_tar(&tar);
    u.report();
    assert!(u.path("a").is_dir());
    assert_eq!(u.read("a/inner"), "x");
    assert_eq!(u.read("b"), "now a file");
    assert_eq!(u.read("c/keep"), "k");
    assert_eq!(std::fs::metadata(u.path("c")).unwrap().permissions().mode() & 0o777, 0o750);
}

#[test]
fn whiteouts_and_opaque_markers_become_overlay_ones() {
    let tar = Archive::new()
        .file("etc/.wh.gone", b"", 0o644)
        .file("kept", b"same layer", 0o644)
        .file(".wh.kept", b"", 0o644) // the layer's own file stays
        .file("share/doc/.wh..wh..opq", b"", 0o644)
        .file("share/doc/README", b"r", 0o644)
        .file(".wh..wh.plnk", b"", 0o644) // AUFS bookkeeping
        .tar();
    let u = unpack_tar(&tar);
    let r = u.report();
    assert!(u.is_whiteout("etc/gone"));
    assert_eq!(u.read("kept"), "same layer");
    assert!(u.opaque("share/doc"));
    assert_eq!(u.read("share/doc/README"), "r");
    assert!(!u.path(".wh..wh.plnk").exists() && !u.path("etc/.wh.gone").exists());
    assert_eq!((r.whiteouts, r.opaque_dirs), (1, 1));
    assert_eq!(r.skipped_other, [".wh..wh.plnk"]);
}

#[test]
fn a_directory_meeting_its_own_whiteout_is_opaque() {
    // Whiteout first, then the directory (explicitly or implicitly), or the
    // directory first and then its whiteout: either way the lower `x` must
    // not show through.
    for tar in [
        Archive::new().file(".wh.x", b"", 0o644).dir("x/", 0o755).file("x/new", b"n", 0o644).tar(),
        Archive::new().file(".wh.x", b"", 0o644).file("x/new", b"n", 0o644).tar(),
        Archive::new().dir("x/", 0o755).file("x/new", b"n", 0o644).file(".wh.x", b"", 0o644).tar(),
    ] {
        let u = unpack_tar(&tar);
        u.report();
        assert!(u.path("x").is_dir());
        assert!(u.opaque("x"), "x should be opaque");
        assert_eq!(u.read("x/new"), "n");
    }
    // A file replacing a whiteout is just a file.
    let u = unpack_tar(&Archive::new().file(".wh.f", b"", 0o644).file("f", b"f", 0o644).tar());
    assert_eq!(u.read("f"), "f");
    assert!(!u.opaque("f"));
}

#[test]
fn devices_are_skipped_and_overlay_attributes_dropped() {
    let tar = Archive::new()
        .special("dev/null", EntryType::Char, 1, 3)
        .special("dev/sda", EntryType::Block, 8, 0)
        .special("dev/fake-whiteout", EntryType::Char, 0, 0)
        .pax_file(
            "data",
            b"d",
            &[
                ("SCHILY.xattr.user.note", b"hello"),
                ("SCHILY.xattr.trusted.overlay.opaque", b"y"),
                ("SCHILY.xattr.user.overlay.redirect", b"/etc"),
            ],
        )
        .tar();
    let u = unpack_tar(&tar);
    let r = u.report();
    assert_eq!(r.skipped_devices, ["dev/null", "dev/sda", "dev/fake-whiteout"]);
    assert!(!u.path("dev/null").exists() && !u.path("dev/fake-whiteout").exists());
    assert_eq!(xattr::lget(&u.path("data"), "user.note").unwrap(), b"hello");
    assert!(xattr::lget(&u.path("data"), "trusted.overlay.opaque").is_err());
    assert!(xattr::lget(&u.path("data"), "user.overlay.redirect").is_err());
    assert_eq!(r.dropped_xattrs, ["data: trusted.overlay.opaque", "data: user.overlay.redirect"]);
}

#[test]
fn pax_records_override_the_header() {
    let tar = Archive::new().pax_file("t", b"", &[("mtime", b"1600000000.5"), ("atime", b"1500000000")]).tar();
    let u = unpack_tar(&tar);
    u.report();
    let m = std::fs::metadata(u.path("t")).unwrap();
    assert_eq!((m.mtime(), m.mtime_nsec(), m.atime()), (1_600_000_000, 500_000_000, 1_500_000_000));
    // Out-of-range ids are refused.
    let u = unpack_tar(&Archive::new().pax_file("u", b"", &[("uid", b"4294967295")]).tar());
    assert!(u.error().contains("out of range"), "{}", u.error());
}

#[test]
fn empty_numeric_fields_read_as_zero_and_garbage_is_refused() {
    let mut h = tar::Header::new_gnu();
    h.as_old_mut().name[..4].copy_from_slice(b"file");
    h.set_size(1);
    h.set_cksum(); // uid, gid, mode and mtime left all-NUL
    let mut out = tar::Builder::new(Vec::new());
    out.append(&h, &b"x"[..]).unwrap();
    let u = unpack_tar(&out.into_inner().unwrap());
    u.report();
    assert_eq!(std::fs::metadata(u.path("file")).unwrap().permissions().mode() & 0o7777, 0);

    let mut h = tar::Header::new_gnu();
    h.as_old_mut().name[..4].copy_from_slice(b"file");
    h.set_size(0);
    h.as_old_mut().uid[..3].copy_from_slice(b"abc");
    h.set_cksum();
    let mut out = tar::Builder::new(Vec::new());
    out.append(&h, io::empty()).unwrap();
    let u = unpack_tar(&out.into_inner().unwrap());
    assert!(u.error().contains("uid"), "{}", u.error());
}

#[test]
fn bad_entries_are_refused() {
    for (tar, why) in [
        (Archive::new().file("a/b", b"", 0o644).file("a/b/c", b"", 0o644).tar(), "not a directory"),
        (Archive::new().link(EntryType::Symlink, "s", "").tar(), "target"),
        (Archive::new().file(".wh.", b"", 0o644).tar(), "whiteout"),
        (Archive::new().link(EntryType::Symlink, "etc", "/nowhere").file("etc/x", b"", 0o644).tar(), "symlink"),
        (Archive::new().file("./", b"", 0o644).tar(), "root"),
    ] {
        let u = unpack_tar(&tar);
        assert!(u.error().contains(why), "{why}: {}", u.error());
    }
}

#[test]
fn clean_names() {
    assert_eq!(clean(b"./a//b/./c").unwrap(), Some(PathBuf::from("a/b/c")));
    assert_eq!(clean(b"/").unwrap(), None);
    assert_eq!(clean(b"./").unwrap(), None);
    assert!(clean(b"a/../b").is_err());
    assert!(clean(b"a\0b").is_err());
    assert_eq!(pax_time("-1.25"), Some(TimeSpec::new(-2, 750_000_000)));
    assert_eq!(pax_time("12"), Some(TimeSpec::new(12, 0)));
    assert_eq!(pax_time("1.123456789999"), Some(TimeSpec::new(1, 123_456_789)));
    assert_eq!(pax_time("x"), None);
}
