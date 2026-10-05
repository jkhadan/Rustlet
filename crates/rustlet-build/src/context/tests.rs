use std::fs;
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::*;

/// An archive entry, read back with the tar crate (as the daemon reads it).
#[derive(Debug)]
struct Entry {
    path: String,
    kind: tar::EntryType,
    mode: u32,
    owners: (u64, u64),
    names: (Vec<u8>, Vec<u8>),
    mtime: u64,
    link: Option<String>,
    data: Vec<u8>,
}

fn read(archive: &[u8]) -> Vec<Entry> {
    let mut archive = tar::Archive::new(archive);
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let header = entry.header().clone();
            let path = String::from_utf8(entry.path_bytes().into_owned()).unwrap();
            let link = entry.link_name_bytes().map(|l| String::from_utf8(l.into_owned()).unwrap());
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            Entry {
                path,
                kind: header.entry_type(),
                mode: header.mode().unwrap(),
                owners: (header.uid().unwrap(), header.gid().unwrap()),
                names: (
                    header.username_bytes().unwrap_or_default().to_vec(),
                    header.groupname_bytes().unwrap_or_default().to_vec(),
                ),
                mtime: header.mtime().unwrap(),
                link,
                data,
            }
        })
        .collect()
}

fn packed(context: &Path, containerfile: &Path) -> (Packed, Vec<Entry>) {
    let mut out = Vec::new();
    let packed = pack(context, containerfile, &mut out).unwrap_or_else(|e| panic!("{e}"));
    (packed, read(&out))
}

fn paths(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.path.as_str()).collect()
}

fn entry<'a>(entries: &'a [Entry], path: &str) -> &'a Entry {
    entries.iter().find(|e| e.path == path).unwrap_or_else(|| panic!("no {path} in {:?}", paths(entries)))
}

/// Writes `rel` under `root` with `mode`, its directories made as needed.
fn write(root: &Path, rel: &str, content: &str, mode: u32) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mkdir(root: &Path, rel: &str, mode: u32) {
    let path = root.join(rel);
    fs::create_dir_all(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

fn set_mtime(path: &Path, seconds: u64) {
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)).unwrap();
}

#[test]
fn the_default_containerfile_is_containerfile_then_dockerfile() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(default_containerfile(dir.path()), None);
    write(dir.path(), "Dockerfile", "FROM a\n", 0o644);
    assert_eq!(default_containerfile(dir.path()), Some(dir.path().join("Dockerfile")));
    write(dir.path(), "Containerfile", "FROM a\n", 0o644);
    assert_eq!(default_containerfile(dir.path()), Some(dir.path().join("Containerfile")));
    fs::remove_file(dir.path().join("Containerfile")).unwrap();
    mkdir(dir.path(), "Containerfile", 0o755);
    assert_eq!(default_containerfile(dir.path()), Some(dir.path().join("Dockerfile")), "a directory isn't one");
}

#[test]
fn the_containerfiles_name_is_its_path_inside_the_context() {
    let dir = tempfile::tempdir().unwrap();
    let context = dir.path().join("ctx");
    write(&context, "Containerfile", "FROM a\n", 0o644);
    write(&context, "docker/app.Containerfile", "FROM a\n", 0o644);
    write(dir.path(), "outside/Containerfile", "FROM a\n", 0o644);
    symlink(dir.path().join("outside/Containerfile"), context.join("linked")).unwrap();
    symlink("docker/app.Containerfile", context.join("inner-link")).unwrap();
    let name = |file: &Path| dockerfile_name(&context, file).unwrap();
    assert_eq!(name(&context.join("Containerfile")), "Containerfile");
    assert_eq!(name(&context.join("docker/app.Containerfile")), "docker/app.Containerfile");
    assert_eq!(name(&context.join("docker/../docker/./app.Containerfile")), "docker/app.Containerfile");
    assert_eq!(name(&dir.path().join("outside/Containerfile")), ".rustlet-containerfile");
    assert_eq!(name(&context.join("linked")), ".rustlet-containerfile", "a symlink out of the context is outside");
    assert_eq!(name(&context.join("inner-link")), "docker/app.Containerfile", "symlinks are resolved");
    assert_eq!(dockerfile_name(&context.join("docker/.."), &context.join("Containerfile")).unwrap(), "Containerfile");
}

#[test]
fn a_missing_or_odd_containerfile_is_an_error_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("Nope");
    match dockerfile_name(dir.path(), &missing) {
        Err(ContextError::Io { path, .. }) => assert_eq!(path, missing),
        other => panic!("{other:?}"),
    }
    let e = dockerfile_name(dir.path(), dir.path()).unwrap_err();
    assert!(matches!(e, ContextError::Invalid(_)) && e.to_string().contains("isn't a file"), "{e}");
    let e = pack(&dir.path().join("gone"), &missing, &mut Vec::new()).unwrap_err();
    assert!(e.to_string().contains("gone"), "{e}");
    write(dir.path(), "file", "x", 0o644);
    let e = pack(&dir.path().join("file"), &missing, &mut Vec::new()).unwrap_err();
    assert!(e.to_string().contains("isn't a directory"), "{e}");
    let e = pack(dir.path(), &missing, &mut Vec::new()).unwrap_err();
    assert!(e.to_string().contains("Nope"), "{e}");
}

#[test]
fn entries_are_sorted_parents_first_with_root_owners_modes_and_times() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM alpine\n", 0o644);
    write(root, "b.txt", "bee", 0o600);
    write(root, "a-b.txt", "", 0o640);
    write(root, "a/z.sh", "#!/bin/sh\n", 0o755);
    write(root, "a/b/c.txt", "sea", 0o444);
    mkdir(root, "a/b", 0o700);
    mkdir(root, "a", 0o751);
    set_mtime(&root.join("b.txt"), 1_600_000_000);

    let (packed, entries) = packed(root, &root.join("Containerfile"));
    assert_eq!(paths(&entries), ["Containerfile", "a/", "a/b/", "a/b/c.txt", "a/z.sh", "a-b.txt", "b.txt"]);
    assert_eq!(packed, Packed { dockerfile: "Containerfile".into(), entries: 7, bytes: 12 + 3 + 10 + 3, excluded: 0 });
    for e in &entries {
        assert_eq!(e.owners, (0, 0), "{}", e.path);
        assert_eq!(e.names, (Vec::new(), Vec::new()), "{}", e.path);
        let on_disk = fs::symlink_metadata(root.join(e.path.trim_end_matches('/'))).unwrap();
        assert_eq!(e.mode, on_disk.mode() & 0o7777, "{}", e.path);
        assert_eq!(e.mtime as i64, on_disk.mtime(), "{}", e.path);
    }
    let modes: Vec<(&str, u32)> = entries.iter().map(|e| (e.path.as_str(), e.mode)).collect();
    assert_eq!(
        modes,
        [
            ("Containerfile", 0o644),
            ("a/", 0o751),
            ("a/b/", 0o700),
            ("a/b/c.txt", 0o444),
            ("a/z.sh", 0o755),
            ("a-b.txt", 0o640),
            ("b.txt", 0o600)
        ]
    );
    assert_eq!(entry(&entries, "a/").kind, tar::EntryType::Directory);
    assert_eq!(entry(&entries, "b.txt").kind, tar::EntryType::Regular);
    assert_eq!(entry(&entries, "b.txt").data, b"bee");
    assert_eq!(entry(&entries, "b.txt").mtime, 1_600_000_000);
    assert_eq!(entry(&entries, "a/b/c.txt").data, b"sea");
}

#[test]
fn symlinks_are_kept_as_symlinks_and_never_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, "real/file", "data", 0o644);
    symlink("real/file", root.join("relative")).unwrap();
    symlink("/etc/passwd", root.join("absolute")).unwrap();
    symlink("nowhere", root.join("dangling")).unwrap();
    symlink("real", root.join("dirlink")).unwrap();
    symlink("../../outside", root.join("escaping")).unwrap();

    let (packed, entries) = packed(root, &root.join("Containerfile"));
    assert_eq!(
        paths(&entries),
        ["Containerfile", "absolute", "dangling", "dirlink", "escaping", "real/", "real/file", "relative"]
    );
    for (path, target) in [
        ("relative", "real/file"),
        ("absolute", "/etc/passwd"),
        ("dangling", "nowhere"),
        ("dirlink", "real"),
        ("escaping", "../../outside"),
    ] {
        let e = entry(&entries, path);
        assert_eq!(e.kind, tar::EntryType::Symlink, "{path}");
        assert_eq!(e.link.as_deref(), Some(target), "{path}");
        assert!(e.data.is_empty(), "{path}");
        assert_eq!(e.owners, (0, 0));
    }
    assert_eq!(packed.bytes, 7 + 4);
}

#[test]
fn hard_links_are_separate_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, "one", "shared", 0o644);
    fs::hard_link(root.join("one"), root.join("two")).unwrap();
    let (packed, entries) = packed(root, &root.join("Containerfile"));
    for path in ["one", "two"] {
        let e = entry(&entries, path);
        assert_eq!((e.kind, e.data.as_slice()), (tar::EntryType::Regular, b"shared".as_slice()), "{path}");
    }
    assert_eq!(packed.bytes, 7 + 6 + 6);
}

#[test]
fn sockets_and_other_special_files_are_left_out() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    let _listener = std::os::unix::net::UnixListener::bind(root.join("app.sock")).unwrap();
    let (packed, entries) = packed(root, &root.join("Containerfile"));
    assert_eq!(paths(&entries), ["Containerfile"]);
    assert_eq!(packed.excluded, 0, "not excluded by the ignore file");
}

#[test]
fn what_the_ignore_file_excludes_is_left_out() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, ".dockerignore", "# build output\ntarget\n*.log\n!keep.log\nsecret/\n**/*.tmp\n", 0o644);
    write(root, "target/debug/app", "binary", 0o755);
    write(root, "target/release/app", "binary", 0o755);
    write(root, "app.log", "log", 0o644);
    write(root, "keep.log", "kept", 0o644);
    write(root, "secret/key", "k", 0o600);
    write(root, "src/main.rs", "fn main() {}", 0o644);
    write(root, "src/scratch.tmp", "", 0o644);
    write(root, "src/target", "a file named target, deeper: kept", 0o644);

    let (packed, entries) = packed(root, &root.join("Containerfile"));
    assert_eq!(paths(&entries), [".dockerignore", "Containerfile", "keep.log", "src/", "src/main.rs", "src/target"]);
    assert_eq!(packed.excluded, 4, "target, app.log, secret and src/scratch.tmp, each once");
    assert_eq!(packed.entries, 6);
}

#[test]
fn an_exception_below_an_excluded_directory_brings_its_parents() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, ".dockerignore", "node_modules\n!node_modules/keep\nempty\n!**/wanted.txt\n", 0o644);
    write(root, "node_modules/x.js", "x", 0o644);
    write(root, "node_modules/keep/index.js", "kept", 0o644);
    write(root, "node_modules/other/y.js", "y", 0o644);
    write(root, "empty/sub/file", "nothing wanted here", 0o644);
    mkdir(root, "node_modules", 0o705);

    let (packed, entries) = packed(root, &root.join("Containerfile"));
    assert_eq!(
        paths(&entries),
        [".dockerignore", "Containerfile", "node_modules/", "node_modules/keep/", "node_modules/keep/index.js"]
    );
    assert_eq!(entry(&entries, "node_modules/").mode, 0o705, "a parent written late keeps its metadata");
    assert!(packed.excluded >= 3, "{packed:?}");
}

#[test]
fn an_unreadable_excluded_directory_is_never_looked_at() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, ".dockerignore", "private\n", 0o644);
    write(root, "private/x", "x", 0o644);
    mkdir(root, "private", 0o000);
    let result = std::panic::catch_unwind(|| packed(root, &root.join("Containerfile")));
    fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o755)).unwrap();
    let (packed, entries) = result.unwrap();
    assert_eq!(paths(&entries), [".dockerignore", "Containerfile"]);
    assert_eq!(packed.excluded, 1);
}

#[test]
fn an_unreadable_directory_that_is_not_excluded_is_an_error_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, "locked/x", "x", 0o644);
    mkdir(root, "locked", 0o000);
    let readable = fs::read_dir(root.join("locked")).is_ok();
    let result = pack(root, &root.join("Containerfile"), &mut Vec::new());
    fs::set_permissions(root.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        return; // root reads anything: nothing to see here
    }
    match result {
        Err(ContextError::Io { path, .. }) => assert_eq!(path, root.canonicalize().unwrap().join("locked")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn excluded_build_metadata_is_not_part_of_the_copy_context() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "build/Containerfile", "FROM a\n", 0o644);
    write(root, ".dockerignore", "*\n.dockerignore\nbuild/Containerfile\n", 0o644);
    write(root, "build/other", "o", 0o644);
    write(root, "README.md", "r", 0o644);
    mkdir(root, "build", 0o750);

    let (packed, entries) = packed(root, &root.join("build/Containerfile"));
    assert_eq!(paths(&entries), [".rustlet-containerfile"]);
    assert_eq!(packed.dockerfile, ".rustlet-containerfile");
    assert_eq!(dockerfile_name(root, &root.join("build/Containerfile")).unwrap(), packed.dockerfile);
    assert_eq!(entry(&entries, ".rustlet-containerfile").data, b"FROM a\n");
}

#[test]
fn an_ignore_file_beside_the_containerfile_is_used_and_can_exclude_itself() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "docker/app.Containerfile", "FROM a\n", 0o644);
    write(root, "docker/app.Containerfile.dockerignore", "*.md\ndocker\n", 0o644);
    write(root, ".dockerignore", "src\n", 0o644);
    write(root, "src/lib.rs", "", 0o644);
    write(root, "notes.md", "", 0o644);
    let (packed, entries) = packed(root, &root.join("docker/app.Containerfile"));
    assert_eq!(paths(&entries), [".dockerignore", ".rustlet-containerfile", "src/", "src/lib.rs"]);
    assert_eq!(packed.excluded, 2, "notes.md and docker/; .dockerignore doesn't apply");
}

#[test]
fn a_containerfile_outside_the_context_is_added_under_a_fixed_name() {
    let dir = tempfile::tempdir().unwrap();
    let context = dir.path().join("ctx");
    write(&context, ".a", "first", 0o644);
    write(&context, "z", "last", 0o644);
    write(&context, ".rustlet-containerfile", "the context's own: replaced", 0o644);
    write(dir.path(), "elsewhere/Containerfile", "FROM outside\n", 0o640);
    write(dir.path(), "elsewhere/Containerfile.dockerignore", "z\n", 0o644);

    let (packed, entries) = packed(&context, &dir.path().join("elsewhere/Containerfile"));
    assert_eq!(packed.dockerfile, ".rustlet-containerfile");
    assert_eq!(paths(&entries), [".a", ".rustlet-containerfile"], "in its sorted place; z is excluded");
    let e = entry(&entries, ".rustlet-containerfile");
    assert_eq!((e.data.as_slice(), e.mode, e.owners), (b"FROM outside\n".as_slice(), 0o640, (0, 0)));
    assert_eq!(packed.excluded, 1);
}

#[test]
fn long_names_and_targets_survive() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    let long_dir = format!("{}/{}", "d".repeat(80), "e".repeat(80));
    let long_file = format!("{long_dir}/{}.txt", "f".repeat(120));
    write(root, &long_file, "deep", 0o644);
    let long_target = format!("../{}", "t".repeat(150));
    symlink(&long_target, root.join("link")).unwrap();

    let (_, entries) = packed(root, &root.join("Containerfile"));
    let d = "d".repeat(80);
    assert_eq!(
        paths(&entries),
        ["Containerfile", &format!("{d}/"), &format!("{long_dir}/"), long_file.as_str(), "link"]
    );
    assert_eq!(entry(&entries, &long_file).data, b"deep");
    assert_eq!(entry(&entries, "link").link.as_deref(), Some(long_target.as_str()));
}

#[test]
fn a_malformed_ignore_file_is_an_error_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Containerfile", "FROM a\n", 0o644);
    write(root, ".dockerignore", "ok\n[unclosed\n", 0o644);
    let e = pack(root, &root.join("Containerfile"), &mut Vec::new()).unwrap_err();
    let message = e.to_string();
    assert!(message.contains(".dockerignore") && message.contains("line 2"), "{message}");
}

#[test]
fn the_archive_unpacks_with_the_tar_crate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("ctx");
    write(&root, "Containerfile", "FROM a\n", 0o644);
    write(&root, "app/main.py", "print('hi')\n", 0o644);
    symlink("app/main.py", root.join("main")).unwrap();
    let mut out = Vec::new();
    pack(&root, &root.join("Containerfile"), &mut out).unwrap();
    let dest = dir.path().join("unpacked");
    tar::Archive::new(out.as_slice()).unpack(&dest).unwrap();
    assert_eq!(fs::read_to_string(dest.join("app/main.py")).unwrap(), "print('hi')\n");
    assert_eq!(fs::read_link(dest.join("main")).unwrap(), Path::new("app/main.py"));
}
