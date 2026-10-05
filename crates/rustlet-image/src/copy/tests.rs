//! Unprivileged tests: everything belongs to the user running them, so
//! `spec.owner` isn't applied and only `user.*` attributes are copied.
//! Owners, and copies into a mounted overlay, are for the privileged build
//! tests.

use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::time::TimeSpec;
use nix::unistd::{getegid, geteuid};

use super::*;

const ATIME: i64 = 1_500_000_000;
const MTIME: i64 = 1_600_000_000;

/// `COPY sources… dest`, in the working directory `/`.
fn spec(sources: &[&str], dest: &str) -> CopySpec {
    CopySpec {
        sources: sources.iter().map(|s| (*s).to_owned()).collect(),
        dest: dest.to_owned(),
        workdir: "/".to_owned(),
        owner: Some((0, 0)),
        mode: None,
        extract_archives: false,
    }
}

/// `ADD sources… dest`.
fn add(sources: &[&str], dest: &str) -> CopySpec {
    CopySpec { extract_archives: true, ..spec(sources, dest) }
}

fn open(p: &Path) -> OwnedFd {
    nix::fcntl::open(p, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty()).unwrap()
}

fn meta(p: &Path) -> std::fs::Metadata {
    std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn mode(p: &Path) -> u32 {
    meta(p).permissions().mode() & 0o7777
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The names in the directory `p`, sorted.
fn listing(p: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// `((atime, nsec), (mtime, nsec))`, of a symlink itself.
fn times_of(p: &Path) -> ((i64, i64), (i64, i64)) {
    let m = meta(p);
    ((m.atime(), m.atime_nsec()), (m.mtime(), m.mtime_nsec()))
}

fn set_times(p: &Path, atime: (i64, i64), mtime: (i64, i64)) {
    let (atime, mtime) = (TimeSpec::new(atime.0, atime.1), TimeSpec::new(mtime.0, mtime.1));
    nix::sys::stat::utimensat(nix::fcntl::AT_FDCWD, p, &atime, &mtime, UtimensatFlags::NoFollowSymlink).unwrap();
}

/// A file holding `data`, with `mode`, its missing parents made.
fn file(p: &Path, data: &str, mode: u32) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
    std::fs::set_permissions(p, Permissions::from_mode(mode)).unwrap();
}

/// A directory with `mode`, made if missing.
fn dir(p: &Path, mode: u32) {
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, Permissions::from_mode(mode)).unwrap();
}

fn symlink(target: impl AsRef<Path>, p: &Path) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, p).unwrap();
}

/// The absolute path `abs` where `RESOLVE_IN_ROOT` finds it inside `root`.
fn inside(root: &Path, abs: &Path) -> PathBuf {
    root.join(abs.strip_prefix("/").unwrap())
}

/// Runs `f` on a thread of its own, so that a test fails rather than hangs
/// if it blocks (a FIFO opened for reading waits for a writer).
fn unblocked<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(30)).expect("blocked (opening a FIFO?)")
}

/// A build context `ctx/`, a root filesystem `root/`, and `outside/`, which
/// symlinks on both sides point to by its absolute path: a copy that
/// followed one of them on the host would show there.
struct Fixture {
    tmp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        for dir in ["ctx", "root", "outside"] {
            std::fs::create_dir(tmp.path().join(dir)).unwrap();
        }
        Fixture { tmp }
    }

    fn under(&self, top: &str, p: &str) -> PathBuf {
        let top = self.tmp.path().join(top);
        if p.is_empty() { top } else { top.join(p) }
    }

    /// `p` in the build context.
    fn ctx(&self, p: &str) -> PathBuf {
        self.under("ctx", p)
    }

    /// `p` in the root filesystem.
    fn root(&self, p: &str) -> PathBuf {
        self.under("root", p)
    }

    /// `p` in neither.
    fn outside(&self, p: &str) -> PathBuf {
        self.under("outside", p)
    }

    fn copy(&self, spec: &CopySpec) -> Result<CopyReport> {
        copy(open(&self.ctx("")).as_fd(), open(&self.root("")).as_fd(), spec)
    }

    fn digest(&self, spec: &CopySpec) -> Result<Digest> {
        digest(open(&self.ctx("")).as_fd(), spec)
    }
}

#[test]
fn a_directory_is_copied_by_its_contents_and_merges_into_an_existing_one() {
    let f = Fixture::new();
    file(&f.ctx("src/a"), "a", 0o644);
    file(&f.ctx("src/sub/b"), "bb", 0o600);
    file(&f.ctx("src/sub/deeper/c"), "ccc", 0o755);
    dir(&f.ctx("src/sub"), 0o750);
    dir(&f.ctx("src"), 0o711);
    file(&f.root("app/old"), "old", 0o644);
    file(&f.root("app/sub/kept"), "kept", 0o644);
    dir(&f.root("app/sub"), 0o700);
    dir(&f.root("app"), 0o701);

    let r = f.copy(&spec(&["src"], "/app")).unwrap();
    // a, sub (merged into), sub/b, sub/deeper, sub/deeper/c
    assert_eq!(r, CopyReport { entries: 5, bytes: 6, extracted: 0, skipped: vec![], unmatched: vec![] });
    assert_eq!(listing(&f.root("app")), ["a", "old", "sub"]);
    assert_eq!(listing(&f.root("app/sub")), ["b", "deeper", "kept"]);
    assert_eq!(read(&f.root("app/old")), "old");
    assert_eq!(read(&f.root("app/sub/deeper/c")), "ccc");
    assert_eq!(mode(&f.root("app/sub/b")), 0o600);
    assert_eq!(mode(&f.root("app/sub/deeper/c")), 0o755);
    assert_eq!(mode(&f.root("app/sub")), 0o750, "a directory merged into takes its source's mode");
    assert_eq!(mode(&f.root("app")), 0o701, "the destination directory keeps its own");
}

#[test]
fn the_whole_context_is_copied_by_naming_its_root() {
    let f = Fixture::new();
    file(&f.ctx("a"), "a", 0o644);
    file(&f.ctx("sub/b"), "b", 0o644);
    for (i, source) in [".", "/", "./", "", "sub/.."].into_iter().enumerate() {
        f.copy(&spec(&[source], &format!("/app{i}/"))).unwrap();
        assert_eq!(listing(&f.root(&format!("app{i}"))), ["a", "sub"], "{source:?}");
    }
}

#[test]
fn a_missing_destination_directory_is_made_0755_with_its_parents() {
    let f = Fixture::new();
    file(&f.ctx("src/a"), "a", 0o644);
    dir(&f.ctx("src"), 0o700);
    for dest in ["/new/deep/dir", "/other/"] {
        f.copy(&spec(&["src"], dest)).unwrap();
    }
    for p in ["new", "new/deep", "new/deep/dir", "other"] {
        assert_eq!(mode(&f.root(p)), 0o755, "{p}");
    }
    assert_eq!(read(&f.root("new/deep/dir/a")), "a");
    assert_eq!(read(&f.root("other/a")), "a");
}

#[test]
fn a_file_goes_into_a_directory_and_otherwise_to_the_path_named() {
    let f = Fixture::new();
    file(&f.ctx("motd"), "hello", 0o640);
    dir(&f.root("srv"), 0o755);
    file(&f.root("data"), "old data", 0o600);
    file(&f.root("taken/motd/inner"), "in the way", 0o644);
    for (dest, copy) in [
        // A trailing slash: a directory, made if missing.
        ("/etc/", "etc/motd"),
        ("/etc/issue", "etc/issue"),
        // An existing directory needs no slash.
        ("/srv", "srv/motd"),
        // An existing file is replaced.
        ("/data", "data"),
        ("/new/name", "new/name"),
        // So is a directory with the file's name in the destination.
        ("/taken/", "taken/motd"),
    ] {
        let r = f.copy(&spec(&["motd"], dest)).unwrap();
        assert_eq!((r.entries, r.bytes), (1, 5), "{dest}");
        assert_eq!(read(&f.root(copy)), "hello", "{dest}");
        assert_eq!(mode(&f.root(copy)), 0o640, "{dest}");
    }
    assert_eq!(mode(&f.root("etc")), 0o755);
    assert_eq!(mode(&f.root("new")), 0o755);
}

#[test]
fn a_file_replaces_a_symlink_at_its_destination_rather_than_follow_it() {
    let f = Fixture::new();
    file(&f.ctx("motd"), "hello", 0o644);
    file(&f.outside("victim"), "keep", 0o644);
    symlink(f.outside("victim"), &f.root("absolute"));
    file(&f.root("etc/real"), "real", 0o644);
    symlink("/etc/real", &f.root("in-root"));
    symlink("nowhere", &f.root("dangling"));
    symlink("loop", &f.root("loop"));
    for name in ["absolute", "in-root", "dangling", "loop"] {
        f.copy(&spec(&["motd"], &format!("/{name}"))).unwrap();
        assert!(meta(&f.root(name)).is_file(), "{name}");
        assert_eq!(read(&f.root(name)), "hello", "{name}");
    }
    assert_eq!(read(&f.outside("victim")), "keep");
    assert_eq!(read(&f.root("etc/real")), "real");
}

#[test]
fn the_destination_resolves_inside_the_root_filesystem() {
    let f = Fixture::new();
    file(&f.ctx("motd"), "hello", 0o644);
    file(&f.ctx("src/a"), "a", 0o644);
    // The image's /app points at a path the host has too.
    symlink(f.outside(""), &f.root("app"));
    for (source, dest) in [("motd", "/app/"), ("src", "/app/sub")] {
        let err = f.copy(&spec(&[source], dest)).unwrap_err().to_string();
        assert!(err.contains(": /app: a symlink to a directory that doesn't exist"), "{err}");
    }
    // Once the image has that directory, the copies go there.
    let image_dir = inside(&f.root(""), &f.outside(""));
    std::fs::create_dir_all(&image_dir).unwrap();
    f.copy(&spec(&["motd"], "/app/")).unwrap();
    f.copy(&spec(&["src"], "/app/sub")).unwrap();
    assert_eq!(read(&image_dir.join("motd")), "hello");
    assert_eq!(read(&image_dir.join("sub/a")), "a");
    // `..` climbs out neither through a symlink nor in the destination.
    symlink("../../../../../../../..", &f.root("up"));
    f.copy(&spec(&["motd"], "/up/x")).unwrap();
    f.copy(&spec(&["motd"], "/../../../../y")).unwrap();
    assert_eq!(read(&f.root("x")), "hello");
    assert_eq!(read(&f.root("y")), "hello");
    assert!(listing(&f.outside("")).is_empty(), "something was written outside");
}

#[test]
fn a_destination_through_a_file_is_an_error() {
    let f = Fixture::new();
    file(&f.ctx("motd"), "hello", 0o644);
    file(&f.ctx("src/a"), "a", 0o644);
    file(&f.root("etc/passwd"), "root:x:0:0", 0o644);
    for (source, dest) in [("motd", "/etc/passwd/"), ("motd", "/etc/passwd/x"), ("src", "/etc/passwd")] {
        let err = f.copy(&spec(&[source], dest)).unwrap_err().to_string();
        assert!(err.contains("/etc/passwd: not a directory"), "{source} to {dest}: {err}");
    }
    assert_eq!(read(&f.root("etc/passwd")), "root:x:0:0");
}

#[test]
fn a_relative_destination_is_below_the_working_directory() {
    let f = Fixture::new();
    file(&f.ctx("motd"), "hello", 0o644);
    for (dest, copy) in [
        ("conf/", "srv/app/conf/motd"),
        (".", "srv/app/motd"),
        ("renamed", "srv/app/renamed"),
        ("../up.txt", "srv/up.txt"),
        ("/abs/", "abs/motd"),
    ] {
        f.copy(&CopySpec { workdir: "/srv/app".to_owned(), ..spec(&["motd"], dest) }).unwrap();
        assert_eq!(read(&f.root(copy)), "hello", "{dest}");
    }
}

#[test]
fn wildcards_match_names_a_component_at_a_time_in_name_order() {
    let f = Fixture::new();
    for (p, data) in [
        ("a.txt", "a"),
        ("b.txt", "b"),
        ("c.md", "c"),
        (".hidden.txt", "h"),
        ("x*y.txt", "a star"),
        ("dir/x.txt", "x"),
        ("dir/sub/y.txt", "y"),
        ("d1/f1", "1"),
        ("d2/f2", "2"),
        ("d1/same", "one"),
        ("d2/same", "two"),
    ] {
        file(&f.ctx(p), data, 0o644);
    }
    let cases: [(&[&str], &str, &[&str]); 7] = [
        (&["*.txt"], "/txt/", &[".hidden.txt", "a.txt", "b.txt", "x*y.txt"]),
        (&["[ab].txt", "?.md"], "/some/", &["a.txt", "b.txt", "c.md"]),
        (&["d?/f*"], "/deep/", &["f1", "f2"]),
        // An escaped wildcard is itself.
        (&["x\\*y.*"], "/escaped/", &["x*y.txt"]),
        // A directory among the matches is copied by its contents, as by
        // Docker.
        (&["dir/*"], "/flat/", &["x.txt", "y.txt"]),
        // After a pattern, names are matched too: `dir` has no `same`.
        (&["d*/same"], "/last/", &["same"]),
        (&["./d1/../*.md"], "/cleaned/", &["c.md"]),
    ];
    for (sources, dest, names) in cases {
        let r = f.copy(&spec(sources, dest)).unwrap();
        assert_eq!(listing(&f.root(&dest[1..])), names, "{sources:?}");
        assert!(r.skipped.is_empty(), "{sources:?}");
    }
    assert_eq!(read(&f.root("last/same")), "two", "matches are copied in name order");
}

#[test]
fn a_name_that_is_not_there_is_an_error_naming_it() {
    let f = Fixture::new();
    file(&f.ctx("a.txt"), "a", 0o644);
    // A plain name; a path through a file; and a wildcard below a directory
    // that isn't there (BuildKit's walk of it fails: a typo, not a pattern
    // that matched nothing).
    for source in ["missing.txt", "a.txt/below", "nodir/*.txt", "nodir/sub/*", "a.txt/sub/*"] {
        let err = f.copy(&spec(&[source], "/out/")).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{source}: {err}");
        assert!(err.to_string().contains(&format!("{source:?}")), "{source}: {err}");
        assert!(f.digest(&spec(&[source], "/out/")).is_err(), "{source}: the digest takes it too");
    }
    let err = f.copy(&spec(&["[a"], "/out/")).unwrap_err().to_string();
    assert!(err.contains("\"[a\" is not a valid wildcard pattern"), "{err}");
    let err = f.copy(&spec(&[], "/out/")).unwrap_err().to_string();
    assert!(err.contains("no source files"), "{err}");
    assert!(listing(&f.root("")).is_empty(), "something was written");
}

// BuildKit sets `AllowEmptyWildcard: true` on every local source
// (`dockerfile2llb/convert_copy.go`; its file backend returns nil when a
// wildcard resolves to nothing), and the classic builder fails only when all
// the sources together match nothing (moby `copy.go`, "no source files were
// specified"): neither fails for `COPY package.json yarn.lock* ./`, the
// idiom of Next.js's own Dockerfile. The wildcards that matched nothing are
// reported, for a warning.
#[test]
fn a_wildcard_matching_nothing_beside_other_sources_is_no_error() {
    let f = Fixture::new();
    file(&f.ctx("package.json"), "{}", 0o644);
    file(&f.ctx("package-lock.json"), "{\"lock\":1}", 0o644);
    let s = CopySpec {
        workdir: "/app".to_owned(),
        ..spec(&["package.json", "yarn.lock*", "package-lock.json*", "pnpm-lock.yaml*"], "./")
    };
    let digest = f.digest(&s).unwrap();
    let r = f.copy(&s).unwrap();
    assert_eq!(listing(&f.root("app")), ["package-lock.json", "package.json"]);
    assert_eq!(r.unmatched, ["yarn.lock*", "pnpm-lock.yaml*"]);
    assert_eq!(r.entries, 2);
    // The digest skips them: it is what the same copy without them has, and
    // changes once one of them matches.
    let without = CopySpec { sources: vec!["package.json".into(), "package-lock.json*".into()], ..s.clone() };
    assert_eq!(f.digest(&without).unwrap(), digest);
    file(&f.ctx("yarn.lock"), "y", 0o644);
    assert_ne!(f.digest(&s).unwrap(), digest);
}

#[test]
fn wildcards_that_match_nothing_copy_nothing_and_make_nothing() {
    let f = Fixture::new();
    file(&f.ctx("a.txt"), "a", 0o644);
    file(&f.ctx("d1/f"), "f", 0o644);
    // In a directory with nothing that matches, below a file, a name after a
    // pattern that no directory has.
    let sources = ["*.nothing", "a.txt/*", "*/a.txt", "d*/same", "d1/*.md"];
    for source in sources {
        let r = f.copy(&spec(&[source], "/out/")).unwrap();
        assert_eq!((r.entries, r.unmatched), (0, vec![source.to_owned()]), "{source}");
        assert!(f.digest(&spec(&[source], "/out/")).is_ok(), "{source}");
    }
    let r = f.copy(&spec(&sources, "/out/")).unwrap();
    assert_eq!(r.unmatched, sources);
    assert!(listing(&f.root("")).is_empty(), "the destination was made for nothing");
}

#[test]
fn several_sources_need_a_directory_to_copy_into() {
    let f = Fixture::new();
    file(&f.ctx("a.txt"), "a", 0o644);
    file(&f.ctx("b.txt"), "b", 0o644);
    file(&f.ctx("c.md"), "c", 0o644);
    file(&f.root("file"), "a file", 0o644);
    for sources in [&["*.txt"][..], &["a.txt", "b.txt"], &["a.txt", "c.*"]] {
        for dest in ["/single", "/file"] {
            let err = f.copy(&spec(sources, dest)).unwrap_err().to_string();
            assert!(
                err.contains("2 sources need a directory") && err.contains(&format!("{dest:?}")),
                "{sources:?} to {dest}: {err}"
            );
        }
    }
    assert_eq!(listing(&f.root("")), ["file"], "something was written");
    assert_eq!(read(&f.root("file")), "a file");
    // One match is one source, which may go to a file's path.
    f.copy(&spec(&["*.md"], "/single.md")).unwrap();
    assert_eq!(read(&f.root("single.md")), "c");
    // An existing directory will do without a trailing slash.
    dir(&f.root("existing"), 0o755);
    f.copy(&spec(&["*.txt"], "/existing")).unwrap();
    assert_eq!(listing(&f.root("existing")), ["a.txt", "b.txt"]);
}

#[test]
fn chmod_sets_the_mode_of_every_file_and_directory_copied() {
    let f = Fixture::new();
    file(&f.ctx("src/f"), "f", 0o644);
    file(&f.ctx("src/sub/g"), "g", 0o600);
    dir(&f.ctx("src/sub"), 0o700);
    symlink("f", &f.ctx("src/link"));
    nix::unistd::mkfifo(&f.ctx("src/pipe"), Mode::from_bits_truncate(0o600)).unwrap();
    let (ctx, root) = (f.ctx(""), f.root(""));
    unblocked(move || {
        let chmod = CopySpec { mode: Some(0o750), ..spec(&["src"], "/a/b/") };
        copy(open(&ctx).as_fd(), open(&root).as_fd(), &chmod).map_err(|e| e.to_string())
    })
    .unwrap();
    for p in ["a/b/f", "a/b/sub", "a/b/sub/g", "a/b/pipe"] {
        assert_eq!(mode(&f.root(p)), 0o750, "{p}");
    }
    for p in ["a", "a/b"] {
        assert_eq!(mode(&f.root(p)), 0o755, "{p}: made, not copied");
    }
    assert!(meta(&f.root("a/b/link")).file_type().is_symlink());
    // The whole mode, special bits included.
    f.copy(&CopySpec { mode: Some(0o4711), ..spec(&["src/f"], "/single") }).unwrap();
    assert_eq!(mode(&f.root("single")), 0o4711);
}

#[test]
fn times_are_kept_and_without_privileges_the_owner_is_the_callers() {
    let f = Fixture::new();
    file(&f.ctx("src/f"), "f", 0o644);
    file(&f.ctx("src/sub/g"), "g", 0o644);
    symlink("f", &f.ctx("src/link"));
    let entries = ["f", "sub", "sub/g", "link"];
    // Times differ per entry, and are set once everything exists: making an
    // entry changes its directory's mtime.
    let stamp = |i: usize| ((ATIME + i as i64, 1_000 + i as i64), (MTIME + i as i64, 123_456_789 + i as i64));
    for (i, p) in entries.iter().enumerate() {
        set_times(&f.ctx("src").join(p), stamp(i).0, stamp(i).1);
    }
    f.copy(&CopySpec { owner: Some((12345, 54321)), ..spec(&["src"], "/dst/") }).unwrap();
    for (i, p) in entries.iter().enumerate() {
        let copy = f.root("dst").join(p);
        assert_eq!(times_of(&copy), stamp(i), "{p}");
        assert_eq!((meta(&copy).uid(), meta(&copy).gid()), (geteuid().as_raw(), getegid().as_raw()), "{p}");
    }
}

#[test]
fn symlinks_below_a_copied_directory_are_copied_as_they_are() {
    let f = Fixture::new();
    file(&f.outside("victim"), "keep", 0o644);
    file(&f.ctx("src/f"), "f", 0o644);
    let links = [
        ("relative", "f".to_owned()),
        ("absolute", f.outside("victim").display().to_string()),
        ("to-a-dir", f.outside("").display().to_string()),
        ("climbing", "../../../../../..".to_owned()),
        ("dangling", "nowhere/at/all".to_owned()),
    ];
    for (name, target) in &links {
        symlink(target, &f.ctx("src").join(name));
    }
    let r = f.copy(&spec(&["src"], "/dst")).unwrap();
    assert_eq!((r.entries, r.bytes), (1 + links.len() as u64, 1));
    for (name, target) in &links {
        let copy = f.root("dst").join(name);
        assert!(meta(&copy).file_type().is_symlink(), "{name}");
        assert_eq!(std::fs::read_link(&copy).unwrap(), Path::new(target), "{name}");
    }
    assert_eq!(read(&f.outside("victim")), "keep");
    assert_eq!(listing(&f.outside("")), ["victim"]);
}

#[test]
fn a_named_source_is_followed_inside_the_source_root() {
    let f = Fixture::new();
    file(&f.ctx("real.txt"), "the context's", 0o640);
    symlink("real.txt", &f.ctx("link"));
    file(&f.ctx("sub/inner"), "inner", 0o644);
    symlink("sub", &f.ctx("dirlink"));
    // To the host's path of a file outside the context: absolute, and
    // climbing.
    file(&f.outside("secret"), "the host's", 0o644);
    symlink(f.outside("secret"), &f.ctx("escape"));
    symlink(format!("../../../../../../../..{}", f.outside("secret").display()), &f.ctx("escape-up"));

    // The copy has the link's name, and its target's contents and mode.
    f.copy(&spec(&["link"], "/a/")).unwrap();
    assert_eq!(read(&f.root("a/link")), "the context's");
    assert_eq!(mode(&f.root("a/link")), 0o640);
    // A link to a directory: its contents.
    f.copy(&spec(&["dirlink"], "/b/")).unwrap();
    assert_eq!(listing(&f.root("b")), ["inner"]);

    for source in ["escape", "escape-up", "esc*"] {
        let err = f.copy(&spec(&[source], "/c/")).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)) && err.to_string().contains(source), "{source}: {err}");
    }
    assert!(!f.root("c").exists(), "something was copied");
    // What they lead to is the context's own path.
    file(&inside(&f.ctx(""), &f.outside("secret")), "inside the context", 0o644);
    f.copy(&spec(&["esc*"], "/c/")).unwrap();
    assert_eq!(listing(&f.root("c")), ["escape", "escape-up"]);
    for p in ["c/escape", "c/escape-up"] {
        assert_eq!(read(&f.root(p)), "inside the context", "{p}");
    }
    assert_eq!(read(&f.outside("secret")), "the host's");
}

#[test]
fn entries_replace_what_the_destination_has_and_directories_merge() {
    let f = Fixture::new();
    file(&f.root("app/x"), "a file", 0o644);
    file(&f.root("app/y/deep/z"), "a tree", 0o644);
    symlink(f.outside(""), &f.root("app/l"));
    file(&f.ctx("one/x/inner"), "now a directory", 0o644);
    file(&f.ctx("one/y"), "now a file", 0o644);
    file(&f.ctx("one/l/inner"), "not through the link", 0o644);

    f.copy(&spec(&["one"], "/app")).unwrap();
    assert_eq!(read(&f.root("app/x/inner")), "now a directory");
    assert_eq!(read(&f.root("app/y")), "now a file");
    assert!(meta(&f.root("app/l")).is_dir(), "the symlink is replaced, not followed");
    assert_eq!(read(&f.root("app/l/inner")), "not through the link");
    assert!(listing(&f.outside("")).is_empty());

    // And back.
    file(&f.ctx("two/x"), "a file again", 0o644);
    f.copy(&spec(&["two"], "/app")).unwrap();
    assert_eq!(read(&f.root("app/x")), "a file again");
}

#[test]
fn hard_links_between_copied_files_stay_links() {
    let f = Fixture::new();
    file(&f.ctx("src/a"), "three names", 0o644);
    std::fs::create_dir(f.ctx("src/sub")).unwrap();
    std::fs::hard_link(f.ctx("src/a"), f.ctx("src/sub/b")).unwrap();
    // Its third name is outside the directory copied.
    std::fs::hard_link(f.ctx("src/a"), f.ctx("c")).unwrap();
    // A symlink can have more than one name too (`hard_link` doesn't
    // follow it).
    symlink("a", &f.ctx("src/s"));
    std::fs::hard_link(f.ctx("src/s"), f.ctx("src/s2")).unwrap();

    let r = f.copy(&spec(&["src"], "/dst")).unwrap();
    // a, s, s2, sub, sub/b
    assert_eq!((r.entries, r.bytes), (5, 11));
    let ino = |p: &str| meta(&f.root(p)).ino();
    assert_eq!(ino("dst/sub/b"), ino("dst/a"));
    assert_eq!(meta(&f.root("dst/a")).nlink(), 2);
    assert_eq!(ino("dst/s2"), ino("dst/s"));
    assert_eq!(std::fs::read_link(f.root("dst/s2")).unwrap(), Path::new("a"));
    // Across the sources of one copy, too.
    let r = f.copy(&spec(&["src/a", "c"], "/both/")).unwrap();
    assert_eq!((r.entries, r.bytes), (2, 11));
    assert_eq!(ino("both/c"), ino("both/a"));
}

#[test]
fn fifos_are_made_anew_and_sockets_skipped() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.ctx("src/sub")).unwrap();
    nix::unistd::mkfifo(&f.ctx("src/pipe"), Mode::from_bits_truncate(0o600)).unwrap();
    std::fs::set_permissions(f.ctx("src/pipe"), Permissions::from_mode(0o640)).unwrap();
    set_times(&f.ctx("src/pipe"), (ATIME, 1), (MTIME, 2));
    let _sockets = [f.ctx("src/sock"), f.ctx("src/sub/sock")].map(|p| UnixListener::bind(p).unwrap());

    // The source FIFO must never be opened: copy where blocking shows.
    let (ctx, root) = (f.ctx(""), f.root(""));
    let (tree, named) = unblocked(move || {
        let (ctx, root) = (open(&ctx), open(&root));
        let run = |spec: CopySpec| copy(ctx.as_fd(), root.as_fd(), &spec).map_err(|e| e.to_string());
        (run(spec(&["src"], "/dst")), run(spec(&["src/pipe", "src/sock"], "/named/")))
    });
    let (tree, named) = (tree.unwrap(), named.unwrap());
    assert_eq!(tree.skipped, [PathBuf::from("src/sock"), PathBuf::from("src/sub/sock")]);
    assert_eq!(tree.entries, 2, "pipe, sub");
    assert_eq!(named.skipped, [PathBuf::from("src/sock")]);
    assert_eq!(named.entries, 1);
    for p in ["dst/pipe", "named/pipe"] {
        let m = meta(&f.root(p));
        assert!(m.file_type().is_fifo(), "{p}");
        assert_eq!(m.permissions().mode() & 0o7777, 0o640, "{p}");
        assert_eq!(times_of(&f.root(p)), ((ATIME, 1), (MTIME, 2)), "{p}");
    }
    for p in ["dst/sock", "dst/sub/sock", "named/sock"] {
        assert!(std::fs::symlink_metadata(f.root(p)).is_err(), "{p}");
    }
}

#[test]
fn extended_attributes_are_copied_but_not_overlays_own() {
    let f = Fixture::new();
    file(&f.ctx("src/file"), "x", 0o644);
    dir(&f.ctx("src/dir"), 0o755);
    for (p, name, value) in [
        ("src/file", "user.note", "hello"),
        ("src/file", "user.overlay.redirect", "/etc"),
        ("src/dir", "user.dir", "d"),
        ("src/dir", "user.overlay.opaque", "y"),
    ] {
        xattr::lset(&f.ctx(p), name, value.as_bytes()).unwrap();
    }
    for (source, dest) in [("src", "/tree/"), ("src/file", "/named/")] {
        f.copy(&spec(&[source], dest)).unwrap();
    }
    for p in ["tree/file", "named/file"] {
        assert_eq!(xattr::lget(&f.root(p), "user.note").unwrap(), b"hello", "{p}");
        assert_eq!(xattr::lget(&f.root(p), "user.overlay.redirect"), Err(Errno::ENODATA), "{p}");
    }
    assert_eq!(xattr::lget(&f.root("tree/dir"), "user.dir").unwrap(), b"d");
    assert_eq!(xattr::lget(&f.root("tree/dir"), "user.overlay.opaque"), Err(Errno::ENODATA));
}

/// A tar archive (`gnu`: with GNU's magic, else POSIX's) of files,
/// directories (`name/`), symlinks (`name -> target`) and character
/// devices (`char name`).
fn tarball(gnu: bool, entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = tar::Builder::new(Vec::new());
    for &(name, data) in entries {
        let mut h = if gnu { tar::Header::new_gnu() } else { tar::Header::new_ustar() };
        h.set_mtime(MTIME as u64);
        h.set_size(0);
        if let Some((link, target)) = name.split_once(" -> ") {
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_mode(0o777);
            out.append_link(&mut h, link, target).unwrap();
        } else if name.ends_with('/') {
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o755);
            out.append_data(&mut h, name, io::empty()).unwrap();
        } else if let Some(device) = name.strip_prefix("char ") {
            h.set_entry_type(tar::EntryType::Char);
            h.set_mode(0o666);
            h.set_device_major(1).unwrap();
            h.set_device_minor(3).unwrap();
            out.append_data(&mut h, device, io::empty()).unwrap();
        } else {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o640);
            h.set_size(data.len() as u64);
            out.append_data(&mut h, name, data.as_bytes()).unwrap();
        }
    }
    out.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 3).unwrap()
}

#[test]
fn add_extracts_tar_archives_whatever_their_compression_and_name() {
    let f = Fixture::new();
    let entries = [
        ("app/", ""),
        ("app/main.py", "print('hi')\n"),
        ("app/.wh.secret", "not a whiteout"),
        ("app/.wh..wh..opq", ""),
        ("top.txt", "top"),
        ("char dev/null", ""),
    ];
    let (posix, gnu) = (tarball(false, &entries), tarball(true, &entries));
    let archives = [("posix.tar", posix.clone()), ("gnu.tar.gz", gzip(&gnu)), ("no-extension", zstd(&posix))];
    for (name, bytes) in &archives {
        std::fs::write(f.ctx(name), bytes).unwrap();
    }
    for (i, (name, _)) in archives.iter().enumerate() {
        let r = f.copy(&add(&[name], &format!("/x{i}/"))).unwrap();
        // app/, its three files and top.txt; the device node is left out.
        assert_eq!(r.entries, 5, "{name}");
        assert_eq!((r.extracted, r.bytes), (1, 12 + 14 + 3), "{name}");
        assert_eq!(r.skipped, [Path::new(name).join("dev/null")], "{name}");
        let at = |p: &str| f.root(&format!("x{i}/{p}"));
        assert_eq!(listing(&at("")), ["app", "top.txt"], "{name}");
        assert_eq!(read(&at("app/main.py")), "print('hi')\n", "{name}");
        assert_eq!(mode(&at("app/main.py")), 0o640, "{name}: the archive's mode");
        assert_eq!(meta(&at("top.txt")).mtime(), MTIME, "{name}: the archive's times");
        // `.wh.` names are files like any other: an archive `ADD`ed is no
        // layer.
        for p in ["app/.wh.secret", "app/.wh..wh..opq"] {
            assert!(meta(&at(p)).is_file(), "{name}: {p}");
        }
        assert_eq!(read(&at("app/.wh.secret")), "not a whiteout", "{name}");
        assert!(xattr::lget(&at("app"), crate::unpack::USER_OPAQUE_XATTR).is_err(), "{name}: made opaque");
    }
}

#[test]
fn add_extracts_into_a_directory_and_stays_inside_it() {
    let f = Fixture::new();
    let tar = tarball(false, &[("link -> /", ""), ("link/escaped", "kept inside")]);
    std::fs::write(f.ctx("app.tar"), &tar).unwrap();
    // No trailing slash: an archive's destination is a directory all the
    // same.
    let r = f.copy(&add(&["app.tar"], "/plain")).unwrap();
    assert_eq!(r.extracted, 1);
    assert_eq!(mode(&f.root("plain")), 0o755);
    assert_eq!(read(&f.root("plain/escaped")), "kept inside", "`/` is the destination directory");
    assert!(!f.root("escaped").exists());
    // A file there is not one.
    file(&f.root("a-file"), "x", 0o644);
    let err = f.copy(&add(&["app.tar"], "/a-file")).unwrap_err().to_string();
    assert!(err.contains("/a-file: not a directory"), "{err}");
}

#[test]
fn add_copies_anything_else_as_it_is() {
    let f = Fixture::new();
    let tar = tarball(false, &[("inside", "x")]);
    let mut bad_sum = tar.clone();
    bad_sum[0] ^= 1;
    let mut gnu_magic_only = vec![0u8; BLOCK];
    gnu_magic_only[257..262].copy_from_slice(b"ustar");
    for (name, bytes) in [
        ("notes.txt", b"plain text, longer than nothing".to_vec()),
        ("empty", Vec::new()),
        ("data.gz", gzip(b"gzipped, but no archive")),
        ("data.zst", zstd(&[b'x'; 2000])),
        ("broken.tar.gz", gzip(&tar)[..20].to_vec()),
        ("short.tar", tar[..300].to_vec()),
        ("bad-checksum.tar", bad_sum),
        ("magic-only", gnu_magic_only),
    ] {
        std::fs::write(f.ctx(name), &bytes).unwrap();
        let r = f.copy(&add(&[name], "/dst/")).unwrap();
        assert_eq!((r.entries, r.extracted, r.bytes), (1, 0, bytes.len() as u64), "{name}");
        assert_eq!(std::fs::read(f.root("dst").join(name)).unwrap(), bytes, "{name}");
    }
    // `COPY` copies an archive as a file.
    std::fs::write(f.ctx("app.tar"), &tar).unwrap();
    f.copy(&spec(&["app.tar"], "/copied/")).unwrap();
    assert_eq!(std::fs::read(f.root("copied/app.tar")).unwrap(), tar);
}

#[test]
fn a_deep_tree_is_copied_and_hashed() {
    const DEPTH: usize = 300;
    let f = Fixture::new();
    let deep: PathBuf = std::iter::repeat_n("d", DEPTH).collect();
    file(&f.ctx("src").join(&deep).join("leaf"), "at the bottom", 0o644);
    let r = f.copy(&spec(&["src"], "/")).unwrap();
    assert_eq!(r.entries, DEPTH as u64 + 1);
    assert_eq!(read(&f.root("").join(&deep).join("leaf")), "at the bottom");
    f.digest(&spec(&["src"], "/")).unwrap();
}

#[test]
fn a_source_or_root_filesystem_that_is_not_a_directory_is_an_error() {
    let f = Fixture::new();
    file(&f.ctx("file"), "x", 0o644);
    let regular = File::open(f.ctx("file")).unwrap();
    let s = spec(&["file"], "/");
    for err in [
        copy(regular.as_fd(), open(&f.root("")).as_fd(), &s).unwrap_err(),
        copy(open(&f.ctx("")).as_fd(), regular.as_fd(), &s).unwrap_err(),
        digest(regular.as_fd(), &s).unwrap_err(),
    ] {
        assert!(err.to_string().contains("is not a directory"), "{err}");
    }
}

#[test]
fn the_digest_is_the_same_for_the_same_files_whatever_their_times() {
    let (a, b) = (Fixture::new(), Fixture::new());
    for f in [&a, &b] {
        file(&f.ctx("src/main.rs"), "fn main() {}", 0o644);
        file(&f.ctx("src/lib/mod.rs"), "", 0o600);
        symlink("main.rs", &f.ctx("src/link"));
        file(&f.ctx("README"), "read me", 0o644);
    }
    let s = spec(&["src", "README*"], "/app/");
    let d = a.digest(&s).unwrap();
    assert_eq!(a.digest(&s).unwrap(), d, "again");
    assert_eq!(b.digest(&s).unwrap(), d, "another context with the same files");
    for p in ["src/main.rs", "src/lib/mod.rs", "src/lib", "src/link", "README", "src"] {
        set_times(&a.ctx(p), (ATIME, 7), (MTIME, 9));
    }
    assert_eq!(a.digest(&s).unwrap(), d, "times changed");
    a.copy(&s).unwrap();
    assert_eq!(a.digest(&s).unwrap(), d, "after a copy, which reads everything");
    assert_ne!(a.digest(&spec(&["src"], "/app/")).unwrap(), d, "fewer sources");
}

#[test]
fn the_digest_changes_with_contents_names_modes_links_and_the_spec() {
    let f = Fixture::new();
    file(&f.ctx("src/main.rs"), "fn main() {}", 0o644);
    symlink("main.rs", &f.ctx("src/link"));
    file(&f.ctx("a.txt"), "a", 0o644);
    let s = spec(&["src", "*.txt"], "/app/");
    let mut seen = vec![f.digest(&s).unwrap()];
    let mut check = |what: &str, d: Digest| {
        assert!(!seen.contains(&d), "{what}: a digest seen before");
        seen.push(d);
    };
    std::fs::write(f.ctx("src/main.rs"), "fn main() { }").unwrap();
    check("contents", f.digest(&s).unwrap());
    std::fs::set_permissions(f.ctx("src/main.rs"), Permissions::from_mode(0o755)).unwrap();
    check("a mode", f.digest(&s).unwrap());
    std::fs::rename(f.ctx("a.txt"), f.ctx("b.txt")).unwrap();
    check("a match's name", f.digest(&s).unwrap());
    file(&f.ctx("c.txt"), "a", 0o644);
    check("another match", f.digest(&s).unwrap());
    std::fs::remove_file(f.ctx("src/link")).unwrap();
    symlink("other.rs", &f.ctx("src/link"));
    check("a symlink's target", f.digest(&s).unwrap());
    std::fs::create_dir(f.ctx("src/empty")).unwrap();
    check("an empty directory", f.digest(&s).unwrap());
    std::fs::hard_link(f.ctx("src/main.rs"), f.ctx("src/same.rs")).unwrap();
    check("a hard link", f.digest(&s).unwrap());
    std::fs::remove_file(f.ctx("src/same.rs")).unwrap();
    file(&f.ctx("src/same.rs"), "fn main() { }", 0o755);
    check("the same file, unlinked", f.digest(&s).unwrap());

    let base = f.digest(&s).unwrap();
    for (what, other) in [
        ("the destination", spec(&["src", "*.txt"], "/srv/")),
        ("a trailing slash", spec(&["src", "*.txt"], "/app")),
        ("the working directory", CopySpec { workdir: "/srv".to_owned(), ..spec(&["src", "*.txt"], "app/") }),
        ("the owner", CopySpec { owner: Some((0, 1)), ..s.clone() }),
        // `None` (the sources' own owners) is not `Some((0, 0))`.
        ("keeping the sources' owners", CopySpec { owner: None, ..s.clone() }),
        ("--chmod", CopySpec { mode: Some(0o644), ..s.clone() }),
        ("ADD", CopySpec { extract_archives: true, ..s.clone() }),
        ("the sources' order", spec(&["*.txt", "src"], "/app/")),
    ] {
        check(what, f.digest(&other).unwrap());
    }
    // What makes no difference to the copy makes none to the digest.
    for (what, same) in [
        (
            "the working directory, for an absolute destination",
            CopySpec { workdir: "/elsewhere".to_owned(), ..s.clone() },
        ),
        ("paths written differently", spec(&["./src/", "/*.txt"], "/srv/../app/.")),
    ] {
        assert_eq!(f.digest(&same).unwrap(), base, "{what}");
    }
}

#[test]
fn the_modes_the_copy_does_not_keep_make_no_difference() {
    let f = Fixture::new();
    file(&f.ctx("src/a"), "a", 0o644);
    let s = spec(&["src"], "/");
    let d = f.digest(&s).unwrap();
    std::fs::set_permissions(f.ctx("src"), Permissions::from_mode(0o750)).unwrap();
    assert_eq!(f.digest(&s).unwrap(), d, "the source directory itself isn't copied");
    // With --chmod, the sources' modes are all replaced.
    let chmod = CopySpec { mode: Some(0o600), ..s };
    let d = f.digest(&chmod).unwrap();
    std::fs::set_permissions(f.ctx("src/a"), Permissions::from_mode(0o755)).unwrap();
    assert_eq!(f.digest(&chmod).unwrap(), d);
}

#[test]
fn the_digest_matches_and_follows_sources_as_the_copy_does() {
    let f = Fixture::new();
    file(&f.ctx("a.txt"), "a", 0o644);
    file(&f.outside("secret"), "the host's", 0o644);
    symlink(f.outside("secret"), &f.ctx("escape"));
    for source in ["missing", "escape"] {
        let err = f.digest(&spec(&[source], "/")).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{source}: {err}");
    }
    // A wildcard that matches nothing isn't copied, and isn't hashed.
    assert_eq!(f.digest(&spec(&["*.md", "a.txt"], "/")).unwrap(), f.digest(&spec(&["a.txt"], "/")).unwrap());
    assert!(f.digest(&spec(&["[a"], "/")).is_err());
    // A named symlink is hashed as what it leads to.
    symlink("a.txt", &f.ctx("link"));
    let d = f.digest(&spec(&["link"], "/x")).unwrap();
    std::fs::write(f.ctx("a.txt"), "changed").unwrap();
    assert_ne!(f.digest(&spec(&["link"], "/x")).unwrap(), d, "the contents of the link's target");
}

#[test]
fn patterns_match_as_gos_filepath_match_does() {
    // Go's own cases (`path/filepath/match_test.go`); `None` is
    // `ErrBadPattern`.
    let cases: &[(&str, &str, Option<bool>)] = &[
        ("abc", "abc", Some(true)),
        ("*", "abc", Some(true)),
        ("*c", "abc", Some(true)),
        ("a*", "a", Some(true)),
        ("a*", "abc", Some(true)),
        ("a*", "ab/c", Some(false)),
        ("a*/b", "abc/b", Some(true)),
        ("a*/b", "a/c/b", Some(false)),
        ("a*b*c*d*e*/f", "axbxcxdxe/f", Some(true)),
        ("a*b*c*d*e*/f", "axbxcxdxexxx/f", Some(true)),
        ("a*b*c*d*e*/f", "axbxcxdxe/xxx/f", Some(false)),
        ("a*b*c*d*e*/f", "axbxcxdxexxx/fff", Some(false)),
        ("a*b?c*x", "abxbbxdbxebxczzx", Some(true)),
        ("a*b?c*x", "abxbbxdbxebxczzy", Some(false)),
        ("ab[c]", "abc", Some(true)),
        ("ab[b-d]", "abc", Some(true)),
        ("ab[e-g]", "abc", Some(false)),
        ("ab[^c]", "abc", Some(false)),
        ("ab[^b-d]", "abc", Some(false)),
        ("ab[^e-g]", "abc", Some(true)),
        ("a\\*b", "a*b", Some(true)),
        ("a\\*b", "ab", Some(false)),
        ("a?b", "a☺b", Some(true)),
        ("a[^a]b", "a☺b", Some(true)),
        ("a???b", "a☺b", Some(false)),
        ("a[^a][^a][^a]b", "a☺b", Some(false)),
        ("[a-ζ]*", "α", Some(true)),
        ("*[a-ζ]", "A", Some(false)),
        ("a?b", "a/b", Some(false)),
        ("a*b", "a/b", Some(false)),
        ("[\\]a]", "]", Some(true)),
        ("[\\-]", "-", Some(true)),
        ("[x\\-]", "x", Some(true)),
        ("[x\\-]", "-", Some(true)),
        ("[x\\-]", "z", Some(false)),
        ("[\\-x]", "x", Some(true)),
        ("[\\-x]", "-", Some(true)),
        ("[\\-x]", "a", Some(false)),
        ("[]a]", "]", None),
        ("[-]", "-", None),
        ("[x-]", "x", None),
        ("[x-]", "-", None),
        ("[x-]", "z", None),
        ("[-x]", "x", None),
        ("[-x]", "-", None),
        ("[-x]", "a", None),
        ("\\", "a", None),
        ("[a-b-c]", "a", None),
        ("[", "a", None),
        ("[^", "a", None),
        ("[^bc", "a", None),
        ("a[", "a", None),
        ("a[", "ab", None),
        ("a[", "x", None),
        ("a/b[", "x", None),
        ("*x", "xxx", Some(true)),
    ];
    for &(pattern, name, want) in cases {
        assert_eq!(glob::matches(pattern.as_bytes(), name.as_bytes()).ok(), want, "{pattern:?} against {name:?}");
    }
    // A name needn't be UTF-8: a byte that starts no character is one.
    assert_eq!(glob::matches(b"a?b", b"a\xffb"), Ok(true));
    assert_eq!(glob::matches(b"a??b", b"a\xffb"), Ok(false));
    assert_eq!(glob::matches(b"*", b"\xff\xfe"), Ok(true));
}

#[test]
fn a_component_is_a_pattern_if_it_has_an_unescaped_wildcard() {
    for (component, pattern) in [
        ("*.txt", true),
        ("a?", true),
        ("[ab]", true),
        ("plain.txt", false),
        ("a\\*", false),
        ("a\\[b\\]", false),
        ("a\\\\*", true),
    ] {
        assert_eq!(glob::is_pattern(component.as_bytes()), pattern, "{component}");
    }
}

#[test]
fn paths_are_cleaned_as_docker_cleans_them() {
    let cases: [(&str, &[&str]); 7] = [
        ("", &[]),
        ("/", &[]),
        ("./a//b/", &["a", "b"]),
        ("../../a", &["a"]),
        ("a/../../b", &["b"]),
        ("a/./b/..", &["a"]),
        ("/a/b/../../..", &[]),
    ];
    for (path, components) in cases {
        assert_eq!(clean(path), components, "{path:?}");
    }
    for (dest, absolute) in [
        ("/app", "/app"),
        ("/app/", "/app/"),
        ("app", "/srv/app"),
        (".", "/srv/"),
        ("..", "/"),
        ("", "/srv/"),
        ("x/.", "/srv/x/"),
        ("/", "/"),
    ] {
        let spec = CopySpec { workdir: "/srv".to_owned(), ..spec(&["a"], dest) };
        assert_eq!(Target::new(&spec).absolute(), absolute, "{dest:?}");
    }
}

// ---------------------------------------------------------------------------
// Owners. An ordinary user can't give files to others, so most of these run
// the copier as root runs it (`privileged` set by hand) with owners the
// caller may give: its own uid, its primary gid, and another group of its own
// as the source's. The two `_needs_root` tests check the same for real, and
// are skipped for anyone else.

/// A group of the caller's other than its primary one, which any user may give
/// their own files to; `None` if there is none (the test is skipped).
fn other_group() -> Option<u32> {
    let primary = getegid();
    nix::unistd::getgroups().ok()?.into_iter().find(|&g| g != primary).map(Gid::as_raw)
}

/// What [`copy`] does for root, run by an ordinary user: its steps with
/// `privileged` set by hand.
fn copy_as_root(f: &Fixture, spec: &CopySpec) {
    let (src, dest) = (open(&f.ctx("")), open(&f.root("")));
    let target = Target::new(spec);
    let Expanded { named, .. } = expand(src.as_fd(), &spec.sources).unwrap();
    let into = target.dir || existing_dir(dest.as_fd(), &target).unwrap();
    let mut copier = Copier {
        spec,
        privileged: true,
        repeated_sources: spec.sources.len() > 1,
        report: CopyReport::default(),
        links: HashMap::new(),
    };
    for named in &named {
        copier.named(src.as_fd(), dest.as_fd(), named, &target, into).unwrap();
    }
}

// `COPY --from=<stage>` without `--chown` keeps the source's owners: moby
// `dispatchers.go` (`if c.From != "" && chownStr == "" { preserveOwnership =
// true }`) and `internals.go` (`if !inst.preserveOwnership { opts.identity =
// &id }`); BuildKit passes no chowner then and fsutil's `copyFileInfo` keeps
// the source's uid/gid. That is `owner: None`: files, directories merged or
// copied, symlinks and hard links keep what the source has.
#[test]
fn copy_from_a_stage_without_chown_keeps_the_source_owners() {
    let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
    let Some(other) = other_group() else {
        eprintln!("skipped: the caller has no group besides its primary one");
        return;
    };
    let f = Fixture::new();
    file(&f.ctx("app/data/db"), "state", 0o644);
    symlink("db", &f.ctx("app/data/current"));
    std::fs::hard_link(f.ctx("app/data/db"), f.ctx("app/db2")).unwrap();
    for p in ["app", "app/data", "app/data/db"] {
        std::os::unix::fs::chown(f.ctx(p), None, Some(other)).unwrap();
    }
    std::os::unix::fs::lchown(f.ctx("app/data/current"), None, Some(other)).unwrap();
    // A directory of the destination that the copy merges into.
    dir(&f.root("srv/data"), 0o755);
    let kept = ["srv/data", "srv/data/db", "srv/data/current", "srv/db2"];
    copy_as_root(&f, &CopySpec { owner: None, ..spec(&["app"], "/srv/") });
    let lost: Vec<_> = kept.into_iter().filter(|p| meta(&f.root(p)).gid() != other).collect();
    assert!(lost.is_empty(), "{lost:?} lost the source's group {other} (the caller's own is {gid})");
    assert_eq!(meta(&f.root("srv")).gid(), gid, "the destination directory keeps its own owner");
    // `Some` replaces them, as `--chown` does.
    copy_as_root(&f, &CopySpec { owner: Some((uid, gid)), ..spec(&["app"], "/srv/") });
    for p in kept {
        assert_eq!(meta(&f.root(p)).gid(), gid, "{p}");
    }
}

// `--chown` reaches everything the copy makes (files, directories, symlinks,
// FIFOs, hard links, and the missing parents of the destination, which are
// also 0755), while an existing destination directory keeps its own owner and
// mode (BuildKit: `copyDirectory` with `overwriteTargetMetadata` false for the
// top; moby: `fixPermissions` skips what existed).
#[test]
fn chown_reaches_every_entry_the_copy_makes() {
    let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
    let Some(other) = other_group() else {
        eprintln!("skipped: the caller has no group besides its primary one");
        return;
    };
    let f = Fixture::new();
    std::fs::create_dir_all(f.ctx("src/sub")).unwrap();
    std::fs::create_dir_all(f.root("existing")).unwrap();
    file(&f.ctx("src/f"), "f", 0o644);
    file(&f.ctx("src/sub/g"), "g", 0o644);
    symlink("f", &f.ctx("src/link"));
    nix::unistd::mkfifo(&f.ctx("src/pipe"), Mode::from_bits_truncate(0o600)).unwrap();
    std::fs::hard_link(f.ctx("src/f"), f.ctx("src/sub/f2")).unwrap();
    for dest in ["/made/by/the/copy/", "/existing/"] {
        copy_as_root(&f, &CopySpec { owner: Some((uid, other)), ..spec(&["src"], dest) });
    }
    for p in ["made", "made/by", "made/by/the", "made/by/the/copy"] {
        assert_eq!((meta(&f.root(p)).gid(), mode(&f.root(p))), (other, 0o755), "{p}: a directory the copy made");
    }
    for d in ["made/by/the/copy", "existing"] {
        for p in ["f", "sub", "sub/g", "sub/f2", "link", "pipe"] {
            assert_eq!(meta(&f.root(&format!("{d}/{p}"))).gid(), other, "{d}/{p}");
        }
    }
    assert_eq!(meta(&f.root("existing")).gid(), gid, "an existing destination directory keeps its owner");
}

// The same for real: as root, `None` keeps the owners (the source's uid and
// gid, not a fixed one), and the directories made only to hold the
// destination are root's, 0755.
#[test]
fn copy_from_a_stage_without_chown_keeps_the_source_owners_needs_root() {
    if !geteuid().is_root() {
        eprintln!("skipped: needs root (owners can't be set otherwise)");
        return;
    }
    let f = Fixture::new();
    file(&f.ctx("app/data/db"), "state", 0o644);
    symlink("db", &f.ctx("app/data/current"));
    for p in ["app", "app/data", "app/data/db"] {
        std::os::unix::fs::chown(f.ctx(p), Some(1000), Some(1001)).unwrap();
    }
    std::os::unix::fs::lchown(f.ctx("app/data/current"), Some(1000), Some(1001)).unwrap();
    f.copy(&CopySpec { owner: None, ..spec(&["app"], "/made/by/the/copy/") }).unwrap();
    for p in ["data", "data/db", "data/current"] {
        let m = meta(&f.root(&format!("made/by/the/copy/{p}")));
        assert_eq!((m.uid(), m.gid()), (1000, 1001), "{p} lost its source's owner");
    }
    for p in ["made", "made/by", "made/by/the", "made/by/the/copy"] {
        let m = meta(&f.root(p));
        assert_eq!((m.uid(), m.gid(), mode(&f.root(p))), (0, 0, 0o755), "{p}: made only to hold the destination");
    }
    // And `Some` still sets the owner of the copies.
    f.copy(&CopySpec { owner: Some((2000, 2001)), ..spec(&["app"], "/chowned/") }).unwrap();
    let m = meta(&f.root("chowned/data/db"));
    assert_eq!((m.uid(), m.gid()), (2000, 2001));
}

// `ADD --chown=u:g archive.tar /dst/`: BuildKit gives every extracted entry
// the `--chown` owner (solver/llbsolver/file/unpack.go: `opts.ChownOpts =
// &archive.ChownOpts{UID: u.UID, GID: u.GID}` when the copy has an owner; the
// destination directory is made with it too), so `ADD --chown=app:app app.tar
// /app/` doesn't leave whoever packed the archive (uid 501 from a Mac, say)
// as the owner. Without an owner the archive's own are kept. Needs root.
#[test]
fn add_chown_applies_to_the_files_extracted_from_an_archive_needs_root() {
    if !geteuid().is_root() {
        eprintln!("skipped: needs root (owners can't be set otherwise)");
        return;
    }
    let f = Fixture::new();
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_ustar();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_uid(501);
    h.set_gid(20);
    h.set_size(5);
    h.set_mtime(MTIME as u64);
    h.set_cksum();
    b.append_data(&mut h, "hello.txt", &b"hello"[..]).unwrap();
    std::fs::write(f.ctx("app.tar"), b.into_inner().unwrap()).unwrap();
    f.copy(&CopySpec { owner: Some((1000, 1001)), ..add(&["app.tar"], "/app/") }).unwrap();
    let m = meta(&f.root("app/hello.txt"));
    assert_eq!((m.uid(), m.gid()), (1000, 1001), "the archive's owner (501:20) stayed");
    f.copy(&CopySpec { owner: None, ..add(&["app.tar"], "/kept/") }).unwrap();
    let m = meta(&f.root("kept/hello.txt"));
    assert_eq!((m.uid(), m.gid()), (501, 20), "without an owner the archive's own are kept");
}

// The digest of a copy that keeps the sources' owners has them: the copy is
// different when one changes (for `Some`, the copy sets its own and they make
// no difference).
#[test]
fn the_digest_of_a_copy_that_keeps_owners_has_the_sources_owners() {
    let Some(other) = other_group() else {
        eprintln!("skipped: the caller has no group besides its primary one");
        return;
    };
    let f = Fixture::new();
    file(&f.ctx("src/a"), "a", 0o644);
    dir(&f.ctx("src/sub"), 0o755);
    let (keeping, setting) = (CopySpec { owner: None, ..spec(&["src"], "/") }, spec(&["src"], "/"));
    let (k, s) = (f.digest(&keeping).unwrap(), f.digest(&setting).unwrap());
    assert_ne!(k, s, "None isn't Some((0, 0))");
    for p in ["src/a", "src/sub"] {
        std::os::unix::fs::chown(f.ctx(p), None, Some(other)).unwrap();
        let after = f.digest(&keeping).unwrap();
        assert_ne!(after, k, "{p}: its group changed");
        std::os::unix::fs::chown(f.ctx(p), None, Some(getegid().as_raw())).unwrap();
        assert_eq!(f.digest(&keeping).unwrap(), k);
    }
    std::os::unix::fs::chown(f.ctx("src/a"), None, Some(other)).unwrap();
    assert_eq!(f.digest(&setting).unwrap(), s, "the copy sets its own owners");
}

// ---------------------------------------------------------------------------
// The cache key and extended attributes

// `copy::digest` is the build cache's key for a COPY: it must change whenever
// what `copy` produces changes, times and (for a `Some` owner) owners
// excepted. `copy` copies extended attributes (as root `security.capability`
// and `trusted.*` too), and the daemon's build context is unpacked with the
// archive's `SCHILY.xattr.*` records applied. A changed attribute of a file or
// directory (a symlink's can't be seen unprivileged) must miss the cache;
// overlay's own are left out of the copy, and so out of the key.
#[test]
fn the_digest_changes_when_an_extended_attribute_changes() {
    let f = Fixture::new();
    file(&f.ctx("src/tool"), "#!/bin/sh\n", 0o755);
    dir(&f.ctx("src/dir"), 0o755);
    let (tree, named) = (spec(&["src"], "/app/"), spec(&["src/tool"], "/app/"));
    let (before, named_before) = (f.digest(&tree).unwrap(), f.digest(&named).unwrap());
    xattr::lset(&f.ctx("src/tool"), "user.capability-like", b"cap_net_bind_service+ep").unwrap();
    // What the copy makes is different now…
    f.copy(&tree).unwrap();
    assert_eq!(xattr::lget(&f.root("app/tool"), "user.capability-like").unwrap(), b"cap_net_bind_service+ep");
    // …so the key must be too, as a tree and as a named file.
    let with_attribute = f.digest(&tree).unwrap();
    assert_ne!(with_attribute, before, "the cache key ignores extended attributes");
    assert_ne!(f.digest(&named).unwrap(), named_before, "…of a named file");
    xattr::lset(&f.ctx("src/tool"), "user.capability-like", b"another value").unwrap();
    assert_ne!(f.digest(&tree).unwrap(), with_attribute, "…and their values");
    xattr::lset(&f.ctx("src/dir"), "user.note", b"x").unwrap();
    let with_directory = f.digest(&tree).unwrap();
    assert_ne!(with_directory, with_attribute, "…of a directory");
    // Overlay's own aren't copied, so they make no difference.
    xattr::lset(&f.ctx("src/dir"), "user.overlay.opaque", b"y").unwrap();
    xattr::lset(&f.ctx("src/tool"), "user.overlay.redirect", b"/etc").unwrap();
    assert_eq!(f.digest(&tree).unwrap(), with_directory);
}

// ---------------------------------------------------------------------------
// ADD

/// One entry of [`raw_tar`]: its name exactly as stored, type, mode, data.
struct RawEntry {
    name: &'static str,
    kind: tar::EntryType,
    mode: u32,
    data: &'static str,
}

fn raw(name: &'static str, kind: tar::EntryType, mode: u32, data: &'static str) -> RawEntry {
    RawEntry { name, kind, mode, data }
}

/// A ustar archive (`old`: V7 headers, without the `ustar` magic) of these
/// entries, names written as given (no normalization by the tar crate).
fn raw_tar(old: bool, entries: &[RawEntry]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for e in entries {
        let mut h = if old { tar::Header::new_old() } else { tar::Header::new_ustar() };
        h.as_old_mut().name[..e.name.len()].copy_from_slice(e.name.as_bytes());
        h.set_entry_type(e.kind);
        h.set_mode(e.mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(MTIME as u64);
        h.set_size(e.data.len() as u64);
        h.set_cksum();
        b.append(&h, e.data.as_bytes()).unwrap();
    }
    b.into_inner().unwrap()
}

// "ADD: a source that is a tar archive (plain, gzip or zstd, told by its
// content …) is extracted" (copy.rs). Docker decides with
// `archive.IsArchivePath` (BuildKit: `isArchivePath`): decompress, then
// `tar.NewReader(r).Next()` succeeds, and Go's reader accepts a V7 header
// (no `ustar` magic) whose checksum adds up, signed or unsigned
// (`archive/tar` `block.getFormat`: `default: return formatV7`). So Docker
// extracts a V7 archive (`tar --format=v7`, old tools).
#[test]
fn add_extracts_a_v7_tar_archive() {
    let f = Fixture::new();
    let tar = raw_tar(true, &[raw("hello.txt", tar::EntryType::Regular, 0o644, "hello")]);
    // Go reads this header: the checksum is right, there is no magic.
    assert_eq!(&tar[257..262], &[0u8; 5], "a V7 header");
    std::fs::write(f.ctx("old.tar"), &tar).unwrap();
    let r = f.copy(&add(&["old.tar"], "/dst/")).unwrap();
    assert_eq!(r.extracted, 1, "copied as a file: {:?}", listing(&f.root("dst")));
    assert_eq!(read(&f.root("dst/hello.txt")), "hello");
    // Compressed, too.
    std::fs::write(f.ctx("old.tar.gz"), gzip(&tar)).unwrap();
    assert_eq!(f.copy(&add(&["old.tar.gz"], "/gz/")).unwrap().extracted, 1);
    assert_eq!(read(&f.root("gz/hello.txt")), "hello");
}

// Go also takes a checksum summed over signed bytes (what old tars made for
// a name with a byte over 0x7f). It is an archive, then, and never a file to
// copy: it is extracted, or (the `tar` crate counts only unsigned sums) an
// error says why.
#[test]
fn add_does_not_copy_a_tar_with_a_signed_checksum_as_a_file() {
    let f = Fixture::new();
    let mut h = tar::Header::new_old();
    h.as_old_mut().name[..8].copy_from_slice(b"caf\xe9.txt");
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(5);
    h.set_cksum();
    let signed: i64 = h
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &b)| i64::from(if (148..156).contains(&i) { b' ' as i8 } else { b as i8 }))
        .sum();
    h.as_mut_bytes()[148..156].copy_from_slice(format!("{signed:06o}\0 ").as_bytes());
    let mut tar = h.as_bytes().to_vec();
    tar.extend_from_slice(b"hello");
    tar.resize(1024 + 512, 0);
    std::fs::write(f.ctx("signed.tar"), &tar).unwrap();
    assert!(is_tar_header(&tar[..BLOCK]), "Go reads this as a header");
    match f.copy(&add(&["signed.tar"], "/dst/")) {
        Ok(r) => assert_eq!(r.extracted, 1, "copied as a file"),
        Err(e) => assert!(e.to_string().contains("extract the archive"), "{e}"),
    }
}

// `ADD` extracts an archive "as `tar -x` would" (copy.rs), but Docker skips
// an archive's own root entry (`./`): moby go-archive `Unpack`, `name :=
// path.Clean(strings.TrimLeft(hdr.Name, "/")); if name == "." { continue }`
// ("Skip entries referring to the extraction root"), used by both the
// classic builder (`archiver.Untar`) and BuildKit (`chrootarchive.Untar`).
// So the destination directory keeps its mode, owner and times. Archives made
// with `tar -C dir -czf app.tgz .` (the usual way) start with `./`, carrying
// the packer's directory mode and uid; `ADD app.tgz /` would otherwise
// change the image's `/`.
#[test]
fn an_archives_root_entry_leaves_the_destination_directory_alone() {
    let f = Fixture::new();
    let tar = raw_tar(
        false,
        &[raw("./", tar::EntryType::Directory, 0o700, ""), raw("./hello.txt", tar::EntryType::Regular, 0o644, "hello")],
    );
    std::fs::write(f.ctx("app.tar"), &tar).unwrap();
    dir(&f.root("srv"), 0o755);
    let r = f.copy(&add(&["app.tar"], "/srv/")).unwrap();
    assert_eq!((r.extracted, r.entries), (1, 1), "the root entry isn't one of the copies");
    assert_eq!(read(&f.root("srv/hello.txt")), "hello");
    assert_eq!(mode(&f.root("srv")), 0o755, "the destination took the archive's `./` mode");
    assert_ne!(meta(&f.root("srv")).mtime(), MTIME, "the destination took the archive's `./` mtime");
    // A destination the copy makes is 0755 all the same.
    f.copy(&add(&["app.tar"], "/new/")).unwrap();
    assert_eq!(mode(&f.root("new")), 0o755);
}

// xz and bzip2 archives aren't extracted (no decompressor), and Docker's
// `ADD rootfs.tar.xz /` (Debian's own base image) would silently build an
// empty image if the file were copied as it is: a file with such a magic
// number and a tar's name is an error saying what to do. `COPY` copies it,
// and so does `ADD` for any other file, whatever its magic number.
#[test]
fn add_refuses_an_xz_or_bzip2_archive_it_can_not_extract() {
    // A ustar archive of `hello.txt` ("hello"), made with Python's lzma and
    // bz2 modules.
    const XZ: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a3e027ff00655d00341949ee8df0bac8ff9bfff20c69af11eb6354891df8a1deed50c1dd2d6af90712edcfcebee555cd853071eefa875688d3bce4d1b829d72dd3ff8d4b02689ad914a27f0ced518a73515e88c247652a12f4213c2f931e499f97e280c50a4e5691dbcf7900000000000029fc7242bdb593d300018101805000009ba23caab1c467fb020000000004595a";
    const BZ2: &str = "425a68393141592653596e376911000072fb80c900000240017f80008062449e40080820005434a3f5269a68d07ea81a6d4124994341a0001f77324841cc2421d84231eb299115490219315dee2761851100caf4a30256c625488dfc0fcfa2a056cef67cf466603f1772453850906e376911";
    let unhex = |h: &str| -> Vec<u8> {
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
    };
    let (xz, bz2) = (unhex(XZ), unhex(BZ2));
    let f = Fixture::new();
    for (name, bytes, kind) in [
        ("tools.tar.xz", &xz, "xz"),
        ("tools.txz", &xz, "xz"),
        ("TOOLS.TAR.XZ", &xz, "xz"),
        ("tools.tar.bz2", &bz2, "bzip2"),
        ("tools.tbz", &bz2, "bzip2"),
        ("tools.tbz2", &bz2, "bzip2"),
        // Named for one, made with the other.
        ("odd.tar.xz", &bz2, "bzip2"),
    ] {
        std::fs::write(f.ctx(name), bytes).unwrap();
        for err in [f.copy(&add(&[name], "/opt/")).unwrap_err(), f.digest(&add(&[name], "/opt/")).unwrap_err()] {
            assert!(matches!(err, Error::Unsupported(_)), "{name}: {err}");
            let message = err.to_string();
            assert!(message.contains(name) && message.contains(&format!("a {kind} archive")), "{name}: {message}");
            assert!(message.contains("use COPY to copy the file as it is"), "{name}: {message}");
        }
    }
    assert!(!f.root("opt").exists(), "something was written");
    // `COPY` copies them; `ADD`, other files with those magic numbers, and
    // tars' names without them.
    for name in ["tools.tar.xz", "tools.tar.bz2"] {
        f.copy(&spec(&[name], "/copied/")).unwrap();
        assert!(f.root("copied").join(name).is_file());
    }
    for (name, bytes) in [("data.xz", xz.clone()), ("data.bz2", bz2.clone()), ("notes.tar.xz", b"not xz".to_vec())] {
        std::fs::write(f.ctx(name), &bytes).unwrap();
        let r = f.copy(&add(&[name], "/files/")).unwrap();
        assert_eq!((r.entries, r.extracted), (1, 0), "{name}");
        assert_eq!(std::fs::read(f.root("files").join(name)).unwrap(), bytes, "{name}");
    }
}

// `ADD` extracts a *named* archive, not archives found inside a directory it
// copies (Docker: only a source that is itself an archive is unpacked).
#[test]
fn add_does_not_extract_archives_inside_a_copied_directory() {
    let f = Fixture::new();
    let tar = raw_tar(false, &[raw("inner.txt", tar::EntryType::Regular, 0o644, "in")]);
    std::fs::create_dir_all(f.ctx("src/sub")).unwrap();
    std::fs::write(f.ctx("src/app.tar"), &tar).unwrap();
    std::fs::write(f.ctx("src/sub/app.tgz"), gzip(&tar)).unwrap();
    let r = f.copy(&add(&["src"], "/dst/")).unwrap();
    assert_eq!(r.extracted, 0);
    assert_eq!(std::fs::read(f.root("dst/app.tar")).unwrap(), tar);
    assert!(f.root("dst/sub/app.tgz").is_file());
    assert!(!f.root("dst/inner.txt").exists());
}

// ---------------------------------------------------------------------------
// Hard links, `--chmod`, and a copy checked against `tar | tar`

// Hard links between copied files stay links (copy.rs), but a copy must not
// fail because of that. Docker copies each source on its own (classic: one
// tar stream per source; BuildKit: one `copy.Copy` per source), so
// `COPY d1 d2 /dst/` where `d1/x` and `d2/y` are one inode and `d2/x` is
// another file gives `/dst/x` (d2's) and `/dst/y` (the shared content).
// The copy of `d1/x` lost its only name to `d2/x`, and an inode with no names
// can't be linked (`ENOENT`): `y` is a copy of its own then. So is a source
// named twice (`COPY a a /dst/`), whose second copy replaces the first.
#[test]
fn a_hard_link_whose_first_copy_was_replaced_is_copied_anew() {
    let f = Fixture::new();
    file(&f.ctx("d1/x"), "shared", 0o644);
    dir(&f.ctx("d2"), 0o755);
    std::fs::hard_link(f.ctx("d1/x"), f.ctx("d2/y")).unwrap();
    file(&f.ctx("d2/x"), "d2's own x", 0o644);
    f.copy(&spec(&["d1", "d2"], "/dst/")).unwrap();
    assert_eq!(read(&f.root("dst/x")), "d2's own x");
    assert_eq!(read(&f.root("dst/y")), "shared");
    // Both names of what is copied again are links of each other again.
    file(&f.ctx("a.txt"), "twice", 0o644);
    std::fs::hard_link(f.ctx("a.txt"), f.ctx("b.txt")).unwrap();
    f.copy(&spec(&["a.txt", "b.txt", "a.txt"], "/twice/")).unwrap();
    assert_eq!(read(&f.root("twice/a.txt")), "twice");
    assert_eq!(meta(&f.root("twice/a.txt")).ino(), meta(&f.root("twice/b.txt")).ino());
}

// `--chmod` is BuildKit's (the classic builder refuses it: moby
// `dispatchers.go`, "the --chmod option requires BuildKit"), and BuildKit
// gives the directories a copy creates for its destination the `--chmod`
// mode, not 0755: tonistiigi/fsutil 183e7fb4d6 (2025-02, "copy: fix custom
// chmod for parent directories"; `Copy` and `prepareTargetDir` pass
// `*ci.Mode` to `MkdirAll`, which chmods each directory it makes; its test
// `TestCopyDirectoryChmodChown` copies into `dest/sub` with mode 0700 and
// checks `dest/sub` is 0700). rustlet makes them 0755 (copy.rs docs): a
// documented choice, and arguably the saner one (a 0600 directory can't be
// entered), so the difference is kept and this test says what rustlet does.
#[test]
fn chmod_leaves_the_directories_made_for_the_destination_0755() {
    let f = Fixture::new();
    file(&f.ctx("secrets/key"), "k", 0o644);
    f.copy(&CopySpec { mode: Some(0o700), ..spec(&["secrets"], "/run/secrets/") }).unwrap();
    assert_eq!(mode(&f.root("run/secrets/key")), 0o700);
    assert_eq!(mode(&f.root("run/secrets")), 0o755, "the destination directory the copy made");
    assert_eq!(mode(&f.root("run")), 0o755);
}

// A tree of awkward names, sizes, modes, links and empty directories is
// copied as `tar | tar` would (what Docker's classic builder does): same
// names, types, modes, contents, link targets, hard-link classes and
// modification times; and the digest of the source is stable across it.
#[test]
fn a_copy_matches_a_tar_pipe_for_an_assorted_tree() {
    let f = Fixture::new();
    let names = ["a b", "-x", ".hidden", "ünï", "tab\tname", "new\nline", "*", "?", "[x]", "x*y", "dir.d"];
    let sizes = [0usize, 1, 511, 512, 4095, 4096, 4097, (1 << 18) - 1, (1 << 18) + 1, (1 << 20) + 3];
    let mut n = 0u32;
    for (i, name) in names.iter().enumerate() {
        let size = sizes[i % sizes.len()];
        let data: String = (0..size).map(|j| char::from(b'a' + ((j as u32 + n) % 26) as u8)).collect();
        let m = [0o644, 0o600, 0o755, 0o4755, 0o2750, 0o444][i % 6];
        file(&f.ctx(&format!("src/{name}")), &data, m);
        file(&f.ctx(&format!("src/d{i}/{name}/leaf")), &data, 0o640);
        dir(&f.ctx(&format!("src/d{i}")), [0o755, 0o700, 0o1777, 0o750][i % 4]);
        n += 7;
    }
    std::fs::create_dir_all(f.ctx("src/empty/deeper")).unwrap();
    symlink("a b", &f.ctx("src/link"));
    symlink("/abs/nowhere", &f.ctx("src/dangling"));
    symlink("d0", &f.ctx("src/dirlink"));
    std::fs::hard_link(f.ctx("src/a b"), f.ctx("src/d1/hard")).unwrap();
    // Known times, set last: making entries changes their directories'.
    let mut all = Vec::new();
    walk(&f.ctx("src"), &mut all);
    for (i, p) in all.iter().enumerate().rev() {
        set_times(p, (ATIME + i as i64, 3 + i as i64), (MTIME + i as i64, 5 + i as i64));
    }
    let before = f.digest(&spec(&["src"], "/dst/")).unwrap();
    f.copy(&spec(&["src"], "/dst/")).unwrap();
    assert_eq!(f.digest(&spec(&["src"], "/dst/")).unwrap(), before);

    // The reference: tar | tar.
    let piped = f.tmp.path().join("piped");
    std::fs::create_dir(&piped).unwrap();
    let ok = std::process::Command::new("sh")
        .arg("-c")
        .arg("tar -C \"$1\" -cf - . | tar -C \"$2\" -xpf -")
        .arg("sh")
        .arg(f.ctx("src"))
        .arg(&piped)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let (mut ours, mut theirs) = (Vec::new(), Vec::new());
    describe(&f.root("dst"), &mut ours);
    describe(&piped, &mut theirs);
    assert_eq!(ours, theirs);
}

fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    let mut kids: Vec<_> = std::fs::read_dir(p).unwrap().map(|e| e.unwrap().path()).collect();
    kids.sort();
    for k in kids {
        out.push(k.clone());
        if meta(&k).is_dir() {
            walk(&k, out);
        }
    }
}

/// `(relative path, mode, contents or target, mtime, hard-link class)` of
/// everything below `root`, one line each.
fn describe(root: &Path, out: &mut Vec<String>) {
    let mut all = Vec::new();
    walk(root, &mut all);
    let mut classes: Vec<u64> = Vec::new();
    for p in all {
        let m = meta(&p);
        let rel = p.strip_prefix(root).unwrap().display().to_string();
        let what = if m.is_symlink() {
            format!("-> {}", std::fs::read_link(&p).unwrap().display())
        } else if m.is_file() {
            let class = match classes.iter().position(|&i| i == m.ino()) {
                Some(c) => c,
                None => {
                    classes.push(m.ino());
                    classes.len() - 1
                }
            };
            format!("{} bytes, digest {}, class {class}", m.len(), Digest::of(&std::fs::read(&p).unwrap()))
        } else {
            "dir".to_owned()
        };
        let mode = if m.is_symlink() { 0 } else { m.permissions().mode() & 0o7777 };
        // Whole seconds: ustar headers can't hold more (`copy` keeps the
        // nanoseconds, which is better than the reference).
        out.push(format!("{rel} {mode:o} {what} @{}", m.mtime()));
    }
}
