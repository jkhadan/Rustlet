//! Who a container runs as: resolving `USER` against the image's own
//! `/etc/passwd` and `/etc/group`.
//!
//! An image's `User` (or `rustlet run -u`) is `user[:group]`, each part a
//! name or a number: `nginx`, `101`, `nginx:adm`, `1000:1000`. The kernel
//! only takes numbers, and a name means whatever the *image* says it means:
//! uid 101 is `nginx` in the nginx image and nobody in particular on your
//! machine. So names are looked up in the image's files, never the host's.
//! The rules are runc's `user.GetExecUser`, which Docker calls on the
//! container's files:
//!
//! | `USER`      | uid            | gid                               | supplementary groups             |
//! |-------------|----------------|-----------------------------------|----------------------------------|
//! | unset, `""` | 0              | root's entry's, else 0            | the groups that list root        |
//! | `nginx`     | from its entry | from its entry                    | the groups that list `nginx`     |
//! | `101`       | 101            | its entry's if it has one, else 0 | as for that entry's name, if any |
//! | `…:adm`     | as above       | `adm`'s, from `/etc/group`        | none                             |
//! | `…:4`       | as above       | 4, listed or not                  | none                             |
//!
//! * **A number needs no entry; a name does.** Plenty of images have no
//!   `/etc/passwd` at all (static binaries built `FROM scratch`), and a
//!   number means the same to the kernel either way. A name that isn't
//!   there is an error, not a guess. A part made of digits is always a
//!   number, even if some entry happens to be called `101`.
//! * **First match wins** when a name or a uid appears twice, as with
//!   `getpwnam(3)`.
//! * **Supplementary groups** are what logging in would give the user
//!   (`initgroups(3)`): every group whose member list names them, in file
//!   order, each gid once. That is why `id` in an Alpine container shows
//!   root in `bin`, `daemon`, `sys`, `adm`, …. Naming a group replaces all
//!   of that: the process gets exactly that one group.
//! * **ids are `0..=4294967294`.** 4294967295 is `(uid_t)-1`, which
//!   `setresuid(2)`, `setresgid(2)` and `chown(2)` read as "leave this id
//!   unchanged": a container told to run as it would simply stay root. So
//!   it is refused in the spec, and a line that uses it is skipped (glibc
//!   would accept that line).
//! * **Malformed lines are skipped**, as glibc's parser skips them: blank
//!   lines, `#` comments, too few fields, an id that isn't a decimal number
//!   in range. runc instead reads an unparsable id as 0, so that a line like
//!   `app:x:oops:oops:…` makes `app` root; here `app` just doesn't exist.
//!
//! The formats are `passwd(5)`'s `name:password:uid:gid:gecos:home:shell`
//! and `group(5)`'s `name:password:gid:member,member,…`. As in glibc, the
//! trailing passwd fields may be missing (`name:x:1:1` has no home, which
//! counts as `/`) and the shell is the rest of the line; a group needs no
//! member list.
//!
//! ## Reading the files
//!
//! The files are written by whoever built the image, and read by the
//! daemon, as root, on the host. Nothing in them may be taken on trust,
//! least of all a path:
//!
//! * They are opened with **`openat2(RESOLVE_IN_ROOT)`** relative to an fd
//!   for the mounted rootfs. The kernel walks the path as if that directory
//!   were `/`: an absolute symlink (some images ship `/etc/passwd ->
//!   /usr/share/defaults/etc/passwd`) is followed *inside* the image, and
//!   `..` stops at its root. With a plain `rootfs.join("etc/passwd")`, an
//!   image's `passwd -> /etc/shadow` would have the daemon read the host's
//!   file. Docker resolves such paths in userspace first and opens the
//!   result afterwards, two steps that a concurrent rename can race; here
//!   the kernel does the walk and the open in one call.
//!   **`RESOLVE_NO_MAGICLINKS`** also refuses `/proc/<pid>/fd/…`-style
//!   links, which point wherever their fd does.
//! * **`O_NONBLOCK`**: opening a FIFO for reading waits for a writer, which
//!   could be forever. With the flag the open returns at once, and the
//!   regular-file check turns the FIFO down. **`O_NOCTTY`**: a terminal
//!   must not become the daemon's controlling terminal.
//! * **Regular files only, at most 1 MiB** (real ones are a few KiB): a
//!   10 GB file must not have the daemon read it all, and a FIFO, socket or
//!   device isn't a file to read. A file that exists but is anything else,
//!   or is larger, is an error naming it. A missing file counts as empty
//!   (`scratch` images have neither), so numeric users still work.
//!
//! The runtime reads `/etc/passwd` the same careful way, from inside the
//! container, to set `HOME` (`rustlet_runtime::process`).

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use rustlet_sys::Errno;
use rustlet_sys::fs::{ResolveFlags, openat2};

use crate::error::{Context, Error, Result};

/// The most of an image's `/etc/passwd` or `/etc/group` that is read.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// A line of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// A line of `/etc/group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// The process identity a `USER` spec resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups (`process.user.additionalGids`).
    pub additional_gids: Vec<u32>,
    /// The passwd name, if the user was found there.
    pub name: Option<String>,
    /// From passwd, else `/`.
    pub home: String,
}

/// Parses `/etc/passwd` text, skipping the lines glibc would skip (see the
/// module docs).
pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    lines(text)
        .filter_map(|line| {
            // Seven fields at most: the shell is the rest of the line, as
            // glibc reads it.
            let mut fields = line.splitn(7, ':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let uid = parse_id(fields.next()?)?;
            let gid = parse_id(fields.next()?)?;
            let _gecos = fields.next();
            let home = fields.next().unwrap_or_default();
            let shell = fields.next().unwrap_or_default();
            Some(PasswdEntry { name: name.into(), uid, gid, home: home.into(), shell: shell.into() })
        })
        .collect()
}

/// Parses `/etc/group` text, skipping the lines glibc would skip (see the
/// module docs).
pub fn parse_group(text: &str) -> Vec<GroupEntry> {
    lines(text)
        .filter_map(|line| {
            let mut fields = line.splitn(4, ':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let gid = parse_id(fields.next()?)?;
            let members = fields
                .next()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(String::from)
                .collect();
            Some(GroupEntry { name: name.into(), gid, members })
        })
        .collect()
}

/// The lines worth parsing: trimmed, neither blank nor `#` comments.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Is `s` written as a number (and so never looked up as a name)?
fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A uid or gid the kernel can take: decimal digits, `0..=u32::MAX - 1`.
/// Checking the digits first matters: Rust's `parse` alone would accept a
/// leading `+`.
fn parse_id(s: &str) -> Option<u32> {
    if !is_number(s) {
        return None;
    }
    s.parse().ok().filter(|&id| id != u32::MAX)
}

/// [`parse_id`] for a number written in the spec, where out of range is an
/// error rather than a line to skip.
fn spec_id(s: &str, what: &str) -> Result<u32> {
    parse_id(s).ok_or_else(|| Error::invalid(format!("{what} {s} is out of range (0 to {})", u32::MAX - 1)))
}

/// Resolves `spec` (`USER`, or `-u`) against parsed files, by the rules in
/// the module docs.
pub fn resolve_in(passwd: &[PasswdEntry], group: &[GroupEntry], spec: Option<&str>) -> Result<ResolvedUser> {
    let spec = spec.unwrap_or_default();
    let (user_part, group_part) = spec.split_once(':').unwrap_or((spec, ""));
    if group_part.contains(':') {
        return Err(Error::invalid(format!("user {spec:?}: expected user[:group]")));
    }

    let (uid, entry) = match user_part {
        "" => (0, passwd.iter().find(|p| p.uid == 0)),
        number if is_number(number) => {
            let uid = spec_id(number, "uid")?;
            (uid, passwd.iter().find(|p| p.uid == uid))
        }
        name => {
            let entry = passwd
                .iter()
                .find(|p| p.name == name)
                .ok_or_else(|| Error::invalid(format!("user {name:?} is not in the image's /etc/passwd")))?;
            (entry.uid, Some(entry))
        }
    };
    let mut user = ResolvedUser {
        uid,
        gid: entry.map_or(0, |p| p.gid),
        additional_gids: Vec::new(),
        name: entry.map(|p| p.name.clone()),
        home: entry.map(|p| p.home.as_str()).filter(|h| !h.is_empty()).unwrap_or("/").into(),
    };

    match group_part {
        // No group given: the user's own (above) plus every group that
        // lists them, if passwd knows their name.
        "" => {
            if let Some(name) = &user.name {
                let mut seen = HashSet::new();
                user.additional_gids = group
                    .iter()
                    .filter(|g| g.members.iter().any(|m| m == name))
                    .map(|g| g.gid)
                    .filter(|&gid| seen.insert(gid))
                    .collect();
            }
        }
        number if is_number(number) => user.gid = spec_id(number, "gid")?,
        name => {
            user.gid = group
                .iter()
                .find(|g| g.name == name)
                .ok_or_else(|| Error::invalid(format!("group {name:?} is not in the image's /etc/group")))?
                .gid;
        }
    }
    Ok(user)
}

/// Resolves `spec` against the files in the mounted rootfs `rootfs` (an fd
/// for its root directory), read as the module docs describe.
pub fn resolve(rootfs: BorrowedFd<'_>, spec: Option<&str>) -> Result<ResolvedUser> {
    let passwd = read_image_file(rootfs, "etc/passwd")?;
    let group = read_image_file(rootfs, "etc/group")?;
    resolve_in(&parse_passwd(&passwd), &parse_group(&group), spec)
}

/// Reads `path` (relative to the image's root) if it is a regular file of
/// at most [`MAX_FILE_BYTES`]; a missing file reads as empty.
fn read_image_file(rootfs: BorrowedFd<'_>, path: &str) -> Result<String> {
    let in_root = ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS;
    // Found as an O_PATH handle first, which opens nothing: a device node
    // there must not have its driver's open() called just to be refused.
    // (The container rootfs is mounted nodev as well.)
    let handle = match openat2(Some(rootfs), path, OFlag::O_PATH, Mode::empty(), in_root) {
        Ok(fd) => fd,
        // No such file, a dangling symlink, or an `etc` that isn't a
        // directory: no file, as in an image built `FROM scratch`.
        Err(Errno::ENOENT | Errno::ENOTDIR) => return Ok(String::new()),
        Err(e) => return Err(e).with_context(|| format!("open the image's /{path}")),
    };
    let st = rustlet_sys::fs::fstatx(handle.as_fd()).with_context(|| format!("stat the image's /{path}"))?;
    if st.file_type() != libc::S_IFREG {
        return Err(Error::invalid(format!("the image's /{path} is not a regular file")));
    }
    // Then opened for reading through the handle, so it is the same inode.
    let fd = rustlet_sys::fs::reopen(handle.as_fd(), OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOCTTY)
        .with_context(|| format!("open the image's /{path}"))?;
    let file = File::from(fd);
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).with_context(|| format!("read the image's /{path}"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(Error::invalid(format!("the image's /{path} is larger than {MAX_FILE_BYTES} bytes")));
    }
    // Names are matched as text, but one stray non-UTF-8 byte (a Latin-1
    // GECOS, say) must not make the whole file unreadable.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt, symlink};
    use std::path::Path;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Alpine 3.24's files, as its minirootfs ships them.
    const ALPINE_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
";
    const ALPINE_GROUP: &str = "\
root:x:0:root
bin:x:1:root,bin,daemon
daemon:x:2:root,bin,daemon
sys:x:3:root,bin
adm:x:4:root,daemon
tty:x:5:
disk:x:6:root
lp:x:7:lp
kmem:x:9:
wheel:x:10:root
floppy:x:11:root
mail:x:12:mail
news:x:13:news
uucp:x:14:uucp
cron:x:16:cron
audio:x:18:
cdrom:x:19:
dialout:x:20:root
ftp:x:21:
sshd:x:22:
input:x:23:
tape:x:26:root
video:x:27:root
netdev:x:28:
kvm:x:34:kvm
games:x:35:
shadow:x:42:
www-data:x:82:
users:x:100:games
ntp:x:123:
abuild:x:300:
utmp:x:406:
ping:x:999:
nogroup:x:65533:
nobody:x:65534:
";
    /// Every Alpine group that lists root: root (its own group lists it
    /// too), bin, daemon, sys, adm, disk, wheel, floppy, dialout, tape,
    /// video. `docker run alpine id` shows the same.
    const ALPINE_ROOT_GROUPS: [u32; 11] = [0, 1, 2, 3, 4, 6, 10, 11, 20, 26, 27];

    fn alpine(spec: Option<&str>) -> Result<ResolvedUser> {
        resolve_in(&parse_passwd(ALPINE_PASSWD), &parse_group(ALPINE_GROUP), spec)
    }

    fn user(uid: u32, gid: u32, additional_gids: &[u32], name: Option<&str>, home: &str) -> ResolvedUser {
        ResolvedUser {
            uid,
            gid,
            additional_gids: additional_gids.to_vec(),
            name: name.map(String::from),
            home: home.into(),
        }
    }

    fn invalid_with(result: Result<ResolvedUser>, words: &[&str]) -> bool {
        matches!(&result, Err(Error::Invalid(m)) if words.iter().all(|w| m.contains(w)))
    }

    #[test]
    fn parses_alpines_files() {
        let passwd = parse_passwd(ALPINE_PASSWD);
        assert_eq!(passwd.len(), 17);
        let ftp = PasswdEntry {
            name: "ftp".into(),
            uid: 21,
            gid: 21,
            home: "/var/lib/ftp".into(),
            shell: "/sbin/nologin".into(),
        };
        assert_eq!(passwd[11], ftp);
        let group = parse_group(ALPINE_GROUP);
        assert_eq!(group.len(), 35);
        assert_eq!(
            group[1],
            GroupEntry { name: "bin".into(), gid: 1, members: vec!["root".into(), "bin".into(), "daemon".into()] }
        );
        assert_eq!(group[5], GroupEntry { name: "tty".into(), gid: 5, members: vec![] });
    }

    #[test]
    fn no_user_is_root_with_its_groups() {
        for spec in [None, Some(""), Some(":")] {
            assert_eq!(alpine(spec).unwrap(), user(0, 0, &ALPINE_ROOT_GROUPS, Some("root"), "/root"), "{spec:?}");
        }
    }

    #[test]
    fn names_and_numbers() {
        // daemon is listed in bin, daemon and adm.
        let daemon = user(2, 2, &[1, 2, 4], Some("daemon"), "/sbin");
        assert_eq!(alpine(Some("daemon")).unwrap(), daemon);
        assert_eq!(alpine(Some("2")).unwrap(), daemon, "a uid with an entry gets its gid, home and groups");
        // games' own group lists nobody; users lists games.
        assert_eq!(alpine(Some("games")).unwrap(), user(35, 35, &[100], Some("games"), "/usr/games"));
        assert_eq!(alpine(Some("guest")).unwrap(), user(405, 100, &[], Some("guest"), "/dev/null"));
        assert_eq!(alpine(Some("1234")).unwrap(), user(1234, 0, &[], None, "/"), "a uid without one gets gid 0 and /");
    }

    #[test]
    fn a_named_or_numbered_group_replaces_the_implicit_ones() {
        assert_eq!(alpine(Some("daemon:wheel")).unwrap(), user(2, 10, &[], Some("daemon"), "/sbin"));
        assert_eq!(alpine(Some("daemon:42")).unwrap(), user(2, 42, &[], Some("daemon"), "/sbin"));
        assert_eq!(alpine(Some("1000:1000")).unwrap(), user(1000, 1000, &[], None, "/"));
        assert_eq!(alpine(Some("1000:wheel")).unwrap(), user(1000, 10, &[], None, "/"));
        assert_eq!(alpine(Some("root:root")).unwrap(), user(0, 0, &[], Some("root"), "/root"));
        assert_eq!(alpine(Some(":wheel")).unwrap(), user(0, 10, &[], Some("root"), "/root"), "no user is root");
        assert_eq!(alpine(Some("root:4242")).unwrap(), user(0, 4242, &[], Some("root"), "/root"), "gid not in group");
        assert_eq!(alpine(Some("games:")).unwrap(), alpine(Some("games")).unwrap(), "an empty group is no group");
    }

    #[test]
    fn unknown_names_are_errors() {
        assert!(invalid_with(alpine(Some("nginx")), &["\"nginx\"", "/etc/passwd"]));
        assert!(invalid_with(alpine(Some("root:nginx")), &["\"nginx\"", "/etc/group"]));
        assert!(invalid_with(alpine(Some("1000:nginx")), &["\"nginx\"", "/etc/group"]));
        // A sign makes it a name, and there is no user called that.
        assert!(invalid_with(alpine(Some("-1")), &["\"-1\""]));
        assert!(invalid_with(alpine(Some("+0")), &["\"+0\""]));
        assert!(invalid_with(alpine(Some("root:wheel:x")), &["user[:group]"]));
    }

    #[test]
    fn ids_must_fit_and_never_be_minus_one() {
        assert_eq!(alpine(Some("4294967294:4294967294")).unwrap(), user(u32::MAX - 1, u32::MAX - 1, &[], None, "/"));
        for spec in ["4294967295", "4294967296", "18446744073709551616", "0:4294967295", "root:99999999999"] {
            assert!(invalid_with(alpine(Some(spec)), &["out of range"]), "{spec}");
        }
        // In the files such ids make the line malformed. glibc would take
        // 4294967295, and `USER evil` would then leave the process root.
        let passwd = parse_passwd(
            "evil:x:4294967295:0::/:/bin/sh\nevil2:x:0:4294967295::/:/bin/sh\nbig:x:4294967296:0::/:/bin/sh\n\
             ok:x:4294967294:0::/:/bin/sh\n",
        );
        assert_eq!(passwd.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["ok"]);
        assert!(invalid_with(resolve_in(&passwd, &[], Some("evil")), &["\"evil\""]));
        let group = parse_group("evil:x:4294967295:ok\ngood:x:7:ok\n");
        assert_eq!(resolve_in(&passwd, &group, Some("ok")).unwrap().additional_gids, [7]);
    }

    #[test]
    fn first_match_wins_and_groups_are_listed_once() {
        let passwd = parse_passwd(
            "app:x:1000:1000::/home/app:/bin/sh\napp:x:0:0::/root:/bin/sh\nalias:x:1000:1500::/home/alias:/bin/sh\n",
        );
        let group = parse_group("staff:x:50:app\nstaff:x:60:app\nteam:x:70:app,app\nsame:x:50:alias,app\n");
        let app = user(1000, 1000, &[50, 60, 70], Some("app"), "/home/app");
        assert_eq!(resolve_in(&passwd, &group, Some("app")).unwrap(), app);
        assert_eq!(resolve_in(&passwd, &group, Some("1000")).unwrap(), app, "the first entry with the uid");
        assert_eq!(resolve_in(&passwd, &group, Some("app:staff")).unwrap().gid, 50);
        assert_eq!(
            resolve_in(&passwd, &group, Some("alias")).unwrap(),
            user(1000, 1500, &[50], Some("alias"), "/home/alias")
        );
    }

    #[test]
    fn comments_and_malformed_lines_are_skipped() {
        let passwd = parse_passwd(concat!(
            "# comment\n",
            "   # indented comment\n",
            "\n",
            "garbage\n",
            "short:x:1\n",
            "word:x:one:1::/:/bin/sh\n",
            "hex:x:0x10:1::/:/bin/sh\n",
            "signed:x:+5:5::/:/bin/sh\n",
            "spaced:x: 7:7::/:/bin/sh\n",
            "nogid:x:5:::/:/bin/sh\n",
            "  padded:x:5:5:Padded:/home/p:/bin/sh  \n",
            "minimal:x:6:6\n",
            "colons:x:7:7:gecos:/home/c:/bin/sh:extra\n",
            "crlf:x:8:8::/home/crlf:/bin/ash\r\n",
        ));
        let parsed: Vec<_> =
            passwd.iter().map(|p| (p.name.as_str(), p.uid, p.home.as_str(), p.shell.as_str())).collect();
        assert_eq!(
            parsed,
            [
                ("padded", 5, "/home/p", "/bin/sh"),
                ("minimal", 6, "", ""),
                ("colons", 7, "/home/c", "/bin/sh:extra"),
                ("crlf", 8, "/home/crlf", "/bin/ash"),
            ]
        );
        assert_eq!(resolve_in(&passwd, &[], Some("minimal")).unwrap().home, "/", "no home counts as /");

        let group = parse_group("# comment\nwheel:x:10: root , alice,,bob\nlonely:x:11\nword:x:ten:root\nshort:x\n");
        let members = vec!["root".to_string(), "alice".into(), "bob".into()];
        assert_eq!(
            group,
            [
                GroupEntry { name: "wheel".into(), gid: 10, members },
                GroupEntry { name: "lonely".into(), gid: 11, members: vec![] }
            ]
        );
    }

    #[test]
    fn without_files_only_numbers_resolve() {
        assert_eq!(resolve_in(&[], &[], None).unwrap(), user(0, 0, &[], None, "/"));
        assert_eq!(resolve_in(&[], &[], Some("65532:65532")).unwrap(), user(65532, 65532, &[], None, "/"));
        assert!(invalid_with(resolve_in(&[], &[], Some("nonroot")), &["\"nonroot\""]));
        assert!(invalid_with(resolve_in(&[], &[], Some("0:staff")), &["\"staff\""]));
    }

    fn open_root(dir: &Path) -> OwnedFd {
        nix::fcntl::open(dir, OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty()).unwrap()
    }

    /// A rootfs with an empty `etc/`.
    fn rootfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        dir
    }

    #[test]
    fn reads_the_files_in_the_rootfs() {
        let dir = rootfs();
        fs::write(dir.path().join("etc/passwd"), ALPINE_PASSWD).unwrap();
        fs::write(dir.path().join("etc/group"), ALPINE_GROUP).unwrap();
        let root = open_root(dir.path());
        assert_eq!(resolve(root.as_fd(), Some("daemon")).unwrap(), alpine(Some("daemon")).unwrap());
        assert_eq!(resolve(root.as_fd(), None).unwrap(), alpine(None).unwrap());
    }

    #[test]
    fn symlinks_are_followed_inside_the_image() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        // Decoys on the host side, next to the rootfs…
        let decoy = tmp.path().join("decoy");
        fs::create_dir(&decoy).unwrap();
        fs::write(decoy.join("passwd"), "app:x:666:666::/decoy:/bin/sh\n").unwrap();
        fs::write(decoy.join("group"), "staff:x:666:app\n").unwrap();
        // …and the image's files at the same paths inside it.
        let inside = rootfs.join(decoy.strip_prefix("/").unwrap());
        fs::create_dir_all(&inside).unwrap();
        fs::write(inside.join("passwd"), "app:x:1000:1000::/home/app:/bin/sh\n").unwrap();
        fs::create_dir_all(rootfs.join("decoy")).unwrap();
        fs::write(rootfs.join("decoy/group"), "staff:x:50:app\n").unwrap();
        // /etc/passwd is an absolute symlink naming the host decoy, and
        // /etc/group a relative one that climbs out with `..`.
        fs::create_dir(rootfs.join("etc")).unwrap();
        symlink(decoy.join("passwd"), rootfs.join("etc/passwd")).unwrap();
        symlink("../../decoy/group", rootfs.join("etc/group")).unwrap();
        // Followed from the host, both lead out of the rootfs…
        assert_eq!(fs::read_to_string(rootfs.join("etc/passwd")).unwrap(), "app:x:666:666::/decoy:/bin/sh\n");
        assert_eq!(fs::read_to_string(rootfs.join("etc/group")).unwrap(), "staff:x:666:app\n");
        // …but RESOLVE_IN_ROOT keeps them in it.
        let app = resolve(open_root(&rootfs).as_fd(), Some("app")).unwrap();
        assert_eq!(app, user(1000, 1000, &[50], Some("app"), "/home/app"));
    }

    #[test]
    fn a_fifo_is_refused_without_hanging() {
        let dir = rootfs();
        let fifo = dir.path().join("etc/group");
        rustlet_sys::fs::mkfifo(&fifo, Mode::from_bits_truncate(0o644)).unwrap();
        let root = open_root(dir.path());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(resolve(root.as_fd(), None));
        });
        let result = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| {
            // Let the stuck open (it waits for a writer) go, then fail.
            let _ = fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(&fifo);
            panic!("resolve blocked on a FIFO");
        });
        assert!(invalid_with(result, &["/etc/group", "not a regular file"]));
    }

    #[test]
    fn only_regular_files_up_to_1_mib_are_read() {
        let dir = rootfs();
        let root = open_root(dir.path());
        let mut passwd = String::from("root:x:0:0:root:/big:/bin/sh\n#");
        passwd.push_str(&"x".repeat(MAX_FILE_BYTES as usize - passwd.len()));
        fs::write(dir.path().join("etc/passwd"), &passwd).unwrap();
        assert_eq!(resolve(root.as_fd(), None).unwrap().home, "/big", "exactly 1 MiB is fine");
        passwd.push('x');
        fs::write(dir.path().join("etc/passwd"), &passwd).unwrap();
        assert!(invalid_with(resolve(root.as_fd(), None), &["/etc/passwd", "larger than 1048576 bytes"]));

        fs::remove_file(dir.path().join("etc/passwd")).unwrap();
        fs::create_dir(dir.path().join("etc/passwd")).unwrap();
        assert!(invalid_with(resolve(root.as_fd(), None), &["/etc/passwd", "not a regular file"]));
    }

    #[test]
    fn missing_files_count_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let root = open_root(dir.path());
        assert_eq!(resolve(root.as_fd(), None).unwrap(), user(0, 0, &[], None, "/"));
        assert_eq!(resolve(root.as_fd(), Some("65532")).unwrap(), user(65532, 0, &[], None, "/"));
        assert!(invalid_with(resolve(root.as_fd(), Some("nonroot")), &["\"nonroot\"", "/etc/passwd"]));
        // An `etc` that is a file, or a dangling symlink, is no different.
        fs::write(dir.path().join("etc"), "").unwrap();
        assert_eq!(resolve(root.as_fd(), Some("1000:1000")).unwrap(), user(1000, 1000, &[], None, "/"));
        fs::remove_file(dir.path().join("etc")).unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        symlink("/nowhere", dir.path().join("etc/passwd")).unwrap();
        assert_eq!(resolve(root.as_fd(), None).unwrap(), user(0, 0, &[], None, "/"));
    }
}
