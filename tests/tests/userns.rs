//! Phase 2c: user namespaces. The containers here get `linux.uidMappings`
//! and `gidMappings` of `0 1000000 65536` (what `--userns=remap` will ask
//! for), on the copy of the Alpine rootfs from `cargo xtask rootfs --remap`,
//! whose files belong to those host ids.
//!
//! Black-box, like the others: what a process inside sees, what the host
//! sees of it, and what `create` refuses. Run with `cargo xtask itest -- us_`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxDeviceBuilder, LinuxDeviceType, LinuxIdMappingBuilder, LinuxNamespaceType, PosixRlimitBuilder,
    PosixRlimitType, Spec,
};
use rustlet_runtime::spec::{REMAP_HOST_ID, REMAP_SIZE};

// ── helpers ──────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_spec_device_is_a_bind_of_the_hosts() {
    let mut s = userns_sh("stat -c '%a %t:%T %u:%g' /dev/fuse; grep ' /dev/fuse ' /proc/self/mountinfo");
    set_cgroup(&mut s, "us-spec-device");
    let node = LinuxDeviceBuilder::default()
        .path("/dev/fuse")
        .typ(LinuxDeviceType::U)
        .major(10)
        .minor(229)
        .file_mode(0o600u32)
        .uid(123u32)
        .gid(456u32)
        .build()
        .unwrap();
    edit_linux(&mut s, |l| {
        l.set_devices(Some(vec![node]));
    });
    let out = run(&s);
    let host = std::fs::metadata("/dev/fuse").unwrap();
    assert!(out.ok().starts_with(&format!("{:o} a:e5 65534:65534\n", host.mode() & 0o7777)), "{out:#?}");
    assert!(out.stdout.contains(" /dev/fuse "), "{out:#?}");
    // Host rdev/type must agree; don't bind a different host node.
    let mut node = s.linux().as_ref().unwrap().devices().as_ref().unwrap()[0].clone();
    node.set_minor(228);
    edit_linux(&mut s, |l| {
        l.set_devices(Some(vec![node]));
    });
    assert_refused(&s, "is not Char device 10:228");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_spec_fifo_is_created_with_its_metadata() {
    let mut s = userns_sh("stat -c '%F %a %u:%g' /dev/events");
    set_cgroup(&mut s, "us-spec-fifo");
    let node = LinuxDeviceBuilder::default()
        .path("/dev/events")
        .typ(LinuxDeviceType::P)
        .major(0)
        .minor(0)
        .file_mode(0o640u32)
        .uid(12u32)
        .gid(34u32)
        .build()
        .unwrap();
    edit_linux(&mut s, |l| {
        l.set_devices(Some(vec![node]));
    });
    assert_eq!(run(&s).ok(), "fifo 640 12:34\n");
}

/// `Uid:`/`Gid:`/`Groups:` of a host process, as the host sees them.
fn host_ids(pid: i32) -> (String, String, String) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let field = |k: &str| status_field(&status, k).unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ");
    (field("Uid"), field("Gid"), field("Groups"))
}

/// Asserts `create` refuses `s` with a message mentioning `needle`, and
/// leaves nothing behind.
#[track_caller]
fn assert_refused(s: &Spec, needle: &str) {
    let mut c = Container::new(s);
    c.create(&[]).refused(needle);
    c.assert_gone();
}

/// Sets the container's uid and gid maps to the given `(container, host,
/// size)` lines.
fn set_maps(s: &mut Spec, uids: &[(u32, u32, u32)], gids: &[(u32, u32, u32)]) {
    let conv = |lines: &[(u32, u32, u32)]| {
        lines
            .iter()
            .map(|&(c, h, n)| LinuxIdMappingBuilder::default().container_id(c).host_id(h).size(n).build().unwrap())
            .collect::<Vec<_>>()
    };
    edit_linux(s, |l| {
        l.set_uid_mappings(Some(conv(uids)));
        l.set_gid_mappings(Some(conv(gids)));
    });
}

/// `rustlet-probe` (tests/src/bin) runnable in a userns container, as in
/// hardening.rs: the binary at /mnt, the host's glibc at /opt. The command is
/// `sh -c <script>` where `$PROBE` runs the probe. `None` (test skipped)
/// without a glibc loader on the host.
fn userns_probe_spec(script: &str) -> Option<(Spec, tempfile::TempDir)> {
    let lib = Path::new("/usr/lib/x86_64-linux-gnu");
    if !lib.join("ld-linux-x86-64.so.2").exists() {
        eprintln!("skipped: no glibc loader at {}/ld-linux-x86-64.so.2", lib.display());
        return None;
    }
    let dir = tempfile::Builder::new().prefix("rustlet-probe-").tempdir().unwrap();
    // Container root is not host root: the directory must be searchable.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_rustlet-probe"), dir.path().join("probe")).unwrap();
    let script = format!("PROBE='/opt/ld-linux-x86-64.so.2 --library-path /opt /mnt/probe'; {script}");
    let mut s = userns_sh(&script);
    add_mount(&mut s, "/mnt", "bind", dir.path().to_str().unwrap(), &["bind", "ro", "nosuid", "nodev"]);
    add_mount(&mut s, "/opt", "bind", lib.to_str().unwrap(), &["bind", "ro", "nosuid", "nodev"]);
    Some((s, dir))
}

// ── identity ─────────────────────────────────────────────────────────────────

/// The milestone: container ids 0..65536 are host ids 1000000..1065536, and
/// the process is root of its namespace.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_uid_and_gid_maps_are_the_remap_range() {
    let out = run(&userns_sh("cat /proc/self/uid_map /proc/self/gid_map; id -u; id -g"));
    let map = format!("0 {REMAP_HOST_ID} {REMAP_SIZE}");
    assert_eq!(norm_lines(out.ok()), [map.as_str(), &map, "0", "0"]);
}

/// Seen from the host, container root is host uid 1000000, in a user
/// namespace of its own.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_container_root_is_an_unprivileged_host_user() {
    let c = Container::started(&userns_spec(&["sleep", "3600"]));
    let pid = c.pid();
    let host = REMAP_HOST_ID.to_string();
    let all = format!("{host} {host} {host} {host}");
    let (uid, gid, groups) = host_ids(pid);
    assert_eq!((uid.as_str(), gid.as_str(), groups.as_str()), (all.as_str(), all.as_str(), ""));
    let theirs = std::fs::read_link(format!("/proc/{pid}/ns/user")).unwrap().display().to_string();
    assert_ne!(theirs, host_ns("user"));
    let map = std::fs::read_to_string(format!("/proc/{pid}/uid_map")).unwrap();
    assert_eq!(norm_lines(&map), [format!("0 {REMAP_HOST_ID} {REMAP_SIZE}")]);
}

/// `process.user` inside is `REMAP_HOST_ID +` that outside, groups included.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_process_user_is_mapped_into_the_range() {
    let mut s = userns_sh("id -u; id -g; grep '^Groups:' /proc/self/status; exec sleep 3600");
    set_user(&mut s, 1000, 1000, &[2000]);
    let c = Container::started(&s);
    wait_until("the container printed its ids", PROMPT, || c.stdout().lines().count() >= 3);
    assert_eq!(norm_lines(&c.stdout()), ["1000", "1000", "Groups: 2000"]);
    let (uid, gid, groups) = host_ids(c.pid());
    let (u, g) = (REMAP_HOST_ID + 1000, REMAP_HOST_ID + 1000);
    assert_eq!(uid, format!("{u} {u} {u} {u}"));
    assert_eq!(gid, format!("{g} {g} {g} {g}"));
    assert_eq!(groups, (REMAP_HOST_ID + 2000).to_string());
}

/// The remapped rootfs belongs to container root (and shadow's group is
/// Alpine's 42), with no chown at run time.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_rootfs_belongs_to_container_root() {
    let out = run(&userns_sh("stat -c '%u:%g %n' / /bin/busybox /etc/shadow"));
    assert_eq!(norm_lines(out.ok()), ["0:0 /", "0:0 /bin/busybox", "0:42 /etc/shadow"]);
}

/// Root of a user namespace gets the same capability sets, seccomp filter
/// and no_new_privs as root without one.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_capabilities_seccomp_and_nnp_are_unchanged() {
    let out = run(&userns_sh("grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status"));
    let text = out.ok();
    for set in ["CapPrm", "CapEff", "CapBnd"] {
        assert_eq!(status_hex(text, set), DEFAULT_CAP_MASK, "{set}: {text}");
    }
    assert_eq!(status_hex(text, "CapInh"), 0, "{text}");
    assert_eq!(status_hex(text, "CapAmb"), 0, "{text}");
    assert_eq!(status_field(text, "NoNewPrivs"), Some("1"), "{text}");
    assert_eq!(status_field(text, "Seccomp"), Some("2"), "{text}");
}

// ── what init can't do for itself ────────────────────────────────────────────

/// Raising a hard rlimit and lowering oom_score_adj need `CAP_SYS_RESOURCE`
/// in the *initial* user namespace, which init doesn't have: the parent sets
/// both from outside before init proceeds.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_rlimits_and_oom_score_adj_are_set_from_outside() {
    // Above our own hard limit, so it really is raised.
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap();
    let ours: u64 = limits
        .lines()
        .find_map(|l| l.strip_prefix("Max realtime priority"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap();
    let want = (ours + 5).min(99);
    assert!(want > ours, "our own RTPRIO hard limit is already {ours}");
    let mut s = userns_sh("grep 'Max realtime priority' /proc/self/limits; cat /proc/self/oom_score_adj");
    edit_process(&mut s, |p| {
        let rtprio =
            PosixRlimitBuilder::default().typ(PosixRlimitType::RlimitRtprio).soft(want).hard(want).build().unwrap();
        let mut rl = p.rlimits().clone().unwrap_or_default();
        rl.push(rtprio);
        p.set_rlimits(Some(rl));
        p.set_oom_score_adj(Some(-500));
    });
    let out = run(&s);
    assert_eq!(norm_lines(out.ok()), [format!("Max realtime priority {want} {want}"), "-500".into()]);
}

/// `mknod` is never allowed in a user namespace, so `/dev` holds bind mounts
/// of the host's nodes: the right devices, and they work.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_dev_nodes_are_bind_mounts_of_the_hosts() {
    let script = "for d in null zero full random urandom tty; do stat -c '%n %F %t:%T' /dev/$d; done; \
                  echo x > /dev/null && echo null-ok; head -c 3 /dev/zero | od -An -tx1; \
                  head -c 8 /dev/urandom | wc -c; (echo x > /dev/full) 2>/dev/null || echo full-enospc";
    let out = run(&userns_sh(script));
    assert_eq!(
        norm_lines(out.ok()),
        [
            "/dev/null character special file 1:3",
            "/dev/zero character special file 1:5",
            "/dev/full character special file 1:7",
            "/dev/random character special file 1:8",
            "/dev/urandom character special file 1:9",
            "/dev/tty character special file 5:0",
            "null-ok",
            "00 00 00",
            "8",
            "full-enospc",
        ]
    );
}

/// Masked and read-only paths still apply inside the user namespace. The
/// read-only half is checked in mountinfo: a write to, say,
/// `/proc/sysrq-trigger` would fail anyway, because the file belongs to host
/// root, which the namespace doesn't map.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_masked_and_readonly_paths_still_apply() {
    let out = run(&userns_sh(
        "wc -c < /proc/kcore; \
         awk '$5 ~ /^\\/proc\\/(bus|fs|irq|sys|sysrq-trigger)$/ { split($6, o, \",\"); print $5, o[1] }' \
         /proc/self/mountinfo | sort",
    ));
    assert_eq!(
        norm_lines(out.ok()),
        ["0", "/proc/bus ro", "/proc/fs ro", "/proc/irq ro", "/proc/sys ro", "/proc/sysrq-trigger ro"]
    );
}

/// Namespaced sysctls work in namespaces the user namespace owns, and the
/// `hostname`/`domainname` fields (syscalls, not sysctls) too.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_sysctls_hostname_and_domainname() {
    let mut s = userns_sh(
        "cat /proc/sys/net/ipv4/ip_unprivileged_port_start /proc/sys/kernel/shmmni; hostname; \
         cat /proc/sys/kernel/domainname",
    );
    s.set_domainname(Some("example.org".into()));
    edit_linux(&mut s, |l| {
        l.set_sysctl(Some(
            [("net.ipv4.ip_unprivileged_port_start", "80"), ("kernel.shmmni", "1234")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        ));
    });
    let out = run(&s);
    assert_eq!(norm_lines(out.ok()), ["80", "1234", "rustlet", "example.org"]);
}

// ── sysfs ────────────────────────────────────────────────────────────────────

/// With a network namespace of its own, `/sys` is a new sysfs, which shows
/// that namespace's devices: only `lo`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_sysfs_is_new_with_a_network_namespace() {
    let out = run(&userns_sh("ls /sys/class/net; awk '$5 == \"/sys\" { print $(NF-2), $6 }' /proc/self/mountinfo"));
    assert_eq!(norm_lines(out.ok()), ["lo", "sysfs ro,nosuid,nodev,noexec,relatime"]);
}

/// Without one, only the network namespace's owner (the host) may mount
/// sysfs, so init binds the host's `/sys`: read-only all the way down, and
/// the kernel keeps the host's submounts locked, so even container root
/// with `CAP_SYS_ADMIN` can't take one off.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_sysfs_falls_back_to_the_hosts_without_a_network_namespace() {
    let script = "ls /sys/class/net | sort | tr '\\n' ' '; echo; \
                  awk '$5 == \"/sys\" { print $(NF-2), $6 }' /proc/self/mountinfo; \
                  m=$(awk '$5 ~ \"^/sys/\" && $5 != \"/sys/fs/cgroup\" { print $5; exit }' /proc/self/mountinfo); \
                  awk -v m=\"$m\" '$5 == m { print (index($6, \"ro\") == 1 ? \"sub-ro\" : \"sub-rw \" $6) }' /proc/self/mountinfo; \
                  umount \"$m\" 2>&1 | sed 's/.*: //'";
    let mut s = userns_sh(script);
    without_namespace(&mut s, LinuxNamespaceType::Network);
    // CAP_SYS_ADMIN (over the container's own namespaces) and no seccomp
    // filter, so that only the lock can stop the umount.
    let caps: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_SYS_ADMIN"]).collect();
    set_capabilities(&mut s, CapSets::root(&caps));
    edit_linux(&mut s, |l| {
        l.set_seccomp(None);
    });
    let out = run(&s);
    let mut host: Vec<String> =
        std::fs::read_dir("/sys/class/net").unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    host.sort();
    assert_eq!(
        norm_lines(out.ok()),
        [host.join(" "), "sysfs ro,nosuid,nodev,noexec,relatime".into(), "sub-ro".into(), "Invalid argument".into()]
    );
}

// ── idmapped mounts ──────────────────────────────────────────────────────────

/// An `idmap` bind of a directory that belongs to host root: inside it
/// belongs to container root, which can write to it, and what it writes is
/// host root's on disk. A plain bind of the same kind of directory shows
/// `nobody` and refuses the write.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_idmapped_bind_mount_translates_owners() {
    let idm = tempfile::tempdir().unwrap();
    let plain = tempfile::tempdir().unwrap();
    for d in [&idm, &plain] {
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(d.path().join("f"), "x").unwrap();
    }
    let mut s = userns_sh(
        "stat -c '%u:%g' /mnt/f; echo y > /mnt/new && echo wrote; stat -c '%u:%g' /opt/f; \
         (echo y > /opt/new) 2>/dev/null || echo refused",
    );
    add_mount(&mut s, "/mnt", "bind", idm.path().to_str().unwrap(), &["bind", "idmap"]);
    add_mount(&mut s, "/opt", "bind", plain.path().to_str().unwrap(), &["bind"]);
    let out = run(&s);
    assert_eq!(norm_lines(out.ok()), ["0:0", "wrote", "65534:65534", "refused"]);
    let meta = std::fs::metadata(idm.path().join("new")).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (0, 0), "written through the idmapped mount as host root");
    assert!(!plain.path().join("new").exists());
}

/// Without a user namespace there is no mapping to idmap with.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_idmap_needs_a_user_namespace() {
    let mut s = spec(&["true"]);
    add_mount(&mut s, "/mnt", "bind", "/tmp", &["bind", "idmap"]);
    assert_refused(&s, "`idmap` needs a new user namespace");
}

// ── exec ─────────────────────────────────────────────────────────────────────

/// `exec` joins the container's user namespace and becomes its root; with
/// `-u`, the host sees the mapped uid.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_exec_joins_the_user_namespace() {
    let c = Container::started(&userns_spec(&["sleep", "3600"]));
    let out = c.exec_in(
        &[],
        &["sh", "-c", "id -u; cat /proc/self/uid_map; readlink /proc/self/ns/user; readlink /proc/1/ns/user; grep ^CapEff /proc/self/status"],
    );
    let lines = norm_lines(out.ok());
    assert_eq!(lines[..2], ["0".to_string(), format!("0 {REMAP_HOST_ID} {REMAP_SIZE}")], "{lines:?}");
    assert_eq!(lines[2], lines[3], "exec'd process and init are in different user namespaces: {lines:?}");
    assert_eq!(lines[4], format!("CapEff: {DEFAULT_CAP_MASK:016x}"));

    let pid_file = c.bundle_dir().join("exec.pid");
    c.exec_in(&["-d", "-u", "1000:1000", "--pid-file", pid_file.to_str().unwrap()], &["sleep", "3600"]).ok();
    let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
    let u = REMAP_HOST_ID + 1000;
    assert_eq!(host_ids(pid).0, format!("{u} {u} {u} {u}"));
}

/// Keyring names are per user namespace, and the container's session
/// keyring belongs to container root: `exec` must become root of the
/// namespace *before* joining it by name, or it would silently get a new,
/// empty keyring of the same name. The serial numbers tell the difference.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_exec_joins_the_containers_session_keyring() {
    let Some((mut s, _dir)) = userns_probe_spec("$PROBE session-keyring; exec sleep 3600") else { return };
    // Docker's profile refuses keyctl (keyrings aren't namespaced).
    edit_linux(&mut s, |l| {
        l.set_seccomp(None);
    });
    let c = Container::started(&s);
    wait_until("init's probe printed its keyring", PROMPT, || c.stdout().contains("session-keyring"));
    let init = c.stdout();
    let init = init.trim();
    assert!(init.ends_with(&format!(";_ses.{}", c.id())), "{init}");
    let exec =
        c.exec_in(&[], &["/opt/ld-linux-x86-64.so.2", "--library-path", "/opt", "/mnt/probe", "session-keyring"]);
    assert_eq!(exec.ok().trim(), init);
}

// ── terminals ────────────────────────────────────────────────────────────────

/// With a terminal, the PTY comes from the container's own devpts (made in
/// the user namespace) and is handed to the container's user.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_terminal_belongs_to_the_container_user() {
    let mut s = userns_sh("stat -c '%u %t' \"$(tty)\"; stat -c '%t %T' /dev/console");
    set_user(&mut s, 1000, 1000, &[]);
    set_terminal(&mut s, None);
    let mut c = Container::new(&s);
    let out = c.run_foreground(&[], Some(b""), TIMEOUT);
    let lines: Vec<&str> = out.stdout.lines().map(|l| l.trim_end_matches('\r')).collect();
    assert_eq!(out.status, 0, "{out:#?}");
    // Major 136 (0x88): the container's devpts.
    assert_eq!(lines, ["1000 88", "88 0"], "{out:#?}");
    c.assert_gone();
}

// ── refused at create ────────────────────────────────────────────────────────

/// Maps that the kernel would refuse, or that would make container root host
/// root, fail `create` with a reason.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_bad_maps_are_refused() {
    let full = (0, REMAP_HOST_ID, REMAP_SIZE);
    let mut s = userns_spec(&["true"]);
    set_maps(&mut s, &[(0, 0, 65536)], &[full]);
    assert_refused(&s, "maps host id 0");

    let mut s = userns_spec(&["true"]);
    set_maps(&mut s, &[(1, REMAP_HOST_ID + 1, 1000)], &[full]);
    assert_refused(&s, "must map id 0");

    let mut s = userns_spec(&["true"]);
    set_maps(&mut s, &[full, (5, 2_000_000, 1)], &[full]);
    assert_refused(&s, "overlap on the container side");

    let mut s = userns_spec(&["true"]);
    set_user(&mut s, 70000, 0, &[]);
    assert_refused(&s, "process.user.uid 70000 is not mapped");

    // Maps without a user namespace to put them in.
    let mut s = spec(&["true"]);
    set_maps(&mut s, &[full], &[full]);
    assert_refused(&s, "no new `user` namespace");
}

/// Namespaces the user namespace wouldn't own, where the kernel needs an
/// owner: refused up front instead of failing halfway through init.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_unowned_namespaces_are_refused() {
    let mut s = userns_spec(&["true"]);
    join_namespace(&mut s, LinuxNamespaceType::User, "/proc/self/ns/user");
    assert_refused(&s, "joining a user namespace by path");

    let mut s = userns_spec(&["true"]);
    without_namespace(&mut s, LinuxNamespaceType::Pid);
    assert_refused(&s, "new `pid` namespace");

    let mut s = userns_spec(&["true"]);
    without_namespace(&mut s, LinuxNamespaceType::Ipc);
    assert_refused(&s, "mqueue can only be mounted in a new `ipc` namespace");

    let mut s = userns_spec(&["true"]);
    without_namespace(&mut s, LinuxNamespaceType::Cgroup);
    assert_refused(&s, "cgroup2 can only be mounted in a new `cgroup` namespace");

    let mut s = userns_spec(&["true"]);
    without_namespace(&mut s, LinuxNamespaceType::Network);
    edit_linux(&mut s, |l| {
        l.set_sysctl(Some([("net.ipv4.ip_forward".to_owned(), "1".to_owned())].into_iter().collect()));
    });
    assert_refused(&s, "needs a new network namespace");

    let mut s = userns_spec(&["true"]);
    edit_linux(&mut s, |l| {
        l.set_sysctl(Some([("kernel.domainname".to_owned(), "x".to_owned())].into_iter().collect()));
    });
    assert_refused(&s, "`domainname` field");
}

/// `exec -u` with a uid the namespace doesn't map is refused, before
/// anything joins the container.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_exec_with_an_unmapped_uid_is_refused() {
    let c = Container::started(&userns_spec(&["sleep", "3600"]));
    c.exec_in(&["-u", "70000"], &["true"]).refused("70000 is not mapped");
    assert_eq!(c.exec_in(&["-u", "65535"], &["id", "-u"]).ok(), "65535\n");
}

/// The flags of the mounts the parent opened (§2.2 step 4.0) hold once init
/// attaches them in the user namespace: the rootfs is `nodev` (and `ro`,
/// as `root.readonly` asks), a read-only bind is `ro`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_mount_flags_hold_in_a_user_namespace() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = userns_sh("awk '$5 == \"/\" || $5 == \"/mnt\" { print $5, $6 }' /proc/self/mountinfo");
    add_mount(&mut s, "/mnt", "bind", dir.path().to_str().unwrap(), &["bind", "ro", "nosuid"]);
    let out = run(&s);
    let options = |mount_point: &str| -> Vec<String> {
        let line = out.stdout.lines().find(|l| l.split(' ').next() == Some(mount_point)).unwrap_or_else(|| {
            panic!("no mount on {mount_point} in {:?}", out.stdout);
        });
        line.split(' ').nth(1).unwrap().split(',').map(str::to_owned).collect()
    };
    let (root, mnt) = (options("/"), options("/mnt"));
    for flag in ["ro", "nodev"] {
        assert!(root.iter().any(|o| o == flag), "/ is not {flag}: {root:?}");
    }
    for flag in ["ro", "nosuid"] {
        assert!(mnt.iter().any(|o| o == flag), "/mnt is not {flag}: {mnt:?}");
    }
}

/// A foreground container in a user namespace without a terminal gets
/// stdio pipes of its own, owned by its (mapped) user: `/dev/stdout` and
/// `/dev/stderr` reopen fd 1 and 2 afresh, and the caller's pipes belong to
/// host root, whom the namespace doesn't map (`EACCES`, as nginx's
/// `error.log -> /dev/stderr` found). Input still arrives, and ends.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_stdio_can_be_reopened() {
    let script = "echo out >/dev/stdout; echo err >/dev/stderr; cat /dev/stdin; stat -c %u:%g /proc/self/fd/1";
    let bundle = TestBundle::new(&userns_sh(script));
    let out = exec_input(bundle.command(), Some(b"input\n"), TIMEOUT);
    assert_eq!(out.ok(), "out\ninput\n0:0\n", "{out:#?}");
    assert_eq!(out.stderr, "err\n", "{out:#?}");

    // A non-root process may reopen them too: they are its user's.
    let mut s = userns_sh("echo hi >/dev/stdout; echo there >/dev/stderr; id -u");
    set_user(&mut s, 1000, 1000, &[]);
    let out = exec_input(TestBundle::new(&s).command(), None, TIMEOUT);
    assert_eq!(out.ok(), "hi\n1000\n", "{out:#?}");
    assert_eq!(out.stderr, "there\n");
}

/// The relay never waits on the container: input it doesn't read can't
/// stop its output (or its exit) from getting through.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_unread_input_does_not_stall_the_relay() {
    let bundle =
        TestBundle::new(&userns_sh("i=0; while [ $i -lt 2000 ]; do echo line-$i; i=$((i+1)); done; echo done"));
    let input = vec![b'x'; 4 << 20];
    let out = exec_input(bundle.command(), Some(&input), TIMEOUT);
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!((lines.len(), lines[1999], lines[2000]), (2001, "line-1999", "done"));
}

/// `exec` gets the same pipes.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn us_exec_stdio_can_be_reopened() {
    let c = Container::started(&userns_spec(&["sleep", "3600"]));
    let out = c.exec_in(&[], &["sh", "-c", "echo out >/dev/stdout; echo err >/dev/stderr"]);
    assert_eq!(out.ok(), "out\n", "{out:#?}");
    assert_eq!(out.stderr, "err\n");
    let out = c.exec_in(&["-u", "1000:1000"], &["sh", "-c", "echo out >/dev/stdout; id -u"]);
    assert_eq!(out.ok(), "out\n1000\n", "{out:#?}");
}
