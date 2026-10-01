//! Phase 2b: what `create` does to make root in a container less dangerous:
//! capabilities, no_new_privs, the seccomp filter, masked and read-only
//! paths, namespaced sysctls, the mount destination rules, the sealed-memfd
//! re-exec (CVE-2019-5736), `--preserve-fds` and the session keyring.
//!
//! Black-box: the tests look at what a process inside sees
//! (`/proc/self/status`, error messages of busybox tools) and at the host.
//! Run with `cargo xtask itest -- hd_`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxNamespaceType, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder, Spec,
};

// ── helpers ──────────────────────────────────────────────────────────────────

/// `grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status` in a container.
const STATUS: &str = "grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status";

/// The container's `/proc/self/status` lines for capabilities, NNP and seccomp.
#[track_caller]
fn status_of(mut s: Spec) -> String {
    edit_process(&mut s, |p| {
        p.set_args(Some(vec!["sh".into(), "-c".into(), STATUS.into()]));
    });
    run(&s).ok().to_owned()
}

/// Asserts `create` refuses `s` with a message mentioning `needle`, and
/// leaves nothing behind (no state, no cgroup).
#[track_caller]
fn assert_refused(mut s: Spec, cgroup: &str, needle: &str) -> CmdOut {
    set_cgroup(&mut s, cgroup);
    let mut c = Container::new(&s);
    let out = c.create(&[]);
    out.refused(needle);
    c.assert_gone();
    out
}

/// Sets `linux.sysctl`.
fn set_sysctls(s: &mut Spec, sysctls: &[(&str, &str)]) {
    let map: HashMap<String, String> = sysctls.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    edit_linux(s, |l| {
        l.set_sysctl(Some(map));
    });
}

/// A host sysctl, trimmed.
fn host_sysctl(key: &str) -> String {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")).trim().to_owned()
}

/// A seccomp profile: `default` for everything but `rules`
/// (`(syscall names, action, errnoRet)`).
fn seccomp(default: LinuxSeccompAction, rules: &[(&[&str], LinuxSeccompAction, Option<u32>)]) -> LinuxSeccomp {
    let syscalls = rules
        .iter()
        .map(|(names, action, errno)| {
            let mut b = LinuxSyscallBuilder::default().names(names.iter().map(|n| n.to_string()).collect::<Vec<_>>());
            b = b.action(*action);
            if let Some(e) = errno {
                b = b.errno_ret(*e);
            }
            b.build().unwrap()
        })
        .collect::<Vec<_>>();
    LinuxSeccompBuilder::default().default_action(default).syscalls(syscalls).build().unwrap()
}

fn set_seccomp(s: &mut Spec, profile: Option<LinuxSeccomp>) {
    edit_linux(s, |l| {
        l.set_seccomp(profile);
    });
}

/// `(mount point, per-mount options, fs type)` of every line of a mountinfo.
fn mountinfo(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let f: Vec<&str> = left.split(' ').collect();
            Some((f.get(4)?.to_string(), f.get(5)?.to_string(), right.split(' ').next()?.to_string()))
        })
        .collect()
}

/// `rustlet-probe` (tests/src/bin) made runnable inside Alpine: the binary is
/// bind-mounted at /mnt, the host's glibc directory at /opt, and the
/// container runs `/opt/ld-linux-x86-64.so.2 --library-path /opt /mnt/probe
/// <probes…>`. `None` (test skipped) if the host has no glibc loader there.
fn probe_spec(probes: &[&str]) -> Option<(Spec, tempfile::TempDir)> {
    let lib = Path::new("/usr/lib/x86_64-linux-gnu");
    if !lib.join("ld-linux-x86-64.so.2").exists() {
        eprintln!("skipped: no glibc loader at {}/ld-linux-x86-64.so.2", lib.display());
        return None;
    }
    let dir = tempfile::Builder::new().prefix("rustlet-probe-").tempdir().unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_rustlet-probe"), dir.path().join("probe")).unwrap();
    let mut argv = vec!["/opt/ld-linux-x86-64.so.2", "--library-path", "/opt", "/mnt/probe"];
    argv.extend(probes);
    let mut s = spec(&argv);
    add_mount(&mut s, "/mnt", "bind", dir.path().to_str().unwrap(), &["bind", "ro", "nosuid", "nodev"]);
    add_mount(&mut s, "/opt", "bind", lib.to_str().unwrap(), &["bind", "ro", "nosuid", "nodev"]);
    Some((s, dir))
}

/// The probe's `name result` lines as pairs.
fn probe_results(out: &str) -> Vec<(String, String)> {
    out.lines().filter_map(|l| l.split_once(' ')).map(|(a, b)| (a.to_owned(), b.to_owned())).collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
}

// ── capabilities ─────────────────────────────────────────────────────────────

/// The milestone: root in a default container has exactly Podman's 11
/// capabilities in its bounding, effective and permitted sets, and nothing
/// inheritable or ambient.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_root_gets_exactly_the_default_capabilities() {
    let out = status_of(spec(&["true"]));
    for set in ["CapPrm", "CapEff", "CapBnd"] {
        assert_eq!(status_hex(&out, set), DEFAULT_CAP_MASK, "{set}: {out}");
    }
    assert_eq!(status_hex(&out, "CapInh"), 0, "{out}");
    assert_eq!(status_hex(&out, "CapAmb"), 0, "{out}");
}

/// The default set in action: root may chown (CAP_CHOWN) but not mknod
/// (no CAP_MKNOD) or reconfigure the network (no CAP_NET_ADMIN).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_default_capabilities_allow_chown_but_not_mknod_or_net_admin() {
    let out = run(&sh("touch /dev/shm/f && chown 1000:1000 /dev/shm/f && stat -c %u:%g /dev/shm/f; \
                       mknod /dev/shm/n c 1 3 || echo mknod-denied; \
                       ip link set lo down || echo net-admin-denied"));
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), ["1000:1000", "mknod-denied", "net-admin-denied"], "{out:#?}");
    assert_eq!(out.stderr.matches("Operation not permitted").count(), 2, "{out:#?}");
}

/// A non-root user keeps nothing but the bounding set: execve as uid 1000
/// clears effective and permitted.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_non_root_user_has_only_the_bounding_set() {
    let mut s = spec(&["true"]);
    set_user(&mut s, 1000, 1000, &[]);
    let out = status_of(s);
    for set in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(status_hex(&out, set), 0, "{set}: {out}");
    }
    assert_eq!(status_hex(&out, "CapBnd"), DEFAULT_CAP_MASK, "{out}");
}

/// Ambient capabilities are how a non-root process keeps a capability across
/// execve: uid 1000 with NET_BIND_SERVICE in all five sets has it effective
/// and can listen on port 80.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_ambient_capabilities_reach_a_non_root_user() {
    let nbs = cap_bit("CAP_NET_BIND_SERVICE");
    let mut s = sh(&format!("{STATUS}; {LISTEN_ON_80}"));
    set_user(&mut s, 1000, 1000, &[]);
    set_capabilities(&mut s, CapSets { bounding: &DEFAULT_CAPS, ..CapSets::all(&["CAP_NET_BIND_SERVICE"]) });
    let out = run(&s);
    let text = out.ok();
    for set in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(status_hex(text, set), nbs, "{set}: {out:#?}");
    }
    assert_eq!(status_hex(text, "CapBnd"), DEFAULT_CAP_MASK, "{out:#?}");
    assert!(text.lines().any(|l| l == "listening"), "uid 1000 could not listen on port 80: {out:#?}");
}

/// Without inheritable+ambient, a non-root user loses the capability at
/// execve (the control for the test above): binding port 80 fails.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_capabilities_without_ambient_are_lost_by_a_non_root_user() {
    let mut s = sh(&format!("{STATUS}; {LISTEN_ON_80}"));
    set_user(&mut s, 1000, 1000, &[]);
    set_capabilities(&mut s, CapSets { bounding: &DEFAULT_CAPS, ..CapSets::root(&["CAP_NET_BIND_SERVICE"]) });
    let out = run(&s);
    let text = out.ok();
    assert_eq!(status_hex(text, "CapEff"), 0, "{out:#?}");
    assert!(text.lines().any(|l| l == "nc-exited"), "{out:#?}");
    assert!(out.stderr.contains("Permission denied"), "{out:#?}");
}

/// A spec's own capability sets replace the defaults exactly, and a missing
/// capability is really missing (root can't chown without CAP_CHOWN).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_custom_capabilities_replace_the_defaults() {
    let mut s = sh(&format!("{STATUS}; touch /dev/shm/f; chown 1000 /dev/shm/f || echo chown-denied"));
    let bounding = ["CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"];
    let granted = ["CAP_KILL", "CAP_NET_RAW"];
    set_capabilities(
        &mut s,
        CapSets { bounding: &bounding, effective: &granted, permitted: &granted, ..CapSets::default() },
    );
    let out = run(&s);
    let text = out.ok();
    assert_eq!(status_hex(text, "CapBnd"), cap_mask(&bounding), "{out:#?}");
    assert_eq!(status_hex(text, "CapEff"), cap_mask(&granted), "{out:#?}");
    assert_eq!(status_hex(text, "CapPrm"), cap_mask(&granted), "{out:#?}");
    assert_eq!(status_hex(text, "CapInh"), 0, "{out:#?}");
    assert!(text.lines().any(|l| l == "chown-denied"), "{out:#?}");
}

/// `process.capabilities` must be given: silently running with all of root's
/// (or none) would both be wrong.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_missing_capabilities_are_refused() {
    let mut s = spec(&["true"]);
    edit_process(&mut s, |p| {
        p.set_capabilities(None);
    });
    assert_refused(s, "hd-no-caps", "capabilities");
}

/// CAP_MKNOD needs a filter, including when only in the bounding set.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_cap_mknod_needs_a_device_filter() {
    let with_mknod: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_MKNOD"]).collect();
    // Only in the bounding set (where it could later be raised from).
    let mut s = spec(&["true"]);
    set_capabilities(&mut s, CapSets { bounding: &with_mknod, ..CapSets::root(&DEFAULT_CAPS) });
    let out = run(&s);
    assert_eq!(out.status, 1, "{out:#?}");
    assert!(out.stderr.contains("linux.cgroupsPath"), "{out:#?}");
    set_cgroup(&mut s, "hd-mknod-bounding");
    run(&s).ok();
    // In every set.
    let mut s = spec(&["true"]);
    set_capabilities(&mut s, CapSets::all(&with_mknod));
    let out = run(&s);
    assert_eq!(out.status, 1, "{out:#?}");
    assert!(out.stderr.contains("linux.cgroupsPath"), "{out:#?}");
    set_cgroup(&mut s, "hd-mknod-all");
    run(&s).ok();
}

/// Capability sets that the kernel's rules make impossible are refused up
/// front: effective ⊄ permitted, ambient ⊄ permitted ∩ inheritable,
/// inheritable ⊄ bounding.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_inconsistent_capability_sets_are_refused() {
    let plus_raw: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_NET_RAW"]).collect();
    let raw = ["CAP_NET_RAW"];
    let cases = [
        (
            "effective-not-permitted",
            CapSets { bounding: &plus_raw, effective: &plus_raw, ..CapSets::root(&DEFAULT_CAPS) },
        ),
        (
            "ambient-not-inheritable",
            CapSets {
                bounding: &plus_raw,
                effective: &plus_raw,
                permitted: &plus_raw,
                inheritable: &[],
                ambient: &raw,
            },
        ),
        ("inheritable-not-bounding", CapSets { inheritable: &raw, ..CapSets::root(&DEFAULT_CAPS) }),
    ];
    for (name, sets) in cases {
        let mut s = spec(&["true"]);
        set_cgroup(&mut s, &format!("hd-caps-{name}"));
        set_capabilities(&mut s, sets);
        let mut c = Container::new(&s);
        let out = c.create(&[]);
        // The message names the offending set.
        out.refused(name.split('-').next().unwrap());
        c.assert_gone();
    }
}

// ── no_new_privs ─────────────────────────────────────────────────────────────

/// With `noNewPrivileges: false` the flag stays off, and the seccomp filter
/// is still loaded, for root and for a non-root user alike. (Without NNP,
/// only a process holding CAP_SYS_ADMIN may load a filter, so the runtime
/// has to load it before it switches identity.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_without_no_new_privs_the_filter_is_still_loaded() {
    for uid in [0, 1000] {
        let mut s = spec(&["true"]);
        set_no_new_privileges(&mut s, false);
        set_user(&mut s, uid, uid, &[]);
        let out = status_of(s);
        assert_eq!(status_field(&out, "NoNewPrivs"), Some("0"), "uid {uid}: {out}");
        assert_eq!(status_field(&out, "Seccomp"), Some("2"), "uid {uid}: {out}");
        assert_eq!(status_field(&out, "Seccomp_filters"), Some("1"), "uid {uid}: {out}");
    }
}

/// The default spec sets no_new_privs.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_no_new_privs_is_on_by_default() {
    let out = status_of(spec(&["true"]));
    assert_eq!(status_field(&out, "NoNewPrivs"), Some("1"), "{out}");
}

// ── seccomp ──────────────────────────────────────────────────────────────────

/// The default spec loads exactly one filter (Docker's profile) in filter mode.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_default_seccomp_filter_is_loaded() {
    let out = status_of(spec(&["true"]));
    assert_eq!(status_field(&out, "Seccomp"), Some("2"), "{out}");
    assert_eq!(status_field(&out, "Seccomp_filters"), Some("1"), "{out}");
}

/// The Phase 2b milestone: `unshare -U` (and every other new namespace) gets
/// EPERM inside a container.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_unshare_is_denied() {
    let out =
        run(&sh("for f in -U -m -n -i -u -p; do unshare $f true && echo \"$f allowed\" || echo \"$f denied\"; done"));
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines, ["-U denied", "-m denied", "-n denied", "-i denied", "-u denied", "-p denied"], "{out:#?}");
    assert_eq!(out.stderr.matches("Operation not permitted").count(), 6, "{out:#?}");
}

/// mount, umount, setns (nsenter) and sethostname all fail inside, and
/// nothing changed: /proc is still mounted and the hostname is the spec's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_mount_umount_setns_and_sethostname_are_denied() {
    let out = run(&sh("mount -t tmpfs t /mnt; echo mount=$?; umount /proc; echo umount=$?; \
                       nsenter -t 1 -n true; echo setns=$?; hostname evil; echo sethostname=$?; \
                       hostname; grep -c ' /proc ' /proc/self/mountinfo"));
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines.len(), 6, "{out:#?}");
    for l in &lines[..4] {
        assert!(!l.ends_with("=0"), "{l}: {out:#?}");
    }
    assert_eq!(lines[4..], ["rustlet", "1"], "{out:#?}");
    let err = out.stderr.to_lowercase();
    assert!(err.matches("operation not permitted").count() + err.matches("permission denied").count() >= 4, "{out:#?}");
}

/// The filter, not just the missing capability, blocks these: with
/// CAP_SYS_ADMIN granted but the default profile (resolved without it),
/// mount, unshare and sethostname still fail. Without the filter the same
/// container can do all three (inside its own namespaces).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_seccomp_blocks_mount_even_with_cap_sys_admin() {
    let caps: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_SYS_ADMIN"]).collect();
    let script = "mount -t tmpfs t /mnt; echo mount=$?; unshare -m true; echo unshare=$?; \
                  hostname other; echo sethostname=$?; hostname";
    let mut s = sh(script);
    set_capabilities(&mut s, CapSets::root(&caps));
    let out = run(&s);
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines.len(), 4, "{out:#?}");
    for l in &lines[..3] {
        assert!(!l.ends_with("=0"), "allowed despite the filter: {l}: {out:#?}");
    }
    assert_eq!(lines[3], "rustlet", "{out:#?}");

    set_seccomp(&mut s, None);
    let out = run(&s);
    assert_eq!(
        out.ok().lines().collect::<Vec<_>>(),
        ["mount=0", "unshare=0", "sethostname=0", "other"],
        "the control (CAP_SYS_ADMIN, no filter) failed: {out:#?}"
    );
}

/// clone3 gets ENOSYS (not EPERM) so that glibc falls back to clone(2):
/// raw clone3 fails, while fork and std's spawn (posix_spawn, which tries
/// clone3 first) still work.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_clone3_gets_enosys_so_libc_falls_back_to_clone() {
    let Some((s, _dir)) = probe_spec(&["clone3", "clone3-newuser", "fork", "spawn", "unshare-user"]) else { return };
    let out = run(&s);
    assert_eq!(
        probe_results(out.ok()),
        pairs(&[
            ("clone3", "ENOSYS"),
            ("clone3-newuser", "ENOSYS"),
            ("fork", "ok"),
            ("spawn", "ok"),
            ("unshare-user", "EPERM")
        ]),
        "{out:#?}"
    );
}

/// Docker's socket rules: AF_VSOCK (40) and AF_ALG (38) are refused with
/// EPERM, ordinary families work.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_socket_families_are_filtered() {
    let Some((s, _dir)) = probe_spec(&["vsock", "alg", "unix", "inet"]) else { return };
    let out = run(&s);
    assert_eq!(
        probe_results(out.ok()),
        pairs(&[("vsock", "EPERM"), ("alg", "EPERM"), ("unix", "ok"), ("inet", "ok")]),
        "{out:#?}"
    );
}

/// Argument filters: personality(2) is allowed only for the exact values
/// Docker lists (the query 0xffffffff, PER_LINUX 0, …), so disabling ASLR
/// (ADDR_NO_RANDOMIZE) is refused.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_seccomp_argument_filters_work() {
    let Some((s, _dir)) = probe_spec(&["personality-query", "personality-linux", "personality-no-randomize"]) else {
        return;
    };
    let out = run(&s);
    assert_eq!(
        probe_results(out.ok()),
        pairs(&[("personality-query", "ok"), ("personality-linux", "ok"), ("personality-no-randomize", "EPERM")]),
        "{out:#?}"
    );
}

/// A custom profile is compiled as written: default ALLOW, mkdir → errno 1
/// (EPERM), chmod → errno 13 (EACCES); everything else still works.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_custom_seccomp_profile_is_honoured() {
    use LinuxSeccompAction::{ScmpActAllow, ScmpActErrno};
    let mut s = sh("mkdir /dev/shm/d; echo mkdir=$?; touch /dev/shm/f; echo touch=$?; \
                    chmod 600 /dev/shm/f; echo chmod=$?; ls /dev/shm; grep -E '^Seccomp:' /proc/self/status");
    set_seccomp(
        &mut s,
        Some(seccomp(
            ScmpActAllow,
            &[(&["mkdir", "mkdirat"], ScmpActErrno, Some(1)), (&["chmod", "fchmodat"], ScmpActErrno, Some(13))],
        )),
    );
    let out = run(&s);
    let lines: Vec<&str> = out.ok().lines().map(str::trim).collect();
    assert_eq!(lines[..4], ["mkdir=1", "touch=0", "chmod=1", "f"], "{out:#?}");
    assert_eq!(status_field(&out.stdout, "Seccomp"), Some("2"), "{out:#?}");
    assert!(out.stderr.contains("Operation not permitted"), "mkdir: {out:#?}");
    assert!(out.stderr.contains("Permission denied"), "chmod: {out:#?}");
}

/// The other actions a profile can use: SCMP_ACT_ERRNO without errnoRet
/// means EPERM, SCMP_ACT_TRACE without a tracer makes the call fail with
/// ENOSYS, SCMP_ACT_LOG lets it through. (KILL and TRAP are left out: they
/// would make the host's core-dump handler collect a core.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_custom_profile_actions_are_honoured() {
    use LinuxSeccompAction::{ScmpActAllow, ScmpActErrno, ScmpActLog, ScmpActTrace};
    let mut s = sh("rmdir /dev/shm; echo rmdir=$?; chmod 1777 /dev/shm; echo chmod=$?; id -u");
    set_seccomp(
        &mut s,
        Some(seccomp(
            ScmpActAllow,
            &[
                (&["rmdir"], ScmpActTrace, None),
                (&["chmod", "fchmodat"], ScmpActErrno, None),
                (&["getuid", "geteuid"], ScmpActLog, None),
            ],
        )),
    );
    let out = run(&s);
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), ["rmdir=1", "chmod=1", "0"], "{out:#?}");
    assert!(out.stderr.contains("Function not implemented"), "rmdir: {out:#?}");
    assert!(out.stderr.contains("Operation not permitted"), "chmod: {out:#?}");
}

/// Seccomp user notification needs an agent, which is Phase 8: both
/// SCMP_ACT_NOTIFY and a listenerPath are refused.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_seccomp_notify_is_refused() {
    use LinuxSeccompAction::{ScmpActAllow, ScmpActNotify};
    let mut s = spec(&["true"]);
    set_seccomp(&mut s, Some(seccomp(ScmpActAllow, &[(&["mkdir"], ScmpActNotify, None)])));
    assert_refused(s, "hd-notify-action", "Phase 8");

    let mut s = spec(&["true"]);
    let mut profile = seccomp(ScmpActAllow, &[]);
    profile.set_listener_path(Some("/run/rustlet-itest-no-such-agent.sock".into()));
    set_seccomp(&mut s, Some(profile));
    assert_refused(s, "hd-notify-listener", "Phase 8");
}

/// No `linux.seccomp` means no filter (as in runc).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_without_a_profile_there_is_no_filter() {
    let mut s = spec(&["true"]);
    set_seccomp(&mut s, None);
    let out = status_of(s);
    assert_eq!(status_field(&out, "Seccomp"), Some("0"), "{out}");
}

// ── masked and read-only paths ───────────────────────────────────────────────

/// Masked files (those this kernel has) are covered by /dev/null: a char
/// device 1:3 that reads as empty.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_masked_files_read_as_empty() {
    let files: Vec<&str> = MASKED_PATHS.iter().copied().filter(|p| Path::new(p).is_file()).collect();
    assert!(files.contains(&"/proc/kcore"), "the host has no /proc/kcore?");
    let script = format!("for p in {}; do echo \"$p $(stat -c %t:%T $p) $(wc -c < $p)\"; done", files.join(" "));
    let out = run(&sh(&script));
    let expected: Vec<String> = files.iter().map(|p| format!("{p} 1:3 0")).collect();
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), expected, "{out:#?}");
}

/// Masked directories are covered by an empty read-only tmpfs.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_masked_directories_are_empty_and_read_only() {
    let dirs: Vec<&str> = MASKED_PATHS.iter().copied().filter(|p| Path::new(p).is_dir()).collect();
    assert!(dirs.contains(&"/sys/firmware"), "the host has no /sys/firmware?");
    let script = format!(
        "for d in {}; do echo \"$d $(ls -A $d | wc -l)\"; touch $d/x; done; cat /proc/self/mountinfo",
        dirs.join(" ")
    );
    let out = run(&sh(&script));
    let text = out.ok();
    let (listing, mounts) = text.split_at(text.lines().take(dirs.len()).map(|l| l.len() + 1).sum());
    let expected: Vec<String> = dirs.iter().map(|d| format!("{d} 0")).collect();
    assert_eq!(listing.lines().collect::<Vec<_>>(), expected, "{out:#?}");
    let mounts = mountinfo(mounts);
    for d in &dirs {
        let m = mounts.iter().rev().find(|m| m.0 == *d).unwrap_or_else(|| panic!("{d} is not a mount point: {out:#?}"));
        assert_eq!(m.2, "tmpfs", "{d}: {m:?}");
        assert!(m.1.split(',').any(|o| o == "ro"), "{d} is not read-only: {m:?}");
        assert!(out.stderr.contains(&format!("{d}/x")), "{out:#?}");
    }
    assert_eq!(out.stderr.matches("Read-only file system").count(), dirs.len(), "{out:#?}");
}

/// The read-only paths are read-only mounts, and writing through them fails
/// with EROFS. (Non-destructive probes: `touch`, i.e. utimensat, of each
/// path, and a sysctl that is private to the container's netns anyway.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_read_only_paths_refuse_writes() {
    let out = run(&sh(&format!(
        "touch {}; echo 1 > /proc/sys/net/ipv4/ip_forward; cat /proc/self/mountinfo",
        READONLY_PATHS.join(" ")
    )));
    let mounts = mountinfo(out.ok());
    for p in READONLY_PATHS {
        let m = mounts.iter().rev().find(|m| m.0 == p).unwrap_or_else(|| panic!("{p} is not a mount point: {out:#?}"));
        assert!(m.1.split(',').any(|o| o == "ro"), "{p} is not read-only: {m:?}");
    }
    for p in READONLY_PATHS.iter().copied().chain(["/proc/sys/net/ipv4/ip_forward"]) {
        assert!(
            out.stderr.lines().any(|l| l.contains(p) && l.contains("Read-only file system")),
            "writing {p} did not fail with EROFS: {out:#?}"
        );
    }
}

/// Masked and read-only paths that don't exist are skipped, not errors.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_missing_masked_and_read_only_paths_are_skipped() {
    let mut s = sh("echo ran");
    edit_linux(&mut s, |l| {
        let masked = l.masked_paths_mut().get_or_insert_with(Vec::new);
        masked.extend(["/proc/rustlet-no-such-file".into(), "/sys/rustlet-no-such-dir".into()]);
        l.readonly_paths_mut().get_or_insert_with(Vec::new).push("/proc/rustlet-no-such-thing".into());
    });
    assert_eq!(run(&s).ok().trim(), "ran");
}

/// Masked and read-only entries must be absolute, free of `..`, and not `/`
/// itself (masking the whole root with /dev/null or making it read-only
/// that way makes no sense).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_masked_and_read_only_paths_must_be_clean_absolute_paths() {
    let cases = [
        (true, "proc/kcore", "proc/kcore"),
        (true, "/proc/../etc/passwd", "/proc/../etc/passwd"),
        (true, "/", "maskedPaths"),
        (false, "proc/sys", "proc/sys"),
        (false, "/proc/sys/../../etc", "/proc/sys/../../etc"),
        (false, "/", "readonlyPaths"),
    ];
    for (i, (masked, bad, needle)) in cases.into_iter().enumerate() {
        let mut s = spec(&["true"]);
        edit_linux(&mut s, |l| {
            let list = if masked { l.masked_paths_mut() } else { l.readonly_paths_mut() };
            list.get_or_insert_with(Vec::new).push(bad.into());
        });
        set_cgroup(&mut s, &format!("hd-bad-path-{i}"));
        let mut c = Container::new(&s);
        c.create(&[]).refused(needle);
        c.assert_gone();
    }
}

/// Masking isn't special to /proc: a file and a directory of the rootfs
/// (/etc/shadow, /root) are hidden the same way.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_masking_works_outside_proc_too() {
    let mut s = sh("wc -c < /etc/shadow; ls -A /root | wc -l; stat -c %t:%T /etc/shadow");
    edit_linux(&mut s, |l| {
        l.masked_paths_mut().get_or_insert_with(Vec::new).extend(["/etc/shadow".into(), "/root".into()]);
    });
    assert_eq!(run(&s).ok().lines().collect::<Vec<_>>(), ["0", "0", "1:3"]);
    assert!(std::fs::metadata(alpine_rootfs().join("etc/shadow")).unwrap().len() > 0);
}

/// CVE-2025-31133: masking binds the container's /dev/null over each masked
/// file. If a spec mount has replaced /dev/null (with a regular host file, or
/// another device such as /dev/zero), the create must fail rather than bind
/// that over /proc/kcore & co.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_a_fake_dev_null_fails_the_create() {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fake-null");
    std::fs::write(&fake, "not /dev/null\n").unwrap();
    for (i, source) in [fake.to_str().unwrap(), "/dev/zero"].into_iter().enumerate() {
        let mut s = spec(&["true"]);
        add_mount(&mut s, "/dev/null", "bind", source, &["bind"]);
        set_cgroup(&mut s, &format!("hd-fake-null-{i}"));
        let mut c = Container::new(&s);
        let out = c.create(&[]);
        assert!(out.status != 0, "masking went ahead with {source} as /dev/null: {out:#?}");
        out.refused("/dev/null");
        c.assert_gone();
    }
    assert_eq!(std::fs::read_to_string(&fake).unwrap(), "not /dev/null\n");
}

// ── sysctls ──────────────────────────────────────────────────────────────────

/// net.* sysctls are applied in the container's own network namespace
/// (dotted and slash-separated keys alike) and never reach the host's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_net_sysctls_are_applied_inside_only() {
    let keys = ["net.ipv4.ip_forward", "net.ipv4.ip_unprivileged_port_start", "net.ipv4.ping_group_range"];
    let host_before: Vec<String> = keys.iter().map(|k| host_sysctl(k)).collect();
    let mut s = sh("cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/ip_unprivileged_port_start \
                    /proc/sys/net/ipv4/ping_group_range");
    set_sysctls(
        &mut s,
        &[
            ("net.ipv4.ip_forward", "1"),
            ("net/ipv4/ip_unprivileged_port_start", "80"),
            // A value with a space in it, as the daemon will write.
            ("net.ipv4.ping_group_range", "0 2147483647"),
        ],
    );
    let out = run(&s);
    assert_eq!(norm_lines(out.ok()), ["1", "80", "0 2147483647"]);
    let host_after: Vec<String> = keys.iter().map(|k| host_sysctl(k)).collect();
    assert_eq!(host_before, host_after, "the host's sysctls changed");
}

/// IPC sysctls (kernel.shm*, kernel.msg*, fs.mqueue.*) are applied with a
/// private IPC namespace, and refused when the container shares the host's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_ipc_sysctls_need_a_private_ipc_namespace() {
    let host_before = (host_sysctl("kernel.shmmax"), host_sysctl("kernel.msgmax"), host_sysctl("fs.mqueue.msg_max"));
    let mut s =
        sh("cat /proc/sys/kernel/shmmax /proc/sys/kernel/msgmax /proc/sys/fs/mqueue/msg_max /proc/sys/kernel/sem");
    set_sysctls(
        &mut s,
        &[
            ("kernel.shmmax", "123456789"),
            ("kernel.msgmax", "4242"),
            ("fs.mqueue.msg_max", "20"),
            ("kernel.sem", "250 32000 32 128"),
        ],
    );
    assert_eq!(norm_lines(run(&s).ok()), ["123456789", "4242", "20", "250 32000 32 128"]);
    let host_after = (host_sysctl("kernel.shmmax"), host_sysctl("kernel.msgmax"), host_sysctl("fs.mqueue.msg_max"));
    assert_eq!(host_before, host_after, "the host's sysctls changed");

    let mut s = spec(&["true"]);
    without_namespace(&mut s, LinuxNamespaceType::Ipc);
    set_sysctls(&mut s, &[("kernel.shmmax", &host_before.0)]);
    assert_refused(s, "hd-sysctl-host-ipc", "kernel.shmmax");
}

/// A sysctl key must not climb out of its namespaced subtree: `net/../vm/…`
/// starts with `net` but names a host-wide knob. Refused. (The values are
/// the host's current ones, so even a runtime that wrote them changes
/// nothing.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_sysctl_keys_cannot_escape_their_subtree() {
    let swappiness = host_sysctl("vm.swappiness");
    let keys =
        ["net/../vm/swappiness", "net/ipv4/../../vm/swappiness", "fs/mqueue/../../vm/swappiness", "net..vm.swappiness"];
    for (i, key) in keys.into_iter().enumerate() {
        let mut s = spec(&["true"]);
        set_sysctls(&mut s, &[(key, &swappiness)]);
        set_cgroup(&mut s, &format!("hd-sysctl-escape-{i}"));
        let mut c = Container::new(&s);
        let out = c.create(&[]);
        assert!(out.status != 0, "sysctl {key:?} was accepted: {out:#?}");
        out.failed();
        c.assert_gone();
    }
    assert_eq!(host_sysctl("vm.swappiness"), swappiness);
}

/// kernel.domainname is per UTS namespace: applied with a private one,
/// refused with the host's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_kernel_domainname_needs_a_private_uts_namespace() {
    let host_before = host_sysctl("kernel.domainname");
    let mut s = sh("cat /proc/sys/kernel/domainname");
    set_sysctls(&mut s, &[("kernel.domainname", "rustlet.test")]);
    assert_eq!(run(&s).ok().trim(), "rustlet.test");
    assert_eq!(host_sysctl("kernel.domainname"), host_before);

    // Without a hostname, which needs a UTS namespace of its own too.
    let mut s = spec(&["true"]);
    s.set_hostname(None);
    without_namespace(&mut s, LinuxNamespaceType::Uts);
    set_sysctls(&mut s, &[("kernel.domainname", &host_before)]);
    assert_refused(s, "hd-sysctl-host-uts", "kernel.domainname");
}

/// kernel.hostname is refused: the spec's `hostname` field sets it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_kernel_hostname_sysctl_is_refused() {
    let mut s = spec(&["true"]);
    set_sysctls(&mut s, &[("kernel.hostname", "sneaky")]);
    assert_refused(s, "hd-sysctl-hostname", "hostname");
}

/// Sysctls that aren't namespaced would change the host: refused. (The
/// values are the host's current ones, so a runtime that wrongly wrote them
/// would still change nothing.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_host_wide_sysctls_are_refused() {
    for (i, key) in
        ["vm.swappiness", "kernel.core_pattern", "fs.file-max", "kernel.randomize_va_space"].iter().enumerate()
    {
        let value = host_sysctl(key);
        let mut s = spec(&["true"]);
        set_sysctls(&mut s, &[(key, &value)]);
        assert_refused(s, &format!("hd-sysctl-global-{i}"), key);
        assert_eq!(host_sysctl(key), value);
    }
}

/// A net.* sysctl that exists but can't be written from a new netns (it is
/// host-wide: net.core.rmem_max is read-only there) fails the create with a
/// message naming it, instead of being skipped. (The value is the host's
/// own, so nothing could change even if it were written.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_unwritable_net_sysctls_fail_the_create() {
    let value = host_sysctl("net.core.rmem_max");
    let mut s = spec(&["true"]);
    set_sysctls(&mut s, &[("net.core.rmem_max", &value)]);
    assert_refused(s, "hd-sysctl-rmem-max", "net.core.rmem_max");
    assert_eq!(host_sysctl("net.core.rmem_max"), value);
}

/// Joining the *host's* UTS or IPC namespace by path is no better than
/// sharing it: a hostname, kernel.domainname or an IPC sysctl would change
/// the host's. All refused. (The values are the host's current ones, so a
/// runtime that wrongly applied them would still change nothing.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_host_namespaces_joined_by_path_get_no_hostname_or_sysctls() {
    let hostname = nix::unistd::gethostname().unwrap().into_string().unwrap();
    let mut s = spec(&["true"]);
    join_namespace(&mut s, LinuxNamespaceType::Uts, "/proc/1/ns/uts");
    s.set_hostname(Some(hostname.clone()));
    assert_refused(s, "hd-host-uts-hostname", "hostname");

    let domain = host_sysctl("kernel.domainname");
    let mut s = spec(&["true"]);
    join_namespace(&mut s, LinuxNamespaceType::Uts, "/proc/1/ns/uts");
    s.set_hostname(None);
    set_sysctls(&mut s, &[("kernel.domainname", &domain)]);
    assert_refused(s, "hd-host-uts-domainname", "kernel.domainname");

    let shmmax = host_sysctl("kernel.shmmax");
    let mut s = spec(&["true"]);
    join_namespace(&mut s, LinuxNamespaceType::Ipc, "/proc/1/ns/ipc");
    set_sysctls(&mut s, &[("kernel.shmmax", &shmmax)]);
    assert_refused(s, "hd-host-ipc-shmmax", "kernel.shmmax");

    assert_eq!(nix::unistd::gethostname().unwrap().into_string().unwrap(), hostname);
}

/// net.* sysctls need a network namespace that isn't the host's: refused
/// when the netns is shared (omitted) or joined from the host by path;
/// allowed when joining another container's netns.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_net_sysctls_need_a_network_namespace_other_than_the_hosts() {
    let host_value = host_sysctl("net.ipv4.ip_forward");
    let mut s = spec(&["true"]);
    without_namespace(&mut s, LinuxNamespaceType::Network);
    set_sysctls(&mut s, &[("net.ipv4.ip_forward", &host_value)]);
    assert_refused(s, "hd-sysctl-shared-netns", "net.ipv4.ip_forward");

    let mut s = spec(&["true"]);
    join_namespace(&mut s, LinuxNamespaceType::Network, "/proc/1/ns/net");
    set_sysctls(&mut s, &[("net.ipv4.ip_forward", &host_value)]);
    assert_refused(s, "hd-sysctl-host-netns-path", "net.ipv4.ip_forward");

    let mut first = spec(&["sleep", "3600"]);
    set_cgroup(&mut first, "hd-sysctl-netns-owner");
    let first = Container::started(&first);
    let mut s = sh("cat /proc/sys/net/ipv4/ip_forward");
    join_namespace(&mut s, LinuxNamespaceType::Network, &format!("/proc/{}/ns/net", first.pid()));
    set_sysctls(&mut s, &[("net.ipv4.ip_forward", "1")]);
    assert_eq!(run(&s).ok().trim(), "1");
    assert_eq!(host_sysctl("net.ipv4.ip_forward"), host_value);
}

// ── mount destinations ───────────────────────────────────────────────────────

/// User mounts can't land under /proc or /sys (where they could hide the
/// masking, or expose the host's view): refused, including the lxcfs
/// destinations when the mount isn't a bind of a regular file, and paths
/// that only reach /proc through `..`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_mounts_under_proc_and_sys_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "x\n").unwrap();
    let (d, f) = (dir.path().to_str().unwrap(), file.to_str().unwrap());
    let cases: [(&str, &str, &str, &[&str]); 8] = [
        ("/proc/sys/kernel", "tmpfs", "tmpfs", &[]),
        ("/proc/1", "bind", d, &["bind"]),
        ("/proc/kcore", "bind", f, &["bind"]),
        ("/proc/meminfo", "bind", d, &["bind"]),
        ("/proc/meminfo", "tmpfs", "tmpfs", &[]),
        ("/sys/kernel", "tmpfs", "tmpfs", &[]),
        ("/sys/fs/cgroup/rustlet", "bind", d, &["bind"]),
        ("/sys/../proc/sys", "tmpfs", "tmpfs", &[]),
    ];
    for (i, (dest, typ, source, options)) in cases.into_iter().enumerate() {
        let mut s = spec(&["true"]);
        add_mount(&mut s, dest, typ, source, options);
        set_cgroup(&mut s, &format!("hd-mount-dest-{i}"));
        let mut c = Container::new(&s);
        let out = c.create(&[]);
        assert!(out.status != 0, "{typ} mount on {dest} was accepted: {out:#?}");
        out.refused(dest);
        c.assert_gone();
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "x\n");
}

/// proc and sysfs belong at /proc and /sys only: a second instance
/// elsewhere would be unmasked and writable.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_proc_and_sysfs_elsewhere_are_refused() {
    for (i, typ) in ["proc", "sysfs"].into_iter().enumerate() {
        let mut s = spec(&["true"]);
        add_mount(&mut s, "/mnt", typ, typ, &["nosuid", "nodev", "noexec"]);
        set_cgroup(&mut s, &format!("hd-{typ}-elsewhere-{i}"));
        let mut c = Container::new(&s);
        let out = c.create(&[]);
        assert!(out.status != 0, "{typ} on /mnt was accepted: {out:#?}");
        out.refused("/mnt");
        c.assert_gone();
    }
}

/// The /proc rule applies to where a mount really lands, not to how the
/// destination is spelled: Alpine's /etc/mtab is a symlink to
/// ../proc/mounts, so a bind onto /etc/mtab would cover a /proc file.
/// (runc checks the destination after resolving it in the rootfs.)
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_mount_destinations_are_checked_after_following_symlinks() {
    assert!(alpine_rootfs().join("etc/mtab").is_symlink(), "Alpine's /etc/mtab is no longer a symlink");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("fake-mounts");
    std::fs::write(&file, "fake mounts\n").unwrap();
    let mut s = sh("head -n1 /proc/self/mounts");
    add_mount(&mut s, "/etc/mtab", "bind", file.to_str().unwrap(), &["bind", "ro"]);
    set_cgroup(&mut s, "hd-mount-via-symlink");
    let mut c = Container::new(&s);
    let out = c.run_foreground(&[], None, TIMEOUT);
    assert!(
        out.status == 1 && out.stderr.contains("rustlet-runc: "),
        "a bind onto /etc/mtab (-> /proc/mounts) was accepted; the container's /proc/self/mounts begins {:?}: {out:#?}",
        out.stdout.lines().next()
    );
    c.assert_gone();
}

/// lxcfs-style overrides are the exception: a bind of a regular host file
/// onto /proc/meminfo or /proc/loadavg is allowed and visible.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_file_binds_onto_the_lxcfs_whitelist_are_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let meminfo = dir.path().join("meminfo");
    let loadavg = dir.path().join("loadavg");
    std::fs::write(&meminfo, "MemTotal:       42 kB\n").unwrap();
    std::fs::write(&loadavg, "0.42 0.42 0.42 1/1 1\n").unwrap();
    let mut s = sh("cat /proc/meminfo /proc/loadavg");
    add_mount(&mut s, "/proc/meminfo", "bind", meminfo.to_str().unwrap(), &["bind", "ro"]);
    add_mount(&mut s, "/proc/loadavg", "bind", loadavg.to_str().unwrap(), &["bind", "ro"]);
    assert_eq!(run(&s).ok(), "MemTotal:       42 kB\n0.42 0.42 0.42 1/1 1\n");
}

// ── CVE-2019-5736: the runtime runs from a sealed memfd ──────────────────────

/// A created container's init (still the runtime, waiting for `start`)
/// runs from a sealed memfd, not from the binary on disk.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_created_init_runs_from_a_sealed_memfd() {
    let mut s = spec(&["true"]);
    set_cgroup(&mut s, "hd-memfd-created");
    let c = Container::created(&s);
    assert_sealed_memfd_exe(c.pid());
}

/// So does a foreground `rustlet-runc run` for as long as it runs.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_foreground_run_runs_from_a_sealed_memfd() {
    let mut r = TestBundle::new(&sh("echo ready; exec sleep 3600")).spawn(&[]);
    let mut line = String::new();
    BufReader::new(r.child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    assert_sealed_memfd_exe(r.child.id() as i32);
}

// ── --preserve-fds ───────────────────────────────────────────────────────────

/// `--preserve-fds 2` passes the caller's fds 3 and 4 (a file to read, one to
/// write) and nothing else: the container sees 0-4, plus the fd `ls` opens.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_preserve_fds_passes_exactly_the_requested_fds() {
    let dir = tempfile::tempdir().unwrap();
    let (input, output) = (dir.path().join("in"), dir.path().join("out"));
    std::fs::write(&input, "from fd 3\n").unwrap();
    let mut s = sh("cat <&3; echo 'to fd 4' >&4; ls /proc/self/fd | tr '\\n' ' '");
    set_cgroup(&mut s, "hd-preserve-2");
    let mut c = Container::new(&s);
    let out = c.run_foreground_with_fds(&["--preserve-fds", "2"], &[ExtraFd::Read(&input), ExtraFd::Write(&output)]);
    assert_eq!(out.ok(), "from fd 3\n0 1 2 3 4 5 ", "{out:#?}");
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "to fd 4\n");
}

/// Fds beyond `--preserve-fds N` are closed, and without the flag no extra
/// fd reaches the container at all.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_fds_beyond_preserve_fds_are_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::write(&a, "a\n").unwrap();
    std::fs::write(&b, "b\n").unwrap();
    let fds = [ExtraFd::Read(&a), ExtraFd::Read(&b)];

    let mut s = sh("cat <&3; ls /proc/self/fd | tr '\\n' ' '");
    set_cgroup(&mut s, "hd-preserve-1");
    let mut c = Container::new(&s);
    // 3 is the preserved fd, 4 the directory `ls` reads.
    assert_eq!(c.run_foreground_with_fds(&["--preserve-fds", "1"], &fds).ok(), "a\n0 1 2 3 4 ");

    let mut s = sh("ls /proc/self/fd | tr '\\n' ' '");
    set_cgroup(&mut s, "hd-preserve-0");
    let mut c = Container::new(&s);
    assert_eq!(c.run_foreground_with_fds(&[], &fds).ok(), "0 1 2 3 ");
}

/// Asking to preserve more fds than the caller has open must never hand the
/// container one of the runtime's own fds (the memfd it runs from, a sync
/// socket, …) in the gaps: either the request is refused, or the missing
/// fds stay closed.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_preserve_fds_never_passes_the_runtimes_own_fds() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    std::fs::write(&a, "a\n").unwrap();
    let mut s =
        sh("for fd in 3 4 5 6 7 8; do [ -e /proc/$$/fd/$fd ] && echo \"$fd $(readlink /proc/$$/fd/$fd)\"; done; true");
    set_cgroup(&mut s, "hd-preserve-gaps");
    let mut c = Container::new(&s);
    let out = c.run_foreground_with_fds(&["--preserve-fds", "4"], &[ExtraFd::Read(&a)]);
    if out.status != 0 {
        out.refused("preserve");
        eprintln!("refused: {}", out.stderr.trim());
        return;
    }
    assert_eq!(out.stdout.lines().collect::<Vec<_>>(), [format!("3 {}", a.display())], "{out:#?}");
}

/// Preserved fds survive from `create` until `start` execs the program.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_preserved_fds_survive_from_create_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("out");
    let mut s = sh("echo started >&3");
    set_cgroup(&mut s, "hd-preserve-create");
    let mut c = Container::new(&s);
    c.create_with_fds(&["--preserve-fds", "1"], &[ExtraFd::Write(&output)]).ok();
    c.start().ok();
    c.wait_for_status("stopped", PROMPT);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "started\n", "stderr: {}", c.stderr());
}

// ── session keyring ──────────────────────────────────────────────────────────

/// Whether the host's /proc/keys lists a keyring named `_ses.<id>`. (The
/// container's init creates it as root; root on the host may view it.)
fn has_session_keyring(id: &str) -> bool {
    let keys = std::fs::read_to_string("/proc/keys").unwrap();
    let want = format!("_ses.{id}");
    keys.lines().any(|l| l.split_whitespace().any(|w| w.trim_end_matches(':') == want))
}

/// Each container gets a fresh session keyring `_ses.<id>`, so containers
/// don't share (or see) the caller's keys; `--no-new-keyring` opts out.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hd_each_container_gets_its_own_session_keyring() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "hd-keyring");
    let c = Container::started(&s);
    assert!(has_session_keyring(c.id()), "no _ses.{} keyring in /proc/keys", c.id());

    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "hd-no-keyring");
    let mut c = Container::new(&s);
    c.create(&["--no-new-keyring"]).ok();
    c.start().ok();
    assert!(!has_session_keyring(c.id()), "--no-new-keyring still made _ses.{}", c.id());
}
