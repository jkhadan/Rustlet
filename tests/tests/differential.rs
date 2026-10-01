//! Phase 2b milestone: the same bundle under `runc` and under `rustlet-runc`
//! must look the same from inside, both for the container's own process
//! (`run`) and for one added with `exec`. A probe script dumps what a
//! process can see of its own confinement (capabilities, NNP, seccomp,
//! mounts, /dev, rlimits, cgroup, identity, env, masked and read-only paths,
//! namespaces, loopback, fds); the two outputs are normalised and compared
//! section by section.
//!
//! Known, accepted differences are handled explicitly in [`normalise`] and
//! [`accepted`], each with its reason. Anything else fails the test.
//!
//! runc's cgroup v2 driver enables every available controller in every
//! ancestor's `cgroup.subtree_control`, all the way from the root, which
//! would change `system.slice` on the host. So runc runs in a cgroup
//! namespace rooted at a leaf of the test scope, with a private mount
//! namespace whose `/sys/fs/cgroup` is that namespace's view: its writes then
//! stay inside the test scope.
//!
//! Run with `cargo xtask itest -- df_`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxDeviceBuilder, LinuxDeviceCgroupBuilder, LinuxDeviceType, LinuxResourcesBuilder, Spec,
};
use rustlet_runtime::spec::to_pretty_json;

const RUNC: &str = "/usr/sbin/runc";

/// Namespace kinds whose sharing with the host the probe reports.
const NS_KINDS: [&str; 10] =
    ["cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "time", "time_for_children", "user", "uts"];

/// The probe. Each section starts with a `== name` line.
fn probe_script() -> String {
    let masked = MASKED_PATHS.join(" ");
    let readonly = READONLY_PATHS.join(" ");
    let ns = NS_KINDS.join(" ");
    [
        "echo '== status'; grep -E '^(Cap|NoNewPrivs|Seccomp|Sig(Blk|Ign)|Uid|Gid|Groups)' /proc/self/status"
            .to_owned(),
        // mount point, fs type, per-mount options, super options
        "echo '== mounts'; awk '{ for (i = 7; $i != \"-\"; i++); print $5, $(i+1), $6, $(i+3) }' /proc/self/mountinfo \
         | sort"
            .to_owned(),
        "echo '== dev'; for n in $(ls -A /dev); do s=$(stat -c '%n %F %A %u:%g %t,%T' /dev/$n); \
         [ -L /dev/$n ] && s=\"$s -> $(readlink /dev/$n)\"; echo \"$s\"; done; \
         for d in /dev/pts /dev/shm /dev/mqueue; do echo \"$d: $(ls -A $d | tr '\\n' ' ')\"; done"
            .to_owned(),
        "echo '== ulimit'; ulimit -a".to_owned(),
        "echo '== cgroup'; cat /proc/self/cgroup".to_owned(),
        "echo '== identity'; id; umask; hostname; echo \"pid $$\"; cat /proc/self/oom_score_adj; \
         cat /proc/self/attr/current 2>&1; echo"
            .to_owned(),
        "echo '== env'; env | sort".to_owned(),
        format!(
            "echo '== masked'; for p in {masked}; do if [ -d $p ]; then echo \"$p dir $(ls -A $p | wc -l)\"; \
             elif [ -e $p ]; then echo \"$p file $(wc -c < $p)\"; else echo \"$p missing\"; fi; done"
        ),
        format!(
            "echo '== readonly'; for p in {readonly}; do touch $p 2>&1 && echo \"$p writable\"; done; \
             {{ echo 1 > /proc/sys/net/ipv4/ip_forward; }} 2>&1 && echo 'ip_forward writable'"
        ),
        format!("echo '== namespaces'; for k in {ns}; do echo \"$k $(readlink /proc/self/ns/$k)\"; done"),
        "echo '== net'; ls /sys/class/net; echo \"lo flags $(cat /sys/class/net/lo/flags)\"; \
         cat /proc/sys/net/ipv4/ip_unprivileged_port_start /proc/sys/net/ipv4/ping_group_range"
            .to_owned(),
        "echo '== fds'; ls /proc/self/fd | tr '\\n' ' '; echo".to_owned(),
    ]
    .join("\n")
}

/// Splits `runtime`'s probe output into sections, with every line passed
/// through [`normalise`].
fn sections(out: &str, runtime: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = String::from("(before the first section)");
    for line in out.lines() {
        if let Some(name) = line.strip_prefix("== ") {
            current = name.to_owned();
            map.entry(current.clone()).or_default();
            continue;
        }
        let line = normalise(&current, runtime, line.trim_end());
        map.entry(current.clone()).or_default().push(line);
    }
    map
}

/// Rewrites what may legitimately differ between the two runs *in the same
/// way for both* (inode numbers), or differs in a known, accepted way (each
/// case says why).
fn normalise(section: &str, runtime: &str, line: &str) -> String {
    match (section, runtime) {
        // Namespace inodes differ between any two containers; what matters
        // is whether each namespace is the host's or a private one.
        ("namespaces", _) => match line.split_once(' ') {
            Some((kind, link)) => format!("{kind} {}", if link == host_ns(kind) { "host" } else { "private" }),
            None => line.to_owned(),
        },
        ("mounts", _) => normalise_mount(runtime, line),
        // The harness, not the runtimes: no spec sets an AppArmor profile,
        // so the container keeps the label of whatever exec'd the runtime.
        // Ubuntu ships an unconfined `runc` profile attached to
        // /usr/sbin/runc, while rustlet-runc inherits the test's label.
        // Both are unconfined, which is what the comparison keeps.
        ("identity", _) if line == "unconfined" || line.ends_with(" (unconfined)") => "(unconfined)".to_owned(),
        // An exec'd process's PID depends on how many processes came
        // before it; only "is it init" is comparable.
        ("identity", _) if line.starts_with("pid ") && line != "pid 1" => "pid (not 1)".to_owned(),
        _ => line.to_owned(),
    }
}

/// A `mount point, fs type, per-mount options, super options` line.
fn normalise_mount(runtime: &str, line: &str) -> String {
    let mut f: Vec<String> = line.split(' ').map(str::to_owned).collect();
    if f.len() != 4 {
        return line.to_owned();
    }
    let drop_opts = |opts: &str, unwanted: &[&str]| -> String {
        opts.split(',').filter(|o| !unwanted.contains(o)).collect::<Vec<_>>().join(",")
    };
    // Deliberate: Rustlets makes mounts read-only with the mount attribute
    // (MOUNT_ATTR_RDONLY) and never flips superblock flags, since a
    // superblock can be shared with the host (sysfs under --net=host,
    // cgroup2 without a new cgroupns) and flipping it would make the host's
    // view read-only too; runc's mount(2) with MS_RDONLY sets both. The
    // per-mount options (third column) say whether this mount is writable,
    // and those are compared; the superblock's ro/rw flag is not.
    f[3] = drop_opts(&f[3], &["ro", "rw"]);
    if runtime == "rustlet" {
        // Deliberate (docs/architecture.md §2.2.2): Rustlets binds the
        // rootfs `nodev`; device nodes only come from its own /dev tmpfs.
        if f[0] == "/" {
            f[2] = drop_opts(&f[2], &["nodev"]);
        }
        // Deliberate extra hardening: the empty read-only tmpfs over a
        // masked directory is also nosuid,nodev,noexec (runc's is only ro).
        // (Masked files are binds of /dev/null, whose fs is the read-write
        // /dev tmpfs; those are left alone.)
        let read_only = f[2].split(',').any(|o| o == "ro");
        if f[1] == "tmpfs" && read_only && MASKED_PATHS.contains(&f[0].as_str()) {
            f[2] = drop_opts(&f[2], &["nosuid", "nodev", "noexec"]);
        }
    }
    f.join(" ")
}

/// One-sided differences we know about and accept, each with the reason:
/// whether `line`, seen only under `runtime`, is one of them.
fn accepted(section: &str, runtime: &str, line: &str) -> bool {
    match (section, runtime) {
        // runc creates /dev/core -> /proc/kcore (a Docker-era convention).
        // Rustlets deliberately doesn't: /proc/kcore is masked anyway, and
        // the link only advertises it.
        ("dev", "runc") => line.starts_with("/dev/core "),
        // runc permits arbitrary char/block mknod and tun by default;
        // Rustlets grants m only for defaults and specified nodes.
        ("access", "runc") => matches!(
            line,
            "mknod:/dev/other-char:c:10:230 ok"
                | "mknod:/dev/other-block:b:8:1 ok"
                | "access:/dev/net/tun:rw ok"
                | "access:/dev/fuse:rw ok"
        ),
        // The fuse request includes a denied write bit. Rustlets applies
        // denies per bit, including O_RDWR; runc's v1 emulator only
        // matches a deny whose access contains the entire request.
        ("access", "rustlet") => matches!(
            line,
            "mknod:/dev/other-char:c:10:230 EPERM"
                | "mknod:/dev/other-block:b:8:1 EPERM"
                | "access:/dev/net/tun:rw EPERM"
                | "access:/dev/fuse:rw EPERM"
        ),
        _ => false,
    }
}

/// Lines of `a` that aren't in `b` (as multisets).
fn only_in(a: &[String], b: &[String]) -> Vec<String> {
    let mut rest = b.to_vec();
    a.iter()
        .filter(|l| match rest.iter().position(|r| r == *l) {
            Some(i) => {
                rest.swap_remove(i);
                false
            }
            None => true,
        })
        .cloned()
        .collect()
}

/// Removes the runc state root and the runc leaf cgroup (killing anything
/// left in it) on drop, even if the test fails halfway.
struct RuncCleanup {
    root: std::path::PathBuf,
    leaf: std::path::PathBuf,
}

impl Drop for RuncCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        // Normally empty by now (runc removed its container cgroup).
        if std::fs::remove_dir(&self.leaf).is_err() && force_remove_cgroup(&self.leaf) {
            eprintln!("df: cleaned up what runc left in {}", self.leaf.display());
        }
    }
}

/// Runs inside the cgroup and mount namespaces set up for runc: replaces
/// /sys/fs/cgroup with the namespace's view, then either runs the bundle in
/// the foreground (no 5th argument) or starts it detached, runs the probe
/// (5th argument) through `runc exec`, and deletes the container.
const RUNC_INNER: &str = r#"
umount -l /sys/fs/cgroup && mount -t cgroup2 cgroup2 /sys/fs/cgroup || exit 98
runc=$1 root=$2 bundle=$3 id=$4
if [ $# -lt 5 ]; then exec "$runc" --root "$root" run --bundle "$bundle" "$id"; fi
"$runc" --root "$root" run --detach --bundle "$bundle" "$id" </dev/null >/dev/null 2>&1 || exit 96
"$runc" --root "$root" exec "$id" sh -c "$5"; rc=$?
"$runc" --root "$root" delete --force "$id" >/dev/null 2>&1
exit $rc
"#;

/// Runs `spec` under runc (with `cgroupsPath` set to `/df-runc`, relative to
/// the cgroup namespace it runs in): in the foreground if `exec_probe` is
/// `None`, else detached with `exec_probe` run through `runc exec`. Returns
/// what the container (or the exec'd probe) printed.
fn run_under_runc(spec: &Spec, exec_probe: Option<&str>) -> CmdOut {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    // The leaf that becomes runc's cgroup namespace root.
    let leaf = itest_cgroup(&format!("df-runc-ns-{n}"));
    let leaf_dir = cgroup_dir(&leaf);
    std::fs::create_dir(&leaf_dir).unwrap();
    let root = std::path::PathBuf::from(format!("/run/rustlet/itest-{pid}-runc-{n}"));
    let _cleanup = RuncCleanup { root: root.clone(), leaf: leaf_dir.clone() };

    let bundle = tempfile::Builder::new().prefix("rustlet-itest-runc-").tempdir().unwrap();
    let mut spec = spec.clone();
    set_cgroups_path(&mut spec, "/df-runc");
    std::fs::write(bundle.path().join("config.json"), to_pretty_json(&spec)).unwrap();

    // sh moves itself into the leaf, then unshare roots a new cgroup
    // namespace there, in a private mount namespace, and runs RUNC_INNER.
    let outer = "inner=$1; echo 0 > \"$2/cgroup.procs\" || exit 97; shift 2; \
                 exec /usr/bin/unshare --cgroup --mount --propagation private -- /bin/sh -c \"$inner\" sh \"$@\"";
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", outer, "sh", RUNC_INNER])
        .arg(&leaf_dir)
        .arg(RUNC)
        .arg(&root)
        .arg(bundle.path())
        .arg(format!("df-runc-{pid}-{n}"))
        .args(exec_probe)
        .stdin(Stdio::null());
    let before = host_mounts();
    let out = exec(cmd);
    assert_host_mounts_unchanged(&before, &host_mounts());
    out
}

/// Compares two probe outputs section by section; returns a report of the
/// differences that are neither normalised away nor accepted.
fn compare(runc_out: &str, ours: &str) -> String {
    eprintln!("── runc ──\n{runc_out}\n── rustlet-runc ──\n{ours}");
    let (theirs, mine) = (sections(runc_out, "runc"), sections(ours, "rustlet"));
    let mut report = String::new();
    let names: std::collections::BTreeSet<&String> = theirs.keys().chain(mine.keys()).collect();
    let empty = Vec::new();
    for name in names {
        let (t, m) = (theirs.get(name).unwrap_or(&empty), mine.get(name).unwrap_or(&empty));
        let runc_only: Vec<String> = only_in(t, m).into_iter().filter(|l| !accepted(name, "runc", l)).collect();
        let ours_only: Vec<String> = only_in(m, t).into_iter().filter(|l| !accepted(name, "rustlet", l)).collect();
        if runc_only.is_empty() && ours_only.is_empty() {
            continue;
        }
        report.push_str(&format!("[{name}]\n"));
        for l in runc_only {
            report.push_str(&format!("  runc only:    {l}\n"));
        }
        for l in ours_only {
            report.push_str(&format!("  rustlet only: {l}\n"));
        }
    }
    report
}

fn have_runc() -> bool {
    let found = Path::new(RUNC).exists();
    if !found {
        eprintln!("skipped: no runc at {RUNC}");
    }
    found
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn df_devices_match_runc() {
    if !have_runc() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_rustlet-probe"), dir.path().join("probe")).unwrap();
    let script = "echo '== nodes'; stat -c '%n %F %a %u:%g %t:%T' /dev/fuse /dev/net/tun; \
        echo '== access'; /opt/ld-linux-x86-64.so.2 --library-path /opt /mnt/probe \
        access:/dev/null:rw access:/dev/fuse:r access:/dev/fuse:w access:/dev/fuse:rw \
        access:/dev/net/tun:rw mknod:/dev/other-char:c:10:230 mknod:/dev/other-block:b:8:1";
    let mut s = sh(script);
    add_mount(&mut s, "/mnt", "bind", dir.path().to_str().unwrap(), &["bind", "ro", "nosuid", "nodev"]);
    add_mount(&mut s, "/opt", "bind", "/usr/lib/x86_64-linux-gnu", &["bind", "ro", "nosuid", "nodev"]);
    let caps: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_MKNOD"]).collect();
    set_capabilities(&mut s, CapSets::root(&caps));
    edit_linux(&mut s, |l| {
        l.set_seccomp(None);
        l.set_devices(Some(vec![
            LinuxDeviceBuilder::default()
                .path("/dev/fuse")
                .typ(LinuxDeviceType::C)
                .major(10)
                .minor(229)
                .file_mode(0o640u32)
                .uid(12u32)
                .gid(34u32)
                .build()
                .unwrap(),
            LinuxDeviceBuilder::default()
                .path("/dev/net/tun")
                .typ(LinuxDeviceType::C)
                .major(10)
                .minor(200)
                .build()
                .unwrap(),
        ]));
        l.set_resources(Some(
            LinuxResourcesBuilder::default()
                .devices(vec![
                    LinuxDeviceCgroupBuilder::default()
                        .allow(true)
                        .typ(LinuxDeviceType::C)
                        .major(10)
                        .minor(229)
                        .access("rw")
                        .build()
                        .unwrap(),
                    LinuxDeviceCgroupBuilder::default()
                        .allow(false)
                        .typ(LinuxDeviceType::C)
                        .major(10)
                        .minor(229)
                        .access("w")
                        .build()
                        .unwrap(),
                ])
                .build()
                .unwrap(),
        ));
    });
    let theirs = run_under_runc(&s, None);
    theirs.ok();
    set_cgroup(&mut s, "df-devices");
    let ours = run(&s);
    let report = compare(&theirs.stdout, ours.ok());
    assert!(report.is_empty(), "device behavior differs unexpectedly:\n{report}");
    // Assert the deliberate differences also occur, so accepting them
    // cannot hide a regression that grants forbidden access.
    for denied in [
        "access:/dev/fuse:rw EPERM",
        "access:/dev/net/tun:rw EPERM",
        "mknod:/dev/other-block:b:8:1 EPERM",
        "mknod:/dev/other-char:c:10:230 EPERM",
    ] {
        assert!(ours.stdout.contains(denied), "{ours:#?}");
    }
}

/// The same default bundle under runc and rustlet-runc looks the same from
/// inside, apart from the differences listed in [`normalise`] and
/// [`accepted`].
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn df_probe_output_matches_runc() {
    if !have_runc() {
        return;
    }
    let base = sh(&probe_script());

    let runc_out = run_under_runc(&base, None);
    assert_eq!(runc_out.status, 0, "the probe failed under runc: {runc_out:#?}");

    let mut s = base.clone();
    set_cgroup(&mut s, "df-rustlet");
    let mut c = Container::new(&s);
    let ours = c.run_foreground(&[], None, TIMEOUT);
    assert_eq!(ours.status, 0, "the probe failed under rustlet-runc: {ours:#?}");
    c.assert_gone();

    let report = compare(&runc_out.stdout, &ours.stdout);
    assert!(report.is_empty(), "runc and rustlet-runc differ:\n{report}");
}

/// The same for `exec`: the probe run through `runc exec` and through
/// `rustlet-runc exec` in a default container (init `sleep 3600`) sees the
/// same confinement.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn df_exec_probe_output_matches_runc() {
    if !have_runc() {
        return;
    }
    let base = spec(&["sleep", "3600"]);
    let probe = probe_script();

    let runc_out = run_under_runc(&base, Some(&probe));
    assert_eq!(runc_out.status, 0, "the probe failed under runc exec: {runc_out:#?}");

    let mut s = base.clone();
    set_cgroup(&mut s, "df-rustlet-exec");
    let c = Container::started(&s);
    let ours = c.exec_in(&[], &["sh", "-c", &probe]);
    assert_eq!(ours.status, 0, "the probe failed under rustlet-runc exec: {ours:#?}");

    let report = compare(&runc_out.stdout, &ours.stdout);
    assert!(report.is_empty(), "runc exec and rustlet-runc exec differ:\n{report}");
}
