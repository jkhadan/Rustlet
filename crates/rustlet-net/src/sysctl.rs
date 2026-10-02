//! The sysctls networking needs, host-wide and per network namespace.
//!
//! Every file under `/proc/sys/net` belongs to the network namespace of the
//! thread that opens it, not to a fixed one: the same path shows the host's
//! `ip_forward` to the daemon's main thread and a container's
//! `ip_unprivileged_port_start` to a thread that has `setns`'d into its
//! namespace. So everything here acts on the caller's namespace.
//!
//! **IP forwarding** is off on this host, and a bridge with NAT needs it on.
//! The value it had is recorded once, before Rustlets first changes it, in
//! a file `scripts/cleanup.sh` reads back (`net.ipv4.ip_forward=0`), and a
//! recorded value is never overwritten: a second daemon must not record the
//! value the first one set. It lives under `/run`, so a reboot (which
//! resets the sysctl) forgets it too. IPv6 forwarding
//! (`net.ipv6.conf.all.forwarding`) is turned on, and recorded in the same
//! file, only once there is an IPv6 network: until then the host's IPv6
//! routing is left exactly as it was.
//!
//! **IPv6 in a container's namespace** starts off on every new interface
//! (`default.disable_ipv6`), and with router advertisements ignored
//! (`default.accept_ra`): an interface on an IPv4-only network never gets
//! even a link-local address, and one on an IPv6 network gets exactly the
//! address and route the daemon gives it, whatever a neighbour on the
//! bridge advertises.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Context, Result};

pub const IP_FORWARD: &str = "net.ipv4.ip_forward";
/// IPv6 forwarding, for every interface at once.
pub const IP6_FORWARD: &str = "net.ipv6.conf.all.forwarding";

/// What every network namespace the daemon pins gets, as Docker's
/// containers do: ports below 1024 can be bound without
/// `CAP_NET_BIND_SERVICE` (which a container in a user namespace doesn't
/// have over a namespace the host owns), and `ping` works without
/// `CAP_NET_RAW` (ICMP echo sockets for every group).
pub const NETNS_DEFAULTS: [(&str, &str); 2] =
    [("net.ipv4.ip_unprivileged_port_start", "0"), ("net.ipv4.ping_group_range", "0 2147483647")];

/// What every pinned namespace gets for IPv6, where the kernel has it: new
/// interfaces start without IPv6 and ignore router advertisements (see the
/// module docs).
pub const NETNS_DEFAULTS6: [(&str, &str); 2] =
    [("net.ipv6.conf.default.disable_ipv6", "1"), ("net.ipv6.conf.default.accept_ra", "0")];

/// `/proc/sys/…` for a dotted name. Interface names may contain dots
/// (`eth0.5`), so those paths are built with [`path_of`] instead.
pub fn path(name: &str) -> PathBuf {
    Path::new("/proc/sys").join(name.replace('.', "/"))
}

/// `/proc/sys/<a>/<b>/…` from its components.
pub fn path_of(components: &[&str]) -> PathBuf {
    components.iter().fold(PathBuf::from("/proc/sys"), |p, c| p.join(c))
}

pub fn read(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?.trim().to_owned())
}

pub fn write(path: &Path, value: &str) -> Result<()> {
    std::fs::write(path, value).with_context(|| format!("write {value:?} to {}", path.display()))
}

/// Turns IPv4 forwarding on, having recorded its old value in `record`
/// unless the record has it already. Returns whether forwarding was off
/// before Rustlets first turned it on (what the record says).
pub fn enable_forwarding(record: &Path) -> Result<bool> {
    turn_on(record, IP_FORWARD)
}

/// [`enable_forwarding`] for IPv6 (every interface).
pub fn enable_forwarding6(record: &Path) -> Result<bool> {
    turn_on(record, IP6_FORWARD)
}

/// Writes `1` to `name`, having recorded its old value in `record` unless
/// the record has a value for it already; returns whether the recorded
/// value is `0`.
fn turn_on(record: &Path, name: &str) -> Result<bool> {
    let current = read(&path(name))?;
    if recorded(record, name).is_none() {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o644)
            .open(record)
            .with_context(|| format!("record the host's sysctls in {}", record.display()))?;
        writeln!(f, "{name}={current}").with_context(|| format!("write {}", record.display()))?;
    }
    if current != "1" {
        write(&path(name), "1")?;
    }
    Ok(recorded(record, name).as_deref() == Some("0"))
}

/// The value `record` holds for `name`.
pub fn recorded(record: &Path, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(record).ok()?;
    text.lines().find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == name).map(|(_, v)| v.trim().to_owned()))
}

/// [`NETNS_DEFAULTS`] and, where the kernel has IPv6, [`NETNS_DEFAULTS6`],
/// in the caller's network namespace.
pub fn set_netns_defaults() -> Result<()> {
    for (name, value) in NETNS_DEFAULTS {
        write(&path(name), value)?;
    }
    if ipv6_available() {
        for (name, value) in NETNS_DEFAULTS6 {
            write(&path(name), value)?;
        }
    }
    Ok(())
}

/// Does the kernel have IPv6 (not disabled at boot)?
pub fn ipv6_available() -> bool {
    Path::new("/proc/sys/net/ipv6").exists()
}

/// No IPv6 on `ifname` (no link-local address, no router solicitations):
/// it is on IPv4-only networks, or a bridge port. Nothing to do if the
/// kernel has no IPv6.
pub fn disable_ipv6(ifname: &str) -> Result<()> {
    if !ipv6_available() {
        return Ok(());
    }
    write_interface6(ifname, "disable_ipv6", "1")
}

/// IPv6 on `ifname`, ignoring router advertisements (the daemon gives it
/// its addresses and routes), with its link-local address usable at once.
/// Both are set before IPv6 comes on, so that there is no moment in which
/// an advertisement could configure it.
///
/// Usable at once, because duplicate address detection would cost the
/// first second or two of forwarded traffic: the kernel sends no Neighbor
/// Solicitation for a packet it forwards out of an interface whose
/// link-local address is still tentative (`ndisc_send_ns` needs one as its
/// source), so a container's first IPv6 connections from the LAN were
/// lost. The addresses can't collide anyway: on a Rustlets bridge the
/// containers' MACs, from which their link-local addresses come, are
/// derived from their unique IPv4 addresses.
pub fn enable_ipv6(ifname: &str) -> Result<()> {
    write_interface6(ifname, "accept_ra", "0")?;
    write_interface6(ifname, "accept_dad", "0")?;
    write_interface6(ifname, "disable_ipv6", "0")
}

/// `net.ipv6.conf.<ifname>.<key>`.
fn write_interface6(ifname: &str, key: &str, value: &str) -> Result<()> {
    write(&path_of(&["net", "ipv6", "conf", ifname, key]), value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(path("net.ipv4.ip_forward"), Path::new("/proc/sys/net/ipv4/ip_forward"));
        assert_eq!(
            path_of(&["net", "ipv6", "conf", "eth0.5", "disable_ipv6"]),
            Path::new("/proc/sys/net/ipv6/conf/eth0.5/disable_ipv6")
        );
        // Readable by anyone.
        assert!(matches!(read(&path(IP_FORWARD)).unwrap().as_str(), "0" | "1"));
    }

    #[test]
    fn records_are_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("host-sysctl.orig");
        assert_eq!(recorded(&record, IP_FORWARD), None);
        std::fs::write(&record, "net.ipv4.ip_forward=0\nother.thing = 5\n").unwrap();
        assert_eq!(recorded(&record, IP_FORWARD).as_deref(), Some("0"));
        assert_eq!(recorded(&record, "other.thing").as_deref(), Some("5"));
    }

    #[test]
    fn a_recorded_value_is_never_overwritten() {
        // turn_on as an ordinary user can't write /proc/sys, but it records
        // before it writes: the record is what this checks.
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("host-sysctl.orig");
        std::fs::write(&record, format!("{IP_FORWARD}=0\n")).unwrap();
        let _ = turn_on(&record, IP_FORWARD);
        let _ = turn_on(&record, IP6_FORWARD);
        let _ = turn_on(&record, IP6_FORWARD);
        let text = std::fs::read_to_string(&record).unwrap();
        assert_eq!(text.matches(IP_FORWARD).count(), 1, "{text}");
        assert_eq!(recorded(&record, IP_FORWARD).as_deref(), Some("0"), "{text}");
        if ipv6_available() {
            assert_eq!(text.matches(IP6_FORWARD).count(), 1, "appended once: {text}");
        }
    }
}
