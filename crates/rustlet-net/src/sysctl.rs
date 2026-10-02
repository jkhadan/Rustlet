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
//! a file `scripts/cleanup.sh` reads back (`net.ipv4.ip_forward=0`), and the
//! record is never overwritten: a second daemon must not record the value
//! the first one set. It lives under `/run`, so a reboot (which resets the
//! sysctl) forgets it too.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Context, Result};

pub const IP_FORWARD: &str = "net.ipv4.ip_forward";

/// What every network namespace the daemon pins gets, as Docker's
/// containers do: ports below 1024 can be bound without
/// `CAP_NET_BIND_SERVICE` (which a container in a user namespace doesn't
/// have over a namespace the host owns), and `ping` works without
/// `CAP_NET_RAW` (ICMP echo sockets for every group).
pub const NETNS_DEFAULTS: [(&str, &str); 2] =
    [("net.ipv4.ip_unprivileged_port_start", "0"), ("net.ipv4.ping_group_range", "0 2147483647")];

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
/// unless a record exists already. Returns whether forwarding was off
/// before Rustlets first turned it on (what the record says).
pub fn enable_forwarding(record: &Path) -> Result<bool> {
    let current = read(&path(IP_FORWARD))?;
    if !record.exists() {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(record)
            .with_context(|| format!("record the host's sysctls in {}", record.display()))?;
        writeln!(f, "{IP_FORWARD}={current}").with_context(|| format!("write {}", record.display()))?;
    }
    if current != "1" {
        write(&path(IP_FORWARD), "1")?;
    }
    Ok(recorded(record, IP_FORWARD).as_deref() == Some("0"))
}

/// The value `record` holds for `name`.
pub fn recorded(record: &Path, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(record).ok()?;
    text.lines().find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == name).map(|(_, v)| v.trim().to_owned()))
}

/// [`NETNS_DEFAULTS`], in the caller's network namespace.
pub fn set_netns_defaults() -> Result<()> {
    for (name, value) in NETNS_DEFAULTS {
        write(&path(name), value)?;
    }
    Ok(())
}

/// No IPv6 on `ifname` (no link-local address, no router solicitations):
/// Rustlets' networks are IPv4. Nothing to do if the kernel has no IPv6.
pub fn disable_ipv6(ifname: &str) -> Result<()> {
    let p = path_of(&["net", "ipv6", "conf", ifname, "disable_ipv6"]);
    match std::fs::write(&p, "1") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !Path::new("/proc/sys/net/ipv6").exists() => Ok(()),
        r => r.with_context(|| format!("write 1 to {}", p.display())),
    }
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
}
