//! ufw, the host's firewall front end, if it is installed.
//!
//! An `accept` in Rustlets' nftables table can't overrule another table's
//! `drop`: every base chain on a hook sees the packet, and any of them may
//! drop it. ufw keeps its rules in iptables (nftables underneath, tables
//! `ip filter` and `ip6 filter`), with its own forward policy: `DROP` on
//! this host (`DEFAULT_FORWARD_POLICY` in `/etc/default/ufw`). With ufw
//! active, containers' traffic would be forwarded by Rustlets' table and
//! dropped by ufw's. So for every network the daemon asks ufw itself to
//! route the bridge's traffic, both ways:
//!
//! ```sh
//! ufw route allow in on rustlet0
//! ufw route allow out on rustlet0
//! ```
//!
//! (Rustlets' own table still decides what may reach a container: only
//! replies, published ports and its own network's traffic. These two rules
//! only keep ufw from dropping what that table lets through.)
//!
//! The rules are kept whether ufw is active or not. An inactive ufw only
//! writes them into its configuration, and they take effect on the day
//! someone runs `ufw enable`: enabling ufw then never cuts the containers
//! off. They show in `ufw status` (and `ufw show added`), go with their
//! network, and `scripts/cleanup.sh` removes them all.
//!
//! Only a daemon in the host's own network namespace does any of this
//! ([`manages_host`]): ufw's rules are the host's, and a daemon in a
//! namespace of its own (every test daemon) has nothing to do with them.
//! `ufw status` itself checks for its chains in the namespace it runs in,
//! so it reports "inactive" there whatever the host's ufw does; but
//! `ufw route allow` would still write the host's configuration files.
//!
//! What ufw doesn't route but delivers to the host itself is still ufw's to
//! decide: the userland proxy listens on published ports, and the traffic
//! it serves (a container connecting to a port published on its own
//! network through the host's address; IPv6 clients of a container without
//! IPv6) meets ufw's incoming policy, as docker-proxy's does.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use crate::error::{Context, Error, Result};

/// `ufw`: `/usr/sbin/ufw`, else whatever `PATH` finds.
fn ufw() -> &'static str {
    if Path::new("/usr/sbin/ufw").exists() { "/usr/sbin/ufw" } else { "ufw" }
}

/// Is ufw installed?
pub fn installed() -> bool {
    Path::new("/usr/sbin/ufw").exists()
        || std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|d| d.join("ufw").exists()))
}

/// Is the caller in the host's network namespace (PID 1's)? Not knowing
/// (no access to PID 1's namespace) counts as no.
pub fn in_host_namespace() -> bool {
    let inode = |p: &str| std::fs::metadata(p).map(|m| (m.dev(), m.ino())).ok();
    matches!((inode("/proc/self/ns/net"), inode("/proc/1/ns/net")), (Some(a), Some(b)) if a == b)
}

/// Should this daemon keep ufw's rules for its networks: ufw is installed
/// and the daemon is in the host's network namespace.
pub fn manages_host() -> bool {
    installed() && in_host_namespace()
}

/// Is ufw active in the caller's network namespace? (`ufw status` needs
/// root; any failure counts as "not active".)
pub fn active() -> bool {
    Command::new(ufw())
        .arg("status")
        .output()
        .is_ok_and(|o| o.status.success() && says_active(&String::from_utf8_lossy(&o.stdout)))
}

/// `ufw status`'s first line is `Status: active` or `Status: inactive`.
fn says_active(status: &str) -> bool {
    status.lines().next().is_some_and(|l| l.trim() == "Status: active")
}

/// The `ufw` arguments that allow (or, with `delete`, stop allowing)
/// routing through `bridge`.
pub fn route_rules(bridge: &str, delete: bool) -> Vec<Vec<String>> {
    ["in", "out"]
        .iter()
        .map(|dir| {
            let mut args = vec!["route".to_owned()];
            if delete {
                args.push("delete".into());
            }
            args.extend(["allow", dir, "on", bridge].map(String::from));
            args
        })
        .collect()
}

/// The rules added to ufw, as `ufw show added` lists them, without the
/// leading `ufw ` (`route allow in on rustlet0`).
pub fn added() -> Result<Vec<String>> {
    let out = Command::new(ufw()).args(["show", "added"]).output().context("run ufw show added")?;
    if !out.status.success() {
        return Err(Error::invalid(format!("ufw show added: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(parse_added(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_added(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("ufw "))
        .map(|r| r.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// Does `added` (from [`added`]) have both of `bridge`'s rules?
pub fn has_route_rules(added: &[String], bridge: &str) -> bool {
    route_rules(bridge, false).iter().all(|args| added.contains(&args.join(" ")))
}

/// Lets ufw route `bridge`'s traffic (adding a rule ufw has already is a
/// no-op for it).
pub fn allow(bridge: &str) -> Result<()> {
    for args in route_rules(bridge, false) {
        run(&args)?;
    }
    Ok(())
}

/// Removes what [`allow`] added (a rule ufw doesn't have is skipped).
pub fn forget(bridge: &str) -> Result<()> {
    for args in route_rules(bridge, true) {
        run(&args)?;
    }
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    let out = Command::new(ufw()).args(args).output().with_context(|| format!("run ufw {}", args.join(" ")))?;
    if !out.status.success() {
        return Err(Error::invalid(format!("ufw {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_rules() {
        assert!(says_active("Status: active\n\nTo                         Action      From\n"));
        assert!(!says_active("Status: inactive\n"));
        assert!(!says_active(""));
        assert_eq!(
            route_rules("rustlet0", false),
            [["route", "allow", "in", "on", "rustlet0"], ["route", "allow", "out", "on", "rustlet0"]]
        );
        assert_eq!(route_rules("rustlet0", true)[1], ["route", "delete", "allow", "out", "on", "rustlet0"]);
    }

    #[test]
    fn added_rules_are_read_back() {
        let text = "Added user rules (see 'ufw status' for running firewall):\n\
                    ufw allow 22/tcp\n\
                    ufw route allow in on rustlet0\n\
                    ufw route allow out on rustlet0\n\
                    ufw route allow in on rlb0123456789ab\n";
        let added = parse_added(text);
        assert_eq!(added.len(), 4);
        assert!(has_route_rules(&added, "rustlet0"));
        assert!(!has_route_rules(&added, "rlb0123456789ab"), "only one of its two");
        assert!(!has_route_rules(&added, "rustlet"), "a prefix of a name isn't the name");
        assert!(parse_added("Added user rules (see 'ufw status' for running firewall):\n(None)\n").is_empty());
    }

    #[test]
    fn a_daemon_outside_the_hosts_namespace_leaves_ufw_alone() {
        // As an ordinary user PID 1's namespace can't be read: "no".
        if !nix::unistd::geteuid().is_root() {
            assert!(!in_host_namespace());
        }
    }
}
