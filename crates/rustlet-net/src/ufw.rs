//! ufw, when it is active.
//!
//! An `accept` in Rustlets' nftables table can't overrule another table's
//! `drop`: every base chain on a hook sees the packet, and any of them may
//! drop it. ufw keeps its rules in iptables (nftables underneath, tables
//! `ip filter` and `ip6 filter`), with its own forward policy: `DROP` on
//! this host (`DEFAULT_FORWARD_POLICY` in `/etc/default/ufw`). With ufw
//! active, containers' traffic would be forwarded by Rustlets' table and
//! dropped by ufw's. So when a bridge is set up and ufw is active, the
//! daemon says so and asks ufw itself to route the bridge's traffic:
//!
//! ```sh
//! ufw route allow in on rustlet0
//! ufw route allow out on rustlet0
//! ```
//!
//! ufw keeps these across reboots; removing the network removes them. ufw
//! is inactive on this host, so normally nothing here runs.

use std::process::Command;

use crate::error::{Context, Error, Result};

/// Is ufw installed and active? (`ufw status` needs root; any failure
/// counts as "not active".)
pub fn active() -> bool {
    Command::new("ufw")
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

/// Lets ufw route `bridge`'s traffic.
pub fn allow(bridge: &str) -> Result<()> {
    for args in route_rules(bridge, false) {
        run(&args)?;
    }
    Ok(())
}

/// Removes what [`allow`] added.
pub fn forget(bridge: &str) -> Result<()> {
    for args in route_rules(bridge, true) {
        run(&args)?;
    }
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    let out = Command::new("ufw").args(args).output().with_context(|| format!("run ufw {}", args.join(" ")))?;
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
}
