//! Capabilities: which of root's privileges the container keeps.
//!
//! Root's power is split into ~41 capabilities (`CAP_SYS_ADMIN` for mounts,
//! `CAP_NET_ADMIN` for network config, `CAP_SYS_MODULE` for kernel modules,
//! …). A container's root gets only a few of them, which is most of what
//! separates "root in a container" from root on the host.
//!
//! ## Five sets, and what `execve` does with them
//!
//! `process.capabilities` in `config.json` lists five sets. What the program
//! ends up with is decided by the kernel at `execve`, from these rules
//! (`capabilities(7)`, "Transformation of capabilities during execve()"):
//!
//! ```text
//!   P'(ambient)     = P(ambient)                      (cleared for setuid/file-cap binaries)
//!   P'(permitted)   = (P(inheritable) & F(inheritable)) | (F(permitted) & P(bounding)) | P'(ambient)
//!   P'(effective)   = F(effective) ? P'(permitted) : P'(ambient)
//! ```
//!
//! where `F` are the file capabilities of the binary. The special case that
//! matters most: **for root (uid 0), every binary counts as having all file
//! capabilities**, so root's permitted and effective sets after `execve`
//! are its *bounding* set (plus inheritable). For a non-root user without
//! file capabilities, only the *ambient* set survives.
//!
//! `no_new_privs` adds one rule: `execve` may never *raise* capabilities,
//! so the new permitted set is also cut down to the old one. With NNP on
//! (the default spec), root keeps exactly the spec's `permitted`; with it
//! off, root regains its whole bounding set at the first `execve`, whatever
//! `permitted` said. (runc behaves the same; it's the kernel.)
//!
//! So for a root container the bounding set is the ceiling that counts, and
//! the inheritable set should stay empty: a non-empty one lets a binary with
//! inheritable *file* capabilities gain them (CVE-2022-24769, fixed in
//! Docker and runc by defaulting inheritable to empty).
//!
//! ## The order in container init
//!
//! 1. [`CapsPlan::drop_bounding`] while still fully privileged (dropping from
//!    the bounding set needs `CAP_SETPCAP`);
//! 2. `PR_SET_KEEPCAPS`, so the permitted set survives `setresuid` away from 0
//!    (by default the kernel clears it: the classic "drop root" behaviour);
//! 3. `setgroups`/`setresgid`/`setresuid` (in `process::switch_user`);
//! 4. [`CapsPlan::apply`]: `capset` effective/permitted/inheritable, then raise
//!    the ambient ones (each must already be permitted *and* inheritable).

use oci_spec::runtime::{Capabilities, LinuxCapabilities};
use rustlet_sys::Errno;
use rustlet_sys::caps::{self, Cap, CapSet, CapState};

use crate::error::{Context, Error, Result};

/// The default set: Podman's (Docker's without `MKNOD`, `NET_RAW` and
/// `AUDIT_WRITE`). Enough for package managers, `su` and servers on low
/// ports; nothing that reaches the kernel's configuration.
pub const DEFAULT: [Cap; 11] = [
    Cap::CHOWN,
    Cap::DAC_OVERRIDE,
    Cap::FOWNER,
    Cap::FSETID,
    Cap::KILL,
    Cap::NET_BIND_SERVICE,
    Cap::SETFCAP,
    Cap::SETGID,
    Cap::SETPCAP,
    Cap::SETUID,
    Cap::SYS_CHROOT,
];

/// [`DEFAULT`] as a set.
pub fn default_set() -> CapSet {
    DEFAULT.into_iter().collect()
}

/// A validated `process.capabilities`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsPlan {
    /// The highest capability the kernel knows (`cap_last_cap`), read on
    /// the host at plan time: inside the container, `/proc` isn't ours to
    /// trust any more.
    pub last: Cap,
    pub bounding: CapSet,
    pub effective: CapSet,
    pub permitted: CapSet,
    pub inheritable: CapSet,
    pub ambient: CapSet,
}

impl CapsPlan {
    /// Checks the spec's sets against each other and against what the kernel
    /// will accept, so a bad combination fails `create` instead of init.
    ///
    /// Capabilities newer than the running kernel (above `last`) are left
    /// out with a warning, as runc does: a spec written for a newer kernel
    /// still runs.
    pub fn from_spec(c: &LinuxCapabilities, last: Cap) -> Result<CapsPlan> {
        let set = |s: &Option<Capabilities>| -> Result<CapSet> {
            let mut out = CapSet::EMPTY;
            for cap in s.iter().flatten() {
                let cap = to_cap(cap)?;
                if cap > last {
                    tracing::warn!(%cap, "this kernel doesn't know the capability; leaving it out");
                } else {
                    out.insert(cap);
                }
            }
            Ok(out)
        };
        let plan = CapsPlan {
            last,
            bounding: set(c.bounding())?,
            effective: set(c.effective())?,
            permitted: set(c.permitted())?,
            inheritable: set(c.inheritable())?,
            ambient: set(c.ambient())?,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        let subset = |a: CapSet, b: CapSet| a.0 & !b.0 == 0;
        let names = |s: CapSet| s.names().join(", ");
        if !subset(self.effective, self.permitted) {
            return Err(Error::invalid(format!(
                "process.capabilities: effective has {} which are not in permitted (the kernel requires effective ⊆ permitted)",
                names(CapSet(self.effective.0 & !self.permitted.0))
            )));
        }
        if !subset(self.inheritable, self.bounding) {
            return Err(Error::invalid(format!(
                "process.capabilities: inheritable has {} which are not in bounding",
                names(CapSet(self.inheritable.0 & !self.bounding.0))
            )));
        }
        let pi = CapSet(self.permitted.0 & self.inheritable.0);
        if !subset(self.ambient, pi) {
            return Err(Error::invalid(format!(
                "process.capabilities: ambient has {} which are not in both permitted and inheritable",
                names(CapSet(self.ambient.0 & !pi.0))
            )));
        }
        Ok(())
    }

    /// Step 1: removes everything not in the bounding set, for good (no
    /// later `execve`, setuid binary or file capability can bring it back).
    ///
    /// All 64 bits, not just up to `last`: should `last` ever be wrong (an
    /// unreadable `cap_last_cap` falls back to 40), a newer kernel's extra
    /// capabilities must not survive. The kernel says EINVAL for numbers it
    /// doesn't know, which `bounding_drop` treats as "already gone".
    pub(crate) fn drop_bounding(&self) -> Result<()> {
        for i in 0..64 {
            let cap = Cap(i);
            if !self.bounding.contains(cap) {
                caps::bounding_drop(cap).with_context(|| format!("drop {cap} from the bounding set"))?;
            }
        }
        Ok(())
    }

    /// Step 4 (after the uid/gid switch): sets effective, permitted and
    /// inheritable, then the ambient set.
    pub(crate) fn apply(&self) -> Result<()> {
        caps::capset(&CapState { effective: self.effective, permitted: self.permitted, inheritable: self.inheritable })
            .context("capset")?;
        // KEEPCAPS only mattered across setresuid; don't leave it for the
        // program (it would keep permitted caps across its own setuid).
        rustlet_sys::prctl::set_keepcaps(false).context("PR_SET_KEEPCAPS=0")?;
        caps::ambient_clear_all().or_else(ignore_enosys).context("clear the ambient set")?;
        for cap in self.ambient.iter() {
            caps::ambient_raise(cap).with_context(|| format!("raise ambient {cap}"))?;
        }
        Ok(())
    }
}

/// Kernels without ambient capabilities (< 4.3) return EINVAL/ENOSYS for
/// the clear; nothing to clear there.
fn ignore_enosys(e: Errno) -> rustlet_sys::Result<()> {
    if matches!(e, Errno::EINVAL | Errno::ENOSYS) { Ok(()) } else { Err(e) }
}

/// `oci_spec`'s capability enum serializes to the kernel's name
/// (`CAP_SYS_ADMIN`), which is what [`Cap`] parses.
fn to_cap(c: &oci_spec::runtime::Capability) -> Result<Cap> {
    let name = serde_json::to_value(c).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    name.parse::<Cap>().map_err(|e| Error::invalid(format!("process.capabilities: {e}")))
}

/// Turns a [`CapSet`] into `oci_spec` form (for the default spec and
/// `exec --cap`).
pub fn to_spec(set: CapSet) -> Capabilities {
    set.iter()
        .filter_map(|c| serde_json::from_value(serde_json::Value::String(c.name())).ok())
        .collect::<Capabilities>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{Capability, LinuxCapabilitiesBuilder};

    fn caps(list: &[Capability]) -> Capabilities {
        list.iter().copied().collect()
    }

    /// (The builder fills unset sets with runc's defaults, so set all five.)
    fn build(
        b: &[Capability],
        e: &[Capability],
        p: &[Capability],
        i: &[Capability],
        a: &[Capability],
    ) -> LinuxCapabilities {
        LinuxCapabilitiesBuilder::default()
            .bounding(caps(b))
            .effective(caps(e))
            .permitted(caps(p))
            .inheritable(caps(i))
            .ambient(caps(a))
            .build()
            .unwrap()
    }

    #[test]
    fn default_mask_is_podmans() {
        // What `grep CapBnd /proc/self/status` shows in a default container.
        assert_eq!(default_set().0, 0x8004_05fb);
        assert_eq!(to_spec(default_set()).len(), 11);
    }

    #[test]
    fn names_round_trip_through_oci_spec() {
        use Capability::*;
        let c = build(&[SysAdmin, NetBindService], &[NetBindService], &[NetBindService], &[], &[]);
        let p = CapsPlan::from_spec(&c, Cap(40)).unwrap();
        assert!(p.bounding.contains(Cap::SYS_ADMIN) && p.bounding.contains(Cap::NET_BIND_SERVICE));
        assert_eq!(p.effective, [Cap::NET_BIND_SERVICE].into_iter().collect());
    }

    #[test]
    fn kernel_rules_are_checked_up_front() {
        use Capability::*;
        let e_not_p = build(&[Kill], &[Kill], &[], &[], &[]);
        assert!(CapsPlan::from_spec(&e_not_p, Cap(40)).unwrap_err().to_string().contains("effective"));
        let a_not_i = build(&[Kill], &[], &[Kill], &[], &[Kill]);
        assert!(CapsPlan::from_spec(&a_not_i, Cap(40)).unwrap_err().to_string().contains("ambient"));
        let i_not_b = build(&[], &[], &[], &[Kill], &[]);
        assert!(CapsPlan::from_spec(&i_not_b, Cap(40)).unwrap_err().to_string().contains("inheritable"));
        let mknod = build(&[Mknod], &[], &[], &[], &[]);
        assert!(CapsPlan::from_spec(&mknod, Cap(40)).unwrap().bounding.contains(Cap::MKNOD));
    }

    #[test]
    fn caps_newer_than_the_kernel_are_left_out() {
        let c = build(&[Capability::CheckpointRestore, Capability::Kill], &[], &[], &[], &[]);
        // Pretend the kernel stops at CAP_AUDIT_READ (37).
        let p = CapsPlan::from_spec(&c, Cap(37)).unwrap();
        assert_eq!(p.bounding, [Cap::KILL].into_iter().collect());
    }
}
