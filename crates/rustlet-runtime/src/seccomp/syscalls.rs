//! The x86_64 system call table: name ↔ number.
//!
//! A seccomp filter never sees a syscall's *name*, only the number the
//! program put in `rax` (`seccomp_data.nr`). Profiles speak in names, so the
//! compiler needs the kernel's numbering, and it must be the numbering of
//! the architecture the filter runs on: `openat` is 257 on x86_64, 295 on
//! i386 and 56 on arm64.
//!
//! The table is generated at build time (`build.rs`) from the kernel's own
//! source of truth rather than from `libc::SYS_*`: the libc crate lags new
//! kernels, and names are what profiles contain.
//!
//! ## Provenance of `syscall_64.tbl`
//!
//! - Source: <https://raw.githubusercontent.com/torvalds/linux/v7.0/arch/x86/entry/syscalls/syscall_64.tbl>
//!   (Linux v7.0), sha256 `93e42d351de2002418bf499b9a538f189fd683e8ecd52b4adc8a0bbe59130455`.
//! - License: `GPL-2.0 WITH Linux-syscall-note` (see its first line). It is
//!   a build *input* only: `build.rs` extracts numbers and names, and no
//!   kernel code ends up in the binary.
//! - To update: download the file for a newer tag to the same place, update
//!   the URL and hash above. New syscalls then resolve by name; profiles
//!   that mention them also move the ENOSYS stub up (see `compile`).

include!(concat!(env!("OUT_DIR"), "/syscalls_x86_64.rs"));

/// The x86_64 number of the syscall called `name`, e.g. `openat` → 257.
/// `None` for names that don't exist on x86_64 (`arm_fadvise64_64`,
/// `socketcall`, typos).
pub fn number(name: &str) -> Option<u32> {
    BY_NAME.binary_search_by(|(n, _)| (*n).cmp(name)).ok().map(|i| BY_NAME[i].1)
}

/// The name of x86_64 syscall `nr`, e.g. 257 → `openat`. `None` for
/// numbers no syscall has (the table has gaps, e.g. 335–423).
pub fn name(nr: u32) -> Option<&'static str> {
    BY_NUMBER.binary_search_by_key(&nr, |(n, _)| *n).ok().map(|i| BY_NUMBER[i].1)
}

/// Every syscall in the table as `(number, name)`, by number.
pub fn all() -> impl Iterator<Item = (u32, &'static str)> {
    BY_NUMBER.iter().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_numbers() {
        assert_eq!(number("read"), Some(0));
        assert_eq!(number("openat"), Some(257));
        assert_eq!(number("clone3"), Some(435));
        assert_eq!(name(435), Some("clone3"));
        assert_eq!(name(57), Some("fork"));
        // `rt_sigaction` must have its native number, not the x32 one (512).
        assert_eq!(number("rt_sigaction"), Some(13));
        assert_eq!(name(512), None);
    }

    #[test]
    fn foreign_and_unknown_names() {
        assert_eq!(number("arm_fadvise64_64"), None);
        assert_eq!(number("socketcall"), None);
        assert_eq!(number("opneat"), None);
        assert_eq!(name(400), None, "335..=423 is a gap on x86_64");
    }

    #[test]
    fn table_agrees_with_libc() {
        let pairs = [
            ("read", libc::SYS_read),
            ("mount", libc::SYS_mount),
            ("unshare", libc::SYS_unshare),
            ("setns", libc::SYS_setns),
            ("pidfd_open", libc::SYS_pidfd_open),
            ("mseal", libc::SYS_mseal),
        ];
        for (n, nr) in pairs {
            assert_eq!(number(n), Some(nr as u32), "{n}");
        }
    }

    #[test]
    fn highest_is_the_last_row() {
        assert_eq!(all().last().map(|(nr, _)| nr), Some(HIGHEST));
        const { assert!(HIGHEST >= 462, "the table predates mseal") };
        assert!(all().all(|(nr, n)| number(n) == Some(nr) && name(nr) == Some(n)));
    }
}
