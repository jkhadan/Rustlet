//! Parser for `/proc/self/mountinfo`.
//!
//! Each line describes one mount:
//!
//! ```text
//! 36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//! (1)(2)(3)   (4)   (5)         (6)       (7)      (8) (9)  (10)      (11)
//! ```
//!
//! (1) mount ID, (2) parent ID, (3) major:minor, (4) root within the fs,
//! (5) mount point, (6) per-mount options, (7) optional fields such as
//! `shared:N` / `master:N` (propagation peer groups), (8) separator,
//! (9) fs type, (10) source, (11) super-block options. Paths escape space,
//! tab, newline and backslash as `\040`-style octal.

use std::path::{Path, PathBuf};

/// One parsed mountinfo line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub id: u64,
    pub parent: u64,
    pub major: u32,
    pub minor: u32,
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub options: String,
    /// Propagation fields: `shared:N`, `master:N`, `propagate_from:N`, `unbindable`.
    pub optional: Vec<String>,
    pub fs_type: String,
    pub source: String,
    pub super_options: String,
}

impl MountInfo {
    /// Is this mount a member of a shared peer group (propagates events)?
    pub fn is_shared(&self) -> bool {
        self.optional.iter().any(|o| o.starts_with("shared:"))
    }
    pub fn is_readonly(&self) -> bool {
        self.options.split(',').any(|o| o == "ro")
    }
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses one line; `None` if it is malformed.
pub fn parse_line(line: &str) -> Option<MountInfo> {
    let (left, right) = line.split_once(" - ")?;
    let mut l = left.split(' ');
    let id = l.next()?.parse().ok()?;
    let parent = l.next()?.parse().ok()?;
    let (maj, min) = l.next()?.split_once(':')?;
    let root = PathBuf::from(unescape(l.next()?));
    let mount_point = PathBuf::from(unescape(l.next()?));
    let options = l.next()?.to_owned();
    let optional = l.filter(|s| !s.is_empty()).map(str::to_owned).collect();
    let mut r = right.split(' ');
    let fs_type = r.next()?.to_owned();
    let source = unescape(r.next().unwrap_or(""));
    let super_options = r.next().unwrap_or("").to_owned();
    Some(MountInfo {
        id,
        parent,
        major: maj.parse().ok()?,
        minor: min.parse().ok()?,
        root,
        mount_point,
        options,
        optional,
        fs_type,
        source,
        super_options,
    })
}

/// Parses a whole mountinfo file.
pub fn parse(text: &str) -> Vec<MountInfo> {
    text.lines().filter_map(parse_line).collect()
}

/// Reads and parses `/proc/self/mountinfo`.
pub fn read_self() -> std::io::Result<Vec<MountInfo>> {
    Ok(parse(&std::fs::read_to_string("/proc/self/mountinfo")?))
}

/// Mounts whose mount point is `path` or lies below it, deepest first —
/// the order in which they must be unmounted.
pub fn mounts_under(mounts: &[MountInfo], path: &Path) -> Vec<MountInfo> {
    let mut v: Vec<MountInfo> = mounts.iter().filter(|m| m.mount_point.starts_with(path)).cloned().collect();
    v.sort_by_key(|m| std::cmp::Reverse(m.mount_point.components().count()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
22 1 8:3 / / rw,relatime shared:1 - ext4 /dev/sda3 rw,errors=remount-ro
36 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs udev rw,size=4000k
99 22 0:50 / /mnt/with\\040space rw master:7 - tmpfs tmpfs rw
100 22 0:51 / /mnt/priv ro - tmpfs none rw
";

    #[test]
    fn parses_fields_and_escapes() {
        let m = parse(SAMPLE);
        assert_eq!(m.len(), 4);
        assert!(m[0].is_shared());
        assert_eq!(m[0].fs_type, "ext4");
        assert_eq!(m[2].mount_point, PathBuf::from("/mnt/with space"));
        assert!(!m[2].is_shared());
        assert!(m[3].optional.is_empty());
        assert!(m[3].is_readonly());
    }

    #[test]
    fn deepest_first() {
        let m = parse(SAMPLE);
        let u = mounts_under(&m, Path::new("/"));
        assert_eq!(u.last().unwrap().mount_point, PathBuf::from("/"));
    }
}
