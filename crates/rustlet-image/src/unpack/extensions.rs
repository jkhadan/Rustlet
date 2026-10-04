//! The headers before an archive entry that change it: PAX extended
//! headers (`x`) and GNU long names (`L`, `K`), read here rather than by the
//! tar crate.
//!
//! The crate does read them, but it splits a PAX header's records at every
//! newline, while a record is `<length> <key>=<value>\n` and its value may
//! hold newlines of its own: an attribute's binary value does whenever one
//! of its bytes is 0x0a (an ACL entry for uid or gid 10, a file capability
//! set with bits 1 and 3). The crate drops such a record, and since its own
//! lookup of `uid`, `gid` and `size` stops at the first bad record, those
//! too when they come after it, as they do in what Go writes (it sorts the
//! keys, and `SCHILY.xattr.*` comes before the lowercase ones). So archives
//! are read in the crate's raw mode, where these headers are entries of
//! their own, and records are parsed by their length, as Go's `archive/tar`
//! parses them.
//!
//! Like Go, a header over 1 MiB is refused: the reader would otherwise hold
//! whatever size one claims. What raw mode gives up is the crate's
//! reassembly of GNU sparse files, which no image builder writes (Go's
//! `archive/tar` can't): a sparse entry is refused rather than written as
//! its packed data, and so is a `size` record that disagrees with the
//! header's (a file over 8 GiB, where Go leaves the header's field 0).

use std::io::{self, Read};

use tar::EntryType;

/// A PAX record: its key and value.
pub(super) type Record = (Vec<u8>, Vec<u8>);

/// The largest extension header read, as Go's `maxSpecialFileSize`.
pub(super) const MAX_HEADER: u64 = 1 << 20;

/// What the extension headers before an entry said about it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Extensions {
    /// A GNU long name (`L`).
    gnu_path: Option<Vec<u8>>,
    /// A GNU long link name (`K`).
    gnu_linkpath: Option<Vec<u8>>,
    /// Every PAX record, in order (a later one for the same key wins).
    records: Vec<Record>,
}

impl Extensions {
    pub(super) fn is_empty(&self) -> bool {
        *self == Extensions::default()
    }

    /// The last value of the PAX record `key`.
    pub(super) fn get(&self, key: &str) -> Option<&[u8]> {
        self.records.iter().rev().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v.as_slice())
    }

    /// Every PAX record, in order.
    pub(super) fn records(&self) -> &[Record] {
        &self.records
    }

    /// The entry's path, if a header gave one: a GNU long name, else the
    /// PAX `path` (Go's order).
    pub(super) fn path(&self) -> Option<&[u8]> {
        self.gnu_path.as_deref().or_else(|| self.get("path"))
    }

    /// The entry's link target, likewise.
    pub(super) fn linkpath(&self) -> Option<&[u8]> {
        self.gnu_linkpath.as_deref().or_else(|| self.get("linkpath"))
    }

    /// Takes in `entry` if it is an extension header (`x`, `L`, `K`);
    /// false for any other entry, which is the one these headers describe.
    pub(super) fn absorb<R: Read>(&mut self, entry: &mut tar::Entry<'_, R>) -> io::Result<bool> {
        match entry.header().entry_type() {
            EntryType::XHeader => {
                let data = read_header(entry)?;
                self.records.extend(parse_records(&data).map_err(invalid)?);
                Ok(true)
            }
            EntryType::GNULongName => {
                self.gnu_path = Some(without_nuls(read_header(entry)?));
                Ok(true)
            }
            EntryType::GNULongLink => {
                self.gnu_linkpath = Some(without_nuls(read_header(entry)?));
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// An extension header's data, refused over [`MAX_HEADER`].
fn read_header<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<Vec<u8>> {
    let size = entry.header().entry_size()?;
    if size > MAX_HEADER {
        return Err(invalid(format!("an extension header of {size} bytes (at most {MAX_HEADER})")));
    }
    let mut data = Vec::with_capacity(size as usize);
    entry.take(MAX_HEADER + 1).read_to_end(&mut data)?;
    Ok(data)
}

/// A GNU long name ends with a NUL (or several).
fn without_nuls(mut name: Vec<u8>) -> Vec<u8> {
    while name.last() == Some(&0) {
        name.pop();
    }
    name
}

/// PAX records, each `<length> <key>=<value>\n` where the length counts the
/// whole record, newline included: the value is whatever lies between `=`
/// and that newline, newlines and all.
pub(super) fn parse_records(mut data: &[u8]) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let space = data.iter().position(|&b| b == b' ').ok_or("a PAX record without a length")?;
        let len: usize = std::str::from_utf8(&data[..space])
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or("a PAX record whose length isn't a number")?;
        if len <= space + 1 || len > data.len() || data[len - 1] != b'\n' {
            return Err(format!("a PAX record of length {len} doesn't fit its header"));
        }
        let record = &data[space + 1..len - 1];
        let eq = record.iter().position(|&b| b == b'=').ok_or("a PAX record without `=`")?;
        if eq == 0 {
            return Err("a PAX record with an empty key".into());
        }
        out.push((record[..eq].to_vec(), record[eq + 1..].to_vec()));
        data = &data[len..];
    }
    Ok(out)
}

fn invalid(e: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(key: &str, value: &[u8]) -> Vec<u8> {
        // The length counts its own digits too.
        let body = [key.as_bytes(), b"=", value, b"\n"].concat();
        let mut len = body.len() + 2;
        while len.to_string().len() + 1 + body.len() != len {
            len = len.to_string().len() + 1 + body.len();
        }
        [len.to_string().as_bytes(), b" ", &body].concat()
    }

    #[test]
    fn records_are_parsed_by_length_newlines_and_all() {
        let data = [record("SCHILY.xattr.user.x", b"a\nb\n"), record("uid", b"4242"), record("path", b"p")].concat();
        let r = parse_records(&data).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], (b"SCHILY.xattr.user.x".to_vec(), b"a\nb\n".to_vec()));
        assert_eq!(r[1].1, b"4242");
        assert_eq!(parse_records(b"").unwrap(), vec![]);
        for bad in [&b"x"[..], b"5 a=b\n", b"6 a=b", b"6 ab\n\n", b"5 =b\n", b"-6 a=b\n", b"0006a=b\n"] {
            assert!(parse_records(bad).is_err(), "{bad:?}");
        }
    }
}
