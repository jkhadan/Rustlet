//! Container ids and generated names.
//!
//! An id is 32 random bytes in hex, as Docker's. Its first 12 digits (the
//! short id) name the container's hostname and its shim's directory, so the
//! daemon never gives two containers the same short id. A container created
//! without `--name` gets an `adjective_surname` name, as in Docker; the
//! surnames are people whose work this project stands on.

use std::io::Read;

const ADJECTIVES: [&str; 32] = [
    "admiring", "agile", "bold", "brave", "calm", "clever", "curious", "daring", "eager", "elegant", "focused",
    "gentle", "happy", "humble", "jolly", "keen", "kind", "lucid", "merry", "nimble", "patient", "quiet", "quirky",
    "serene", "sharp", "steady", "sturdy", "swift", "tender", "upbeat", "vibrant", "witty",
];

#[rustfmt::skip]
const SURNAMES: [&str; 32] = [
    "allen", "babbage", "backus", "bellard", "cerf", "corbato", "dijkstra", "engelbart", "hamilton", "hopper",
    "kahn", "kay", "knuth", "lamport", "liskov", "lovelace", "mccarthy", "mcilroy", "ossanna", "pike", "ritchie",
    "shannon", "spolsky", "stroustrup", "tanenbaum", "thompson", "torvalds", "turing", "vixie", "wirth", "wozniak",
    "zuse",
];

/// `n` random bytes from the kernel.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    if let Err(e) = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)) {
        // Never happens on Linux; but an id must still be unique-ish.
        tracing::warn!("read /dev/urandom: {e}");
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> ((i % 16) * 8)) as u8 ^ (std::process::id() as u8).wrapping_add(i as u8);
        }
    }
    buf
}

/// A new container id whose short form `taken` says is free.
pub fn new_id(taken: impl Fn(&str) -> bool) -> String {
    loop {
        let id = hex(&random_bytes::<32>());
        if !taken(rustlet_spec::short_id(&id)) {
            return id;
        }
    }
}

/// A generated name that `taken` says is free (with a number on the end
/// once the plain combinations are getting used up).
pub fn new_name(taken: impl Fn(&str) -> bool) -> String {
    for attempt in 0u32.. {
        let [a, b, c, d] = random_bytes::<4>();
        let name = format!("{}_{}", ADJECTIVES[a as usize % ADJECTIVES.len()], SURNAMES[b as usize % SURNAMES.len()]);
        let name = if attempt < 8 { name } else { format!("{name}{}", u16::from_le_bytes([c, d]) % 1000) };
        if !taken(&name) {
            return name;
        }
    }
    unreachable!("the loop only ends by returning")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_64_hex_digits_with_a_free_short_form() {
        let id = new_id(|_| false);
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        let first = rustlet_spec::short_id(&id).to_owned();
        // A short id that is taken is skipped.
        let other = new_id(|s| s == first);
        assert_ne!(rustlet_spec::short_id(&other), first);
    }

    #[test]
    fn names_are_valid_and_free() {
        let n = new_name(|_| false);
        assert!(rustlet_spec::valid_container_name(&n), "{n}");
        assert!(n.contains('_'));
        // Every plain combination taken: a number is added.
        let n = new_name(|name| !name.chars().last().unwrap().is_ascii_digit());
        assert!(n.chars().last().unwrap().is_ascii_digit(), "{n}");
    }
}
