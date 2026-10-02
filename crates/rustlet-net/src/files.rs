//! A container's `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf`.
//!
//! The daemon writes them into the container's directory at each start and
//! bind-mounts them over the image's, as Docker does: the image can't know
//! the container's address, its name servers or its hostname.
//!
//! **Name servers.** On a user-defined network a container asks the embedded
//! server at `127.0.0.11`, which answers its neighbours' names and forwards
//! the rest. Elsewhere it asks the host's name servers itself, from its own
//! network namespace, so a loopback server is no use to it: on this host
//! `/etc/resolv.conf` names only systemd-resolved's stub, `127.0.0.53`.
//! Then the servers the stub forwards to are read from
//! `/run/systemd/resolve/resolv.conf` instead (Docker does the same), and if
//! nothing usable is left, Google's public servers are the fallback
//! (Docker's too). A container without an IPv6 address can't reach an IPv6
//! server, so those are left out of its file (Docker does the same). A
//! container in the host's network namespace shares its loopback and gets a
//! plain copy.
//!
//! The daemon rewrites `hosts` and `resolv.conf` in place (the same inode,
//! which the bind mount shows) when the container is connected to a
//! network or disconnected from one while it runs.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// systemd-resolved's list of the servers its stub forwards to.
pub const RESOLVED_UPSTREAMS: &str = "/run/systemd/resolve/resolv.conf";

/// The fallback name servers.
pub const DEFAULT_DNS: [IpAddr; 2] = [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))];

/// The parts of a `resolv.conf` that matter here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvConf {
    pub nameservers: Vec<IpAddr>,
    pub search: Vec<String>,
    pub options: Vec<String>,
}

impl ResolvConf {
    /// Parses `resolv.conf(5)`: `nameserver`, `search` (or the older
    /// `domain`), `options`; comments and anything else are ignored.
    pub fn parse(text: &str) -> ResolvConf {
        let mut r = ResolvConf::default();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut words = line.split_whitespace();
            match words.next() {
                Some("nameserver") => {
                    if let Some(ip) = words.next().and_then(|w| w.split('%').next()?.parse().ok()) {
                        r.nameservers.push(ip);
                    }
                }
                Some("search" | "domain") => r.search = words.map(str::to_owned).collect(),
                Some("options") => r.options.extend(words.map(str::to_owned)),
                _ => {}
            }
        }
        r
    }

    /// `path` as it is (nothing, if it can't be read).
    pub fn read(path: &Path) -> ResolvConf {
        std::fs::read_to_string(path).map(|t| ResolvConf::parse(&t)).unwrap_or_default()
    }

    /// The host's configuration as containers in namespaces of their own
    /// should see it: `path` (`/etc/resolv.conf`), or, if that names only
    /// loopback servers and systemd-resolved's list exists, that list.
    pub fn host(path: &Path) -> ResolvConf {
        let conf = ResolvConf::read(path);
        let only_loopback = !conf.nameservers.is_empty() && conf.nameservers.iter().all(IpAddr::is_loopback);
        if only_loopback && let Ok(text) = std::fs::read_to_string(RESOLVED_UPSTREAMS) {
            return ResolvConf::parse(&text);
        }
        conf
    }

    /// The servers a container can reach from its own network namespace:
    /// no loopback ones, and no IPv6 ones unless it has IPv6;
    /// [`DEFAULT_DNS`] if that leaves none.
    pub fn reachable_servers(&self, ipv6: bool) -> Vec<IpAddr> {
        let servers: Vec<IpAddr> =
            self.nameservers.iter().copied().filter(|ip| !ip.is_loopback() && (ipv6 || ip.is_ipv4())).collect();
        if servers.is_empty() { DEFAULT_DNS.to_vec() } else { servers }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for ns in &self.nameservers {
            let _ = writeln!(out, "nameserver {ns}");
        }
        if !self.search.is_empty() {
            let _ = writeln!(out, "search {}", self.search.join(" "));
        }
        if !self.options.is_empty() {
            let _ = writeln!(out, "options {}", self.options.join(" "));
        }
        out
    }
}

/// `--dns`, `--dns-search`, `--dns-option`: each replaces the host's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsOptions {
    pub servers: Vec<IpAddr>,
    pub search: Vec<String>,
    pub options: Vec<String>,
}

/// How a container resolves names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolver {
    /// The embedded server, `127.0.0.11` (a user-defined network).
    Embedded,
    /// The host's servers, asked directly (the default network, `none`).
    Direct,
    /// The host's file as it is (the host's network namespace).
    Host,
}

/// The container's `resolv.conf`, from the host's at `path`: as it is for a
/// container in the host's namespace (its loopback is the host's: a stub
/// at `127.0.0.53` answers there), otherwise as [`ResolvConf::host`] has
/// it. `ipv6`: the container has an IPv6 address (servers it couldn't
/// reach otherwise are left out).
pub fn container_resolv_conf(path: &Path, dns: &DnsOptions, resolver: Resolver, ipv6: bool) -> String {
    let host = match resolver {
        // A copy, word for word: what this parser would drop (a link-local
        // server's `%interface`, `sortlist`) works there as on the host.
        Resolver::Host if *dns == DnsOptions::default() => return std::fs::read_to_string(path).unwrap_or_default(),
        Resolver::Host => ResolvConf::read(path),
        Resolver::Embedded | Resolver::Direct => ResolvConf::host(path),
    };
    resolv_conf(&host, dns, resolver, ipv6)
}

/// The container's `resolv.conf`, from the host's configuration as
/// [`container_resolv_conf`] picks it.
pub fn resolv_conf(host: &ResolvConf, dns: &DnsOptions, resolver: Resolver, ipv6: bool) -> String {
    let pick = |given: &[String], host: &[String]| if given.is_empty() { host.to_vec() } else { given.to_vec() };
    let conf = match resolver {
        Resolver::Embedded => {
            let mut options = pick(&dns.options, &host.options);
            // Every name is tried as given first, so a neighbour's bare name
            // is answered at once rather than after each search domain.
            if !options.iter().any(|o| o.starts_with("ndots:")) {
                options.push("ndots:0".into());
            }
            ResolvConf {
                nameservers: vec![IpAddr::V4(crate::firewall::DNS_ADDR)],
                search: pick(&dns.search, &host.search),
                options,
            }
        }
        Resolver::Direct => ResolvConf {
            nameservers: if dns.servers.is_empty() { host.reachable_servers(ipv6) } else { dns.servers.clone() },
            search: pick(&dns.search, &host.search),
            options: pick(&dns.options, &host.options),
        },
        Resolver::Host => ResolvConf {
            nameservers: if dns.servers.is_empty() { host.nameservers.clone() } else { dns.servers.clone() },
            search: pick(&dns.search, &host.search),
            options: pick(&dns.options, &host.options),
        },
    };
    format!("# Generated by rustletd: this container's resolver.\n{}", conf.render())
}

/// The lines every `/etc/hosts` starts with (Docker's).
const LOCALHOST: &str = "127.0.0.1\tlocalhost
::1\tlocalhost ip6-localhost ip6-loopback
fe00::0\tip6-localnet
ff00::0\tip6-mcastprefix
ff02::1\tip6-allnodes
ff02::2\tip6-allrouters
";

/// The container's `/etc/hosts`: localhost, the `--add-host` entries
/// (`(name, address)`), then a line with `names` for each of its own
/// addresses (on every network it is on, IPv4 then IPv6, its first network
/// first, which is what a lookup of its own name gets).
pub fn hosts(own: &[IpAddr], names: &[String], extra: &[(String, String)]) -> String {
    let mut out = String::from(LOCALHOST);
    for (name, ip) in extra {
        let _ = writeln!(out, "{ip}\t{name}");
    }
    if !names.is_empty() {
        for ip in own {
            let _ = writeln!(out, "{ip}\t{}", names.join(" "));
        }
    }
    out
}

/// `/etc/hosts` for a container in the host's network namespace: the host's
/// own file, then the `--add-host` entries.
pub fn host_network_hosts(host_hosts: &str, extra: &[(String, String)]) -> String {
    let mut out = host_hosts.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for (name, ip) in extra {
        let _ = writeln!(out, "{ip}\t{name}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STUB: &str = "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch lastgateway.lan\n";

    #[test]
    fn parses_resolv_conf() {
        let r = ResolvConf::parse(STUB);
        assert_eq!(r.nameservers, ["127.0.0.53".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            (r.search.as_slice(), r.options.as_slice()),
            (&["lastgateway.lan".to_owned()][..], &["edns0".to_owned(), "trust-ad".to_owned()][..])
        );
        let r = ResolvConf::parse(
            "nameserver 1.1.1.1 # cloudflare\nnameserver fe80::1%eth0\ndomain example.org\nnameserver junk\n",
        );
        assert_eq!(r.nameservers.len(), 2);
        assert_eq!(r.search, ["example.org"]);
        assert_eq!(ResolvConf::parse(STUB).reachable_servers(true), DEFAULT_DNS, "only loopback: the fallback");
        let both = ResolvConf::parse("nameserver fd00::53\nnameserver 192.0.2.53\n");
        assert_eq!(both.reachable_servers(true).len(), 2);
        assert_eq!(both.reachable_servers(false), ["192.0.2.53".parse::<IpAddr>().unwrap()], "no IPv6 without IPv6");
        let only6 = ResolvConf::parse("nameserver fd00::53\n");
        assert_eq!(only6.reachable_servers(false), DEFAULT_DNS);
    }

    #[test]
    fn the_host_s_stub_is_skipped_for_resolveds_list() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("resolv.conf");
        std::fs::write(&plain, "nameserver 192.168.50.1\nsearch lan\n").unwrap();
        assert_eq!(ResolvConf::host(&plain).nameservers, ["192.168.50.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ResolvConf::host(&dir.path().join("missing")), ResolvConf::default());
    }

    #[test]
    fn container_resolv_confs() {
        let host = ResolvConf::parse("nameserver 192.168.50.1\nsearch lastgateway.lan\noptions edns0\n");
        let none = DnsOptions::default();
        assert_eq!(
            resolv_conf(&host, &none, Resolver::Embedded, false),
            "# Generated by rustletd: this container's resolver.\nnameserver 127.0.0.11\nsearch lastgateway.lan\noptions edns0 ndots:0\n"
        );
        assert_eq!(
            resolv_conf(&host, &none, Resolver::Direct, false),
            "# Generated by rustletd: this container's resolver.\nnameserver 192.168.50.1\nsearch lastgateway.lan\noptions edns0\n"
        );
        let given = DnsOptions {
            servers: vec!["9.9.9.9".parse().unwrap()],
            search: vec!["corp".into()],
            options: vec!["ndots:2".into()],
        };
        let direct = resolv_conf(&host, &given, Resolver::Direct, false);
        assert!(direct.contains("nameserver 9.9.9.9\nsearch corp\noptions ndots:2\n") && !direct.contains("192.168"));
        let embedded = resolv_conf(&host, &given, Resolver::Embedded, false);
        assert!(embedded.contains("nameserver 127.0.0.11\nsearch corp\noptions ndots:2\n"), "{embedded}");
        let stub = ResolvConf::parse(STUB);
        assert!(resolv_conf(&stub, &none, Resolver::Host, false).contains("nameserver 127.0.0.53"));
        assert!(
            resolv_conf(&stub, &none, Resolver::Direct, false).contains("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
        );
    }

    #[test]
    fn the_hosts_namespace_keeps_the_stub() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("resolv.conf");
        std::fs::write(&stub, STUB).unwrap();
        let none = DnsOptions::default();
        let host = container_resolv_conf(&stub, &none, Resolver::Host, false);
        assert_eq!(host, STUB, "a plain copy");
        // In a namespace of its own, never the stub: resolved's list where
        // there is one, else the fallback.
        let direct = container_resolv_conf(&stub, &none, Resolver::Direct, false);
        assert!(!direct.contains("127.0.0.53"), "{direct}");
    }

    #[test]
    fn the_hosts_namespace_gets_the_file_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        let text = "nameserver fe80::1%eth0\nsortlist 130.155.160.0/255.255.240.0\noptions rotate\n";
        std::fs::write(&path, text).unwrap();
        assert_eq!(container_resolv_conf(&path, &DnsOptions::default(), Resolver::Host, true), text);
        // With --dns, a file of its own.
        let dns = DnsOptions { servers: vec![Ipv4Addr::new(9, 9, 9, 9).into()], ..DnsOptions::default() };
        let given = container_resolv_conf(&path, &dns, Resolver::Host, true);
        assert!(given.contains("nameserver 9.9.9.9\noptions rotate\n") && !given.contains("fe80"), "{given}");
    }

    #[test]
    fn hosts_files() {
        let names = ["abc123def456".to_owned()];
        let extra = [("db".to_owned(), "10.0.0.5".to_owned())];
        let h = hosts(&[Ipv4Addr::new(10, 89, 0, 2).into()], &names, &extra);
        assert!(h.starts_with("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"));
        assert!(h.ends_with("10.0.0.5\tdb\n10.89.0.2\tabc123def456\n"), "{h}");
        assert!(!hosts(&[], &names, &[]).contains("10.89"));
        // Several networks, IPv6: a line each, in order.
        let own: [IpAddr; 3] =
            [Ipv4Addr::new(10, 89, 1, 2).into(), "fd00:89:0:1::2".parse().unwrap(), Ipv4Addr::new(10, 89, 2, 2).into()];
        let h = hosts(&own, &names, &[]);
        assert!(h.ends_with("10.89.1.2\tabc123def456\nfd00:89:0:1::2\tabc123def456\n10.89.2.2\tabc123def456\n"), "{h}");
        assert_eq!(host_network_hosts("127.0.0.1 localhost", &extra), "127.0.0.1 localhost\n10.0.0.5\tdb\n");
    }
}
