//! `sd_notify`: telling systemd the daemon is ready (`Type=notify`).
//!
//! systemd passes a datagram socket in `$NOTIFY_SOCKET`; `READY=1` sent to
//! it moves the unit from "activating" to "active", so `systemctl start
//! rustletd` returns only once the API socket accepts connections. A name
//! starting with `@` is an abstract socket (no file; std spells it
//! `SocketAddr::from_abstract_name`).

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Sends `state` (`READY=1`, `STOPPING=1`, `STATUS=…`) if systemd asked
/// for notifications; otherwise does nothing.
pub fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let path = path.to_string_lossy().into_owned();
    let result = (|| -> std::io::Result<()> {
        let sock = UnixDatagram::unbound()?;
        let addr = match path.strip_prefix('@') {
            Some(name) => SocketAddr::from_abstract_name(name.as_bytes())?,
            None => SocketAddr::from_pathname(&path)?,
        };
        sock.send_to_addr(state.as_bytes(), &addr)?;
        Ok(())
    })();
    if let Err(e) = result {
        tracing::warn!("sd_notify {state:?} to {path}: {e}");
    }
}
