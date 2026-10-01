//! The image config: the JSON document that says how to run an image.
//!
//! ```json
//! { "architecture": "amd64", "os": "linux",
//!   "config": { "Env": ["PATH=…"], "Cmd": ["/bin/sh"], "User": "nginx", … },
//!   "rootfs": { "type": "layers", "diff_ids": ["sha256:…", …] },
//!   "history": [ … ] }
//! ```
//!
//! The capitalized keys under `config` are Docker's heritage; OCI kept them.
//! `rootfs.diff_ids` lists the *uncompressed* digest of every layer, in order
//! (see `digest`). Docker adds a few keys OCI never adopted, `Healthcheck`
//! the useful one; [`ImageConfig`] parses it alongside `oci-spec`'s type.

use oci_spec::image::{Config, ImageConfiguration};
use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::error::{Error, Result};

/// Configs are small JSON; refuse to buffer anything larger than this.
pub const MAX_CONFIG_BYTES: u64 = 8 << 20;

/// A parsed image config.
#[derive(Debug, Clone)]
pub struct ImageConfig {
    /// Everything OCI defines.
    pub oci: ImageConfiguration,
    /// `rootfs.diff_ids`, parsed.
    pub diff_ids: Vec<Digest>,
    /// Docker's `config.Healthcheck` (used from Phase 4).
    pub healthcheck: Option<Healthcheck>,
}

/// Docker's `HEALTHCHECK`. Durations are nanoseconds, as Go writes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Healthcheck {
    /// `["NONE"]`, `["CMD", args…]` or `["CMD-SHELL", command]`.
    #[serde(default)]
    pub test: Vec<String>,
    #[serde(default)]
    pub interval: Option<i64>,
    #[serde(default)]
    pub timeout: Option<i64>,
    #[serde(default)]
    pub start_period: Option<i64>,
    #[serde(default)]
    pub start_interval: Option<i64>,
    #[serde(default)]
    pub retries: Option<i64>,
}

impl ImageConfig {
    /// Parses config JSON (OCI or Docker; they share the layout).
    pub fn parse(bytes: &[u8]) -> Result<ImageConfig> {
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(Error::invalid(format!(
                "image config of {} bytes is larger than {MAX_CONFIG_BYTES}",
                bytes.len()
            )));
        }
        let oci: ImageConfiguration =
            serde_json::from_slice(bytes).map_err(|e| Error::invalid(format!("image config: {e}")))?;
        if oci.rootfs().typ() != "layers" {
            return Err(Error::invalid(format!(
                "image config: rootfs.type {:?}, expected \"layers\"",
                oci.rootfs().typ()
            )));
        }
        let diff_ids = oci
            .rootfs()
            .diff_ids()
            .iter()
            .map(|d| Digest::parse(d).map_err(|e| Error::invalid(format!("image config diff_id: {e}"))))
            .collect::<Result<Vec<_>>>()?;

        #[derive(Deserialize)]
        struct Docker {
            config: Option<DockerConfig>,
        }
        #[derive(Deserialize)]
        struct DockerConfig {
            #[serde(rename = "Healthcheck")]
            healthcheck: Option<Healthcheck>,
        }
        let docker: Docker = serde_json::from_slice(bytes).map_err(|e| Error::invalid(format!("image config: {e}")))?;
        Ok(ImageConfig { oci, diff_ids, healthcheck: docker.config.and_then(|c| c.healthcheck) })
    }

    /// The `config` section (`Env`, `Cmd`, `User`, …), if the image has one.
    pub fn config(&self) -> Option<&Config> {
        self.oci.config().as_ref()
    }

    /// `os/architecture[/variant]`.
    pub fn platform(&self) -> String {
        match self.oci.variant() {
            Some(v) => format!("{}/{}/{v}", self.oci.os(), self.oci.architecture()),
            None => format!("{}/{}", self.oci.os(), self.oci.architecture()),
        }
    }

    /// Refuses images this host can't run: other OSes and architectures.
    pub fn check_runnable(&self) -> Result<()> {
        let (os, arch) = (self.oci.os().to_string(), self.oci.architecture().to_string());
        if os != "linux" || arch != "amd64" {
            return Err(Error::unsupported(format!("image is for {}; this host runs linux/amd64", self.platform())));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parses_a_docker_config_with_a_healthcheck() {
        let json = format!(
            r#"{{"architecture":"amd64","os":"linux",
                "config":{{"Env":["PATH=/usr/bin"],"Cmd":["nginx","-g","daemon off;"],"User":"101",
                          "ExposedPorts":{{"80/tcp":{{}}}},"StopSignal":"SIGQUIT",
                          "Healthcheck":{{"Test":["CMD-SHELL","curl -f http://localhost/"],"Interval":30000000000,"Retries":3}}}},
                "rootfs":{{"type":"layers","diff_ids":["{D1}"]}}}}"#
        );
        let c = ImageConfig::parse(json.as_bytes()).unwrap();
        assert_eq!(c.diff_ids, vec![Digest::parse(D1).unwrap()]);
        assert_eq!(c.config().unwrap().user().as_deref(), Some("101"));
        assert_eq!(c.config().unwrap().stop_signal().as_deref(), Some("SIGQUIT"));
        let h = c.healthcheck.as_ref().unwrap();
        assert_eq!(h.test, ["CMD-SHELL", "curl -f http://localhost/"]);
        assert_eq!((h.interval, h.retries, h.timeout), (Some(30_000_000_000), Some(3), None));
        assert_eq!(c.platform(), "linux/amd64");
        c.check_runnable().unwrap();
    }

    #[test]
    fn refuses_bad_configs_and_other_platforms() {
        let bad_diff = r#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:x"]}}"#;
        assert!(ImageConfig::parse(bad_diff.as_bytes()).is_err());
        let bad_type =
            format!(r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"tarballs","diff_ids":["{D1}"]}}}}"#);
        assert!(ImageConfig::parse(bad_type.as_bytes()).is_err());
        let arm = format!(
            r#"{{"architecture":"arm64","variant":"v8","os":"linux","rootfs":{{"type":"layers","diff_ids":["{D1}"]}}}}"#
        );
        let c = ImageConfig::parse(arm.as_bytes()).unwrap();
        assert!(c.check_runnable().unwrap_err().to_string().contains("linux/arm64/v8"));
    }
}
