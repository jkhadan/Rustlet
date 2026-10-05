//! Review tests for Phase 7's API types: what an older record or a client's
//! JSON may leave out, and what the durations accept.

use crate::build::{BuildOptions, BuildQuery};
use crate::container::{ContainerConfig, ContainerState, Health, HealthConfig, HealthStatus};

/// Checked, holds (container.rs: every record type is `#[serde(default)]`):
/// a container record stored before Phase 7, with neither `healthcheck` in
/// its config nor `health` in its state, still deserializes, with no
/// health; and the new types take what a client leaves out.
#[test]
fn review_old_container_records_without_health_deserialize() {
    let state: ContainerState =
        serde_json::from_str(r#"{"status":"running","pid":42,"exit_code":null,"restart_count":1}"#).unwrap();
    assert_eq!((state.health, state.pid, state.restart_count), (None, Some(42), 1));
    let config: ContainerConfig = serde_json::from_str(r#"{"image":"alpine","cmd":["sh"],"stop_timeout":3}"#).unwrap();
    assert_eq!((config.healthcheck, config.stop_timeout), (None, Some(3)));
    let off: HealthConfig = serde_json::from_str(r#"{"test":["NONE"]}"#).unwrap();
    assert!(off.is_none() && off.interval.is_none() && off.retries.is_none());
    let health: Health = serde_json::from_str(r#"{"status":"healthy"}"#).unwrap();
    assert_eq!((health.status, health.failing_streak, health.log.len()), (HealthStatus::Healthy, 0, 0));
}

/// Checked, holds (container.rs: "Durations are in nanoseconds"): a
/// duration is a whole, non-negative number of nanoseconds on the wire; a
/// string ("30s"), a fraction or a negative number is refused rather than
/// read as something else.
#[test]
fn review_health_durations_are_whole_nanoseconds_never_negative() {
    let h = HealthConfig { interval: Some(90_000_000_000), timeout: Some(500_000_000), ..HealthConfig::default() };
    let json = serde_json::to_value(&h).unwrap();
    assert_eq!(json["interval"], 90_000_000_000u64);
    assert_eq!(json["timeout"], 500_000_000u64);
    for bad in [r#"{"interval":-1}"#, r#"{"interval":1.5}"#, r#"{"retries":-1}"#, r#"{"interval":"30s"}"#] {
        assert!(serde_json::from_str::<HealthConfig>(bad).is_err(), "{bad}");
    }
}

/// Checked, holds (build.rs: "the options travel in the query, as one JSON
/// value"): options whose text holds quotes, newlines, emoji, `%`, `&`, `=`
/// and `+` come back from the JSON as they went in.
#[test]
fn review_build_options_survive_their_json_whatever_the_text() {
    let nasty = "he said \"hi\"\n\u{1f600} %41 &x=y+z #frag ?q";
    let o = BuildOptions {
        tags: vec!["registry.example:5000/a/b:1".into()],
        build_args: [("Q".to_owned(), nasty.to_owned()), ("EMPTY".to_owned(), String::new())].into(),
        labels: [(nasty.to_owned(), nasty.to_owned())].into(),
        ..BuildOptions::default()
    };
    assert_eq!(BuildQuery::new(&o).options().unwrap(), o);
}
