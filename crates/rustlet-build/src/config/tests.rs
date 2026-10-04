use std::time::Duration;

use serde_json::json;

use super::*;
use crate::op::{CopyOp, HealthcheckOp};
use crate::parser::parse_instruction;

/// `text` as an op, expanded with no variables set.
fn op(text: &str) -> Op {
    let instruction = parse_instruction(text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
    Op::new(&instruction.kind, '\\', &|_| None).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

/// A state after `steps`, from `base`.
fn after(base: Option<Value>, steps: &[&str]) -> ImageConfigState {
    let mut state = ImageConfigState::new(base.as_ref());
    for step in steps {
        state.apply(&op(step)).unwrap_or_else(|e| panic!("{step:?}: {e}"));
    }
    state
}

fn s(text: &str) -> String {
    text.to_owned()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|x| s(x)).collect()
}

#[test]
fn scratch_starts_with_an_empty_config() {
    let state = ImageConfigState::new(None);
    assert_eq!(state.to_value(), json!({}));
    assert_eq!((state.author.as_deref(), state.cmd_set), (None, false));
    assert_eq!(state.env(), Vec::<String>::new());
    assert_eq!(state.user(), None);
    assert_eq!(state.workdir(), "/");
    assert_eq!(state.shell(), ["/bin/sh", "-c"]);
    assert_eq!(ImageConfigState::new(Some(&json!(null))).to_value(), json!({}), "a null config is none");
}

#[test]
fn the_base_config_is_kept_unknown_fields_included_but_not_its_triggers() {
    let base = json!({
        "Env": ["PATH=/usr/bin"],
        "Cmd": ["sh"],
        "ArgsEscaped": true,
        "X-Custom": {"a": 1},
        "OnBuild": ["RUN echo parent"],
    });
    let state = ImageConfigState::new(Some(&base));
    assert_eq!(
        state.to_value(),
        json!({"Env": ["PATH=/usr/bin"], "Cmd": ["sh"], "ArgsEscaped": true, "X-Custom": {"a": 1}})
    );
}

#[test]
fn env_replaces_a_name_in_place_or_appends() {
    let state = after(
        Some(json!({"Env": ["PATH=/usr/bin", "LANG=C", "BARE"]})),
        &["ENV PATH=/opt/bin:/usr/bin NEW=1", "ENV BARE=set", "ENV LANG C.UTF-8"],
    );
    assert_eq!(state.env(), ["PATH=/opt/bin:/usr/bin", "LANG=C.UTF-8", "BARE=set", "NEW=1"]);
    assert_eq!(state.env_var("PATH").as_deref(), Some("/opt/bin:/usr/bin"));
    assert_eq!(state.env_var("NEW").as_deref(), Some("1"));
    assert_eq!(state.env_var("path"), None, "names are case-sensitive");
    let bare = ImageConfigState::new(Some(&json!({"Env": ["FLAG", "EMPTY="]})));
    assert_eq!(bare.env_var("FLAG").as_deref(), Some(""));
    assert_eq!(bare.env_var("EMPTY").as_deref(), Some(""));
    assert_eq!(after(None, &["ENV A=1"]).to_value(), json!({"Env": ["A=1"]}));
    assert_eq!(after(Some(json!({"Env": null})), &["ENV A=1"]).env(), ["A=1"]);
}

#[test]
fn labels_ports_and_volumes_add_to_their_sets() {
    let base = json!({"Labels": {"a": "1", "keep": "x"}, "ExposedPorts": {"22/tcp": {}}, "Volumes": null});
    let state = after(
        Some(base),
        &["LABEL a=2 b=\"x y\"", "EXPOSE 80 53/udp", "EXPOSE 80", "VOLUME /data", "VOLUME [\"/logs\"]"],
    );
    assert_eq!(state.config["Labels"], json!({"a": "2", "b": "x y", "keep": "x"}));
    assert_eq!(state.config["ExposedPorts"], json!({"22/tcp": {}, "80/tcp": {}, "53/udp": {}}));
    assert_eq!(state.config["Volumes"], json!({"/data": {}, "/logs": {}}));
}

#[test]
fn a_malformed_base_config_is_an_error_not_a_panic() {
    let mut state = ImageConfigState::new(Some(&json!({"Env": "PATH=/bin", "Labels": ["a"]})));
    assert!(state.apply(&op("ENV A=1")).unwrap_err().contains("Env"));
    assert!(state.apply(&op("LABEL a=1")).unwrap_err().contains("Labels"));
    assert_eq!(state.env(), Vec::<String>::new());
}

#[test]
fn workdir_joins_the_current_one_and_is_cleaned() {
    let state = after(None, &["WORKDIR /app", "WORKDIR src", "WORKDIR ../lib/./x/"]);
    assert_eq!(state.workdir(), "/app/lib/x");
    assert_eq!(state.config["WorkingDir"], "/app/lib/x");
    assert_eq!(after(None, &["WORKDIR /a", "WORKDIR /b//c/.."]).workdir(), "/b");
    assert_eq!(after(None, &["WORKDIR rel"]).workdir(), "/rel");
    assert_eq!(after(Some(json!({"WorkingDir": "base"})), &["WORKDIR x"]).workdir(), "/base/x");
    assert_eq!(after(None, &["WORKDIR /../.."]).workdir(), "/");
}

#[test]
fn user_stopsignal_and_shell_are_set() {
    let state =
        after(Some(json!({"User": "root"})), &["USER app:app", "STOPSIGNAL SIGQUIT", "SHELL [\"/bin/bash\", \"-c\"]"]);
    assert_eq!(state.user().as_deref(), Some("app:app"));
    assert_eq!(state.config["StopSignal"], "SIGQUIT");
    assert_eq!(state.shell(), ["/bin/bash", "-c"]);
    assert_eq!(after(Some(json!({"User": "app"})), &["USER $NOBODY"]).user(), None, "an empty user is none");
}

#[test]
fn shell_form_commands_use_the_shell() {
    let state = after(None, &["CMD echo hi"]);
    assert_eq!(state.config["Cmd"], json!(["/bin/sh", "-c", "echo hi"]));
    assert!(state.cmd_set);
    let state = after(None, &["SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]", "ENTRYPOINT exec app"]);
    assert_eq!(state.config["Entrypoint"], json!(["/bin/bash", "-o", "pipefail", "-c", "exec app"]));
    let state = after(None, &["CMD [\"a\", \"b c\"]"]);
    assert_eq!(state.config["Cmd"], json!(["a", "b c"]));
    assert_eq!(state.run_args(&Command::Shell(s("x y"))), ["/bin/sh", "-c", "x y"]);
    assert_eq!(state.run_args(&Command::Exec(strings(&["x", "y"]))), ["x", "y"]);
}

#[test]
fn entrypoint_clears_an_inherited_cmd() {
    let base = || Some(json!({"Entrypoint": ["/old"], "Cmd": ["--base"]}));
    let state = after(base(), &["ENTRYPOINT [\"/app\"]"]);
    assert_eq!(state.config.get("Cmd"), None);
    assert_eq!(state.config["Entrypoint"], json!(["/app"]));
}

#[test]
fn entrypoint_keeps_a_cmd_this_stage_set() {
    let base = || Some(json!({"Cmd": ["--base"]}));
    let state = after(base(), &["CMD [\"--serve\"]", "ENTRYPOINT [\"/app\"]"]);
    assert_eq!(state.config["Cmd"], json!(["--serve"]));
    let state = after(base(), &["ENTRYPOINT [\"/app\"]", "CMD [\"--later\"]"]);
    assert_eq!(state.config["Cmd"], json!(["--later"]));
    assert_eq!(state.config["Entrypoint"], json!(["/app"]));
}

#[test]
fn empty_exec_forms_clear_cmd_and_entrypoint() {
    let state = after(Some(json!({"Entrypoint": ["/x"], "Cmd": ["y"]})), &["ENTRYPOINT []", "CMD []"]);
    assert_eq!(state.config["Entrypoint"], json!([]));
    assert_eq!(state.config["Cmd"], json!([]));
}

#[test]
fn healthcheck_becomes_dockers_object() {
    let state = after(None, &["HEALTHCHECK --interval=30s --retries=3 CMD curl -f http://localhost/"]);
    assert_eq!(
        state.config["Healthcheck"],
        json!({"Test": ["CMD-SHELL", "curl -f http://localhost/"], "Interval": 30_000_000_000u64, "Retries": 3})
    );
    let state = after(None, &["HEALTHCHECK --timeout=1500ms --start-period=1m --start-interval=2s CMD [\"true\"]"]);
    assert_eq!(
        state.config["Healthcheck"],
        json!({"Test": ["CMD", "true"], "Timeout": 1_500_000_000u64, "StartPeriod": 60_000_000_000u64, "StartInterval": 2_000_000_000u64})
    );
    let state = after(Some(json!({"Healthcheck": {"Test": ["CMD", "x"], "Retries": 9}})), &["HEALTHCHECK NONE"]);
    assert_eq!(state.config["Healthcheck"], json!({"Test": ["NONE"]}), "replaced whole");
}

#[test]
fn maintainer_sets_the_author_outside_config() {
    let state = after(None, &["MAINTAINER Jane <jane@example.com>"]);
    assert_eq!(state.author.as_deref(), Some("Jane <jane@example.com>"));
    assert_eq!(state.to_value(), json!({}));
}

#[test]
fn onbuild_appends_a_trigger() {
    let state = after(None, &["ONBUILD COPY . /src", "ONBUILD RUN make"]);
    assert_eq!(state.config["OnBuild"], json!(["COPY . /src", "RUN make"]));
}

#[test]
fn run_copy_add_and_arg_change_nothing() {
    let base = json!({"Env": ["A=1"], "Cmd": ["x"]});
    let state = after(Some(base.clone()), &["RUN apk add curl", "COPY a b", "ADD c d", "ARG X=1"]);
    assert_eq!(state.to_value(), base);
    assert!(!state.cmd_set);
}

#[test]
fn history_lines_are_buildkits_without_the_comment() {
    let state = after(Some(json!({"WorkingDir": "/app"})), &[]);
    let line = |text: &str| created_by(&op(text), &state);
    assert_eq!(line("RUN apk add curl"), "RUN /bin/sh -c apk add curl");
    assert_eq!(line("RUN [\"/bin/app\", \"--init\"]"), "RUN /bin/app --init");
    assert_eq!(line("CMD [\"sh\"]"), "CMD [\"sh\"]");
    assert_eq!(line("CMD python app.py"), "CMD [\"/bin/sh\",\"-c\",\"python app.py\"]");
    assert_eq!(line("ENTRYPOINT [\"/app\", \"--serve\"]"), "ENTRYPOINT [\"/app\",\"--serve\"]");
    assert_eq!(line("COPY app.py /app/"), "COPY app.py /app/");
    assert_eq!(
        line("COPY --from=build --chown=app:app --chmod=0755 /out /bin/ /usr/local/"),
        "COPY --from=build --chown=app:app --chmod=755 /out /bin/ /usr/local/"
    );
    assert_eq!(line("ADD app.tar.gz /srv/"), "ADD app.tar.gz /srv/");
    assert_eq!(line("ENV A=b C=\"d e\""), "ENV A=b C=d e");
    assert_eq!(line("LABEL k=v"), "LABEL k=v");
    assert_eq!(line("WORKDIR src"), "WORKDIR /app/src", "the resulting directory");
    assert_eq!(line("USER app"), "USER app");
    assert_eq!(line("EXPOSE 80 443"), "EXPOSE 80/tcp 443/tcp");
    assert_eq!(line("VOLUME /data"), "VOLUME [\"/data\"]");
    assert_eq!(line("STOPSIGNAL SIGTERM"), "STOPSIGNAL SIGTERM");
    assert_eq!(
        line("HEALTHCHECK --interval=30s CMD curl -f http://localhost/"),
        "HEALTHCHECK --interval=30s CMD-SHELL curl -f http://localhost/"
    );
    assert_eq!(
        line(
            "HEALTHCHECK --interval=90s --timeout=500ms --start-period=1h --start-interval=1.5s --retries=2 CMD [\"redis-cli\", \"ping\"]"
        ),
        "HEALTHCHECK --interval=1m30s --timeout=500ms --start-period=1h0m0s --start-interval=1.5s --retries=2 CMD redis-cli ping"
    );
    assert_eq!(line("HEALTHCHECK NONE"), "HEALTHCHECK NONE");
    assert_eq!(line("SHELL [\"/bin/bash\", \"-c\"]"), "SHELL [\"/bin/bash\",\"-c\"]");
    assert_eq!(line("ARG a=1 b"), "ARG a=1 b");
    assert_eq!(line("MAINTAINER x"), "MAINTAINER x");
    assert_eq!(line("ONBUILD RUN make"), "ONBUILD RUN make");
}

#[test]
fn a_runs_history_line_uses_the_shell_before_it() {
    let state = after(None, &["SHELL [\"/bin/bash\", \"-c\"]"]);
    assert_eq!(created_by(&op("RUN echo hi"), &state), "RUN /bin/bash -c echo hi");
}

#[test]
fn history_lines_take_ops_built_by_hand() {
    let state = ImageConfigState::new(None);
    let copy = Op::Copy(CopyOp {
        add: false,
        sources: strings(&["a", "b"]),
        dest: s("/d/"),
        from: None,
        chown: Some(s("1:2")),
        chmod: Some(0o644),
    });
    assert_eq!(created_by(&copy, &state), "COPY --chown=1:2 --chmod=644 a b /d/");
    let check = Op::Healthcheck(Some(HealthcheckOp {
        test: strings(&["CMD-SHELL", "true"]),
        interval: None,
        timeout: Some(Duration::from_secs(5)),
        start_period: None,
        start_interval: None,
        retries: None,
    }));
    assert_eq!(created_by(&check, &state), "HEALTHCHECK --timeout=5s CMD-SHELL true");
}

#[test]
fn durations_print_as_go_prints_them() {
    let d = format_duration;
    assert_eq!(d(Duration::ZERO), "0s");
    assert_eq!(d(Duration::from_nanos(1)), "1ns");
    assert_eq!(d(Duration::from_nanos(1500)), "1.5µs");
    assert_eq!(d(Duration::from_micros(999)), "999µs");
    assert_eq!(d(Duration::from_millis(1)), "1ms");
    assert_eq!(d(Duration::from_micros(1500)), "1.5ms");
    assert_eq!(d(Duration::from_millis(500)), "500ms");
    assert_eq!(d(Duration::from_secs(1)), "1s");
    assert_eq!(d(Duration::from_millis(1500)), "1.5s");
    assert_eq!(d(Duration::from_secs(30)), "30s");
    assert_eq!(d(Duration::from_secs(60)), "1m0s");
    assert_eq!(d(Duration::from_secs(90)), "1m30s");
    assert_eq!(d(Duration::from_secs(3600)), "1h0m0s");
    assert_eq!(d(Duration::from_nanos(3_723_000_000_001)), "1h2m3.000000001s");
    assert_eq!(d(Duration::from_secs(100 * 3600)), "100h0m0s");
    for text in ["30s", "1m30s", "1.5s", "500ms", "2h45m0s", "1.5µs", "7ns"] {
        assert_eq!(d(parse_duration(text).unwrap()), text, "round trip");
    }
}
