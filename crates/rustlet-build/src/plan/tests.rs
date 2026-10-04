use std::collections::BTreeMap;

use super::*;
use crate::parser::parse;

fn file(text: &str) -> Containerfile {
    parse(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

fn args(list: &[(&str, &str)]) -> BTreeMap<String, String> {
    list.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn planned(text: &str, target: Option<&str>, build_args: &[(&str, &str)]) -> Plan {
    plan(&file(text), target, &args(build_args)).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

fn plan_error(text: &str, target: Option<&str>, build_args: &[(&str, &str)]) -> String {
    match plan(&file(text), target, &args(build_args)) {
        Ok(plan) => panic!("{text:?} planned: {plan:?}"),
        Err(e) => e,
    }
}

const MULTI: &str = "\
FROM golang:1.23 AS build
RUN go build -o /out/app
FROM alpine AS test
RUN go test
FROM build AS lint
RUN vet
FROM alpine:3.20
COPY --from=build /out/app /usr/bin/app
CMD [\"app\"]
";

#[test]
fn the_default_target_is_the_last_stage_and_what_it_copies_from() {
    let plan = planned(MULTI, None, &[]);
    assert_eq!(plan.target, 3);
    assert_eq!(plan.stages, [0, 3], "test and lint are not needed");
    assert_eq!(plan.total_steps, (1 + 1) + (1 + 2));
    assert_eq!(
        plan.bases,
        [
            Base::Image("golang:1.23".into()),
            Base::Image("alpine".into()),
            Base::Stage(0),
            Base::Image("alpine:3.20".into())
        ]
    );
    assert!(plan.unused_args.is_empty());
}

#[test]
fn a_target_is_a_stage_name_in_any_case_or_an_index() {
    assert_eq!(planned(MULTI, Some("test"), &[]).stages, [1]);
    assert_eq!(planned(MULTI, Some("LINT"), &[]).stages, [0, 2], "lint is FROM build");
    assert_eq!(planned(MULTI, Some("lint"), &[]).total_steps, 4);
    assert_eq!(planned(MULTI, Some("1"), &[]).target, 1);
    assert_eq!(planned(MULTI, Some("3"), &[]).stages, [0, 3]);
}

#[test]
fn an_unknown_target_lists_the_stages() {
    for target in ["nope", "4", "", "-1", "+1"] {
        let e = plan_error(MULTI, Some(target), &[]);
        assert!(e.contains(&format!("target stage {target:?} could not be found")), "{e}");
        assert!(e.contains("build, test, lint, 3"), "unnamed stages by their index: {e}");
    }
}

#[test]
fn a_stage_reached_only_through_copy_from_is_built() {
    let text = "\
FROM alpine AS assets
RUN make assets
FROM alpine AS unrelated
RUN sleep 1000
FROM alpine AS deps
RUN fetch
FROM deps AS app
COPY --from=0 /assets /srv/
";
    let plan = planned(text, None, &[]);
    assert_eq!(plan.stages, [0, 2, 3]);
    assert_eq!(plan.bases[3], Base::Stage(2));
}

#[test]
fn copy_from_an_image_or_by_name_case_insensitively() {
    let text = "FROM alpine AS Build\nRUN x\nFROM alpine AS other\nFROM scratch\nCOPY --from=BUILD /x /x\nCOPY --from=nginx:latest /etc/nginx /etc/nginx\n";
    let plan = planned(text, None, &[]);
    assert_eq!(plan.stages, [0, 2]);
    assert_eq!(plan.bases[2], Base::Scratch);
}

#[test]
fn copy_from_a_later_stage_is_an_error() {
    let e = plan_error("FROM alpine\nCOPY --from=later /x /x\nFROM alpine AS later\n", Some("0"), &[]);
    assert!(e.starts_with("line 2: COPY --from=later"), "{e}");
    assert!(e.contains("isn't before this stage"), "{e}");
    let e = plan_error("FROM alpine\nCOPY --from=0 /x /x\n", None, &[]);
    assert!(e.contains("stage 0 isn't before this stage"), "a stage can't copy from itself: {e}");
    let e = plan_error("FROM alpine\nCOPY --from=7 /x /x\n", None, &[]);
    assert!(e.contains("stage 7"), "{e}");
}

#[test]
fn a_stage_name_used_before_its_stage_is_an_image() {
    let plan = planned("FROM later\nFROM alpine AS later\n", None, &[]);
    assert_eq!(plan.bases[0], Base::Image("later".into()));
    let plan = planned("FROM alpine AS self\nFROM SELF\n", None, &[]);
    assert_eq!(plan.bases[1], Base::Stage(0));
}

#[test]
fn from_lines_see_the_global_args() {
    let text =
        "ARG BASE=alpine\nARG TAG=3.20\nARG FULL=$BASE:$TAG\nFROM ${FULL}\nFROM ${BASE}:${TAG:-latest} AS second\n";
    let plan = planned(text, Some("0"), &[]);
    assert_eq!(plan.bases[0], Base::Image("alpine:3.20".into()));
    assert_eq!(plan.global_args["FULL"].as_deref(), Some("alpine:3.20"), "a default sees the args before it");
    let plan = planned(text, None, &[("TAG", "3.19"), ("BASE", "debian")]);
    assert_eq!(plan.bases, [Base::Image("debian:3.19".into()), Base::Image("debian:3.19".into())]);
}

#[test]
fn a_build_arg_overrides_a_global_default_but_needs_a_declaration() {
    let plan = planned("ARG IMAGE=alpine\nFROM $IMAGE\n", None, &[("IMAGE", "busybox")]);
    assert_eq!(plan.bases[0], Base::Image("busybox".into()));
    let e = plan_error("FROM $UNDECLARED\n", None, &[("UNDECLARED", "busybox")]);
    assert!(e.contains("line 1: FROM $UNDECLARED: the image name is empty"), "{e}");
}

#[test]
fn an_unexpandable_from_is_an_error() {
    let e = plan_error("ARG V\nFROM alpine:${V:?set_V}\n", None, &[]);
    assert!(e.starts_with("line 2: FROM alpine:${V:?set_V}") && e.contains("V: set_V"), "{e}");
    let e = plan_error("FROM alpine\nFROM ${broken\n", Some("0"), &[]);
    assert!(e.contains("line 2") && e.contains("missing '}'"), "every stage's FROM is expanded: {e}");
    let e = plan_error("ARG A=${B:?no}\nFROM alpine\n", None, &[]);
    assert!(e.contains("ARG A") && e.contains("B: no"), "{e}");
}

#[test]
fn platform_args_are_defined_without_an_arg() {
    let args = platform_args();
    assert_eq!(args["TARGETPLATFORM"], "linux/amd64");
    assert_eq!(args["TARGETOS"], "linux");
    assert_eq!(args["TARGETARCH"], "amd64");
    assert_eq!(args["TARGETVARIANT"], "");
    assert_eq!(args["BUILDPLATFORM"], "linux/amd64");
    assert_eq!(args["BUILDOS"], "linux");
    assert_eq!(args["BUILDARCH"], "amd64");
    assert_eq!(args["BUILDVARIANT"], "");
    assert_eq!(args.len(), 8);
    let plan = planned("FROM --platform=$BUILDPLATFORM golang:1.23-$TARGETOS AS build\n", None, &[]);
    assert_eq!(plan.bases[0], Base::Image("golang:1.23-linux".into()));
    assert_eq!(plan.global_args["TARGETARCH"].as_deref(), Some("amd64"));
}

#[test]
fn a_platform_variable_must_come_to_linux_amd64() {
    let text = "ARG P=linux/arm64\nFROM --platform=$P alpine\n";
    let e = plan_error(text, None, &[]);
    assert!(e.contains("line 2") && e.contains("--platform=linux/arm64"), "{e}");
    assert_eq!(planned(text, None, &[("P", "linux/amd64")]).stages, [0]);
}

#[test]
fn copy_from_is_expanded_with_the_global_args() {
    let text = "ARG SRC=assets\nFROM alpine AS assets\nFROM alpine AS other\nFROM alpine\nCOPY --from=$SRC /a /a\n";
    assert_eq!(planned(text, None, &[]).stages, [0, 2]);
    assert_eq!(planned(text, None, &[("SRC", "other")]).stages, [1, 2]);
    assert_eq!(planned(text, None, &[("SRC", "nginx")]).stages, [2], "an image is no stage");
    let e = plan_error("FROM alpine\nCOPY --from=${X:?} /a /a\n", None, &[]);
    assert!(e.starts_with("line 2: COPY --from=${X:?}"), "{e}");
}

#[test]
fn unused_build_args_are_those_no_arg_declares() {
    let text = "ARG GLOBAL\nFROM alpine AS a\nARG IN_A=1\nFROM alpine\nARG IN_B\n";
    let plan = planned(
        text,
        Some("1"),
        &[
            ("GLOBAL", "1"),
            ("IN_A", "x"),
            ("IN_B", "y"),
            ("NOBODY", "z"),
            ("ANOTHER", "w"),
            ("TARGETARCH", "arm64"),
            ("HTTP_PROXY", "http://proxy:3128"),
            ("no_proxy", "localhost"),
        ],
    );
    assert_eq!(plan.unused_args, ["ANOTHER", "NOBODY"], "an ARG in a stage not built still counts");
}

#[test]
fn global_args_without_a_value_are_unset() {
    let plan = planned("ARG NONE\nARG TARGETOS\nFROM alpine\n", None, &[]);
    assert_eq!(plan.global_args["NONE"], None);
    assert_eq!(plan.global_args["TARGETOS"].as_deref(), Some("linux"), "a platform arg keeps its value");
}

#[test]
fn resolve_from_names_stages_before_the_current_one() {
    let file = file(MULTI);
    assert_eq!(resolve_from(&file, 3, "build"), Ok(FromSource::Stage(0)));
    assert_eq!(resolve_from(&file, 3, "Test"), Ok(FromSource::Stage(1)));
    assert_eq!(resolve_from(&file, 3, "2"), Ok(FromSource::Stage(2)));
    assert_eq!(resolve_from(&file, 3, "02"), Ok(FromSource::Stage(2)));
    assert_eq!(resolve_from(&file, 3, "alpine:3.20"), Ok(FromSource::Image("alpine:3.20".into())));
    assert_eq!(
        resolve_from(&file, 3, "docker.io/library/Build"),
        Ok(FromSource::Image("docker.io/library/Build".into()))
    );
    assert!(resolve_from(&file, 1, "lint").unwrap_err().contains("the stage \"lint\" isn't before this stage"));
    assert!(resolve_from(&file, 1, "test").unwrap_err().contains("isn't before this stage"));
    assert!(resolve_from(&file, 1, "1").unwrap_err().contains("stage 1 isn't before"));
    assert!(resolve_from(&file, 1, "99999999999999999999999").is_err());
}

#[test]
fn an_arg_takes_the_build_arg_then_its_default_then_the_global() {
    let global: BTreeMap<String, Option<String>> = [
        ("G".to_owned(), Some("global".to_owned())),
        ("BOTH".to_owned(), Some("global".to_owned())),
        ("UNSET".to_owned(), None),
    ]
    .into();
    let mut scope = ArgScope::new(global, args(&[("BOTH", "built"), ("ONLY_BUILD", "b")]));
    assert_eq!(scope.get("G"), None, "a global is visible only once declared");
    scope.declare("G", None);
    assert_eq!(scope.get("G").as_deref(), Some("global"));
    scope.declare("BOTH", Some("default".into()));
    assert_eq!(scope.get("BOTH").as_deref(), Some("built"), "the build arg wins over the default");
    scope.declare("LOCAL", Some("default".into()));
    assert_eq!(scope.get("LOCAL").as_deref(), Some("default"));
    scope.declare("G2", Some("mine".into()));
    scope.declare("ONLY_BUILD", None);
    assert_eq!(scope.get("ONLY_BUILD").as_deref(), Some("b"));
    scope.declare("UNSET", None);
    assert_eq!(scope.get("UNSET"), None);
    assert_eq!(scope.get("NEVER"), None);
    assert_eq!(
        scope.vars(),
        [
            ("BOTH".to_owned(), "built".to_owned()),
            ("G".to_owned(), "global".to_owned()),
            ("G2".to_owned(), "mine".to_owned()),
            ("LOCAL".to_owned(), "default".to_owned()),
            ("ONLY_BUILD".to_owned(), "b".to_owned()),
        ],
        "sorted, and only those with values"
    );
}

#[test]
fn a_default_in_the_stage_wins_over_the_global() {
    let mut scope = ArgScope::new([("V".to_owned(), Some("global".to_owned()))].into(), BTreeMap::new());
    scope.declare("V", Some("stage".into()));
    assert_eq!(scope.get("V").as_deref(), Some("stage"));
}

#[test]
fn declaring_again_without_a_value_keeps_the_value() {
    let mut scope = ArgScope::new(BTreeMap::new(), BTreeMap::new());
    scope.declare("V", Some("1".into()));
    scope.declare("V", None);
    assert_eq!(scope.get("V").as_deref(), Some("1"));
    scope.declare("V", Some("2".into()));
    assert_eq!(scope.get("V").as_deref(), Some("2"));
}

#[test]
fn proxy_build_args_reach_run_without_an_arg() {
    let mut scope = ArgScope::new(
        BTreeMap::new(),
        args(&[
            ("HTTP_PROXY", "http://p:3128"),
            ("no_proxy", "localhost"),
            ("https_proxy", "http://s"),
            ("OTHER", "x"),
        ]),
    );
    assert_eq!(scope.get("HTTP_PROXY"), None, "not a variable for expansion");
    assert_eq!(
        scope.proxy_env(),
        [
            ("HTTP_PROXY".to_owned(), "http://p:3128".to_owned()),
            ("https_proxy".to_owned(), "http://s".to_owned()),
            ("no_proxy".to_owned(), "localhost".to_owned()),
        ]
    );
    scope.declare("no_proxy", None);
    assert_eq!(scope.vars(), [("no_proxy".to_owned(), "localhost".to_owned())]);
    assert_eq!(scope.proxy_env().len(), 2, "a declared one is a variable instead");
}

#[test]
fn a_plan_feeds_each_stage_its_arg_scope() {
    let text = "ARG VERSION=1.0\nFROM alpine\nARG VERSION\nRUN echo $VERSION\n";
    let plan = planned(text, None, &[]);
    let mut scope = ArgScope::new(plan.global_args.clone(), BTreeMap::new());
    scope.declare("VERSION", None);
    assert_eq!(scope.get("VERSION").as_deref(), Some("1.0"));
    scope.declare("TARGETARCH", None);
    assert_eq!(scope.get("TARGETARCH").as_deref(), Some("amd64"));
}
