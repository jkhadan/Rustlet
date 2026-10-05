use std::time::Duration;

use super::*;
use crate::parser::parse_instruction;

/// `DIR=/srv`, `NAME=my app`, `FILES=a.txt b.txt`, `EMPTY=`; others unset.
fn vars(name: &str) -> Option<String> {
    match name {
        "DIR" => Some("/srv".into()),
        "NAME" => Some("my app".into()),
        "FILES" => Some("a.txt b.txt".into()),
        "PORTS" => Some("80 443/udp".into()),
        "MODE" => Some("0640".into()),
        "STAGE" => Some("build".into()),
        "EMPTY" => Some(String::new()),
        _ => None,
    }
}

/// `text` parsed as one instruction and expanded with [`vars`].
fn op(text: &str) -> Result<Op, String> {
    let instruction = parse_instruction(text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
    Op::new(&instruction.kind, '\\', &vars)
}

fn ok(text: &str) -> Op {
    op(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

fn err(text: &str) -> String {
    match op(text) {
        Ok(op) => panic!("{text:?} gave {op:?}"),
        Err(e) => e,
    }
}

fn s(text: &str) -> String {
    text.to_owned()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|x| s(x)).collect()
}

fn copy(text: &str) -> CopyOp {
    match ok(text) {
        Op::Copy(copy) => copy,
        other => panic!("{text:?} gave {other:?}"),
    }
}

#[test]
fn commands_are_never_expanded() {
    assert_eq!(ok("RUN echo $DIR \"${NAME}\""), Op::Run(Command::Shell(s("echo $DIR \"${NAME}\""))));
    assert_eq!(ok("RUN [\"echo\", \"$DIR\"]"), Op::Run(Command::Exec(strings(&["echo", "$DIR"]))));
    assert_eq!(ok("CMD echo $DIR"), Op::Cmd(Command::Shell(s("echo $DIR"))));
    assert_eq!(ok("ENTRYPOINT [\"$DIR/app\"]"), Op::Entrypoint(Command::Exec(strings(&["$DIR/app"]))));
    assert_eq!(ok("SHELL [\"$DIR/sh\", \"-c\"]"), Op::Shell(strings(&["$DIR/sh", "-c"])));
    assert_eq!(ok("ONBUILD RUN echo $DIR"), Op::Onbuild(s("RUN echo $DIR")));
}

#[test]
fn env_and_label_expand_names_and_values() {
    assert_eq!(
        ok("ENV ROOT=$DIR/root TITLE=\"${NAME}!\" RAW='$DIR' ESC=\\$DIR"),
        Op::Env(vec![
            (s("ROOT"), s("/srv/root")),
            (s("TITLE"), s("my app!")),
            (s("RAW"), s("$DIR")),
            (s("ESC"), s("$DIR")),
        ])
    );
    assert_eq!(ok("ENV MSG hello $NAME"), Op::Env(vec![(s("MSG"), s("hello my app"))]));
    assert_eq!(ok("LABEL \"org.$STAGE\"=\"v ${UNSET:-1}\""), Op::Label(vec![(s("org.build"), s("v 1"))]));
    assert!(err("ENV $UNSET=x").contains("ENV names can't be empty"));
    assert!(err("ENV A=${UNSET:?needed}").contains("UNSET: needed"));
}

#[test]
fn env_pairs_all_read_the_variables_from_before_the_instruction() {
    // DIR is /srv before; the second pair still sees that, as in Docker.
    assert_eq!(ok("ENV DIR=/new OTHER=$DIR"), Op::Env(vec![(s("DIR"), s("/new")), (s("OTHER"), s("/srv"))]));
}

#[test]
fn arg_defaults_are_expanded() {
    assert_eq!(
        ok("ARG A B=$DIR/b C=\"${NAME}\""),
        Op::Arg(vec![(s("A"), None), (s("B"), Some(s("/srv/b"))), (s("C"), Some(s("my app")))])
    );
}

#[test]
fn single_word_instructions_are_expanded() {
    assert_eq!(ok("WORKDIR $DIR/${NAME}"), Op::Workdir(s("/srv/my app")));
    assert_eq!(ok("USER ${UNSET:-app}"), Op::User(s("app")));
    assert_eq!(ok("USER $EMPTY"), Op::User(String::new()), "an empty user is root again");
    assert_eq!(ok("MAINTAINER $NAME"), Op::Maintainer(s("$NAME")));
    assert_eq!(ok("STOPSIGNAL ${UNSET:-SIGQUIT}"), Op::StopSignal(s("SIGQUIT")));
    assert!(err("WORKDIR $UNSET").contains("WORKDIR $UNSET: the path is empty"));
}

#[test]
fn maintainer_keeps_variables_quotes_and_apostrophes_as_written() {
    assert_eq!(ok("MAINTAINER Pat O'Brien <pat@example.com>"), Op::Maintainer(s("Pat O'Brien <pat@example.com>")));
    assert_eq!(ok("MAINTAINER \"$NAME\""), Op::Maintainer(s("\"$NAME\"")));
}

#[test]
fn build_arg_overrides_skip_their_defaults_expansion() {
    let instruction = parse_instruction("ARG VERSION=${VERSION:?required}").unwrap();
    let args = [(s("VERSION"), s("1.2"))].into();
    let expanded = Op::new_with_build_args(&instruction.kind, '\\', &|_| None, &args).unwrap();
    let Op::Arg(declarations) = expanded else { panic!("{expanded:?}") };
    let mut scope = crate::plan::ArgScope::new(BTreeMap::new(), args);
    for (name, default) in declarations {
        scope.declare(&name, default);
    }
    assert_eq!(scope.get("VERSION").as_deref(), Some("1.2"));
    assert!(Op::new(&instruction.kind, '\\', &|_| None).unwrap_err().contains("required"));
}

#[test]
fn stop_signals_are_names_or_numbers() {
    for signal in ["SIGTERM", "TERM", "term", "SIGKILL", "9", "1", "31", "SIGWINCH"] {
        ok(&format!("STOPSIGNAL {signal}"));
    }
    for signal in ["SIGFOO", "0", "65", "-1", "TERM9"] {
        assert!(err(&format!("STOPSIGNAL {signal}")).contains("unknown signal"), "{signal}");
    }
    for signal in ["32", "34", "64", "SIGRTMIN", "RTMIN+3", "SIGRTMAX-2"] {
        assert!(err(&format!("STOPSIGNAL {signal}")).contains("realtime signals are not supported"), "{signal}");
    }
}

#[test]
fn exposed_ports_become_port_and_protocol() {
    assert_eq!(ok("EXPOSE 80"), Op::Expose(strings(&["80/tcp"])));
    assert_eq!(
        ok("EXPOSE 80/tcp 53/udp 9/sctp 8080/UDP"),
        Op::Expose(strings(&["80/tcp", "53/udp", "9/sctp", "8080/udp"]))
    );
    assert_eq!(ok("EXPOSE 8000-8002"), Op::Expose(strings(&["8000/tcp", "8001/tcp", "8002/tcp"])));
    assert_eq!(ok("EXPOSE 5000-5001/udp 80/"), Op::Expose(strings(&["5000/udp", "5001/udp", "80/tcp"])));
    assert_eq!(ok("EXPOSE $PORTS 80"), Op::Expose(strings(&["80/tcp", "443/udp"])), "a variable's words, each once");
    assert_eq!(ok("EXPOSE 1 65535"), Op::Expose(strings(&["1/tcp", "65535/tcp"])));
}

#[test]
fn bad_ports_are_errors() {
    for (text, wanted) in [
        ("EXPOSE 0", "from 1 to 65535"),
        ("EXPOSE 65536", "from 1 to 65535"),
        ("EXPOSE http", "from 1 to 65535"),
        ("EXPOSE 8080:80", "from 1 to 65535"),
        ("EXPOSE 80/icmp", "tcp, udp or sctp"),
        ("EXPOSE 80/tcp/x", "tcp, udp or sctp"),
        ("EXPOSE 10-5", "the range ends before it starts"),
        ("EXPOSE 1-", "from 1 to 65535"),
        ("EXPOSE $UNSET", "no port"),
    ] {
        let e = err(text);
        assert!(e.contains(wanted), "{text}: {e}");
    }
}

#[test]
fn volumes_are_expanded_and_split() {
    assert_eq!(ok("VOLUME [\"$DIR/data\", \"/my logs\"]"), Op::Volume(strings(&["/srv/data", "/my logs"])));
    assert_eq!(ok("VOLUME $DIR/a \"/b c\" $FILES"), Op::Volume(strings(&["/srv/a", "/b c", "a.txt", "b.txt"])));
    assert!(err("VOLUME $UNSET").contains("no path"));
    assert!(err("VOLUME [\"$UNSET\"]").contains("a path can't be empty"));
}

#[test]
fn copy_expands_its_words_and_flags() {
    assert_eq!(
        copy("COPY --from=build --chown=${UID:-1000}:app --chmod=$MODE $FILES \"$NAME\" $DIR/"),
        CopyOp {
            add: false,
            sources: strings(&["a.txt", "b.txt", "my app"]),
            dest: s("/srv/"),
            from: Some(s("build")),
            chown: Some(s("1000:app")),
            chmod: Some(0o640),
        }
    );
    assert_eq!(
        copy("COPY [\"$NAME\", \"$FILES\", \"/dst/\"]"),
        CopyOp {
            add: false,
            sources: strings(&["my app", "a.txt b.txt"]),
            dest: s("/dst/"),
            from: None,
            chown: None,
            chmod: None,
        },
        "the JSON form's elements are one word each"
    );
}

#[test]
fn a_flag_that_expands_to_nothing_is_no_flag() {
    let copy = copy("COPY --from= --chown=$EMPTY --chmod=${UNSET} a b");
    assert_eq!((copy.from, copy.chown, copy.chmod), (None, None, None));
}

#[test]
fn chmod_is_octal() {
    assert_eq!(copy("COPY --chmod=755 a b").chmod, Some(0o755));
    assert_eq!(copy("COPY --chmod=0644 a b").chmod, Some(0o644));
    assert_eq!(copy("COPY --chmod=7777 a b").chmod, Some(0o7777));
    for mode in ["8", "0o755", "+755", "u+x", "17777", "-1", "75 5"] {
        let e = err(&format!("COPY --chmod=\"{mode}\" a b"));
        assert!(e.contains("expected an octal mode"), "{mode}: {e}");
    }
}

#[test]
fn copy_needs_two_words_after_expansion() {
    let e = err("COPY $DIR $UNSET");
    assert!(e.contains("COPY requires at least two arguments") && e.contains("1 after expansion"), "{e}");
    assert!(err("COPY $UNSET $EMPTY").contains("0 after expansion"));
    assert!(err("COPY [\"$UNSET\", \"/dst\"]").contains("a path is empty"));
    let copy = copy("COPY $FILES $EMPTY");
    assert_eq!((copy.sources, copy.dest), (strings(&["a.txt"]), s("b.txt")), "a variable can hold the destination");
}

#[test]
fn add_refuses_urls_and_git_repositories() {
    for source in ["http://example.com/a.tar.gz", "https://example.com/a", "https://github.com/o/r.git"] {
        let e = err(&format!("ADD {source} /dst/"));
        assert!(e.starts_with("ADD from a URL is not supported"), "{source}: {e}");
        assert!(e.contains(source), "{e}");
    }
    assert!(err("ADD https://example.com/app.tgz /").contains("use RUN with curl or wget"));
    for source in ["git@github.com:o/r.git", "git://example.com/r", "ssh://git@example.com/r", "https://x/r.git#main"] {
        let e = err(&format!("ADD {source} /dst/"));
        assert!(e.contains("ADD from a URL is not supported: use RUN with git clone"), "{source}: {e}");
    }
    let add = copy("ADD app.tar.gz a@b /dst/");
    assert!(add.add);
    assert_eq!(add.sources, strings(&["app.tar.gz", "a@b"]), "local names, even odd ones, are fine");
    assert_eq!(
        copy("COPY http://example.com/x /dst/").sources,
        strings(&["http://example.com/x"]),
        "COPY is left alone"
    );
}

#[test]
fn healthchecks_become_docker_tests() {
    assert_eq!(ok("HEALTHCHECK NONE"), Op::Healthcheck(None));
    assert_eq!(
        ok(
            "HEALTHCHECK --interval=30s --timeout=1m30s --start-period=500ms --start-interval=1.5s --retries=3 CMD curl -f http://localhost/ || exit 1"
        ),
        Op::Healthcheck(Some(HealthcheckOp {
            test: strings(&["CMD-SHELL", "curl -f http://localhost/ || exit 1"]),
            interval: Some(Duration::from_secs(30)),
            timeout: Some(Duration::from_secs(90)),
            start_period: Some(Duration::from_millis(500)),
            start_interval: Some(Duration::from_millis(1500)),
            retries: Some(3),
        }))
    );
    assert_eq!(
        ok("HEALTHCHECK CMD [\"redis-cli\", \"ping\"]"),
        Op::Healthcheck(Some(HealthcheckOp {
            test: strings(&["CMD", "redis-cli", "ping"]),
            interval: None,
            timeout: None,
            start_period: None,
            start_interval: None,
            retries: None,
        }))
    );
}

#[test]
fn zero_healthcheck_options_mean_the_default() {
    let Op::Healthcheck(Some(check)) = ok("HEALTHCHECK --interval=0s --timeout=0 --retries=0 CMD true") else {
        panic!()
    };
    assert_eq!((check.interval, check.timeout, check.retries), (None, None, None));
}

#[test]
fn healthcheck_options_are_checked() {
    assert_eq!(health_duration("interval", Some("1ms")), Ok(Some(Duration::from_millis(1))));
    assert!(health_duration("interval", Some("999us")).unwrap_err().contains("can't be less than 1ms"));
    assert!(health_duration("timeout", Some("x")).unwrap_err().contains("HEALTHCHECK --timeout: invalid duration"));
    assert!(health_duration("interval", Some("3000000h")).unwrap_err().contains("too long"));
    assert_eq!(health_duration("interval", None), Ok(None));
    assert_eq!(health_duration("interval", Some("")), Ok(None));
    assert_eq!(health_retries(Some("10")), Ok(Some(10)));
    assert_eq!(health_retries(Some("0")), Ok(None));
    assert!(health_retries(Some("-2")).unwrap_err().contains("can't be negative"));
    assert!(health_retries(Some("1.5")).unwrap_err().contains("not a number"));
    assert!(health_retries(Some("4294967296")).unwrap_err().contains("too many"));
}

#[test]
fn the_escape_character_is_the_files() {
    let instruction = parse_instruction("WORKDIR C:\\app\\$DIR").unwrap();
    assert_eq!(Op::new(&instruction.kind, '`', &vars), Ok(Op::Workdir(s("C:\\app\\/srv"))));
    assert_eq!(Op::new(&instruction.kind, '\\', &vars), Ok(Op::Workdir(s("C:app$DIR"))));
}

#[test]
fn filesystem_instructions_make_layers() {
    assert!(ok("RUN true").makes_layer());
    assert!(ok("COPY a b").makes_layer());
    assert!(ok("ADD a b").makes_layer());
    assert!(ok("WORKDIR /x").makes_layer());
    for text in ["ENV a=b", "CMD x", "ARG a", "LABEL a=b", "EXPOSE 80", "USER x", "VOLUME /v"] {
        assert!(!ok(text).makes_layer(), "{text}");
    }
}
