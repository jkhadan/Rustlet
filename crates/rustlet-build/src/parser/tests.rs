use super::*;

fn ok(text: &str) -> Containerfile {
    parse(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

/// The error a file gives: its line and message.
fn fails(text: &str) -> (usize, String) {
    match parse(text) {
        Ok(file) => panic!("{text:?} parsed: {file:?}"),
        Err(ParseError { line, message }) => (line, message),
    }
}

/// The instructions of a one-stage file whose `FROM` is the first line.
fn kinds(body: &str) -> Vec<InstructionKind> {
    ok(&format!("FROM alpine\n{body}")).stages[0].instructions.iter().map(|i| i.kind.clone()).collect()
}

fn kind(body: &str) -> InstructionKind {
    let mut kinds = kinds(body);
    assert_eq!(kinds.len(), 1, "{body:?}: {kinds:?}");
    kinds.remove(0)
}

/// The message for one instruction after a `FROM` (so on line 2).
fn refused(body: &str) -> String {
    let (line, message) = fails(&format!("FROM alpine\n{body}"));
    assert_eq!(line, 2, "{body:?}: {message}");
    message
}

fn s(text: &str) -> String {
    text.to_owned()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter().map(|(k, v)| (s(k), s(v))).collect()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|x| s(x)).collect()
}

#[test]
fn a_minimal_file_is_one_stage() {
    let file = ok("FROM alpine:3.20\nRUN echo hi\n");
    assert_eq!(file.escape, '\\');
    assert!(file.global_args.is_empty());
    assert!(file.warnings.is_empty());
    assert_eq!(
        file.stages,
        [Stage {
            index: 0,
            name: None,
            base: s("alpine:3.20"),
            platform: None,
            line: 1,
            instructions: vec![Instruction {
                line: 2,
                original: s("RUN echo hi"),
                kind: InstructionKind::Run(Command::Shell(s("echo hi"))),
            }],
        }]
    );
}

#[test]
fn instruction_names_are_case_insensitive() {
    let file = ok("from alpine as Build\nrun echo a\nCmd [\"sh\"]\nwOrKdIr /app\n");
    let stage = &file.stages[0];
    assert_eq!(stage.name.as_deref(), Some("build"), "stage names are lowercased");
    assert_eq!(stage.instructions[0].kind, InstructionKind::Run(Command::Shell(s("echo a"))));
    assert_eq!(stage.instructions[1].kind, InstructionKind::Cmd(Command::Exec(strings(&["sh"]))));
    assert_eq!(stage.instructions[2].kind, InstructionKind::Workdir(s("/app")));
    assert_eq!(stage.instructions[1].original, "Cmd [\"sh\"]", "the original keeps the case it had");
}

#[test]
fn stages_are_numbered_and_named() {
    let file =
        ok("FROM golang AS build\nRUN go build\n\nFROM alpine AS Final\nCOPY --from=build /out /\nFROM scratch\n");
    let summary: Vec<_> = file.stages.iter().map(|s| (s.index, s.name.clone(), s.base.clone(), s.line)).collect();
    assert_eq!(
        summary,
        [(0, Some(s("build")), s("golang"), 1), (1, Some(s("final")), s("alpine"), 4), (2, None, s("scratch"), 6),]
    );
    assert_eq!(file.stages[1].instructions[0].line, 5);
}

#[test]
fn stage_names_are_checked() {
    for name in ["1st", "-x", "na$me", "a/b", "ünïcode"] {
        let (line, message) = fails(&format!("FROM alpine AS {name}\n"));
        assert_eq!(line, 1);
        assert!(message.contains("invalid stage name"), "{name}: {message}");
    }
    for name in ["a", "a-b_c.d", "build2", "UPPER"] {
        ok(&format!("FROM alpine AS {name}\n"));
    }
    let (line, message) = fails("FROM alpine AS build\nFROM alpine AS BUILD\n");
    assert_eq!(line, 2);
    assert!(message.contains("duplicate stage name \"build\"") && message.contains("line 1"), "{message}");
    let (_, message) = fails("FROM alpine AS scratch\n");
    assert!(message.contains("scratch"), "{message}");
}

#[test]
fn from_takes_one_or_three_words() {
    for text in ["FROM\n", "FROM a b\n", "FROM a AS\n", "FROM a AS b c\n", "FROM a FROM b\n"] {
        let (line, message) = fails(text);
        assert_eq!(line, 1, "{text:?}");
        assert!(message.contains("FROM requires either one or three arguments"), "{text:?}: {message}");
    }
}

#[test]
fn from_platform_must_be_linux_amd64_or_a_variable() {
    let file = ok("FROM --platform=linux/amd64 alpine\nFROM --platform=$BUILDPLATFORM golang AS b\n");
    assert_eq!(file.stages[0].platform.as_deref(), Some("linux/amd64"));
    assert_eq!(file.stages[1].platform.as_deref(), Some("$BUILDPLATFORM"));
    let (line, message) = fails("FROM alpine\nFROM --platform=linux/arm64 alpine\n");
    assert_eq!(line, 2);
    assert!(message.contains("linux/arm64") && message.contains("linux/amd64 images only"), "{message}");
    let (_, message) = fails("FROM --platform alpine\n");
    assert!(message.contains("--platform needs a value"), "{message}");
    let (_, message) = fails("FROM --pull=always alpine\n");
    assert!(message.contains("unknown flag --pull"), "{message}");
}

#[test]
fn a_file_without_from_is_an_error_of_the_whole_file() {
    for text in ["", "\n\n", "# just a comment\n", "ARG A=1\nARG B\n"] {
        let (line, message) = fails(text);
        assert_eq!(line, 0, "{text:?}");
        assert!(message.contains("no FROM"), "{message}");
    }
}

#[test]
fn only_arg_comes_before_the_first_from() {
    let file = ok("ARG BASE=alpine\nARG TAG\nFROM ${BASE}:${TAG}\n");
    assert_eq!(
        file.global_args,
        [ArgDecl { name: s("BASE"), default: Some(s("alpine")) }, ArgDecl { name: s("TAG"), default: None }]
    );
    assert!(file.stages[0].instructions.is_empty());
    let (line, message) = fails("ARG A\n\nrun echo\nFROM alpine\n");
    assert_eq!(line, 3);
    assert!(message.contains("RUN before the first FROM"), "{message}");
}

#[test]
fn continuations_join_lines() {
    let file = ok("FROM alpine\nRUN apk add \\\n    gcc \\\n    musl-dev\nCMD x\n");
    let run = &file.stages[0].instructions[0];
    assert_eq!(run.line, 2);
    assert_eq!(run.original, "RUN apk add     gcc     musl-dev");
    assert_eq!(run.kind, InstructionKind::Run(Command::Shell(s("apk add     gcc     musl-dev"))));
    assert_eq!(file.stages[0].instructions[1].line, 5);
}

#[test]
fn a_continuation_may_have_spaces_after_the_escape() {
    let run = kind("RUN a \\  \t\n  b");
    assert_eq!(run, InstructionKind::Run(Command::Shell(s("a   b"))));
}

#[test]
fn comment_lines_inside_a_continuation_are_dropped() {
    let file = ok("FROM alpine\nRUN a \\\n# a comment \\\n   # another\n  b\n");
    let run = &file.stages[0].instructions[0];
    assert_eq!(run.original, "RUN a   b");
    assert!(file.warnings.is_empty());
}

#[test]
fn empty_continuation_lines_are_dropped_with_a_warning() {
    let file = ok("FROM alpine\nRUN a \\\n\n   \n  b\nRUN c\n");
    assert_eq!(file.stages[0].instructions[0].original, "RUN a   b");
    assert_eq!(file.stages[0].instructions[1].line, 6);
    assert_eq!(file.warnings.len(), 2, "{:?}", file.warnings);
    assert!(file.warnings[0].starts_with("line 3: empty continuation line"), "{:?}", file.warnings);
    assert!(file.warnings[1].starts_with("line 4: "), "{:?}", file.warnings);
}

#[test]
fn a_final_continuation_ends_with_the_file() {
    assert_eq!(kind("RUN a \\"), InstructionKind::Run(Command::Shell(s("a"))));
}

#[test]
fn a_comment_never_continues() {
    let file = ok("FROM alpine\n# comment \\\nRUN a\n");
    assert_eq!(file.stages[0].instructions[0].kind, InstructionKind::Run(Command::Shell(s("a"))));
}

#[test]
fn indented_lines_and_crlf_endings_are_read() {
    let file = ok("\u{feff}  FROM alpine\r\n\t RUN a \\\r\n b\r\n");
    assert_eq!(file.stages[0].base, "alpine");
    assert_eq!(file.stages[0].instructions[0].original, "RUN a  b");
}

#[test]
fn the_escape_directive_makes_backtick_the_escape_character() {
    let file = ok("# escape=`\nFROM mcr.example/windows\nCOPY C:\\src\\ C:\\dst\\\nRUN dir `\n  C:\\\n");
    assert_eq!(file.escape, '`');
    let instructions = &file.stages[0].instructions;
    assert_eq!(
        instructions[0].kind,
        InstructionKind::Copy(CopyArgs {
            from: None,
            chown: None,
            chmod: None,
            args: Args::Shell(s("C:\\src\\ C:\\dst\\")),
        }),
        "a final backslash doesn't continue"
    );
    assert_eq!(instructions[1].original, "RUN dir   C:\\");
}

#[test]
fn directives_are_read_only_at_the_top() {
    let directive_then = |first: &str| ok(&format!("{first}\n# escape=`\nFROM a\n")).escape;
    assert_eq!(directive_then("# syntax=docker/dockerfile:1"), '`');
    assert_eq!(directive_then("# check=skip=all"), '`');
    assert_eq!(directive_then("# a comment"), '\\', "a comment ends them");
    assert_eq!(directive_then(""), '\\', "an empty line ends them");
    assert_eq!(directive_then("# unknowndirective=value"), '\\', "an unknown directive is a comment");
    assert_eq!(ok("FROM a\n# escape=`\n").escape, '\\', "after an instruction, a comment");
}

#[test]
fn directive_syntax_allows_whitespace_and_any_case() {
    for line in ["#escape=`", "# escape =`", "#\tescape= `", "# escape = ` ", "#   EsCaPe=`", "  # escape=`"] {
        assert_eq!(ok(&format!("{line}\nFROM a\n")).escape, '`', "{line:?}");
    }
}

#[test]
fn a_directive_given_twice_or_a_bad_escape_is_an_error() {
    let (line, message) = fails("# escape=`\n# escape=\\\nFROM a\n");
    assert_eq!(line, 2);
    assert!(message.contains("only one escape parser directive"), "{message}");
    let (line, message) = fails("# syntax=a\n# SYNTAX=b\nFROM a\n");
    assert_eq!(line, 2);
    assert!(message.contains("only one syntax"), "{message}");
    let (line, message) = fails("# syntax=x\n# escape=/\nFROM a\n");
    assert_eq!(line, 2);
    assert!(message.contains("invalid escape character \"/\""), "{message}");
}

#[test]
fn run_takes_a_shell_string_or_a_json_array() {
    assert_eq!(kind("RUN echo \"$HOME\" > /x"), InstructionKind::Run(Command::Shell(s("echo \"$HOME\" > /x"))));
    assert_eq!(
        kind("RUN [\"/bin/echo\", \"a b\", \"$HOME\"]"),
        InstructionKind::Run(Command::Exec(strings(&["/bin/echo", "a b", "$HOME"])))
    );
    assert_eq!(kind("RUN   [ \"a\" ]  "), InstructionKind::Run(Command::Exec(strings(&["a"]))));
}

#[test]
fn invalid_json_is_the_shell_form() {
    for text in ["[\"a\", 'b']", "[a]", "[\"a\"] && b", "[\"unclosed\""] {
        assert_eq!(kind(&format!("CMD {text}")), InstructionKind::Cmd(Command::Shell(s(text))), "{text}");
    }
}

#[test]
fn a_json_array_of_other_things_is_an_error() {
    for text in ["CMD [1, 2]", "ENTRYPOINT [\"a\", null]", "RUN [[\"a\"]]", "VOLUME [true]", "SHELL [{}]"] {
        let message = refused(text);
        assert!(message.contains("arrays must be comprised of strings only"), "{text}: {message}");
    }
}

#[test]
fn run_needs_a_command() {
    for text in ["RUN", "RUN   ", "RUN []"] {
        assert!(refused(text).contains("RUN requires at least one argument"), "{text}");
    }
}

#[test]
fn cmd_and_entrypoint_may_be_empty() {
    assert_eq!(kind("CMD []"), InstructionKind::Cmd(Command::Exec(Vec::new())));
    assert_eq!(kind("ENTRYPOINT []"), InstructionKind::Entrypoint(Command::Exec(Vec::new())));
    assert_eq!(kind("CMD"), InstructionKind::Cmd(Command::Shell(String::new())));
    assert_eq!(kind("ENTRYPOINT [\"/app\"]"), InstructionKind::Entrypoint(Command::Exec(strings(&["/app"]))));
    assert_eq!(kind("ENTRYPOINT exec /app"), InstructionKind::Entrypoint(Command::Shell(s("exec /app"))));
}

#[test]
fn buildkit_run_flags_are_refused_with_their_line() {
    for flag in ["mount=type=cache,target=/root/.cache", "network=none", "security=insecure"] {
        let message = refused(&format!("RUN --{flag} make"));
        let name = flag.split('=').next().unwrap();
        assert!(
            message.contains(&format!("RUN --{name} is a BuildKit feature Rustlets doesn't support")),
            "{flag}: {message}"
        );
    }
    assert!(refused("RUN --network=host x").contains("rustlet build --network"));
    assert!(refused("RUN --rm x").contains("RUN: unknown flag --rm"));
    assert!(refused("CMD --help").contains("CMD: unknown flag --help"), "flags are read for every instruction");
}

#[test]
fn heredocs_are_refused() {
    for text in [
        "RUN <<EOF",
        "RUN cat <<EOF > /etc/x",
        "RUN <<-EOF",
        "RUN <<\"EOF\"",
        "RUN <<'EOF'",
        "RUN 3<<EOF cat",
        "RUN python3 <<PY",
        "COPY <<EOF /etc/x",
        "ADD <<EOF /etc/x",
        "ONBUILD RUN <<EOF",
    ] {
        let message = refused(text);
        assert!(message.contains("heredoc"), "{text}: {message}");
        assert!(message.contains("BuildKit feature Rustlets doesn't support"), "{text}: {message}");
    }
}

#[test]
fn shifts_here_strings_and_quoted_angles_are_not_heredocs() {
    for text in [
        "RUN cat <<< 'string'",
        "RUN echo \"<<EOF\"",
        "RUN echo '<<EOF'",
        "RUN echo \\<<EOF",
        "RUN echo $((1 << 2))",
        "RUN cat << EOF",
        "RUN a<<b",
        "RUN [\"sh\", \"-c\", \"cat <<EOF\"]",
    ] {
        kind(text);
    }
}

#[test]
fn copy_takes_flags_and_its_arguments_as_written() {
    assert_eq!(
        kind("COPY --from=build --chown=app:app --chmod=0755 /out/ ${DEST}/"),
        InstructionKind::Copy(CopyArgs {
            from: Some(s("build")),
            chown: Some(s("app:app")),
            chmod: Some(s("0755")),
            args: Args::Shell(s("/out/ ${DEST}/")),
        })
    );
    assert_eq!(
        kind("COPY [\"my file\", \"/dst/\"]"),
        InstructionKind::Copy(CopyArgs {
            from: None,
            chown: None,
            chmod: None,
            args: Args::Json(strings(&["my file", "/dst/"]))
        })
    );
    assert_eq!(
        kind("ADD --chown=1000 app.tar.gz /"),
        InstructionKind::Add(CopyArgs {
            from: None,
            chown: Some(s("1000")),
            chmod: None,
            args: Args::Shell(s("app.tar.gz /")),
        })
    );
}

#[test]
fn flag_values_lose_their_quotes_as_buildkit_reads_them() {
    let InstructionKind::Copy(copy) = kind("COPY --chown=\"app user\" --from='build' a b") else { panic!() };
    assert_eq!(copy.chown.as_deref(), Some("app user"));
    assert_eq!(copy.from.as_deref(), Some("build"));
}

#[test]
fn a_lone_double_dash_ends_the_flags() {
    let InstructionKind::Copy(copy) = kind("COPY --chown=1 -- --odd-name /dst/") else { panic!() };
    assert_eq!(copy.chown.as_deref(), Some("1"));
    assert_eq!(copy.args, Args::Shell(s("--odd-name /dst/")));
}

#[test]
fn an_empty_flag_value_is_no_value() {
    let InstructionKind::Copy(copy) = kind("COPY --from= a b") else { panic!() };
    assert_eq!(copy.from, None);
}

#[test]
fn copy_and_add_refuse_buildkit_flags() {
    for (text, flag) in [
        ("COPY --link a b", "COPY --link"),
        ("COPY --link=true a b", "COPY --link"),
        ("COPY --parents a/b c", "COPY --parents"),
        ("COPY --exclude=*.md . /", "COPY --exclude"),
        ("ADD --link a b", "ADD --link"),
        ("ADD --exclude=x a b", "ADD --exclude"),
        ("ADD --checksum=sha256:abc https://x/y /", "ADD --checksum"),
        ("ADD --keep-git-dir=true git@x:y /", "ADD --keep-git-dir"),
    ] {
        let message = refused(text);
        assert!(
            message.contains(&format!("{flag} is a BuildKit feature Rustlets doesn't support")),
            "{text}: {message}"
        );
    }
    assert!(refused("ADD --from=build a b").contains("ADD: unknown flag --from"), "ADD has no --from in Docker");
    assert!(refused("COPY --frm=build a b").contains("COPY: unknown flag --frm"));
    assert!(refused("COPY --from build a b").contains("COPY --from needs a value"));
    assert!(refused("COPY --from=a --from=b x y").contains("--from is given twice"));
}

#[test]
fn copy_needs_a_source_and_a_destination() {
    for text in ["COPY", "COPY onlyone", "COPY [\"one\"]", "ADD x", "COPY \"a b\"", "COPY --chown=1 x"] {
        assert!(refused(text).contains("requires at least two arguments"), "{text}");
    }
}

#[test]
fn env_takes_pairs_with_their_values_as_written() {
    assert_eq!(
        kind("ENV A=1 B=\"two words\" C='$HOME' D=x\\ y E= F=$A"),
        InstructionKind::Env(pairs(&[
            ("A", "1"),
            ("B", "\"two words\""),
            ("C", "'$HOME'"),
            ("D", "x\\ y"),
            ("E", ""),
            ("F", "$A"),
        ]))
    );
    assert_eq!(kind("ENV MSG=\"a = b\""), InstructionKind::Env(pairs(&[("MSG", "\"a = b\"")])));
    assert_eq!(
        kind("ENV PATH=/a:$PATH \\\n    LANG=C.UTF-8"),
        InstructionKind::Env(pairs(&[("PATH", "/a:$PATH"), ("LANG", "C.UTF-8")]))
    );
}

#[test]
fn env_has_an_old_form_whose_value_is_the_rest_of_the_line() {
    assert_eq!(kind("ENV MSG hello   world"), InstructionKind::Env(pairs(&[("MSG", "hello   world")])));
    assert_eq!(kind("ENV X \"quoted value\""), InstructionKind::Env(pairs(&[("X", "\"quoted value\"")])));
    assert_eq!(kind("ENV X a=b"), InstructionKind::Env(pairs(&[("X", "a=b")])), "the first word decides");
}

#[test]
fn malformed_env_and_label_are_errors() {
    assert!(refused("ENV").contains("ENV requires at least one argument"));
    assert!(refused("ENV ONLY").contains("ENV must have two arguments"));
    assert!(refused("ENV A=1 B").contains("no = in \"B\""));
    assert!(refused("ENV =x").contains("ENV names can't be empty"));
    assert!(refused("LABEL").contains("LABEL requires at least one argument"));
    assert!(refused("LABEL a=1 b").contains("LABEL: no = in"));
    assert!(refused("ENV --x=1 A=1").contains("ENV: unknown flag --x"));
}

#[test]
fn label_takes_pairs_like_env() {
    assert_eq!(
        kind("LABEL \"com.example.vendor\"=\"ACME Inc\" version=1.0 description=\"a \\\n  b\""),
        InstructionKind::Label(pairs(&[
            ("\"com.example.vendor\"", "\"ACME Inc\""),
            ("version", "1.0"),
            ("description", "\"a   b\""),
        ]))
    );
    assert_eq!(
        kind("LABEL maintainer someone@example.com"),
        InstructionKind::Label(pairs(&[("maintainer", "someone@example.com")]))
    );
}

#[test]
fn arg_declares_names_with_or_without_defaults() {
    assert_eq!(
        kind("ARG A B=2 C=\"x y\" D="),
        InstructionKind::Arg(vec![
            ArgDecl { name: s("A"), default: None },
            ArgDecl { name: s("B"), default: Some(s("2")) },
            ArgDecl { name: s("C"), default: Some(s("\"x y\"")) },
            ArgDecl { name: s("D"), default: Some(String::new()) },
        ])
    );
    assert!(refused("ARG").contains("ARG requires at least one argument"));
    assert!(refused("ARG =1").contains("ARG names can't be empty"));
}

#[test]
fn single_argument_instructions_keep_the_rest_of_the_line() {
    assert_eq!(kind("WORKDIR   /my app/$DIR  "), InstructionKind::Workdir(s("/my app/$DIR")));
    assert_eq!(kind("USER app:app"), InstructionKind::User(s("app:app")));
    assert_eq!(kind("STOPSIGNAL SIGQUIT"), InstructionKind::StopSignal(s("SIGQUIT")));
    assert_eq!(kind("EXPOSE 80 443/tcp $PORT"), InstructionKind::Expose(s("80 443/tcp $PORT")));
    for name in ["WORKDIR", "USER", "STOPSIGNAL", "MAINTAINER"] {
        assert!(refused(name).contains(&format!("{name} requires exactly one argument")), "{name}");
    }
    assert!(refused("EXPOSE").contains("EXPOSE requires at least one argument"));
}

#[test]
fn maintainer_is_kept_with_a_warning() {
    let file = ok("FROM alpine\n\nMAINTAINER Jane <jane@example.com>\n");
    assert_eq!(file.stages[0].instructions[0].kind, InstructionKind::Maintainer(s("Jane <jane@example.com>")));
    assert_eq!(file.warnings.len(), 1);
    assert!(file.warnings[0].starts_with("line 3: MAINTAINER is deprecated"), "{:?}", file.warnings);
}

#[test]
fn volume_takes_a_json_array_or_words() {
    assert_eq!(
        kind("VOLUME [\"/data\", \"/my logs\"]"),
        InstructionKind::Volume(Args::Json(strings(&["/data", "/my logs"])))
    );
    assert_eq!(kind("VOLUME /data $LOGS"), InstructionKind::Volume(Args::Shell(s("/data $LOGS"))));
    assert!(refused("VOLUME").contains("VOLUME requires at least one argument"));
    assert!(refused("VOLUME []").contains("VOLUME requires at least one argument"));
}

#[test]
fn healthcheck_none_disables_the_check() {
    assert_eq!(kind("HEALTHCHECK NONE"), InstructionKind::Healthcheck(Healthcheck::None));
    assert_eq!(kind("healthcheck none"), InstructionKind::Healthcheck(Healthcheck::None));
    assert!(refused("HEALTHCHECK NONE x").contains("HEALTHCHECK NONE takes no arguments"));
}

#[test]
fn healthcheck_cmd_takes_options_and_a_command() {
    assert_eq!(
        kind(
            "HEALTHCHECK --interval=30s --timeout=3s --start-period=1m --start-interval=2s --retries=5 \\\n  CMD curl -f http://localhost/ || exit 1"
        ),
        InstructionKind::Healthcheck(Healthcheck::Check {
            command: Command::Shell(s("curl -f http://localhost/ || exit 1")),
            interval: Some(s("30s")),
            timeout: Some(s("3s")),
            start_period: Some(s("1m")),
            start_interval: Some(s("2s")),
            retries: Some(s("5")),
        })
    );
    assert_eq!(
        kind("HEALTHCHECK cmd [\"redis-cli\", \"ping\"]"),
        InstructionKind::Healthcheck(Healthcheck::Check {
            command: Command::Exec(strings(&["redis-cli", "ping"])),
            interval: None,
            timeout: None,
            start_period: None,
            start_interval: None,
            retries: None,
        })
    );
}

#[test]
fn malformed_healthchecks_are_errors() {
    for (text, wanted) in [
        ("HEALTHCHECK", "HEALTHCHECK requires at least one argument"),
        ("HEALTHCHECK CMD", "HEALTHCHECK CMD needs a command"),
        ("HEALTHCHECK CMD []", "HEALTHCHECK CMD needs a command"),
        ("HEALTHCHECK --interval=5s", "HEALTHCHECK requires at least one argument"),
        ("HEALTHCHECK curl -f x", "HEALTHCHECK curl: unknown type"),
        ("HEALTHCHECK --every=5s CMD x", "HEALTHCHECK: unknown flag --every"),
        ("HEALTHCHECK --interval CMD x", "HEALTHCHECK --interval needs a value"),
        ("HEALTHCHECK --interval=5 CMD x", "HEALTHCHECK --interval: invalid duration"),
        ("HEALTHCHECK --timeout=1us CMD x", "can't be less than 1ms"),
        ("HEALTHCHECK --retries=-1 CMD x", "--retries=-1: can't be negative"),
        ("HEALTHCHECK --retries=many CMD x", "--retries=many: not a number"),
    ] {
        let message = refused(text);
        assert!(message.contains(wanted), "{text}: {message}");
    }
}

#[test]
fn shell_requires_a_json_array() {
    assert_eq!(
        kind("SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]"),
        InstructionKind::Shell(strings(&["/bin/bash", "-o", "pipefail", "-c"]))
    );
    assert!(refused("SHELL /bin/bash -c").contains("SHELL requires the arguments to be in JSON form"));
    assert!(refused("SHELL []").contains("SHELL requires at least one argument"));
    assert!(refused("SHELL").contains("SHELL requires at least one argument"));
}

#[test]
fn onbuild_keeps_its_instruction_as_written() {
    assert_eq!(kind("ONBUILD COPY . /app/src"), InstructionKind::Onbuild(s("COPY . /app/src")));
    assert_eq!(
        kind("onbuild run --mount=type=cache,target=/c make"),
        InstructionKind::Onbuild(s("run --mount=type=cache,target=/c make"))
    );
    assert_eq!(kind("ONBUILD RUN a \\\n  b"), InstructionKind::Onbuild(s("RUN a   b")));
}

#[test]
fn onbuild_refuses_what_docker_refuses() {
    assert!(refused("ONBUILD ONBUILD RUN x").contains("ONBUILD ONBUILD isn't allowed"));
    assert!(refused("ONBUILD FROM alpine").contains("FROM isn't allowed as an ONBUILD trigger"));
    assert!(refused("ONBUILD maintainer x").contains("MAINTAINER isn't allowed as an ONBUILD trigger"));
    assert!(refused("ONBUILD COPPY a b").contains("ONBUILD: unknown instruction: COPPY"));
    assert!(refused("ONBUILD").contains("ONBUILD requires at least one argument"));
}

#[test]
fn unknown_instructions_are_errors() {
    let message = refused("COPPY a b");
    assert_eq!(message, "unknown instruction: COPPY");
    let (line, _) = fails("FROM alpine\nRUN a\n\n  FOO bar\n");
    assert_eq!(line, 4);
}

#[test]
fn errors_carry_the_line_the_instruction_starts_on() {
    let (line, message) = fails("FROM alpine\nRUN a \\\n  b\nCOPY \\\n  --link \\\n  a b\n");
    assert_eq!(line, 4);
    assert!(message.contains("--link"), "{message}");
    let error = parse("FROM a\nWORKDIR\n").unwrap_err();
    assert_eq!(error.to_string(), "line 2: WORKDIR requires exactly one argument");
}

#[test]
fn parse_instruction_reads_one_instruction() {
    let instruction = parse_instruction("CMD [\"sh\"]").unwrap();
    assert_eq!(instruction.line, 1);
    assert_eq!(instruction.original, "CMD [\"sh\"]");
    assert_eq!(instruction.kind, InstructionKind::Cmd(Command::Exec(strings(&["sh"]))));
    assert_eq!(
        parse_instruction("  ENV A=1 \\\n  B=2\n").unwrap().kind,
        InstructionKind::Env(pairs(&[("A", "1"), ("B", "2")]))
    );
    assert_eq!(
        parse_instruction("ARG X").unwrap().kind,
        InstructionKind::Arg(vec![ArgDecl { name: s("X"), default: None }])
    );
}

#[test]
fn parse_instruction_refuses_from_several_and_none() {
    let error = parse_instruction("FROM alpine").unwrap_err();
    assert!(error.message.contains("FROM can't be used here"), "{error}");
    let error = parse_instruction("CMD a\nENV b=c").unwrap_err();
    assert_eq!(error.line, 2);
    assert!(error.message.contains("one instruction expected"), "{error}");
    for text in ["", "   ", "# comment"] {
        let error = parse_instruction(text).unwrap_err();
        assert_eq!((error.line, error.message.as_str()), (0, "no instruction"), "{text:?}");
    }
    let error = parse_instruction("EXPOSE").unwrap_err();
    assert_eq!(error.to_string(), "line 1: EXPOSE requires at least one argument");
    assert!(parse_instruction("# escape=`\nCMD a").is_ok(), "no directives: the comment is a comment");
}

#[test]
fn heredoc_words_are_recognized_as_buildkit_does() {
    for word in ["<<EOF", "<<-EOF", "2<<EOF", "<<\"EOF\"", "<<'E O F'", "<<EOF)"] {
        assert!(is_heredoc(word), "{word}");
    }
    for word in ["<<", "<<-", "<<<x", "a<<EOF", "\\<<EOF", "\"<<EOF\"", "<<a<b"] {
        assert!(!is_heredoc(word), "{word}");
    }
}

#[test]
fn words_keep_quotes_and_escapes() {
    assert_eq!(split_words("a  'b c'  \"d \\\" e\" f\\ g", '\\'), ["a", "'b c'", "\"d \\\" e\"", "f\\ g"]);
    assert_eq!(split_words("x='it''s' y", '\\'), ["x='it''s'", "y"]);
    assert_eq!(split_words("a\\", '\\'), ["a"], "a final escape character is dropped");
    assert_eq!(split_words("`  a", '`'), ["` ", "a"]);
    assert_eq!(split_words("   ", '\\'), Vec::<String>::new());
}

#[test]
fn flags_are_the_leading_double_dash_words() {
    assert_eq!(extract_flags("--a=1 --b='x y' rest --c"), (strings(&["--a=1", "--b=x y"]), "rest --c"));
    assert_eq!(extract_flags("-x --a"), (Vec::new(), "-x --a"));
    assert_eq!(extract_flags("--a=\\\"q"), (strings(&["--a=\"q"]), ""));
    assert_eq!(extract_flags("--a --"), (strings(&["--a"]), ""));
    assert_eq!(extract_flags(""), (Vec::new(), ""));
}
