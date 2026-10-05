use super::*;

/// `A=a`, `EMPTY=` (set, empty), `SPACED=" x  y "`, `DIR=/srv`; others unset.
fn env(name: &str) -> Option<String> {
    match name {
        "A" => Some("a".into()),
        "EMPTY" => Some(String::new()),
        "SPACED" => Some(" x  y ".into()),
        "DIR" => Some("/srv".into()),
        "B_2" => Some("b2".into()),
        _ => None,
    }
}

fn w(raw: &str) -> String {
    word(raw, '\\', &env).unwrap_or_else(|e| panic!("{raw:?}: {e}"))
}

fn ws(raw: &str) -> Vec<String> {
    words(raw, '\\', &env).unwrap_or_else(|e| panic!("{raw:?}: {e}"))
}

fn err(raw: &str) -> String {
    word(raw, '\\', &env).expect_err(raw).0
}

#[test]
fn plain_and_braced_variables_expand() {
    assert_eq!(w("$A"), "a");
    assert_eq!(w("${A}"), "a");
    assert_eq!(w("x$A-y"), "xa-y");
    assert_eq!(w("${A}b"), "ab");
    assert_eq!(w("$Ab"), "", "the name runs on: Ab is unset");
    assert_eq!(w("$B_2/x"), "b2/x");
    assert_eq!(w("$DIR/${A}"), "/srv/a");
    assert_eq!(w("$UNSET"), "");
    assert_eq!(w("${UNSET}"), "");
}

#[test]
fn a_dollar_without_a_name_is_literal() {
    assert_eq!(w("$"), "$");
    assert_eq!(w("a$"), "a$");
    assert_eq!(w("$1"), "$1");
    assert_eq!(w("$$"), "$$");
    assert_eq!(w("$ a"), "$ a");
    assert_eq!(w("price: 5$"), "price: 5$");
    assert_eq!(w("\"$\""), "$");
}

#[test]
fn defaults_apply_when_unset_or_with_colon_when_empty() {
    assert_eq!(w("${A:-d}"), "a");
    assert_eq!(w("${UNSET:-d}"), "d");
    assert_eq!(w("${EMPTY:-d}"), "d");
    assert_eq!(w("${A-d}"), "a");
    assert_eq!(w("${UNSET-d}"), "d");
    assert_eq!(w("${EMPTY-d}"), "", "set, though empty: no default without the colon");
    assert_eq!(w("${UNSET:-}"), "");
}

#[test]
fn alternatives_apply_when_set_or_with_colon_when_not_empty() {
    assert_eq!(w("${A:+alt}"), "alt");
    assert_eq!(w("${UNSET:+alt}"), "");
    assert_eq!(w("${EMPTY:+alt}"), "");
    assert_eq!(w("${A+alt}"), "alt");
    assert_eq!(w("${UNSET+alt}"), "");
    assert_eq!(w("${EMPTY+alt}"), "alt", "set, though empty");
}

#[test]
fn required_variables_fail_with_their_message() {
    assert_eq!(w("${A:?need A}"), "a");
    assert_eq!(w("${A?need A}"), "a");
    assert_eq!(w("${EMPTY?no}"), "", "set, though empty: fine without the colon");
    let e = err("${UNSET:?set UNSET with --build-arg}");
    assert!(e.contains("UNSET: set UNSET with --build-arg"), "{e}");
    let e = err("${UNSET?}");
    assert!(e.contains("UNSET: is not allowed to be unset"), "{e}");
    let e = err("${EMPTY:?}");
    assert!(e.contains("EMPTY: is not allowed to be empty"), "{e}");
    let e = err("${UNSET:?$A is missing}");
    assert!(e.contains("UNSET: a is missing"), "the message is processed too: {e}");
}

#[test]
fn defaults_are_processed_and_nest() {
    assert_eq!(w("${UNSET:-$A}"), "a");
    assert_eq!(w("${UNSET:-${OTHER:-${A}}}"), "a");
    assert_eq!(w("${UNSET:-x}y"), "xy");
    assert_eq!(w("${UNSET:-'}'}"), "}", "a quoted brace doesn't close");
    assert_eq!(w(r"${UNSET:-a\}b}"), "a}b", "nor does an escaped one");
    assert_eq!(w("${UNSET:-\"q $A\"}"), "q a");
}

#[test]
fn single_quotes_keep_everything_literal() {
    assert_eq!(w("'$A'"), "$A");
    assert_eq!(w(r"'a\b'"), r"a\b");
    assert_eq!(w("'a \"b\" c'"), "a \"b\" c");
    assert_eq!(w("x'$A'y"), "x$Ay");
}

#[test]
fn double_quotes_expand_and_escape_only_some_characters() {
    assert_eq!(w("\"$A b\""), "a b");
    assert_eq!(w(r#""\$A""#), "$A");
    assert_eq!(w(r#""a\"b""#), "a\"b");
    assert_eq!(w(r#""a\\b""#), r"a\b");
    assert_eq!(w(r#""a\nb""#), r"a\nb", "other escapes stay as written");
    assert_eq!(w("\"it's\""), "it's");
    assert_eq!(w("\"a\\\nb\""), "a\nb", "an escaped newline is a newline");
}

#[test]
fn the_escape_character_makes_the_next_one_literal() {
    assert_eq!(w(r"\$A"), "$A");
    assert_eq!(w(r"a\ b"), "a b");
    assert_eq!(w(r#"\"x\""#), "\"x\"");
    assert_eq!(w(r"\'"), "'");
    assert_eq!(w(r"a\\b"), r"a\b");
    assert_eq!(w(r"a\b"), "ab");
    assert_eq!(w(r"trailing\"), "trailing", "a final escape character is dropped");
}

#[test]
fn a_backtick_escape_leaves_backslashes_alone() {
    let w = |raw: &str| word(raw, '`', &env).unwrap();
    assert_eq!(w(r"C:\Users\$A"), r"C:\Users\a");
    assert_eq!(w("`$A"), "$A");
    assert_eq!(w("\"a`\"b\""), "a\"b");
    assert_eq!(w(r#""a\""#), r"a\", "inside quotes too, the backslash is plain");
}

#[test]
fn word_keeps_whitespace_as_it_is() {
    assert_eq!(w("a  b"), "a  b");
    assert_eq!(w("$SPACED"), " x  y ");
    assert_eq!(w("  lead"), "  lead");
}

#[test]
fn malformed_input_is_an_error() {
    for (raw, wanted) in [
        ("'open", "unterminated single quote"),
        ("\"open", "unterminated double quote"),
        ("\"open\\\"", "unterminated double quote"),
        ("${A", "missing '}'"),
        ("${", "missing '}'"),
        ("${UNSET:-x", "missing '}'"),
        ("${UNSET:", "missing '}'"),
        ("${}", "bad substitution"),
        ("${1}", "bad substitution"),
        ("${:-x}", "bad substitution"),
        ("${A#a}", "unsupported modifier (#)"),
        ("${A%a}", "unsupported modifier (%)"),
        ("${A/a/b}", "unsupported modifier (/)"),
        ("${A:=x}", "unsupported modifier (:=)"),
        ("${A x}", "unsupported modifier ( )"),
    ] {
        let e = err(raw);
        assert!(e.contains(wanted), "{raw:?}: {e}");
        assert!(e.contains(&format!("{raw:?}")), "the message names the input: {e}");
    }
}

#[test]
fn words_split_at_unquoted_whitespace() {
    assert_eq!(ws("a b\t c"), ["a", "b", "c"]);
    assert_eq!(ws("  a  "), ["a"]);
    assert_eq!(ws(""), Vec::<String>::new());
    assert_eq!(ws("   "), Vec::<String>::new());
    assert_eq!(ws("\"a b\" c"), ["a b", "c"]);
    assert_eq!(ws("'a b' c"), ["a b", "c"]);
    assert_eq!(ws(r"a\ b c"), ["a b", "c"]);
    assert_eq!(ws("x\"y z\"w"), ["xy zw"]);
}

#[test]
fn unquoted_variables_split_into_words_and_quoted_ones_do_not() {
    assert_eq!(ws("$SPACED"), ["x", "y"]);
    assert_eq!(ws("a$SPACED"), ["a", "x", "y"]);
    assert_eq!(ws("\"$SPACED\""), [" x  y "]);
    assert_eq!(ws("${UNSET:-$SPACED}"), ["x", "y"]);
    assert_eq!(ws("\"${UNSET:-$SPACED}\""), [" x  y "]);
}

#[test]
fn a_default_keeps_its_own_quotes() {
    assert_eq!(ws("${UNSET:-\"a b\"} c"), ["a b", "c"]);
    assert_eq!(ws("${UNSET:-a b}"), ["a", "b"]);
    assert_eq!(ws("${A:+'x y'}"), ["x y"]);
}

#[test]
fn empty_expansions_and_empty_quotes_make_no_word() {
    assert_eq!(ws("$UNSET a"), ["a"]);
    assert_eq!(ws("$EMPTY"), Vec::<String>::new());
    assert_eq!(ws("a $UNSET b"), ["a", "b"]);
    assert_eq!(ws("\"\" a"), ["a"]);
    assert_eq!(ws("''"), Vec::<String>::new());
    assert_eq!(ws("x$UNSET"), ["x"]);
}

// Run in a child: a regression must not abort the whole test runner.
#[test]
fn deeply_nested_expansion_returns_an_error_without_aborting() {
    const CHILD: &str = "REVIEW_DEEP_EXPANSION_CHILD";
    const NAME: &str = "expand::tests::deeply_nested_expansion_returns_an_error_without_aborting";
    if std::env::var_os(CHILD).is_some() {
        let input = format!("{}x{}", "${A:-".repeat(20_000), "}".repeat(20_000));
        let worker = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || crate::expand::word(&input, '\\', &|_| None).map(|s| s.len()).map_err(|e| e.0.len()))
            .unwrap();
        let result = worker.join().unwrap();
        assert!(result.is_err(), "deep expansion must be refused");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([NAME, "--exact", "--test-threads=1", "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expanding 20 000 nested ${{A:-…}} ended the process: {} ({})",
        output.status,
        stderr.lines().find(|l| l.contains("overflow")).unwrap_or("")
    );
}
