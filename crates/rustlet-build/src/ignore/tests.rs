use super::*;

fn rules(text: &str) -> IgnoreRules {
    IgnoreRules::parse(text).unwrap_or_else(|e| panic!("{text:?}: {e}"))
}

/// One pattern against one path, as `patternmatcher`'s
/// `MatchesOrParentMatches` tests do.
fn excluded(pattern: &str, path: &str) -> bool {
    rules(pattern).excludes(path)
}

#[test]
fn patternmatcher_cases() {
    // moby/patternmatcher's TestMatches, less the paths with a trailing
    // slash (a walk never asks for one).
    for (pattern, path, matches) in [
        ("**", "file", true),
        ("**/", "file", true),
        ("**", "dir/file", true),
        ("**/", "dir/file", true),
        ("**/**", "dir/file", true),
        ("dir/**", "dir/file", true),
        ("dir/**", "dir/dir2/file", true),
        ("**/dir", "dir", true),
        ("**/dir", "dir/file", true),
        ("**/dir2/*", "dir/dir2/file", true),
        ("**/dir2/**", "dir/dir2/dir3/file", true),
        ("**file", "file", true),
        ("**file", "dir/file", true),
        ("**/file", "dir/file", true),
        ("**file", "dir/dir/file", true),
        ("**/file", "dir/dir/file", true),
        ("**/file*", "dir/dir/file", true),
        ("**/file*", "dir/dir/file.txt", true),
        ("**/file*txt", "dir/dir/file.txt", true),
        ("**/file*.txt", "dir/dir/file.txt", true),
        ("**/file*.txt*", "dir/dir/file.txt", true),
        ("**/**/*.txt", "dir/dir/file.txt", true),
        ("**/**/*.txt2", "dir/dir/file.txt", false),
        ("**/*.txt", "file.txt", true),
        ("**/**/*.txt", "file.txt", true),
        ("a**/*.txt", "a/file.txt", true),
        ("a**/*.txt", "a/dir/file.txt", true),
        ("a**/*.txt", "a/dir/dir/file.txt", true),
        ("a/*.txt", "a/dir/file.txt", false),
        ("a/*.txt", "a/file.txt", true),
        ("a/*.txt**", "a/file.txt", true),
        ("a[b-d]e", "ae", false),
        ("a[b-d]e", "ace", true),
        ("a[b-d]e", "aae", false),
        ("a[^b-d]e", "aze", true),
        (".*", ".foo", true),
        (".*", "foo", false),
        ("abc.def", "abcdef", false),
        ("abc.def", "abc.def", true),
        ("abc.def", "abcZdef", false),
        ("abc?def", "abcZdef", true),
        ("abc?def", "abcdef", false),
        ("a\\\\", "a\\", true),
        ("**/foo/bar", "foo/bar", true),
        ("**/foo/bar", "dir/foo/bar", true),
        ("**/foo/bar", "dir/dir2/foo/bar", true),
        ("abc/**", "abc", false),
        ("abc/**", "abc/def", true),
        ("abc/**", "abc/def/ghi", true),
        ("**/.foo", ".foo", true),
        ("**/.foo", "bar.foo", false),
        ("a(b)c/def", "a(b)c/def", true),
        ("a(b)c/def", "a(b)c/xyz", false),
        ("a.|)$(}+{bc", "a.|)$(}+{bc", true),
        (
            "dist/proxy.py-2.4.0rc3.dev36+g08acad9-py3-none-any.whl",
            "dist/proxy.py-2.4.0rc3.dev36+g08acad9-py3-none-any.whl",
            true,
        ),
        ("dist/*.whl", "dist/proxy.py-2.4.0rc3.dev36+g08acad9-py3-none-any.whl", true),
    ] {
        assert_eq!(excluded(pattern, path), matches, "{pattern:?} against {path:?}");
    }
}

#[test]
fn patternmatcher_multi_pattern_cases() {
    for (patterns, path, matches) in [
        (&["**", "!util/docker/web"][..], "util/docker/web/foo", false),
        (&["**", "!util/docker/web", "util/docker/web/foo"][..], "util/docker/web/foo", true),
        (
            &["**", "!dist/proxy.py-2.4.0rc3.dev36+g08acad9-py3-none-any.whl"][..],
            "dist/proxy.py-2.4.0rc3.dev36+g08acad9-py3-none-any.whl",
            false,
        ),
        (&["**", "!dist/*.whl"][..], "dist/proxy.py-2.4.0rc3.dev36+g08acad9-py3-none-any.whl", false),
    ] {
        assert_eq!(rules(&patterns.join("\n")).excludes(path), matches, "{patterns:?} against {path:?}");
    }
}

#[test]
fn quirks_of_a_leading_double_star_are_kept() {
    assert!(excluded("**foo", "barfoo"), "**text is a suffix match");
    assert!(!excluded("**/foo", "barfoo"));
    assert!(excluded("**", "anything/at/all"));
}

#[test]
fn a_directory_pattern_excludes_everything_below_it() {
    let r = rules("target\nnode_modules/\n/secret\n");
    for path in ["target", "target/debug/app", "node_modules", "node_modules/x/y.js", "secret", "secret/key"] {
        assert!(r.excludes(path), "{path}");
    }
    for path in ["targets", "src/target", "src/node_modules", "secrets", "a/secret"] {
        assert!(!r.excludes(path), "{path}");
    }
}

#[test]
fn wildcards_stay_within_one_component() {
    let r = rules("*.log\ndocs/*.md\n?.tmp\n");
    assert!(r.excludes("app.log"));
    assert!(!r.excludes("logs/app.log"), "* doesn't cross /");
    assert!(r.excludes("docs/readme.md"));
    assert!(!r.excludes("docs/api/readme.md"));
    assert!(r.excludes("a.tmp"));
    assert!(!r.excludes("ab.tmp"));
    assert!(!r.excludes("/.tmp"));
    let r = rules("**/*.log");
    assert!(r.excludes("app.log") && r.excludes("a/b/c/app.log"));
}

#[test]
fn the_last_matching_pattern_decides() {
    let r = rules("*.md\n!README.md\nREADME.md\n!docs\n");
    assert!(r.excludes("CHANGES.md"));
    assert!(r.excludes("README.md"), "excluded again after the exception");
    let r = rules("*.md\n!README.md\n");
    assert!(!r.excludes("README.md"));
    assert!(r.excludes("CHANGES.md"));
}

#[test]
fn an_exception_includes_a_directory_below_an_excluded_one() {
    let r = rules("node_modules\n!node_modules/keep\n");
    assert!(r.excludes("node_modules"));
    assert!(r.excludes("node_modules/other/x"));
    assert!(!r.excludes("node_modules/keep"));
    assert!(!r.excludes("node_modules/keep/index.js"), "an exception's parent match includes again too");
}

#[test]
fn everything_but_some_paths() {
    let r = rules("*\n!src\n!Containerfile\n");
    assert!(r.excludes("target") && r.excludes("README.md") && r.excludes(".git"));
    assert!(!r.excludes("src") && !r.excludes("src/main.rs") && !r.excludes("Containerfile"));
}

#[test]
fn comments_blank_lines_and_whitespace() {
    let r = rules("# a comment\n\n   \n  spaced  \n  # not a comment\n");
    assert!(r.excludes("spaced"));
    assert!(r.excludes("# not a comment"), "# is a comment only in the first column");
    assert!(!r.excludes("a comment") && !r.excludes("# a comment"));
    assert!(rules("\u{feff}# bom\nfile\n").excludes("file"));
    assert!(!rules("\u{feff}# bom\nfile\n").excludes("# bom"), "a byte order mark is not part of the line");
}

#[test]
fn patterns_are_cleaned_and_relative_to_the_context() {
    let r = rules("/abs/path\n./dot/./x\na//b/\nc/../d\n! /negated/abs\n");
    for path in ["abs/path", "dot/x", "a/b", "d"] {
        assert!(r.excludes(path), "{path}");
    }
    assert!(!r.excludes("c"));
    assert!(!rules("*\n! /negated/abs\n").excludes("negated/abs"));
    assert!(!rules("/").excludes("anything"), "/ alone matches no context path");
}

#[test]
fn escapes_make_wildcards_literal() {
    let r = rules("a\\*b\nq\\?\n");
    assert!(r.excludes("a*b"));
    assert!(!r.excludes("axb"));
    assert!(r.excludes("q?"));
    assert!(!r.excludes("qx"));
    assert!(rules("[[]x").excludes("[x"));
    assert!(rules("x[\\]]").excludes("x]"));
}

#[test]
fn backslashes_have_patternmatchers_regex_semantics() {
    for pattern in [r"docs\images", r"build\output", r"secrets\keys"] {
        let error = IgnoreRules::parse(pattern).unwrap_err();
        assert!(error.contains("syntax error in pattern"), "{error}");
    }
    for (pattern, path, matches) in [
        (r"file\d", "file7", true),
        (r"file\d", "filed", false),
        (r"file\d", "file٧", false),
        (r"file[\d]", "file7", true),
        (r"file[\d]", "filed", false),
        (r"a\b", "a", true),
        (r"a\b", "ab", false),
        (r"x\s", "x\t", true),
        (r"x\s", "x\u{a0}", false),
        (r"x\w", "x_", true),
        (r"x\w", "xé", false),
        (r"\123", "S", true),
    ] {
        assert_eq!(excluded(pattern, path), matches, "{pattern:?} against {path:?}");
    }
}

#[test]
fn malformed_patterns_are_errors_with_their_line() {
    for (text, line) in
        [("[", 1), ("ok\n[^", 2), ("a[]b", 1), ("[a-", 1), ("[a-]", 1), ("[-a]", 1), ("trailing\\", 1), ("x\n\n!", 3)]
    {
        let e = IgnoreRules::parse(text).expect_err(text);
        assert!(e.starts_with(&format!("line {line}: ")), "{text:?}: {e}");
    }
    assert!(IgnoreRules::parse("!").unwrap_err().contains("\"!\" alone"));
    assert!(IgnoreRules::parse("[a-z]\n[^0-9]x\n[\\-]").is_ok());
}

#[test]
fn no_rules_exclude_nothing() {
    let r = IgnoreRules::default();
    assert!(!r.excludes("anything") && !r.may_include_below("anything"));
    assert_eq!(rules("# only comments\n\n"), IgnoreRules::default());
}

#[test]
fn may_include_below_looks_for_exceptions_that_reach_into_a_directory() {
    let r = rules("node_modules\n!node_modules/keep/package.json\n*.log\n");
    assert!(r.may_include_below("node_modules"));
    assert!(!r.may_include_below("target"));
    assert!(!r.may_include_below("node_modules_old"));
    let r = rules("*\n!src\n!docs/*.md\n");
    assert!(r.may_include_below("docs"));
    assert!(!r.may_include_below("target"));
    assert!(r.may_include_below("src/sub"), "an exception for a parent: conservative");
    let r = rules("*\n!**/keep\n");
    assert!(r.may_include_below("anything/at/all"), "a wildcard at the start could match anywhere");
    let r = rules("build\n!build*.txt\n");
    assert!(r.may_include_below("build"));
    assert!(!rules("target\n").may_include_below("target"), "no exception: nothing to look for");
}

#[test]
fn a_pathological_pattern_is_still_quick() {
    let r = rules("*a*a*a*a*a*a*a*a*a*a*b");
    let path = "a".repeat(200);
    assert!(!r.excludes(&path));
    let r = rules("**/**/**/**/**/**/x");
    let deep = vec!["d"; 100].join("/");
    assert!(!r.excludes(&deep));
    assert!(r.excludes(&format!("{deep}/x")));
}

#[test]
fn the_ignore_file_next_to_the_containerfile_wins() {
    let dir = tempfile::tempdir().unwrap();
    let context = dir.path();
    let containerfile = context.join("docker/app.Containerfile");
    std::fs::create_dir(context.join("docker")).unwrap();
    std::fs::write(&containerfile, "FROM a\n").unwrap();
    assert_eq!(ignore_file(context, &containerfile), None);
    std::fs::write(context.join(".dockerignore"), "x").unwrap();
    assert_eq!(ignore_file(context, &containerfile), Some(context.join(".dockerignore")));
    std::fs::write(context.join(".containerignore"), "x").unwrap();
    assert_eq!(ignore_file(context, &containerfile), Some(context.join(".containerignore")));
    std::fs::write(context.join("docker/app.Containerfile.dockerignore"), "x").unwrap();
    assert_eq!(ignore_file(context, &containerfile), Some(context.join("docker/app.Containerfile.dockerignore")));
    std::fs::remove_file(context.join(".containerignore")).unwrap();
    std::fs::create_dir(context.join(".containerignore")).unwrap();
    std::fs::remove_file(context.join("docker/app.Containerfile.dockerignore")).unwrap();
    assert_eq!(ignore_file(context, &containerfile), Some(context.join(".dockerignore")), "a directory isn't a file");
}
