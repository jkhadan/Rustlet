//! Lexical path cleaning, as Go's `path.Clean`: what Docker does to
//! `.dockerignore` patterns and to `WORKDIR`.

/// `a//b/./c/..` → `a/b`; `/../a` → `/a`; `a/..` → `.`; never a trailing
/// `/` except for `/` itself. Nothing on disk is looked at.
pub(crate) fn clean(path: &str) -> String {
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&last) if last != ".." => {
                    parts.pop();
                }
                // `..` above the root is the root; above a relative start it stays.
                _ if rooted => {}
                _ => parts.push(".."),
            },
            part => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::clean;

    #[test]
    fn paths_are_cleaned_as_go_cleans_them() {
        for (path, cleaned) in [
            ("", "."),
            (".", "."),
            ("/", "/"),
            ("//", "/"),
            ("a/b", "a/b"),
            ("a//b/", "a/b"),
            ("./a/./b/.", "a/b"),
            ("a/b/../c", "a/c"),
            ("a/..", "."),
            ("../a", "../a"),
            ("a/../../b", "../b"),
            ("/../a", "/a"),
            ("/a/../..", "/"),
            ("/app/", "/app"),
        ] {
            assert_eq!(clean(path), cleaned, "{path:?}");
        }
    }
}
