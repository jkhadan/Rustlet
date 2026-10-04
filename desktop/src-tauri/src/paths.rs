//! Paths the user types into a form: a build context, a compose file, an
//! archive to save or load.
//!
//! The CLI resolves a relative path against the shell's working directory,
//! and the shell has expanded `~` before the CLI sees it. The app has
//! neither: it is started from a launcher, and its working directory is
//! nobody's choice. So a path must be absolute, or start at the home
//! directory (`~`, `~/…`), which is expanded here as a shell would; a
//! relative one is refused rather than resolved against a directory the
//! user never chose.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{CommandError, CommandResult};

/// `typed`, as an absolute path.
pub fn user_path(typed: &str) -> CommandResult<PathBuf> {
    user_path_in(typed, std::env::var_os("HOME"))
}

/// [`user_path`] with `home` for `$HOME`.
fn user_path_in(typed: &str, home: Option<OsString>) -> CommandResult<PathBuf> {
    // A path pasted from a terminal often brings a space or a newline.
    let t = typed.trim();
    if t.is_empty() {
        return Err(CommandError::invalid("give a path"));
    }
    let path = match t.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            let home = home
                .filter(|h| !h.is_empty())
                .ok_or_else(|| CommandError::invalid(format!("{t}: HOME isn't set, so ~ names no directory")))?;
            let mut path = PathBuf::from(home);
            let rest = rest.trim_start_matches('/');
            if !rest.is_empty() {
                path.push(rest);
            }
            path
        }
        // `~user` isn't expanded: it stays relative, and is refused below.
        _ => PathBuf::from(t),
    };
    if !path.is_absolute() {
        return Err(CommandError::invalid(format!(
            "{t}: give an absolute path, or one from ~/ (the app has no working directory to start a relative one from)"
        )));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Option<OsString> {
        Some("/home/u".into())
    }

    #[test]
    fn absolute_paths_stay_as_typed_less_the_spaces_around_them() {
        assert_eq!(user_path_in(" /srv/app/compose.yaml\n", home()).unwrap(), PathBuf::from("/srv/app/compose.yaml"));
    }

    #[test]
    fn a_tilde_is_the_home_directory_as_in_a_shell() {
        assert_eq!(user_path_in("~", home()).unwrap(), PathBuf::from("/home/u"));
        assert_eq!(user_path_in("~/src/hits", home()).unwrap(), PathBuf::from("/home/u/src/hits"));
        assert_eq!(user_path_in("~//x", home()).unwrap(), PathBuf::from("/home/u/x"));
        let e = user_path_in("~/x", None).unwrap_err();
        assert_eq!(e.kind, "invalid");
        assert!(e.message.contains("HOME"), "{e:?}");
    }

    #[test]
    fn relative_paths_are_refused_not_resolved_against_the_apps_directory() {
        for typed in ["src/app", "./compose.yaml", "../x", "~other/x"] {
            let e = user_path_in(typed, home()).unwrap_err();
            assert_eq!(e.kind, "invalid", "{typed}");
            assert!(e.message.starts_with(typed), "{e:?}");
        }
        assert_eq!(user_path_in("  ", home()).unwrap_err().message, "give a path");
    }
}
