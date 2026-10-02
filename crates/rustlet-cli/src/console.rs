//! The CLI's standard streams, as values.
//!
//! Commands print through a [`Console`] rather than with `println!`, for
//! two reasons. The tests run the real command code in-process against a
//! mock daemon, with buffers in place of the terminal, and read back what
//! was printed. And the relay of an attached session takes stdin away into
//! a reader thread of its own, which a global can't express.
//!
//! Writes are plain blocking `std::io` writes, also from async code: a
//! terminal or pipe that can't keep up slows the session down, which is
//! the backpressure wanted, and the runtime has other threads for the rest.

use std::io::{self, IsTerminal, Read, Write};

use anyhow::bail;

/// Standard input, output and error, and whether each is a terminal.
pub struct Console {
    /// Taken by the first session that forwards input.
    pub stdin: Option<Box<dyn Read + Send>>,
    pub stdout: Box<dyn Write + Send>,
    pub stderr: Box<dyn Write + Send>,
    pub stdin_tty: bool,
    pub stdout_tty: bool,
    pub stderr_tty: bool,
}

impl Console {
    /// The process's own streams.
    pub fn system() -> Console {
        Console {
            stdin: Some(Box::new(io::stdin())),
            stdout: Box::new(io::stdout()),
            stderr: Box::new(io::stderr()),
            stdin_tty: io::stdin().is_terminal(),
            stdout_tty: io::stdout().is_terminal(),
            stderr_tty: io::stderr().is_terminal(),
        }
    }

    /// Docker's confirmation: `question` and ` [y/N] ` on stdout, then a
    /// line of stdin as the answer, whatever stdin is (`echo y | …` answers
    /// too). `y` or `Y` is a yes, any other answer (an empty line too) a
    /// no. Input that ends before any answer (a script without `-f`, with
    /// nobody to ask) is an error, where Docker takes a quiet no: a script
    /// can't then mistake a prune that never happened for one that found
    /// nothing.
    pub async fn confirm(&mut self, question: &str) -> anyhow::Result<bool> {
        write!(self.stdout, "{question} [y/N] ")?;
        self.stdout.flush()?;
        let answer = match self.stdin.take() {
            Some(mut stdin) => {
                // A blocking read, off the runtime's threads.
                let (stdin, answer) = tokio::task::spawn_blocking(move || {
                    let answer = read_line(&mut *stdin);
                    (stdin, answer)
                })
                .await?;
                self.stdin = Some(stdin);
                answer?
            }
            None => String::new(),
        };
        // Only a terminal echoes the answer, and its newline: otherwise the
        // question's line is still open.
        if !(self.stdin_tty && answer.ends_with('\n')) {
            writeln!(self.stdout)?;
        }
        if answer.is_empty() {
            bail!("no answer on stdin, so nothing was done (-f goes ahead without asking)");
        }
        Ok(answer.trim().eq_ignore_ascii_case("y"))
    }
}

/// Input up to and with the first newline, or to its end: read a byte at a
/// time, so that nothing after the line is taken from whoever reads next.
fn read_line(input: &mut dyn Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0];
    while line.last() != Some(&b'\n') {
        match input.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

#[cfg(test)]
pub mod testing {
    //! Buffers to stand in for the terminal.

    use std::sync::{Arc, Mutex};

    use super::*;

    /// A writer whose bytes can be read back while it is still in use.
    #[derive(Clone, Default)]
    pub struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A console that reads `stdin` and writes into the returned buffers;
    /// nothing is a terminal.
    pub fn console(stdin: &[u8]) -> (Console, Buffer, Buffer) {
        let (stdout, stderr) = (Buffer::default(), Buffer::default());
        let console = Console {
            stdin: Some(Box::new(io::Cursor::new(stdin.to_vec()))),
            stdout: Box::new(stdout.clone()),
            stderr: Box::new(stderr.clone()),
            stdin_tty: false,
            stdout_tty: false,
            stderr_tty: false,
        };
        (console, stdout, stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::console;
    use super::*;

    #[tokio::test]
    async fn a_confirmation_takes_one_line() {
        let (mut c, stdout, _) = console(b"Y\nmore input\n");
        // As if typed: the terminal has echoed the answer and its newline.
        c.stdin_tty = true;
        assert!(c.confirm("Sure?").await.unwrap());
        assert_eq!(stdout.text(), "Sure? [y/N] ");
        // What follows the line is still there for the next reader.
        let mut rest = String::new();
        c.stdin.take().unwrap().read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "more input\n");

        // Ctrl-D on a terminal: no answer, and the line ends here.
        let (mut c, stdout, _) = console(b"");
        c.stdin_tty = true;
        let e = c.confirm("Sure?").await.unwrap_err();
        assert!(e.to_string().starts_with("no answer on stdin"), "{e}");
        assert_eq!(stdout.text(), "Sure? [y/N] \n");

        // An answer without a newline, at the end of piped input.
        let (mut c, stdout, _) = console(b" y ");
        assert!(c.confirm("Sure?").await.unwrap());
        assert_eq!(stdout.text(), "Sure? [y/N] \n");
    }
}
