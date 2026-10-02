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
