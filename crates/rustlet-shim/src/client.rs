//! The daemon's side of `shim.sock`.

use std::io;
use std::path::Path;

use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::protocol::{ExitStatus, Frame, Request, Response, decode, read_frame, write_frame};

/// One connection to a shim.
#[derive(Debug)]
pub struct ShimClient {
    stream: UnixStream,
}

impl ShimClient {
    pub async fn connect(socket: &Path) -> io::Result<ShimClient> {
        Ok(ShimClient { stream: UnixStream::connect(socket).await? })
    }

    /// Sends `request` and reads its response.
    pub async fn call(&mut self, request: &Request) -> io::Result<Response> {
        write_frame(&mut self.stream, &Frame::request(request)).await?;
        match read_frame(&mut self.stream).await? {
            Some(Frame::Message(json)) => decode(&json),
            // Output can't arrive before a stream was asked for.
            Some(_) => Err(invalid("output frame before the response")),
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the shim closed the connection")),
        }
    }

    /// `Attach` or `Exec`: sends `request`; on `Ok`/`Started`, the connection
    /// becomes a [`ShimStream`].
    pub async fn open_stream(mut self, request: &Request) -> io::Result<(Response, Option<ShimStream>)> {
        let response = self.call(request).await?;
        match response {
            Response::Ok | Response::Started { .. } => {
                let (reader, writer) = self.stream.into_split();
                Ok((response, Some(ShimStream { reader, writer: StreamWriter { writer } })))
            }
            other => Ok((other, None)),
        }
    }
}

/// Connects, sends one request, returns its response.
pub async fn call(socket: &Path, request: &Request) -> io::Result<Response> {
    ShimClient::connect(socket).await?.call(request).await
}

/// What arrives on an attach or exec stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The process exited; nothing follows.
    Exited(ExitStatus),
}

/// An attach or exec session.
#[derive(Debug)]
pub struct ShimStream {
    reader: OwnedReadHalf,
    writer: StreamWriter,
}

impl ShimStream {
    /// The next output or the exit; `None` if the shim hung up without
    /// reporting an exit (it died).
    pub async fn recv(&mut self) -> io::Result<Option<StreamEvent>> {
        recv(&mut self.reader).await
    }

    pub fn writer(&mut self) -> &mut StreamWriter {
        &mut self.writer
    }

    /// Reading and writing from different tasks.
    pub fn split(self) -> (StreamReader, StreamWriter) {
        (StreamReader { reader: self.reader }, self.writer)
    }
}

/// The receiving half of a [`ShimStream`].
#[derive(Debug)]
pub struct StreamReader {
    reader: OwnedReadHalf,
}

impl StreamReader {
    pub async fn recv(&mut self) -> io::Result<Option<StreamEvent>> {
        recv(&mut self.reader).await
    }
}

async fn recv(reader: &mut OwnedReadHalf) -> io::Result<Option<StreamEvent>> {
    match read_frame(reader).await? {
        None => Ok(None),
        Some(Frame::Stdout(b)) => Ok(Some(StreamEvent::Stdout(b))),
        Some(Frame::Stderr(b)) => Ok(Some(StreamEvent::Stderr(b))),
        Some(Frame::Message(json)) => match decode(&json)? {
            Response::Exited(status) => Ok(Some(StreamEvent::Exited(status))),
            other => Err(invalid(&format!("unexpected message in a stream: {other:?}"))),
        },
        Some(Frame::Stdin(_)) => Err(invalid("stdin frame from the shim")),
    }
}

/// The sending half of a [`ShimStream`]: the process's input and terminal.
#[derive(Debug)]
pub struct StreamWriter {
    writer: OwnedWriteHalf,
}

impl StreamWriter {
    pub async fn stdin(&mut self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(crate::protocol::CHUNK) {
            write_frame(&mut self.writer, &Frame::Stdin(chunk.to_vec())).await?;
        }
        Ok(())
    }
    pub async fn close_stdin(&mut self) -> io::Result<()> {
        write_frame(&mut self.writer, &Frame::request(&Request::CloseStdin)).await
    }
    pub async fn resize(&mut self, rows: u16, cols: u16) -> io::Result<()> {
        write_frame(&mut self.writer, &Frame::request(&Request::Resize { rows, cols })).await
    }

    /// In an exec stream: a signal for the exec's process (the shim ignores
    /// it in an attach stream).
    pub async fn signal(&mut self, signal: i32) -> io::Result<()> {
        write_frame(&mut self.writer, &Frame::request(&Request::Kill { signal, all: false })).await
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}
