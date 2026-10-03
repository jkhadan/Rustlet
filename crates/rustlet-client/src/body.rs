//! Bodies that are streamed rather than held whole: a request body sent as
//! it is produced ([`RequestBody`]: a build context being packed, an
//! archive being read from disk), and a response body handed over as it
//! arrives ([`ByteStream`]: `save`'s archive).
//!
//! A build context can be gigabytes, and is packed by blocking code (the
//! `tar` crate writes to a `std::io::Write`), so [`RequestBody::pipe`]
//! joins the two worlds: the packer writes into a [`BodyWriter`] on a
//! blocking thread, and each 64 KiB it fills crosses a bounded channel to
//! the connection, which sends it. The bound makes the packer wait for the
//! network instead of filling memory; a request that fails makes the
//! writer's next write fail (`BrokenPipe`), which stops the packer.

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::stream::{BoxStream, Stream, StreamExt};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/// How much a [`BodyWriter`] gathers before sending it.
const CHUNK: usize = 64 * 1024;
/// Chunks in flight between a writer and the connection.
const IN_FLIGHT: usize = 8;

/// A request body sent as it is produced. An `Err` item fails the request.
pub struct RequestBody {
    pub(crate) stream: BoxStream<'static, io::Result<Bytes>>,
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBody").finish_non_exhaustive()
    }
}

impl RequestBody {
    /// The bytes of `stream`, as they come.
    pub fn from_stream(stream: impl Stream<Item = io::Result<Bytes>> + Send + 'static) -> RequestBody {
        RequestBody { stream: stream.boxed() }
    }

    /// `bytes`, all at once.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> RequestBody {
        let bytes = bytes.into();
        RequestBody::from_stream(futures::stream::once(async move { Ok(bytes) }))
    }

    /// Everything `reader` reads, read on a blocking thread (a file, the
    /// process's stdin).
    pub fn from_reader(mut reader: impl Read + Send + 'static) -> RequestBody {
        let (body, mut writer) = RequestBody::pipe();
        tokio::task::spawn_blocking(move || match io::copy(&mut reader, &mut writer) {
            Ok(_) => {
                // A failure here is the request's, which reports it.
                let _ = writer.finish();
            }
            Err(e) => writer.abort(e),
        });
        body
    }

    /// A body and the writer that produces it. The writer is for blocking
    /// code: use it on a blocking thread (`tokio::task::spawn_blocking`),
    /// never on an async one, where its waiting would stall the runtime
    /// (tokio panics). The body ends when the writer is
    /// [finished](BodyWriter::finish); [`abort`](BodyWriter::abort) fails
    /// the request instead, and so does a writer dropped without either, so
    /// that a body cut short never passes for a whole one.
    pub fn pipe() -> (RequestBody, BodyWriter) {
        let (tx, rx) = mpsc::channel(IN_FLIGHT);
        let stream = futures::stream::unfold(Some(rx), |rx| async move {
            let mut rx = rx?;
            match rx.recv().await {
                Some(Piece::Data(bytes)) => Some((Ok(bytes), Some(rx))),
                Some(Piece::Failed(e)) => Some((Err(e), None)),
                Some(Piece::End) => None,
                None => {
                    Some((Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the body's writer stopped early")), None))
                }
            }
        });
        (RequestBody::from_stream(stream), BodyWriter { tx: Some(tx), buf: Vec::with_capacity(CHUNK) })
    }
}

/// What crosses a pipe.
enum Piece {
    Data(Bytes),
    Failed(io::Error),
    End,
}

/// The writing end of [`RequestBody::pipe`].
pub struct BodyWriter {
    tx: Option<mpsc::Sender<Piece>>,
    buf: Vec<u8>,
}

impl BodyWriter {
    /// Sends what is buffered and ends the body.
    pub fn finish(mut self) -> io::Result<()> {
        self.send_buffered()?;
        let tx = self.tx.take().expect("not finished yet");
        tx.blocking_send(Piece::End).map_err(|_| gone())
    }

    /// Ends the body with an error: the request fails.
    pub fn abort(mut self, error: io::Error) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.blocking_send(Piece::Failed(error));
        }
    }

    fn send_buffered(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK)));
        let tx = self.tx.as_ref().ok_or_else(gone)?;
        tx.blocking_send(Piece::Data(chunk)).map_err(|_| gone())
    }
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the request is no longer being sent")
}

impl Write for BodyWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.tx.is_none() {
            return Err(gone());
        }
        let n = data.len().min(CHUNK - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == CHUNK {
            self.send_buffered()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffered()
    }
}

/// A response body, chunk by chunk as it arrives. Dropping it hangs up.
pub struct ByteStream {
    inner: BoxStream<'static, Result<Bytes>>,
}

impl ByteStream {
    pub(crate) fn new(body: Incoming) -> ByteStream {
        let inner = futures::stream::unfold(body, |mut body| async move {
            loop {
                match body.frame().await? {
                    Ok(frame) => {
                        if let Ok(data) = frame.into_data() {
                            return Some((Ok(data), body));
                        }
                    }
                    Err(e) => return Some((Err(Error::from(e)), body)),
                }
            }
        });
        ByteStream { inner: inner.boxed() }
    }
}

impl Stream for ByteStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes>>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl std::fmt::Debug for ByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByteStream").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_pipe_carries_what_is_written_in_chunks() {
        let (body, mut writer) = RequestBody::pipe();
        let writing = tokio::task::spawn_blocking(move || {
            for i in 0..3 * CHUNK / 1000 {
                writer.write_all(format!("{:0999}\n", i).as_bytes()).unwrap();
            }
            writer.finish()
        });
        let chunks: Vec<Bytes> = body.stream.map(|c| c.unwrap()).collect().await;
        writing.await.unwrap().unwrap();
        assert!(chunks.iter().all(|c| c.len() <= CHUNK));
        let all: Vec<u8> = chunks.concat();
        assert_eq!(all.len(), 3 * CHUNK / 1000 * 1000);
        assert!(all.starts_with(b"000"));
    }

    #[tokio::test]
    async fn an_abort_fails_the_body_and_a_gone_reader_stops_the_writer() {
        let (body, mut writer) = RequestBody::pipe();
        let writing = tokio::task::spawn_blocking(move || {
            writer.write_all(b"partial").unwrap();
            writer.flush().unwrap();
            writer.abort(io::Error::other("a file vanished"));
        });
        let items: Vec<io::Result<Bytes>> = body.stream.collect().await;
        writing.await.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].as_ref().unwrap_err().to_string(), "a file vanished");

        let (body, mut writer) = RequestBody::pipe();
        drop(body);
        let e = tokio::task::spawn_blocking(move || writer.write_all(&vec![0; 2 * CHUNK])).await.unwrap().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn a_writer_dropped_unfinished_fails_the_body() {
        let (body, mut writer) = RequestBody::pipe();
        tokio::task::spawn_blocking(move || {
            writer.write_all(b"half").unwrap();
            writer.flush().unwrap();
        })
        .await
        .unwrap();
        let items: Vec<io::Result<Bytes>> = body.stream.collect().await;
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].as_ref().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_reader_is_read_to_its_end() {
        let body = RequestBody::from_reader(io::Cursor::new(vec![7u8; CHUNK + 10]));
        let all: Vec<u8> = body.stream.map(|c| c.unwrap()).collect::<Vec<_>>().await.concat();
        assert_eq!(all.len(), CHUNK + 10);
    }
}
