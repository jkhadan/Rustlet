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
use std::sync::{Arc, Mutex, PoisonError};
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
    failure: ReadFailure,
}

/// Why the reader behind a [`RequestBody::from_reader`] body failed, if a
/// read of it did: not a write that failed because the request had ended.
/// The body then fails the request, and what the connection says of that
/// ("connection error") names no cause; whoever sends the body asks this
/// once the request has failed, to tell the user what went wrong instead.
#[derive(Debug, Clone, Default)]
pub struct ReadFailure(Arc<Mutex<Option<(io::ErrorKind, String)>>>);

impl ReadFailure {
    /// The failed read's error, if one failed.
    pub fn error(&self) -> Option<io::Error> {
        let failed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        failed.as_ref().map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn note(&self, error: &io::Error) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some((error.kind(), error.to_string()));
    }
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBody").finish_non_exhaustive()
    }
}

impl RequestBody {
    /// The bytes of `stream`, as they come.
    pub fn from_stream(stream: impl Stream<Item = io::Result<Bytes>> + Send + 'static) -> RequestBody {
        RequestBody { stream: stream.boxed(), failure: ReadFailure::default() }
    }

    /// What went wrong reading, for a body made by
    /// [`from_reader`](Self::from_reader); nothing for any other. Taken
    /// before the body is sent, asked after the request has failed.
    pub fn read_failure(&self) -> ReadFailure {
        self.failure.clone()
    }

    /// `bytes`, all at once.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> RequestBody {
        let bytes = bytes.into();
        RequestBody::from_stream(futures::stream::once(async move { Ok(bytes) }))
    }

    /// Everything `reader` reads, read on a blocking thread (a file, the
    /// process's stdin). A read that fails fails the request, and is noted
    /// in [`read_failure`](Self::read_failure); a write that fails means
    /// the request has ended, which is its own failure to report.
    pub fn from_reader(mut reader: impl Read + Send + 'static) -> RequestBody {
        let (mut body, mut writer) = RequestBody::pipe();
        let failure = ReadFailure::default();
        body.failure = failure.clone();
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0; CHUNK];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        // A failure here is the request's, which reports it.
                        let _ = writer.finish();
                        return;
                    }
                    Ok(n) => {
                        if writer.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        failure.note(&e);
                        writer.abort(e);
                        return;
                    }
                }
            }
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

    /// A reader that hands out `data` bytes, then fails.
    struct FailsAfter {
        data: usize,
    }

    impl Read for FailsAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data == 0 {
                return Err(io::Error::other("Input/output error"));
            }
            let n = buf.len().min(self.data);
            buf[..n].fill(1);
            self.data -= n;
            Ok(n)
        }
    }

    /// Expected (the docs of `from_reader`: "a read that fails fails the
    /// request, and is noted in `read_failure`"): the body ends with the
    /// reader's error, which is noted before the request can see it.
    #[tokio::test]
    async fn a_reader_that_fails_fails_the_body_and_is_noted() {
        let body = RequestBody::from_reader(FailsAfter { data: 100 });
        let failure = body.read_failure();
        assert!(failure.error().is_none(), "nothing failed yet");
        let items: Vec<io::Result<Bytes>> = body.stream.collect().await;
        assert_eq!(items.last().unwrap().as_ref().unwrap_err().to_string(), "Input/output error");
        let noted = failure.error().expect("the failure is noted");
        assert_eq!((noted.kind(), noted.to_string()), (io::ErrorKind::Other, "Input/output error".to_owned()));
    }

    /// Expected: a write that fails because the request has ended is the
    /// request's failure, not the reader's: nothing is noted.
    #[tokio::test]
    async fn a_request_that_ended_is_not_the_readers_failure() {
        struct Endless(std::sync::mpsc::Sender<()>);
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                buf.fill(7);
                Ok(buf.len())
            }
        }
        impl Drop for Endless {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let (stopped, wait) = std::sync::mpsc::channel();
        let body = RequestBody::from_reader(Endless(stopped));
        let failure = body.read_failure();
        drop(body);
        let waited = tokio::task::spawn_blocking(move || wait.recv_timeout(std::time::Duration::from_secs(5))).await;
        waited.unwrap().expect("the reader's thread stops once the request is gone");
        assert!(failure.error().is_none(), "{:?}", failure.error());
    }

    /// Expected (`io::copy` and every reader loop retry `Interrupted`): a
    /// read that was interrupted is read again, and is no failure.
    #[tokio::test]
    async fn an_interrupted_read_is_tried_again_and_is_no_failure() {
        struct Flaky {
            interrupted: bool,
            left: usize,
        }
        impl Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !std::mem::replace(&mut self.interrupted, true) {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let n = buf.len().min(self.left);
                self.left -= n;
                Ok(n)
            }
        }
        let body = RequestBody::from_reader(Flaky { interrupted: false, left: 10 });
        let failure = body.read_failure();
        let all: Vec<u8> = body.stream.map(|c| c.unwrap()).collect::<Vec<_>>().await.concat();
        assert_eq!(all.len(), 10);
        assert!(failure.error().is_none());
    }

    #[tokio::test]
    async fn a_reader_is_read_to_its_end() {
        let body = RequestBody::from_reader(io::Cursor::new(vec![7u8; CHUNK + 10]));
        let all: Vec<u8> = body.stream.map(|c| c.unwrap()).collect::<Vec<_>>().await.concat();
        assert_eq!(all.len(), CHUNK + 10);
    }
}
