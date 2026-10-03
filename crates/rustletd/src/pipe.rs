//! Bodies that are streamed between blocking code and HTTP: an archive
//! written by `rustlet_image::archive::save` (a `std::io::Write`) going out
//! as a response, and a request body (a build context, an archive to load)
//! read by the tar crate (a `std::io::Read`), each on a blocking thread.
//!
//! A response written this way can fail half-way: once it has started, its
//! status can't change, so the stream's last item is an error, which makes
//! hyper end the connection without the chunked body's final chunk. The
//! client then sees an incomplete body, never a short archive that looks
//! whole; so does a writer that stops without [`ChannelWriter::finish`].

use std::io::{self, Read, Write};

use axum::body::Body;
use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use tokio::sync::mpsc;

const CHUNK: usize = 64 * 1024;
const IN_FLIGHT: usize = 8;

/// What crosses the channel.
enum Piece {
    Data(Bytes),
    Failed(io::Error),
    End,
}

/// The writing end of [`channel`]; for a blocking thread.
pub struct ChannelWriter {
    tx: Option<mpsc::Sender<Piece>>,
    buf: Vec<u8>,
}

/// A writer for a blocking thread and the stream of what it writes, for a
/// response body.
pub fn channel() -> (ChannelWriter, impl Stream<Item = io::Result<Bytes>> + Send + 'static) {
    let (tx, rx) = mpsc::channel(IN_FLIGHT);
    let stream = futures::stream::unfold(Some(rx), |rx| async move {
        let mut rx = rx?;
        match rx.recv().await {
            Some(Piece::Data(b)) => Some((Ok(b), Some(rx))),
            Some(Piece::Failed(e)) => Some((Err(e), None)),
            Some(Piece::End) => None,
            None => Some((Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the writer stopped early")), None)),
        }
    });
    (ChannelWriter { tx: Some(tx), buf: Vec::with_capacity(CHUNK) }, stream)
}

impl ChannelWriter {
    /// Sends the rest and ends the stream.
    pub fn finish(mut self) -> io::Result<()> {
        self.send_buffered()?;
        let tx = self.tx.take().expect("not finished yet");
        tx.blocking_send(Piece::End).map_err(|_| gone())
    }

    /// Ends the stream with `error`.
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
    io::Error::new(io::ErrorKind::BrokenPipe, "the client went away")
}

impl Write for ChannelWriter {
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

/// A request body as a blocking reader: create it in the handler (it takes
/// the runtime's handle), read it on a blocking thread.
pub fn reader(body: Body) -> impl Read + Send + 'static {
    let stream = body.into_data_stream().map_err(io::Error::other);
    tokio_util::io::SyncIoBridge::new(tokio_util::io::StreamReader::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn what_is_written_arrives_and_an_early_stop_is_an_error() {
        let (mut w, stream) = channel();
        let writing = tokio::task::spawn_blocking(move || {
            w.write_all(&[1; 3 * CHUNK + 5]).unwrap();
            w.finish()
        });
        let all: Vec<io::Result<Bytes>> = stream.collect().await;
        writing.await.unwrap().unwrap();
        assert_eq!(all.iter().map(|c| c.as_ref().unwrap().len()).sum::<usize>(), 3 * CHUNK + 5);

        let (mut w, stream) = channel();
        tokio::task::spawn_blocking(move || {
            w.write_all(b"half").unwrap();
            w.flush().unwrap();
        })
        .await
        .unwrap();
        let all: Vec<io::Result<Bytes>> = stream.collect().await;
        assert!(all.last().unwrap().is_err(), "a writer dropped without finishing ends with an error");
    }

    #[tokio::test]
    async fn a_body_reads_as_a_reader_on_a_blocking_thread() {
        let body = Body::from_stream(futures::stream::iter(
            (0..3).map(|i| Ok::<_, io::Error>(Bytes::from(vec![i as u8; 100_000]))),
        ));
        let mut r = reader(body);
        let n = tokio::task::spawn_blocking(move || {
            let mut all = Vec::new();
            r.read_to_end(&mut all).map(|_| all)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n.len(), 300_000);
        assert_eq!(n[250_000], 2);
    }
}
