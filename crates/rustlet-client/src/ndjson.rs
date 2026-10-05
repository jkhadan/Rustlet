//! NDJSON responses, decoded item by item as they arrive.
//!
//! The daemon writes one JSON value per line and sends each as it happens,
//! so a `logs --follow` or `events` response never ends on its own. Its
//! body is therefore read frame by frame, never collected: the bytes go
//! into a [`LineBuffer`], which hands out each complete line once its `\n`
//! is in. HTTP framing has nothing to do with line boundaries, so a frame
//! may end halfway through a line (the rest arrives with the next) or carry
//! hundreds of them (a `--tail all`); both are the same to the buffer.
//!
//! A stream that fails after it started can't change its status code any
//! more, so it ends with an error line instead (`{"error": "…"}`,
//! [`rustlet_spec::StreamError`]). Every streamed type takes missing fields
//! as defaults, so that line would also decode as an item made of
//! defaults; it is recognised first, by its `error` member, which no
//! streamed type has, and becomes [`Error::Stream`]. After an error (that
//! one, a line that doesn't decode, a connection that breaks) the stream
//! is over.

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::{BoxStream, Stream, StreamExt};
use http::Response;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// The longest line accepted. The longest real one is a log entry (16 KiB
/// of text, which JSON escaping can make several times longer); anything
/// near this is a daemon that stopped writing newlines.
pub(crate) const MAX_LINE: usize = 16 << 20;

/// An NDJSON response: a [`Stream`] of decoded items, each available as
/// soon as its line has arrived. Dropping it hangs up, which ends a
/// `follow` stream on the daemon's side too.
///
/// It yields `Ok` items until the response ends; an `Err` is always the
/// last item.
pub struct JsonStream<T> {
    inner: BoxStream<'static, Result<T>>,
}

impl<T: DeserializeOwned + Send + 'static> JsonStream<T> {
    /// Decodes `body`. `check` sees every item and may turn it into the
    /// error that ends the stream (a pull's `error` event).
    pub(crate) fn new(body: Incoming, check: fn(T) -> Result<T>) -> JsonStream<T> {
        Self::with_upload(body, check, None)
    }

    /// The response to a streamed upload, which may still be in progress
    /// when the daemon answers and closes the connection.
    pub(crate) fn upload(mut response: Response<Incoming>, check: fn(T) -> Result<T>) -> JsonStream<T> {
        let upload = response.extensions_mut().remove::<crate::UploadProgress>();
        Self::with_upload(response.into_body(), check, upload)
    }

    fn with_upload(body: Incoming, check: fn(T) -> Result<T>, upload: Option<crate::UploadProgress>) -> JsonStream<T> {
        let state =
            State { body, lines: LineBuffer::default(), eof: false, done: false, check, upload, item: PhantomData };
        let inner = futures::stream::unfold(state, |mut state| async move {
            let item = state.next().await?;
            Some((item, state))
        });
        JsonStream { inner: inner.boxed() }
    }
}

impl<T> Stream for JsonStream<T> {
    type Item = Result<T>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<T>>> {
        self.inner.poll_next_unpin(cx)
    }
}

impl<T> std::fmt::Debug for JsonStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonStream").field("item", &std::any::type_name::<T>()).finish_non_exhaustive()
    }
}

struct State<T> {
    body: Incoming,
    lines: LineBuffer,
    /// The body has ended; what's left in `lines` is all there is.
    eof: bool,
    /// An error was returned, or everything was: nothing more comes.
    done: bool,
    check: fn(T) -> Result<T>,
    upload: Option<crate::UploadProgress>,
    item: PhantomData<fn() -> T>,
}

impl<T: DeserializeOwned> State<T> {
    async fn next(&mut self) -> Option<Result<T>> {
        loop {
            if self.done {
                return None;
            }
            if let Some(line) = self.lines.next_line(self.eof) {
                // The last frame may both cross the bound and finish the
                // line; checking only the pending bytes below misses it.
                if line.len() > MAX_LINE {
                    self.done = true;
                    return Some(Err(Error::Protocol(format!("a streamed line is longer than {MAX_LINE} bytes"))));
                }
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let item = parse_line(line).and_then(self.check);
                self.done = item.is_err();
                return Some(item);
            }
            if self.eof {
                self.done = true;
                return None;
            }
            if self.lines.pending() > MAX_LINE {
                self.done = true;
                return Some(Err(Error::Protocol(format!("a streamed line is longer than {MAX_LINE} bytes"))));
            }
            match self.body.frame().await {
                // Trailers carry nothing for us.
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.lines.push(&data);
                    }
                }
                Some(Err(e)) => {
                    self.done = true;
                    return Some(Err(crate::upload_error(e, self.upload.as_ref())));
                }
                None => self.eof = true,
            }
        }
    }
}

/// One line: an error line ends the stream, anything else must be a `T`.
pub(crate) fn parse_line<T: DeserializeOwned>(line: &[u8]) -> Result<T> {
    let value: serde_json::Value = serde_json::from_slice(line)?;
    if let Some(serde_json::Value::String(message)) = value.get("error") {
        return Err(Error::Stream(message.clone()));
    }
    Ok(serde_json::from_value(value)?)
}

/// Bytes in, complete lines out, whatever the chunking.
///
/// Consumed lines are only dropped from the front when more data comes in,
/// so a frame holding many lines is split without moving the rest each
/// time; and the part of an incomplete line already searched for `\n` is
/// not searched again, so a long line arriving in small pieces costs no
/// more than a short one.
#[derive(Debug, Default)]
pub(crate) struct LineBuffer {
    buf: Vec<u8>,
    /// Where the unconsumed bytes start.
    start: usize,
    /// `buf[start..scanned]` has no `\n` in it.
    scanned: usize,
}

impl LineBuffer {
    pub(crate) fn push(&mut self, data: &[u8]) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.scanned -= self.start;
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next complete line, without its `\n`. Once no more data will
    /// come (`eof`), whatever follows the last `\n` is a line too.
    pub(crate) fn next_line(&mut self, eof: bool) -> Option<&[u8]> {
        let line = match self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
            Some(i) => {
                let end = self.scanned + i;
                let line = self.start..end;
                self.start = end + 1;
                line
            }
            None if eof && self.start < self.buf.len() => {
                let line = self.start..self.buf.len();
                self.start = self.buf.len();
                line
            }
            None => {
                self.scanned = self.buf.len();
                return None;
            }
        };
        self.scanned = self.start;
        Some(&self.buf[line])
    }

    /// Bytes of the incomplete line.
    pub(crate) fn pending(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustlet_spec::logs::LogEntry;

    fn lines_of(chunks: &[&[u8]]) -> Vec<String> {
        let mut b = LineBuffer::default();
        let mut out = Vec::new();
        for chunk in chunks {
            b.push(chunk);
            while let Some(line) = b.next_line(false) {
                out.push(String::from_utf8(line.to_vec()).unwrap());
            }
        }
        while let Some(line) = b.next_line(true) {
            out.push(String::from_utf8(line.to_vec()).unwrap());
        }
        out
    }

    #[test]
    fn lines_survive_any_chunking() {
        let text = b"{\"a\":1}\n{\"b\":2}\n\n{\"c\":3}\n";
        let whole = lines_of(&[text]);
        assert_eq!(whole, ["{\"a\":1}", "{\"b\":2}", "", "{\"c\":3}"]);
        // Every split point, and byte-by-byte.
        for cut in 0..text.len() {
            assert_eq!(lines_of(&[&text[..cut], &text[cut..]]), whole, "cut at {cut}");
        }
        let bytes: Vec<&[u8]> = text.chunks(1).collect();
        assert_eq!(lines_of(&bytes), whole);
    }

    #[test]
    fn a_last_line_without_newline_counts() {
        assert_eq!(lines_of(&[b"x\ny"]), ["x", "y"]);
        assert_eq!(lines_of(&[b"x\n"]), ["x"]);
        assert!(lines_of(&[b""]).is_empty());
    }

    #[test]
    fn pending_counts_the_incomplete_line() {
        let mut b = LineBuffer::default();
        b.push(b"done\npart");
        assert_eq!(b.next_line(false), Some(&b"done"[..]));
        assert_eq!(b.next_line(false), None);
        assert_eq!(b.pending(), 4);
        b.push(b"ial\n");
        assert_eq!(b.next_line(false), Some(&b"partial"[..]));
        assert_eq!(b.pending(), 0);
        assert_eq!(b.next_line(true), None);
    }

    #[test]
    fn error_lines_end_streams() {
        let e = parse_line::<LogEntry>(br#"{"error":"log file vanished"}"#).unwrap_err();
        assert!(matches!(&e, Error::Stream(m) if m == "log file vanished"), "{e:?}");
        let entry: LogEntry = parse_line(br#"{"ts":"t","stream":"stderr","log":"x\n"}"#).unwrap();
        assert_eq!(entry.log, "x\n");
        assert!(matches!(parse_line::<LogEntry>(b"{nope"), Err(Error::Json(_))));
    }
}
