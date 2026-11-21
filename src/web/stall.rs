//! The write stall of a connection: a connection whose writes make no progress for the stall time is closed.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Sleep;

/// The peer address of a connection, as handlers read it through `ConnectInfo`.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub SocketAddr);

impl Connected<IncomingStream<'_, StallListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, StallListener>) -> Self {
        Peer(*stream.remote_addr())
    }
}

/// A TCP listener whose connections are wrapped in `StallStream`.
pub struct StallListener {
    listener: TcpListener,
    stall: Duration,
}

impl StallListener {
    pub fn new(listener: TcpListener, stall: Duration) -> Self {
        StallListener { listener, stall }
    }
}

impl Listener for StallListener {
    type Io = StallStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (io, addr) = Listener::accept(&mut self.listener).await;
        (StallStream::new(io, self.stall), addr)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// A connection whose writes and flushes end with `TimedOut` after the stall time without progress.
pub struct StallStream<S> {
    inner: S,
    stall: Duration,
    /// Running while a write or flush waits; cleared when one progresses.
    timer: Option<Pin<Box<Sleep>>>,
}

impl<S> StallStream<S> {
    pub fn new(inner: S, stall: Duration) -> Self {
        StallStream {
            inner,
            stall,
            timer: None,
        }
    }

    /// Starts the timer when a call first waits; `TimedOut` once the stall time has passed.
    fn waited(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let stall = self.stall;
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            Poll::Pending => Ok(()),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StallStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StallStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) if n > 0 => {
                this.timer = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.waited(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) if n > 0 => {
                this.timer = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.waited(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.timer = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.waited(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;

    /// The stall of these tests. Real time: the crate builds tokio without `test-util`, so paused time is not
    /// available.
    const STALL: Duration = Duration::from_millis(300);
    /// Longer than any wait these tests make, so a test that never ends fails rather than hangs.
    const GIVE_UP: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn a_write_that_makes_no_progress_errors_with_timed_out_after_the_stall_time() {
        let (near, _far) = tokio::io::duplex(8);
        let mut stream = StallStream::new(near, STALL);
        let started = Instant::now();
        let result = tokio::time::timeout(GIVE_UP, stream.write_all(&[7u8; 64]))
            .await
            .expect("the stalled write must end");
        let error = result.expect_err("a write nobody reads must fail");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= STALL,
            "the error comes after the stall time, not before: {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < GIVE_UP,
            "the error comes once the stall time has passed"
        );
    }

    #[tokio::test]
    async fn a_write_that_progresses_within_the_stall_time_never_errors() {
        let (near, mut far) = tokio::io::duplex(8);
        let mut stream = StallStream::new(near, Duration::from_secs(1));
        let reader = tokio::spawn(async move {
            let mut total = Vec::new();
            let mut chunk = [0u8; 8];
            while total.len() < 64 {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let read = far.read(&mut chunk).await.expect("the reader reads");
                total.extend_from_slice(&chunk[..read]);
            }
            total
        });
        let result = tokio::time::timeout(GIVE_UP, stream.write_all(&[9u8; 64]))
            .await
            .expect("the writes must end");
        result.expect("every write progresses within the stall time");
        assert_eq!(reader.await.expect("reader task").len(), 64);
    }

    #[tokio::test]
    async fn an_idle_read_is_not_closed_by_the_stall_time() {
        let (near, mut far) = tokio::io::duplex(8);
        let mut stream = StallStream::new(near, STALL);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            far.write_all(b"late").await.expect("the peer writes");
        });
        let mut buf = [0u8; 4];
        let result = tokio::time::timeout(GIVE_UP, stream.read_exact(&mut buf))
            .await
            .expect("the read must end");
        result.expect("a read that waits longer than the stall time is not an error");
        assert_eq!(&buf, b"late");
    }
}
