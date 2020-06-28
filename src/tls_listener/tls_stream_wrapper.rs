use async_dup::{Arc, Mutex};
use async_std::io::{Read, Result, Write};
use async_std::net::TcpStream;
use async_tls::server::TlsStream;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct TlsStreamWrapper(Arc<Mutex<TlsStream<TcpStream>>>);

impl TlsStreamWrapper {
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        Self(Arc::new(Mutex::new(stream)))
    }
}

impl Read for TlsStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut &*self.0).poll_read(cx, buf)
    }
}

impl Write for TlsStreamWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut &*self.0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &*self.0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &*self.0).poll_close(cx)
    }
}
