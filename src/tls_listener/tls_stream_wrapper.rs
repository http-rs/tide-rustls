use async_std::io::{self, Read, Write};
use async_std::net::TcpStream;
use async_tls::server::TlsStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
    ) -> Poll<std::io::Result<usize>> {
        match self.0.lock() {
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            Ok(mut this) => Read::poll_read(Pin::new(&mut *this), cx, buf),
        }
    }
}

impl Write for TlsStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.0.lock() {
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            Ok(mut this) => Write::poll_write(Pin::new(&mut *this), cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.0.lock() {
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            Ok(mut this) => Write::poll_flush(Pin::new(&mut *this), cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.0.lock() {
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
            Ok(mut this) => Write::poll_close(Pin::new(&mut *this), cx),
        }
    }
}
