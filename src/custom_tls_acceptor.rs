use async_rustls::server::TlsStream;
use async_std::net::TcpStream;

/// The CustomTlsAcceptor trait provides a custom implementation of accepting
/// TLS connections from a [`TcpStream`]. tide-rustls will call the
/// [`CustomTlsAcceptor::accept`] function for each new [`TcpStream`] it
/// accepts, to obtain a [`TlsStream`]).
///
/// Implementing this trait gives you control over the TLS negotiation process,
/// and allows you to process some TLS connections internally without passing
/// them through to tide, such as for multiplexing or custom ALPN negotiation.
#[tide::utils::async_trait]
pub trait CustomTlsAcceptor: Send + Sync {
    /// Accept a [`TlsStream`] from a [`TcpStream`].
    ///
    /// If TLS negotiation succeeds, but does not result in a stream that tide
    /// should process HTTP connections from, return `Ok(None)`.
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Option<TlsStream<TcpStream>>>;
}

/// Crate-private adapter to make `async_rustls::TlsAcceptor` implement
/// `CustomTlsAcceptor`, without creating a conflict between the two `accept`
/// methods.
pub(crate) struct StandardTlsAcceptor(pub(crate) async_rustls::TlsAcceptor);

#[tide::utils::async_trait]
impl CustomTlsAcceptor for StandardTlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Option<TlsStream<TcpStream>>> {
        self.0.accept(stream).await.map(Some)
    }
}
