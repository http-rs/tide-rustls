use async_std::io;
use async_std::net::TcpListener;

use rustls::ServerConfig;

use super::{CustomTlsAcceptor, TcpConnection, TlsListener, TlsListenerConfig};

use std::marker::PhantomData;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// # A builder for TlsListeners
///
/// This is created with a call to
/// [`TlsListener::build`](crate::TlsListener::build). This also can
/// be passed directly to [`tide::Server::listen`], skipping the
/// [`TlsListenerBuilder::finish`] call.
///
/// # Examples
///
/// ```rust
/// # use tide_rustls::TlsListener;
/// let listener = TlsListener::<()>::build()
///     .addrs("localhost:4433")
///     .cert("./tls/localhost-4433.cert")
///     .key("./tls/localhost-4433.key")
///     .finish();
/// ```
///
/// ```rust
/// # use tide_rustls::TlsListener;
/// let listener = TlsListener::<()>::build()
///     .tcp(std::net::TcpListener::bind("localhost:4433").unwrap())
///     .config(rustls::ServerConfig::new(rustls::NoClientAuth::new()))
///     .finish();
/// ```
pub struct TlsListenerBuilder<State> {
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    config: Option<ServerConfig>,
    tls_acceptor: Option<Arc<dyn CustomTlsAcceptor>>,
    tcp: Option<TcpListener>,
    addrs: Option<Vec<SocketAddr>>,
    _state: PhantomData<State>,
}

impl<State> Default for TlsListenerBuilder<State> {
    fn default() -> Self {
        Self {
            key: None,
            cert: None,
            config: None,
            tls_acceptor: None,
            tcp: None,
            addrs: None,
            _state: PhantomData,
        }
    }
}

impl<State> std::fmt::Debug for TlsListenerBuilder<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListenerBuilder")
            .field("key", &self.key)
            .field("cert", &self.cert)
            .field(
                "config",
                &if self.config.is_some() {
                    "Some(ServerConfig { .. })"
                } else {
                    "None"
                },
            )
            .field(
                "tls_acceptor",
                &if self.tls_acceptor.is_some() {
                    "Some(_)"
                } else {
                    "None"
                },
            )
            .field("tcp", &self.tcp)
            .field("addrs", &self.addrs)
            .finish()
    }
}

impl<State> TlsListenerBuilder<State> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Provide a path to a key file, in either pkcs8 or rsa
    /// formats. This is mutually exclusive with providing a server
    /// config with [`TlsListenerBuilder::config`], but must be used
    /// in conjunction with [`TlsListenerBuilder::cert`]
    pub fn key(mut self, path: impl AsRef<Path>) -> Self {
        self.key = Some(path.as_ref().into());
        self
    }

    /// Provide a path to a cert file. This is mutually exclusive with
    /// providing a server config with [`TlsListenerBuilder::config`],
    /// but must be used in conjunction with
    /// [`TlsListenerBuilder::key`]
    pub fn cert(mut self, path: impl AsRef<Path>) -> Self {
        self.cert = Some(path.as_ref().into());
        self
    }

    /// Provide a prebuilt
    /// [`rustls::ServerConfig`](::rustls::ServerConfig) with any
    /// options. This is mutually exclusive with both
    /// [`TlsListenerBuilder::key`] and [`TlsListenerBuilder::cert`],
    /// but provides the opportunity for more configuration choices.
    pub fn config(mut self, config: ServerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Provides a custom acceptor for TLS connections.  This is mutually
    /// exclusive with any of [`TlsListenerBuilder::key`],
    /// [`TlsListenerBuilder::cert`], and [`TlsListenerBuilder::config`], but
    /// gives total control over accepting TLS connections, including
    /// multiplexing other streams or ALPN negotiations on the same TLS
    /// connection that tide should ignore.
    pub fn tls_acceptor(mut self, acceptor: Arc<dyn CustomTlsAcceptor>) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Provides a bound tcp listener (either async-std or std) to
    /// build this tls listener on. This is mutually exclusive with
    /// [`TlsListenerBuilder::addrs`], but one of them is mandatory.
    pub fn tcp(mut self, tcp: impl Into<TcpListener>) -> Self {
        self.tcp = Some(tcp.into());
        self
    }

    /// Provides a [`std::net::ToSocketAddrs`] specification for this
    /// tls listener. This is mutually exclusive with
    /// [`TlsListenerBuilder::tcp`] but one of them is mandatory.
    pub fn addrs(mut self, addrs: impl ToSocketAddrs) -> Self {
        if let Ok(socket_addrs) = addrs.to_socket_addrs() {
            self.addrs = Some(socket_addrs.collect());
        }
        self
    }

    /// finishes building a TlsListener from this TlsListenerBuilder.
    ///
    /// # Errors
    ///
    /// this will return an error unless all of the following conditions are met:
    /// * either of these is provided, but not both
    ///   * [`TlsListenerBuilder::tcp`]
    ///   * [`TlsListenerBuilder::addrs`]
    /// * exactly one of these is provided
    ///   * both [`TlsListenerBuilder::cert`] AND [`TlsListenerBuilder::key`]
    ///   * [`TlsListenerBuilder::config`]
    ///   * [`TlsListenerBuilder::tls_acceptor`]
    pub fn finish(self) -> io::Result<TlsListener<State>> {
        let Self {
            key,
            cert,
            config,
            tls_acceptor,
            tcp,
            addrs,
            ..
        } = self;

        let config = match (key, cert, config, tls_acceptor) {
            (Some(key), Some(cert), None, None) => TlsListenerConfig::Paths { key, cert },
            (None, None, Some(config), None) => TlsListenerConfig::ServerConfig(config),
            (None, None, None, Some(tls_acceptor)) => TlsListenerConfig::Acceptor(tls_acceptor),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "need exactly one of cert + key, ServerConfig, or TLS acceptor",
                ))
            }
        };

        let connection = match (tcp, addrs) {
            (Some(tcp), None) => TcpConnection::Connected(tcp),
            (None, Some(addrs)) => TcpConnection::Addrs(addrs),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "either tcp or addrs are required",
                ))
            }
        };

        Ok(TlsListener::new(connection, config))
    }
}
