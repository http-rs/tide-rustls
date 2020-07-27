use crate::{TcpConnection, TlsListenerBuilder, TlsListenerConfig, TlsStreamWrapper};

use tide::listener::{Listener, ToListener};
use tide::Server;

use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::{io, task};

use async_tls::TlsAcceptor;
use rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};

use std::fmt::{self, Debug, Display, Formatter};
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// The primary type for this crate
#[derive(Debug)]
pub struct TlsListener {
    connection: TcpConnection,
    config: TlsListenerConfig,
}

impl TlsListener {
    pub(crate) fn new(connection: TcpConnection, config: TlsListenerConfig) -> Self {
        Self { connection, config }
    }
    /// The primary entrypoint to create a TlsListener. See
    /// [TlsListenerBuilder](crate::TlsListenerBuilder) for more
    /// configuration options.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tide_rustls::TlsListener;
    /// let listener = TlsListener::build()
    ///     .addrs("localhost:4433")
    ///     .cert("./tls/localhost-4433.cert")
    ///     .key("./tls/localhost-4433.key")
    ///     .finish();
    /// ```
    pub fn build() -> TlsListenerBuilder {
        TlsListenerBuilder::new()
    }

    async fn configure(&mut self) -> io::Result<TlsAcceptor> {
        self.config = match std::mem::take(&mut self.config) {
            TlsListenerConfig::Paths { cert, key } => {
                let certs = load_certs(&cert)?;
                let mut keys = load_keys(&key)?;
                let mut config = ServerConfig::new(NoClientAuth::new());
                config
                    .set_single_cert(certs, keys.remove(0))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

                TlsListenerConfig::Acceptor(TlsAcceptor::from(Arc::new(config)))
            }

            TlsListenerConfig::ServerConfig(config) => {
                TlsListenerConfig::Acceptor(TlsAcceptor::from(Arc::new(config)))
            }

            other => other,
        };

        if let TlsListenerConfig::Acceptor(ref a) = self.config {
            Ok(a.clone())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "could not configure tlslistener",
            ))
        }
    }

    async fn connect(&mut self) -> io::Result<&TcpListener> {
        if let TcpConnection::Addrs(addrs) = &self.connection {
            let tcp = TcpListener::bind(&addrs[..]).await?;
            self.connection = TcpConnection::Connected(tcp);
        }

        if let TcpConnection::Connected(tcp) = &self.connection {
            Ok(tcp)
        } else {
            unreachable!()
        }
    }
}

fn handle_tls<State: Clone + Send + Sync + 'static>(
    app: Server<State>,
    stream: TcpStream,
    acceptor: TlsAcceptor,
) {
    task::spawn(async move {
        let local_addr = stream.local_addr().ok();
        let peer_addr = stream.peer_addr().ok();

        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                let stream = TlsStreamWrapper::new(tls_stream);
                let fut = async_h1::accept(stream, |mut req| async {
                    if req.url_mut().set_scheme("https").is_err() {
                        tide::log::error!("unable to set https scheme on url", { url: req.url().to_string() });
                    }

                    req.set_local_addr(local_addr);
                    req.set_peer_addr(peer_addr);
                    app.respond(req).await
                });

                if let Err(error) = fut.await {
                    tide::log::error!("async-h1 error", { error: error.to_string() });
                }
            }

            Err(tls_error) => {
                tide::log::error!("tls error", { error: tls_error.to_string() });
            }
        }
    });
}

impl<State: Clone + Send + Sync + 'static> ToListener<State> for TlsListener {
    type Listener = Self;
    fn to_listener(self) -> io::Result<Self::Listener> {
        Ok(self)
    }
}

impl<State: Clone + Send + Sync + 'static> ToListener<State> for TlsListenerBuilder {
    type Listener = TlsListener;
    fn to_listener(self) -> io::Result<Self::Listener> {
        self.finish()
    }
}

#[tide::utils::async_trait]
impl<State: Clone + Send + Sync + 'static> Listener<State> for TlsListener {
    async fn listen(&mut self, app: Server<State>) -> io::Result<()> {
        let acceptor = self.configure().await?;
        let listener = self.connect().await?;
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            match stream {
                Err(ref e) if is_transient_error(e) => continue,
                Err(error) => {
                    let delay = Duration::from_millis(500);
                    tide::log::error!("Error: {}. Pausing for {:?}.", error, delay);
                    task::sleep(delay).await;
                    continue;
                }

                Ok(stream) => {
                    handle_tls(app.clone(), stream, acceptor.clone());
                }
            };
        }
        Ok(())
    }
}

fn is_transient_error(e: &io::Error) -> bool {
    match e.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset => true,
        _ => false,
    }
}

impl Display for TlsListener {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.connection)
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let mut bufreader = BufReader::new(File::open(path)?);
    if let Ok(pkcs8) = pkcs8_private_keys(&mut bufreader) {
        if !pkcs8.is_empty() {
            return Ok(pkcs8);
        }
    }

    bufreader.seek(SeekFrom::Start(0))?;

    if let Ok(rsa) = rsa_private_keys(&mut bufreader) {
        if !rsa.is_empty() {
            return Ok(rsa);
        }
    }

    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
