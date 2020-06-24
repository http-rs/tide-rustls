mod tls_stream_wrapper;

use std::fmt::{self, Debug, Display, Formatter};
use tide::listener::{Listener, ToListener};
use tide::Server;

use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::{io, task};

use async_tls::TlsAcceptor;
use rustls::internal::pemfile::{certs, pkcs8_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};

use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

pub use tls_stream_wrapper::TlsStreamWrapper;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct TlsListener {
    addrs: Option<Vec<SocketAddr>>,
    cert: PathBuf,
    key: PathBuf,
    acceptor: Option<TlsAcceptor>,
    tcp: Option<TcpListener>,
}

impl TlsListener {
    #[allow(dead_code)]
    pub fn from_addr(
        addrs: impl ToSocketAddrs,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Self {
        Self {
            addrs: Some(addrs.to_socket_addrs().unwrap().collect()),
            cert: cert.as_ref().into(),
            key: key.as_ref().into(),
            acceptor: None,
            tcp: None,
        }
    }

    #[allow(dead_code)]
    pub fn from_tcp(tcp: TcpListener, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Self {
        Self {
            addrs: None,
            cert: cert.as_ref().into(),
            key: key.as_ref().into(),
            acceptor: None,
            tcp: Some(tcp),
        }
    }
}

fn handle_tls<State: Send + Sync + 'static>(
    app: Server<State>,
    stream: TcpStream,
    acceptor: TlsAcceptor,
) {
    task::spawn(async move {
        let local_addr = stream.local_addr().ok();
        let peer_addr = stream.peer_addr().ok();

        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                let fut = async_h1::accept(TlsStreamWrapper::new(tls_stream), |mut req| async {
                    req.url_mut().set_scheme("https").ok();
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

impl<State: Send + Sync + 'static> ToListener<State> for TlsListener {
    type Listener = Self;
    fn to_listener(self) -> io::Result<Self::Listener> {
        Ok(self)
    }
}

impl<State: Send + Sync + 'static> Listener<State> for TlsListener {
    fn connect<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let certs = load_certs(&self.cert)?;
            let mut keys = load_keys(&self.key)?;
            let mut config = ServerConfig::new(NoClientAuth::new());
            config
                .set_single_cert(certs, keys.remove(0))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            self.acceptor = Some(TlsAcceptor::from(Arc::new(config)));
            if self.tcp.is_none() {
                self.tcp = Some(TcpListener::bind(&self.addrs.as_ref().unwrap()[..]).await?);
            }
            Ok(())
        })
    }

    fn listen<'a>(&'a self, app: Server<State>) -> BoxFuture<'a, async_std::io::Result<()>> {
        Box::pin(async move {
            let listener = self.tcp.as_ref().unwrap();
            let mut incoming = listener.incoming();
            let acceptor = self.acceptor.as_ref().unwrap();

            while let Some(stream) = incoming.next().await {
                match stream {
                    Err(ref e) if is_transient_error(e) => continue,
                    Err(error) => {
                        let delay = std::time::Duration::from_millis(500);
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
        })
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
        if let Some(ref tcp) = self.tcp {
            write!(
                f,
                "https://{}",
                tcp.local_addr()
                    .ok()
                    .map(|a| a.to_string())
                    .as_deref()
                    .unwrap_or("[unknown]")
            )
        } else if let Some(ref addrs) = self.addrs {
            write!(
                f,
                "{}",
                addrs
                    .iter()
                    .map(|a| format!("https://{}", a))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            write!(f, "https://[unknown]")
        }
    }
}

impl Debug for TlsListener {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsListener")
            .field("addrs", &self.addrs)
            .field("cert", &self.cert)
            .field("key", &self.key)
            .field("tcp", &self.tcp)
            .finish()
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
