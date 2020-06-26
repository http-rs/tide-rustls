use async_std::io;
use async_std::net::TcpListener;

use rustls::ServerConfig;

use super::{TlsListener, TlsListenerConfig, TlsListenerConnection};

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct TlsListenerBuilder {
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    config: Option<ServerConfig>,
    tcp: Option<TcpListener>,
    addrs: Option<Vec<SocketAddr>>,
}

impl TlsListenerBuilder {
    pub(crate) fn new() -> Self {
        TlsListenerBuilder::default()
    }
    pub fn key(mut self, path: impl AsRef<Path>) -> Self {
        self.key = Some(path.as_ref().into());
        self
    }
    pub fn cert(mut self, path: impl AsRef<Path>) -> Self {
        self.cert = Some(path.as_ref().into());
        self
    }
    pub fn config(mut self, config: ServerConfig) -> Self {
        self.config = Some(config);
        self
    }
    pub fn tcp(mut self, tcp: impl Into<TcpListener>) -> Self {
        self.tcp = Some(tcp.into());
        self
    }
    pub fn addrs(mut self, addrs: impl ToSocketAddrs) -> Self {
        if let Ok(socket_addrs) = addrs.to_socket_addrs() {
            self.addrs = Some(socket_addrs.collect());
        }
        self
    }

    pub(crate) fn build(self) -> io::Result<TlsListener> {
        let Self {
            key,
            cert,
            config,
            tcp,
            addrs,
        } = self;

        let config = match (key, cert, config) {
            (Some(key), Some(cert), None) => TlsListenerConfig::Paths { key, cert },
            (None, None, Some(config)) => TlsListenerConfig::ServerConfig(config),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "either cert + key are required or a ServerConfig",
                ))
            }
        };

        let connection = match (tcp, addrs) {
            (Some(tcp), None) => TlsListenerConnection::Connected(tcp),
            (None, Some(addrs)) => TlsListenerConnection::Addrs(addrs),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "either tcp or addrs are required",
                ))
            }
        };

        Ok(TlsListener { connection, config })
    }
}
