use std::fmt::{self, Debug, Formatter};

use rustls::ServerConfig;

use super::CustomTlsAcceptor;

use std::path::PathBuf;
use std::sync::Arc;

impl Default for TlsListenerConfig {
    fn default() -> Self {
        Self::Unconfigured
    }
}
pub(crate) enum TlsListenerConfig {
    Unconfigured,
    Acceptor(Arc<dyn CustomTlsAcceptor>),
    ServerConfig(ServerConfig),
    Paths { cert: PathBuf, key: PathBuf },
}

impl Debug for TlsListenerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unconfigured => write!(f, "TlsListenerConfig::Unconfigured"),
            Self::Acceptor(_) => write!(f, "TlsListenerConfig::Acceptor(..)"),
            Self::ServerConfig(_) => write!(f, "TlsListenerConfig::ServerConfig(..)"),
            Self::Paths { cert, key } => f
                .debug_struct("TlsListenerConfig::Paths")
                .field("cert", cert)
                .field("key", key)
                .finish(),
        }
    }
}
