mod tcp_connection;
mod tls_listener;
mod tls_listener_builder;
mod tls_listener_config;
mod tls_stream_wrapper;

pub use tcp_connection::TcpConnection;
pub use tls_listener::TlsListener;
pub use tls_listener_builder::TlsListenerBuilder;
pub use tls_listener_config::TlsListenerConfig;
pub use tls_stream_wrapper::TlsStreamWrapper;

use std::future::Future;
use std::pin::Pin;
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
