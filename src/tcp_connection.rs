use async_std::net::{SocketAddr, TcpListener};
use std::fmt::{self, Debug, Display, Formatter};

#[derive(Debug)]
pub(crate) enum TcpConnection {
    Addrs(Vec<SocketAddr>),
    Connected(TcpListener),
}

impl Display for TcpConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addrs(addrs) => write!(
                f,
                "{}",
                addrs
                    .iter()
                    .map(|a| format!("https://{}", a))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),

            Self::Connected(tcp) => write!(
                f,
                "https://{}",
                tcp.local_addr()
                    .ok()
                    .map(|a| a.to_string())
                    .as_deref()
                    .unwrap_or("[unknown]")
            ),
        }
    }
}
