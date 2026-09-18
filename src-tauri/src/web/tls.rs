//! Optional TLS termination for the standalone `codeg-server` binary.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

pub const ENV_TLS_CERT: &str = "CODEG_TLS_CERT";
pub const ENV_TLS_KEY: &str = "CODEG_TLS_KEY";

/// A peer that connects and then stalls must not pin a task and a queue slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const ACCEPT_QUEUE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("{set} is set but {missing} is not; set both to serve HTTPS, or neither to serve plain HTTP")]
    Incomplete {
        set: &'static str,
        missing: &'static str,
    },

    #[error("failed to load the certificate chain from {path} (CODEG_TLS_CERT): {source}")]
    Certificate {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },

    #[error("{path} (CODEG_TLS_CERT) contains no certificates")]
    EmptyCertificateChain { path: PathBuf },

    #[error("failed to load the private key from {path} (CODEG_TLS_KEY): {source}")]
    PrivateKey {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },

    #[error("certificate and private key were rejected: {0}")]
    Rejected(#[from] rustls::Error),
}

/// Read `CODEG_TLS_CERT` / `CODEG_TLS_KEY`; `Ok(None)` means plain HTTP.
pub fn tls_paths_from_env() -> Result<Option<TlsPaths>, TlsConfigError> {
    resolve_tls_paths(
        std::env::var(ENV_TLS_CERT).ok(),
        std::env::var(ENV_TLS_KEY).ok(),
    )
}

/// Half a TLS config is an operator mistake, never a reason to fall back to
/// cleartext.
pub fn resolve_tls_paths(
    cert: Option<String>,
    key: Option<String>,
) -> Result<Option<TlsPaths>, TlsConfigError> {
    let cert = cert.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let key = key.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some(TlsPaths {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
        })),
        (Some(_), None) => Err(TlsConfigError::Incomplete {
            set: ENV_TLS_CERT,
            missing: ENV_TLS_KEY,
        }),
        (None, Some(_)) => Err(TlsConfigError::Incomplete {
            set: ENV_TLS_KEY,
            missing: ENV_TLS_CERT,
        }),
        (None, None) => Ok(None),
    }
}

pub fn server_config(paths: &TlsPaths) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let certs = CertificateDer::pem_file_iter(&paths.cert)
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .map_err(|source| TlsConfigError::Certificate {
            path: paths.cert.clone(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsConfigError::EmptyCertificateChain {
            path: paths.cert.clone(),
        });
    }

    let key =
        PrivateKeyDer::from_pem_file(&paths.key).map_err(|source| TlsConfigError::PrivateKey {
            path: paths.key.clone(),
            source,
        })?;

    // Named provider rather than the process default: the graph has several
    // rustls consumers and none of them installs one.
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    // HTTP/1.1 only: hyper has no RFC 8441 extended CONNECT, so negotiating h2
    // would push every WebSocket onto a fallback connection.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A TCP listener that hands axum already-handshaked TLS streams.
///
/// Handshakes run in their own task rather than inside `accept`, so one slow
/// or hostile peer cannot stall every connection behind it.
pub struct TlsListener {
    local_addr: SocketAddr,
    incoming: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let (tx, incoming) = mpsc::channel(ACCEPT_QUEUE);
        let acceptor = TlsAcceptor::from(config);

        tokio::spawn(async move {
            loop {
                let (stream, peer) = tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            // As in axum's own listener: never fatal, but do not
                            // spin on a broken listener.
                            tracing::warn!("[SERVER][TLS] accept failed: {e}");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    },
                    _ = tx.closed() => return,
                };

                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let _ = tx.send((stream, peer)).await;
                        }
                        Ok(Err(e)) => tracing::debug!("[SERVER][TLS] handshake with {peer}: {e}"),
                        Err(_) => tracing::debug!("[SERVER][TLS] handshake with {peer} timed out"),
                    }
                });
            }
        });

        Ok(Self {
            local_addr,
            incoming,
        })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.incoming.recv().await {
                Some(conn) => return conn,
                // Unreachable while the accept task holds a sender, and `accept`
                // may not report an error, so park instead of panicking.
                None => std::future::pending().await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_vars_unset_means_plain_http() {
        assert_eq!(resolve_tls_paths(None, None).unwrap(), None);
        assert_eq!(
            resolve_tls_paths(Some("  ".to_string()), Some(String::new())).unwrap(),
            None
        );
    }

    #[test]
    fn both_vars_set_means_https() {
        let paths = resolve_tls_paths(Some("/c.pem".to_string()), Some("/k.pem".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(paths.cert, PathBuf::from("/c.pem"));
        assert_eq!(paths.key, PathBuf::from("/k.pem"));
    }

    #[test]
    fn half_a_config_names_the_missing_var() {
        let err = resolve_tls_paths(Some("/c.pem".to_string()), None).unwrap_err();
        assert!(
            err.to_string().contains(ENV_TLS_KEY),
            "should name the missing var: {err}"
        );

        let err = resolve_tls_paths(None, Some("/k.pem".to_string())).unwrap_err();
        assert!(
            err.to_string().contains(ENV_TLS_CERT),
            "should name the missing var: {err}"
        );

        // A whitespace-only value is unset, not half-configured.
        let err = resolve_tls_paths(Some("/c.pem".to_string()), Some(" ".to_string())).unwrap_err();
        assert!(err.to_string().contains(ENV_TLS_KEY), "{err}");
    }

    #[test]
    fn a_missing_certificate_file_is_reported_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("absent.pem");
        let err = server_config(&TlsPaths {
            cert: cert.clone(),
            key: dir.path().join("absent.key"),
        })
        .unwrap_err();
        assert!(
            err.to_string().contains(&cert.display().to_string()),
            "{err}"
        );
    }
}
