//! Loader for an extra TLS trust anchor used by the WebSocket / file-store
//! clients in `WebSocketTransport`.
//!
//! The native-tls stack (`tokio-native-tls`, `hyper-tls`) honors any
//! certificate added with `TlsConnectorBuilder::add_root_certificate` *in
//! addition to* the OS trust store. That makes a self-signed dev/test
//! server reachable without disabling chain or hostname validation: the
//! extra anchor still has to match the server's leaf, and the server's SAN
//! still has to cover the hostname the client dials.
//!
//! Exactly one anchor is supported (the `--trust-cert <PATH>` flag and the
//! `ENCRYPTED_SPACES_TRUST_CERT` env var both take a single path). The loader
//! tries PEM first, then falls back to DER. Every successful load is
//! logged at `info` with the source path and a SHA-256 of the cert bytes
//! so an operator can audit what their client trusts on each launch.

use std::path::Path;

use sha2::{Digest, Sha256};

use encrypted_spaces_backend::error::{Result, SdkError};

/// Load a single PEM/DER cert from `path` and wrap it in a
/// `tokio_native_tls::TlsConnector` that trusts (OS roots + this cert).
///
/// The returned connector is used by both legs of `WebSocketTransport`:
/// the WS upgrade and the file-store HTTP client. Hostname verification
/// stays on either way — the anchor only widens *who* the client trusts
/// to issue a cert for the server, not *which* cert is acceptable for a
/// given URL.
pub fn load_trust_cert(path: impl AsRef<Path>) -> Result<tokio_native_tls::TlsConnector> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(|e| {
        SdkError::ValidationError(format!("trust-cert: cannot read {}: {e}", path.display()))
    })?;

    let cert = parse_cert_bytes(&bytes).map_err(|e| {
        SdkError::ValidationError(format!(
            "trust-cert: failed to parse {} as PEM or DER: {e}",
            path.display()
        ))
    })?;

    log::info!(
        "trust-cert loaded: path={} sha256={}",
        path.display(),
        sha256_hex(&bytes)
    );

    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(cert)
        .build()
        .map_err(|e| {
            SdkError::ValidationError(format!("trust-cert: TlsConnector build failed: {e}"))
        })?;
    Ok(tokio_native_tls::TlsConnector::from(connector))
}

fn parse_cert_bytes(bytes: &[u8]) -> std::result::Result<native_tls::Certificate, String> {
    if let Ok(cert) = native_tls::Certificate::from_pem(bytes) {
        return Ok(cert);
    }
    native_tls::Certificate::from_der(bytes).map_err(|e| format!("DER parse failed: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_trust_cert_missing_file_errors() {
        let err = load_trust_cert("/definitely/not/a/real/path.pem").unwrap_err();
        match err {
            SdkError::ValidationError(msg) => assert!(msg.contains("cannot read")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_trust_cert_rejects_garbage_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.pem");
        std::fs::write(&path, b"this is not a certificate").unwrap();

        let err = load_trust_cert(&path).unwrap_err();
        match err {
            SdkError::ValidationError(msg) => {
                assert!(msg.contains("parse"), "unexpected error: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
