use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile as pemfile;
use std::io::BufReader;

pub fn build_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(cfg)
}

fn load_certs(path: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error + Send + Sync>> {
    use std::fs::File;
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let certs = pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        Err("no certificates found in cert file".into())
    } else {
        Ok(certs)
    }
}

fn load_key(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error + Send + Sync>> {
    use std::fs::File;
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut keys = pemfile::pkcs8_private_keys(&mut reader)?;
    if keys.is_empty() {
        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        keys = pemfile::rsa_private_keys(&mut reader)?;
    }
    keys.into_iter()
        .next()
        .map(PrivateKey)
        .ok_or_else(|| "no private keys found in key file".into())
}
