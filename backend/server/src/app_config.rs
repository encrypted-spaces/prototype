use clap::Parser;
use encrypted_spaces_backend::SpaceId;
use std::io;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// CLI definition (clap derive)
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "encrypted-spaces-server")]
#[command(about = "Encrypted Spaces backend server")]
pub struct CliArgs {
    /// Path to a schema/seed file applied to every new space.
    #[arg(long = "schema", env = "SERVER_DEFAULT_SCHEMA_PATH")]
    pub schema: Option<String>,

    /// Root directory for per-space local artifacts.
    #[arg(long = "space-root", env = "SERVER_SPACE_ROOT")]
    pub space_root: Option<String>,

    /// Host address to bind.
    #[arg(long = "bind-addr", env = "BIND_ADDR", default_value = "127.0.0.1")]
    pub bind_addr: IpAddr,

    /// HTTP port.
    #[arg(long, env = "PORT", default_value_t = 8080)]
    pub port: u16,

    /// TLS port.
    #[arg(long = "tls-port", env = "TLS_PORT", default_value_t = 8443)]
    pub tls_port: u16,

    /// Path to the TLS certificate file (PEM).
    #[arg(long = "tls-cert", env = "TLS_CERT_PATH")]
    pub tls_cert: Option<String>,

    /// Path to the TLS private key file (PEM).
    #[arg(long = "tls-key", env = "TLS_KEY_PATH")]
    pub tls_key: Option<String>,
}

// ---------------------------------------------------------------------------
// ServerConfig — network / TLS settings extracted from CliArgs
// ---------------------------------------------------------------------------

pub struct ServerConfig {
    pub bind_host: IpAddr,
    pub port: u16,
    pub tls_port: u16,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl ServerConfig {
    pub fn tls_config(&self) -> Option<(String, String)> {
        self.tls_cert
            .as_ref()
            .zip(self.tls_key.as_ref())
            .map(|(c, k)| (c.clone(), k.clone()))
    }
}

impl From<&CliArgs> for ServerConfig {
    fn from(args: &CliArgs) -> Self {
        Self {
            bind_host: args.bind_addr,
            port: args.port,
            tls_port: args.tls_port,
            tls_cert: args.tls_cert.clone(),
            tls_key: args.tls_key.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Application-level config types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum BootstrapDataSource {
    None,
    SchemaFile(String),
}

/// Targeted initialization config for a single space instance.
/// Passed to [`SpaceState::init_server`] instead of the full [`AppConfig`].
#[derive(Clone, Debug)]
pub struct SpaceInitConfig {
    /// The space this configuration applies to.
    pub space_id: SpaceId,
    /// Per-space artifact directory, or `None` for temporary local artifacts.
    pub artifact_path: Option<String>,
    /// Path for verbose file-based logging, if any.
    pub verbose_logfile: Option<String>,
    /// Schema bundle to load when the space is first created.
    pub bootstrap_data: BootstrapDataSource,
}

#[derive(Clone)]
pub struct AppConfig {
    /// If specified, used for verbose file-based logging.
    pub verbose_logfile: Option<String>,
    /// The root directory for per-space local artifacts.
    pub space_root: Option<String>,
    /// Optional schema bundle for all new spaces.
    pub bootstrap_data: BootstrapDataSource,
}

impl AppConfig {
    /// Build an [`AppConfig`] from parsed CLI arguments.
    ///
    /// Clap's `env` attribute already handles environment-variable fallback for
    /// `--schema` (`SERVER_DEFAULT_SCHEMA_PATH`) and `--space-root` (`SERVER_SPACE_ROOT`).
    pub fn from_cli(args: &CliArgs) -> Result<Self, io::Error> {
        let bootstrap_data = match &args.schema {
            Some(path) => BootstrapDataSource::SchemaFile(path.clone()),
            None => BootstrapDataSource::None,
        };

        Ok(Self {
            verbose_logfile: Some("logfile.txt".to_string()),
            space_root: args.space_root.clone(),
            bootstrap_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_with_no_args() {
        let args = CliArgs::try_parse_from(["server"]).unwrap();
        assert_eq!(args.bind_addr, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(args.port, 8080);
        assert_eq!(args.tls_port, 8443);
        assert!(args.schema.is_none());
    }

    #[test]
    fn schema_flag() {
        let args = CliArgs::try_parse_from(["server", "--schema", "seed.json"]).unwrap();
        assert_eq!(args.schema.as_deref(), Some("seed.json"));
    }

    #[test]
    fn schema_equals_syntax() {
        let args = CliArgs::try_parse_from(["server", "--schema=seed.json"]).unwrap();
        assert_eq!(args.schema.as_deref(), Some("seed.json"));
    }

    #[test]
    fn restore_flag_is_error() {
        assert!(CliArgs::try_parse_from(["server", "--restore", "space.json"]).is_err());
    }

    #[test]
    fn server_config_from_cli_args() {
        let args = CliArgs::try_parse_from([
            "server",
            "--bind-addr",
            "0.0.0.0",
            "--port",
            "9090",
            "--tls-port",
            "9443",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
        ])
        .unwrap();
        let srv = ServerConfig::from(&args);
        assert_eq!(srv.bind_host, IpAddr::from([0, 0, 0, 0]));
        assert_eq!(srv.port, 9090);
        assert_eq!(srv.tls_port, 9443);
        assert_eq!(srv.tls_config(), Some(("c.pem".into(), "k.pem".into())));
    }

    #[test]
    fn tls_config_none_when_incomplete() {
        let args = CliArgs::try_parse_from(["server", "--tls-cert", "c.pem"]).unwrap();
        let srv = ServerConfig::from(&args);
        assert!(srv.tls_config().is_none());
    }

    #[test]
    fn schema_flag_sets_bootstrap_data() {
        let args = CliArgs::try_parse_from(["server", "--schema", "s.json"]).unwrap();
        let cfg = AppConfig::from_cli(&args).unwrap();
        assert!(matches!(cfg.bootstrap_data, BootstrapDataSource::SchemaFile(p) if p == "s.json"));
    }

    #[test]
    fn no_schema_means_no_bootstrap_data() {
        let args = CliArgs::try_parse_from(["server"]).unwrap();
        let cfg = AppConfig::from_cli(&args).unwrap();
        assert!(matches!(cfg.bootstrap_data, BootstrapDataSource::None));
    }

    #[test]
    fn unknown_flag_is_error() {
        assert!(CliArgs::try_parse_from(["server", "--bogus"]).is_err());
    }
}
