# TLS certs for `wss://`

This directory is a convenient default location for the PEM-encoded certificate and private key the server presents when launched with `--tls-cert` / `--tls-key`. It is **not required** — those flags accept any readable path, so the cert and key can live wherever makes sense for your environment.

The canonical TLS / `--trust-cert` documentation lives in [`../README.md`](../README.md#tls-wss). The summary below mirrors it so this folder is self-explanatory; if the two ever drift, the parent README wins.

## Summary (mirrors `../README.md`)

The SDK's WebSocket client performs full TLS chain + hostname validation against the OS trust store — there is no "skip verification" mode. To enable `wss://`, point the server at a PEM-encoded cert + key:

```bash
cargo run -p encrypted-spaces-backend-server -- \
  --schema ./demos/tauri/app_schema.kdl \
  --tls-cert ./backend/server/certs/server-cert.pem \
  --tls-key  ./backend/server/certs/server-key.pem
```

The server then listens on `127.0.0.1:8443` (override with `--tls-port`), and clients connect with `wss://<hostname>:8443/ws`. The hostname in the client URL must match a SAN on the cert, and the cert must chain to a CA the client machine trusts.

For dev or CI scenarios where the server cert is self-signed (i.e. doesn't chain to any CA the OS trust store knows), the Tauri demo accepts an extra trust anchor without disabling chain or hostname validation:

| Flag | Env var | Description |
|------|---------|-------------|
| `--trust-cert=<PATH>` | `ENCRYPTED_SPACES_TRUST_CERT` | Add a single PEM or DER cert file as a trust anchor |

Only one anchor is supported. If both are set, the CLI flag wins. A startup audit log records the source path and SHA-256 of the cert that gets loaded. See the parent README for the full `tauri dev` / direct-binary examples.

## Folder-specific notes

If you do drop cert files here, the layout might look like:

```
backend/server/certs/
├── server-cert.pem    # PEM-encoded certificate (public)
└── server-key.pem     # PEM-encoded private key (keep local)
```

The filenames are not special; the server uses whatever paths you pass on the command line.

### Don't commit private material

The repo's `.gitignore` already excludes `*.pem`, `*.key`, and `*.crt` under this directory so dev certs dropped here won't be committed accidentally. If you store cert material elsewhere in the repo, add equivalent ignore rules for that path. Treat the private key as sensitive and never commit or ship it regardless of location.
