# Server

Runs a WebSocket server that services remote database requests from the SDK.  
Each request is executed against a Merk database on the server, and results are returned to the client.

## CLI Options

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--schema <path>` | `SERVER_DEFAULT_SCHEMA_PATH` | — | Schema file applied to every new Space (`.kdl` or JSON `SchemaBundle`) |
| `--space-root <path>` | `SERVER_SPACE_ROOT` | — | Root directory for per-Space local artifacts |
| `--bind-addr <host>` | `BIND_ADDR` | `127.0.0.1` | Host address to bind |
| `--port <port>` | `PORT` | `8080` | HTTP port |
| `--tls-port <port>` | `TLS_PORT` | `8443` | TLS port (used instead of `--port` when TLS is configured) |
| `--tls-cert <path>` | `TLS_CERT_PATH` | — | Path to TLS certificate file (PEM) |
| `--tls-key <path>` | `TLS_KEY_PATH` | — | Path to TLS private key file (PEM) |

CLI flags take precedence over environment variables.

## Examples

### Basic — new Spaces with a schema template

```bash
cargo run -p encrypted-spaces-backend-server -- --schema ./demos/tauri/app_schema.kdl
```

### Use a per-Space artifact root

```bash
cargo run -p encrypted-spaces-backend-server -- \
  --schema ./demos/tauri/app_schema.kdl \
  --space-root ./spaces
```

### Custom address and port

```bash
cargo run -p encrypted-spaces-backend-server -- \
  --schema ./demos/tauri/app_schema.kdl \
  --space-root ./spaces \
  --bind-addr 0.0.0.0 \
  --port 9090
```

### TLS (`wss://`)

The SDK's WebSocket client performs full TLS chain + hostname validation against the OS trust store — there is no "skip verification" mode. To enable `wss://`, place a valid PEM-encoded certificate and private key in [`backend/server/certs/`](./certs/) (or any directory of your choice), then start the server with `--tls-cert` / `--tls-key` pointing at them:

```bash
cargo run -p encrypted-spaces-backend-server -- \
  --schema ./demos/tauri/app_schema.kdl \
  --tls-cert ./backend/server/certs/server-cert.pem \
  --tls-key ./backend/server/certs/server-key.pem
```

The server then listens on `127.0.0.1:8443` (override with `--tls-port`), and clients connect with `wss://<hostname>:8443/ws`. The hostname in the client URL must match a SAN on the cert, and the cert must chain to a CA the client machine trusts. Provisioning the cert itself is out of scope for this README — use whatever mechanism is appropriate for your environment.

If you replace the cert, restart the server so it loads the new key.

The cert and key can live anywhere readable by the server process; [`backend/server/certs/`](./certs/) is just a convenient default location. The repo's `.gitignore` excludes `*.pem`, `*.key`, and `*.crt` under that directory so dev certs you drop there won't be committed accidentally. If you store them elsewhere in the repo, add equivalent ignore rules for that path. Treat the private key as sensitive and never commit or ship it regardless of location.

#### Dev / test with self-signed certs

For dev or CI scenarios where the server cert is self-signed (i.e. doesn't chain to any CA the OS trust store knows), the Tauri demo accepts a flag that adds an **extra** trust anchor to the client without disabling chain or hostname validation:

| Flag | Env var | Description |
|------|---------|-------------|
| `--trust-cert=<PATH>` | `ENCRYPTED_SPACES_TRUST_CERT` | Add a single PEM or DER cert file as a trust anchor |

Only one anchor is supported. If both the CLI flag and the env var are set, the CLI flag wins.

A startup audit log records the source path and SHA-256 of the cert that gets loaded, so operators can confirm what their client trusts on each launch.

Example: generate a self-signed cert with a `127.0.0.1` SAN, start the server with it, and run the demo client with that cert as a trust anchor:

```bash
# 1. One-time: generate a self-signed cert covering 127.0.0.1.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout backend/server/certs/dev-key.pem \
  -out    backend/server/certs/dev-cert.pem \
  -days 365 -subj '/CN=encrypted-spaces-dev' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

# 2. Start the server with TLS.
cargo run -p encrypted-spaces-backend-server -- \
  --schema ./demos/tauri/app_schema.kdl \
  --tls-cert ./backend/server/certs/dev-cert.pem \
  --tls-key  ./backend/server/certs/dev-key.pem

# 3a. Recommended for `tauri dev`: use the env var. `tauri dev` forwards
#     extra tokens to `cargo run` (not to the binary), so `--trust-cert=...`
#     on the command line ends up parsed by cargo and rejected. The env
#     var passes through cleanly.
#
#     Heads-up: under `tauri dev` the binary's cwd is
#     `demos/tauri/src-tauri/`, NOT the directory you ran `npm` from.
#     Relative paths resolve against that cwd. The simplest fix is to
#     pass an absolute path via `$PWD` from the repo root.
ENCRYPTED_SPACES_TRUST_CERT=$PWD/backend/server/certs/dev-cert.pem \
  npm --prefix demos/tauri run tauri dev

# 3b. The CLI flag works when invoking the binary directly (no `tauri dev`).
cargo run -p encrypted-spaces-demo -- \
  --trust-cert=./backend/server/certs/dev-cert.pem
```

In the demo's Setup screen, enter `wss://127.0.0.1:8443/ws` as the server address. The same anchor is used for both the WebSocket upgrade and the file-store HTTPS calls.

### Using environment variables

```bash
SERVER_DEFAULT_SCHEMA_PATH=./demos/tauri/app_schema.kdl \
SERVER_SPACE_ROOT=./spaces \
BIND_ADDR=0.0.0.0 \
PORT=9090 \
cargo run -p encrypted-spaces-backend-server
```

### Debug output

```bash
RUST_LOG=info,debug cargo run -p encrypted-spaces-backend-server -- \
  --schema ./demos/tauri/app_schema.kdl
```

## Server console commands

```
  print     | p - pretty-print all tables to console
  changelog | c - dump the changelog to the console
  quit      | q - stop the server
  help      | h - show this list
```

The interactive console only runs when stdin is a TTY. In detached
containers / under systemd it is skipped automatically; the server
still listens normally.

## Docker

The server ships with a `Dockerfile` (amd64-only). Builds require
BuildKit plus SSH access to the private `encrypted-spaces/merk-nomic`
repository.

The image is currently built in **dev mode** (RISC0 fake proofs) for
fast iteration. To switch to real proofs see the
"Switching to real proofs" subsection below and the comment block at
the top of `backend/server/Dockerfile`.

### Build

```bash
# From the repo root:
docker buildx build \
  --ssh default \
  --platform linux/amd64 \
  -f backend/server/Dockerfile \
  -t encrypted-spaces-server:dev \
  .
```

To bake a different schema into the image, override the
`SERVER_SCHEMA_SOURCE` build arg (resolved against the build context):

```bash
docker buildx build \
  --ssh default \
  --platform linux/amd64 \
  -f backend/server/Dockerfile \
  --build-arg SERVER_SCHEMA_SOURCE=path/to/your_schema.kdl \
  -t encrypted-spaces-server:dev \
  .
```

Notes:

- `--ssh default` forwards your host's SSH agent into the build so
  Cargo can fetch `merk-nomic`. The workspace `Cargo.toml` declares
  the dep with an `ssh://` URL, so the agent is used directly.
- The build compiles the workspace once and the RISC0 guest ELFs
  for both `encrypted-spaces-ffproof-methods` and `encrypted-spaces-client-methods`
  (required even in dev mode — see "Switching to real proofs" below).
  First build is typically 5–10 minutes; rebuilds reuse a BuildKit
  `target/` cache.
- The RISC0 toolchain is pinned via `--build-arg RISC0_VERSION=` —
  bump it in lockstep with `risc0-zkvm` / `risc0-build` in workspace
  `Cargo.toml`.
- `--build-arg SERVER_SCHEMA_SOURCE=...` picks which schema KDL is
  baked into the image at `/etc/encrypted-spaces/app_schema.kdl`.
  Defaults to `demos/tauri/app_schema.kdl`.

### Run

Ephemeral (in-memory) — useful for smoke tests. The image bakes in
the schema selected by the `SERVER_SCHEMA_SOURCE` build arg (default:
`demos/tauri/app_schema.kdl`) at `/etc/encrypted-spaces/app_schema.kdl`
and points `SERVER_DEFAULT_SCHEMA_PATH` at it by default, so no schema
mount is needed:

```bash
docker run --rm -p 8080:8080 encrypted-spaces-server:dev
```

To apply a different schema, mount it and override the env var:

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/my_schema.kdl:/schema/app_schema.kdl:ro" \
  -e SERVER_DEFAULT_SCHEMA_PATH=/schema/app_schema.kdl \
  encrypted-spaces-server:dev
```

Persistent file-blob store (the Merk DB stays in-memory regardless;
see "Volumes and ports" below):

```bash
docker volume create encrypted-spaces-data
docker run -d --name encrypted-spaces \
  -p 8080:8080 \
  -v encrypted-spaces-data:/data \
  -e SERVER_SPACE_ROOT=/data \
  encrypted-spaces-server:dev
```

If you switch to real proofs, add `--stop-timeout 60` (or higher):
real proof generation can take longer than Docker's default 10-second
SIGTERM grace period to finish in `add_change`, and without a larger
budget `docker stop` will SIGKILL in-flight proving. Dev-mode proofs
complete in milliseconds, so the default is fine for this image.

### Configuration via environment

All flags from the CLI options table above are accepted as env
variables. Image defaults:

| Variable           | Default      | Notes |
|--------------------|--------------|-------|
| `BIND_ADDR`        | `0.0.0.0`    | Bind all interfaces inside the container |
| `PORT`             | `8080`       | |
| `TLS_PORT`         | `8443`       | Used instead of `PORT` when TLS is configured |
| `RUST_LOG`         | `info`       | |
| `RISC0_DEV_MODE`   | `1`          | Fake proofs (matches the dev-mode build) |
| `SERVER_SPACE_ROOT`| *(unset)*    | Set to `/data` to persist per-space file blobs; the Merk database is in-memory regardless and is lost on container restart |
| `SERVER_DEFAULT_SCHEMA_PATH` | `/etc/encrypted-spaces/app_schema.kdl` | The demo schema (`demos/tauri/app_schema.kdl`) is baked into the image at this path. Override to point at a mounted schema file (KDL or JSON) if you need a different one |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | *(unset)* | PEM files; mount them into the container |

### Switching to real proofs

The current image builds **without**
`--features encrypted-spaces-ffproof/real-proofs`, so the runtime always
produces fake proofs (`RISC0_DEV_MODE=1`).

Guest ELFs are still compiled and embedded (no `RISC0_SKIP_BUILD=1`)
because `r0vm` loads and parses them in both modes — skipping the
build crashes with `Malformed ProgramBinary: unexpected end of file`.
The `r0vm` binary itself is shipped (~109 MB) because `risc0-zkvm
3.0.x` always uses `ExternalProver`, which shells out to `r0vm` for
both real and dev-mode proving (the dev-mode short-circuit happens
inside `r0vm`).

To produce a real-proofs image, edit `backend/server/Dockerfile`:

1. **Builder stage**, add `--features encrypted-spaces-ffproof/real-proofs`
   to the `cargo build --release` line.
2. **Runtime stage**, change `ENV RISC0_DEV_MODE=1` to
   `ENV RISC0_DEV_MODE=0`.
3. **Documentation**, set `--stop-timeout 60` (or larger) on
   `docker run` and `docker stop`.

A GPU (Bonsai or a CUDA `r0vm`) is required for efficient proving.


### Volumes and ports

- `VOLUME /data` — per-space **file store** (binary blobs uploaded via
  `/file/<hash>`). The Merk relational database itself is in-memory only
  and **does not survive restart**. Use `SERVER_DEFAULT_SCHEMA_PATH`
  to bootstrap schema for new spaces at startup. **Single-writer:** each process owns its
  own in-memory state, so do not run multiple replicas against the
  same `/data` volume expecting shared state.
- `EXPOSE 8080 8443` — HTTP + TLS, only one is active at a time
  (TLS is selected automatically when `TLS_CERT_PATH` and
  `TLS_KEY_PATH` are both set).

### Healthcheck

The image's `HEALTHCHECK` hits `GET /healthz`, switching to HTTPS when
TLS is configured. Override at runtime via
`docker run --health-cmd ...` if you need different behavior.

### Caveats

- **Non-root user** (uid 1000). Host bind mounts must be readable /
  writable by uid 1000:
  ```bash
  chown -R 1000:1000 ./my-data
  # or:
  docker run --user $(id -u):$(id -g) ...
  ```
- **Authentication is a placeholder.** `AuthContext` is currently
  passed as a base64url query-string parameter; do not expose the
  container to the open internet without a fronting auth layer.
