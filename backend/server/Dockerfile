# syntax=docker/dockerfile:1.7
#
# Dockerfile for encrypted-spaces-backend-server (amd64).
#
# Build:
#   docker buildx build --ssh default --platform linux/amd64 \
#     -f backend/server/Dockerfile -t encrypted-spaces-server .
#
# Notes:
#   * BuildKit is required for `--mount=type=ssh`, `--mount=type=cache`,
#     and `--mount=type=secret`.
#   * The build needs SSH access to encrypted-spaces/merk-nomic. The
#     workspace `Cargo.toml` already declares the dep with an
#     `ssh://git@github.com/...` URL, so the SSH agent forwarded via
#     `--mount=type=ssh` is used directly.
#
# ─── Proof mode ────────────────────────────────────────────────────────────
#
# This image is currently built in **dev mode** (RISC0 fake proofs):
#   * `--features encrypted-spaces-ffproof/real-proofs` is NOT passed, so
#     `encrypted-spaces-ffproof`
#     leaves `RISC0_DEV_MODE=1` as the default. The runtime image also
#     pins it explicitly via ENV so behavior is unambiguous.
#   * Guest ELFs ARE built (no `RISC0_SKIP_BUILD=1`). They must exist as
#     real RISC-V binaries because `r0vm` loads and parses them even in
#     dev mode — it only short-circuits the *STARK proving* step, not
#     ELF loading. Skipping the build produces zero-byte placeholders
#     that crash r0vm with `Malformed ProgramBinary: unexpected end of
#     file`.
#   * The RISC0 toolchain (`rzup`) is installed in the builder so guest
#     ELFs can compile. The runtime image ships `r0vm` (~109 MB):
#     risc0-zkvm 3.0.x's `default_prover()` always returns an
#     `ExternalProver` that shells out to `r0vm` for both real and
#     dev-mode proving. Without `r0vm` on PATH the server panics with
#     `os error 2` on the first FF proof attempt.
#
# To re-enable real proofs:
#   1. Pass `--features encrypted-spaces-ffproof/real-proofs` to
#      `cargo build` (this stops ffproof from forcing
#      `RISC0_DEV_MODE=1` at runtime).
#   2. In runtime stage, set `ENV RISC0_DEV_MODE=0`.
#   3. Bump `docker stop -t 60` (or larger) in deployment docs — real
#      proofs in `add_change` can take minutes per batch on CPU and
#      will SIGKILL otherwise.
#
# RISC0 toolchain version is pinned to match the locked
# `risc0-zkvm` / `risc0-build` versions in workspace `Cargo.toml`.
# Update RISC0_VERSION in lockstep when bumping those crates.

ARG RUST_BASE=rust:1-bookworm
ARG RUNTIME_BASE=debian:bookworm-slim
ARG RISC0_VERSION=3.0.5

# Schema to bake into the image at `/etc/encrypted-spaces/app_schema.kdl`,
# which is the default `SERVER_DEFAULT_SCHEMA_PATH`. Override with
# `--build-arg SERVER_SCHEMA_SOURCE=path/to/your_schema.kdl` (the path
# is resolved against the Docker build context — typically the repo
# root when this Dockerfile is invoked from there).
ARG SERVER_SCHEMA_SOURCE=demos/tauri/app_schema.kdl

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM ${RUST_BASE} AS builder

ARG RISC0_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=always \
    CARGO_INCREMENTAL=0 \
    CARGO_NET_GIT_FETCH_WITH_CLI=true

# Build deps for the workspace. protobuf-compiler is used by
# backend/build.rs (prost_build); openssh-client/git enable the
# SSH-forwarded private dep fetch for encrypted-spaces/merk-nomic.
# As of the InMemoryOnly merk refactor the build no longer needs
# RocksDB or its dev libs (clang/cmake/libgflags/libsnappy/etc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        jq \
        openssh-client \
        pkg-config \
        protobuf-compiler \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# RISC0 toolchain (rzup). cargo-risczero / r0vm are pinned to
# RISC0_VERSION so they match the locked risc0-zkvm / risc0-build in
# the workspace Cargo.toml. The RISC0 rust toolchain has its own
# versioning scheme (not the zkvm version), so we install whatever
# `rzup install rust` selects as the latest compatible toolchain. The
# build fails loudly if the installed cargo-risczero version doesn't
# match RISC0_VERSION.
ENV PATH="/root/.risc0/bin:/root/.rzup/bin:${PATH}"
RUN set -eux; \
    curl -L https://risczero.com/install | bash; \
    rzup install rust; \
    rzup install cargo-risczero ${RISC0_VERSION}; \
    rzup install r0vm ${RISC0_VERSION}; \
    installed="$(cargo risczero --version | awk '{print $2}')"; \
    if [ "${installed}" != "${RISC0_VERSION}" ]; then \
        echo "ERROR: cargo-risczero ${installed} != ${RISC0_VERSION}"; exit 1; \
    fi

WORKDIR /usr/src/app

# Pre-trust github.com's host key so the SSH-mounted Cargo fetch
# doesn't prompt or fail on first contact.
RUN mkdir -p /root/.ssh && \
    printf "%s\n" \
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" \
        > /root/.ssh/known_hosts && \
    chmod 600 /root/.ssh/known_hosts

# Copy the workspace. We rely on `.dockerignore` to keep target/,
# .git/, node_modules/, etc. out of the build context.
COPY . .

# Single combined `RUN`:
#   * --mount=type=ssh forwards the host SSH agent so cargo can clone
#     merk-nomic from the encrypted-spaces org.
#   * Cache mounts speed up rebuilds without baking dep state into the
#     final image.
#   * Guest ELFs ARE built (no `RISC0_SKIP_BUILD=1`). They must be real
#     binaries because `r0vm` loads and parses them in both real and
#     dev mode. The dev-mode short-circuit (fast fake receipts) only
#     skips the STARK proving step itself.
#   * No `--features encrypted-spaces-ffproof/real-proofs`:
#     encrypted-spaces-ffproof's default code path sets RISC0_DEV_MODE=1
#     at startup. `r0vm` then produces fake receipts in milliseconds
#     instead of running real STARKs.
#
# To switch this image to real proofs:
#   1. Add `--features encrypted-spaces-ffproof/real-proofs` to
#      `cargo build`.
#   2. See header comments for the runtime-stage change
#      (RISC0_DEV_MODE=0).
#
# A future improvement (tracked in plan.md) is to introduce a
# cargo-chef stage so dep compilation isn't invalidated on every
# source change. The nested RISC0 guest workspaces make manual
# manifest-first copying brittle, so we leave it as a follow-up for
# now and rely on the BuildKit `target/` cache mount.
RUN --mount=type=ssh \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/usr/src/app/target,sharing=locked,id=encrypted-spaces-server-target \
    set -eux; \
    cargo build --release --locked \
        -p encrypted-spaces-backend-server; \
    # The `target/` mount disappears when the RUN ends, so move the
    # binary somewhere persistent before the cache mount unmounts.
    cp target/release/encrypted-spaces-backend-server /usr/local/bin/encrypted-spaces-server; \
    strip /usr/local/bin/encrypted-spaces-server; \
    # Also stash the FF guest image ID before the target/ mount goes
    # away. Clients that build against this exact server image can pin
    # the same ImageID by passing `ENCRYPTED_SPACES_FF_IMAGE_ID_FILE=...`
    # to their build — see the `ff-image-id` stage below.
    mkdir -p /artifacts; \
    methods_rs="$(find target/release/build \
        -path '*encrypted-spaces-ffproof-methods-*/out/methods.rs' \
        -printf '%T@ %p\n' | sort -rn | head -1 | awk '{print $2}')"; \
    if [ -z "$methods_rs" ]; then \
        echo "ERR: could not locate FF methods.rs (guest build skipped?)" >&2; \
        exit 1; \
    fi; \
    sed -nE 's/.*EXTEND_FF_ID:[[:space:]]*\[u32;[[:space:]]*8\][[:space:]]*=[[:space:]]*\[([^]]+)\].*/\1/p' \
        "$methods_rs" \
        | tr ',' ' ' \
        | tr -s ' ' \
        | sed -e 's/^ //' -e 's/ $//' \
        > /artifacts/ff_image_id.txt; \
    tokens=$(wc -w < /artifacts/ff_image_id.txt); \
    if [ "$tokens" -ne 8 ]; then \
        echo "ERR: extracted $tokens FF image ID tokens, expected 8" >&2; \
        exit 1; \
    fi; \
    echo "FF guest image ID: $(cat /artifacts/ff_image_id.txt)"

# ---------------------------------------------------------------------------
# Stage 2: ff-image-id (optional, build-only)
# ---------------------------------------------------------------------------
#
# Exports the FF guest ImageID computed inside the builder as a single
# extractable file. This stage is NOT selected by a default
# `docker buildx build` — choose it explicitly with `--target ff-image-id`
# and `--output ...` to retrieve the file. Example:
#
#   docker buildx build \
#     --ssh default --platform linux/amd64 \
#     -f backend/server/Dockerfile \
#     --target ff-image-id \
#     --output type=tar,dest=./ff-image-id.tar \
#     .
#   mkdir -p client-build-config
#   tar -xf ff-image-id.tar -C client-build-config
#   # client-build-config/ff_image_id.txt now contains the ImageID.
#
# Use `--output type=tar` (not `type=local`) — `local` tries to chown
# back to root on the host and fails on rootless / WSL setups.
#
# Clients can then build against this server's exact ImageID:
#
#   ENCRYPTED_SPACES_FF_IMAGE_ID_FILE=$PWD/client-build-config/ff_image_id.txt \
#     cargo build -p encrypted-spaces-demo
#
# This is the recommended way to interoperate with a deployed server:
# without it, host-built clients and container-built servers produce
# different ImageIDs (because the guest ELF embeds environment-
# sensitive bytes like absolute paths) and proof verification fails.
#
# This stage must come BEFORE the runtime stage so that the runtime
# image remains the default `docker buildx build` target.
FROM scratch AS ff-image-id
COPY --from=builder /artifacts/ff_image_id.txt /ff_image_id.txt

# ---------------------------------------------------------------------------
# Stage 3: runtime (default build target)
# ---------------------------------------------------------------------------
FROM ${RUNTIME_BASE} AS runtime

# Runtime-only shared libs. The server binary links libc, libm, and
# libgcc_s; we use rustls (not openssl), so libssl3 is not needed.
# curl is kept for the HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/encrypted-spaces-server /usr/local/bin/encrypted-spaces-server

# Ship `r0vm` even though we're in dev mode.
#
# risc0-zkvm 3.0.x always uses `ExternalProver` from `default_prover()`,
# which shells out to `r0vm` for both real and dev-mode proving. The
# dev-mode short-circuit (fast fake receipts) happens *inside* `r0vm`
# itself — not in the calling library. Without this binary on PATH,
# the server panics with `os error 2: No such file or directory` the
# first time `add_change → maybe_generate_ff_proof` runs (every 5
# changes by default).
#
# To switch this image to real proofs, the only other things needed are:
#   * Build with `--features encrypted-spaces-ffproof/real-proofs`.
#   * Change `ENV RISC0_DEV_MODE=1` to 0 below.
#   * Bump `docker stop -t 60` in deployment docs.
COPY --from=builder /root/.risc0/extensions /opt/risc0/extensions
RUN set -eux; \
    r0vm_path="$(find /opt/risc0/extensions -name r0vm -type f -executable | head -1)"; \
    if [ -z "$r0vm_path" ]; then echo "r0vm not found in /opt/risc0"; exit 1; fi; \
    ln -s "$r0vm_path" /usr/local/bin/r0vm; \
    /usr/local/bin/r0vm --version

# Non-root user. uid 1000 is the conventional default; host bind
# mounts will need to be chowned to 1000:1000 (or runs need
# `--user $(id -u):$(id -g)`). See README.
# We deliberately do NOT use `--system` here: combining `--system`
# with an explicit `--uid 1000` triggers Debian's `SYS_UID_MAX` warning
# (system uids are <999). 1000 is the standard non-system uid we want.
RUN groupadd --gid 1000 spaces \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /data --shell /usr/sbin/nologin spaces \
    && mkdir -p /data /etc/encrypted-spaces \
    && chown spaces:spaces /data

# Bake a schema into the image so the container can run in
# environments that forbid mounting any volume — for example Azure
# Container Instances with managed-identity-only access. The schema
# source is controlled by the `SERVER_SCHEMA_SOURCE` build argument
# (defaults to `demos/tauri/app_schema.kdl`); override with
# `--build-arg SERVER_SCHEMA_SOURCE=path/to/your_schema.kdl`.
#
# The destination path inside the image is always
# `/etc/encrypted-spaces/app_schema.kdl`, matching
# `SERVER_DEFAULT_SCHEMA_PATH` below. Mount a different schema and
# override the env var at run time to use it for newly-created spaces.
ARG SERVER_SCHEMA_SOURCE
COPY --chown=root:root --chmod=0644 \
    ${SERVER_SCHEMA_SOURCE} /etc/encrypted-spaces/app_schema.kdl

USER spaces:spaces
WORKDIR /data
VOLUME ["/data"]

# Listen on all interfaces by default; users can override via env.
# SERVER_SPACE_ROOT is intentionally NOT set: keep the existing
# "in-memory unless explicitly persistent" signal — defaulting to
# /data would silently lose data on `docker rm` without a mounted
# volume. Users opt in with:
#   -v encrypted-spaces-data:/data -e SERVER_SPACE_ROOT=/data
#
# SERVER_DEFAULT_SCHEMA_PATH points at the schema baked in above so
# the container is self-contained out of the box. Override by setting
# the env var at `docker run` time when you have a different schema
# to apply to newly-created spaces.
#
# RISC0_DEV_MODE=1 matches the build configuration (no
# `--features encrypted-spaces-ffproof/real-proofs`). risc0-zkvm reads
# this var at runtime, so on a real-proofs build of the image,
# `-e RISC0_DEV_MODE=1` on `docker run` flips it into fake-proofs
# mode. The reverse (-e RISC0_DEV_MODE=0 on this dev-build image)
# does NOT enable real proofs: encrypted-spaces-ffproof's
# `ensure_risc0_proof_mode()` unconditionally sets RISC0_DEV_MODE=1
# at startup when the ffproof `real-proofs` feature is off.
ENV BIND_ADDR=0.0.0.0 \
    PORT=8080 \
    TLS_PORT=8443 \
    RUST_LOG=info \
    RISC0_DEV_MODE=1 \
    SERVER_DEFAULT_SCHEMA_PATH=/etc/encrypted-spaces/app_schema.kdl

EXPOSE 8080 8443

# Send SIGTERM (the default for `docker stop`) for explicitness; the
# server installs a SIGTERM/SIGINT handler that drains in-flight
# WebSocket connections before exiting. With real proofs the
# `add_change → maybe_generate_ff_proof` path can take minutes; bump
# `docker stop -t 60` (or higher) for those builds. Dev-mode proofs
# complete in milliseconds, so the default 10s is fine here.
STOPSIGNAL SIGTERM

# Healthcheck hits the stable /healthz route on the configured port.
# Switches to HTTPS when TLS material is configured.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD /bin/sh -c 'if [ -n "$TLS_CERT_PATH" ] && [ -n "$TLS_KEY_PATH" ]; then \
            curl -fksS "https://127.0.0.1:${TLS_PORT:-8443}/healthz" ; \
        else \
            curl -fsS "http://127.0.0.1:${PORT:-8080}/healthz" ; \
        fi || exit 1'

ENTRYPOINT ["/usr/local/bin/encrypted-spaces-server"]
