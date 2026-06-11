# Encrypted Collaboration Spaces

A cryptographic framework for building collaborative applications over an
untrusted server, and a working prototype implementation.

The cryptographic design is described in full in the
[whitepaper](https://encryptedspaces.org/whitepapers/encrypted-spaces.pdf). For a
high-level overview of the project, see
[encryptedspaces.org](https://encryptedspaces.org).

## ⚠️⚠️⚠️ DO NOT USE IN PRODUCTION ⚠️⚠️⚠️

This is experimental code published for research purposes.

The implementation remains under active development and has not yet undergone the level of security review, testing, auditing, and hardening required for production deployment. The issues tracked in this repository are not a complete accounting of security limitations, known issues, or remaining risks.

***This code MUST NOT be used to protect sensitive data or in security-critical applications.***

- **Authentication is a placeholder.** The reference server accepts a
  client-asserted identity on connection and does not yet verify it. Security
  rests on the cryptographic verification each client performs on server
  responses, *not* on server-enforced access control.
- **Fast-forward proofs require `--features real-proofs`.** Default builds run
  RISC Zero in dev mode (`RISC0_DEV_MODE=1`), which accepts non-cryptographic
  "fake" receipts for fast iteration. Builds intended to rely on succinct
  fast-forward proofs must enable the `real-proofs` feature.
- **DoS hardening is incomplete.** Some deserialization paths are not yet
  depth-bounded, so malformed input can exhaust resources. The insider-DoS
  resistance described in the design goals below is a target, not a hardened
  guarantee in this prototype.

## What is this?

Most collaboration software stores shared application state on servers in
plaintext, requiring users to trust those servers (and any integrated
services) with the contents of their documents, chats, and databases.
End-to-end encryption addresses messaging but does not directly generalize
to applications where participants must read, modify, and verify long-lived
structured state.

An *Encrypted Collaboration Space* is a shared, mutable application state
with dynamic membership, shared cryptographic key material, an authenticated
history of operations, and a verifiable database representing current
contents. The server holds only ciphertexts and proof material; clients
verify every server response locally with cryptographic proofs.

The design targets four security properties:

- **Verifiable history.** Members can confirm that the membership list and
  shared data are the correct result of all previous operations.
- **Selective data retention.** Members can delete shared data items and
  give new members access to the non-deleted older data.
- **Insider robustness.** Malicious insiders cannot compromise security of
  communications occurring before or after their membership, or cause
  denial of service for other members.
- **Deniable sender authentication.** Members can authenticate the author
  of each data object without producing publicly-verifiable cryptographic
  evidence of user relationships.

## Architecture at a glance

- **Changelog.** Append-only, hash-chained log of operations. The
  authenticated history of a Space.
- **Verifiable database.** Current state exposed via Merkle search trees;
  clients check the database commitment against the latest changelog
  commitment on every response.
- **Tables, lists, text.** Relational rows with primary-key and
  secondary-index search trees; ordered lists via keyless
  order-statistic trees; collaborative text layered on lists.
- **Membership.** A members table tracks who can participate. Existing
  members invite new ones by issuing provisional keys; removal triggers a
  rekey of the remaining members, without requiring re-encryption of data.
- **Access control.** Per-table rules constrain which members can write or
  delete which rows, enforced cryptographically rather than by
  server policy.
- **Retention.** Members can grant new joiners access to historic data, or
  selectively delete data before a chosen point so neither the server nor
  future members can read it, without re-encrypting the entire Space.
- **Fast-forward proofs.** Succinct zero-knowledge proofs that let clients
  skip ahead in the changelog without replaying every operation.

## Repository layout

| Path           | Contents                                                |
| -------------- | ------------------------------------------------------- |
| `sdk/`         | Client SDK and verifiable database API (start here)     |
| `crypto/`      | Core cryptographic primitives                           |
| `zkp/`         | Zero-knowledge proof system                             |
| `ffproof/`     | Fast-forward changelog proofs                           |
| `retention/`   | Selective data retention construction                   |
| `key_manager/` | Group key state and rekey protocols                     |
| `backend/`     | Reference server implementation                         |
| `demos/`       | Example applications                                    |

## Using the SDK

The `sdk/` crate is the main interface for application developers. It
exposes a relational database API: tables, rows, schemas, and access
control rules. It also handles encryption, proof verification, and
synchronization with the backend behind the scenes.

See [`sdk/README.md`](sdk/README.md) for an overview, code examples, and
quickstart instructions.

## Prerequisites

The Rust toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml)
and installed automatically by `cargo`; you only need
[rustup](https://rustup.rs/) itself.

| Dependency                   | Needed for                                  | Notes                                                            |
| ---------------------------- | ------------------------------------------- | ---------------------------------------------------------------- |
| rustup / Rust                | everything                                  | toolchain auto-installs from `rust-toolchain.toml`               |
| protobuf compiler            | building the workspace                      |                                                                  |
| Node.js + npm                | the Tauri demo                              |                                                                  |
| WebKit / GTK system libraries | the Tauri demo (Linux only)                | see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) |
| Python 3 (with `venv`)       | the demo launcher                           | the launcher bootstraps its own venv + Textual                   |
| RISC Zero                    | **optional** — succinct fast-forward proofs | skip with `RISC0_SKIP_BUILD=1`                                   |

### macOS

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
brew install protobuf node
# Optional: RISC Zero, only for succinct fast-forward proofs
curl -L https://risczero.com/install | bash
```

### Ubuntu

```bash
sudo apt install libssl-dev pkg-config protobuf-compiler nodejs npm \
    libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
# Optional: RISC Zero, only for succinct fast-forward proofs
curl -L https://risczero.com/install | bash
```

See [`openssl-sys`](https://docs.rs/openssl/latest/openssl/#automatic) for
other systems, and the
[Tauri prerequisites guide](https://v2.tauri.app/start/prerequisites/) for the
demo's system dependencies on other platforms.

### Build and test

```bash
cargo build
cargo test
```

RISC Zero is only required for succinct fast-forward proofs. If you have not
installed it, skip building the zkVM guest by setting `RISC0_SKIP_BUILD=1`:

```bash
RISC0_SKIP_BUILD=1 cargo build
```

`--release` improves runtime performance significantly at the cost of
compile time.

## Demo

The canonical end-to-end demo lives in `demos/tauri`. This demonstrates
how one might build various applications such as a multi-channel chat,
document editor, calendar, task list, and file system. The demo is built
with [Tauri v2](https://v2.tauri.app/) and [Next.js](https://nextjs.org/).
It exercises the full stack: the Rust SDK manages a `Space`, encrypts and
signs each operation, and synchronizes with the reference backend over WebSocket;
the React frontend talks to the SDK through Tauri's IPC bridge. Multiple instances
connect to the same backend and verify each other's writes via cryptographic proofs.

Once the prerequisites above are installed, run the launcher from the
repository root:

```bash
python3 demos/tauri/demo_launcher.py
```

The launcher builds everything, starts the backend and the Next.js dev server,
and provides a TUI for spawning additional client instances. It bootstraps its
own Python virtual environment (installing
[Textual](https://github.com/Textualize/textual) for the TUI); the remaining
prerequisites — Node.js and, on Linux, the WebKit/GTK libraries — must already
be installed. If RISC Zero is not detected, the launcher automatically builds
and runs without succinct fast-forward proofs.

See [`demos/tauri/README.md`](demos/tauri/README.md) for prerequisites,
manual run instructions, and architecture details.

## About

Encrypted Spaces is a project of the Encrypted Spaces Foundation, a nonprofit corporation,
developed with close collaboration and support from the Cryptography Group at Microsoft Research
and the Applied Social Media Lab at Harvard's
Berkman Klein Center for Internet & Society.

## License

Apache License 2.0. See [LICENSE](LICENSE).
