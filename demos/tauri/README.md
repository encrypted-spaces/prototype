# Spaces — Tauri Demo

A desktop chat application demonstrating the Encrypted Spaces SDK. Built with [Tauri v2](https://v2.tauri.app/start/) (Rust backend) and [Next.js](https://nextjs.org/) (React frontend).

## What is Tauri?

Tauri is a framework for building desktop (and mobile) apps using web technologies for the UI and Rust for the backend. Unlike Electron, Tauri uses the OS's native webview instead of bundling Chromium, producing small, fast binaries. The two layers communicate via IPC — the frontend calls Rust functions through Tauri's `invoke()` bridge.

See the [Tauri v2 docs](https://v2.tauri.app/) for more.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Next.js Frontend (React/TypeScript)            │
│  app/, components/, lib/                        │
│                                                 │
│  invoke("send_message", { ... })                │
│         │                                       │
│─────────┼───────────────────────────────────────│
│         ▼  Tauri IPC bridge                     │
│  Rust Backend (src-tauri/)                      │
│  commands.rs → chat.rs → encrypted-spaces-sdk       │
│                              │                  │
│                              ▼                  │
│                    WebSocket to server           │
└─────────────────────────────────────────────────┘
```

- **Frontend** (`app/`, `components/`, `lib/`): Next.js with static export. React context for state, Tauri `invoke()` for all backend calls. No direct network access — everything goes through the Rust layer.
- **Backend** (`src-tauri/`): Rust process that manages the `Space<WebSocketTransport>`, handles encryption/decryption via the SDK, and connects to a remote Encrypted Spaces server over WebSocket.
- **Real-time updates**: The Rust backend listens for broadcast events from the server and emits Tauri events to the frontend.

### Why Next.js?

We use Next.js (in static export mode) as the frontend framework. The same React codebase could eventually power a browser-based web app that talks to the SDK through WASM bindings, once the SDK has been finalized and bridged to WebAssembly. Using Next.js now means the frontend components, state management, and UI can be reused with minimal changes when that transition happens.

## Prerequisites

- **Rust** toolchain (via [rustup](https://rustup.rs/))
- **Node.js** and **npm** (on Ubuntu: `sudo apt install npm`)
- **Tauri v2 CLI**: installed via npm (included in devDependencies)
- **System dependencies**: see the [Tauri prerequisites guide](https://v2.tauri.app/start/prerequisites/) for your OS. On Ubuntu:
  ```bash
  sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
  ```

## Running the Demo

All commands below are run from the repository root.

### 1. Start the backend server

```bash
cargo run -p encrypted-spaces-backend-server -- --schema ./demos/tauri/app_schema.kdl
```

By default the server listens for plaintext WebSocket connections on `127.0.0.1:8080`. The client can also connect over TLS (`wss://`) — see [TLS (`wss://`)](../../backend/server/README.md#tls-wss) in the server README for the full setup, then enter the `wss://127.0.0.1:8443/ws` URL in the Tauri app's Setup screen instead of `ws://127.0.0.1:8080/ws`.

### 2. Install frontend dependencies

```bash
npm --prefix demos/tauri install
```

### 3. Run in development mode

```bash
npm --prefix demos/tauri run tauri dev
```

This starts the Next.js dev server and opens the Tauri window. Rust and frontend changes hot-reload automatically.

### 4. Production build

```bash
npm --prefix demos/tauri run tauri build
```

Produces a native application bundle in `src-tauri/target/release/`.

## Running Multiple Instances

To test multi-user chat, you need multiple app instances connecting to the same server. Since Tauri stores app data per-user by default, each instance uses the same snapshot path. The simplest approach:

1. Run `npm --prefix demos/tauri run tauri dev` to open the first instance — create a space and a channel.
2. Use the invite dialog to generate an invite JSON file.
3. Run a second instance from a separate terminal with `cargo run -p encrypted-spaces-demo` — use "Join Space" with the invite file.

Both instances connect to the same backend server and receive real-time broadcast updates.

> **Tip**: If you need fully isolated instances (separate snapshots), you can change the `identifier` in `src-tauri/tauri.conf.json` before launching the second instance, which gives it a separate app data directory.

## Running Tests

The Rust backend has unit tests covering chat logic, command parsing, and state management:

```bash
cargo test -p encrypted-spaces-demo
```

The chat tests use `LocalTransport` (an in-memory transport from the SDK) to test business logic without a running server.

## Multi-Actor Harness (`demo-harness`)

A headless test harness drives the same Rust modules the Tauri commands wrap
(`chat`, `tasks`, `calendar`, `notes`, `files`) over an in-process
`LocalTransport`, with multiple `Space` handles representing different users.
Useful for orchestrating scripted scenarios (Alice creates, invites Bob, etc.)
and for fuzzing the UX surface without a running server or webview.

Build / run (the harness is a separate sibling crate so the regular Tauri
build is unchanged):

```bash
# Built-in Alice / Bob / Charlie scenario
cargo run -p encrypted-spaces-demo-test-harness --bin demo-harness -- demo

# Replay a JSON scenario
cargo run -p encrypted-spaces-demo-test-harness --bin demo-harness -- \
    replay demos/tauri/test-harness/scenarios/demo.json

# Random scenario (seeded; --save captures the trace for replay)
cargo run -p encrypted-spaces-demo-test-harness --bin demo-harness -- \
    fuzz --seed 42 --steps 100 --actors 4 --save /tmp/trace.json

# Just print a generated scenario (no execution)
cargo run -p encrypted-spaces-demo-test-harness --bin demo-harness -- \
    gen --seed 42 --steps 50
```

A scenario is a JSON list of `{actor, type, ...}` steps; see
[`test-harness/scenarios/demo.json`](test-harness/scenarios/demo.json) for the
full shape. The action vocabulary lives in
[`test-harness/src/action.rs`](test-harness/src/action.rs) — currently
covering space lifecycle (create/invite/join), channels, messages
(send/edit/delete/reply/react), tasks, calendar events, shared notes, and
explicit sync.

### Debugging failures

When a step errors, the runner returns a `RunnerError::Step { index, actor,
label, source }` carrying the full `anyhow` chain, and the CLI exits non-zero
with that error printed to stderr. To make post-mortem debugging easy:

- **Auto failure dump.** On failure the runner writes a `FailureReport` JSON
  containing the successful prefix (every step that ran cleanly), the failing
  step, and the formatted error chain. By default it lands at
  `<tempdir>/demo-harness-failure.json`; override with `--dump-failure
  <path>`, or pass `--dump-failure ''` to disable. Replay the prefix with:
  ```bash
  jq '.successful_prefix' /tmp/demo-harness-failure.json > /tmp/prefix.json
  cargo run -p encrypted-spaces-demo-test-harness --bin demo-harness -- \
      replay /tmp/prefix.json
  ```
- **Auto-saved fuzz scenarios.** `fuzz` always writes the generated scenario
  to `<tempdir>/demo-harness-fuzz-seed-<SEED>.json` (or `--save <path>`) before
  executing, so even a panicking run is reproducible via `replay`. Pass
  `--save ''` to opt out.
- **Verbose logs.** `RUST_LOG=debug` (or
  `RUST_LOG=encrypted_spaces_demo=debug,encrypted_spaces_sdk=info`) surfaces every
  dispatched step plus the SDK's own debug output. `--verbose` additionally
  prints the planned step list before execution starts.

When using the harness as a Rust library, set `runner.failure_dump_path =
Some(path)` before calling `runner.execute(&scenario).await`; the field is
unset by default so unit tests don't pollute the filesystem.

The harness is exercised in CI via:

```bash
cargo test -p encrypted-spaces-demo-test-harness --test harness_smoke
```

which runs the canned multi-actor scenario plus a short seeded fuzz pass and
asserts cross-actor convergence (Bob and Charlie see Alice's message; Alice
sees Bob's task; etc.).

## Project Structure

```
demos/tauri/
├── app/                    # Next.js pages
│   ├── setup/page.tsx      #   Create / Join / Restore space
│   └── chat/page.tsx       #   Main chat interface
├── components/             # React components
│   ├── channel-list.tsx    #   Sidebar channel list
│   ├── message-list.tsx    #   Message display
│   ├── message-input.tsx   #   Compose messages
│   ├── thread-panel.tsx    #   Thread view
│   └── ...
├── lib/
│   ├── api.ts              # Tauri invoke() wrappers
│   ├── types.ts            # TypeScript interfaces
│   └── store.tsx           # React context (app state)
├── src-tauri/
│   ├── src/
│   │   ├── main.rs         # Tauri app setup, menus
│   │   ├── commands.rs     # Tauri command handlers
│   │   ├── chat.rs         # Chat business logic
│   │   ├── state.rs        # App state, snapshots
│   │   └── broadcast.rs    # Real-time event listener
│   ├── Cargo.toml
│   └── tauri.conf.json
├── package.json
└── next.config.mjs
```

## Maintaining the Frontend

The frontend UI is built and iterated on using the [Claude Code frontend-design plugin](https://github.com/anthropics/claude-code/blob/main/plugins/frontend-design/skills/frontend-design/SKILL.md). This plugin guides creation of distinctive, production-grade interfaces with strong aesthetic direction — thoughtful typography, color, motion, and layout rather than generic defaults.

To use it: install the plugin in Claude Code, then invoke it with `/frontend-design` followed by what you want to build or change. It will generate working React/TypeScript code that fits the existing component structure.

The backend Rust code (`src-tauri/src/`) follows standard Rust patterns and is tested independently of the frontend.

## Demo Launcher
There is a python script that builds everything, starts the backend and the Next.js server (required for Tauri) and has UI to launch new instances of the app.  From the repository root, run
```bash
python3 demos/tauri/demo_launcher.py
```
It should detect dependencies and provide instructions to install them. The primary ones are python, pip and venv; the script will install 
the [Textual](https://github.com/Textualize/textual) python module, which provides the UI support.


## Demo Quickstart
Once everything is setup, these essential commands can be run from the repository root.
```bash
# Start the backend server
cargo run -p encrypted-spaces-backend-server -- --schema ./demos/tauri/app_schema.kdl

# Start a first client (builds the frontend and opens the Tauri window)
npm --prefix demos/tauri run tauri dev

# Run additional clients with
cargo run -p encrypted-spaces-demo

```
If RISC Zero is not installed, the demo can still run without succinct fast-forward proofs by setting `RISC0_SKIP_BUILD=1`:
```bash
# Start the backend server
RISC0_SKIP_BUILD=1 cargo run -p encrypted-spaces-backend-server -- --schema ./demos/tauri/app_schema.kdl

# Start a first client (builds the frontend and opens the Tauri window)
npm --prefix demos/tauri run tauri dev

# Run additional clients with
cargo run -p encrypted-spaces-demo

```



