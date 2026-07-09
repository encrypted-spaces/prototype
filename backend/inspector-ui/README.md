# Encrypted Spaces Inspector SPA

A small Vite + React + TypeScript app that visualizes the backend's
internal state — schema, encrypted tables, the AVL Merkle tree, the MMR
changelog, membership/proof events, and the wire-level event timeline.

The compiled bundle is **embedded into the backend binary** (via
`include_dir!` in `backend/server/src/inspector/http.rs`) and served at
`http://<server>:<port>/_inspect/`. There's nothing to deploy separately.

See `INSPECTOR_PLAN.md` at the repo root for the full design rationale.

## Running the inspector

Three modes, depending on what you're trying to do:

| Use case | How to run | Where to open |
|---|---|---|
| **Full demo + live inspector** — the normal "show me everything" path. Launcher builds the SPA, the backend, and a Tauri client, and wires them together. | `cd demos/tauri && python3 demo_launcher.py` | `http://localhost:8080/_inspect/` |
| **Backend on its own** — useful for loading a previously captured `.ndjson`, driving the backend with the test harness or your own SDK code, or debugging the backend without the Tauri client. | `cargo run -p encrypted-spaces-backend-server` | `http://localhost:8080/_inspect/` |
| **SPA dev loop** — editing the inspector UI itself. Vite hot-reloads on file save; the live WebSocket isn't available (Vite doesn't proxy to the backend), so you'll be loading captured `.ndjson` files. | `cd backend/inspector-ui && npm run dev` | `http://localhost:5174/_inspect/` |

**Capturing a recording.**
`demo_launcher.py` writes events to `demos/tauri/logs/inspector.ndjson`
by default; the live WebSocket on `/_inspect/ws` is enabled at the same
time. For the "backend on its own" mode, the inspector is opt-in — set
`ENCRYPTED_SPACES_INSPECTOR_LOG` before starting the backend to enable both
the file and the live feed:

```sh
export ENCRYPTED_SPACES_INSPECTOR_LOG=/tmp/inspector.ndjson
```

Captured `.ndjson` files load in any inspector instance via the
**Load NDJSON…** button — useful for sharing sessions, replaying bug
reports, or working in SPA dev mode.

To capture a multi-actor session without spinning up the launcher:

```sh
ENCRYPTED_SPACES_INSPECTOR_LOG=/tmp/inspector.ndjson \
  cargo test --package encrypted-spaces-demo-test-harness \
    --test harness_smoke -- alice_bob_charlie_converges
```

## Building the SPA bundle

The launcher (`demo_launcher.py`) runs `npm install` and `npm run build`
automatically before invoking cargo, so you don't normally have to think
about this. For manual builds:

```sh
cd backend/inspector-ui
npm install
npm run build
```

`npm run build` produces `dist/`, which the next `cargo build -p
encrypted-spaces-backend-server` embeds. If `dist/` is missing at build time
(fresh clone, never built the SPA), `backend/server/build.rs` writes a
placeholder so cargo still succeeds — the running server then serves a
page telling you to run `npm run build`.

## Toolchain notes

Required: **Node ≥ 20**, **npm ≥ 10**. Set in `package.json` `"engines"`;
older versions surface an error from npm rather than a confusing
TypeScript failure later.

> **Do not** rely on `apt install node-typescript` for the TypeScript
> compiler. Ubuntu 24.04 ships TypeScript 5.0.4 in that package, which
> rejects this project's `tsconfig.json` (`moduleResolution: "Bundler"`,
> `allowImportingTsExtensions`). The version pinned in `package.json`
> (5.6+) is installed under `node_modules/.bin/tsc` by `npm install`;
> `npm run build` invokes that one automatically.
