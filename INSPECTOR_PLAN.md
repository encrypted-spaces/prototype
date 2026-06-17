# Backend Inspector — Visualization UI Plan

A visualization UI for the Encrypted Spaces backend server, aimed at giving
end-users / prospects an intuition for what's happening cryptographically:
what the schema looks like, what is encrypted vs. plaintext, how the Merkle
trees evolve, what proofs are exchanged, and how data is stored and protected.

Real-time and replay are both supported; the design treats the NDJSON event
log as the source of truth, with the live WebSocket stream as "replay from
`now`".

---

## Context the design relies on

- **The schema is already a teaching artifact.** `demos/tauri/server_schema.kdl`
  annotates `plaintext=#true` per column and declares ACLs in plain text.
  That file should be a first-class object in the UI, not just config.
- **Two distinct trees** must not be conflated:
  - `backend/src/merk_storage/` — the **Merk** tree, current encrypted-state
    store (root hash → "the server's view of reality")
  - `ffproof/changelog_core/src/mmr_tree.rs` — the **MMR** changelog
    (append-only history; peaks grow as a Merkle Mountain Range)
  - Plus a third concept worth surfacing: the **key-history / ratchet epoch**
    driven by `_key_history` and `crypto/src/key_derivation.rs`.
- **The natural tap point already exists.** `backend/server/src/websocket.rs`
  (lines 32–92) has `extract_broadcast_data()` which pulls `ChangelogEntry`
  + `ChangeResponse` for every Change / AddMember / RemoveMember / Retention.
  A sibling emitter for a *structured* telemetry record costs almost nothing.
- **No structured logging today** — just `log::info!/debug!` text. Parsing
  those for replay would be painful. We add an NDJSON sink instead of
  scraping logs.
- **Tauri demo is React/Next.js**, so frontend tooling is familiar to the
  team.

---

## Shape chosen: backend-served `/_inspect` SPA

Hyper gains a `/_inspect` HTTP route serving a small SPA, plus a
`/_inspect/ws` WebSocket that streams a new `InspectorEvent` enum (JSON).
The same process writes `inspector.ndjson` to disk. Loading the file in
the SPA gives full replay / scrub.

Why this over alternatives:

- Sidecar process — cleaner separation but two things to run.
- Bolt into Tauri demo — would conflate "user view" with "server view";
  the central pedagogic move is "look at the server — it's holding only
  ciphertexts and hashes", and that's strongest when you're literally
  looking at the server.

---

## Panel layout

Six panels, each with hover-explainers and a details drawer:

1. **Schema** — `server_schema.kdl` rendered as a table grid. Green tint
   for plaintext (indexable) columns, dark with a lock icon for encrypted
   columns. ACL rules as bubbles on the table headers, rule strings shown
   verbatim. Hover during playback highlights rows whose values touched
   that column in the recent timeline.
2. **Merk tree (current state)** — collapsible tree, nodes labeled by key
   prefix (`table/row/col`). On every `apply_batch`, highlight changed
   paths and animate the new root hash sliding in. Click a node → drawer
   showing key bytes, value bytes (hex + size), "this is ciphertext —
   only members with key epoch N can decrypt". Plaintext columns show
   cleartext.
3. **Changelog MMR** — Merkle Mountain Range visualization (peaks as
   triangles, growing right). Each new entry slides in as a leaf and
   triggers peak merges with brief animation. The *history* story; pairs
   with the wire log.
4. **Wire log / event timeline** — chronological list of
   `DbRequest`/`DbResponse`. Each row expandable to: encrypted payload
   (hex, with "this is what's on the wire" badge), decoded operation type,
   sidecar size, latency, before/after roots, proof bytes attached.
   Playback controls: ⏮ ⏯ ⏭ + scrubber.
5. **Membership & keys** — current members list, key epoch counter, last
   rekey time. `AddMember`/`RemoveMember` animates a "ratchet step" with
   the epoch incrementing. Touchpoint for deniable auth.
6. **Proof inspector** — when `handle_fast_forward` or `handle_select`
   produces a proof, pop a card showing: what it proves (one sentence),
   proof size, original data size (succinctness ratio), verification time,
   generation time (RISC-Zero cycle count from the existing benchmarks).
   Click → side-by-side with the actual proof bytes.

Cross-cutting:

- **Explain mode** toggle in the top bar overlays plain-English annotations
  on every panel.
- **Scenario picker** drives scripted walkthroughs (member joins → posts
  message → another member reads → ratchet → fast-forward) for first-time
  viewers.

---

## Event schema (concrete sketch)

One emitter, six event variants — enough to drive every panel. NDJSON
keeps replay trivial (file = recording); same encoder feeds the WebSocket.

```json
{ "ts": "...", "space_id": "...", "kind": "Connection",
  "client": "...", "event": "connect|disconnect" }

{ "ts": ..., "kind": "Request",
  "op": "Change|Select|FastForward|AddMember|RemoveMember|Retention",
  "size_bytes": N, "request_summary": {...} }

{ "ts": ..., "kind": "MerkUpdate",
  "old_root": "hex", "new_root": "hex",
  "changed_keys": [
    { "prefix": "messages/42/content", "op": "insert|update|delete",
      "value_size": N, "encrypted": true }
  ] }

{ "ts": ..., "kind": "ChangelogAppend",
  "leaf_hash": "hex", "tree_size": N, "peaks": ["hex", ...] }

{ "ts": ..., "kind": "Membership",
  "event": "add|remove", "members": N, "epoch": N }

{ "ts": ..., "kind": "ProofEmitted",
  "kind2": "FastForward|Update|Select", "bytes": N,
  "covers_entries": N, "gen_ms": N, "cycle_count": N }
```

---

## Cross-cutting decisions

- **Event schema is the contract.** Define `InspectorEvent` in
  `backend/src/proto/` (or a new `backend/src/inspector/` module) using
  `serde` + `schemars`. Emit JSON Schema; generate TypeScript types from
  it. Single source of truth.
- **Conceptual + Raw views from day one.** Every panel takes a
  `verbosity: "conceptual" | "raw"` prop; "conceptual" truncates hashes to
  4 bytes, hides internal-table prefixes, etc. Cheap up front, expensive
  to retrofit.
- **Config gate.** Shipped as a single environment variable rather than an
  `AppConfig` section: setting `CYPHERSPACES_INSPECTOR_LOG=<path>` enables the
  inspector and writes NDJSON to `<path>`; unset = fully disabled (singleton
  stays `None`, zero overhead). The inspector HTTP/WS endpoints are served on
  the same port as the protobuf WS (default `127.0.0.1:8080`) under `/_inspect`
  rather than on a separate bind. Deferred knobs (worth filing as follow-ups):
  - `capture_payloads = "summary" | "full"` — currently always captures
    summaries; no full-payload mode.
  - Separate inspector bind address.
- **Frontend stack.** Vite + React + TypeScript, single SPA, static export.
  Embedded as bytes in the Rust binary (`include_dir!`) and served by
  Hyper. Avoids Next.js' overhead; keeps deploy a single artifact. Use
  `d3-hierarchy` for the Merk tree, hand-rolled SVG for the MMR.

---

## Phased plan

Each phase ends with something demo-able so we can stop or pivot at any
boundary.

### Phase 0 — Event schema + NDJSON sink (no UI) ✅ Done

Goal: capture a full Tauri demo session to a file. Diff-able,
version-controlled recordings for later phases.

1. New module `backend/server/src/inspector/mod.rs`:
   - `enum InspectorEvent` with variants `Connection`, `Request`,
     `MerkUpdate`, `ChangelogAppend`, `Membership`, `ProofEmitted`.
   - `pub struct Inspector { tx: broadcast::Sender<InspectorEvent>,
     file: Option<tokio::fs::File> }` with `emit(&self, event)` that does
     both fan-outs.
   - `Inspector::from_config(&AppConfig)` returning
     `Option<Arc<Inspector>>`; threaded into `SpaceState` next to
     `verbose_logfile`.
2. Wire up the five hook points:
   - `db.rs:1631` `handle_change` → `Request` + `MerkUpdate` +
     `ChangelogAppend`
   - `db.rs:1879` `handle_select` → `Request` + `ProofEmitted`
   - `db.rs:1915` `handle_fast_forward` → `Request` + `ProofEmitted`
     with RISC-Zero `gen_ms`/`cycle_count`
   - `db.rs:2042` `handle_add_member` / sibling for remove → `Membership`
   - `websocket.rs:48` `client_connected` / disconnect → `Connection`
3. JSON Schema emit via `schemars` — **deferred**. TypeScript event types are
   currently hand-maintained in `inspector-ui/src/types/events.ts` and kept in
   sync with the Rust `InspectorEvent` enum manually. Revisit if drift becomes
   painful.
4. **Acceptance**: `CYPHERSPACES_INSPECTOR_LOG=/path/to/log.ndjson`, run a
   Tauri demo session, get a coherent NDJSON file. Sanity-check with
   `jq .kind inspector.ndjson | sort | uniq -c`.

### Phase 1 — SPA shell with timeline + wire log ✅ Done

Goal: load an NDJSON file in the browser, scrub through events, see the
wire-level story.

1. New crate `backend/inspector-ui/` (Vite + React + TS). `npm run build`
   → `dist/`; backend uses `include_dir!("dist")` to serve.
2. New Hyper routes:
   - `GET /_inspect` → SPA index
   - `GET /_inspect/*` → static assets
   - In-browser file picker for `.ndjson` (keeps server stateless).
3. Core state: a single reducer fed by events in order. Side-effects:
   maintain a derived "current view" (members, last roots, merk mirror,
   peaks).
4. Two panels live in this phase:
   - **Wire log** (`/components/WireLog.tsx`): virtualized list, playback
     bar (⏮ ⏯ ⏭, speed 0.25×–8×, scrubber). Click a row → JSON drawer.
   - **Status bar**: current root (Merk + MMR), space ID, member count,
     epoch — always-on summary.
5. **Acceptance**: open a captured `.ndjson`, scrub from t=0 to end, every
   event visible with timestamps and types.

### Phase 2 — Schema, Merk, MMR panels ✅ Done

Goal: the three cryptography panels that carry the explainer story.

1. Backend adds `GET /_inspect/schema` returning the parsed KDL schema as
   JSON. Inspector emits a `SchemaSnapshot` event at startup so replays
   embed the schema.
2. **Schema panel** (`/components/SchemaPanel.tsx`): grid of tables ×
   columns. `plaintext=#true` cells green with an "indexable on the
   server" tag; encrypted cells dark with a lock icon. ACL bubbles on
   table headers with rule strings verbatim. Hovering a cell during
   playback highlights rows whose values touched it.
3. **Merk tree panel** (`/components/MerkPanel.tsx`):
   - Client-side mirror built from `MerkUpdate` events. Nodes labeled by
     key prefix; tooltip shows full key + value-size + epoch.
   - Animation: changed paths flash; the root hash card rolls over
     (old → new) with the delta highlighted.
   - "Conceptual" view collapses repeated table/row structure; "Raw"
     shows everything.
4. **MMR panel** (`/components/MmrPanel.tsx`): peaks as triangles, leaves
   slide in right-to-left; merge animations when peaks combine. Shows
   tree size, current peaks list. Click a leaf → drawer with the
   changelog entry.
5. **Acceptance**: scrubbing a recording shows the trees evolve
   coherently; the schema panel makes "what's encrypted" obvious to a
   non-cryptographer at first glance.

### Phase 3 — Live streaming ✅ Done

Goal: "real-time" mode that mirrors replay.

1. Hyper WebSocket route `GET /_inspect/ws` upgrades and subscribes the
   connection to the `Inspector` broadcast channel. Backpressure: on a slow
   consumer the tokio broadcast returns `RecvError::Lagged(n)`; we log a
   warning and continue (the consumer skips ahead rather than getting
   disconnected). This is observability, not data, so a missed event is
   acceptable.
2. SPA gains a "source picker": `[File] [Live]`. In Live mode events
   stream in; the same reducer runs. Scrubber locks to `now` but user can
   pause and rewind into the live buffer.
3. **Acceptance**: open the inspector in the browser, run the Tauri demo,
   watch events arrive within ~50 ms.

### Phase 3.5 — Operations view ⏳ Next

Goal: collapse the verbose raw event stream into the built-in operation
taxonomy a non-engineer demo audience can follow.

The raw stream is great for debugging but overwhelming for a viewer: a
single user-facing action like "Alice sends a message" produces a
`Request` + one or more `MerkUpdate`s + a `ChangelogAppend` + sometimes a
`ProofEmitted`, and the audience loses the thread. The fix is a UI mode
that groups those into one card per high-level operation.

1. **Taxonomy source.** Import `cypherspaces_changelog_core::changelog::OpType`
   (defined in `ffproof/changelog_core/src/changelog.rs:42`) — covers the
   14 changelog-level operations (CreateSpace, InviteUser, RefreshKeys,
   RemoveUser, Extend, Reduce, Rekey, Insert, Update, Delete, ListAppend,
   ListInsert, ListUpdate, ListDelete). Add a thin local enum for the
   two wire-only operations not represented there (`Select`,
   `FastForward`). This keeps the inspector aligned with the SDK
   taxonomy without redeclaring it.
2. **Backend stamping.** Each `Request` event gains a stamped
   `operation: String` field set at the request boundary from the
   incoming payload (`Change` → resolved to one of the `OpType` labels
   from the dispatched change; `AddMember` → `InviteUser`; etc.).
   Computation happens in one helper in `inspector/mod.rs` so the
   mapping stays in a single place.
3. **SPA view toggle.** Add an `[Operations] [Raw]` toggle next to
   `[File] [Live]`. Raw is today's behavior. Operations mode renders one
   collapsible card per `Request`, header line shows the stamped label,
   actor, affected table (if any), proof size (if any). Expanding the
   card reveals the underlying raw events (MerkUpdate, ChangelogAppend,
   Membership, ProofEmitted) that contributed to it, in order.
4. Events not tied to a request (`Connection`, startup `SchemaSnapshot`
   / `MerkSnapshot`) render as small inline separators in Operations
   mode so the timeline still reads coherently.
5. **Acceptance**: drive the Tauri demo, switch to Operations mode, and
   a non-engineer can read the timeline as "Alice created the space →
   Alice invited Bob → Bob joined → Alice inserted into messages → …"
   with one row per action.

### Phase 4 — Membership + Proof inspector ✅ Done

Goal: the remaining two panels — the "who can see this" and "what is
being proven" stories.

1. **Membership panel** (`/components/MembershipPanel.tsx`): member list,
   current key epoch, last rekey time. Add/remove animates a "ratchet
   step" with the epoch counter ticking. One-line explainer of *why*
   ratcheting matters from a tooltip.
2. **Proof inspector** (`/components/ProofPanel.tsx`): pops a card on
   `ProofEmitted`. Three-line summary ("this proof lets a new joiner
   skip N entries; verifying takes X ms vs replaying Y MB"), expandable
   to show proof bytes, RISC-Zero cycle count, gen time, verify time,
   size. Tie to the cycle-count benchmarks merged in `8aa65e04` and
   `3baa1898` — show real numbers.
3. **Acceptance**: a recording of "member joins → fast-forwards" produces
   a proof card whose numbers match the benchmark suite.

### Phase 5 — Explain mode + scenarios 🟡 Partial (Explain done; scenarios pending)

Goal: turn the inspector into something a prospect would understand
without help.

1. **Explain mode** ✅ — toolbar toggle flips a panel-wide annotation
   layer. Each panel (wire log, operations, tables, Merk tree, MMR,
   members, proofs) renders a short title + 1–3 sentence explainer at
   its top when enabled. Texts live inline in
   `inspector-ui/src/components/Explain.tsx` (plan originally called
   for MDX; deferred — prose is short enough that the tooling overhead
   wasn't worth it).
2. **Scenario picker** ⏳ — ship 3 canned `.ndjson` recordings under
   `inspector-ui/scenarios/`:
   - "Two users chatting" (Change → Change → Change)
   - "A new member joins and catches up" (AddMember → FastForward)
   - "A member is removed and keys rotate" (RemoveMember → Membership rekey)
   Each scenario has a step-by-step narrative (an `mdx` script) that
   auto-pauses playback at key moments and points at the relevant panel.
3. **Acceptance**: hand the URL to a non-cryptographer; without
   instructions, they can step through "Two users chatting" and
   articulate what the server can and cannot see.

---

## Risks / things to keep in mind

- **Secrets hygiene.** The inspector trivially leaks raw ciphertext +
  key-history side info. Gate the whole feature behind a config flag and
  bind to `127.0.0.1` by default. Document this loudly — someone *will*
  enable it in prod otherwise.
- **Granularity vs. cost.** Pretty-printing the whole Merk tree on every
  op gets expensive for large Spaces. Send only the changed subtree per
  event; let the UI maintain its own mirror.
- **Intuition vs. accuracy.** A simplified tree is more legible but lies
  a little. The Conceptual / Raw toggle covers both audiences.
- **iOS demo.** `demos/ios` exists — out of scope for the inspector, but
  the same NDJSON stream is consumable from anywhere if a session-share
  for support is ever desired.

## What we defer

- Auth on `/_inspect` beyond bind-to-localhost — fine for demos, needs a
  token if ever exposed externally.
- iOS demo integration.
- Server-side history search ("find me all FastForward proofs > 50ms") —
  easy to add once schema is stable.
- Persistence of the SPA's reducer state — keep it all in-memory.

## Resolved decisions

1. **Schema parsing**: reuse `parse_schema_bundle()` in
   `backend/src/schema_kdl.rs` — already used by the SDK, the Tauri demo
   (`demos/tauri/src-tauri/src/commands.rs:1087`), and the test harness
   (`demos/tauri/test-harness/src/world.rs:39`). KDL is the "KDL Document
   Language" (kdl.dev), a known config format. `GET /_inspect/schema`
   simply serializes the resulting `SchemaBundle` to JSON.
2. **Scenarios**: scripted via the existing test harness
   (`demos/tauri/test-harness/`). Each scenario is a harness test that
   drives the SDK against a backend with `enable_inspector=true` and
   captures the resulting `inspector.ndjson`. The captured files become
   the static fixtures shipped under `inspector-ui/scenarios/` and are
   regenerable by re-running the harness.
3. **Layout**: keep it inside `backend/`. Add `backend/server/src/inspector/`
   (Rust module) and `backend/inspector-ui/` (Vite/React app, sibling
   directory, not a Rust crate). Promote to a top-level crate later only
   if the inspector grows non-trivial logic that needs to be reused
   outside the backend.
