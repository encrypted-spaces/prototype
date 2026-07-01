# Application schema

An app declares its tables, key-value stores, access-control rules, and actions in a single KDL file. The build-time `sdk-codegen` parses the file, computes the initial data commitment, and emits an `Actions` extension trait on `Space` whose methods are typed wrappers around the underlying `call_*_action` entry points.

The top level holds `table` blocks and `store` blocks. Each `table` body has columns and an optional `rules { }` block. The rules block declares ACL clauses, action-gating, and action definitions. Everything that governs the table lives inside its block. A `store` (see [Stores](#stores)) is a namespaced key-value collection with no columns or rules.

## Tables and rules

```kdl
table "messages" {
    column "id"         type="int"  plaintext=#true
    column "channel_id" type="int"  plaintext=#true indexed=#true
    column "user_id"    type="int"  plaintext=#true indexed=#true
    column "content"    type="text"
    column "timestamp"  type="int"
    column "thread_id"  type="int"  plaintext=#true indexed=#true

    rules {
        allow write  "auth.user_id == row.user_id"
        allow delete "auth.user_id == row.user_id"

        only_via_actions write  "send_message" "update_message"
        only_via_actions delete "delete_message"

        action "send_message" {
            assert "self.thread_id == 0 || exists(messages, row.id == self.thread_id)"
            insert
        }

        action "delete_message" {
            delete
            cascade_delete table="reactions"   where="row.message_id == self.id"
            cascade_delete table="attachments" where="row.message_id == self.id"
            cascade_delete table="messages"    where="row.thread_id == self.id"
        }
    }
}
```

### Columns

- `type` is one of `int`, `real`, `text`, `blob`, `fileref`, `list`.
- `plaintext=#true` opts a column out of encryption (required for indexed columns; implicit for `fileref` and `list`).
- `indexed=#true` adds a secondary index.
- `auto_increment=#false` on the table node makes inserts require an explicit `id`. Actions can only touch auto-increment tables; mixing them with client-supplied ids is rejected at parse time.

Internal tables (`_users`, `_retention`, `_access_control`, `_key_history`, `_lists`) are created automatically and must not be declared.

### Rules block

`rules { }` is optional. A table without it is open-write: anyone authenticated can insert, update, or delete. Inside the block, three node types compose freely:

- `allow write|delete "<predicate>"`. Per-row authorization. Predicates can combine the six comparison operators, `&&`, `||`, `!`, and parens over integer literals, `auth.user_id`, and `row.<column>`. Evaluated against the existing row for `delete`/`update` and against the incoming row for `insert`.
- `only_via_actions write|delete "<name>" ...`. Action-gating. When present, direct `Insert` / `Update` / `Delete` against the table is rejected; the entry must be an `OpType::Action` op naming a listed action. Composes with `allow`: both must hold.
- `action "<name>" { ... }`. An action definition (see below). The action's primary leg targets the enclosing table.

A table can have at most one `rules { }` block.

## Actions

An action is a named, declarative wrapper around one or more primitive ops. The SDK emits a typed method on `Space` per action; the verifier replays the action's legs and assertions from authenticated state.

```kdl
action "send_message" {
    assert "self.thread_id == 0 || exists(messages, row.id == self.thread_id)"
    insert
}

action "delete_message" {
    delete
    cascade_delete table="reactions"   where="row.message_id == self.id"
    cascade_delete table="attachments" where="row.message_id == self.id"
    cascade_delete table="messages"    where="row.thread_id == self.id"
}
```

Each `action` block has zero or more `assert "<expr>"` predicates followed by one primary leg (`insert` / `update` / `delete`) and optional `cascade_delete` legs.

- **Primary leg.** `insert`, `update`, or `delete` with no `table=` attribute. The target is the table whose `rules` block contains the action.
- **`update cols="a,b,c"`.** Optional allowlist of writable columns. Kvs touching anything outside the list are rejected at dispatch. Lock-by-default for narrow mutation surfaces.
- **Cascade legs.** `cascade_delete table="<other>" where="row.<col> == self.<col>"`. The cascade target is named explicitly because it crosses tables (or self-references, like deleting thread replies). The `where` must be a single `row.<col> == self.<col>` equality, which compiles to one secondary-index read.
- **Assertions.** Evaluate against `auth.user_id` and `self.<col>` (the primary leg's row) and may use `exists(other_table, row.<col> == self.<col>)` for cross-table existence checks.
- **Per-leg ACL.** Primary legs inherit the table's `allow` predicates; cascade legs inherit authorization from the primary delete.

See `docs/actions.md` for the action data model in more depth, including the codegen output and call-site shape.

## Stores

A `store` is a namespaced key-value collection, declared at the top level alongside tables:

```kdl
store "prefs"
store "cache" encrypted=#false
```

Unlike a table, a store has no columns, indexes, or access control. It is **open**: any member of the space can read, write, overwrite, or delete any key. Keys are opaque plaintext bytes (used for lookup); values are opaque bytes, encrypted client-side by default. Set `encrypted=#false` only for non-sensitive metadata.

Use a store through the `Space::store` handle:

```rust
let store = space.store("prefs")?;
store.put("theme", b"dark".to_vec()).await?;
let value = store.get("theme").await?;          // Option<Vec<u8>>
store.delete("theme").await?;
let ui = store.list_prefix("ui/").await?;        // Vec<(key, value)>, key order
```

Notes and constraints:

- **Open access, still authenticated.** Writes flow through the same zkVM verifier as table writes: it authenticates the writer's membership, checks the entries target a single declared store, and applies them. It performs no per-key authorization — there is no `allow` or `only_via_actions` for stores in this version, and a `store` block may not contain any children.
- **Flat namespace.** A store name may not collide with a table (or another store), and may not start with `_`.
- **Reads.** Served from the local KV cache when possible; a cache miss fetches and verifies a Merk proof, splices it in, and re-reads. (The networked transport's store read is a follow-up; in-process/`LocalTransport` is supported today.)
- **Relationship to `_retention`.** Stores are the purpose-built primitive that the internal `_retention` "temporary KV-store shim" (`backend/src/internal_schemas.kdl`) anticipated; migrating retention state onto a store is future work.

Per-store access control (`rules { allow ... }`, per-key ownership) and store actions are an explicit follow-up.

## What gets generated

`sdk-codegen::compile("app_schema.kdl")` produces, at build time, a `sdk_codegen` module containing:

- `DATA_COMMITMENT`. The initial merk root computed from the parsed schema.
- `FF_GUEST_IMAGE_ID`. The RISC0 image ID this build trusts.
- `SCHEMA_KDL`. The raw KDL bytes embedded for runtime use.
- `application_schema()`. Convenience constructor.
- `Actions` trait. One method per action. Insert methods are generic over `R: Serialize`; apps define their own row types and pass them in. Update methods return a typed setter builder. Delete methods take `id: i64`.
