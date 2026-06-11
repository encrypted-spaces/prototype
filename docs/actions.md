# Actions

An action is a schema-declared op: a named bundle of one or more primitive table ops (`insert` / `update` / `delete` / `cascade_delete`) plus optional cross-table assertions. The SDK exposes each action as a typed method on `Space`; the verifier replays the action end-to-end from authenticated state, so the signed entry's audit trail names the action rather than enumerating low-level kvs.

Actions are declared inside a table's `rules { }` block; the primary leg implicitly targets the enclosing table. See `docs/schema.md` for the surrounding schema syntax.

## Why actions

Three things actions add on top of direct primitive ops:

1. **Auditability.** The signed entry carries an action-marker kv naming the invoked action, so what the user signed maps to a stable, named operation in the schema.
2. **Multi-leg atomicity.** A single signed entry can touch multiple rows across multiple tables. The verifier proves all legs together or rejects.
3. **Cross-table assertions.** `assert` clauses can `exists(other_table, ...)` to enforce invariants that span tables (e.g. "the message you're replying to is in this channel"). Primitive ops can't do this.

## Shape

```kdl
table "messages" {
    column "id"         type="int" plaintext=#true
    column "channel_id" type="int" plaintext=#true indexed=#true
    column "thread_id"  type="int" plaintext=#true indexed=#true
    // ...

    rules {
        action "send_message" {
            assert "self.thread_id == 0 || exists(messages, row.id == self.thread_id && row.channel_id == self.channel_id)"
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

Each action has:

- A name (used as the Rust method name and the entry's action-marker value). Unique across the whole schema.
- Zero or more `assert "<expr>"` predicates, all evaluated before any leg runs. Assertions see `auth.user_id`, `self.<col>` (the primary leg's row), and `exists(table, predicate)` for cross-table lookups.
- Exactly one primary leg: `insert`, `update`, or `delete`. No `table=` attribute, the primary table is the `table` block enclosing the action.
- Zero or more `cascade_delete table="<other>" where="row.<col> == self.<col>"` tail legs, only allowed after a primary `delete`. Cascade legs name a cross-table target explicitly (or self-reference for things like deleting thread replies). They prove FK completeness via a secondary-index read; per-row ACL is inherited from the primary delete.

An update leg may carry a `cols="a,b,c"` allowlist that restricts which columns the update is permitted to touch. Kvs targeting a column outside the list are rejected at dispatch. Lock-by-default, useful when an action is intended as a narrow mutation surface (e.g. an `update_message` action that only lets `content` change).

## What the SDK gets

`sdk-codegen` generates an `Actions` extension trait on `Space`:

```rust
impl Actions for Space {
    async fn send_message<R: Serialize>(&self, row: &R) -> Result<i64> { ... }
    async fn delete_message(&self, id: i64) -> Result<usize> { ... }
}
```

Bring it into scope and call directly:

```rust
use sdk_codegen::Actions;

space.send_message(&Message {
    id: None,
    channel_id,
    user_id,
    content: text.to_string(),
    timestamp: chrono::Utc::now().timestamp(),
    thread_id: 0,
}).await?;

space.delete_message(message_id).await?;
```

- **Insert actions** are generic over `R: Serialize`. Apps pass any struct whose field names match the table's columns. Same trust model as `Table::<T>::insert(&data)`: column-name mismatches surface at the verifier, not at compile time.
- **Update actions** return a builder (`<ActionName>Update`) with one `.column(value)` setter per writable column, then `.execute().await`.
- **Delete actions** take `id: i64`. Cascade rows are derived server-side by the verifier from each cascade leg's FK secondary index.

## How the verifier handles an action entry

1. The first kv of the signed entry is the action-marker (`tuple("M", "action_marker", primary_table)`); its value is the action's UTF-8 name. The verifier extracts both `primary_table` and `action_name` from this single kv.
2. The verifier reads the named action from authenticated state at `tuple("S", primary_table, "action", action_name)`.
3. The remaining kvs are the primary row's column kvs. Cascade rows are derived at verify time from each cascade leg's FK secondary index, not bundled in the entry.
4. The action's `asserts` evaluate against the primary leg's self-row, with `exists(...)` resolved via secondary-index reads.
5. Each leg dispatches to its primitive op's verifier with `ctx.action_name = Some(<name>)`. Per-table ACL runs as it would for the equivalent direct op. Tables marked `only_via_actions <op>` reject direct ops; action dispatch sets `action_name` so the gate's allowed-list check passes.

## Out of scope (today)

- `lookup(table, predicate).<col>`. `exists` is the only cross-table primitive available in assertions today.
- Custom helper functions in action assertions.
- Action parameters separate from row column values.
- String / timestamp / list literals in predicates. The predicate language is integer-and-boolean only; adding richer types is a follow-up that touches `predicate.pest` plus the evaluator's `resolve_value`.
