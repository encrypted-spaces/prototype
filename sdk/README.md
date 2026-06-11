# SDK

A Rust library for working with relational data.

## Features

- **Tables**: Traditional relational data with schemas
- **User Management**: Basic user management, but eventually will extend with invite etc functionality
- **Access Control**: Specify rules which restrict which users can read/write/delete rows

## Quick Start

* To build the SDK, run `cargo build`
* To run the tests: `cargo test`
* To run an example: `cargo run --example <name>`, e.g., `cargo run --example basic`
* To use the SDK, add to your `Cargo.toml`:
   ```toml
   [dependencies]
   sdk = "0.1.0"
   ```
* To build to wasm `wasm-pack build --target nodejs --out-dir ./wasm`

Add the `--release` flag to the `build`, `run` and `test` command to use the release mode.


### Tables

```rust
use encrypted_spaces_sdk::{local_transport::LocalTransport, Space};
use encrypted_spaces_sdk::schema::{ColumnType, SchemaBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Product {
    id: Option<i64>,
    name: String,
    price: f64,
    author_id: i64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let space = Space::new(LocalTransport::in_memory().await?).await?;

    let schema = SchemaBuilder::new("products")
        .column("id", ColumnType::Integer).plaintext_primary_key()
        .column("name", ColumnType::Text)?.not_null()
        .column("price", ColumnType::Real)
        .column("author_id", ColumnType::Integer).plaintext()?
        .build()?;
    space.create_table(&schema).await?;

    let products = space.table::<Product>("products");

    let laptop = Product { id: None, name: "Laptop".into(), price: 999.99, author_id: 1 };
    let _id = products.insert(&laptop).execute().await?;

    let product: Option<Product> = products.select()
        .where_eq("name", "Laptop")
        .first()
        .await?;

    println!("{:?}", product);
    Ok(())
}
```

### Access Control

Access control rules are defined in the server's schema (not via the SDK) and
are enforced automatically on writes (Write/Delete).

## Architecture

The SDK is transport-agnostic: it talks to a server through the `Transport`
trait. `LocalTransport` runs the server in-process for tests and demos, and
`WebSocketTransport` connects to a remote server.
