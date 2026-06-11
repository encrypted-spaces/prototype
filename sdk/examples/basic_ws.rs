//! Basic WebSocket example.
//!
//! Requires a running backend server bound to the same schema. Start it from
//! the repo root with:
//!
//! ```sh
//! cargo run -p encrypted-spaces-backend-server -- --schema sdk/examples/schemas/basic_ws.kdl
//! ```
//!
//! Then in another terminal:
//!
//! ```sh
//! cargo run --example basic_ws -p encrypted-spaces-sdk --features testing
//! ```

use encrypted_spaces_sdk::{ApplicationSchema, Space, WebSocketTransport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Project {
    id: Option<i64>,
    name: String,
    owner_id: i64, // foreign key to users.id
}

#[derive(Debug, Serialize, Deserialize)]
struct Note {
    id: Option<i64>,
    title: String,
    body: String,
    author_id: i64, // foreign key to users.id
    priority: u8,
    pinned: u8, // Stored as Integer in schema (0=false, 1=true)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Basic WebSocket Demo");
    println!("====================");
    println!();

    println!("Testing protobuf WebSocket connection to server...");

    const APP_SCHEMA_BYTES: &[u8] = include_bytes!("./schemas/basic_ws.kdl");

    // Initial data commitment for `schemas/basic_ws.kdl`.  The server
    // is started with `--schema <this same file>` and derives the
    // identical merk root on bootstrap.  Hardcoded here in lieu of a
    // build-time `DATA_COMMITMENT` from `sdk-codegen`; regenerate if
    // the schema changes.
    const APP_DATA_COMMITMENT: [u8; 32] = [
        21, 74, 178, 136, 143, 174, 60, 201, 147, 227, 56, 143, 16, 148, 223, 138, 240, 44, 196,
        48, 93, 93, 244, 35, 134, 169, 90, 154, 87, 25, 41, 81,
    ];

    let transport = WebSocketTransport::new("ws://127.0.0.1:8080/ws")
        .await
        .map_err(|e| format!("connection failed: {e}"))?;
    let space = Space::create(
        transport,
        ApplicationSchema::for_testing_from_bytes(APP_SCHEMA_BYTES, APP_DATA_COMMITMENT),
    )
    .await
    .map_err(|e| format!("space creation failed: {e}"))?;
    println!("✓ Connected to server");

    // -----------------------
    // USER MANAGEMENT (built-in table)
    // -----------------------
    let users = space.users();

    let alice_id = space.invite_user().await?.id().unwrap();
    let bob_id = space.invite_user().await?.id().unwrap();
    println!("Inserted users:");
    println!("- [{}] alice", alice_id);
    println!("- [{}] bob", bob_id);

    // -----------------------
    // TABLE USAGE (structured)
    // -----------------------
    let projects = space.table::<Project>("projects");

    let proj_id1 = projects
        .insert(&Project {
            id: None,
            name: "Internal Tools".into(),
            owner_id: alice_id,
        })
        .execute()
        .await?;

    let proj_id2 = projects
        .insert(&Project {
            id: None,
            name: "Meta tooling".into(),
            owner_id: bob_id,
        })
        .execute()
        .await?;
    println!("Inserted projects:");
    println!("- [{}] Internal Tools (owner_id: {})", proj_id1, alice_id);
    println!("- [{}] Meta tooling (owner_id: {})", proj_id2, bob_id);

    let owned_by_alice = projects
        .select()
        .where_eq("owner_id", alice_id)
        .all()
        .await?;
    println!(
        "Projects owned by alice ({} project(s)):",
        owned_by_alice.len()
    );
    for project in &owned_by_alice {
        println!(
            "- [{}] {} (owner_id: {})",
            project.id.unwrap(),
            project.name,
            project.owner_id
        );
    }

    // ---------------------------
    // NOTES TABLE
    // ---------------------------
    let notes = space.table::<Note>("notes");

    let rust_note_id = notes
        .insert(&Note {
            id: None,
            title: "Rust tips".into(),
            body: "Use cargo fmt!".into(),
            author_id: alice_id,
            priority: 2,
            pinned: 0,
        })
        .execute()
        .await?;

    let shopping_note_id = notes
        .insert(&Note {
            id: None,
            title: "Shopping list".into(),
            body: "Milk, eggs, bread".into(),
            author_id: bob_id,
            priority: 1,
            pinned: 1,
        })
        .execute()
        .await?;

    println!("Inserted notes:");
    println!("- [{}] Rust tips", rust_note_id);
    println!("- [{}] Shopping list", shopping_note_id);

    let alice_notes: Vec<Note> = notes.select().where_eq("author_id", alice_id).all().await?;

    println!("Notes by Alice:");
    for note in &alice_notes {
        print_note(note);
    }

    // Bump priority for all Alice's notes
    let bumped = notes
        .update()
        .set("priority", 3)
        .where_eq("author_id", alice_id)
        .execute()
        .await?;
    println!("Priorities bumped for {bumped} of Alice's notes");

    let all_notes: Vec<Note> = notes.select().all().await?;
    println!("All notes:");
    for note in &all_notes {
        print_note(note);
    }

    // Clean up: delete notes owned by Bob
    let removed = notes
        .delete()
        .where_eq("author_id", bob_id)
        .execute()
        .await?;
    println!("Deleted {removed} note(s) by bob");

    // Verify results
    let all_users = users.select().all().await?;
    let all_projects = projects.select().all().await?;
    let all_notes: Vec<Note> = notes.select().all().await?;

    println!(
        "Summary - Users: {}, Notes: {}, Projects: {}",
        all_users.len(),
        all_notes.len(),
        all_projects.len()
    );

    println!("All users:");
    for user in &all_users {
        println!("- [{}]", user.id.unwrap());
    }

    println!("All notes:");
    for note in &all_notes {
        print_note(note);
    }

    println!("All projects:");
    for project in &all_projects {
        println!(
            "- [{}] {} (owner_id: {})",
            project.id.unwrap(),
            project.name,
            project.owner_id
        );
    }

    Ok(())
}

fn print_note(note: &Note) {
    println!(
        "- [{}] {}: {} by user {} (priority: {}, pinned: {})",
        note.id.unwrap(),
        note.title,
        note.body,
        note.author_id,
        note.priority,
        note.pinned
    );
}
