/// Task list example — demonstrates the List<T> API with a simple task tracker.
///
/// Lists are now columns within tables. Each row with a `ColumnType::List`
/// column gets its own ordered, key-based, cryptographically verified list.
use encrypted_spaces_sdk::{ColumnType, List, ListEntry, LocalTransport, SchemaBuilder, Space};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Task {
    title: String,
    done: bool,
}

/// A table row that owns a task list via a List column.
#[derive(Debug, Serialize, Deserialize)]
struct Project {
    id: Option<i64>,
    name: String,
    tasks: List<Task>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Task List Demo");
    println!("==============");
    println!();

    let space = Space::new(LocalTransport::in_memory().await?).await?;

    let schema = SchemaBuilder::new("projects")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("name", ColumnType::String)?
        .column("tasks", ColumnType::List)?
        .build()?;
    space.create_table(&schema).await?;

    // Insert a project row — the List column is auto-initialized.
    let projects = space.table::<Project>("projects");
    let project_id = projects
        .insert(&Project {
            id: None,
            name: "My Project".into(),
            tasks: List::empty(),
        })
        .execute()
        .await?;

    // Get a hydrated list handle for the project's tasks column.
    let tasks = space.list::<Task>("projects", project_id, "tasks");

    // -----------------------
    // EMPTY LIST
    // -----------------------
    println!("=== Empty list ===");
    println!("Length: {}", tasks.len().await?);
    println!();

    // -----------------------
    // APPEND TASKS
    // -----------------------
    println!("=== Appending tasks ===");
    let key_groceries = tasks
        .append(&Task {
            title: "Buy groceries".into(),
            done: false,
        })
        .await?;
    let key_laundry = tasks
        .append(&Task {
            title: "Do laundry".into(),
            done: false,
        })
        .await?;
    let _key_email = tasks
        .append(&Task {
            title: "Reply to emails".into(),
            done: false,
        })
        .await?;

    print_tasks(&tasks).await?;

    // -----------------------
    // INSERT AFTER KEY
    // -----------------------
    println!("=== Insert 'Walk the dog' after 'Buy groceries' ===");
    let _key_dog = tasks
        .insert_after_key(
            &key_groceries,
            &Task {
                title: "Walk the dog".into(),
                done: false,
            },
        )
        .await?;

    print_tasks(&tasks).await?;

    // -----------------------
    // UPDATE BY KEY
    // -----------------------
    println!("=== Mark 'Do laundry' as done ===");
    tasks
        .update_by_key(
            &key_laundry,
            &Task {
                title: "Do laundry".into(),
                done: true,
            },
        )
        .await?;

    print_tasks(&tasks).await?;

    // -----------------------
    // DELETE BY KEY
    // -----------------------
    println!("=== Delete 'Buy groceries' ===");
    tasks.delete_by_key(&key_groceries).await?;

    print_tasks(&tasks).await?;

    // -----------------------
    // INDIVIDUAL GET
    // -----------------------
    println!("=== Get item at position 0 ===");
    let first = tasks.get(0).await?;
    println!(
        "  Position {}: {} (done: {}, key: {})",
        first.position,
        first.value.title,
        first.value.done,
        hex::encode(&first.key)
    );

    Ok(())
}

async fn print_tasks(tasks: &List<Task>) -> Result<(), Box<dyn std::error::Error>> {
    let items: Vec<ListEntry<Task>> = tasks.get_all().await?;
    println!("  Tasks ({} items):", items.len());
    for item in &items {
        let check = if item.value.done { "x" } else { " " };
        println!(
            "    [{}] {} (key: {})",
            check,
            item.value.title,
            hex::encode(&item.key)
        );
    }
    println!();
    Ok(())
}
