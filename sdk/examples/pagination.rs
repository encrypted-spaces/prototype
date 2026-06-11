//! Cursor pagination over a table, walking backwards (newest first) with
//! `.descending()` + `.limit(N)`. Each page is fetched independently, and
//! each page's proof is bound to that page's narrowed range — so the
//! server can't slip in extra rows or hide rows it doesn't like.
//!
//! The pattern: the first page has no cursor — just take the largest `N`.
//! For each subsequent page, ask for `id < cursor` where `cursor` is the
//! smallest id seen so far. Stop when a page comes back empty.

use encrypted_spaces_sdk::{ColumnType, LocalTransport, SchemaBuilder, Space};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Project {
    id: Option<i64>,
    title: String,
}

const PAGE_SIZE: u32 = 4;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Pagination Demo");
    println!("===============");
    println!();

    let space = Space::new(LocalTransport::in_memory().await?).await?;

    let schema = SchemaBuilder::new("projects")
        .column("id", ColumnType::Integer)
        .plaintext_primary_key()
        .column("title", ColumnType::String)?
        .build()?;
    space.create_table(&schema).await?;

    let projects = space.table::<Project>("projects");
    for i in 1..=12 {
        projects
            .insert(&Project {
                id: None,
                title: format!("Project #{i:02}"),
            })
            .execute()
            .await?;
    }

    println!("Walking 12 projects backwards in pages of {PAGE_SIZE}:");
    let mut cursor: Option<i64> = None;
    let mut page_num = 1;
    loop {
        let page: Vec<Project> = match cursor {
            Some(id) => {
                projects
                    .select()
                    .where_lt("id", id)
                    .descending()
                    .limit(PAGE_SIZE)
                    .all()
                    .await?
            }
            None => {
                projects
                    .select()
                    .descending()
                    .limit(PAGE_SIZE)
                    .all()
                    .await?
            }
        };
        if page.is_empty() {
            break;
        }
        println!("  page {page_num} ({} row(s)):", page.len());
        for project in &page {
            println!("    [{:>2}] {}", project.id.unwrap(), project.title);
        }
        cursor = Some(page.last().unwrap().id.unwrap());
        page_num += 1;
    }

    println!("Done. Each page above is independently proof-bound to the");
    println!("merk root, so the server can't substitute or omit rows.");

    Ok(())
}
