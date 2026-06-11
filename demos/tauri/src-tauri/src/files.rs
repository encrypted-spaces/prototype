use anyhow::Result;
use encrypted_spaces_sdk::{File, Space};
use serde::{Deserialize, Serialize};

use crate::sdk_codegen::Actions;

// ─── Inode types ─────────────────────────────────────────────────────────────

/// Inode types stored in the `type` column.
pub const INODE_FILE: i64 = 1;
pub const INODE_FOLDER: i64 = 2;

/// The core inode struct matching the `inodes` table schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    pub id: Option<i64>,
    pub parent_id: i64,
    pub author_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub inode_type: i64,
    pub size: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub mime_type: String,
    pub file_hash: File,
}

/// Joined result of inode + users_meta (for author display name).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeWithAuthor {
    pub id: Option<i64>,
    pub parent_id: i64,
    pub author_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub inode_type: i64,
    pub size: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub mime_type: String,
    pub file_hash: File,
    /// Author display name from users_meta join.
    pub author_name: String,
}

/// Deserialized from the join query (users_meta.name comes back as "name" which
/// conflicts with inodes.name, so we select explicit columns with table prefixes).
#[derive(Debug, Deserialize)]
struct InodeJoined {
    id: Option<i64>,
    parent_id: i64,
    author_id: i64,
    name: String,
    #[serde(rename = "type")]
    inode_type: i64,
    size: i64,
    ctime: i64,
    mtime: i64,
    mime_type: String,
    file_hash: File,
    #[serde(rename = "author_name")]
    author_name: String,
}

/// A file to be uploaded (before encryption/storage).
pub struct PendingFile {
    pub data: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
}

// ─── CRUD operations ─────────────────────────────────────────────────────────

/// Upload files as inodes under the given parent_id.
pub async fn upload_files(
    space: &Space,
    parent_id: i64,
    author_id: i64,
    files: Vec<PendingFile>,
) -> Result<Vec<Inode>> {
    let handle = space.file();
    let ts = chrono::Utc::now().timestamp();
    let mut result = Vec::new();

    for file in files {
        let size = file.data.len() as i64;
        let file_hash = handle.upload(File::from_data(file.data)).await?;
        let entry = Inode {
            id: None,
            parent_id,
            author_id,
            name: file.filename,
            inode_type: INODE_FILE,
            size,
            ctime: ts,
            mtime: ts,
            mime_type: file.mime_type,
            file_hash,
        };
        let id = space.add_inode(&entry).await?;
        result.push(Inode {
            id: Some(id),
            ..entry
        });
    }

    Ok(result)
}

/// Create a folder inode under the given parent_id.
pub async fn create_folder(
    space: &Space,
    parent_id: i64,
    author_id: i64,
    name: &str,
) -> Result<Inode> {
    let ts = chrono::Utc::now().timestamp();
    let entry = Inode {
        id: None,
        parent_id,
        author_id,
        name: name.to_string(),
        inode_type: INODE_FOLDER,
        size: 0,
        ctime: ts,
        mtime: ts,
        mime_type: String::new(),
        file_hash: File::from_hash("0".repeat(64)),
    };
    let id = space.add_inode(&entry).await?;
    Ok(Inode {
        id: Some(id),
        ..entry
    })
}

/// List inodes directly under a parent, with author names, newest first.
pub async fn list_children(space: &Space, parent_id: i64) -> Result<Vec<InodeWithAuthor>> {
    let joined: Vec<InodeJoined> = space
        .table::<Inode>("inodes")
        .select()
        .columns(&[
            "inodes.id",
            "inodes.parent_id",
            "inodes.author_id",
            "inodes.name",
            "inodes.type",
            "inodes.size",
            "inodes.ctime",
            "inodes.mtime",
            "inodes.mime_type",
            "inodes.file_hash",
            "users_meta.name as author_name",
        ])
        .where_eq("parent_id", parent_id)
        .join("users_meta", "author_id", "id")
        .all_as()
        .await?;

    let mut result: Vec<InodeWithAuthor> = joined
        .into_iter()
        .map(|j| InodeWithAuthor {
            id: j.id,
            parent_id: j.parent_id,
            author_id: j.author_id,
            name: j.name,
            inode_type: j.inode_type,
            size: j.size,
            ctime: j.ctime,
            mtime: j.mtime,
            mime_type: j.mime_type,
            file_hash: j.file_hash,
            author_name: j.author_name,
        })
        .collect();

    // Folders first (type 2), then files (type 1); within each group newest first.
    result.sort_by(|a, b| {
        a.inode_type
            .cmp(&b.inode_type)
            .reverse()
            .then_with(|| b.ctime.cmp(&a.ctime))
    });

    Ok(result)
}

/// Recursively delete an inode and all descendants.
pub async fn delete_inode_recursive(space: &Space, inode_id: i64) -> Result<bool> {
    // First, recursively delete all children
    let children: Vec<Inode> = space
        .table::<Inode>("inodes")
        .select()
        .where_eq("parent_id", inode_id)
        .all()
        .await?;

    for child in children {
        if let Some(child_id) = child.id {
            Box::pin(delete_inode_recursive(space, child_id)).await?;
        }
    }

    // Then delete the inode itself
    let deleted = space
        .table::<Inode>("inodes")
        .delete()
        .where_eq("id", inode_id)
        .execute()
        .await?;
    Ok(deleted > 0)
}

/// Move an inode to a new parent.
pub async fn move_inode(space: &Space, inode_id: i64, new_parent_id: i64) -> Result<bool> {
    let ts = chrono::Utc::now().timestamp();
    let updated = space
        .move_inode(inode_id)
        .parent_id(new_parent_id)
        .mtime(ts)
        .execute()
        .await?;
    Ok(updated > 0)
}

/// Rename an inode.
pub async fn rename_inode(space: &Space, inode_id: i64, new_name: &str) -> Result<bool> {
    let ts = chrono::Utc::now().timestamp();
    let updated = space
        .rename_inode(inode_id)
        .name(new_name.to_string())
        .mtime(ts)
        .execute()
        .await?;
    Ok(updated > 0)
}

/// Download and decrypt a file blob by its content hash.
///
/// Shared by the Tauri `download_file` command (after a disk-cache miss)
/// and the test harness, so both go through the same SDK call path.
pub async fn download_file_by_hash(space: &Space, hash: &str) -> Result<Vec<u8>> {
    let downloaded = space
        .file()
        .download(&File::from_hash(hash.to_string()))
        .await?;
    Ok(downloaded.into_data()?)
}

/// Look up a file inode by id and download its decrypted bytes.
pub async fn download_file(space: &Space, inode_id: i64) -> Result<Vec<u8>> {
    let inode = space
        .table::<Inode>("inodes")
        .select()
        .where_eq("id", inode_id)
        .first()
        .await?
        .ok_or_else(|| anyhow::anyhow!("inode {inode_id} not found"))?;
    download_file_by_hash(space, inode.file_hash.hash()?).await
}
