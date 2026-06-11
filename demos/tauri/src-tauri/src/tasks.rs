use anyhow::Result;
use encrypted_spaces_sdk::{List, ListEntry};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub title: String,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    pub key: String, // hex-encoded key
    pub title: String,
    pub done: bool,
    pub position: u64,
}

impl From<ListEntry<Task>> for TaskItem {
    fn from(entry: ListEntry<Task>) -> Self {
        TaskItem {
            key: hex::encode(&entry.key),
            title: entry.value.title,
            done: entry.value.done,
            position: entry.position,
        }
    }
}

pub async fn load_tasks(tasks: &List<Task>) -> Result<Vec<TaskItem>> {
    let entries = tasks.get_all().await?;
    Ok(entries.into_iter().map(TaskItem::from).collect())
}

pub async fn add_task(tasks: &List<Task>, title: &str) -> Result<TaskItem> {
    let task = Task {
        title: title.to_string(),
        done: false,
    };
    let position = tasks.len().await?;
    let key = tasks.append(&task).await?;
    Ok(TaskItem {
        key: hex::encode(&key),
        title: task.title,
        done: task.done,
        position,
    })
}

pub async fn toggle_task(tasks: &List<Task>, key_hex: &str) -> Result<bool> {
    let key = hex::decode(key_hex)?;

    let entry = tasks
        .get_all()
        .await?
        .into_iter()
        .find(|e| e.key == key)
        .ok_or_else(|| anyhow::anyhow!("task not found"))?;

    let new_done = !entry.value.done;
    let updated = Task {
        title: entry.value.title.clone(),
        done: new_done,
    };
    tasks.update_by_key(&key, &updated).await?;
    Ok(new_done)
}

pub async fn update_task_title(tasks: &List<Task>, key_hex: &str, title: &str) -> Result<()> {
    let key = hex::decode(key_hex)?;

    let entry = tasks
        .get_all()
        .await?
        .into_iter()
        .find(|e| e.key == key)
        .ok_or_else(|| anyhow::anyhow!("task not found"))?;

    let updated = Task {
        title: title.to_string(),
        done: entry.value.done,
    };
    tasks.update_by_key(&key, &updated).await?;
    Ok(())
}

pub async fn delete_task(tasks: &List<Task>, key_hex: &str) -> Result<()> {
    let key = hex::decode(key_hex)?;
    tasks.delete_by_key(&key).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_sdk::{
        ApplicationSchema, ColumnType, LocalTransport, SchemaBuilder, Space,
    };
    use serde::{Deserialize, Serialize};

    const TABLE: &str = "test_table";
    const COL: &str = "tasks";

    #[derive(Debug, Serialize, Deserialize)]
    struct Row {
        id: Option<i64>,
        name: String,
        tasks: List<Task>,
    }

    async fn create_space_with_tasks() -> anyhow::Result<List<Task>> {
        let schema = SchemaBuilder::new(TABLE)
            .column("id", ColumnType::Integer)
            .plaintext_primary_key()
            .column("name", ColumnType::String)?
            .column(COL, ColumnType::List)?
            .build()?;
        let transport = LocalTransport::new(std::slice::from_ref(&schema), None, None).await?;
        let root = transport.get_root_hash().await?;
        let schema_app = ApplicationSchema::for_testing(vec![schema], root);
        let space = Space::create(transport, schema_app).await?;
        let row_id = space
            .table::<Row>(TABLE)
            .insert(&Row {
                id: None,
                name: "test".into(),
                tasks: List::empty(),
            })
            .execute()
            .await?;
        Ok(space.list(TABLE, row_id, COL))
    }

    #[tokio::test]
    async fn test_load_empty_tasks() -> anyhow::Result<()> {
        let tasks = create_space_with_tasks().await?;
        let items = load_tasks(&tasks).await?;
        assert!(items.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_add_and_load_task() -> anyhow::Result<()> {
        let tasks = create_space_with_tasks().await?;
        let item = add_task(&tasks, "Buy groceries").await?;
        assert_eq!(item.title, "Buy groceries");
        assert!(!item.done);

        let items = load_tasks(&tasks).await?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Buy groceries");
        Ok(())
    }

    #[tokio::test]
    async fn test_toggle_task() -> anyhow::Result<()> {
        let tasks = create_space_with_tasks().await?;
        let item = add_task(&tasks, "Test task").await?;
        assert!(!item.done);

        let done = toggle_task(&tasks, &item.key).await?;
        assert!(done);

        let items = load_tasks(&tasks).await?;
        assert!(items[0].done);

        let done = toggle_task(&tasks, &item.key).await?;
        assert!(!done);
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_task() -> anyhow::Result<()> {
        let tasks = create_space_with_tasks().await?;
        let item = add_task(&tasks, "Delete me").await?;
        delete_task(&tasks, &item.key).await?;

        let items = load_tasks(&tasks).await?;
        assert!(items.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_update_task_title() -> anyhow::Result<()> {
        let tasks = create_space_with_tasks().await?;
        let item = add_task(&tasks, "Old title").await?;
        update_task_title(&tasks, &item.key, "New title").await?;

        let items = load_tasks(&tasks).await?;
        assert_eq!(items[0].title, "New title");
        Ok(())
    }
}
