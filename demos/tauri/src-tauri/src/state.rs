use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use encrypted_spaces_sdk::{Space, TextArea};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: i64,
    pub user_name: String,
    pub ws_address: String,
    pub current_channel_id: i64,
    pub current_channel_name: String,
}

pub struct AppState {
    pub space: tokio::sync::Mutex<Option<Arc<Space>>>,
    pub user_info: tokio::sync::Mutex<Option<UserInfo>>,
    pub snapshot_path: tokio::sync::Mutex<Option<PathBuf>>,
    pub notes: tokio::sync::Mutex<Option<TextArea>>,
    pub default_zoom: u32,
    /// Extra TLS trust anchor file path from `--trust-cert` / the
    /// `ENCRYPTED_SPACES_TRUST_CERT` env var. Re-read from disk on every
    /// WebSocket connect (Create / Join / Restore Space). That keeps
    /// `AppState` clonable + Send + Sync without holding non-Clone
    /// native-tls types, and the I/O cost is negligible at connect time.
    /// A startup probe in `main.rs` enumerates exactly what got loaded
    /// once at process launch.
    pub trust_cert_path: Option<PathBuf>,
}

impl AppState {
    pub fn new(default_zoom: u32, trust_cert_path: Option<PathBuf>) -> Self {
        Self {
            space: tokio::sync::Mutex::new(None),
            user_info: tokio::sync::Mutex::new(None),
            snapshot_path: tokio::sync::Mutex::new(None),
            notes: tokio::sync::Mutex::new(None),
            default_zoom,
            trust_cert_path,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub user_info: UserInfo,
    pub space_snapshot: serde_json::Value,
}

pub async fn save_snapshot(
    space: &Space,
    user_info: &UserInfo,
    path: &PathBuf,
) -> anyhow::Result<()> {
    let snapshot = SnapshotFile {
        user_info: user_info.clone(),
        space_snapshot: space.snapshot().await?,
    };
    let json = serde_json::to_string_pretty(&snapshot)?;
    tokio::fs::write(path, json).await?;
    Ok(())
}

pub async fn load_snapshot(path: &PathBuf) -> anyhow::Result<SnapshotFile> {
    let json = tokio::fs::read_to_string(path).await?;
    let snapshot: SnapshotFile = serde_json::from_str(&json)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user_info() -> UserInfo {
        UserInfo {
            user_id: 1,
            user_name: "alice".into(),
            ws_address: "ws://localhost:8080".into(),
            current_channel_id: 42,
            current_channel_name: "general".into(),
        }
    }

    #[test]
    fn app_state_new_all_none() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = AppState::new(100, None);
            assert!(state.space.lock().await.is_none());
            assert!(state.user_info.lock().await.is_none());
            assert!(state.snapshot_path.lock().await.is_none());
        });
    }

    #[test]
    fn user_info_serde_roundtrip() {
        let info = sample_user_info();
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: UserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn snapshot_file_serde_roundtrip() {
        let snapshot = SnapshotFile {
            user_info: sample_user_info(),
            space_snapshot: serde_json::json!({"tables": [], "version": 1}),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: SnapshotFile = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, deserialized);
    }

    #[tokio::test]
    async fn load_snapshot_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.json");

        let snapshot = SnapshotFile {
            user_info: sample_user_info(),
            space_snapshot: serde_json::json!({"data": "test"}),
        };
        let json = serde_json::to_string_pretty(&snapshot).unwrap();
        tokio::fs::write(&path, json).await.unwrap();

        let loaded = load_snapshot(&path).await.unwrap();
        assert_eq!(loaded, snapshot);
    }

    #[tokio::test]
    async fn load_snapshot_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        tokio::fs::write(&path, "not valid json!!!").await.unwrap();

        let result = load_snapshot(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_snapshot_missing_file() {
        let path = PathBuf::from("/tmp/nonexistent_snapshot_test_12345.json");
        let result = load_snapshot(&path).await;
        assert!(result.is_err());
    }
}
