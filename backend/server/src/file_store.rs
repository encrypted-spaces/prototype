use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::PathBuf;

/// Maximum file size (50 MiB).
pub const MAX_FILE_SIZE: usize = 50 * 1024 * 1024;

/// Content-addressed file storage on disk, scoped to a single space.
///
/// Files are addressed by their SHA-256 hash (of the encrypted content).
/// The server verifies the hash on upload.
///
/// Storage layout: `{root}/{hash[0..2]}/{hash}`
pub struct FileStore {
    root_dir: PathBuf,
}

impl FileStore {
    pub fn new(root_dir: PathBuf) -> Self {
        Self { root_dir }
    }

    /// Store a file, verifying that `sha256(data) == hash` and that the data
    /// does not exceed [`MAX_FILE_SIZE`].
    pub fn put(&self, hash: &str, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "file too large: {} bytes (max {} bytes)",
                    data.len(),
                    MAX_FILE_SIZE
                ),
            ));
        }

        let actual_hash = hex::encode(Sha256::digest(data));
        if actual_hash != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("hash mismatch: expected {hash}, got {actual_hash}"),
            ));
        }

        let file_path = self.file_path(hash);
        if file_path.exists() {
            return Ok(());
        }

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write atomically via temp file + rename to avoid partial writes
        let tmp_path = file_path.with_extension("tmp");
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, &file_path)?;

        Ok(())
    }

    /// Retrieve a file by hash. Returns `None` if not found.
    pub fn get(&self, hash: &str) -> io::Result<Option<Vec<u8>>> {
        let file_path = self.file_path(hash);
        if !file_path.exists() {
            return Ok(None);
        }
        fs::read(&file_path).map(Some)
    }

    /// Delete a file by hash.
    pub fn delete(&self, hash: &str) -> io::Result<()> {
        let file_path = self.file_path(hash);
        if file_path.exists() {
            fs::remove_file(&file_path)?;
        }
        Ok(())
    }

    /// Check if a file exists.
    pub fn exists(&self, hash: &str) -> bool {
        self.file_path(hash).exists()
    }

    /// Compute the on-disk path for a file.
    fn file_path(&self, hash: &str) -> PathBuf {
        let prefix = &hash[..2.min(hash.len())];
        self.root_dir.join(prefix).join(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("file_store_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn put_and_get_roundtrip() {
        let dir = temp_dir();
        let store = FileStore::new(dir.clone());
        let data = b"hello file world";
        let hash = hex::encode(Sha256::digest(data));

        store.put(&hash, data).unwrap();
        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_hash_mismatch() {
        let dir = temp_dir();
        let store = FileStore::new(dir.clone());
        let data = b"hello";
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = store.put(wrong_hash, data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = temp_dir();
        let store = FileStore::new(dir.clone());
        let result = store
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        assert_eq!(result, None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_file() {
        let dir = temp_dir();
        let store = FileStore::new(dir.clone());
        let data = b"to be deleted";
        let hash = hex::encode(Sha256::digest(data));

        store.put(&hash, data).unwrap();
        assert!(store.exists(&hash));

        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_idempotent() {
        let dir = temp_dir();
        let store = FileStore::new(dir.clone());
        let data = b"idempotent data";
        let hash = hex::encode(Sha256::digest(data));

        store.put(&hash, data).unwrap();
        store.put(&hash, data).unwrap();
        assert_eq!(store.get(&hash).unwrap(), Some(data.to_vec()));

        let _ = fs::remove_dir_all(&dir);
    }
}
