//! Canonical `/`-separated paths used to address nodes in the key
//! derivation tree exercised by [`KeyTreeTransition`].
//!
//! [`KeyTreeTransition`]: crate::transitions::KeyTreeTransition

use core::fmt;

use encrypted_spaces_crypto::key_derivation::DerivationTag;
use serde::{Deserialize, Serialize};
use spongefish::{instantiations::Shake128, DuplexSpongeInterface};

/// Canonical representation for absolute `/`-separated paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Build a canonical path, panicking if the input cannot be normalized.
    ///
    /// Use [`CanonicalPath::normalize`] for fallible parsing of untrusted input.
    pub fn new(path: impl AsRef<str>) -> Self {
        Self::normalize(path.as_ref()).expect("path must normalize to a canonical absolute path")
    }

    /// Normalize an input path into canonical absolute form.
    ///
    /// Examples:
    /// - `""` -> `/`
    /// - `a//b/` -> `/a/b`
    pub fn normalize(path: &str) -> Option<Self> {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Some(Self("/".to_string()));
        }

        let with_root = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{trimmed}")
        };

        let mut normalized = String::new();
        let mut prev_was_slash = false;
        for ch in with_root.chars() {
            if ch == '/' {
                if !prev_was_slash {
                    normalized.push(ch);
                }
                prev_was_slash = true;
            } else {
                normalized.push(ch);
                prev_was_slash = false;
            }
        }

        if normalized.len() > 1 {
            normalized = normalized.trim_end_matches('/').to_string();
        }

        if normalized.is_empty() || !normalized.starts_with('/') {
            return None;
        }

        Some(Self(normalized))
    }

    pub fn root() -> Self {
        Self("/".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// Append a segment to this path. Panics if the resulting path is not canonical.
    pub fn child(&self, segment: impl AsRef<str>) -> Self {
        let segment = segment.as_ref().trim_matches('/');
        if segment.is_empty() {
            return self.clone();
        }
        let joined = if self.is_root() {
            format!("/{segment}")
        } else {
            format!("{}/{}", self.0, segment)
        };
        Self::normalize(&joined).expect("child segment must yield a canonical path")
    }

    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let split_at = self.0.rfind('/')?;
        let parent = if split_at == 0 {
            "/".to_string()
        } else {
            self.0[..split_at].to_string()
        };
        Some(Self(parent))
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CanonicalPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&CanonicalPath> for DerivationTag {
    fn from(value: &CanonicalPath) -> Self {
        let bytes: [u8; 32] = Shake128::default()
            .absorb(b"encrypted_spaces:canonical-path:v1")
            .absorb(value.0.as_bytes())
            .squeeze_array::<32>();
        DerivationTag::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::CanonicalPath;

    #[test]
    fn normalize_strips_redundant_slashes() {
        let p = CanonicalPath::normalize("a//b/c/").expect("normalize");
        assert_eq!(p.as_str(), "/a/b/c");
    }

    #[test]
    fn parent_walks_up_to_root() {
        let p = CanonicalPath::new("/a/b/c");
        assert_eq!(p.parent().expect("parent").as_str(), "/a/b");
        assert_eq!(p.parent().unwrap().parent().unwrap().as_str(), "/a");
        assert_eq!(
            p.parent().unwrap().parent().unwrap().parent().unwrap(),
            CanonicalPath::root()
        );
        assert!(CanonicalPath::root().parent().is_none());
    }

    #[test]
    fn child_appends_segment() {
        let p = CanonicalPath::root().child("a").child("b");
        assert_eq!(p.as_str(), "/a/b");
    }
}
