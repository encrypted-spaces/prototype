use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{convert::TryFrom, fmt, str::FromStr};
use uuid::Uuid;

/// A unique identifier for a space.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SpaceId(Uuid);

impl SpaceId {
    pub const LEN: usize = 16;

    /// Generate a random `SpaceId`.
    ///
    /// Called by clients when creating a new space. The server never generates
    /// space IDs; it only stores and looks them up.
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> [u8; Self::LEN] {
        *self.0.as_bytes()
    }
}

/* ---------------- Conversions ---------------- */

impl From<[u8; SpaceId::LEN]> for SpaceId {
    fn from(bytes: [u8; SpaceId::LEN]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl From<SpaceId> for [u8; SpaceId::LEN] {
    fn from(id: SpaceId) -> Self {
        *id.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for SpaceId {
    type Error = SpaceIdParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Uuid::from_slice(bytes)
            .map(Self)
            .map_err(|_| SpaceIdParseError::InvalidLength)
    }
}

impl TryFrom<Vec<u8>> for SpaceId {
    type Error = SpaceIdParseError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(v.as_slice())
    }
}

/* ---------------- Display + Parse (hex form) ---------------- */

impl fmt::Display for SpaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.simple().fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceIdParseError {
    InvalidLength,
    InvalidHex,
}

impl fmt::Display for SpaceIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(
                f,
                "invalid SpaceId length: expected 16 bytes (32 hex chars)"
            ),
            Self::InvalidHex => write!(f, "invalid SpaceId hex encoding"),
        }
    }
}

impl std::error::Error for SpaceIdParseError {}

impl FromStr for SpaceId {
    type Err = SpaceIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s.replace('-', "")).map_err(|_| SpaceIdParseError::InvalidHex)?;
        vec.try_into()
    }
}

/* ---------------- Serde (hex string) ---------------- */

impl Serialize for SpaceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SpaceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<SpaceId>().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hex() {
        let id: SpaceId = "0102030405060708090a0b0c0d0e0f10".parse().unwrap();
        assert_eq!(id.to_string(), "0102030405060708090a0b0c0d0e0f10");
        let parsed: SpaceId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn all_zeros() {
        assert!("00000000000000000000000000000000"
            .parse::<SpaceId>()
            .is_ok());
    }

    #[test]
    fn all_ff() {
        assert!("ffffffffffffffffffffffffffffffff"
            .parse::<SpaceId>()
            .is_ok());
    }

    #[test]
    fn too_short() {
        assert!("0102030405060708".parse::<SpaceId>().is_err());
    }

    #[test]
    fn too_long() {
        assert!("0102030405060708090a0b0c0d0e0f1011"
            .parse::<SpaceId>()
            .is_err());
    }

    #[test]
    fn bad_hex() {
        assert!("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            .parse::<SpaceId>()
            .is_err());
    }

    #[test]
    fn empty() {
        assert!("".parse::<SpaceId>().is_err());
    }

    #[test]
    fn random_is_unique() {
        let a = SpaceId::random();
        let b = SpaceId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn serde_json_roundtrip() {
        let id = SpaceId::from([0xAB; 16]);
        let s = serde_json::to_string(&id).unwrap();
        // Serialized as a JSON string of 32 hex chars
        assert_eq!(s, format!("\"{}\"", id));
        let back: SpaceId = serde_json::from_str(&s).unwrap();
        assert_eq!(id, back);
    }
}
