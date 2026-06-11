//! Shared id-validation for inserts.
//!
//! Every insert path (server storage, SDK pre-check, changelog verifier)
//! needs to classify an incoming id against the table's `auto_increment`
//! schema flag the same way.  This module centralises that decision so
//! the layers cannot drift.

/// Classification of a validated insert id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertId {
    /// Caller should allocate the id from the table's next-id counter.
    AutoAssign,
    /// Caller should use this explicit id.  Guaranteed `> 0`.
    Explicit(i64),
}

/// Reason an insert id is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdValidationError {
    /// Auto-increment table received an explicit positive id.
    ExplicitOnAutoTable(i64),
    /// Explicit-id table received no id (or `id = 0`).
    MissingIdOnExplicitTable,
    /// Id was negative.  Invalid in every mode.
    NegativeId(i64),
}

impl IdValidationError {
    /// Render the error as a human-readable sentence scoped to `table`.
    pub fn describe(&self, table: &str) -> String {
        match self {
            Self::ExplicitOnAutoTable(id) => {
                format!("table '{table}' is auto-increment; remove the explicit id={id}")
            }
            Self::MissingIdOnExplicitTable => {
                format!("table '{table}' requires an explicit id")
            }
            Self::NegativeId(id) => {
                format!("table '{table}' insert id={id} must be non-negative")
            }
        }
    }
}

/// Validate the shape of an insert id and normalise the "no explicit id"
/// sentinel.  Rejects negatives; collapses `Some(0)` and `None` to `None`.
fn validate_insert_id(raw_id: Option<i64>) -> Result<Option<i64>, IdValidationError> {
    if let Some(id) = raw_id {
        if id < 0 {
            return Err(IdValidationError::NegativeId(id));
        }
    }
    Ok(raw_id.filter(|id| *id != 0))
}

/// Classify an insert's id against the table's auto-increment mode.
///
/// `raw_id` is the id the caller supplied (or parsed out of a signed
/// entry).  `Some(0)` and `None` are equivalent: both mean "no explicit id."
pub fn classify_insert_id(
    raw_id: Option<i64>,
    auto_increment: bool,
) -> Result<InsertId, IdValidationError> {
    let explicit_id = validate_insert_id(raw_id)?;
    match (auto_increment, explicit_id) {
        (true, None) => Ok(InsertId::AutoAssign),
        (false, Some(id)) => Ok(InsertId::Explicit(id)),
        (true, Some(id)) => Err(IdValidationError::ExplicitOnAutoTable(id)),
        (false, None) => Err(IdValidationError::MissingIdOnExplicitTable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_no_id_allocates() {
        assert_eq!(classify_insert_id(None, true), Ok(InsertId::AutoAssign));
        assert_eq!(classify_insert_id(Some(0), true), Ok(InsertId::AutoAssign));
    }

    #[test]
    fn explicit_positive_uses_supplied() {
        assert_eq!(
            classify_insert_id(Some(42), false),
            Ok(InsertId::Explicit(42))
        );
        assert_eq!(
            classify_insert_id(Some(i64::MAX), false),
            Ok(InsertId::Explicit(i64::MAX))
        );
    }

    #[test]
    fn explicit_on_auto_rejected() {
        assert_eq!(
            classify_insert_id(Some(5), true),
            Err(IdValidationError::ExplicitOnAutoTable(5))
        );
    }

    #[test]
    fn missing_on_explicit_rejected() {
        assert_eq!(
            classify_insert_id(None, false),
            Err(IdValidationError::MissingIdOnExplicitTable)
        );
        assert_eq!(
            classify_insert_id(Some(0), false),
            Err(IdValidationError::MissingIdOnExplicitTable)
        );
    }

    #[test]
    fn negative_rejected_regardless_of_mode() {
        assert_eq!(
            classify_insert_id(Some(-5), true),
            Err(IdValidationError::NegativeId(-5))
        );
        assert_eq!(
            classify_insert_id(Some(-5), false),
            Err(IdValidationError::NegativeId(-5))
        );
        assert_eq!(
            validate_insert_id(Some(-5)),
            Err(IdValidationError::NegativeId(-5))
        );
    }

    #[test]
    fn validate_insert_id_normalises_zero_and_none() {
        assert_eq!(validate_insert_id(None), Ok(None));
        assert_eq!(validate_insert_id(Some(0)), Ok(None));
        assert_eq!(validate_insert_id(Some(42)), Ok(Some(42)));
    }

    #[test]
    fn describe_names_the_table() {
        assert!(IdValidationError::NegativeId(-1)
            .describe("projects")
            .contains("projects"));
        assert!(IdValidationError::ExplicitOnAutoTable(5)
            .describe("projects")
            .contains("auto-increment"));
        assert!(IdValidationError::MissingIdOnExplicitTable
            .describe("projects")
            .contains("requires an explicit id"));
    }
}
