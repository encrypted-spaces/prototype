use crate::{users::UserWithSecrets, Space};
use encrypted_spaces_backend::access_control::AuthContext;
#[cfg(test)]
use encrypted_spaces_backend::access_control::{
    AccessRule, ColumnNamespace, ComparisonOp, RuleValue,
};
#[cfg(any(test, feature = "testing"))]
use encrypted_spaces_backend::error::Result;
use encrypted_spaces_backend::SpaceId;

/// Test-only and crate-internal helpers for manipulating a [`Space`]'s
/// authentication context. The public client API exposes only
/// [`Space::uid`] for reading the current user; these helpers are gated
/// behind `#[cfg(any(test, feature = "testing"))]` so they are not part
/// of the production SDK surface.
#[cfg(any(test, feature = "testing"))]
impl Space {
    /// Set the authentication context for this space
    pub fn set_auth_context(&self, auth: AuthContext) {
        self.with_state_mut(|state| state.auth_context = auth);
    }

    /// Get the current auth context (or a default anonymous one)
    pub fn get_auth_context(&self) -> AuthContext {
        self.with_state(|state| state.auth_context.clone())
    }

    pub async fn authenticate_as_id(&self, user_id: i64) -> Result<()> {
        self.authenticate(AuthContext::new(Some(user_id), self.id))
            .await
    }
}

impl Space {
    /// Re-authenticate the transport with the given auth context, updating
    /// local state. If the new context matches the current one, the transport
    /// reconnect is skipped.
    #[cfg(any(test, feature = "testing"))]
    async fn authenticate(&self, auth: AuthContext) -> Result<()> {
        let already_connected = self.with_state(|state| state.auth_context == auth);
        if !already_connected {
            self.transport.authenticate(&auth).await?;
        }
        self.with_state_mut(|state| state.auth_context = auth);
        Ok(())
    }
}

impl UserWithSecrets {
    /// Generates an [`AuthContext`] for a given user.
    ///
    /// TODO: Utilize the user's auth key to properly authenticate with the space.
    pub(crate) fn as_auth_context(&self, space_id: SpaceId) -> AuthContext {
        AuthContext::new(self.id, space_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encrypted_spaces_backend::SpaceId;
    use serde_json::json;

    fn sid() -> SpaceId {
        SpaceId::from([0u8; 16])
    }

    #[test]
    fn test_simple_comparison_rule() {
        let rule =
            AccessRule::comparison(RuleValue::Int(5), ComparisonOp::Greater, RuleValue::Int(3));

        let auth_context = AuthContext::new(None, sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(result);
    }

    #[test]
    fn test_auth_user_id_rule() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::Int(42),
        );

        let auth_context = AuthContext::new(Some(42), sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(result);

        let auth_context = AuthContext::new(Some(123), sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_resource_column_rule() {
        let rule = AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
            ComparisonOp::Equal,
            RuleValue::Int(100),
        );

        let auth_context = AuthContext::new(None, sid());
        let resource_data = json!({
            "author_id": 100,
            "title": "Test Document"
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(result);

        let resource_data = json!({
            "author_id": 200,
            "title": "Test Document"
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_and_rule() {
        let rule =
            AccessRule::comparison(RuleValue::Int(10), ComparisonOp::Greater, RuleValue::Int(5))
                .and(AccessRule::comparison(
                    RuleValue::Int(3),
                    ComparisonOp::Less,
                    RuleValue::Int(8),
                ));

        let auth_context = AuthContext::new(None, sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(result); // 10 > 5 AND 3 < 8 = true AND true = true

        let rule =
            AccessRule::comparison(RuleValue::Int(2), ComparisonOp::Greater, RuleValue::Int(5))
                .and(AccessRule::comparison(
                    RuleValue::Int(3),
                    ComparisonOp::Less,
                    RuleValue::Int(8),
                ));

        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(!result); // 2 > 5 AND 3 < 8 = false AND true = false
    }

    #[test]
    fn test_or_rule() {
        let rule =
            AccessRule::comparison(RuleValue::Int(2), ComparisonOp::Greater, RuleValue::Int(5)).or(
                AccessRule::comparison(RuleValue::Int(3), ComparisonOp::Less, RuleValue::Int(8)),
            );

        let auth_context = AuthContext::new(None, sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(result); // 2 > 5 OR 3 < 8 = false OR true = true

        let rule =
            AccessRule::comparison(RuleValue::Int(2), ComparisonOp::Greater, RuleValue::Int(5)).or(
                AccessRule::comparison(RuleValue::Int(10), ComparisonOp::Less, RuleValue::Int(8)),
            );

        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(!result); // 2 > 5 OR 10 < 8 = false OR false = false
    }

    #[test]
    fn test_not_rule() {
        let rule =
            AccessRule::comparison(RuleValue::Int(5), ComparisonOp::Equal, RuleValue::Int(5)).not();

        let auth_context = AuthContext::new(None, sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(!result); // NOT(5 == 5) = NOT(true) = false
    }

    #[test]
    fn test_complex_nested_rule() {
        // (auth.uid == resource.author_id) AND (resource.public == 1)
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
        )
        .and(AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "public"),
            ComparisonOp::Equal,
            RuleValue::Int(1),
        ));

        // Test case 1: Owner with public document
        let auth_context = AuthContext::new(Some(100), sid());
        let resource_data = json!({
            "author_id": 100,
            "public": 1
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(result); // owner AND public = true AND true = true

        // Test case 2: Owner with private document
        let auth_context = AuthContext::new(Some(100), sid());
        let resource_data = json!({
            "author_id": 100,
            "public": 0
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result); // owner AND private = true AND false = false

        // Test case 3: Non-owner with public document
        let auth_context = AuthContext::new(Some(200), sid());
        let resource_data = json!({
            "author_id": 100,
            "public": 1
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result); // non_owner AND public = false AND true = false

        // Test case 4: Non-owner with private document
        let auth_context = AuthContext::new(Some(200), sid());
        let resource_data = json!({
            "author_id": 100,
            "public": 0
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result); // non_owner AND private = false AND false = false
    }

    #[test]
    fn test_null_value_handling() {
        // Test null == null
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
        );

        let auth_context = AuthContext::new(None, sid()); // null uid
        let resource_data = json!({
            "author_id": null
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result); // null == null = false (deny)

        // Test null != value
        let resource_data = json!({
            "author_id": 100
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result); // null == 100 = false

        // Test null != null (NotEqual operator)
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::NotEqual,
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
        );

        let resource_data = json!({
            "author_id": null
        });

        let result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        assert!(!result); // null != null = false
    }

    #[test]
    fn test_short_circuit_evaluation() {
        // Test AND short-circuit: if left is false, right should not be evaluated
        let rule =
            AccessRule::comparison(RuleValue::Int(1), ComparisonOp::Greater, RuleValue::Int(5))
                .and(AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "nonexistent"), // This would cause error if evaluated
                    ComparisonOp::Equal,
                    RuleValue::Int(1),
                ));

        let auth_context = AuthContext::new(None, sid());
        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(!result); // Should return false without evaluating right side

        // Test OR short-circuit: if left is true, right should not be evaluated
        let rule =
            AccessRule::comparison(RuleValue::Int(5), ComparisonOp::Greater, RuleValue::Int(1)).or(
                AccessRule::comparison(
                    RuleValue::column(ColumnNamespace::Resource, "nonexistent"), // This would cause error if evaluated
                    ComparisonOp::Equal,
                    RuleValue::Int(1),
                ),
            );

        let result = rule.evaluate(auth_context.uid, None).unwrap();
        assert!(result); // Should return true without evaluating right side
    }

    #[test]
    fn test_serialization_deserialization() {
        let rule = AccessRule::comparison(
            RuleValue::AuthUserId,
            ComparisonOp::Equal,
            RuleValue::column(ColumnNamespace::Resource, "author_id"),
        )
        .and(AccessRule::comparison(
            RuleValue::column(ColumnNamespace::Resource, "public"),
            ComparisonOp::Equal,
            RuleValue::Int(1),
        ));

        // Serialize to JSON
        let json_str = serde_json::to_string(&rule).unwrap();

        // Deserialize back
        let deserialized_rule: AccessRule = serde_json::from_str(&json_str).unwrap();

        // Test that the deserialized rule works the same
        let auth_context = AuthContext::new(Some(100), sid());
        let resource_data = json!({
            "author_id": 100,
            "public": 1
        });

        let original_result = rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();
        let deserialized_result = deserialized_rule
            .evaluate(auth_context.uid, Some(&resource_data))
            .unwrap();

        assert_eq!(original_result, deserialized_result);
        assert!(original_result);
    }
}
