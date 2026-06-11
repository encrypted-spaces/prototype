//! Pest grammar wiring + AST construction.
//!
//! The grammar lives in `predicate.pest` next to this file. Two public
//! entry points:
//!
//! - [`parse_access_rule`] for ACL clauses. Rejects `exists()` at
//!   AST-build time with a clear error.
//! - [`parse_assertion`] for action `assert "..."` blocks. Accepts the
//!   full grammar including `exists()`.
//!
//! Adding a new grammar feature is the same shape every time: add a
//! rule in `predicate.pest`, add an arm in the `build_*` walk below,
//! and (when the feature is semantic, not just syntactic) extend the
//! AST + evaluator. See the docs at the top of `lib.rs` for the
//! deliberate scope boundary.
//!
//! Pest's error type is wrapped in [`ParseError`] so callers don't need
//! to depend on pest directly. Line/column information is preserved in
//! the message — a clear improvement over the previous hand-rolled
//! parser, which only reported token indices.

use crate::{AccessRule, Assertion, ColumnNamespace, ComparisonOp, RuleValue};
use pest::iterators::{Pair, Pairs};
use pest::Parser as _;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "predicate.pest"]
struct PredicateParser;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "predicate parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

impl From<pest::error::Error<Rule>> for ParseError {
    fn from(e: pest::error::Error<Rule>) -> Self {
        ParseError(format!("{e}"))
    }
}

/// Parse an ACL predicate.  Rejects `exists(...)` (only assertions
/// allow cross-table reads).
pub fn parse_access_rule(input: &str) -> Result<AccessRule, ParseError> {
    let assertion = parse_assertion(input)?;
    assertion_into_access_rule(assertion)
}

/// Parse an action assertion.  Accepts the full grammar.
pub fn parse_assertion(input: &str) -> Result<Assertion, ParseError> {
    let mut pairs = PredicateParser::parse(Rule::predicate, input)?;
    let predicate = pairs
        .next()
        .ok_or_else(|| ParseError("empty input".into()))?;
    // `predicate = { SOI ~ or ~ EOI }` — inner pairs are the `or` and
    // `EOI`. Grab the `or`.
    let or_pair = predicate
        .into_inner()
        .find(|p| p.as_rule() == Rule::or)
        .ok_or_else(|| ParseError("internal: missing or-clause in predicate".into()))?;
    build_or(or_pair)
}

fn assertion_into_access_rule(a: Assertion) -> Result<AccessRule, ParseError> {
    match a {
        Assertion::Rule(r) => Ok(r),
        Assertion::Exists { .. } => Err(ParseError(
            "`exists(...)` is not allowed in ACL clauses; use it inside an action `assert`"
                .to_string(),
        )),
        Assertion::And(l, r) => {
            Ok(assertion_into_access_rule(*l)?.and(assertion_into_access_rule(*r)?))
        }
        Assertion::Or(l, r) => {
            Ok(assertion_into_access_rule(*l)?.or(assertion_into_access_rule(*r)?))
        }
        Assertion::Not(inner) => Ok(assertion_into_access_rule(*inner)?.not()),
    }
}

// ─── Walkers ──────────────────────────────────────────────────────────────────

fn build_or(pair: Pair<Rule>) -> Result<Assertion, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::or);
    let mut inner = pair.into_inner();
    let mut acc = build_and(next_required(&mut inner, "or → and")?)?;
    for next in inner {
        // Grammar: `or = { and ~ ("||" ~ and)* }` — only `and`s show up
        // in `into_inner` because `||` is a literal, not a rule.
        acc = acc.or(build_and(next)?);
    }
    Ok(acc)
}

fn build_and(pair: Pair<Rule>) -> Result<Assertion, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::and);
    let mut inner = pair.into_inner();
    let mut acc = build_unary(next_required(&mut inner, "and → unary")?)?;
    for next in inner {
        acc = acc.and(build_unary(next)?);
    }
    Ok(acc)
}

fn build_unary(pair: Pair<Rule>) -> Result<Assertion, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::unary);
    let mut inner = pair.into_inner();
    let first = next_required(&mut inner, "unary")?;
    match first.as_rule() {
        Rule::not_op => {
            // `unary = { not_op ~ unary | primary }` — the second inner
            // pair (if present) is the recursive `unary`.
            let inner_unary = next_required(&mut inner, "unary after not")?;
            Ok(build_unary(inner_unary)?.not())
        }
        Rule::primary => build_primary(first),
        other => Err(ParseError(format!(
            "unexpected rule under unary: {other:?}"
        ))),
    }
}

fn build_primary(pair: Pair<Rule>) -> Result<Assertion, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::primary);
    let mut inner = pair.into_inner();
    let head = next_required(&mut inner, "primary")?;
    match head.as_rule() {
        // `primary = { "(" ~ or ~ ")" | ... }` — parens are literals;
        // only the `or` survives in `into_inner`.
        Rule::or => build_or(head),
        Rule::exists_call => build_exists(head),
        Rule::comparison => build_comparison(head).map(Assertion::Rule),
        other => Err(ParseError(format!(
            "unexpected rule under primary: {other:?}"
        ))),
    }
}

fn build_exists(pair: Pair<Rule>) -> Result<Assertion, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::exists_call);
    let mut inner = pair.into_inner();
    let table_pair = next_required(&mut inner, "exists table name")?;
    if table_pair.as_rule() != Rule::ident {
        return Err(ParseError(format!(
            "exists: expected table identifier, got {:?}",
            table_pair.as_rule()
        )));
    }
    let table = table_pair.as_str().to_string();
    let predicate_pair = next_required(&mut inner, "exists predicate")?;
    let predicate = build_or(predicate_pair)?;
    // The predicate body is an `AccessRule`, not an `Assertion`. Reject
    // nested `exists(A, exists(B, ...))` at AST-build time.
    let predicate = assertion_into_access_rule(predicate).map_err(|_| {
        ParseError(
            "exists: nested `exists(...)` inside an `exists` body is not supported".to_string(),
        )
    })?;
    Ok(Assertion::Exists { table, predicate })
}

fn build_comparison(pair: Pair<Rule>) -> Result<AccessRule, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::comparison);
    let mut inner = pair.into_inner();
    let left = build_value(next_required(&mut inner, "comparison lhs")?)?;
    let op_pair = next_required(&mut inner, "comparison op")?;
    let op = build_cmp_op(op_pair)?;
    let right = build_value(next_required(&mut inner, "comparison rhs")?)?;
    Ok(AccessRule::comparison(left, op, right))
}

fn build_cmp_op(pair: Pair<Rule>) -> Result<ComparisonOp, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::cmp_op);
    Ok(match pair.as_str() {
        "==" => ComparisonOp::Equal,
        "!=" => ComparisonOp::NotEqual,
        "<=" => ComparisonOp::LessEqual,
        ">=" => ComparisonOp::GreaterEqual,
        "<" => ComparisonOp::Less,
        ">" => ComparisonOp::Greater,
        other => {
            return Err(ParseError(format!(
                "internal: unexpected cmp_op token `{other}`"
            )))
        }
    })
}

fn build_value(pair: Pair<Rule>) -> Result<RuleValue, ParseError> {
    debug_assert_eq!(pair.as_rule(), Rule::value);
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| ParseError("value: empty".into()))?;
    match inner.as_rule() {
        Rule::auth_uid => Ok(RuleValue::AuthUserId),
        Rule::self_col => {
            let name = column_name_from_dotted(inner, "self.")?;
            Ok(RuleValue::Column {
                namespace: ColumnNamespace::SelfRow,
                name,
            })
        }
        Rule::row_col => {
            let name = column_name_from_dotted(inner, "row.")?;
            Ok(RuleValue::Column {
                namespace: ColumnNamespace::Resource,
                name,
            })
        }
        Rule::integer => {
            let s = inner.as_str();
            s.parse::<i64>()
                .map(RuleValue::Int)
                .map_err(|e| ParseError(format!("invalid integer literal '{s}': {e}")))
        }
        other => Err(ParseError(format!(
            "unexpected rule under value: {other:?}"
        ))),
    }
}

/// `self_col` / `row_col` are atomic (`${ ... }`) so their `as_str()`
/// is the full `"<prefix>.<ident>"`.  Strip the prefix and validate the
/// remainder against the `ident` shape.
fn column_name_from_dotted(pair: Pair<Rule>, prefix: &str) -> Result<String, ParseError> {
    let s = pair.as_str();
    s.strip_prefix(prefix)
        .map(str::to_string)
        .ok_or_else(|| ParseError(format!("internal: expected prefix `{prefix}` on `{s}`")))
}

fn next_required<'a>(
    pairs: &mut Pairs<'a, Rule>,
    context: &str,
) -> Result<Pair<'a, Rule>, ParseError> {
    pairs
        .next()
        .ok_or_else(|| ParseError(format!("internal: missing pair at {context}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> RuleValue {
        RuleValue::AuthUserId
    }
    fn rcol(c: &str) -> RuleValue {
        RuleValue::column(ColumnNamespace::Resource, c)
    }
    fn scol(c: &str) -> RuleValue {
        RuleValue::column(ColumnNamespace::SelfRow, c)
    }

    // ─── ACL grammar (no exists) ────────────────────────────────────────────

    #[test]
    fn parses_simple_equality() {
        let r = parse_access_rule("auth.user_id == row.user_id").unwrap();
        assert_eq!(
            r,
            AccessRule::comparison(auth(), ComparisonOp::Equal, rcol("user_id"))
        );
    }

    #[test]
    fn parses_integer_literal() {
        let r = parse_access_rule("auth.user_id == 1").unwrap();
        assert_eq!(
            r,
            AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(1))
        );
    }

    #[test]
    fn parses_negative_integer() {
        let r = parse_access_rule("row.score >= -5").unwrap();
        assert_eq!(
            r,
            AccessRule::comparison(
                rcol("score"),
                ComparisonOp::GreaterEqual,
                RuleValue::Int(-5)
            ),
        );
    }

    #[test]
    fn parses_all_comparisons() {
        for (src, op) in [
            ("==", ComparisonOp::Equal),
            ("!=", ComparisonOp::NotEqual),
            ("<", ComparisonOp::Less),
            ("<=", ComparisonOp::LessEqual),
            (">", ComparisonOp::Greater),
            (">=", ComparisonOp::GreaterEqual),
        ] {
            let s = format!("auth.user_id {src} 1");
            let r = parse_access_rule(&s).unwrap();
            assert_eq!(r, AccessRule::comparison(auth(), op, RuleValue::Int(1)));
        }
    }

    #[test]
    fn parses_and_or() {
        let r = parse_access_rule("auth.user_id == row.user_id && auth.user_id != 0").unwrap();
        let a = AccessRule::comparison(auth(), ComparisonOp::Equal, rcol("user_id"));
        let b = AccessRule::comparison(auth(), ComparisonOp::NotEqual, RuleValue::Int(0));
        assert_eq!(r, a.and(b));

        let r = parse_access_rule("auth.user_id == 1 || auth.user_id == 2").unwrap();
        let a = AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(1));
        let b = AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(2));
        assert_eq!(r, a.or(b));
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // `A || B && C` parses as `A || (B && C)`
        let r = parse_access_rule("auth.user_id == 1 || auth.user_id == 2 && row.x == 3").unwrap();
        let a = AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(1));
        let b = AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(2));
        let c = AccessRule::comparison(rcol("x"), ComparisonOp::Equal, RuleValue::Int(3));
        assert_eq!(r, a.or(b.and(c)));
    }

    #[test]
    fn parens_override_precedence() {
        let r =
            parse_access_rule("(auth.user_id == 1 || auth.user_id == 2) && row.x == 3").unwrap();
        let a = AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(1));
        let b = AccessRule::comparison(auth(), ComparisonOp::Equal, RuleValue::Int(2));
        let c = AccessRule::comparison(rcol("x"), ComparisonOp::Equal, RuleValue::Int(3));
        assert_eq!(r, a.or(b).and(c));
    }

    #[test]
    fn parses_not() {
        let r = parse_access_rule("!(auth.user_id == row.user_id)").unwrap();
        let inner = AccessRule::comparison(auth(), ComparisonOp::Equal, rcol("user_id"));
        assert_eq!(r, inner.not());
    }

    #[test]
    fn rejects_unknown_auth_field() {
        let err = parse_access_rule("auth.role == 1").unwrap_err();
        // `auth.<anything else>` is not a value form; pest reports a
        // generic mismatch but the message contains positional info.
        assert!(!err.0.is_empty());
    }

    #[test]
    fn rejects_unknown_identifier() {
        let err = parse_access_rule("foo.bar == 1").unwrap_err();
        assert!(!err.0.is_empty());
    }

    #[test]
    fn rejects_missing_comparison_op() {
        assert!(parse_access_rule("auth.user_id").is_err());
    }

    #[test]
    fn rejects_unbalanced_parens() {
        assert!(parse_access_rule("(auth.user_id == 1").is_err());
    }

    #[test]
    fn rejects_trailing_input() {
        assert!(parse_access_rule("auth.user_id == 1 garbage").is_err());
    }

    #[test]
    fn rejects_dollar_param_prefix() {
        // `$` is no longer a value token in any context.
        assert!(parse_access_rule("$x == 1").is_err());
    }

    // ─── Assertion grammar (with exists) ────────────────────────────────────

    #[test]
    fn parses_self_col_in_assertion() {
        let a = parse_assertion("auth.user_id == self.sender_id").unwrap();
        assert_eq!(
            a,
            Assertion::Rule(AccessRule::comparison(
                auth(),
                ComparisonOp::Equal,
                scol("sender_id"),
            ))
        );
    }

    #[test]
    fn parses_exists_simple() {
        let a = parse_assertion("exists(messages, row.id == self.thread_id)").unwrap();
        assert_eq!(
            a,
            Assertion::Exists {
                table: "messages".to_string(),
                predicate: AccessRule::comparison(
                    rcol("id"),
                    ComparisonOp::Equal,
                    scol("thread_id"),
                ),
            }
        );
    }

    #[test]
    fn parses_exists_with_and_body() {
        let a = parse_assertion(
            "exists(messages, row.id == self.thread_id && row.channel_id == self.channel_id)",
        )
        .unwrap();
        assert_eq!(
            a,
            Assertion::Exists {
                table: "messages".to_string(),
                predicate: AccessRule::comparison(
                    rcol("id"),
                    ComparisonOp::Equal,
                    scol("thread_id")
                )
                .and(AccessRule::comparison(
                    rcol("channel_id"),
                    ComparisonOp::Equal,
                    scol("channel_id"),
                )),
            }
        );
    }

    #[test]
    fn parses_negated_exists() {
        let a = parse_assertion("!exists(messages, row.id == self.thread_id)").unwrap();
        assert_eq!(
            a,
            Assertion::Exists {
                table: "messages".to_string(),
                predicate: AccessRule::comparison(
                    rcol("id"),
                    ComparisonOp::Equal,
                    scol("thread_id")
                ),
            }
            .not()
        );
    }

    #[test]
    fn parses_exists_inside_or() {
        let a =
            parse_assertion("self.thread_id == 0 || exists(messages, row.id == self.thread_id)")
                .unwrap();
        assert_eq!(
            a,
            Assertion::Rule(AccessRule::comparison(
                scol("thread_id"),
                ComparisonOp::Equal,
                RuleValue::Int(0),
            ))
            .or(Assertion::Exists {
                table: "messages".to_string(),
                predicate: AccessRule::comparison(
                    rcol("id"),
                    ComparisonOp::Equal,
                    scol("thread_id"),
                ),
            })
        );
    }

    #[test]
    fn rejects_missing_comma_in_exists() {
        assert!(parse_assertion("exists(messages row.id == 1)").is_err());
    }

    #[test]
    fn rejects_nested_exists() {
        let err = parse_assertion("exists(a, exists(b, row.x == 1))").unwrap_err();
        assert!(err.0.contains("nested"), "msg={}", err.0);
    }

    #[test]
    fn rejects_exists_in_acl_rule() {
        let err = parse_access_rule("exists(messages, row.id == 1)").unwrap_err();
        assert!(
            err.0.contains("ACL") || err.0.contains("exists"),
            "msg={}",
            err.0
        );
    }

    // ─── Error-message quality (pest gives line/column) ────────────────────

    #[test]
    fn error_message_includes_positional_info() {
        let err = parse_access_rule("auth.user_id == ").unwrap_err();
        // Pest reports line/column. The previous hand-rolled parser
        // only reported token indices.
        assert!(
            err.0.contains("1:") || err.0.contains("line"),
            "msg={}",
            err.0
        );
    }

    #[test]
    fn error_message_for_bad_operator_is_clear() {
        let err = parse_access_rule("auth.user_id = 1").unwrap_err();
        // `=` (single) is not a valid cmp_op.
        assert!(!err.0.is_empty());
    }
}
