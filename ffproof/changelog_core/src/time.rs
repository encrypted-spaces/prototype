//! Shared timestamp policy for changelog validation.
//!
//! Live submission, client replay, and fast-forward verification all need to
//! agree on which signed change timestamps are fresh enough to accept. The
//! live server records `accepted_at_server_time` for every accepted change and
//! validates the signed timestamp against that acceptance time: the timestamp
//! may be slightly in the future to allow clock skew, and it may be behind the
//! acceptance time only by the expiry window.
//!
//! Client one-by-one replay uses the same acceptance-time rule against the
//! server-reported `accepted_at_server_time`, then compares that reported time
//! to the client's local clock. This second comparison uses a dedicated,
//! symmetric `CLIENT_CLOCK_TOLERANCE_SECONDS` budget rather than the tight
//! server/signer `CLOCK_SKEW_TOLERANCE_SECONDS`, so the replaying client only
//! needs to be loosely (not tightly) synchronized to real time, in either
//! direction. The past side of this window is the security-relevant one: it
//! bounds how far a malicious server can backdate `accepted_at_server_time` to
//! make an expired signed change look fresh, giving an effective one-by-one
//! replay-age bound of `CLIENT_CLOCK_TOLERANCE_SECONDS + CHANGE_EXPIRY_SECONDS`.
//! The future side is a liveness sanity bound; it prevents the slow-client
//! self-wedge where a client a few seconds behind real time would otherwise
//! reject the server's response to its own just-submitted change.
//!
//! Fast-forward tails use the acceptance-time rule plus a client-side timestamp
//! HWM instead of the client's local clock. Proof-backed tails seed the HWM
//! from the verified proof journal. Proofless FF tails seed it from the
//! client's persisted HWM, which is updated after every accepted single or
//! ragged change. Note that the acceptance-time rule alone is not a freshness
//! gate on ragged tails: the server chooses `accepted_at_server_time` for tail
//! changes, so it can always satisfy that check. The HWM is therefore the
//! effective relative-staleness bound for ragged-tail replay.
//!
//! Proof-compressed fast-forward ranges cannot rely on wall-clock time inside
//! the proof. Instead, recursive proof I/O threads a timestamp high-water mark
//! through `FastForwardRange`, alongside the sigref map and recent root window.
//! The first chunk seeds the HWM to 0, extension chunks inherit the previous
//! journal HWM, and each entry updates or checks it: timestamps at or above the
//! HWM advance it; timestamps below the HWM are accepted only when they lag the
//! HWM by at most `TIMESTAMP_HWM_TOLERANCE_SECONDS`. That tolerance is the
//! expiry window widened by the clock-skew allowance, so HWM-based replay and
//! proof verification never reject a change the live server already accepted.
//! This enforces relative timestamp consistency and bounded reordering in proof
//! mode. It intentionally does not close the known proof-compressed inactivity
//! freshness gap; a future trusted absolute-time anchor can harden that case.

use crate::changelog::ChangelogError;

pub const CHANGE_EXPIRY_SECONDS: u64 = 100;

/// Tight skew budget between the *server* and *signer* clocks, applied at live
/// acceptance time (`validate_change_timestamp_at_acceptance`). Both are
/// submission-time actors expected to be NTP-synchronized, so this stays small.
pub const CLOCK_SKEW_TOLERANCE_SECONDS: u64 = 5;

/// Loose budget for how far a *replaying client's* local clock may diverge from
/// real time, in either direction, when checking a server-reported
/// `accepted_at_server_time`
/// (`validate_accepted_at_server_time_against_local_clock`).
///
/// This is deliberately separate from — and much larger than —
/// `CLOCK_SKEW_TOLERANCE_SECONDS`. Replaying clients are arbitrary end-user
/// devices whose clocks may lag or lead real time by more than the tight
/// server/signer skew; reusing the 5s skew here made honest clients that were
/// merely a few seconds slow reject fresh, validly-accepted changes — including
/// the server's response to their own writes. The budget is symmetric:
///   * Past side (security): bounds how far a malicious server can backdate
///     `accepted_at_server_time`. Combined with the acceptance-time rule, the
///     effective one-by-one replay-age bound is
///     `CLIENT_CLOCK_TOLERANCE_SECONDS + CHANGE_EXPIRY_SECONDS`.
///   * Future side (liveness): a sanity bound that stops a slow client from
///     rejecting changes the server legitimately accepted at roughly real time.
///
/// It only loosens the client-clock assumption; the server-enforced expiry and
/// the FF timestamp HWM are unaffected.
pub const CLIENT_CLOCK_TOLERANCE_SECONDS: u64 = 120;

/// Maximum amount a signed change timestamp may sit *below* the running
/// timestamp high-water mark and still be accepted by HWM-based replay and FF
/// proof checks.
///
/// This must cover the worst-case gap the live server already accepts;
/// otherwise replay / FF verification would reject a change the server
/// acknowledged, permanently breaking fast-forward across that history. The
/// server accepts a signed timestamp `t` whenever
/// `s - CHANGE_EXPIRY_SECONDS <= t <= s + CLOCK_SKEW_TOLERANCE_SECONDS`, where
/// `s` is the server's acceptance-time clock reading. Assuming the server clock
/// is monotonic across accepted changes (`s_j <= s_i` for an earlier change
/// `j`), an earlier change can raise the HWM to at most
/// `s_j + CLOCK_SKEW_TOLERANCE_SECONDS`, while a later change can be accepted as
/// low as `s_i - CHANGE_EXPIRY_SECONDS`. The gap is therefore bounded by
/// `CHANGE_EXPIRY_SECONDS + CLOCK_SKEW_TOLERANCE_SECONDS`.
pub const TIMESTAMP_HWM_TOLERANCE_SECONDS: u64 =
    CHANGE_EXPIRY_SECONDS + CLOCK_SKEW_TOLERANCE_SECONDS;

pub fn validate_change_timestamp_at_acceptance(
    change_timestamp: u64,
    accepted_at_server_time: u64,
) -> Result<(), ChangelogError> {
    if change_timestamp > accepted_at_server_time.saturating_add(CLOCK_SKEW_TOLERANCE_SECONDS) {
        return Err(ChangelogError::Generic(format!(
            "Change timestamp {change_timestamp} is more than {CLOCK_SKEW_TOLERANCE_SECONDS}s in the future (accepted_at_server_time={accepted_at_server_time})"
        )));
    }
    if accepted_at_server_time.saturating_sub(change_timestamp) > CHANGE_EXPIRY_SECONDS {
        return Err(ChangelogError::Generic(format!(
            "Change has expired, older than {CHANGE_EXPIRY_SECONDS} seconds at acceptance time"
        )));
    }
    Ok(())
}

/// Guardrail comparing the server-reported `accepted_at_server_time` to the
/// replaying client's `local_time`, using the loose, symmetric
/// `CLIENT_CLOCK_TOLERANCE_SECONDS` budget (see that constant for the rationale
/// and the security/liveness split). Only the one-by-one replay path applies
/// this check; FF tails rely on the timestamp HWM instead.
pub fn validate_accepted_at_server_time_against_local_clock(
    accepted_at_server_time: u64,
    local_time: u64,
) -> Result<(), ChangelogError> {
    let latest = local_time.saturating_add(CLIENT_CLOCK_TOLERANCE_SECONDS);
    if accepted_at_server_time > latest {
        return Err(ChangelogError::Generic(format!(
            "Server acceptance time {accepted_at_server_time} is more than {CLIENT_CLOCK_TOLERANCE_SECONDS}s in the future (local_time={local_time})"
        )));
    }

    if local_time.saturating_sub(accepted_at_server_time) > CLIENT_CLOCK_TOLERANCE_SECONDS {
        return Err(ChangelogError::Generic(format!(
            "Server acceptance time {accepted_at_server_time} is outside the local clock freshness window (local_time={local_time}, max_age={CLIENT_CLOCK_TOLERANCE_SECONDS}s)"
        )));
    }
    Ok(())
}

/// Validate a change timestamp against the running high-water mark.
///
/// Timestamps at or above the HWM advance it. Timestamps below the HWM are
/// accepted only when they lag by at most `TIMESTAMP_HWM_TOLERANCE_SECONDS`,
/// which is wide enough to admit every change the live server accepts while
/// still bounding relative staleness and reordering.
pub fn validate_timestamp_hwm(change_timestamp: u64, timestamp_hwm: &mut u64) -> bool {
    if change_timestamp >= *timestamp_hwm {
        *timestamp_hwm = change_timestamp;
        return true;
    }

    timestamp_hwm.saturating_sub(change_timestamp) <= TIMESTAMP_HWM_TOLERANCE_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_hwm_accepts_bounded_reorder_and_rejects_outlier() {
        let mut timestamp_hwm = 0;
        for timestamp in [10, 12, 11, 15, 100, 104, 110, 107] {
            assert!(
                validate_timestamp_hwm(timestamp, &mut timestamp_hwm),
                "timestamp {timestamp} should be accepted"
            );
        }
        assert_eq!(timestamp_hwm, 110);
        // An entry older than the HWM by more than the combined tolerance
        // (expiry + clock skew) is rejected and does not move the HWM.
        let outlier = 110 - TIMESTAMP_HWM_TOLERANCE_SECONDS - 1;
        assert!(!validate_timestamp_hwm(outlier, &mut timestamp_hwm));
        assert_eq!(timestamp_hwm, 110);
    }

    #[test]
    fn timestamp_hwm_inherited_state_rejects_stale_extension_entry() {
        let mut timestamp_hwm = CHANGE_EXPIRY_SECONDS + 50;
        let stale = timestamp_hwm - TIMESTAMP_HWM_TOLERANCE_SECONDS - 1;
        assert!(!validate_timestamp_hwm(stale, &mut timestamp_hwm));
        assert_eq!(timestamp_hwm, CHANGE_EXPIRY_SECONDS + 50);
    }

    /// Regression test for issue #18: any change the live server accepts must
    /// also pass the HWM check, otherwise FF proof generation / replay would
    /// reject a change the server already acknowledged and brick fast-forward
    /// across that history.
    ///
    /// Worst case under a monotonic server clock: an earlier change sets the
    /// HWM at the maximum future skew the server allows, and a later change is
    /// accepted at the maximum age the server allows. The resulting HWM gap is
    /// exactly `CHANGE_EXPIRY_SECONDS + CLOCK_SKEW_TOLERANCE_SECONDS` and must
    /// be accepted.
    #[test]
    fn timestamp_hwm_accepts_worst_case_the_server_accepts() {
        let accepted_at = 10_000;

        // Earliest change raises the HWM as high as the server allows.
        let hwm_setter_ts = accepted_at + CLOCK_SKEW_TOLERANCE_SECONDS;
        validate_change_timestamp_at_acceptance(hwm_setter_ts, accepted_at)
            .expect("server accepts a max-future-skew change");

        // Later change is as old as the server allows at the same accept time.
        let oldest_accepted_ts = accepted_at - CHANGE_EXPIRY_SECONDS;
        validate_change_timestamp_at_acceptance(oldest_accepted_ts, accepted_at)
            .expect("server accepts a max-age change");

        let mut timestamp_hwm = 0;
        assert!(validate_timestamp_hwm(hwm_setter_ts, &mut timestamp_hwm));
        assert_eq!(timestamp_hwm, hwm_setter_ts);
        assert!(
            validate_timestamp_hwm(oldest_accepted_ts, &mut timestamp_hwm),
            "HWM must accept any change the live server already accepted"
        );
    }

    /// The HWM still rejects changes older than the combined tolerance so the
    /// relative-staleness bound stays meaningful.
    #[test]
    fn timestamp_hwm_rejects_beyond_combined_tolerance() {
        let mut timestamp_hwm = 10_000;
        let too_old = timestamp_hwm - TIMESTAMP_HWM_TOLERANCE_SECONDS - 1;
        assert!(!validate_timestamp_hwm(too_old, &mut timestamp_hwm));
        assert_eq!(timestamp_hwm, 10_000);
    }

    #[test]
    fn accepted_at_local_clock_allows_bounded_response_age_beyond_skew() {
        let local_time = 1_000;
        let accepted_at_server_time = local_time - CLOCK_SKEW_TOLERANCE_SECONDS - 1;

        validate_accepted_at_server_time_against_local_clock(accepted_at_server_time, local_time)
            .unwrap();
    }

    #[test]
    fn accepted_at_local_clock_rejects_too_old_acceptance_time() {
        let local_time = 1_000;
        let accepted_at_server_time = local_time - CLIENT_CLOCK_TOLERANCE_SECONDS - 1;

        let err = validate_accepted_at_server_time_against_local_clock(
            accepted_at_server_time,
            local_time,
        )
        .unwrap_err();
        assert!(err.to_string().contains("freshness window"));
    }

    #[test]
    fn accepted_at_local_clock_rejects_future_acceptance_time() {
        let local_time = 1_000;
        let accepted_at_server_time = local_time + CLIENT_CLOCK_TOLERANCE_SECONDS + 1;

        let err = validate_accepted_at_server_time_against_local_clock(
            accepted_at_server_time,
            local_time,
        )
        .unwrap_err();
        assert!(err.to_string().contains("future"));
    }
}
