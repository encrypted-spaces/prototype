//! Proof-system security profiles.
//!
//! The relevant formula to keep in mind is:
//!
//! `epsilon(delta) <= epsilon_mca(delta) + |Lambda(C, delta)| / |K| + epsilon_fri(delta)`,
//!
//! where `K` is the challenge field, and this crate accounts for
//! `epsilon_fri(delta)` as
//! `2^-query_pow_bits * (1 - delta)^t`.
use p3_fri::FriParameters;

/// Concrete FRI parameters used by a security profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityParameters {
    /// The inverse code rate: `rho = 2^-log_blowup`.
    pub log_blowup: usize,
    /// Early stop for FRI folding.
    /// The final polynomial has length `2^log_final_poly_len`; stopping later can reduce
    /// the final message, while stopping earlier can reduce the number of folding
    /// oracles.
    pub log_final_poly_len: usize,
    ///  The largest FRI fold arity per round. The arity is
    /// `2^max_log_arity`, although Plonky3 may use a smaller arity in a round to
    /// align with input heights and the final polynomial length. Higher arity means
    /// fewer committed FRI layers, but wider round messages and openings.
    pub max_log_arity: usize,
    ///  The number `t` in the query error `(1 - delta)^t`.
    pub num_queries: usize,
    /// The grinding cost before sampling each batching challenge.
    /// It raises prover time and protects against grinding over
    /// those challenges, but is not counted as direct soundness bits by this
    /// profile estimate.
    pub commit_proof_of_work_bits: usize,
    /// The grinding cost before sampling FRI queries.
    /// It raises prover time and directly subtracts from the remaining query
    /// security target in Plonky3's accounting.
    pub query_proof_of_work_bits: usize,
}

impl SecurityParameters {
    /// Build Plonky3 FRI parameters by attaching a concrete MMCS.
    pub fn fri_params_zk<Mmcs>(self, mmcs: Mmcs) -> FriParameters<Mmcs> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: self.max_log_arity,
            num_queries: self.num_queries,
            commit_proof_of_work_bits: self.commit_proof_of_work_bits,
            query_proof_of_work_bits: self.query_proof_of_work_bits,
            mmcs,
        }
    }
}

/// Type-level security profile for constructing zk FRI parameters.
pub trait SecurityProfile: Clone + Copy + Default + Send + Sync + 'static {
    /// Return the concrete FRI knobs used by this profile.
    fn security_parameters() -> SecurityParameters;
}

/// Conservative Johnson-bound profile.
///
/// The Johnson-bound setting assumes each oracle is within distance
/// `1 - sqrt(rho) - eta` of a Reed-Solomon codeword, with
/// `eta = sqrt(rho) / 20`.
///
/// Thus, the per-query failure term is
/// `1 - delta = sqrt(rho) + eta = 1.05 * sqrt(rho)`, so the query error is
/// `(1.05 * sqrt(rho))^t`. With `log_blowup = 3`, `rho = 1/8`,
/// `commit_proof_of_work_bits = 10`, and `query_proof_of_work_bits = 11`,
/// each query contributes `-log2(1.05 * sqrt(1/8)) ~= 1.4296` bits.
/// Therefore `t = 82` gives about `82 * 1.4296 + 11 = 128.2`
/// FRI query/grinding bits.
///
/// For Reed-Solomon codes in this Johnson regime,
/// `|Lambda(C, delta)| <= (2 * eta * sqrt(rho))^-1`.
///
/// `max_log_arity = 3` permits up to 8-way folding. Benchmarks on the target
/// mVE workload found this faster and smaller than the previous 16-way
/// maximum. This is a performance choice, not a soundness requirement.
/// Likewise, `log_blowup = 3` is justified by this profile's soundness
/// calculation; the old grouped-lookup-specific minimum no longer applies
/// after the Plonky3 0.6 interaction-based LogUp migration.
///
/// The BCHKS-style linear correlated-agreement can be computed with
/// `m = max(ceil(sqrt(rho) / (2 * eta)), 3)`, `m' = m + 1/2`,
/// `n = dimension / rho`, and
///
/// `epsilon_ca <= (((2m'^5 + 3m' * delta * rho) * n) / (3 * rho * sqrt(rho)) + m' / sqrt(rho)) / |K|`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Conservative;

impl SecurityProfile for Conservative {
    fn security_parameters() -> SecurityParameters {
        SecurityParameters {
            log_blowup: 3,
            log_final_poly_len: 3,
            max_log_arity: 3,
            num_queries: 82,
            commit_proof_of_work_bits: 10,
            query_proof_of_work_bits: 11,
        }
    }
}

/// Aggressive capacity-bound profile.
///
/// The capacity-bound setting assumes each oracle is within distance
/// `1 - rho - eta` of a Reed-Solomon codeword, with `eta = rho / 20`.
///
/// Under this assumption the per-query failure term is
/// `1 - delta = rho + eta = 1.05 * rho`, so the query error is
/// `(1.05 * rho)^t`. With `log_blowup = 3`, `rho = 1/8`,
/// `commit_proof_of_work_bits = 10`, and `query_proof_of_work_bits = 14`,
/// each query contributes `-log2(1.05 / 8) ~= 2.9296` bits.
/// Therefore `t = 39` gives about `39 * 2.9296 + 14 = 128.3`
/// FRI query/grinding bits.
///
/// This is under the conjecture that Reed-Solomon codes
/// are decodable up to capacity and have correlated agreement,
/// up to capacity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggressive;

impl SecurityProfile for Aggressive {
    fn security_parameters() -> SecurityParameters {
        SecurityParameters {
            log_blowup: 3,
            log_final_poly_len: 3,
            max_log_arity: 4,
            num_queries: 39,
            commit_proof_of_work_bits: 10,
            query_proof_of_work_bits: 14,
        }
    }
}
