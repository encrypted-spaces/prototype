//! A RNG wrapper for the prover's private coins.
//!
//! The crypto RNGs we rely on do not expose a way to snapshot and resume their
//! stream state. This module records a ChaCha seed plus word position so prover
//! code can cheaply fork deterministic streams where the P3 stack requires it.

use rand::{
    rngs::{ChaCha20Rng, SysRng},
    Rng, SeedableRng, TryCryptoRng, TryRng,
};

const CHACHA_WORD_POS_MASK: u128 = (1u128 << 68) - 1;

/// The seeds used to commit to the preproceesed MMCS
pub(crate) const PLACEHOLDER_MMCS_SEED: u64 = 0x5645_5249_4659_4d4d;
/// The seeds used to commit to the preprocessed PCS
pub(crate) const PLACEHOLDER_PCS_SEED: u64 = 0x5645_5249_4659_5043;

/// ChaCha20 RNG for prover-private randomness.
///
/// It tracks seed and word position, so P3 consumers can clone the state.
pub struct ChaChaCsrng {
    seed: [u8; 32],
    word_pos: u128,
}

impl ChaChaCsrng {
    pub(crate) const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed, word_pos: 0 }
    }

    pub(crate) fn from_seed_u64(seed: u64) -> Self {
        let mut full_seed = [0u8; 32];
        full_seed[..8].copy_from_slice(&seed.to_le_bytes());
        Self::from_seed(full_seed)
    }

    pub(crate) fn from_entropy() -> Self {
        let mut seed = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut seed)
            .unwrap_or_else(|err| panic!("system RNG failed while seeding prover RNG: {err}"));
        Self::from_seed(seed)
    }

    fn chacha_at_current_position(&self) -> ChaCha20Rng {
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        rng.set_word_pos(self.word_pos);
        rng
    }

    fn advance_words(&mut self, words: u128) {
        self.word_pos = self.word_pos.wrapping_add(words) & CHACHA_WORD_POS_MASK;
    }
}

impl Clone for ChaChaCsrng {
    fn clone(&self) -> Self {
        Self::from_entropy()
    }
}

impl core::fmt::Debug for ChaChaCsrng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaChaCsrng").finish_non_exhaustive()
    }
}

impl TryRng for ChaChaCsrng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut rng = self.chacha_at_current_position();
        let value = rng.next_u32();
        self.advance_words(1);
        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut rng = self.chacha_at_current_position();
        let value = rng.next_u64();
        self.advance_words(2);
        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let mut rng = self.chacha_at_current_position();
        rng.fill_bytes(dst);
        self.advance_words(dst.len().div_ceil(4) as u128);
        Ok(())
    }
}

impl TryCryptoRng for ChaChaCsrng {}
