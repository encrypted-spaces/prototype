mod blake3_baby_bear;
mod blake3_koala_bear;
mod keccak_baby_bear;
mod keccak_koala_bear;
mod poseidon2_baby_bear;
mod poseidon2_koala_bear;

#[cfg(not(target_arch = "wasm32"))]
pub fn setup_logging() {
    use tracing_forest::tag::NoTag;
    use tracing_forest::util::LevelFilter;
    use tracing_forest::{ForestLayer, PrettyPrinter};
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry};

    use crate::demo::LogMakeWriter;

    const PLONKY3_SPANS: &[&str] = &[
        "FRI prover",
        "prove_with_preprocessed",
        "verify_with_preprocessed",
        "commit to trace data",
        "open",
    ];

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::TRACE.into())
        .from_env_lossy();

    let span_filter = filter_fn(|meta| {
        if meta.target().starts_with("p3_") {
            meta.is_span() && PLONKY3_SPANS.contains(&meta.name())
        } else {
            true
        }
    });

    let forest_layer = ForestLayer::new(PrettyPrinter::new().writer(LogMakeWriter), NoTag);
    let _ = Registry::default()
        .with(env_filter)
        .with(forest_layer.with_filter(span_filter.clone()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(LogMakeWriter)
                .with_filter(span_filter),
        )
        .try_init();
}

pub use blake3_baby_bear::*;
pub use blake3_koala_bear::*;
pub use keccak_baby_bear::*;
pub use keccak_koala_bear::*;
pub use poseidon2_baby_bear::*;
pub use poseidon2_koala_bear::*;
