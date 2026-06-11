mod derivation_trees;
pub mod hash;
pub mod mve;

pub use derivation_trees::*;
pub use hash::*;
pub use mve::*;

use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};
use tracing_subscriber::fmt::MakeWriter;

/// Print byte count in SI data sizes.
pub fn human(bytes: usize) -> String {
    let display = bytesize::ByteSize::b(bytes as u64).display().si();
    format!("{display} ({bytes} B)")
}

//
//
// List of available demos for testing
//

/// A demo is a function with a name and a default input size.
pub struct DemoSpec {
    /// The name of the function to be benchmarked.
    pub name: &'static str,
    /// The actual demo function, taking as input
    /// the input size for the demo.
    pub run: fn(usize) -> Vec<u8>,
    /// The default input size when the user doesn't provide an argument.
    pub default_input_size: usize,
}

const DEFAULT_HASH_INPUT_SIZE: usize = 128;
const DEFAULT_MVE_RECIPIENTS: usize = 10;
const DEFAULT_DERIVATION_TREES_INPUT_SIZE: usize = 8;

/// Available demos for benchmarking
pub const DEMOS: &[DemoSpec] = &[
    DemoSpec {
        name: "mVE::mlkem768+poseidon2",
        default_input_size: DEFAULT_MVE_RECIPIENTS,
        run: poseidon_mve_demo::<encrypted_spaces_crypto::pke::mlkem::MlKem768>,
    },
    DemoSpec {
        name: "mVE::xwing+poseidon2",
        default_input_size: DEFAULT_MVE_RECIPIENTS,
        run: poseidon_mve_demo::<encrypted_spaces_crypto::pke::XWing>,
    },
    DemoSpec {
        name: "mVE::xwing-ristretto+poseidon2",
        default_input_size: DEFAULT_MVE_RECIPIENTS,
        run: poseidon_mve_demo::<encrypted_spaces_crypto::pke::XWingRistretto>,
    },
    DemoSpec {
        name: "mVE::ristretto255dh+poseidon2",
        default_input_size: DEFAULT_MVE_RECIPIENTS,
        run: poseidon_mve_demo::<encrypted_spaces_crypto::pke::Ristretto255Dh>,
    },
    DemoSpec {
        name: "hash::blake3_baby_bear_zk",
        default_input_size: DEFAULT_HASH_INPUT_SIZE,
        run: blake3_baby_bear_zk,
    },
    DemoSpec {
        name: "hash::blake3_koala_bear_zk",
        default_input_size: DEFAULT_HASH_INPUT_SIZE,
        run: blake3_koala_bear_zk,
    },
    DemoSpec {
        name: "hash::keccak_baby_bear_zk",
        default_input_size: DEFAULT_HASH_INPUT_SIZE,
        run: keccak_baby_bear_zk,
    },
    DemoSpec {
        name: "hash::keccak_koala_bear_zk",
        default_input_size: DEFAULT_HASH_INPUT_SIZE,
        run: keccak_koala_bear_zk,
    },
    DemoSpec {
        name: "hash::poseidon2_baby_bear_zk",
        default_input_size: DEFAULT_HASH_INPUT_SIZE,
        run: poseidon2_baby_bear_zk,
    },
    DemoSpec {
        name: "hash::poseidon2_koala_bear_zk",
        default_input_size: DEFAULT_HASH_INPUT_SIZE,
        run: poseidon2_koala_bear_zk,
    },
    DemoSpec {
        name: "derivation_trees",
        default_input_size: DEFAULT_DERIVATION_TREES_INPUT_SIZE,
        run: derivation_trees,
    },
];

//
// Logging utilities used in the web and iOS demos.
//

const LOG_BUFFER_MAX_BYTES: usize = 256 * 1024;
static LOG_BUFFER: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();

fn log_buffer() -> &'static Mutex<Vec<u8>> {
    LOG_BUFFER.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn append_log_bytes(bytes: &[u8]) {
    let mut buffer = log_buffer()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    buffer.extend_from_slice(bytes);
    if buffer.len() > LOG_BUFFER_MAX_BYTES {
        let excess = buffer.len() - LOG_BUFFER_MAX_BYTES;
        buffer.drain(0..excess);
    }
}

pub fn drain_logs() -> String {
    let mut buffer = log_buffer()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let bytes = std::mem::take(&mut *buffer);
    String::from_utf8_lossy(&bytes).into_owned()
}

pub struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        append_log_bytes(buf);
        io::stdout().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

#[derive(Clone, Copy)]
pub struct LogMakeWriter;

impl<'a> MakeWriter<'a> for LogMakeWriter {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter
    }
}
