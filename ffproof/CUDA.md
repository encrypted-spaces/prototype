# Notes for using RISC Zero with CUDA Acceleration
This file contains some rough notes explaining how we setup and tested RISC Zero
with CUDA acceleration to speed up proof generation.

## Running `cargo test --features real-proofs,cuda` from `ffproof/`

Verified on: RTX 5070 Ti (Blackwell, `sm_120`), driver 580, CUDA toolkit 12.9, risc0 3.0.5.

## Prerequisites (one-time)

### Use NVIDIA's apt repo, not Ubuntu's

The Ubuntu-packaged `nvidia-cuda-toolkit` is usually outdated and the driver/toolkit versions drift out of sync — which breaks the screen, not just the build. Instead, add NVIDIA's official CUDA repo for `ubuntu2404` and install everything from there. This is what's already configured on this machine (`/etc/apt/sources.list.d/cuda-*.list` pointing at `developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/`).

If setting up a new machine:

```bash
# Add NVIDIA's CUDA repo (Ubuntu 24.04). Adjust distro tag for other versions.
distro=ubuntu2404
arch=x86_64
wget https://developer.download.nvidia.com/compute/cuda/repos/$distro/$arch/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt update

# Driver (matches toolkit ABI; 580 supports both CUDA 12.x and 13.x toolkits).
sudo apt install nvidia-driver-580-open
# Reboot after driver install if it's the first time.
```

Do **not** mix `nvidia-cuda-toolkit` (Ubuntu) with `cuda-toolkit-*` (NVIDIA repo); pick the NVIDIA repo and stay on it for both the driver and toolkit so the driver↔toolkit ABIs stay in sync.

### Toolkit version

- NVIDIA driver ≥ 580 (supports CUDA 13 runtime).
- **CUDA toolkit 12.9** active. *Do not use 13.x*: its bundled CCCL headers fail to compile risc0/sppark `.cu` files.
  ```bash
  sudo apt install cuda-toolkit-12-9
  sudo update-alternatives --config cuda   # pick /usr/local/cuda-12.9
  nvcc --version                           # confirm V12.9.x
  ```

Multiple toolkit versions can coexist (`/usr/local/cuda-12.9`, `/usr/local/cuda-13.2`) and `update-alternatives` flips the `/usr/local/cuda` symlink between them.

### Cache CUDA compilation with sccache (highly recommended)

The risc0 CUDA `sys` crates (`risc0-circuit-rv32im-sys`,
`risc0-circuit-recursion-sys`, `risc0-circuit-keccak-sys`,
`risc0-groth16-sys`, plus `sppark`) compile dozens of `.cu` files into PTX,
CUBIN, and device code, and each clean rebuild takes **10–20 minutes**.
sccache caches those nvcc invocations natively (CUDA / PTX / CUBIN cache
classes) and turns a clean rebuild into seconds when the toolkit/flags
haven't changed.

One-time setup:

```bash
# 1. Install
cargo install sccache --locked   # or: sudo apt install sccache (>=0.10)

# 2. Tell cargo about it. Put this in ~/.cargo/config.toml:
#
#    [build]
#    rustc-wrapper = "sccache"
#
# DO NOT set CC, CXX, or NVCC env vars: cc-rs auto-prepends sccache to
# every C/C++/CUDA invocation whenever RUSTC_WRAPPER=sccache. Setting
# CC=sccache-cc (or any wrapper script) causes double-wrap — sccache then
# tries to identify the wrapper script as a compiler and fails with
# "Compiler not supported" or "ToolNotFound". The minimal config above is
# all that's needed; cc-rs will find /usr/local/cuda/bin/nvcc on PATH and
# run it as `sccache nvcc …` automatically.

# 3. (Optional) Pick a cache location and size:
mkdir -p .sccache
export SCCACHE_DIR="$PWD/.sccache"      # project-local; or use ~/.cache/sccache (default)
export SCCACHE_CACHE_SIZE="20G"         # default 10G; CUDA cubins are large
```

After the first `cargo test --features real-proofs,cuda` populates the
cache, check it's working:

```bash
sccache --show-stats | grep -E "Cache (hits|misses) \((CUDA|CUBIN|PTX|C/C\+\+)"
```

Typical first build records ~50 CUDA + 48 PTX + 47 CUBIN misses. Every
subsequent clean rebuild (after `cargo clean -p risc0-*-sys -p sppark`
or a `target/` wipe) reads those back as hits and skips nvcc entirely.

The cache key includes the preprocessed source plus all relevant compiler
flags, so changing `NVCC_APPEND_FLAGS` (e.g. switching GPU arch) correctly
invalidates the affected entries.

## Each time the toolkit version, GPU arch, or NVCC flags change

Cargo does not detect env-var changes for CUDA build scripts, so cached cubins from a prior config get silently reused. Clean the affected crates first:

```bash
cd /home/gregz/dev/encrypted-spaces/prototype
cargo clean -p sppark \
            -p risc0-zkp \
            -p risc0-sys \
            -p risc0-circuit-recursion-sys \
            -p risc0-circuit-rv32im-sys \
            -p risc0-circuit-keccak-sys \
            -p risc0-groth16-sys
```

## Build + test

```bash
cd /home/gregz/dev/encrypted-spaces/prototype/ffproof

# sppark hardcodes -arch=sm_80 and PTX-JIT to sm_120 fails at cuMemAllocAsync
# during NTTParameters init. Force native cubin for Blackwell + PTX fallback.
# Note: setting NVCC_APPEND_FLAGS also disables risc0-build-kernel's default
# -arch=native, which is fine since we're being explicit.
export NVCC_APPEND_FLAGS="-gencode=arch=compute_120,code=sm_120 -gencode=arch=compute_120,code=compute_120"
cargo test --features real-proofs,cuda
```

For a different GPU, replace `120` with that GPU's compute capability (e.g. Ada `89`, Hopper `90`, Ampere `80`). Check with `nvidia-smi --query-gpu=compute_cap --format=csv`.

For the RTX 5070ti specifically we can drop PTX support and reduce our compile time with these flags instead:
```bash
export NVCC_APPEND_FLAGS="-gencode=arch=compute_120,code=sm_120"
```

## Switching back to a non-CUDA toolkit later

```bash
sudo update-alternatives --config cuda    # pick 13.2 if you want it back
```

### Datasheet on this GPU (risc0 v3.0.5 m2, RTX 5070 Ti, 16 GB)

Rebuilt the upstream datasheet from
the same clone after `git checkout v3.0.5` (Rust 1.89 stable, m2 circuit):

```bash
cd /home/gregz/dev/encrypted-spaces/risc0
git checkout v3.0.5
export NVCC_APPEND_FLAGS="-gencode=arch=compute_120,code=sm_120 -gencode=arch=compute_120,code=compute_120"
cargo build --release --example datasheet -F cuda
./target/release/examples/datasheet --max-po2 20 composite
git checkout main   # restore for future work
```

| po2 | cycles | duration | throughput | RAM      |
|-----|--------|----------|------------|---------:|
| 15  | 32 K   | 87.7 ms  | 365 KHz    | 283.9 MB |
| 16  | 64 K   | 116.4 ms | 550 KHz    | 567.9 MB |
| 17  | 128 K  | 164.6 ms | 778 KHz    | 1.11 GB  |
| 18  | 256 K  | 276.2 ms | 927 KHz    | 2.22 GB  |
| 19  | 512 K  | 483.3 ms | 1.0 MHz    | 4.44 GB  |
| **20** | **1 M** | **901.5 ms** | **1.1 MHz** | **8.87 GB** |
| 21  | 2 M    | **OOM** (864 MB alloc failed in `risc0::zkp::hal::cuda`) | — | — |

