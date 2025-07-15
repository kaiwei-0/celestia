#!/bin/bash

set -e

export ENCRYPTION_KEY="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
#cargo run --release --bin cli -- --execute

cargo run --release --bin cli -- --execute --save-inputs my_inputs.bin

cargo run --release --bin cli -- --execute --load-inputs my_inputs.bin

#cargo run --release --bin cli -- --prove

# Create a timestamped log folder
LOG_DIR="$(pwd)/logs/$(date +'%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"

# settings for 64-core, 512GB RAM machine
export CHUNK_SIZE=4194304
export CHUNK_BATCH_SIZE=12
export SPLIT_THRESHOLD=1048576
export RUST_LOG=info
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
# JEMALLOC may not work properly on aws
# export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export VK_VERIFICATION=false

RUNS=1

for i in $(seq 1 $RUNS); do
  echo "===== Run #$i ====="
  LOG_FILE="bench_run${i}.log"
  # cargo run --profile perf --features jemalloc,nightly-features | tee "$LOG_DIR/$LOG_FILE"
  cargo run --profile perf  --bin cli -- --prove | tee "$LOG_DIR/$LOG_FILE"
done

echo "pico benchmark celestia program-chacha (kb) completed!"