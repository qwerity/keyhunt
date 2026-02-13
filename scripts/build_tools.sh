#!/usr/bin/env bash
# Сборка Rust-утилит (release): decrypt_results, convert_hash160_to_binary, gpu_info.
# Запускать из корня проекта.
#
# decrypt_results, convert_hash160_to_binary — без CUDA.
# gpu_info — с фичей gpu-info (cudarc); требует CUDA-драйвер в runtime.

set -e
cd "$(dirname "$0")/.."

echo "=== Rust tools (release) ==="
cargo build --release --manifest-path rust/Cargo.toml --bin decrypt_results --bin convert_hash160_to_binary
cargo build --release --manifest-path rust/Cargo.toml --bin gpu_info --features gpu-info

echo "OK: rust/target/release/decrypt_results"
echo "OK: rust/target/release/convert_hash160_to_binary"
echo "OK: rust/target/release/gpu_info"
