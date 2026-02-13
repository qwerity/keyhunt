#!/usr/bin/env bash
# Сборка Rust-хоста без GPU (release, только проверка компиляции).
# Бинарник: rust/target/release/keyhunt-pvk

set -e
cd "$(dirname "$0")/.."

cargo build --release --manifest-path rust/Cargo.toml
echo "OK: rust/target/release/keyhunt-pvk"
