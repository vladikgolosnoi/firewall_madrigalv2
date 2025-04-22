#!/bin/bash

set -e

echo "📦 Компиляция eBPF-программы..."
cargo +nightly build \
  -Z build-std \
  --target bpfel-unknown-none \
  -p firewall-ebpf \
  --release

echo "✅ Готово: target/bpfel-unknown-none/release/firewall"
