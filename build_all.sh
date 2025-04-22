#!/bin/bash

set -e

echo "🔨 Сборка eBPF..."
cd firewall-ebpf
RUSTFLAGS="-C panic=abort" cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
cd ..

echo "🔨 Сборка основного приложения..."
cargo build -p firewall --release

echo "✅ Всё собрано успешно."
echo "🔥 Запустить файрвол: sudo ./target/release/firewall --iface enp0s3"