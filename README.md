# 🔥 eBPF Firewall

Минималистичный фаервол на базе Rust + eBPF, разработанный для XDP. Позволяет гибко управлять блокировкой IP-адресов, TCP/UDP протоколов и сетевого трафика через простой YAML-конфиг.

## 📌 Репозиторий

https://github.com/vladikgolosnoi/firewall_madrigalv2

## 💾 Установка и запуск (быстрый старт)

### 1. Установи зависимости:

sudo apt update && sudo apt install -y clang llvm libbpf-dev build-essential pkg-config iproute2 git
rustup default nightly
rustup component add rust-src

### 2. Клонируй проект:

git clone https://github.com/vladikgolosnoi/firewall_madrigalv2.git
cd firewall_madrigalv2

### 3. Сборка eBPF-программы:

cd firewall-ebpf
RUSTFLAGS="-C panic=abort" cargo +nightly build -Z build-std --target bpfel-unknown-none --release
cd ..

### 4. Сборка и запуск CLI:

cargo build -p firewall --release
sudo ./target/release/firewall --iface <имя_интерфейса>
Пример:
sudo ./target/release/firewall --iface enp0s3

После запуска ты увидишь лог с загруженной конфигурацией и статусом правил:
✅ Firewall запущен. Нажми Ctrl+C для выхода.

---

## ⚙️ Конфигурация: config.yml

Создай файл config.yml в корне репозитория. Пример:

blocked:
  tcp: "*"
  udp: "*"
  ips:
    - 1.1.1.1
    - 8.8.8.8

allowed:
  http1.0: 80
  http1.1: 80
  https1.1: 443
  https2: 443
  http3: 443
  dns: 53

---

## 🧪 Автоматическое тестирование

Запусти встроенный скрипт автотестирования:

chmod +x test_firewall.sh
./test_firewall.sh

### 🔍 Что проверяет:
- HTTP (example.com)
- HTTPS (example.com)
- DNS (9.9.9.9)
- Ping до 1.1.1.1 (должен быть заблокирован)
- Ping до 8.8.8.8 (должен быть заблокирован)

---

### Сборка eBPF (ручная):
cd firewall-ebpf
RUSTFLAGS="-C panic=abort" cargo +nightly build -Z build-std --target bpfel-unknown-none --release

### Очистка проекта:
cargo clean

---

## 📜 Лицензия
MIT © [vladikgolosnoi](https://github.com/vladikgolosnoi)

---

Готово! Фаервол собран и работает ✅
