#!/bin/bash

echo "=== 🚀 Firewall Test Script Started ==="

check() {
    local description=$1
    local command=$2
    local expect_success=$3

    output=$(timeout 5 bash -c "$command" 2>&1)
    status=$?

    if [[ $expect_success == "yes" && $status -eq 0 ]]; then
        echo "✅ $description"
    elif [[ $expect_success == "no" && $status -ne 0 ]]; then
        echo "✅ $description правильно заблокирован"
    else
        echo "❌ $description — результат неожиданный"
        echo "   ↳ $output"
    fi
}

check "HTTP 1.1 (example.com)" "curl -s --http1.1 http://example.com" yes
check "HTTPS (example.com)" "curl -s --http1.1 https://example.com" yes
check "DNS-запрос через 9.9.9.9" "dig +short google.com @9.9.9.9" yes
check "Ping к 1.1.1.1" "ping -c 2 -W 1 1.1.1.1" no
check "Ping к 8.8.8.8" "ping -c 2 -W 1 8.8.8.8" no

echo "=== ✅ Тестирование завершено ==="