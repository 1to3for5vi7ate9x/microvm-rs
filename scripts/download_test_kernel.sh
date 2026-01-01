#!/bin/bash
# Download a test kernel for microvm-rs
#
# This script downloads a minimal ARM64 Linux kernel for testing.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KERNEL_DIR="$PROJECT_DIR/test-assets"

mkdir -p "$KERNEL_DIR"
cd "$KERNEL_DIR"

echo "=== microvm-rs Kernel Download ==="
echo ""

# Detect architecture
ARCH=$(uname -m)
echo "Host architecture: $ARCH"

if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    echo "Downloading ARM64 kernel..."

    # Option 1: Alpine Linux kernel (minimal, good for testing)
    # Alpine 3.19 ARM64 kernel
    KERNEL_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/netboot/vmlinuz-lts"
    INITRD_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/netboot/initramfs-lts"

    if [ ! -f "vmlinuz-lts-arm64" ]; then
        echo "Downloading Alpine Linux kernel..."
        curl -L -o vmlinuz-lts-arm64 "$KERNEL_URL"
        echo "Downloaded: vmlinuz-lts-arm64 ($(du -h vmlinuz-lts-arm64 | cut -f1))"
    else
        echo "Kernel already exists: vmlinuz-lts-arm64"
    fi

    if [ ! -f "initramfs-lts-arm64" ]; then
        echo "Downloading initramfs..."
        curl -L -o initramfs-lts-arm64 "$INITRD_URL"
        echo "Downloaded: initramfs-lts-arm64 ($(du -h initramfs-lts-arm64 | cut -f1))"
    else
        echo "Initramfs already exists: initramfs-lts-arm64"
    fi

    echo ""
    echo "=== Download complete ==="
    echo ""
    echo "To test:"
    echo "  cargo run --example boot_linux -- $KERNEL_DIR/vmlinuz-lts-arm64"
    echo ""
    echo "With initrd:"
    echo "  cargo run --example boot_linux -- $KERNEL_DIR/vmlinuz-lts-arm64 $KERNEL_DIR/initramfs-lts-arm64"

elif [ "$ARCH" = "x86_64" ]; then
    echo "Downloading x86_64 kernel..."

    KERNEL_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/netboot/vmlinuz-lts"
    INITRD_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/netboot/initramfs-lts"

    if [ ! -f "vmlinuz-lts-x86_64" ]; then
        echo "Downloading Alpine Linux kernel..."
        curl -L -o vmlinuz-lts-x86_64 "$KERNEL_URL"
        echo "Downloaded: vmlinuz-lts-x86_64 ($(du -h vmlinuz-lts-x86_64 | cut -f1))"
    else
        echo "Kernel already exists: vmlinuz-lts-x86_64"
    fi

    if [ ! -f "initramfs-lts-x86_64" ]; then
        echo "Downloading initramfs..."
        curl -L -o initramfs-lts-x86_64 "$INITRD_URL"
        echo "Downloaded: initramfs-lts-x86_64 ($(du -h initramfs-lts-x86_64 | cut -f1))"
    else
        echo "Initramfs already exists: initramfs-lts-x86_64"
    fi

    echo ""
    echo "=== Download complete ==="
    echo ""
    echo "To test:"
    echo "  cargo run --example boot_linux -- $KERNEL_DIR/vmlinuz-lts-x86_64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
