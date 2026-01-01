#!/bin/bash
# Build a minimal Linux kernel for microvm-rs
#
# This script:
# 1. Installs cross-compiler (if needed)
# 2. Downloads Linux kernel source
# 3. Configures a minimal kernel for microVM
# 4. Builds the kernel
#
# Result: guest/kernel/Image (raw ARM64 kernel)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KERNEL_BUILD_DIR="$PROJECT_DIR/guest/kernel"
LINUX_VERSION="6.6.119"  # LTS kernel (supported until Dec 2026)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== microvm-rs Kernel Builder ===${NC}"
echo ""

# Step 1: Check/Install cross-compiler
echo -e "${YELLOW}Step 1: Checking cross-compiler...${NC}"

if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
    echo "Cross-compiler not found. Installing via Homebrew..."

    if ! command -v brew &> /dev/null; then
        echo -e "${RED}Error: Homebrew not installed. Please install it first.${NC}"
        exit 1
    fi

    # Install ARM64 Linux cross-compiler
    brew install aarch64-elf-gcc 2>/dev/null || brew tap messense/macos-cross-toolchains && brew install aarch64-unknown-linux-gnu

    # Also try the FiloSottile tap which has better Linux toolchains
    if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
        echo "Trying alternative toolchain..."
        brew tap SergioBenitez/osxct 2>/dev/null || true
        brew install aarch64-linux-gnu 2>/dev/null || true
    fi
fi

# Check again
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    CROSS_COMPILE="aarch64-linux-gnu-"
    echo -e "${GREEN}✓ Found: $(aarch64-linux-gnu-gcc --version | head -1)${NC}"
elif command -v aarch64-unknown-linux-gnu-gcc &> /dev/null; then
    CROSS_COMPILE="aarch64-unknown-linux-gnu-"
    echo -e "${GREEN}✓ Found: $(aarch64-unknown-linux-gnu-gcc --version | head -1)${NC}"
elif command -v aarch64-elf-gcc &> /dev/null; then
    CROSS_COMPILE="aarch64-elf-"
    echo -e "${YELLOW}⚠ Found bare-metal toolchain (may work): $(aarch64-elf-gcc --version | head -1)${NC}"
else
    echo -e "${RED}Error: Could not install cross-compiler.${NC}"
    echo ""
    echo "Please install manually:"
    echo "  Option 1: brew tap messense/macos-cross-toolchains && brew install aarch64-unknown-linux-gnu"
    echo "  Option 2: Download from https://developer.arm.com/downloads/-/gnu-a"
    exit 1
fi

# Step 2: Create build directory
echo ""
echo -e "${YELLOW}Step 2: Setting up build directory...${NC}"
mkdir -p "$KERNEL_BUILD_DIR"
cd "$KERNEL_BUILD_DIR"

# Step 3: Download kernel source
echo ""
echo -e "${YELLOW}Step 3: Downloading Linux kernel $LINUX_VERSION...${NC}"

KERNEL_TARBALL="linux-$LINUX_VERSION.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/$KERNEL_TARBALL"

if [ ! -d "linux-$LINUX_VERSION" ]; then
    if [ ! -f "$KERNEL_TARBALL" ]; then
        echo "Downloading $KERNEL_URL..."
        curl -L -O "$KERNEL_URL"
    fi
    echo "Extracting..."
    tar xf "$KERNEL_TARBALL"
    echo -e "${GREEN}✓ Kernel source ready${NC}"
else
    echo -e "${GREEN}✓ Kernel source already exists${NC}"
fi

cd "linux-$LINUX_VERSION"

# Step 4: Create minimal kernel config
echo ""
echo -e "${YELLOW}Step 4: Creating minimal microVM kernel config...${NC}"

# Start with a minimal config
make ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE defconfig

# Now customize for microVM
cat > microvm_config_fragment << 'EOF'
# Disable unnecessary features for faster boot
CONFIG_MODULES=n
CONFIG_PRINTK=y
CONFIG_BUG=y

# Serial console (critical for output)
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_SERIAL_EARLYCON=y

# Virtio devices (for networking and vsock)
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y

# Basic networking
CONFIG_NET=y
CONFIG_INET=y
CONFIG_PACKET=y
CONFIG_UNIX=y

# Minimal filesystem support
CONFIG_TMPFS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y

# RAM disk for initramfs
CONFIG_BLK_DEV_RAM=y
CONFIG_BLK_DEV_INITRD=y

# Disable unused features
CONFIG_SOUND=n
CONFIG_USB=n
CONFIG_DRM=n
CONFIG_FB=n
CONFIG_VGA_CONSOLE=n
CONFIG_HID=n
CONFIG_INPUT=n
CONFIG_SERIO=n
CONFIG_HWMON=n
CONFIG_THERMAL=n
CONFIG_WATCHDOG=n
CONFIG_REGULATOR=n
CONFIG_POWER_SUPPLY=n
CONFIG_LEDS=n
CONFIG_RTC=n
CONFIG_IOMMU=n
CONFIG_CRYPTO=n
CONFIG_WIRELESS=n
CONFIG_WLAN=n
CONFIG_BT=n
CONFIG_NFC=n
CONFIG_RFKILL=n
CONFIG_MEDIA=n
CONFIG_STAGING=n
CONFIG_ACCESSIBILITY=n
EOF

# Apply the fragment
./scripts/kconfig/merge_config.sh -m .config microvm_config_fragment

# Clean up
rm microvm_config_fragment

echo -e "${GREEN}✓ Config created${NC}"

# Step 5: Build the kernel
echo ""
echo -e "${YELLOW}Step 5: Building kernel (this takes a few minutes)...${NC}"
echo ""

# Use all CPU cores
JOBS=$(sysctl -n hw.ncpu)

make ARCH=arm64 CROSS_COMPILE=$CROSS_COMPILE -j$JOBS Image

# Step 6: Copy the result
echo ""
if [ -f "arch/arm64/boot/Image" ]; then
    cp arch/arm64/boot/Image "$KERNEL_BUILD_DIR/Image"
    SIZE=$(du -h "$KERNEL_BUILD_DIR/Image" | cut -f1)

    echo -e "${GREEN}=== BUILD SUCCESSFUL ===${NC}"
    echo ""
    echo "Kernel: $KERNEL_BUILD_DIR/Image"
    echo "Size:   $SIZE"
    echo ""
    echo "To test:"
    echo "  cargo run --example boot_linux -- $KERNEL_BUILD_DIR/Image"
else
    echo -e "${RED}Build failed - Image not found${NC}"
    exit 1
fi
