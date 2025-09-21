#!/bin/bash

# ESP32 Remote Signer - QEMU Emulator Launch Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration - Check ESP-IDF tools first, then fallback to system paths
if [ -d "$HOME/.espressif/tools/qemu-xtensa" ]; then
    # Find the latest QEMU version in ESP-IDF tools
    QEMU_ESP_PATH=$(find "$HOME/.espressif/tools/qemu-xtensa" -name "qemu-system-xtensa" -type f -executable 2>/dev/null | head -1)
    if [ -n "$QEMU_ESP_PATH" ]; then
        echo -e "${GREEN}Found QEMU at: $QEMU_ESP_PATH${NC}"
    fi
fi

# Set default QEMU path
QEMU_ESP32_PATH="${QEMU_ESP32_PATH:-${QEMU_ESP_PATH:-/usr/local/bin/qemu-system-xtensa}}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
FIRMWARE_BIN="${BUILD_DIR}/esp32-remote-signer.bin"

# GPIO simulation flags
GPIO_PROVISIONING_MODE=0  # Set to 1 to simulate provisioning mode

echo -e "${GREEN}ESP32 Remote Signer Emulator${NC}"
echo "================================"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --provisioning)
            GPIO_PROVISIONING_MODE=1
            echo -e "${YELLOW}Starting in PROVISIONING MODE${NC}"
            shift
            ;;
        --build)
            SHOULD_BUILD=1
            shift
            ;;
        --debug)
            DEBUG_MODE=1
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --provisioning  Start emulator in provisioning mode"
            echo "  --build         Build the firmware before running"
            echo "  --debug         Enable GDB debugging on port 1234"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check if QEMU is installed
if ! command -v qemu-system-xtensa &> /dev/null && [ ! -f "$QEMU_ESP32_PATH" ]; then
    echo -e "${RED}Error: QEMU for ESP32 not found!${NC}"
    echo ""
    echo "Please install QEMU ESP32 first:"
    echo ""
    echo "Method 1: Install via ESP-IDF tools (recommended):"
    echo "  brew install libgcrypt glib pixman sdl2 libslirp"
    echo "  idf_tools.py install qemu-xtensa qemu-riscv32"
    echo "  . ~/esp/esp-idf/export.sh"
    echo ""
    echo "Method 2: Use ESP-IDF's built-in QEMU command:"
    echo "  idf.py qemu monitor"
    echo ""
    echo "Or set QEMU_ESP32_PATH environment variable if installed elsewhere:"
    echo "  export QEMU_ESP32_PATH=/path/to/qemu-system-xtensa"
    exit 1
fi

# Find QEMU executable
if [ -f "$QEMU_ESP32_PATH" ]; then
    QEMU_BIN="$QEMU_ESP32_PATH"
elif command -v qemu-system-xtensa &> /dev/null; then
    QEMU_BIN="qemu-system-xtensa"
else
    echo -e "${RED}Error: Cannot find QEMU executable${NC}"
    exit 1
fi

# Build firmware if requested
if [ "$SHOULD_BUILD" = "1" ]; then
    echo -e "${GREEN}Building firmware for emulator...${NC}"
    cd "$PROJECT_ROOT"

    # Use emulator configuration
    cp sdkconfig.emulator sdkconfig.defaults
    idf.py build

    echo -e "${GREEN}Build complete!${NC}"
fi

# Check if firmware exists
if [ ! -f "$FIRMWARE_BIN" ]; then
    echo -e "${RED}Error: Firmware not found at $FIRMWARE_BIN${NC}"
    echo "Run with --build flag to build the firmware first"
    exit 1
fi

# Prepare QEMU arguments
QEMU_ARGS=(
    -M esp32
    -m 4M
    -kernel "$BUILD_DIR/bootloader/bootloader.bin"
    -drive file="$BUILD_DIR/esp32-remote-signer.bin",if=mtd,format=raw
    -nic user,model=esp32_wifi,hostfwd=tcp::8443-:443
    -serial stdio
    -display none
)

# Add GPIO simulation for provisioning mode
if [ "$GPIO_PROVISIONING_MODE" = "1" ]; then
    # Simulate GPIO 2 and 4 pulled low (provisioning mode)
    QEMU_ARGS+=(-global esp32.gpio2.level=0)
    QEMU_ARGS+=(-global esp32.gpio4.level=0)
else
    # Simulate GPIO 2 and 4 pulled high (signing mode)
    QEMU_ARGS+=(-global esp32.gpio2.level=1)
    QEMU_ARGS+=(-global esp32.gpio4.level=1)
fi

# Add debug options if requested
if [ "$DEBUG_MODE" = "1" ]; then
    QEMU_ARGS+=(-s -S)
    echo -e "${YELLOW}Debug mode enabled. GDB server listening on port 1234${NC}"
    echo "Connect with: xtensa-esp32-elf-gdb -ex 'target remote :1234'"
fi

# Create virtual flash image if it doesn't exist
FLASH_IMG="${BUILD_DIR}/flash_image.bin"
if [ ! -f "$FLASH_IMG" ]; then
    echo -e "${GREEN}Creating virtual flash image...${NC}"

    # Create a 4MB flash image
    dd if=/dev/zero of="$FLASH_IMG" bs=1M count=4 2>/dev/null

    # Write bootloader at 0x1000
    dd if="${BUILD_DIR}/bootloader/bootloader.bin" of="$FLASH_IMG" bs=1 seek=$((0x1000)) conv=notrunc 2>/dev/null

    # Write partition table at 0x8000
    dd if="${BUILD_DIR}/partition_table/partition-table.bin" of="$FLASH_IMG" bs=1 seek=$((0x8000)) conv=notrunc 2>/dev/null

    # Write application at 0x10000
    dd if="${BUILD_DIR}/esp32-remote-signer.bin" of="$FLASH_IMG" bs=1 seek=$((0x10000)) conv=notrunc 2>/dev/null
fi

echo ""
echo -e "${GREEN}Starting QEMU ESP32 Emulator...${NC}"
echo "================================"
echo "Device Mode: $([ "$GPIO_PROVISIONING_MODE" = "1" ] && echo "PROVISIONING" || echo "SIGNING")"
echo "HTTPS Server: https://localhost:8443"
echo "Serial Console: Active"
echo ""
echo "Press Ctrl+A, X to exit QEMU"
echo "================================"
echo ""

# Run QEMU
exec "$QEMU_BIN" "${QEMU_ARGS[@]}"