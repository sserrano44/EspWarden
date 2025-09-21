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

# Note: QEMU detection is handled by ESP-IDF's idf.py qemu command
# No need for manual QEMU detection since we use ESP-IDF integration

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

# Source ESP-IDF environment if not already sourced
if [ -z "$IDF_PATH" ]; then
    if [ -f "$HOME/esp/esp-idf/export.sh" ]; then
        echo -e "${GREEN}Sourcing ESP-IDF environment...${NC}"
        . "$HOME/esp/esp-idf/export.sh" > /dev/null 2>&1
    else
        echo -e "${RED}Error: ESP-IDF environment not found${NC}"
        echo "Please source ESP-IDF: . ~/esp/esp-idf/export.sh"
        exit 1
    fi
fi

# Use ESP-IDF's QEMU integration for best compatibility
echo -e "${GREEN}Starting QEMU using ESP-IDF integration...${NC}"

# Build QEMU command based on mode
if [ "$GPIO_PROVISIONING_MODE" = "1" ]; then
    echo -e "${YELLOW}Provisioning mode: GPIO simulation not fully supported in ESP-IDF QEMU${NC}"
    echo -e "${YELLOW}Application will start in normal mode - use software configuration${NC}"
fi

# Add debug options if requested
if [ "$DEBUG_MODE" = "1" ]; then
    echo -e "${YELLOW}Debug mode enabled${NC}"
    QEMU_EXTRA_ARGS="-s -S"
    echo "Connect with: xtensa-esp32-elf-gdb -ex 'target remote :1234'"
    idf.py qemu --qemu-extra-args="$QEMU_EXTRA_ARGS" &
    QEMU_PID=$!
else
    # Start QEMU without monitor for background operation
    idf.py qemu &
    QEMU_PID=$!
fi

# Wait a moment for QEMU to start
sleep 2

echo -e "${GREEN}QEMU started (PID: $QEMU_PID)${NC}"
echo "Serial connection available on socket://localhost:5555"
echo ""
echo "To connect to serial:"
echo "  nc localhost 5555"
echo "  or: idf.py monitor -p socket://localhost:5555"
echo ""
echo "To stop QEMU:"
echo "  kill $QEMU_PID"
echo ""

# Wait for user input or timeout
if [ "$DEBUG_MODE" != "1" ]; then
    echo "Press Enter to stop QEMU, or Ctrl+C to leave it running..."
    read -t 30 || true
    kill $QEMU_PID 2>/dev/null || true
    echo -e "${GREEN}QEMU stopped${NC}"
fi

exit 0

