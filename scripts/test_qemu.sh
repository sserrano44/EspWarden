#!/bin/bash

# Test QEMU ESP32 connection script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}ESP32 QEMU Test Script${NC}"
echo "================================"

# Source ESP-IDF if needed
if [ -z "$IDF_PATH" ]; then
    if [ -f "$HOME/esp/esp-idf/export.sh" ]; then
        echo -e "${GREEN}Sourcing ESP-IDF environment...${NC}"
        . "$HOME/esp/esp-idf/export.sh" 2>/dev/null
    fi
fi

# Check if QEMU is already running
if nc -z localhost 5555 2>/dev/null; then
    echo -e "${YELLOW}QEMU appears to be already running on port 5555${NC}"
    echo "Killing existing QEMU process..."
    pkill -f "qemu-system-xtensa.*5555" || true
    sleep 2
fi

echo -e "${GREEN}Starting QEMU in background...${NC}"
# Start QEMU without monitor
idf.py qemu 2>&1 | grep -E "Running qemu|flash|efuse" &
QEMU_PID=$!

# Wait for QEMU to start
echo "Waiting for QEMU to start..."
for i in {1..10}; do
    if nc -z localhost 5555 2>/dev/null; then
        echo -e "${GREEN}QEMU started successfully!${NC}"
        break
    fi
    sleep 1
done

if ! nc -z localhost 5555 2>/dev/null; then
    echo -e "${RED}Failed to start QEMU${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Testing connection to QEMU...${NC}"
# Send a simple test to see if we get any response
echo "" | nc -w 2 localhost 5555 | head -20 || true

echo ""
echo -e "${GREEN}QEMU is running!${NC}"
echo "You can now:"
echo "1. Connect manually: nc localhost 5555"
echo "2. Use monitor: idf.py monitor -p socket://localhost:5555"
echo "3. Stop QEMU: pkill qemu-system-xtensa"
echo ""
echo "Note: The application may crash due to secure boot being enabled in emulator."
echo "To test properly, use emulator build configuration (make emulator-build)."