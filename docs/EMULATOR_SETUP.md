# ESP32 Remote Signer - Emulator Setup Guide

This guide explains how to run the ESP32 Remote Signer firmware in an emulator for development and testing without physical hardware.

## Overview

The emulator setup allows you to:
- Test firmware functionality without ESP32 hardware
- Develop and debug with faster iteration cycles
- Run automated tests in CI/CD pipelines
- Simulate different device modes (provisioning vs signing)

## Prerequisites

### 1. ESP-IDF Installation
Ensure ESP-IDF v5.x is installed and configured:
```bash
# If not installed, follow:
# https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/
source ~/esp-idf/export.sh
```

### 2. Python Dependencies
```bash
pip install requests urllib3
```

## Installing QEMU for ESP32

### macOS (Recommended)
```bash
# Using Homebrew
brew tap espressif/tap
brew install qemu-esp32

# Or use the Makefile target
make install-qemu-macos
```

### Linux
```bash
# Ubuntu/Debian
wget https://github.com/espressif/qemu/releases/download/esp-v8.1.0-20230815/qemu-esp32-v8.1.0-20230815-x86_64-linux-gnu.tar.xz
tar -xf qemu-esp32-v8.1.0-20230815-x86_64-linux-gnu.tar.xz
export PATH=$PATH:$(pwd)/qemu/bin
```

### Windows
Download the Windows release from:
https://github.com/espressif/qemu/releases

## Quick Start

### 1. Build for Emulator
```bash
make emulator-build
```

This creates a special build without hardware security features that would prevent emulation.

### 2. Run in Signing Mode (Default)
```bash
make emulator-run
```

### 3. Run in Provisioning Mode
```bash
make emulator-run-provisioning
```

### 4. All-in-One Setup
```bash
make emulator-setup
```

## Emulator Features

### Supported Features
✅ Core application logic
✅ REST API endpoints
✅ GPIO simulation (provisioning/signing mode)
✅ Basic WiFi simulation
✅ HTTP/HTTPS server
✅ NVS storage (unencrypted)
✅ Serial console output
✅ GDB debugging support

### Limitations
❌ Secure Boot (disabled in emulator)
❌ Flash Encryption (disabled in emulator)
❌ Real WiFi connectivity (simulated)
❌ Hardware random number generator (software fallback)
❌ Actual cryptographic signing (placeholder implementation)
❌ Real-time performance characteristics

## Advanced Usage

### Manual QEMU Launch
```bash
qemu-system-xtensa \
    -M esp32 \
    -m 4M \
    -kernel build/bootloader/bootloader.bin \
    -drive file=build/esp32-remote-signer.bin,if=mtd,format=raw \
    -nic user,model=esp32_wifi,hostfwd=tcp::8443-:443 \
    -serial stdio \
    -display none
```

### Environment Variables

Control emulator behavior with environment variables:

```bash
# Simulate provisioning mode
export ESP32_PROVISIONING_MODE=1

# Enable WiFi simulation
export ESP32_WIFI_SIMULATION=1

# Then run emulator
./scripts/run_emulator.sh
```

### Port Forwarding

The emulator forwards the ESP32's HTTPS port (443) to localhost:8443:
- Device URL in emulator: `https://localhost:8443`
- Use `curl -k` or disable SSL verification for self-signed certificates

### Debugging with GDB

1. Start emulator in debug mode:
```bash
./scripts/run_emulator.sh --debug
```

2. In another terminal, connect GDB:
```bash
xtensa-esp32-elf-gdb build/esp32-remote-signer.elf
(gdb) target remote :1234
(gdb) continue
```

## Testing

### Automated Testing
```bash
# Start emulator
make emulator-run &

# Wait for startup
sleep 5

# Run tests
python test/emulator_test.py
```

### Manual Testing with curl

Test health endpoint:
```bash
curl -k https://localhost:8443/health
```

Test info endpoint:
```bash
curl -k https://localhost:8443/info
```

Test provisioning (only works in provisioning mode):
```bash
curl -k -X POST https://localhost:8443/wifi \
  -H "Content-Type: application/json" \
  -d '{"ssid":"TestNetwork","psk":"password"}'
```

### Node.js Client Testing

```javascript
const { ESP32Client } = require('./client/dist');

const client = new ESP32Client({
    deviceUrl: 'https://localhost:8443',
    authKey: '0'.repeat(64),  // Test key
    clientId: 'emulator-test'
});

// Disable SSL verification for self-signed cert
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

async function test() {
    const health = await client.getHealth();
    console.log('Health:', health);

    const info = await client.getInfo();
    console.log('Device Info:', info);
}

test().catch(console.error);
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: ESP32 Emulator Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install ESP-IDF
        run: |
          git clone --recursive https://github.com/espressif/esp-idf.git
          cd esp-idf
          ./install.sh

      - name: Install QEMU
        run: |
          wget https://github.com/espressif/qemu/releases/download/esp-v8.1.0-20230815/qemu-esp32-v8.1.0-20230815-x86_64-linux-gnu.tar.xz
          tar -xf qemu-esp32-v8.1.0-20230815-x86_64-linux-gnu.tar.xz
          echo "$(pwd)/qemu/bin" >> $GITHUB_PATH

      - name: Build Firmware
        run: |
          source esp-idf/export.sh
          make emulator-build

      - name: Run Tests
        run: |
          make emulator-run &
          sleep 10
          python test/emulator_test.py
```

## Troubleshooting

### QEMU Not Found
```bash
# Check if QEMU is installed
which qemu-system-xtensa

# Set path manually if needed
export QEMU_ESP32_PATH=/path/to/qemu-system-xtensa
```

### Build Errors
```bash
# Clean build directory
make clean

# Ensure correct config is used
cp sdkconfig.emulator sdkconfig.defaults
idf.py fullclean
idf.py build
```

### Emulator Won't Start
- Check if port 8443 is already in use
- Verify firmware was built with emulator config
- Check QEMU version compatibility

### Connection Refused
- Wait for device to fully boot (10-15 seconds)
- Check firewall settings
- Verify port forwarding with `netstat -an | grep 8443`

### GPIO Simulation Issues
- Provisioning mode: GPIO 2 & 4 = LOW
- Signing mode: GPIO 2 & 4 = HIGH
- Check environment variables are set correctly

## Performance Notes

The emulator runs significantly slower than real hardware:
- Boot time: 10-15 seconds (vs 2-3 seconds on hardware)
- API response time: 50-200ms (vs 10-50ms on hardware)
- CPU-intensive operations may timeout

Adjust timeouts in test scripts accordingly.

## Next Steps

1. **Development Workflow**
   - Make code changes
   - Run `make emulator-build`
   - Test with `make emulator-run`
   - Use automated tests for validation

2. **Debugging**
   - Use GDB for step debugging
   - Add logging statements
   - Monitor serial console output

3. **Testing**
   - Write unit tests for new features
   - Use emulator for integration testing
   - Validate on real hardware before production

## Related Documentation

- [Hardware Setup](HARDWARE_SETUP.md) - For physical ESP32 setup
- [Project Status](PROJECT_STATUS.md) - Implementation status
- [Security Model](SECURITY_MODEL.md) - Security considerations
- [QEMU ESP32 Documentation](https://github.com/espressif/qemu/wiki)