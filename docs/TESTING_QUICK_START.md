# Testing Quick Start Guide

## 🚀 5-Minute Setup

### Prerequisites Check
```bash
# Check ESP-IDF
echo $IDF_PATH  # Should show ESP-IDF path

# If not installed:
cd ~/esp && git clone -b v5.0 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh && source ./export.sh
```

### Install Test Dependencies
```bash
cd test
pip3 install -r requirements.txt
```

## 🧪 Running Tests

### Option 1: Test Everything (Recommended)
```bash
# From project root
./test/run_tests.sh all
```

### Option 2: Test With Emulator (No Hardware)
```bash
# Build and test in emulator
make emulator-build
make emulator-run-bg
python3 test/emulator_test.py
```

### Option 3: Test With Real Hardware
```bash
# Flash device
make flash

# Run API tests
python3 test/test_crypto.py
```

## 📊 Understanding Results

### Good Output ✅
```
✓ Health check passed: nonce=a1b2c3d4...
✓ Device unlocked: token=xyz123...
✓ EIP-155 signing passed: v=37, r=7c1f8a76...
✓ Signature verification passed
✓ Performance Test: 25.3 signatures/second

======================================
✓ ALL TESTS PASSED
======================================
```

### Issues to Fix ❌
```
✗ Signing failed: 403 (Device in provisioning mode)
  → Solution: Remove GPIO jumpers

✗ Authentication failed: 401
  → Solution: Check AUTH_KEY environment variable

✗ Timeout waiting for device
  → Solution: Check device is running and accessible
```

## 🔍 Quick Diagnostics

### Check Device Status
```bash
# Is device responding?
curl -k https://192.168.1.100/health

# Check device mode
curl -k https://192.168.1.100/info | jq .mode
```

### View Device Logs
```bash
# Hardware
idf.py monitor

# Emulator
nc localhost 5555
```

### Test Specific Component
```bash
# Test only crypto operations
python3 -c "from test_crypto import TestCryptoOperations; t = TestCryptoOperations(); t.test_eip155_signing()"

# Test only performance
./test/run_tests.sh crypto
```

## 🏃 Speed Run Commands

```bash
# Complete test in one command (emulator)
make emulator-build && make emulator-run-bg && sleep 5 && python3 test/emulator_test.py

# Quick hardware test
make flash && python3 test/test_crypto.py

# Minimal smoke test
curl -k https://device-ip/health && echo "✓ Device OK"
```

## 📈 Performance Targets

| Metric | Target | Command to Test |
|--------|--------|-----------------|
| Signature Rate | >10/sec | `python3 test/test_crypto.py::test_crypto_performance` |
| Response Time | <500ms | `curl -k -w "%{time_total}" https://device/health` |
| Memory Stable | No leaks | `./test/run_tests.sh emulator` (includes memory test) |

## 🐛 Common Fixes

| Problem | Quick Fix |
|---------|-----------|
| "QEMU not found" | `make install-qemu-macos` or `idf_tools.py install qemu-xtensa` |
| "Port 5555 in use" | `lsof -i :5555` then `kill -9 <PID>` |
| "SSL certificate error" | `export ESP32_SKIP_SSL_VERIFY=1` |
| "Device not responding" | Check IP: `export ESP32_SIGNER_URL="https://correct-ip"` |
| "403 Forbidden" | Device in provisioning mode - remove GPIO jumpers |

## 📝 Test Checklist

Before commit:
- [ ] `make dev-build` - Builds successfully
- [ ] `./test/run_tests.sh unit` - Unit tests pass
- [ ] `./test/run_tests.sh emulator` - Emulator tests pass
- [ ] `./test/run_tests.sh api` - API tests pass
- [ ] No memory leaks reported
- [ ] Performance meets targets

## 🎯 What to Test After Changes

### Changed Crypto Code?
```bash
./test/run_tests.sh crypto
pytest test/test_crypto.py::TestCryptoOperations -v
```

### Changed API Endpoints?
```bash
./test/run_tests.sh api
python3 test/test_crypto.py
```

### Changed Build Config?
```bash
make clean
make emulator-build
./test/run_tests.sh emulator
```

### Everything?
```bash
./test/run_tests.sh all
```

## 📱 Contact & Support

- Test failures? Check `test/logs/`
- Need help? See full [TESTING.md](TESTING.md)
- Found a bug? File an issue with test output