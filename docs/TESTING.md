# ESP32 Remote Signer - Testing Documentation

## Table of Contents
1. [Overview](#overview)
2. [Test Architecture](#test-architecture)
3. [Setting Up Testing Environment](#setting-up-testing-environment)
4. [Running Tests](#running-tests)
5. [Test Suites Detailed](#test-suites-detailed)
6. [Interpreting Results](#interpreting-results)
7. [Troubleshooting](#troubleshooting)
8. [Continuous Integration](#continuous-integration)

## Overview

The ESP32 Remote Signer employs a multi-layered testing strategy to ensure reliability and security of cryptographic operations:

- **Unit Tests**: Test individual crypto functions at the firmware level
- **Integration Tests**: Test component interactions
- **API Tests**: Validate HTTP/HTTPS endpoints
- **Emulator Tests**: Test complete system without hardware
- **Performance Tests**: Benchmark signing operations

### Key Testing Goals

1. **Cryptographic Correctness**: Verify secp256k1 operations produce valid Ethereum signatures
2. **Security Validation**: Ensure authentication and mode enforcement work correctly
3. **Performance Metrics**: Confirm signing rate meets requirements
4. **Memory Stability**: Detect memory leaks and resource issues
5. **API Compliance**: Validate REST API responses match specifications

## Test Architecture

```
┌─────────────────────────────────────────────┐
│           Test Suite Architecture           │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────┐      ┌─────────────┐      │
│  │  Unit Tests │      │   API Tests  │      │
│  │   (Unity)   │      │   (Python)   │      │
│  └──────┬──────┘      └──────┬──────┘      │
│         │                     │              │
│  ┌──────▼───────────────────▼──────┐       │
│  │     Integration Test Layer       │       │
│  │   (Python + ESP-IDF + QEMU)      │       │
│  └──────────────┬───────────────────┘       │
│                 │                            │
│  ┌──────────────▼───────────────────┐       │
│  │    Performance & Load Testing     │       │
│  │         (Python + Locust)         │       │
│  └───────────────────────────────────┘      │
│                                             │
└─────────────────────────────────────────────┘
```

## Setting Up Testing Environment

### Prerequisites

#### 1. ESP-IDF Environment
```bash
# Install ESP-IDF v5.x
mkdir -p ~/esp
cd ~/esp
git clone -b v5.0 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32
source ./export.sh
```

#### 2. Python Dependencies
```bash
cd test
pip3 install -r requirements.txt
```

#### 3. QEMU ESP32 (for emulator tests)
```bash
# macOS
make install-qemu-macos

# Linux
idf_tools.py install qemu-xtensa

# Verify installation
qemu-system-xtensa --version
```

### Test Configuration

Create a test configuration file:

```bash
# test/config.env
export ESP32_SIGNER_URL="https://192.168.1.100"
export ESP32_AUTH_KEY="test_auth_key_for_development"
export ESP32_SKIP_SSL_VERIFY=1
export ESP32_TEST_MODE="emulator"  # or "hardware"
```

Load configuration:
```bash
source test/config.env
```

## Running Tests

### Quick Start - Run All Tests

```bash
# Run complete test suite
cd test
./run_tests.sh all

# Run with verbose output
./run_tests.sh all --verbose
```

### Individual Test Suites

#### 1. Unit Tests (Firmware Level)

```bash
# Build and flash unit tests to hardware
cd test/unit
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor

# Expected output:
# [CRYPTO_TEST] Starting crypto unit tests
# [UNITY] test_crypto_manager_init PASS
# [UNITY] test_generate_private_key PASS
# ... (more test results)
# [UNITY] 9 Tests 0 Failures 0 Ignored
```

#### 2. Emulator Tests

```bash
# Build firmware for emulator
make emulator-build

# Start emulator in background
make emulator-run-bg

# Run emulator test suite
python3 test/emulator_test.py

# Run specific emulator test
python3 -c "from emulator_test import ESP32EmulatorTest; t = ESP32EmulatorTest(); t.test_eip155_signing()"
```

#### 3. API Tests

```bash
# Start device or emulator first
make emulator-run-bg

# Run API tests
python3 test/test_crypto.py

# Run with pytest for detailed output
pytest test/test_crypto.py -v

# Run specific test class
pytest test/test_crypto.py::TestCryptoOperations -v

# Run single test
pytest test/test_crypto.py::TestCryptoOperations::test_eip155_signing -v
```

#### 4. Performance Tests

```bash
# Run performance benchmarks
python3 test/test_crypto.py::TestPerformance

# Run with custom parameters
python3 -c "
from test_crypto import PerformanceTest
perf = PerformanceTest()
perf.test_signing_performance(iterations=1000)
"
```

### Test Modes

#### Hardware Testing
```bash
# Flash firmware to real ESP32
make flash

# Set device IP
export ESP32_SIGNER_URL="https://192.168.1.100"

# Run tests against hardware
./run_tests.sh api
```

#### Emulator Testing
```bash
# Use QEMU emulator (no hardware required)
make emulator-setup
./run_tests.sh emulator
```

#### Mock Testing
```bash
# Run with mocked crypto operations
export ESP32_USE_MOCK_CRYPTO=1
python3 test/test_crypto.py
```

## Test Suites Detailed

### Crypto Operations Tests

Tests core trezor-crypto integration:

| Test | Description | Expected Result |
|------|-------------|-----------------|
| `test_generate_private_key` | Generate secp256k1 private key | 32-byte random key |
| `test_derive_public_key` | Derive public key from private | 64-byte uncompressed key |
| `test_ethereum_address` | Calculate Ethereum address | 20-byte address |
| `test_transaction_signing` | Sign with secp256k1 | Valid (r,s,v) signature |
| `test_signature_determinism` | RFC6979 deterministic signing | Identical signatures |
| `test_signature_verification` | Verify ECDSA signature | Pass/fail correctly |
| `test_different_chain_ids` | EIP-155 chain ID handling | Correct v values |

### API Endpoint Tests

| Endpoint | Test | Validation |
|----------|------|------------|
| `/health` | Connection and nonce | 200 OK, 32-byte nonce |
| `/info` | Device information | Mode, address, version |
| `/unlock` | HMAC authentication | Valid session token |
| `/sign/eip155` | EIP-155 signing | Valid signature |
| `/sign/eip1559` | EIP-1559 signing | Valid signature |
| `/provision/*` | Provisioning endpoints | Mode-dependent access |

### Security Tests

| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Mode Enforcement | Signing blocked in provisioning | 403 Forbidden |
| Authentication | Requires valid HMAC | 401 Unauthorized |
| Rate Limiting | Enforces request limits | 429 Too Many Requests |
| Input Validation | Rejects malformed data | 400 Bad Request |
| Session Timeout | Token expiration | Re-authentication required |

### Performance Benchmarks

| Metric | Target | Measurement |
|--------|--------|-------------|
| Signature Rate | >10 sig/sec | Actual rate |
| Response Time | <500ms | P50, P95, P99 |
| Memory Usage | <50KB/request | Heap monitoring |
| Concurrent Requests | 10 parallel | Success rate |

## Interpreting Results

### Success Indicators

✅ **Green Flags**:
```
✓ All tests passed!
✓ Signature verification successful
✓ Memory stable after 1000 operations
✓ Rate: 25.3 signatures/second
```

### Warning Signs

⚠️ **Yellow Flags**:
```
⚠ Device in provisioning mode - some tests skipped
⚠ Performance below target: 8.5 sig/sec
⚠ Memory usage high: 45KB/request
```

### Failure Indicators

❌ **Red Flags**:
```
✗ Signature verification failed
✗ Memory leak detected: 1024 bytes lost
✗ Authentication failed: Invalid HMAC
✗ Timeout waiting for device
```

### Test Report Example

```
=====================================
ESP32 Remote Signer - Test Report
Generated: 2024-01-20 15:30:45
=====================================

Test Results:
-------------
✓ Unit Tests: PASS (9/9)
✓ API Tests: PASS (12/12)
✓ Security Tests: PASS (5/5)
✓ Performance Tests: PASS (4/4)

Performance Metrics:
-------------------
Signature Rate: 22.7 sig/sec
Average Response: 43ms
Memory Usage: 32KB
Concurrent Success: 100%

Build Information:
-----------------
Commit: abc1234
Branch: main
ESP-IDF: v5.0.1
Trezor-Crypto: integrated

Coverage:
---------
Crypto Functions: 95%
API Endpoints: 92%
Error Handling: 88%
Overall: 91%
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Emulator Won't Start
```bash
# Error: QEMU not found
# Solution:
idf_tools.py install qemu-xtensa
export PATH=$HOME/.espressif/tools/qemu-xtensa/bin:$PATH

# Error: Port 5555 already in use
# Solution:
lsof -i :5555
kill -9 <PID>
```

#### 2. Authentication Failures
```bash
# Error: 401 Unauthorized
# Solution: Check auth key
export ESP32_AUTH_KEY="correct_key"

# Error: Invalid HMAC
# Solution: Verify nonce freshness
curl -k https://device/health  # Get fresh nonce
```

#### 3. Signing Errors
```bash
# Error: 403 Forbidden
# Solution: Device in wrong mode
# Switch to signing mode (remove GPIO jumpers)

# Error: 500 Internal Server Error
# Solution: Check device logs
idf.py monitor  # View serial output
```

#### 4. Performance Issues
```bash
# Slow signature rate
# Solutions:
- Check CPU frequency: CONFIG_ESP32_DEFAULT_CPU_FREQ_240=y
- Disable debug logging: CONFIG_LOG_DEFAULT_LEVEL_INFO=y
- Use release build: make prod-build
```

### Debug Mode

Enable detailed logging:

```python
# In test files
import logging
logging.basicConfig(level=logging.DEBUG)

# In firmware
idf.py menuconfig
# Component config → Log output → Default log level → Debug
```

Monitor device output:
```bash
# Serial console
idf.py monitor

# Emulator console
nc localhost 5555

# Network traffic
tcpdump -i any -s0 -w capture.pcap port 443
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3
      with:
        submodules: recursive

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install ESP-IDF
      run: |
        mkdir ~/esp
        cd ~/esp
        git clone -b v5.0 --recursive https://github.com/espressif/esp-idf.git
        cd esp-idf
        ./install.sh

    - name: Install Dependencies
      run: |
        pip install -r test/requirements.txt
        . ~/esp/esp-idf/export.sh
        idf_tools.py install qemu-xtensa

    - name: Build Firmware
      run: |
        . ~/esp/esp-idf/export.sh
        make emulator-build

    - name: Run Unit Tests
      run: |
        . ~/esp/esp-idf/export.sh
        cd test/unit
        idf.py build

    - name: Run Emulator Tests
      run: |
        . ~/esp/esp-idf/export.sh
        make emulator-run-bg
        sleep 5
        python3 test/emulator_test.py

    - name: Generate Report
      if: always()
      run: |
        ./test/run_tests.sh all --report

    - name: Upload Test Results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: test/test_report_*.txt
```

### Local CI Simulation

```bash
# Run tests as CI would
./test/ci_local.sh

# Script content:
#!/bin/bash
set -e
source ~/esp/esp-idf/export.sh
make clean
make emulator-build
./test/run_tests.sh all --ci-mode
```

## Best Practices

### Writing New Tests

1. **Follow Naming Conventions**
   - Test files: `test_*.py` or `*_test.c`
   - Test functions: `test_<functionality>`
   - Test classes: `Test<Component>`

2. **Use Fixtures**
   ```python
   @pytest.fixture
   def authenticated_client():
       client = ESP32SignerTestClient()
       client.authenticate()
       return client
   ```

3. **Clean Up Resources**
   ```python
   def tearDown(self):
       self.client.close()
       cleanup_test_data()
   ```

4. **Test Edge Cases**
   - Null/empty inputs
   - Maximum values
   - Invalid formats
   - Timeout scenarios

5. **Document Tests**
   ```python
   def test_signature_verification(self):
       """
       Test that signatures can be verified.

       This test:
       1. Signs a transaction
       2. Extracts the signature
       3. Verifies it matches expected format
       4. Validates against public key
       """
   ```

### Test Coverage Goals

- **Critical Functions**: 100% coverage
  - Key generation
  - Signing operations
  - Authentication

- **API Endpoints**: >90% coverage
  - All success paths
  - Common error cases

- **Error Handling**: >80% coverage
  - Invalid inputs
  - Resource failures

- **Performance**: Baseline metrics
  - Signature rate
  - Memory usage
  - Response times

## Support

For testing support:
1. Check test logs in `test/logs/`
2. Review this documentation
3. Check GitHub Issues for known problems
4. Enable debug logging for details
5. Contact development team

## Appendix

### Test Data Files

Located in `test/fixtures/`:
- `test_keys.json`: Known key pairs for deterministic tests
- `test_transactions.json`: Sample transactions
- `expected_signatures.json`: Pre-calculated signatures
- `policy_configs.json`: Test policy configurations

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ESP32_SIGNER_URL` | Device URL | `https://localhost:8443` |
| `ESP32_AUTH_KEY` | Auth key | `0000...` (64 zeros) |
| `ESP32_SKIP_SSL_VERIFY` | Skip SSL | `1` |
| `ESP32_TEST_TIMEOUT` | Timeout (s) | `30` |
| `ESP32_TEST_MODE` | Test mode | `emulator` |