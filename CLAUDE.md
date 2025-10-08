# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP32 Remote Signer is a secure, policy-enforced hardware signer for Ethereum transactions. It consists of ESP32 firmware (C/ESP-IDF) and a Node.js client library (TypeScript). The device operates in two modes: provisioning (configuration) and signing (operational), controlled by the built-in BOOT button.

## Critical Commands

### Emulator Development (No Hardware Required)

```bash
# Quick start with emulator
make install-qemu-macos     # Install QEMU ESP32 (one-time)
make emulator-build          # Build firmware for emulator
make emulator-run            # Run in signing mode
make emulator-run-provisioning  # Run in provisioning mode

# Test in emulator
python test/emulator_test.py  # Run automated tests
```

### ESP32 Firmware Development

```bash
# Prerequisites: ESP-IDF v5.x must be installed and sourced
. ~/esp-idf/export.sh  # Or wherever ESP-IDF is installed

# Development workflow
make dev-build        # Build with development configuration
make flash           # Flash to device (auto-detects port)
make monitor         # Serial monitor for debugging

# Production workflow
make generate-keys   # Generate secure boot keys (ONLY ONCE!)
make prod-build      # Build with production security features
make flash-secure    # Flash with secure boot enabled

# Configuration
idf.py menuconfig    # Modify ESP32 configuration
```

### Node.js Client Development

```bash
cd client
npm install          # Install dependencies
npm run build        # Compile TypeScript
npm run dev          # Watch mode for development
npm test            # Run tests (when implemented)
npm run lint        # Check TypeScript code style
```

## Architecture & Implementation Status

### Dual-Architecture System

1. **ESP32 Firmware** (`/main/`): Implements secure storage, HTTPS server, and transaction signing
2. **Node.js Client** (`/client/`): Provides ethers.js-compatible Signer and direct API access

### Key Implementation Gaps

Currently ~75% complete. Critical unimplemented components that require attention:

1. **HMAC Authentication** (`main/auth_manager.c`): Framework exists but no actual HMAC verification. Session tokens are placeholders.

2. **Crypto Operations** (`main/crypto_manager.c`): No secp256k1 signing implemented. Need to integrate trezor-crypto library.

3. **Policy Engine** (`main/policy_engine.c`): Transaction validation logic missing. Policy structure defined but not enforced.

4. **Encrypted Storage** (`main/storage_manager.c`): NVS partitions configured but key/policy persistence not implemented.

### Mode Switching Logic

The device determines its operational mode at boot via the BOOT button:
- **Provisioning Mode**: BOOT button held during power-on/reset → Allows configuration changes
- **Signing Mode**: Normal boot (BOOT button not pressed) → Read-only operation, only signs transactions

This is enforced in `device_mode.c` and checked by all API handlers in `api_handlers.c`.

### API Authentication Flow

1. Client calls `/health` to get nonce
2. Client computes HMAC(auth_key, nonce||method||path||body)
3. Client sends HMAC to `/unlock` to get session token
4. Client includes token in subsequent signing requests
5. Token expires after 60 seconds

Currently returns placeholder tokens - needs implementation in `auth_manager.c`.

### Transaction Signing Pipeline

1. Client sends EIP-1559/155 transaction to `/sign/eip1559` or `/sign/eip155`
2. Device validates against policy (whitelists, caps)
3. Device signs with private key using secp256k1
4. Returns signature (r,s,v) for client to broadcast

Currently returns 501 Not Implemented - needs crypto library integration.

## File Modifications Pattern

When implementing missing components:

1. **ESP32 C files**: Follow existing patterns in `api_handlers.c` for endpoint structure
2. **Include guards**: All headers use `#ifndef FILENAME_H` pattern
3. **Error handling**: Use `signer_error_t` enum from `esp32_signer.h`
4. **Client TypeScript**: Extend existing classes, maintain error hierarchy in `errors.ts`

## Security Configurations

Two distinct build configurations:

- **Development** (`sdkconfig.defaults.dev`): JTAG enabled, debug logging, development flash encryption
- **Production** (`sdkconfig.defaults.prod`): JTAG disabled, secure boot v2, release flash encryption

Never use development configuration with real funds.

## Testing Hardware Setup

Minimum hardware requirements:
- ESP32 NodeMCU-32S or compatible
- USB cable for power/programming

Entering provisioning mode:
- Hold the BOOT button while powering on or resetting the device

## PRD Compliance

Implementation must follow requirements in `PRD_v0.md`:
- HMAC challenge-response authentication
- Policy enforcement before signing
- Rate limiting (10 req/min default)
- Secure boot and flash encryption in production
- No sensitive data in logs

## Port Configuration

Default ports and protocols:
- ESP32 HTTPS Server: Port 443 (self-signed cert)
- Serial Monitor: 115200 baud
- WiFi: Configured during provisioning

For development, set `NODE_TLS_REJECT_UNAUTHORIZED=0` to accept self-signed certificates.
- we should never build an endpoint that returns the private key
- ESP-IDF Python virtual environment is at /Users/sebas/esp/esp-idf