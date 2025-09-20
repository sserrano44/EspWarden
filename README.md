# ESP32 Remote Signer

A secure, policy-enforced remote signer for Ethereum transactions using ESP32 hardware. This project provides a low-cost alternative to expensive Hardware Security Modules (HSMs) for market-making bots and automated trading systems.

## ⚠️ Security Notice

This is **NOT** a tamper-proof HSM. This device is suitable for hot balances with limited blast radius under strict policy enforcement. See [Security Model](#security-model) for details.

## Features

- 🔐 **Hardware-isolated private keys** - Keys never leave the ESP32 device
- 📋 **Policy enforcement** - Address whitelisting, gas caps, function selector filtering
- 🔐 **Secure Boot & Flash Encryption** - Production-grade ESP32 security features
- 🌐 **HTTPS API** - Challenge-response HMAC authentication
- ⚡ **EIP-155/EIP-1559 support** - Modern Ethereum transaction formats
- 🛡️ **Rate limiting** - Configurable request limits and abuse prevention
- 📦 **Node.js client** - Drop-in ethers.js Signer replacement
- 🔄 **Dual mode operation** - Provisioning mode for setup, signing mode for operation

## Quick Start

### Hardware Setup

1. **Required Hardware:**
   - ESP32 NodeMCU-32S (or compatible with Secure Boot support)
   - 2 jumper wires for provisioning mode
   - USB cable for programming

2. **GPIO Connections:**
   ```
   Provisioning Jumper:
   GPIO 2 ──┬── GND (for provisioning mode)
   GPIO 4 ──┘
   ```

### Firmware Installation

1. **Install ESP-IDF:**
   ```bash
   # Install ESP-IDF v5.x
   git clone --recursive https://github.com/espressif/esp-idf.git
   cd esp-idf
   ./install.sh
   . ./export.sh
   ```

2. **Build and Flash:**
   ```bash
   git clone https://github.com/your-org/esp32-remote-signer.git
   cd esp32-remote-signer

   # Development build
   make dev-build
   make flash

   # Production build (with secure boot)
   make generate-keys
   make prod-build
   make flash-secure
   ```

### Device Provisioning

1. **Enter Provisioning Mode:**
   - Connect GPIO 2 and GPIO 4 to GND
   - Power on the device
   - Device will create a WiFi access point

2. **Configure the Device:**
   ```javascript
   const { ESP32Client } = require('@esp32/remote-signer-client');

   const client = new ESP32Client({
     deviceUrl: 'https://192.168.1.100', // Device IP
     authKey: 'your-256-bit-hex-auth-key',
     clientId: 'provisioning-client'
   });

   // Configure WiFi
   await client.configureWiFi({
     ssid: 'YourWiFiNetwork',
     psk: 'your-wifi-password'
   });

   // Set authentication key
   await client.configureAuth({
     password: 'your-strong-provisioning-password'
   });

   // Generate or import private key
   await client.configureKey({
     mode: 'generate' // or 'import' with seed/privkey
   });

   // Set transaction policy
   await client.configurePolicy({
     allowedChains: [1, 10, 8453], // Ethereum, Optimism, Base
     toWhitelist: [
       '0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8',
       '0xA0b86a33E6417C7Ef6D7680B2d5df2aC4d5a6E1B'
     ],
     functionWhitelist: [
       '0xa9059cbb', // transfer(address,uint256)
       '0x095ea7b3'  // approve(address,uint256)
     ],
     maxValueWei: '0x16345785d8a0000', // 0.1 ETH
     maxGasLimit: 200000,
     maxFeePerGasWei: '0x2540be400', // 10 gwei
     allowEmptyDataToWhitelist: true
   });
   ```

3. **Switch to Signing Mode:**
   - Remove the provisioning jumper
   - Restart the device

### Using with ethers.js

```javascript
const { ESP32Signer } = require('@esp32/remote-signer-client');
const { JsonRpcProvider } = require('ethers');

// Create provider
const provider = new JsonRpcProvider('https://mainnet.infura.io/v3/your-key');

// Create ESP32 signer
const signer = new ESP32Signer({
  deviceUrl: 'https://192.168.1.100',
  authKey: 'your-256-bit-hex-auth-key',
  clientId: 'trading-bot-1'
}, provider);

// Use like any ethers.js signer
const tx = await signer.sendTransaction({
  to: '0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8',
  value: ethers.parseEther('0.01'),
  data: '0xa9059cbb000000000000000000000000742d35cc3672c1bfee3d4d5a0e6e9c4ffbe7e8a80000000000000000000000000000000000000000000000000de0b6b3a7640000'
});

console.log('Transaction hash:', tx.hash);
```

## API Reference

### Device Endpoints

#### Public Endpoints (Both Modes)
- `GET /health` - Device health and nonce for authentication
- `GET /info` - Device information and configuration status
- `POST /unlock` - Authenticate and get session token

#### Provisioning Mode Only
- `POST /wifi` - Configure WiFi credentials
- `POST /auth` - Set authentication password
- `POST /key` - Generate or import private key
- `POST /policy` - Set transaction policy
- `POST /wipe` - Factory reset device

#### Signing Mode Only
- `POST /sign/eip1559` - Sign EIP-1559 transaction
- `POST /sign/eip155` - Sign legacy EIP-155 transaction

### Node.js Client API

```javascript
const { ESP32Signer, ESP32Client } = require('@esp32/remote-signer-client');

// Configuration
const config = {
  deviceUrl: 'https://device-ip-address',
  authKey: 'hex-auth-key',
  clientId: 'unique-client-id',
  timeout: 30000, // Request timeout
  retryOptions: {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 30000,
    factor: 2
  }
};

// ESP32Signer (ethers.js compatible)
const signer = new ESP32Signer(config, provider);
await signer.getAddress();
await signer.signTransaction(txRequest);

// ESP32Client (direct API access)
const client = new ESP32Client(config);
await client.getHealth();
await client.getInfo();
await client.signEIP1559(transaction);
```

## Security Model

### What This Device Protects Against
- ✅ Private key extraction from compromised host systems
- ✅ Unauthorized transactions outside policy parameters
- ✅ Replay attacks with nonce-based authentication
- ✅ Man-in-the-middle attacks (HTTPS with cert pinning)
- ✅ Excessive transaction volume (rate limiting)

### What This Device Does NOT Protect Against
- ❌ Physical access to the device
- ❌ Side-channel attacks on ESP32 hardware
- ❌ Attacks on the policy configuration itself
- ❌ Compromise of the provisioning process
- ❌ Quantum computer attacks on secp256k1

### Recommended Use Cases
- ✅ Market-making bots with limited exposure
- ✅ Automated DeFi strategies with whitelisted contracts
- ✅ Development and testing environments
- ✅ Educational and research projects

### NOT Recommended For
- ❌ High-value treasury management
- ❌ Critical infrastructure signing
- ❌ Applications requiring formal security certification
- ❌ Multi-signature wallet implementations

## Policy Configuration

The device enforces policies before signing any transaction:

```javascript
const policy = {
  // Allowed blockchain networks
  allowedChains: [1, 10, 137, 8453],

  // Whitelisted recipient addresses
  toWhitelist: [
    '0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8',
    '0xA0b86a33E6417C7Ef6D7680B2d5df2aC4d5a6E1B'
  ],

  // Allowed function selectors (first 4 bytes of call data)
  functionWhitelist: [
    '0xa9059cbb', // transfer(address,uint256)
    '0x095ea7b3', // approve(address,uint256)
    '0x23b872dd'  // transferFrom(address,address,uint256)
  ],

  // Maximum ETH value per transaction
  maxValueWei: '0x16345785d8a0000', // 0.1 ETH

  // Maximum gas limit
  maxGasLimit: 200000,

  // Maximum fee per gas (for EIP-1559)
  maxFeePerGasWei: '0x2540be400', // 10 gwei

  // Allow transactions with empty data to whitelisted addresses
  allowEmptyDataToWhitelist: true
};
```

## Rate Limiting

Default rate limits:
- **10 requests per minute** (global)
- **Configurable per-client limits**
- **Exponential backoff** on rate limit exceeded
- **Circuit breaker** for repeated failures

## Development

### Building the Firmware

```bash
# Install dependencies
make dev-setup

# Build and flash development version
make dev-build
make flash
make monitor

# Build production version
make prod-build
```

### Building the Client

```bash
cd client
npm install
npm run build
npm test
```

### Testing

```bash
# Run firmware tests
cd tests
npm install
npm test

# Run client tests
cd client
npm test
```

## Troubleshooting

### Common Issues

1. **Device not responding:**
   - Check WiFi connectivity
   - Verify correct IP address
   - Check if device is in correct mode

2. **Authentication failures:**
   - Verify auth key is correct 256-bit hex string
   - Check system time synchronization
   - Ensure nonce is from recent /health call

3. **Policy violations:**
   - Check transaction parameters against policy
   - Verify recipient address is whitelisted
   - Check function selector if sending contract calls

4. **Rate limiting:**
   - Implement exponential backoff in client
   - Reduce request frequency
   - Use circuit breaker pattern

### Debug Mode

Enable verbose logging:
```bash
export DEBUG=esp32-signer:*
node your-script.js
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty. Use at your own risk. The authors are not responsible for any loss of funds or security breaches resulting from the use of this software.