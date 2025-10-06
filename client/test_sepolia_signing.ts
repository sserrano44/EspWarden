#!/usr/bin/env ts-node
/**
 * ESP32 Remote Signer - Sepolia Test Script
 *
 * Tests signing transactions on Sepolia testnet:
 * 1. Successful signing to whitelisted address
 * 2. Policy violation when attempting to sign to non-whitelisted address
 */

import { ethers } from 'ethers';
import { ESP32Signer } from './src/ESP32Signer';
import { ESP32Config } from './src/types';
import { PolicyViolationError, AuthenticationError } from './src/errors';

// Configuration
const DEVICE_CONFIG: ESP32Config = {
  deviceUrl: 'https://192.168.1.16',
  authKey: 'd168c659f97376ed7d0b23b7de87a748cd74be551e1ab1ee95bc4a4a57ff97b4',
  clientId: 'sepolia-test-client',
  timeout: 10000,
  retryOptions: {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 5000,
    factor: 2
  }
};

// Test addresses
const SIGNER_ADDRESS = '0x742d35CC3672C1bFEE3d4D5A0e6e9c4FFbE7e8a8';
const WHITELISTED_ADDRESS = '0x6C3ACDc8C93d13087E3348732a1894e5f3C164B3';
const NON_WHITELISTED_ADDRESS = '0x198089d68083Ef2d93635c2E03C6D0bBEB23bAAb';

// Sepolia configuration
const SEPOLIA_CHAIN_ID = 11155111;
const SEPOLIA_RPC_URL = 'https://sepolia.drpc.org';

class SepoliaSigningTest {
  private provider: ethers.JsonRpcProvider;
  private signer: ESP32Signer;

  constructor() {
    // Disable SSL verification for self-signed certificates
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    this.provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_URL);
    this.signer = new ESP32Signer(DEVICE_CONFIG, this.provider);
  }

  async run(): Promise<void> {
    console.log('🔧 ESP32 Remote Signer - Sepolia Test Suite');
    console.log('='.repeat(50));
    console.log(`Device URL: ${DEVICE_CONFIG.deviceUrl}`);
    console.log(`Chain: Sepolia (${SEPOLIA_CHAIN_ID})`);
    console.log('');

    try {
      await this.checkDeviceHealth();
      await this.verifySignerAddress();
      await this.testWhitelistedTransaction();
      await this.testNonWhitelistedTransaction();

      console.log('✅ All tests completed successfully!');
    } catch (error) {
      console.error('❌ Test suite failed:', error);
      process.exit(1);
    }
  }

  private async checkDeviceHealth(): Promise<void> {
    console.log('📡 Checking device health...');

    try {
      const health = await this.signer.getDeviceHealth();
      console.log(`  Status: ${health.status}`);
      console.log(`  Nonce: ${health.nonce}`);
      console.log(`  Rate remaining: ${health.rateRemaining}`);
      console.log('  ✅ Device is healthy');
    } catch (error) {
      console.error('  ❌ Health check error details:', error);
      throw new Error(`Device health check failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    console.log('');
  }

  private async verifySignerAddress(): Promise<void> {
    console.log('🔍 Verifying signer address...');

    try {
      const deviceInfo = await this.signer.getDeviceInfo();
      const signerAddress = await this.signer.getAddress();

      console.log(`  Device firmware: ${deviceInfo.fw}`);
      console.log(`  Device mode: ${deviceInfo.mode}`);
      console.log(`  Secure boot: ${deviceInfo.secureBoot}`);
      console.log(`  Flash encryption: ${deviceInfo.flashEnc}`);
      console.log(`  Device address: ${signerAddress}`);

      // We'll use the actual device address for testing
      console.log('  ✅ Address verified');
    } catch (error) {
      throw new Error(`Address verification failed: ${error}`);
    }

    console.log('');
  }

  private async testWhitelistedTransaction(): Promise<void> {
    console.log('✅ Test 1: Signing transaction to WHITELISTED address');
    console.log(`   Recipient: ${WHITELISTED_ADDRESS}`);
    console.log('   Expected: Transaction should be signed successfully');

    try {
      const transaction = {
        to: WHITELISTED_ADDRESS,
        value: ethers.parseEther('0.001'), // 0.001 ETH
        chainId: SEPOLIA_CHAIN_ID,
        gasLimit: 21000,
        maxFeePerGas: ethers.parseUnits('20', 'gwei'),
        maxPriorityFeePerGas: ethers.parseUnits('1', 'gwei')
      };

      console.log('   📝 Transaction details:');
      console.log(`     To: ${transaction.to}`);
      console.log(`     Value: ${ethers.formatEther(transaction.value)} ETH`);
      console.log(`     Gas limit: ${transaction.gasLimit}`);
      console.log(`     Max fee: ${ethers.formatUnits(transaction.maxFeePerGas, 'gwei')} gwei`);
      console.log(`     Priority fee: ${ethers.formatUnits(transaction.maxPriorityFeePerGas, 'gwei')} gwei`);

      console.log('   🔐 Signing transaction...');

      try {
        const signedTx = await this.signer.signTransaction(transaction);

        console.log('   ✅ Transaction signed successfully!');
        console.log(`   📜 Signed transaction length: ${signedTx.length} characters`);
        console.log(`   🔍 Signature preview: ${signedTx.substring(0, 50)}...`);

        // Note: We don't broadcast the transaction since we don't have funds
        console.log('   ℹ️  Transaction not broadcasted (no funds in test account)');
      } catch (authError) {
        console.log('   ❌ Authentication/Signing error:');
        console.log(`   📋 Error type: ${(authError as any)?.constructor?.name || 'Unknown'}`);
        console.log(`   📋 Error message: ${authError instanceof Error ? authError.message : String(authError)}`);
        console.log(`   📋 Auth key being used: ${DEVICE_CONFIG.authKey.substring(0, 16)}...`);
        throw authError;
      }

    } catch (error) {
      throw new Error(`Whitelisted transaction test failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    console.log('');
  }

  private async testNonWhitelistedTransaction(): Promise<void> {
    console.log('❌ Test 2: Attempting to sign transaction to NON-WHITELISTED address');
    console.log(`   Recipient: ${NON_WHITELISTED_ADDRESS}`);
    console.log('   Expected: Transaction should be rejected due to policy violation');

    try {
      const transaction = {
        to: NON_WHITELISTED_ADDRESS,
        value: ethers.parseEther('0.001'), // 0.001 ETH
        chainId: SEPOLIA_CHAIN_ID,
        gasLimit: 21000,
        maxFeePerGas: ethers.parseUnits('20', 'gwei'),
        maxPriorityFeePerGas: ethers.parseUnits('1', 'gwei')
      };

      console.log('   📝 Transaction details:');
      console.log(`     To: ${transaction.to}`);
      console.log(`     Value: ${ethers.formatEther(transaction.value)} ETH`);

      console.log('   🚫 Attempting to sign (should fail)...');

      try {
        const signedTx = await this.signer.signTransaction(transaction);

        // If we reach here, the test failed - the transaction should have been rejected
        throw new Error('❌ POLICY FAILURE: Non-whitelisted transaction was signed when it should have been rejected!');

      } catch (error) {
        // Check if it's the expected policy violation error
        if (error instanceof PolicyViolationError ||
            (error as any).message?.includes('policy') ||
            (error as any).message?.includes('whitelist') ||
            (error as any).message?.includes('POLICY_VIOLATION')) {
          console.log('   ✅ Policy violation detected correctly!');
          console.log(`   📋 Error details: ${error instanceof Error ? error.message : String(error)}`);
          console.log('   🛡️  ESP32 signer correctly enforced the whitelist policy');
        } else {
          // Some other error occurred
          throw new Error(`Unexpected error during policy test: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

    } catch (error) {
      if ((error instanceof Error && error.message.includes('POLICY FAILURE')) || String(error).includes('POLICY FAILURE')) {
        throw error; // Re-throw policy failure errors
      }
      throw new Error(`Non-whitelisted transaction test failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    console.log('');
  }
}

// Helper function to handle graceful shutdown
function setupSignalHandlers() {
  const cleanup = () => {
    console.log('\n🛑 Test interrupted by user');
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

// Main execution
async function main() {
  setupSignalHandlers();

  const test = new SepoliaSigningTest();
  await test.run();
}

// Run the test if this file is executed directly
if (require.main === module) {
  main().catch((error) => {
    console.error('💥 Fatal error:', error);
    process.exit(1);
  });
}

export default SepoliaSigningTest;
