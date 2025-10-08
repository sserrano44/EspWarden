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
  deviceUrl: 'https://192.168.1.54',
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

// Test addresses (signer address will be retrieved from device)
const WHITELISTED_ADDRESS = '0x6C3ACDc8C93d13087E3348732a1894e5f3C164B3';
const NON_WHITELISTED_ADDRESS = '0x198089d68083Ef2d93635c2E03C6D0bBEB23bAAb';

// Sepolia configuration
const SEPOLIA_CHAIN_ID = 11155111;
const SEPOLIA_RPC_URL = 'https://sepolia.drpc.org';

class SepoliaSigningTest {
  private provider: ethers.JsonRpcProvider;
  private signer: ESP32Signer;
  private shouldBroadcast: boolean;
  private deviceAddress?: string;

  constructor(shouldBroadcast: boolean = false) {
    // Disable SSL verification for self-signed certificates
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    this.provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_URL);
    this.signer = new ESP32Signer(DEVICE_CONFIG, this.provider);
    this.shouldBroadcast = shouldBroadcast;
  }

  async run(): Promise<void> {
    console.log('🔧 ESP32 Remote Signer - Sepolia Test Suite');
    console.log('='.repeat(50));
    console.log(`Device URL: ${DEVICE_CONFIG.deviceUrl}`);
    console.log(`Chain: Sepolia (${SEPOLIA_CHAIN_ID})`);
    console.log(`Broadcast mode: ${this.shouldBroadcast ? 'ENABLED' : 'DISABLED'}`);
    console.log('');

    try {
      await this.checkDeviceHealth();
      await this.verifySignerAddress();

      if (this.shouldBroadcast) {
        await this.checkBalance();
      }

      const signedTx = await this.testWhitelistedTransaction();

      if (this.shouldBroadcast && signedTx) {
        await this.broadcastTransaction(signedTx);
      }

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

      if (health.signingAddress) {
        console.log(`  🔑 Signing address: ${health.signingAddress}`);
      } else {
        console.log('  ⚠️  Signing address not available');
      }

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

      // Store the device address for use in balance checks
      this.deviceAddress = signerAddress;

      console.log('  ✅ Address verified');
    } catch (error) {
      throw new Error(`Address verification failed: ${error}`);
    }

    console.log('');
  }

  private async checkBalance(): Promise<void> {
    console.log('💰 Checking account balance...');

    try {
      // Use the device address we verified earlier
      const deviceAddress = this.deviceAddress || await this.signer.getAddress();
      const health = await this.signer.getDeviceHealth();
      const signingAddress = health.signingAddress || deviceAddress;

      console.log(`  📋 Address being used for balance check: ${signingAddress}`);

      // Check balance for the signing address
      const balance = await this.provider.getBalance(signingAddress, 'latest');
      const balanceEth = ethers.formatEther(balance);

      console.log(`  Balance: ${balanceEth} ETH`);
      console.log(`  Balance (wei): ${balance.toString()}`);

      const estimatedTxCost = ethers.parseEther('0.001') + (21000n * ethers.parseUnits('20', 'gwei'));
      const estimatedCostEth = ethers.formatEther(estimatedTxCost);

      console.log(`  Estimated tx cost: ${estimatedCostEth} ETH`);

      if (balance === 0n) {
        console.log('  ⚠️  WARNING: Signing address has no ETH - transaction will fail!');
        console.log(`  💡 Send testnet ETH to: ${signingAddress}`);
        console.log('  💡 Get testnet ETH from: https://sepoliafaucet.com/');
        throw new Error('Insufficient balance for broadcasting transaction');
      } else if (balance < estimatedTxCost) {
        console.log(`  ⚠️  WARNING: Insufficient balance for transaction! Need at least ${estimatedCostEth} ETH`);
        console.log(`  💡 Send more testnet ETH to: ${signingAddress}`);
        console.log('  💡 Get testnet ETH from: https://sepoliafaucet.com/');
        throw new Error(`Insufficient balance: have ${balanceEth} ETH, need ${estimatedCostEth} ETH`);
      } else {
        console.log('  ✅ Sufficient balance for transaction');
      }
    } catch (error) {
      throw new Error(`Balance check failed: ${error}`);
    }

    console.log('');
  }

  private async broadcastTransaction(signedTx: string): Promise<void> {
    console.log('📡 Broadcasting transaction to Sepolia network...');

    try {
      // Parse the transaction to show details before broadcasting
      const parsedTx = ethers.Transaction.from(signedTx);
      const gasEstimate = parsedTx.gasLimit * (parsedTx.maxFeePerGas || parsedTx.gasPrice || 0n);
      const totalCost = (parsedTx.value || 0n) + gasEstimate;

      console.log('  📋 Transaction details:');
      console.log(`     To: ${parsedTx.to}`);
      console.log(`     Value: ${ethers.formatEther(parsedTx.value || 0)} ETH`);
      console.log(`     Gas limit: ${parsedTx.gasLimit}`);
      console.log(`     Max fee: ${ethers.formatUnits(parsedTx.maxFeePerGas || 0, 'gwei')} gwei`);
      console.log(`     Gas cost: ${ethers.formatEther(gasEstimate)} ETH`);
      console.log(`     Total cost: ${ethers.formatEther(totalCost)} ETH`);
      console.log('');

      // Final balance check before broadcasting
      console.log('  🔍 Final balance verification...');
      const signerAddress = this.deviceAddress || await this.signer.getAddress();
      const currentBalance = await this.provider.getBalance(signerAddress, 'latest');

      console.log(`     Current balance: ${ethers.formatEther(currentBalance)} ETH`);
      console.log(`     Required amount: ${ethers.formatEther(totalCost)} ETH`);

      if (currentBalance < totalCost) {
        const shortfall = totalCost - currentBalance;
        console.log(`  ❌ Insufficient balance! Short by ${ethers.formatEther(shortfall)} ETH`);
        throw new Error(`Insufficient funds: need ${ethers.formatEther(totalCost)} ETH, have ${ethers.formatEther(currentBalance)} ETH`);
      }

      // Broadcast the transaction
      console.log('  🚀 Sending transaction...');
      const txResponse = await this.provider.broadcastTransaction(signedTx);

      console.log('  ✅ Transaction broadcast successfully!');
      console.log(`  📋 Transaction hash: ${txResponse.hash}`);
      console.log(`  🔗 Etherscan link: https://sepolia.etherscan.io/tx/${txResponse.hash}`);
      console.log('');

      // Wait for confirmation
      console.log('  ⏳ Waiting for confirmation...');
      const receipt = await txResponse.wait(1);

      if (receipt) {
        console.log('  ✅ Transaction confirmed!');
        console.log(`  📋 Block number: ${receipt.blockNumber}`);
        console.log(`  ⛽ Gas used: ${receipt.gasUsed}`);
        console.log(`  💰 Gas price: ${ethers.formatUnits(receipt.gasPrice || 0, 'gwei')} gwei`);
        console.log(`  💸 Total cost: ${ethers.formatEther((receipt.gasUsed * (receipt.gasPrice || 0n)))} ETH`);
      } else {
        console.log('  ⚠️  Transaction confirmed but receipt not available');
      }

    } catch (error) {
      console.error('  ❌ Broadcast failed:', error);
      throw new Error(`Transaction broadcast failed: ${error instanceof Error ? error.message : String(error)}`);
    }

    console.log('');
  }

  private async testWhitelistedTransaction(): Promise<string | null> {
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

      // Get the current nonce from the network
      const signerAddress = this.deviceAddress || await this.signer.getAddress();
      const networkNonce = await this.provider.getTransactionCount(signerAddress, 'latest');
      console.log(`   📋 Network nonce for ${signerAddress}: ${networkNonce}`);

      // Update transaction with correct nonce
      const transactionWithNonce = {
        ...transaction,
        nonce: networkNonce
      };

      console.log('   📋 Transaction being signed:');
      console.log(`     Nonce: ${transactionWithNonce.nonce}`);
      console.log(`     ChainId: ${transactionWithNonce.chainId}`);

      try {
        const signedTx = await this.signer.signTransaction(transactionWithNonce);

        console.log('   ✅ Transaction signed successfully!');
        console.log(`   📜 Signed transaction length: ${signedTx.length} characters`);
        console.log(`   🔍 Signature preview: ${signedTx.substring(0, 50)}...`);

        // Parse and verify the signed transaction
        const parsedSignedTx = ethers.Transaction.from(signedTx);
        console.log('   🔍 Parsed signed transaction:');
        console.log(`     Nonce: ${parsedSignedTx.nonce}`);
        console.log(`     To: ${parsedSignedTx.to}`);
        console.log(`     Value: ${ethers.formatEther(parsedSignedTx.value || 0)} ETH`);
        console.log(`     Gas Limit: ${parsedSignedTx.gasLimit}`);
        console.log(`     Max Fee: ${ethers.formatUnits(parsedSignedTx.maxFeePerGas || 0, 'gwei')} gwei`);
        console.log(`     Chain ID: ${parsedSignedTx.chainId}`);
        console.log(`     From: ${parsedSignedTx.from}`);
        console.log(`     Signature v: ${parsedSignedTx.signature?.v}`);
        console.log(`     Signature r: ${parsedSignedTx.signature?.r}`);
        console.log(`     Signature s: ${parsedSignedTx.signature?.s}`);

        if (!this.shouldBroadcast) {
          console.log('   📋 Full signed transaction:');
          console.log(`   ${signedTx}`);
          console.log('   ℹ️  To broadcast manually, use: await provider.broadcastTransaction("' + signedTx + '")');
        }

        return signedTx;
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
    return null;
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

// Parse command line arguments
function parseArguments() {
  const args = process.argv.slice(2);
  const shouldBroadcast = args.includes('--broadcast');

  if (shouldBroadcast) {
    console.log('⚠️  BROADCAST MODE ENABLED - This will send real transactions to Sepolia!');
    console.log('💰 Make sure your account has testnet ETH from https://sepoliafaucet.com/');
    console.log('');
  }

  return { shouldBroadcast };
}

// Main execution
async function main() {
  setupSignalHandlers();

  const { shouldBroadcast } = parseArguments();
  const test = new SepoliaSigningTest(shouldBroadcast);
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
