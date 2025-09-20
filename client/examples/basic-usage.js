const { ESP32Signer } = require('../dist');
const { JsonRpcProvider, parseEther } = require('ethers');

async function basicUsageExample() {
  console.log('ESP32 Remote Signer - Basic Usage Example');
  console.log('==========================================');

  // Create provider (replace with your RPC endpoint)
  const provider = new JsonRpcProvider('https://mainnet.infura.io/v3/YOUR_KEY');

  // Create ESP32 signer
  const signer = new ESP32Signer({
    deviceUrl: 'https://192.168.1.100', // Replace with your device IP
    authKey: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', // Replace with your auth key
    clientId: 'example-client'
  }, provider);

  try {
    // Get device info
    console.log('Getting device information...');
    const info = await signer.getDeviceInfo();
    console.log('Device Info:', {
      firmware: info.fw,
      address: info.address,
      mode: info.mode,
      secureBoot: info.secureBoot,
      flashEncryption: info.flashEnc
    });

    // Check device health
    console.log('\nChecking device health...');
    const health = await signer.getDeviceHealth();
    console.log('Device Health:', {
      status: health.status,
      rateRemaining: health.rateRemaining
    });

    // Get signer address
    console.log('\nGetting signer address...');
    const address = await signer.getAddress();
    console.log('Signer Address:', address);

    // Create a simple transaction
    console.log('\nPreparing transaction...');
    const transaction = {
      to: '0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8',
      value: parseEther('0.01'),
      gasLimit: 21000,
      data: '0x'
    };

    // Sign the transaction (but don't send it)
    console.log('\nSigning transaction...');
    const signedTx = await signer.signTransaction(transaction);
    console.log('Signed Transaction:', signedTx);

    // For demonstration, we won't actually send the transaction
    console.log('\n✅ Transaction signed successfully!');
    console.log('Note: Transaction was not sent to the network.');

  } catch (error) {
    console.error('❌ Error:', error.message);

    if (error.code) {
      console.error('Error Code:', error.code);
    }

    if (error.reason) {
      console.error('Reason:', error.reason);
    }
  }
}

// Run the example
basicUsageExample()
  .then(() => console.log('\nExample completed.'))
  .catch(console.error);