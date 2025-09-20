const { ESP32Client } = require('../dist');

async function provisioningExample() {
  console.log('ESP32 Remote Signer - Provisioning Example');
  console.log('==========================================');

  // Create client for provisioning
  const client = new ESP32Client({
    deviceUrl: 'https://192.168.4.1', // Default AP mode IP
    authKey: '0000000000000000000000000000000000000000000000000000000000000000', // Temporary key for initial setup
    clientId: 'provisioning-client'
  });

  try {
    console.log('Step 1: Check device is in provisioning mode...');
    const info = await client.getInfo();

    if (info.mode !== 'provisioning') {
      throw new Error('Device must be in provisioning mode. Check jumper connections.');
    }

    console.log('✅ Device is in provisioning mode');

    console.log('\nStep 2: Configure WiFi...');
    await client.configureWiFi({
      ssid: 'YourWiFiNetwork',      // Replace with your WiFi SSID
      psk: 'your-wifi-password'     // Replace with your WiFi password
    });
    console.log('✅ WiFi configured');

    console.log('\nStep 3: Set authentication password...');
    await client.configureAuth({
      password: 'your-strong-provisioning-password' // Replace with a strong password
    });
    console.log('✅ Authentication configured');

    console.log('\nStep 4: Generate private key...');
    await client.configureKey({
      mode: 'generate' // Use 'import' to import existing key
    });
    console.log('✅ Private key generated');

    console.log('\nStep 5: Configure transaction policy...');
    await client.configurePolicy({
      allowedChains: [1, 10, 8453], // Ethereum, Optimism, Base
      toWhitelist: [
        '0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8', // Replace with your addresses
        '0xA0b86a33E6417C7Ef6D7680B2d5df2aC4d5a6E1B'
      ],
      functionWhitelist: [
        '0xa9059cbb', // transfer(address,uint256)
        '0x095ea7b3', // approve(address,uint256)
        '0x23b872dd'  // transferFrom(address,address,uint256)
      ],
      maxValueWei: '0x16345785d8a0000', // 0.1 ETH
      maxGasLimit: 200000,
      maxFeePerGasWei: '0x2540be400', // 10 gwei
      allowEmptyDataToWhitelist: true
    });
    console.log('✅ Policy configured');

    console.log('\n🎉 Provisioning complete!');
    console.log('\nNext steps:');
    console.log('1. Remove the provisioning jumper (disconnect GPIO 2 & 4 from GND)');
    console.log('2. Restart the device');
    console.log('3. Device will boot into signing mode');
    console.log('4. Update your auth key to the one derived from your password');
    console.log('5. Use the device IP address from your WiFi network');

  } catch (error) {
    console.error('❌ Provisioning failed:', error.message);

    if (error.code) {
      console.error('Error Code:', error.code);
    }

    if (error.reason) {
      console.error('Reason:', error.reason);
    }

    console.log('\nTroubleshooting:');
    console.log('- Ensure the provisioning jumper is connected (GPIO 2 & 4 to GND)');
    console.log('- Check that the device is powered on and reachable');
    console.log('- Verify the device URL is correct');
  }
}

// Run the provisioning example
provisioningExample()
  .then(() => console.log('\nProvisioning example completed.'))
  .catch(console.error);