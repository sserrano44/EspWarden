const { ESP32Signer } = require('../dist');
const { JsonRpcProvider, parseEther, Contract } = require('ethers');

// ERC-20 ABI for token transfers
const ERC20_ABI = [
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)'
];

class TradingBot {
  constructor(config) {
    this.provider = new JsonRpcProvider(config.rpcUrl);
    this.signer = new ESP32Signer({
      deviceUrl: config.deviceUrl,
      authKey: config.authKey,
      clientId: config.clientId || 'trading-bot'
    }, this.provider);

    this.config = config;
  }

  async initialize() {
    console.log('Initializing trading bot...');

    // Get device info
    const info = await this.signer.getDeviceInfo();
    console.log('Device Info:', {
      address: info.address,
      mode: info.mode,
      firmware: info.fw
    });

    if (info.mode !== 'signing') {
      throw new Error('Device must be in signing mode for trading');
    }

    this.address = await this.signer.getAddress();
    console.log('Bot Address:', this.address);

    // Check ETH balance
    const balance = await this.provider.getBalance(this.address);
    console.log('ETH Balance:', balance.toString(), 'wei');

    return this.address;
  }

  async transferETH(to, amount) {
    console.log(`\nTransferring ${amount} ETH to ${to}...`);

    try {
      const tx = await this.signer.sendTransaction({
        to: to,
        value: parseEther(amount),
        gasLimit: 21000
      });

      console.log('Transaction sent:', tx.hash);
      console.log('Waiting for confirmation...');

      const receipt = await tx.wait();
      console.log('✅ Transfer confirmed in block:', receipt.blockNumber);

      return receipt;
    } catch (error) {
      console.error('❌ Transfer failed:', error.message);
      throw error;
    }
  }

  async transferToken(tokenAddress, to, amount) {
    console.log(`\nTransferring ${amount} tokens to ${to}...`);

    try {
      const tokenContract = new Contract(tokenAddress, ERC20_ABI, this.signer);

      // Get token decimals
      const decimals = await tokenContract.decimals();
      const tokenAmount = parseEther(amount); // Assuming 18 decimals

      const tx = await tokenContract.transfer(to, tokenAmount);
      console.log('Transaction sent:', tx.hash);

      const receipt = await tx.wait();
      console.log('✅ Token transfer confirmed in block:', receipt.blockNumber);

      return receipt;
    } catch (error) {
      console.error('❌ Token transfer failed:', error.message);
      throw error;
    }
  }

  async getDeviceHealth() {
    const health = await this.signer.getDeviceHealth();
    console.log('Device Health:', {
      status: health.status,
      rateRemaining: health.rateRemaining
    });
    return health;
  }

  async executeStrategy() {
    console.log('\n🤖 Executing trading strategy...');

    try {
      // Example strategy: Transfer small amounts to whitelisted addresses
      const recipients = [
        '0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8',
        '0xA0b86a33E6417C7Ef6D7680B2d5df2aC4d5a6E1B'
      ];

      for (const recipient of recipients) {
        // Check device health before each transaction
        await this.getDeviceHealth();

        // Execute transfer (small amount for demo)
        await this.transferETH(recipient, '0.001');

        // Wait between transactions to respect rate limits
        await this.sleep(10000); // 10 seconds
      }

      console.log('✅ Strategy execution complete');
    } catch (error) {
      console.error('❌ Strategy execution failed:', error.message);

      // Handle different error types
      if (error.name === 'PolicyViolationError') {
        console.error('Policy violation - check whitelist and limits');
      } else if (error.name === 'RateLimitError') {
        console.error('Rate limit exceeded - implementing backoff');
        await this.sleep(60000); // Wait 1 minute
      } else if (error.name === 'AuthenticationError') {
        console.error('Authentication failed - clearing session');
        this.signer.clearSession();
      }

      throw error;
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

async function tradingBotExample() {
  console.log('ESP32 Remote Signer - Trading Bot Example');
  console.log('=========================================');

  const bot = new TradingBot({
    rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY', // Replace with your RPC
    deviceUrl: 'https://192.168.1.100', // Replace with your device IP
    authKey: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', // Replace with your auth key
    clientId: 'trading-bot-example'
  });

  try {
    await bot.initialize();

    // For demonstration, we'll just show the capabilities
    // Uncomment the next line to actually execute trades
    // await bot.executeStrategy();

    console.log('\n✅ Trading bot example completed successfully');
    console.log('Note: No actual transactions were sent (demo mode)');

  } catch (error) {
    console.error('❌ Trading bot failed:', error.message);
  }
}

// Run the trading bot example
tradingBotExample()
  .then(() => console.log('\nTrading bot example completed.'))
  .catch(console.error);