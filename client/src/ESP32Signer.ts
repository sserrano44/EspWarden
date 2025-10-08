import { AbstractSigner, Provider, TransactionRequest, TransactionResponse, Transaction } from 'ethers';
import { ESP32Client } from './ESP32Client';
import { ESP32Config, EIP1559Transaction, EIP155Transaction } from './types';
import { ValidationError } from './errors';

export class ESP32Signer extends AbstractSigner {
  private client: ESP32Client;
  private _address?: string;

  constructor(config: Partial<ESP32Config>, provider?: Provider) {
    super(provider);
    this.client = new ESP32Client(config);
  }

  /**
   * Get the Ethereum address for this signer
   */
  async getAddress(): Promise<string> {
    if (!this._address) {
      const info = await this.client.getInfo();
      // Normalize the address to handle checksum differences
      this._address = info.address.toLowerCase();
    }
    return this._address;
  }

  /**
   * Sign a transaction
   */
  async signTransaction(transaction: TransactionRequest): Promise<string> {
    // Populate transaction if provider is available
    const populatedTx = await this.populateTransaction(transaction);

    // Convert to the format expected by ESP32
    if (populatedTx.maxFeePerGas && populatedTx.maxPriorityFeePerGas) {
      // EIP-1559 transaction
      const eip1559Tx: EIP1559Transaction = {
        chainId: Number(populatedTx.chainId) || 1,
        nonce: this.toHex(populatedTx.nonce),
        maxFeePerGas: this.toHex(populatedTx.maxFeePerGas),
        maxPriorityFeePerGas: this.toHex(populatedTx.maxPriorityFeePerGas),
        gasLimit: this.toHex(populatedTx.gasLimit),
        to: populatedTx.to || '',
        value: this.toHex(populatedTx.value || 0),
        data: populatedTx.data || '0x'
      };

      // Debug: Create an unsigned transaction to compute the expected hash
      const unsignedTx = {
        type: 2,
        chainId: eip1559Tx.chainId,
        nonce: parseInt(eip1559Tx.nonce),
        maxFeePerGas: eip1559Tx.maxFeePerGas,
        maxPriorityFeePerGas: eip1559Tx.maxPriorityFeePerGas,
        gasLimit: eip1559Tx.gasLimit,
        to: eip1559Tx.to,
        value: eip1559Tx.value,
        data: eip1559Tx.data,
        accessList: []
      };

      const ethersUnsigned = Transaction.from(unsignedTx);
      const expectedHash = ethersUnsigned.unsignedHash;
      console.log('DEBUG: Expected transaction hash (ethers):', expectedHash);

      // Get the raw unsigned serialized data that ethers uses for hashing
      const ethersUnsignedSerialized = ethersUnsigned.unsignedSerialized;
      console.log('DEBUG: Ethers unsigned serialized:', ethersUnsignedSerialized);

      const signature = await this.client.signEIP1559(eip1559Tx);

      // Return the raw serialized transaction if available
      if (signature.raw) {
        return signature.raw;
      }

      // Otherwise, construct the serialized transaction
      return this.serializeEIP1559Transaction(eip1559Tx, signature);
    } else {
      // Legacy EIP-155 transaction
      const eip155Tx: EIP155Transaction = {
        chainId: Number(populatedTx.chainId) || 1,
        nonce: this.toHex(populatedTx.nonce),
        gasPrice: this.toHex(populatedTx.gasPrice),
        gasLimit: this.toHex(populatedTx.gasLimit),
        to: populatedTx.to || '',
        value: this.toHex(populatedTx.value || 0),
        data: populatedTx.data || '0x'
      };

      const signature = await this.client.signEIP155(eip155Tx);

      // Return the raw serialized transaction if available
      if (signature.raw) {
        return signature.raw;
      }

      // Otherwise, construct the serialized transaction
      return this.serializeEIP155Transaction(eip155Tx, signature);
    }
  }

  /**
   * Sign a message (not supported by hardware signer)
   */
  async signMessage(message: string | Uint8Array): Promise<string> {
    throw new Error('Message signing not supported by ESP32 Remote Signer');
  }

  /**
   * Sign typed data (not supported by hardware signer)
   */
  async signTypedData(
    domain: any,
    types: Record<string, any[]>,
    value: Record<string, any>
  ): Promise<string> {
    throw new Error('Typed data signing not supported by ESP32 Remote Signer');
  }

  /**
   * Connect to a provider
   */
  connect(provider: Provider): ESP32Signer {
    return new ESP32Signer(this.client.getConfig(), provider);
  }

  /**
   * Get device information
   */
  async getDeviceInfo() {
    return this.client.getInfo();
  }

  /**
   * Check device health
   */
  async getDeviceHealth() {
    return this.client.getHealth();
  }

  /**
   * Clear stored session
   */
  clearSession(): void {
    this.client.clearSession();
  }

  /**
   * Get ESP32 client for advanced operations
   */
  getClient(): ESP32Client {
    return this.client;
  }

  /**
   * Helper to convert values to hex strings
   */
  private toHex(value: any): string {
    if (typeof value === 'string' && value.startsWith('0x')) {
      return value;
    }

    if (typeof value === 'number') {
      const hex = value.toString(16);
      return '0x' + (hex.length % 2 ? '0' + hex : hex);
    }

    if (typeof value === 'bigint') {
      const hex = value.toString(16);
      return '0x' + (hex.length % 2 ? '0' + hex : hex);
    }

    if (value && typeof value.toHexString === 'function') {
      return value.toHexString();
    }

    if (value && typeof value.toString === 'function') {
      const str = value.toString();
      if (str.startsWith('0x')) {
        return str;
      }
      const hex = parseInt(str).toString(16);
      return '0x' + (hex.length % 2 ? '0' + hex : hex);
    }

    return '0x0';
  }

  /**
   * Serialize EIP-1559 transaction with signature
   */
  private serializeEIP1559Transaction(tx: EIP1559Transaction, sig: any): string {
    // For EIP-1559 transactions, we need to use yParity instead of v
    // The ESP32 returns v as 0 or 1 (the recovery ID) which is correct for yParity
    const completeTx = {
      type: 2, // EIP-1559
      chainId: tx.chainId,
      nonce: parseInt(tx.nonce),
      maxFeePerGas: tx.maxFeePerGas,
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
      gasLimit: tx.gasLimit,
      to: tx.to,
      value: tx.value,
      data: tx.data,
      accessList: [],
      signature: {
        r: '0x' + sig.r,
        s: '0x' + sig.s,
        yParity: sig.v  // ESP32 returns 0 or 1, use directly as yParity
      }
    };

    // Use ethers to serialize the transaction
    return Transaction.from(completeTx).serialized;
  }

  /**
   * Serialize EIP-155 transaction with signature
   */
  private serializeEIP155Transaction(tx: EIP155Transaction, sig: any): string {
    // For EIP-155, the ESP32 returns v = chainId * 2 + 35 + recovery_id
    // This is the correct v value for legacy transactions
    const completeTx = {
      type: 0, // Legacy transaction
      chainId: tx.chainId,
      nonce: parseInt(tx.nonce),
      gasPrice: tx.gasPrice,
      gasLimit: tx.gasLimit,
      to: tx.to,
      value: tx.value,
      data: tx.data,
      signature: {
        r: '0x' + sig.r,
        s: '0x' + sig.s,
        v: sig.v  // ESP32 returns correct EIP-155 v value
      }
    };

    // Use ethers to serialize the transaction
    return Transaction.from(completeTx).serialized;
  }
}