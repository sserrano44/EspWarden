import { AbstractSigner, Provider, TransactionRequest, TransactionResponse } from 'ethers';
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
      this._address = info.address;
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
        chainId: populatedTx.chainId || 1,
        nonce: this.toHex(populatedTx.nonce),
        maxFeePerGas: this.toHex(populatedTx.maxFeePerGas),
        maxPriorityFeePerGas: this.toHex(populatedTx.maxPriorityFeePerGas),
        gasLimit: this.toHex(populatedTx.gasLimit),
        to: populatedTx.to || '',
        value: this.toHex(populatedTx.value || 0),
        data: populatedTx.data || '0x'
      };

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
        chainId: populatedTx.chainId || 1,
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
      return '0x' + value.toString(16);
    }

    if (typeof value === 'bigint') {
      return '0x' + value.toString(16);
    }

    if (value && typeof value.toHexString === 'function') {
      return value.toHexString();
    }

    if (value && typeof value.toString === 'function') {
      const str = value.toString();
      if (str.startsWith('0x')) {
        return str;
      }
      return '0x' + parseInt(str).toString(16);
    }

    return '0x0';
  }

  /**
   * Serialize EIP-1559 transaction with signature
   */
  private serializeEIP1559Transaction(tx: EIP1559Transaction, sig: any): string {
    // This is a simplified implementation
    // In a real implementation, you would use RLP encoding
    const fields = [
      tx.chainId,
      tx.nonce,
      tx.maxPriorityFeePerGas,
      tx.maxFeePerGas,
      tx.gasLimit,
      tx.to,
      tx.value,
      tx.data,
      sig.v,
      '0x' + sig.r,
      '0x' + sig.s
    ];

    // Note: This is a placeholder. Real implementation needs proper RLP encoding
    throw new Error('Transaction serialization not implemented - use signature.raw from device');
  }

  /**
   * Serialize EIP-155 transaction with signature
   */
  private serializeEIP155Transaction(tx: EIP155Transaction, sig: any): string {
    // This is a simplified implementation
    // In a real implementation, you would use RLP encoding
    const fields = [
      tx.nonce,
      tx.gasPrice,
      tx.gasLimit,
      tx.to,
      tx.value,
      tx.data,
      sig.v,
      '0x' + sig.r,
      '0x' + sig.s
    ];

    // Note: This is a placeholder. Real implementation needs proper RLP encoding
    throw new Error('Transaction serialization not implemented - use signature.raw from device');
  }
}