import { ESP32Config, RetryOptions, RateLimitOptions } from './types';
import { ValidationError } from './errors';

export class ConfigManager {
  private config: ESP32Config;

  constructor(config: Partial<ESP32Config>) {
    this.config = this.validateAndSetDefaults(config);
  }

  private validateAndSetDefaults(config: Partial<ESP32Config>): ESP32Config {
    if (!config.deviceUrl) {
      throw new ValidationError('deviceUrl is required');
    }

    if (!config.authKey) {
      throw new ValidationError('authKey is required');
    }

    if (!config.clientId) {
      throw new ValidationError('clientId is required');
    }

    // Validate device URL format
    try {
      const url = new URL(config.deviceUrl);
      if (!['https:', 'http:'].includes(url.protocol)) {
        throw new ValidationError('deviceUrl must use http or https protocol');
      }
    } catch (error) {
      throw new ValidationError('Invalid deviceUrl format');
    }

    // Validate auth key format (should be hex string)
    if (!/^[0-9a-fA-F]{64}$/.test(config.authKey)) {
      throw new ValidationError('authKey must be a 64-character hex string (256 bits)');
    }

    return {
      deviceUrl: config.deviceUrl,
      authKey: config.authKey,
      clientId: config.clientId,
      timeout: config.timeout ?? 30000,
      retryOptions: {
        maxRetries: config.retryOptions?.maxRetries ?? 3,
        baseDelay: config.retryOptions?.baseDelay ?? 1000,
        maxDelay: config.retryOptions?.maxDelay ?? 30000,
        factor: config.retryOptions?.factor ?? 2
      },
      rateLimitOptions: {
        requestsPerMinute: config.rateLimitOptions?.requestsPerMinute ?? 10,
        burstSize: config.rateLimitOptions?.burstSize ?? 5
      }
    };
  }

  getConfig(): ESP32Config {
    return { ...this.config };
  }

  getDeviceUrl(): string {
    return this.config.deviceUrl;
  }

  getAuthKey(): string {
    return this.config.authKey;
  }

  getClientId(): string {
    return this.config.clientId;
  }

  getTimeout(): number {
    return this.config.timeout!;
  }

  getRetryOptions(): RetryOptions {
    return { ...this.config.retryOptions! };
  }

  getRateLimitOptions(): RateLimitOptions {
    return { ...this.config.rateLimitOptions! };
  }

  /**
   * Update configuration (useful for runtime changes)
   */
  updateConfig(updates: Partial<ESP32Config>): void {
    const newConfig = { ...this.config, ...updates };
    this.config = this.validateAndSetDefaults(newConfig);
  }

  /**
   * Create configuration from environment variables
   */
  static fromEnvironment(): ConfigManager {
    const config: Partial<ESP32Config> = {
      deviceUrl: process.env.ESP32_DEVICE_URL,
      authKey: process.env.ESP32_AUTH_KEY,
      clientId: process.env.ESP32_CLIENT_ID || 'nodejs-client',
      timeout: process.env.ESP32_TIMEOUT ? parseInt(process.env.ESP32_TIMEOUT) : undefined
    };

    return new ConfigManager(config);
  }

  /**
   * Validate transaction parameters
   */
  static validateTransactionParams(params: any): void {
    if (!params.chainId || typeof params.chainId !== 'number') {
      throw new ValidationError('chainId must be a number');
    }

    if (!params.to || typeof params.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(params.to)) {
      throw new ValidationError('to must be a valid Ethereum address');
    }

    if (!params.value || typeof params.value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(params.value)) {
      throw new ValidationError('value must be a hex string');
    }

    if (!params.data || typeof params.data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(params.data)) {
      throw new ValidationError('data must be a hex string');
    }

    if (!params.nonce || typeof params.nonce !== 'string' || !/^0x[0-9a-fA-F]+$/.test(params.nonce)) {
      throw new ValidationError('nonce must be a hex string');
    }

    if (!params.gasLimit || typeof params.gasLimit !== 'string' || !/^0x[0-9a-fA-F]+$/.test(params.gasLimit)) {
      throw new ValidationError('gasLimit must be a hex string');
    }
  }
}