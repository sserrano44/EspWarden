import fetch from 'node-fetch';
import { AuthManager } from './AuthManager';
import { RetryManager } from './RetryManager';
import { ConfigManager } from './ConfigManager';
import {
  ESP32Config,
  DeviceInfo,
  HealthResponse,
  UnlockResponse,
  SignatureResponse,
  EIP1559Transaction,
  EIP155Transaction,
  PolicyConfig,
  WiFiCredentials,
  AuthConfig,
  KeyConfig
} from './types';
import {
  ESP32SignerError,
  AuthenticationError,
  PolicyViolationError,
  RateLimitError,
  NetworkError,
  DeviceModeError
} from './errors';

export class ESP32Client {
  private configManager: ConfigManager;
  private authManager: AuthManager;
  private retryManager: RetryManager;
  private rateLimiter: Map<string, number[]> = new Map();

  constructor(config: Partial<ESP32Config>) {
    this.configManager = new ConfigManager(config);
    this.authManager = new AuthManager(
      this.configManager.getAuthKey(),
      this.configManager.getClientId()
    );
    this.retryManager = new RetryManager(this.configManager.getRetryOptions());
  }

  /**
   * Make authenticated HTTP request to device
   */
  private async makeRequest<T>(
    method: string,
    path: string,
    body?: any,
    requiresAuth: boolean = false
  ): Promise<T> {
    await this.checkRateLimit();

    const url = `${this.configManager.getDeviceUrl()}${path}`;
    const bodyString = body ? JSON.stringify(body) : '';

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'ESP32RemoteSignerClient/1.0.0'
    };

    // Add authentication if required
    if (requiresAuth) {
      const token = this.authManager.getToken();
      if (!token) {
        throw new AuthenticationError('No valid session token available');
      }
      headers['Authorization'] = `Bearer ${token}`;
    }

    return this.retryManager.executeWithRetry(async () => {
      const response = await fetch(url, {
        method,
        headers,
        body: bodyString || undefined,
        timeout: this.configManager.getTimeout(),
        // Disable SSL verification for self-signed certificates
        agent: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? undefined : undefined
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw this.createErrorFromResponse(response.status, errorData);
      }

      return response.json() as T;
    }, `${method} ${path}`);
  }

  /**
   * Create appropriate error from response
   */
  private createErrorFromResponse(status: number, errorData: any): Error {
    const message = errorData.message || 'Unknown error';
    const code = errorData.code || 'UNKNOWN_ERROR';
    const reason = errorData.reason;

    switch (status) {
      case 401:
        return new AuthenticationError(message, reason);
      case 403:
        if (code.includes('POLICY')) {
          return new PolicyViolationError(message, reason);
        }
        return new DeviceModeError(message, reason);
      case 429:
        return new RateLimitError(message, reason);
      default:
        return new ESP32SignerError(message, code, reason, status);
    }
  }

  /**
   * Check rate limiting
   */
  private async checkRateLimit(): Promise<void> {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const options = this.configManager.getRateLimitOptions();

    const clientId = this.configManager.getClientId();
    const requests = this.rateLimiter.get(clientId) || [];

    // Remove old requests outside the window
    const recentRequests = requests.filter(time => now - time < windowMs);

    if (recentRequests.length >= options.requestsPerMinute) {
      const oldestRequest = recentRequests[0];
      const waitTime = windowMs - (now - oldestRequest);
      throw new RateLimitError(`Rate limit exceeded. Wait ${Math.ceil(waitTime / 1000)} seconds.`);
    }

    recentRequests.push(now);
    this.rateLimiter.set(clientId, recentRequests);
  }

  /**
   * Get device health status
   */
  async getHealth(): Promise<HealthResponse> {
    return this.makeRequest<HealthResponse>('GET', '/health');
  }

  /**
   * Get device information
   */
  async getInfo(): Promise<DeviceInfo> {
    return this.makeRequest<DeviceInfo>('GET', '/info');
  }

  /**
   * Unlock device and get session token
   */
  async unlock(): Promise<UnlockResponse> {
    // Get nonce from health endpoint
    const health = await this.getHealth();
    const unlockRequest = this.authManager.generateUnlockRequest(health.nonce);

    const response = await this.makeRequest<UnlockResponse>('POST', '/unlock', unlockRequest);

    // Store the token
    this.authManager.setToken(response.token, response.ttl);

    return response;
  }

  /**
   * Ensure we have a valid session token
   */
  private async ensureAuthenticated(): Promise<void> {
    if (this.authManager.isTokenExpired()) {
      await this.unlock();
    }
  }

  /**
   * Sign EIP-1559 transaction
   */
  async signEIP1559(transaction: EIP1559Transaction): Promise<SignatureResponse> {
    await this.ensureAuthenticated();

    ConfigManager.validateTransactionParams(transaction);

    const payload = {
      token: this.authManager.getToken(),
      tx: transaction
    };

    return this.makeRequest<SignatureResponse>('POST', '/sign/eip1559', payload, true);
  }

  /**
   * Sign EIP-155 transaction
   */
  async signEIP155(transaction: EIP155Transaction): Promise<SignatureResponse> {
    await this.ensureAuthenticated();

    ConfigManager.validateTransactionParams(transaction);

    if (!transaction.gasPrice || !/^0x[0-9a-fA-F]+$/.test(transaction.gasPrice)) {
      throw new Error('gasPrice must be a hex string');
    }

    const payload = {
      token: this.authManager.getToken(),
      tx: transaction
    };

    return this.makeRequest<SignatureResponse>('POST', '/sign/eip155', payload, true);
  }

  /**
   * Configure WiFi (provisioning mode only)
   */
  async configureWiFi(credentials: WiFiCredentials): Promise<{ success: boolean }> {
    return this.makeRequest('POST', '/wifi', credentials);
  }

  /**
   * Configure authentication (provisioning mode only)
   */
  async configureAuth(authConfig: AuthConfig): Promise<{ success: boolean }> {
    return this.makeRequest('POST', '/auth', authConfig);
  }

  /**
   * Configure private key (provisioning mode only)
   */
  async configureKey(keyConfig: KeyConfig): Promise<{ success: boolean }> {
    return this.makeRequest('POST', '/key', keyConfig);
  }

  /**
   * Configure policy (provisioning mode only)
   */
  async configurePolicy(policy: PolicyConfig): Promise<{ success: boolean }> {
    return this.makeRequest('POST', '/policy', policy);
  }

  /**
   * Wipe device (provisioning mode only)
   */
  async wipe(): Promise<{ success: boolean }> {
    await this.ensureAuthenticated();
    return this.makeRequest('POST', '/wipe', {}, true);
  }

  /**
   * Clear stored session token
   */
  clearSession(): void {
    this.authManager.clearToken();
  }
}