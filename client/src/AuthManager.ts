import CryptoJS from 'crypto-js';
import { AuthenticationError } from './errors';

export class AuthManager {
  private authKey: string;
  private clientId: string;
  private currentToken?: string;
  private tokenExpiry?: number;

  constructor(authKey: string, clientId: string) {
    this.authKey = authKey;
    this.clientId = clientId;
  }

  /**
   * Generate HMAC for challenge-response authentication
   * HMAC(auth_key, nonce || method || path || body)
   */
  generateHMAC(nonce: string, method: string, path: string, body: string = ''): string {
    const message = nonce + method + path + body;

    // Convert hex key to WordArray for proper HMAC calculation
    const keyWordArray = CryptoJS.enc.Hex.parse(this.authKey);
    const hmac = CryptoJS.HmacSHA256(message, keyWordArray);

    return hmac.toString(CryptoJS.enc.Hex);
  }

  /**
   * Generate unlock request payload
   */
  generateUnlockRequest(nonce: string): object {
    // The ESP32 reconstructs the body using cJSON_PrintUnformatted which produces:
    // {"clientId":"sepolia-test-client","nonce":"nonce_value"}
    // We need to match this exact format including the nonce
    const bodyForHmac = `{"clientId":"${this.clientId}","nonce":"${nonce}"}`;
    const hmac = this.generateHMAC(nonce, 'POST', '/unlock', bodyForHmac);

    return {
      clientId: this.clientId,
      nonce: nonce,
      hmac: hmac
    };
  }

  /**
   * Set session token
   */
  setToken(token: string, ttlSeconds: number): void {
    this.currentToken = token;
    this.tokenExpiry = Date.now() + (ttlSeconds * 1000) - 5000; // 5 second buffer
  }

  /**
   * Get current token if valid
   */
  getToken(): string | undefined {
    if (!this.currentToken || !this.tokenExpiry) {
      return undefined;
    }

    if (Date.now() >= this.tokenExpiry) {
      this.currentToken = undefined;
      this.tokenExpiry = undefined;
      return undefined;
    }

    return this.currentToken;
  }

  /**
   * Check if token is expired or will expire soon
   */
  isTokenExpired(): boolean {
    return !this.getToken();
  }

  /**
   * Clear current token
   */
  clearToken(): void {
    this.currentToken = undefined;
    this.tokenExpiry = undefined;
  }

  /**
   * Generate authorization header with HMAC
   */
  generateAuthHeader(nonce: string, method: string, path: string, body: string = ''): string {
    const hmac = this.generateHMAC(nonce, method, path, body);
    return `HMAC ${this.clientId}:${hmac}`;
  }
}