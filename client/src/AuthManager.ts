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
    const hmac = CryptoJS.HmacSHA256(message, this.authKey);
    return hmac.toString(CryptoJS.enc.Hex);
  }

  /**
   * Generate unlock request payload
   */
  generateUnlockRequest(nonce: string): object {
    const hmac = this.generateHMAC(nonce, 'POST', '/unlock', `{"clientId":"${this.clientId}"}`);
    return {
      clientId: this.clientId,
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