export interface ESP32Config {
  deviceUrl: string;
  authKey: string;
  clientId: string;
  timeout?: number;
  retryOptions?: RetryOptions;
  rateLimitOptions?: RateLimitOptions;
}

export interface RetryOptions {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  factor: number;
}

export interface RateLimitOptions {
  requestsPerMinute: number;
  burstSize: number;
}

export interface DeviceInfo {
  fw: string;
  address: string;
  policyHash: string;
  secureBoot: boolean;
  flashEnc: boolean;
  mode: 'provisioning' | 'signing';
}

export interface HealthResponse {
  status: string;
  nonce: string;
  rateRemaining: number;
  signingAddress?: string;
}

export interface UnlockResponse {
  token: string;
  ttl: number;
}

export interface SignatureResponse {
  r: string;
  s: string;
  v: number;
  raw?: string;
}

export interface EIP1559Transaction {
  chainId: number;
  nonce: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  gasLimit: string;
  to: string;
  value: string;
  data: string;
}

export interface EIP155Transaction {
  chainId: number;
  nonce: string;
  gasPrice: string;
  gasLimit: string;
  to: string;
  value: string;
  data: string;
}

export interface PolicyConfig {
  allowedChains: number[];
  toWhitelist: string[];
  functionWhitelist: string[];
  maxValueWei: string;
  maxGasLimit: number;
  maxFeePerGasWei: string;
  allowEmptyDataToWhitelist: boolean;
}

export interface WiFiCredentials {
  ssid: string;
  psk: string;
}

export interface AuthConfig {
  password: string;
}

export interface KeyConfig {
  mode: 'generate' | 'import';
  seed?: string;
  privkey?: string;
}