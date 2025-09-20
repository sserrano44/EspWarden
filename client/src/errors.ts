export class ESP32SignerError extends Error {
  constructor(
    message: string,
    public code: string,
    public reason?: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'ESP32SignerError';
  }
}

export class AuthenticationError extends ESP32SignerError {
  constructor(message: string, reason?: string) {
    super(message, 'AUTH_FAILED', reason, 401);
    this.name = 'AuthenticationError';
  }
}

export class PolicyViolationError extends ESP32SignerError {
  constructor(message: string, reason?: string) {
    super(message, 'POLICY_VIOLATION', reason, 403);
    this.name = 'PolicyViolationError';
  }
}

export class RateLimitError extends ESP32SignerError {
  constructor(message: string, reason?: string) {
    super(message, 'RATE_LIMITED', reason, 429);
    this.name = 'RateLimitError';
  }
}

export class DeviceModeError extends ESP32SignerError {
  constructor(message: string, reason?: string) {
    super(message, 'INVALID_MODE', reason, 403);
    this.name = 'DeviceModeError';
  }
}

export class NetworkError extends ESP32SignerError {
  constructor(message: string, reason?: string) {
    super(message, 'NETWORK_ERROR', reason);
    this.name = 'NetworkError';
  }
}

export class ValidationError extends ESP32SignerError {
  constructor(message: string, reason?: string) {
    super(message, 'VALIDATION_ERROR', reason, 400);
    this.name = 'ValidationError';
  }
}