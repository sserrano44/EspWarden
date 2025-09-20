import { RetryOptions } from './types';
import { NetworkError } from './errors';

export class RetryManager {
  private options: RetryOptions;

  constructor(options: Partial<RetryOptions> = {}) {
    this.options = {
      maxRetries: options.maxRetries ?? 3,
      baseDelay: options.baseDelay ?? 1000,
      maxDelay: options.maxDelay ?? 30000,
      factor: options.factor ?? 2
    };
  }

  /**
   * Execute function with exponential backoff retry
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    context: string = 'operation'
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 0; attempt <= this.options.maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;

        // Don't retry certain errors
        if (this.isNonRetryableError(error)) {
          throw error;
        }

        // If this was the last attempt, throw the error
        if (attempt === this.options.maxRetries) {
          throw new NetworkError(
            `${context} failed after ${this.options.maxRetries + 1} attempts: ${lastError.message}`,
            `MAX_RETRIES_EXCEEDED`
          );
        }

        // Calculate delay with exponential backoff and jitter
        const delay = Math.min(
          this.options.baseDelay * Math.pow(this.options.factor, attempt),
          this.options.maxDelay
        );

        // Add random jitter (±25%)
        const jitter = delay * 0.25 * (Math.random() - 0.5) * 2;
        const finalDelay = Math.max(100, delay + jitter);

        console.warn(`${context} attempt ${attempt + 1} failed, retrying in ${Math.round(finalDelay)}ms: ${lastError.message}`);

        await this.sleep(finalDelay);
      }
    }

    throw lastError!;
  }

  /**
   * Check if error should not be retried
   */
  private isNonRetryableError(error: any): boolean {
    // Don't retry authentication errors
    if (error.statusCode === 401 || error.statusCode === 403) {
      return true;
    }

    // Don't retry client errors (4xx except 429)
    if (error.statusCode >= 400 && error.statusCode < 500 && error.statusCode !== 429) {
      return true;
    }

    return false;
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Create a circuit breaker that fails fast after consecutive failures
   */
  createCircuitBreaker<T>(
    operation: () => Promise<T>,
    failureThreshold: number = 5,
    resetTimeout: number = 60000
  ) {
    let consecutiveFailures = 0;
    let circuitOpen = false;
    let lastFailureTime = 0;

    return async (): Promise<T> => {
      // Check if circuit should be reset
      if (circuitOpen && Date.now() - lastFailureTime > resetTimeout) {
        circuitOpen = false;
        consecutiveFailures = 0;
      }

      // Fail fast if circuit is open
      if (circuitOpen) {
        throw new NetworkError(
          'Circuit breaker is open - failing fast',
          'CIRCUIT_BREAKER_OPEN'
        );
      }

      try {
        const result = await operation();
        consecutiveFailures = 0; // Reset on success
        return result;
      } catch (error) {
        consecutiveFailures++;
        lastFailureTime = Date.now();

        if (consecutiveFailures >= failureThreshold) {
          circuitOpen = true;
        }

        throw error;
      }
    };
  }
}