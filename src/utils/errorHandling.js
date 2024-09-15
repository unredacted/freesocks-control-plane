/**
 * Logs an error message along with optional error details.
 * @param {string} message - The error message to log.
 * @param {Error} [error] - Optional Error object with additional details.
 */
export function logError(message, error = null) {
    console.error(`[ERROR] ${message}`);
    if (error) {
      console.error(error.stack || error);
    }
  }
  
  /**
   * Logs an informational message.
   * @param {string} message - The message to log.
   */
  export function logInfo(message) {
    console.log(`[INFO] ${message}`);
  }
  
  /**
   * Creates a standardized error response.
   * @param {string} message - The error message.
   * @param {number} status - The HTTP status code.
   * @param {Error} [error] - Optional Error object with additional details.
   * @returns {Response} A Response object with the error details.
   */
  export function handleError(message, status, error = null) {
    logError(message, error);
    const body = JSON.stringify({
      error: message,
      details: error ? error.message : undefined
    });
    return new Response(body, {
      status: status,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  /**
   * Wraps an async function with error handling.
   * @param {Function} fn - The async function to wrap.
   * @returns {Function} A wrapped function that catches and handles errors.
   */
  export function withErrorHandling(fn) {
    return async (...args) => {
      try {
        return await fn(...args);
      } catch (error) {
        return handleError('An unexpected error occurred', 500, error);
      }
    };
  }