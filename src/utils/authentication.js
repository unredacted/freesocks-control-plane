/**
 * Verifies the authentication of a request.
 * @param {Request} request - The incoming request object.
 * @param {string} authToken - The expected authentication token.
 * @returns {boolean} True if authenticated, false otherwise.
 */
export async function verifyAuth(request, authToken) {
    const authHeader = request.headers.get('Authorization');
    return authHeader && authHeader === `Bearer ${authToken}`;
  }
  
  /**
   * Verifies a Cloudflare Turnstile token.
   * @param {string} token - The Turnstile token to verify.
   * @param {string} secret - The secret key for Turnstile verification.
   * @returns {boolean} True if the token is valid, false otherwise.
   */
  export async function verifyTurnstile(token, secret) {
    try {
      const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `response=${encodeURIComponent(token)}&secret=${encodeURIComponent(secret)}`,
      });
  
      const turnstileValidation = await response.json();
      return turnstileValidation.success;
    } catch (error) {
      console.error('Error verifying Cloudflare Turnstile:', error);
      return false;
    }
  }