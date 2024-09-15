/**
 * Queries the Prometheus API.
 * @param {string} promApiEndpoint - The Prometheus API endpoint URL.
 * @param {string} query - The PromQL query string.
 * @param {string} clientId - The Cloudflare Access client ID.
 * @param {string} clientSecret - The Cloudflare Access client secret.
 * @returns {Object} An object with the query result or error information.
 */
export async function queryPrometheus(promApiEndpoint, query, clientId, clientSecret) {
    const queryUrl = `${promApiEndpoint}/api/v1/query?query=${encodeURIComponent(query)}`;
    const headers = {
      'CF-Access-Client-Id': clientId,
      'CF-Access-Client-Secret': clientSecret
    };
  
    try {
      const response = await fetch(queryUrl, { headers });
      if (!response.ok) {
        throw new Error(`Prometheus API request failed: ${response.status} ${response.statusText}`);
      }
  
      const data = await response.json();
      return { success: true, data: data.data.result };
    } catch (error) {
      console.error('Error querying Prometheus:', error);
      return { success: false, error: error.message };
    }
  }