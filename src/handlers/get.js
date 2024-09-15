import {
    turnstileSecretKey,
    turnstileSiteKey,
    API_ENDPOINTS_NAMESPACE,
    ACCESS_KEYS_NAMESPACE,
    EXPIRATION_DAYS,
    PREFIX_DISGUISE,
    WEIGHT_LATENCY,
    WEIGHT_ACCESS_KEY_COUNT,
    API_ENDPOINT_TIMEOUT
  } from '../config/constants.js';
  import { verifyTurnstile } from '../utils/authentication.js';
  import { handleError, logError } from '../utils/errorHandling.js';
  
  // Main request handling function
  export async function handleRequest(request) {
    const requestHostname = new URL(request.url).hostname;
  
    if (request.method === "POST") {
      const isHuman = await validateFormAndTurnstile(request, turnstileSecretKey);
      if (!isHuman) {
        return new Response("Cloudflare Turnstile verification failed", { status: 403 });
      }
  
      try {
        const endpointKey = await getOptimalApiEndpoint(API_ENDPOINTS_NAMESPACE);
        let apiEndpointUrl = await API_ENDPOINTS_NAMESPACE.get(endpointKey);
  
        if (apiEndpointUrl) {
          apiEndpointUrl = modifyApiEndpointUrl(apiEndpointUrl, requestHostname);
        }
  
        if (!apiEndpointUrl) {
          return new Response('API endpoint URL not found', { status: 500 });
        }
  
        const accessKeyData = await createNewAccessKey(apiEndpointUrl);
        if (accessKeyData && accessKeyData.id) {
          const keyId = `${endpointKey}-key-${accessKeyData.id}`;
          const currentDate = new Date();
          
          const keyData = {
            creationTime: currentDate.toISOString(),
            deletionTime: null,
            lastSeen: null,
            currentlyConnected: null
          };
          await ACCESS_KEYS_NAMESPACE.put(keyId, JSON.stringify(keyData));
  
          const accessKeyOutput = `${accessKeyData.accessUrl}${PREFIX_DISGUISE}`;
          const output = generateHtmlOutput(currentDate, accessKeyOutput);
          return new Response(output, { headers: { 'content-type': 'text/html' } });
        } else {
          return new Response('Failed to create access key', { status: 500 });
        }
      } catch (error) {
        logError('Error in creating access key:', error);
        if (error.message === 'No available API endpoints.') {
          return new Response('Service temporarily unavailable. Please try again later.', { status: 503 });
        } else {
          return new Response('Error processing your request', { status: 500 });
        }
      }
    } else {
      return serveHtmlForm();
    }
  }
  
  // Function to modify the API endpoint URL based on the request hostname
  function modifyApiEndpointUrl(originalApiEndpointUrl, requestHostname) {
    const originalUrl = new URL(originalApiEndpointUrl);
    const originalHostnameParts = originalUrl.hostname.split('.');
    const requestHostnameParts = requestHostname.split('.');
    if (originalHostnameParts.length > 1 && requestHostnameParts.length > 1) {
      originalHostnameParts[originalHostnameParts.length - 2] = requestHostnameParts[requestHostnameParts.length - 2];
      originalHostnameParts[originalHostnameParts.length - 1] = requestHostnameParts[requestHostnameParts.length - 1];
      originalUrl.hostname = originalHostnameParts.join('.');
    }
    return originalUrl.toString();
  }
  
  // Function to validate the form and Cloudflare Turnstile token
  async function validateFormAndTurnstile(request, secret) {
    const formData = await request.formData();
    const token = formData.get('cf-turnstile-response');
    return await verifyTurnstile(token, secret);
  }
  
  // Function to get the optimal API endpoint based on latency and access key count
  async function getOptimalApiEndpoint(namespace) {
    const endpoints = await namespace.list();
    const endpointScores = [];
  
    const fetchPromises = endpoints.keys.map(async endpoint => {
      const apiEndpointUrl = await namespace.get(endpoint.name);
      const accessKeysUrl = `${apiEndpointUrl}/access-keys`;
  
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), API_ENDPOINT_TIMEOUT);
  
        const startTime = performance.now();
        const response = await fetch(accessKeysUrl, { signal: controller.signal });
        const endTime = performance.now();
        const latency = endTime - startTime;
  
        clearTimeout(timeoutId);
  
        if (response.ok) {
          const accessKeys = await response.json();
          const accessKeyCount = accessKeys.accessKeys.length;
          
          const score = WEIGHT_LATENCY * latency + WEIGHT_ACCESS_KEY_COUNT * accessKeyCount;
          
          endpointScores.push({ endpoint: endpoint.name, score });
        } else {
          logError(`Failed to fetch access keys from ${accessKeysUrl}. Status: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          logError(`Request to ${accessKeysUrl} timed out.`);
        } else {
          logError(`Error fetching access keys from ${accessKeysUrl}:`, error);
        }
      }
    });
  
    try {
      await Promise.all(fetchPromises);
    } catch (error) {
      logError('Error fetching access keys:', error);
    }
  
    if (endpointScores.length === 0) {
      throw new Error('No available API endpoints.');
    }
  
    endpointScores.sort((a, b) => a.score - b.score);
  
    return endpointScores[0].endpoint;
  }
  
  // Function to create a new access key
  async function createNewAccessKey(apiEndpointUrl) {
    const response = await fetch(apiEndpointUrl + '/access-keys', { method: 'POST' });
    if (response.ok) {
      return await response.json();
    } else {
      logError('Failed to create new access key:', response.statusText);
      return null;
    }
  }
  
  // Function to serve the HTML form
  function serveHtmlForm() {
    const htmlForm = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Get an access key</title>
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
          <style>
            body {
              background-color: #1a1a1a;
              color: #ffffff;
              font-family: Arial, sans-serif;
            }
            form {
              max-width: 400px;
              margin: 0 auto;
              padding: 20px;
            }
            input[type="submit"] {
              background-color: #333333;
              color: #ffffff;
              padding: 10px 20px;
              border: none;
              cursor: pointer;
            }
          </style>
        </head>
        <body>
          <noscript>
            <p>Please enable JavaScript to access this page.</p>
          </noscript>
          <form action="/get" method="post">
            <p>If you are human, click the check box when it shows up.</p>
            <div id="turnstile-container">
              <div id="turnstile-loading-text">Loading Cloudflare Turnstile widget. Please wait...</div>
              <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}"></div>
            </div>
            <p>Then click submit to get an access key.</p>
            <input type="submit" value="Submit">
          </form>
          <script>
            function checkTurnstileLoaded() {
              var turnstileWidget = document.querySelector('.cf-turnstile iframe');
              if (turnstileWidget) {
                var loadingText = document.getElementById('turnstile-loading-text');
                if (loadingText) {
                  loadingText.parentNode.removeChild(loadingText);
                }
              } else {
                setTimeout(checkTurnstileLoaded, 100);
              }
            }
            checkTurnstileLoaded();
          </script>
        </body>
      </html>
    `;
  
    return new Response(htmlForm, { headers: { 'Content-Type': 'text/html' } });
  }
  
  // Function to generate the HTML output for the access key
  function generateHtmlOutput(currentDate, accessKeyOutput) {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Access key generated</title>
          <style>
            body {
              background-color: #1a1a1a;
              color: #ffffff;
              font-family: Arial, sans-serif;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              padding: 20px;
            }
            .access-key-box {
              background-color: #282828;
              border: 1px solid #444444;
              padding: 10px;
              margin-bottom: 10px;
              cursor: pointer;
              word-wrap: break-word;
            }
            .copy-button {
              background-color: #333333;
              color: #ffffff;
              padding: 5px 10px;
              border: none;
              cursor: pointer;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Access key generated</h2>
            <p>Creation date: ${currentDate.toISOString()}</p>
            <p>Expiration date: This key will intelligently expire after ${EXPIRATION_DAYS} days if you don't use it.</p>
            <p>Access key:</p>
            <div class="access-key-box" onclick="copyToClipboard('${accessKeyOutput}')">
              <p>${accessKeyOutput}</p>
            </div>
            <button class="copy-button" onclick="copyToClipboard('${accessKeyOutput}')">Copy Access Key</button>
            <script>
              function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(function() {
                  alert('Access key copied to clipboard');
                }, function() {
                  alert('Failed to copy access key');
                });
              }
            </script>
          </div>
        </body>
      </html>
    `;
  }