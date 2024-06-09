// Event listener for handling fetch events
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const turnstileSecretKey = TURNSTILE_SECRET_KEY; // Cloudflare Turnstile secret key
const turnstileSiteKey = TURNSTILE_SITE_KEY; // Cloudflare Turnstile site key

const API_ENDPOINTS_NAMESPACE = FREESOCKS_OUTLINE_API_ENDPOINTS; // Namespace for storing API endpoints
const ACCESS_KEYS_NAMESPACE = FREESOCKS_OUTLINE_ACCESS_KEYS; // Namespace for storing access keys
const EXPIRATION_DAYS = VAR_EXPIRATION_DAYS; // Set the expiration period in days
const PREFIX_DISGUISE = VAR_PREFIX_DISGUISE; // Prefix disguise to append after the access URL
const WEIGHT_LATENCY = VAR_WEIGHT_LATENCY; // Weight for latency in the score calculation
const WEIGHT_ACCESS_KEY_COUNT = VAR_WEIGHT_ACCESS_KEY_COUNT; // Weight for access key count in the score calculation
const API_ENDPOINT_TIMEOUT = VAR_API_ENDPOINT_TIMEOUT; // Timeout duration for API endpoint requests (in milliseconds)

// Main request handling function
async function handleRequest(request) {
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
        
        const timeData = {
          creationTime: currentDate.toISOString()
        };
        await ACCESS_KEYS_NAMESPACE.put(keyId, JSON.stringify(timeData));

        const accessKeyOutput = `${accessKeyData.accessUrl}${PREFIX_DISGUISE}`;
        const output = generateHtmlOutput(currentDate, accessKeyOutput);
        return new Response(output, { headers: { 'content-type': 'text/html' } });
      } else {
        return new Response('Failed to create access key', { status: 500 });
      }
    } catch (error) {
      console.error('Error in creating access key:', error);
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
        console.error(`Failed to fetch access keys from ${accessKeysUrl}. Status: ${response.status}`);
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        console.error(`Request to ${accessKeysUrl} timed out.`);
      } else {
        console.error(`Error fetching access keys from ${accessKeysUrl}:`, error);
      }
    }
  });

  try {
    await Promise.all(fetchPromises);
  } catch (error) {
    console.error('Error fetching access keys:', error);
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
    console.error('Failed to create new access key:', response.statusText);
    return null;
  }
}

// Function to verify the Cloudflare Turnstile token
async function verifyTurnstile(token, secret) {
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

// Export the handleRequest function to be used in index.js
export { handleRequest };
