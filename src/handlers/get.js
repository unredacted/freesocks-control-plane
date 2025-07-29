import {
    turnstileSecretKey,
    turnstileSiteKey,
    API_ENDPOINTS_NAMESPACE,
    ACCESS_KEYS_NAMESPACE,
    EXPIRATION_DAYS,
    PREFIX_DISGUISE,
    WEIGHT_LATENCY,
    WEIGHT_ACCESS_KEY_COUNT,
    API_ENDPOINT_TIMEOUT,
    WEBSOCKET_ENABLED,
    WEBSOCKET_TCP_PATH,
    WEBSOCKET_UDP_PATH,
    WEBSOCKET_TLS,
    S3_PROVIDERS_ENABLED,
    S3_UPLOAD_MAX_RETRIES
  } from '../config/constants.js';
  import { verifyTurnstile } from '../utils/authentication.js';
  import { handleError, logError, logInfo } from '../utils/errorHandling.js';
  import { parseS3Providers, uploadToMultipleS3, extractServerName } from '../utils/s3Storage.js';
  
  // Main request handling function
  export async function handleRequest(request, env) {
    const requestHostname = new URL(request.url).hostname;
  
    if (request.method === "POST") {
      const isHuman = await validateFormAndTurnstile(request, turnstileSecretKey);
      if (!isHuman) {
        return new Response("Cloudflare Turnstile verification failed", { status: 403 });
      }
  
      try {
        const endpointKey = await getOptimalApiEndpoint(API_ENDPOINTS_NAMESPACE);
        const endpointDataStr = await API_ENDPOINTS_NAMESPACE.get(endpointKey);
        
        if (!endpointDataStr) {
          return new Response('API endpoint not found', { status: 500 });
        }
        
        let endpointData;
        try {
          endpointData = JSON.parse(endpointDataStr);
        } catch (e) {
          // Backward compatibility: if it's not JSON, assume it's just the API URL
          endpointData = { apiUrl: endpointDataStr };
        }
        
        let apiEndpointUrl = endpointData.apiUrl;
        const websocketDomain = endpointData.websocketDomain || '';
        
        if (apiEndpointUrl) {
          apiEndpointUrl = modifyApiEndpointUrl(apiEndpointUrl, requestHostname);
        }
  
        if (!apiEndpointUrl) {
          return new Response('API endpoint URL not found', { status: 500 });
        }
  
        const accessKeyData = await createNewAccessKey(apiEndpointUrl, websocketDomain);
        if (accessKeyData && accessKeyData.id) {
          const keyId = `${endpointKey}-key-${accessKeyData.id}`;
          const currentDate = new Date();
          let finalAccessKeyUrl;
          let s3Urls = [];
          
          // Handle WebSocket keys with S3 upload
          if (accessKeyData.dynamicAccessKeyUrl && S3_PROVIDERS_ENABLED) {
            try {
              logInfo(`Processing WebSocket key: ${accessKeyData.id}`);
              logInfo(`Dynamic URL returned by API: ${accessKeyData.dynamicAccessKeyUrl}`);
              logInfo(`WebSocket domain: ${websocketDomain}`);
              
              // Construct the correct URL using our apiUrl from KV
              const correctDynamicUrl = `${apiEndpointUrl}/access-keys/${accessKeyData.id}`;
              logInfo(`Corrected dynamic URL: ${correctDynamicUrl}`);
              
              // Fetch the YAML content from the corrected dynamic access key URL
              logInfo('Fetching YAML content from corrected URL...');
              const yamlResponse = await fetch(correctDynamicUrl);
              if (!yamlResponse.ok) {
                const errorText = await yamlResponse.text();
                logError(`Failed to fetch dynamic key content. Status: ${yamlResponse.status}, Body: ${errorText}`);
                throw new Error(`Failed to fetch dynamic key content: ${yamlResponse.status} - ${errorText}`);
              }
              const yamlContent = await yamlResponse.text();
              logInfo(`YAML content fetched, length: ${yamlContent.length} bytes`);
              
              // Extract server name from WebSocket domain
              const serverName = extractServerName(websocketDomain);
              logInfo(`Extracted server name: ${serverName}`);
              
              // Parse S3 providers and upload
              const s3Providers = parseS3Providers(env);
              logInfo(`Found ${s3Providers.length} S3 providers`);
              
              if (s3Providers.length > 0) {
                logInfo('Starting S3 uploads...');
                s3Urls = await uploadToMultipleS3(s3Providers, serverName, accessKeyData.id, yamlContent);
                logInfo(`S3 upload successful. URLs: ${JSON.stringify(s3Urls)}`);
                // Use the first successful upload URL in ssconf format
                finalAccessKeyUrl = `ssconf://${s3Urls[0].replace('https://', '')}`;
                logInfo(`Final access key URL: ${finalAccessKeyUrl}`);
              } else {
                logError('No S3 providers configured');
                throw new Error('No S3 providers configured');
              }
            } catch (error) {
              // If S3 upload fails, delete the created key and fail
              logError('S3 upload failed, cleaning up access key:', error);
              logError('Error stack:', error.stack);
              logError('Error details:', JSON.stringify({
                message: error.message,
                name: error.name,
                websocketDomain: websocketDomain,
                keyId: accessKeyData.id,
                originalDynamicUrl: accessKeyData.dynamicAccessKeyUrl,
                correctedUrl: `${apiEndpointUrl}/access-keys/${accessKeyData.id}`,
                apiEndpointUrl: apiEndpointUrl
              }));
              
              try {
                await deleteAccessKey(apiEndpointUrl, accessKeyData.id);
                logInfo('Successfully deleted orphaned access key');
              } catch (deleteError) {
                logError('Failed to delete access key after S3 upload failure:', deleteError);
              }
              return new Response(`Failed to process WebSocket access key: ${error.message}`, { status: 500 });
            }
          } else {
            // Use regular access URL for non-WebSocket keys
            finalAccessKeyUrl = `${accessKeyData.accessUrl}${PREFIX_DISGUISE}`;
          }
          
          const keyData = {
            creationTime: currentDate.toISOString(),
            deletionTime: null,
            lastSeen: null,
            currentlyConnected: null,
            isWebSocket: WEBSOCKET_ENABLED && websocketDomain ? true : false,
            s3Paths: s3Urls,
            serverName: extractServerName(websocketDomain),
            apiEndpoint: apiEndpointUrl
          };
          await ACCESS_KEYS_NAMESPACE.put(keyId, JSON.stringify(keyData));
  
          const output = generateHtmlOutput(currentDate, finalAccessKeyUrl, accessKeyData.dynamicAccessKeyUrl ? true : false);
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
      const endpointDataStr = await namespace.get(endpoint.name);
      if (!endpointDataStr) return;
      
      let apiEndpointUrl;
      try {
        const endpointData = JSON.parse(endpointDataStr);
        apiEndpointUrl = endpointData.apiUrl;
      } catch (e) {
        // Backward compatibility
        apiEndpointUrl = endpointDataStr;
      }
      
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
  async function createNewAccessKey(apiEndpointUrl, websocketDomain) {
    let requestBody = {};
    
    // If WebSocket is enabled, include WebSocket configuration
    if (WEBSOCKET_ENABLED && websocketDomain) {
      requestBody = {
        websocket: {
          enabled: true,
          tcpPath: WEBSOCKET_TCP_PATH,
          udpPath: WEBSOCKET_UDP_PATH,
          domain: websocketDomain,
          tls: WEBSOCKET_TLS
        }
      };
    }
    
    const response = await fetch(apiEndpointUrl + '/access-keys', { 
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: Object.keys(requestBody).length > 0 ? JSON.stringify(requestBody) : undefined
    });
    
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
  
  /**
   * Internal function to delete an access key - ONLY used for cleanup on S3 upload failure
   * This is NOT exposed as a public endpoint and requires the API endpoint URL
   * which is only available internally after key creation
   * 
   * Security: This function is only called when:
   * 1. A key was successfully created on the Outline server
   * 2. S3 upload failed and we need to prevent orphaned keys
   * 3. The API endpoint URL is already known from the creation process
   * 
   * @param {string} apiEndpointUrl - The Outline API endpoint (with auth path)
   * @param {string} keyId - The ID of the key to delete
   * @returns {Promise<boolean>} - True if deletion succeeded
   */
  async function deleteAccessKey(apiEndpointUrl, keyId) {
    const response = await fetch(`${apiEndpointUrl}/access-keys/${keyId}`, { 
      method: 'DELETE' 
    });
    
    if (!response.ok) {
      throw new Error(`Failed to delete access key: ${response.status}`);
    }
    
    return true;
  }
  
  // Function to generate the HTML output for the access key
  function generateHtmlOutput(currentDate, accessKeyOutput, isWebSocketKey = false) {
    const keyTypeMessage = isWebSocketKey 
      ? '<p style="color: #4ade80;"><strong>WebSocket-enabled key generated!</strong> This key uses advanced censorship-resistant technology.</p>' 
      : '';
    
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
            ${keyTypeMessage}
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