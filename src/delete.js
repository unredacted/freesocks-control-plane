addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, false));
});

addEventListener('scheduled', event => {
  event.waitUntil(handleRequest(null, true));
});

const AUTH_TOKEN = SECRET_AUTH_TOKEN; // Replace with your actual auth token
const ACCESS_KEYS_NAMESPACE = FREESOCKS_OUTLINE_ACCESS_KEYS; // Namespace for storing access keys
const API_ENDPOINTS_NAMESPACE = FREESOCKS_OUTLINE_API_ENDPOINTS; // Namespace for storing API endpoints
const ACCESS_KEYS_DELETION_NAMESPACE = FREESOCKS_OUTLINE_ACCESS_KEYS_DELETION; // Namespace for storing details about deleted access keys
const PROM_API_ENDPOINTS_NAMESPACE = FREESOCKS_PROM_API_ENDPOINTS; // Namespace for Outline Prometheus API endpoints
const PROM_QUERY_TIME_RANGE = VAR_PROM_QUERY_TIME_RANGE; // Set the time range for the PromQL query (e.g., '30d')
const CF_ACCESS_CLIENT_ID = VAR_CF_ACCESS_CLIENT_ID; // Set the Cloudflare Access client ID
const CF_ACCESS_CLIENT_SECRET = VAR_CF_ACCESS_CLIENT_SECRET; // Set the Cloudflare Access client secret

async function handleRequest(request, isCronTriggered) {
  console.log(`handleRequest triggered, isCronTriggered: ${isCronTriggered}`);
  
  const isDryRun = request && request.headers.get('X-Dry-Run') === 'true';

  if (!isCronTriggered) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || authHeader !== `Bearer ${AUTH_TOKEN}`) {
      console.log('Unauthorized access attempt');
      return new Response('Unauthorized', { status: 401 });
    }
  }

  // Get all the hostnames from the PROM_API_ENDPOINTS_NAMESPACE
  let hostnames;
  try {
    hostnames = await PROM_API_ENDPOINTS_NAMESPACE.list();
  } catch (error) {
    console.error(`Error retrieving hostnames from PROM_API_ENDPOINTS_NAMESPACE: ${error}`);
    return new Response('Internal Server Error', { status: 500 });
  }

  let processedKeysInfo = [];
  let keysEligibleForDeletion = 0;

  for (const hostname of hostnames.keys) {
    try {
      const promApiEndpoint = await PROM_API_ENDPOINTS_NAMESPACE.get(hostname.name);

      // Query the Prometheus API to get the access keys that have not been used in the specified time range
      const queryUrl = `${promApiEndpoint}/api/v1/query?query=sum(increase(shadowsocks_data_bytes{dir=~"c<p|p>t"}[${PROM_QUERY_TIME_RANGE}])) by (access_key) == 0`;
      const headers = {
        'CF-Access-Client-Id': CF_ACCESS_CLIENT_ID,
        'CF-Access-Client-Secret': CF_ACCESS_CLIENT_SECRET
      };
      let response;
      try {
        response = await fetch(queryUrl, { headers });
      } catch (error) {
        console.error(`Error querying Prometheus API for hostname: ${hostname.name}, Error: ${error}`);
        processedKeysInfo.push(`Error querying Prometheus API for hostname: ${hostname.name}`);
        continue;
      }

      if (!response.ok) {
        console.error(`Error response from Prometheus API for hostname: ${hostname.name}, Status: ${response.status}`);
        processedKeysInfo.push(`Error response from Prometheus API for hostname: ${hostname.name}`);
        continue;
      }

      let jsonResponse;
      try {
        jsonResponse = await response.json();
      } catch (error) {
        console.error(`Error parsing JSON response from Prometheus API for hostname: ${hostname.name}, Error: ${error}`);
        processedKeysInfo.push(`Error parsing JSON response from Prometheus API for hostname: ${hostname.name}`);
        continue;
      }

      // Extract the access keys to be deleted and their unused days
      const keysToDelete = jsonResponse.data.result.map(result => ({
        accessKey: result.metric.access_key,
        unusedDays: getUnusedDays(PROM_QUERY_TIME_RANGE)
      }));

      // Delete the access keys
      for (const { accessKey, unusedDays } of keysToDelete) {
        const endpointKey = hostname.name;
        let apiEndpointUrl;
        try {
          apiEndpointUrl = await API_ENDPOINTS_NAMESPACE.get(endpointKey);
        } catch (error) {
          console.error(`Error retrieving API endpoint URL for key: ${endpointKey}, Error: ${error}`);
          processedKeysInfo.push(`Error retrieving API endpoint URL for key: ${endpointKey}`);
          continue;
        }

        if (apiEndpointUrl) {
          try {
            const keyName = `${endpointKey}-key-${accessKey}`;
            keysEligibleForDeletion++;

            if (isDryRun) {
              processedKeysInfo.push(`Would delete key: ${keyName}, Unused for ${unusedDays} days`);
            } else {
              console.log(`Attempting to delete key: ${keyName}`);
              const deleteResult = await sendDeleteRequest(`${apiEndpointUrl}/access-keys/${accessKey}`, isDryRun);
              if (deleteResult.success) {
                console.log(`Key deletion successful: ${keyName}`);
                await logDeletion(keyName, new Date(), isDryRun);
                try {
                  await ACCESS_KEYS_NAMESPACE.delete(keyName);
                  processedKeysInfo.push(`Deleted key: ${keyName}, Unused for ${unusedDays} days`);
                } catch (error) {
                  console.error(`Error deleting key from ACCESS_KEYS_NAMESPACE: ${keyName}, Error: ${error}`);
                  processedKeysInfo.push(`Error deleting key from ACCESS_KEYS_NAMESPACE: ${keyName}`);
                }
              } else {
                processedKeysInfo.push(`Failed to delete key: ${keyName}, Unused for ${unusedDays} days, Reason: ${deleteResult.error}`);
              }
            }
          } catch (error) {
            console.error(`Error processing key: ${accessKey}, Error: ${error}`);
            processedKeysInfo.push(`Failed to delete key (exception): ${accessKey}`);
          }
        } else {
          console.error(`API endpoint URL not found for key: ${endpointKey}`);
          processedKeysInfo.push(`API endpoint URL not found for key: ${endpointKey}`);
        }
      }
    } catch (error) {
      console.error(`Error processing hostname: ${hostname.name}, Error: ${error}`);
      processedKeysInfo.push(`Error processing hostname: ${hostname.name}`);
    }
  }

  if (keysEligibleForDeletion === 0) {
    let noDeletionReason = isDryRun ? 'Dry run: No keys are eligible for deletion based on the Prometheus query.' : 'Wet run: No keys are eligible for deletion based on the Prometheus query.';
    return new Response(noDeletionReason, { status: 200 });
  }

  if (isDryRun) {
    let dryRunInfo = `Dry run: ${processedKeysInfo.length} keys would be processed.\n${processedKeysInfo.join('\n')}`;
    return new Response(dryRunInfo, { status: 200 });
  }

  return new Response(processedKeysInfo.join('\n'), { status: 200 });
}

function getUnusedDays(promQueryTimeRange) {
  const match = promQueryTimeRange.match(/(\d+)([dhms])/);
  if (match) {
    const [, value, unit] = match;
    const days = {
      d: 1,
      h: 1 / 24,
      m: 1 / (24 * 60),
      s: 1 / (24 * 60 * 60)
    }[unit];
    return Math.floor(value * days);
  }
  return 0;
}

async function sendDeleteRequest(url, isDryRun) {
  try {
    if (!isDryRun) {
      console.log(`Sending DELETE request to: ${url}`);
      const response = await fetch(url, { method: 'DELETE' });
      if (!response.ok) {
        console.error(`Failed to delete key. Status: ${response.status}, StatusText: ${response.statusText}`);
        const responseBody = await response.text();
        console.error(`Response body: ${responseBody}`);
        return { success: false, error: `Status: ${response.status}, Response: ${responseBody}` };
      }
    }
    return { success: true };
  } catch (error) {
    console.error(`Error in sendDeleteRequest: ${error}`);
    return { success: false, error: error.message };
  }
}

async function logDeletion(keyName, deletionDate, isDryRun) {
  if (!isDryRun) {
    try {
      const keyDataString = await ACCESS_KEYS_NAMESPACE.get(keyName);
      let creationTime;

      if (keyDataString && keyDataString.trim().startsWith('{')) {
        const keyData = JSON.parse(keyDataString);
        creationTime = keyData.creationTime;
      } else {
        creationTime = keyDataString;
      }

      const deletionLog = {
        creationTime: creationTime,
        deletionTime: deletionDate.toISOString()
      };

      await ACCESS_KEYS_DELETION_NAMESPACE.put(keyName, JSON.stringify(deletionLog));
      console.log(`Logged deletion for key: ${keyName}`);
    } catch (error) {
      console.error(`Error in logDeletion for key: ${keyName}, Error: ${error}`);
    }
  }
}

// Export the handleRequest function to be used in index.js
export { handleRequest };
