import {
  AUTH_TOKEN,
  ACCESS_KEYS_NAMESPACE,
  API_ENDPOINTS_NAMESPACE,
  CF_ACCESS_CLIENT_ID,
  CF_ACCESS_CLIENT_SECRET,
  MAX_KEYS_PER_RUN,
  STATE_NAMESPACE,
  MAX_RETRIES,
  RETRY_DELAY
} from '../config/constants.js';
import { verifyAuth } from '../utils/authentication.js';
import { handleError, logError, logInfo } from '../utils/errorHandling.js';
import { queryPrometheus } from '../utils/prometheusQueries.js';

const UPDATE_CURSOR_KEY = 'update_script_cursor';

async function retry(fn, maxRetries = MAX_RETRIES, delay = RETRY_DELAY) {
  let lastError;
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}

export async function handleRequest(request, isCronTriggered) {
  logInfo(`handleRequest triggered, isCronTriggered: ${isCronTriggered}`);

  const isDryRun = request && request.headers.get('X-Dry-Run') === 'true';
  const targetKey = request && request.headers.get('X-Target-Key');
  const isDebug = request && request.headers.get('X-Debug') === 'true';

  if (!isCronTriggered) {
    const isAuthorized = await verifyAuth(request, AUTH_TOKEN);
    if (!isAuthorized) {
      return handleError('Unauthorized', 401);
    }
  }

  try {
    let updateResults;
    if (targetKey) {
      updateResults = await updateTargetKey(targetKey, isDryRun, isDebug);
    } else {
      const startCursor = await retry(() => STATE_NAMESPACE.get(UPDATE_CURSOR_KEY));
      updateResults = await updateAccessKeys(isDryRun, startCursor, isDebug);
      
      if (!isDryRun && updateResults.nextCursor) {
        await retry(() => STATE_NAMESPACE.put(UPDATE_CURSOR_KEY, updateResults.nextCursor));
      } else if (!isDryRun && !updateResults.nextCursor) {
        await retry(() => STATE_NAMESPACE.delete(UPDATE_CURSOR_KEY));
      }
    }

    updateResults.isDryRun = isDryRun;
    updateResults.targetKey = targetKey || null;
    updateResults.isDebug = isDebug;
    
    return new Response(JSON.stringify(updateResults, null, 2), { 
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return handleError('Error updating access keys', 500, error);
  }
}

async function updateTargetKey(targetKey, isDryRun, isDebug) {
  const updateResults = {
    updatedKeys: [],
    errors: [],
    debugInfo: isDebug ? {} : undefined
  };

  try {
    const [hostname] = targetKey.split('-key-');
    const endpointDataStr = await retry(() => API_ENDPOINTS_NAMESPACE.get(hostname));
    
    if (!endpointDataStr) {
      updateResults.errors.push(`Endpoint not found for hostname: ${hostname}`);
      return updateResults;
    }
    
    let promApiEndpoint;
    try {
      const endpointData = JSON.parse(endpointDataStr);
      promApiEndpoint = endpointData.prometheusUrl;
    } catch (e) {
      updateResults.errors.push(`Invalid endpoint data for hostname: ${hostname}`);
      return updateResults;
    }
    
    logInfo(`Processing target key: ${targetKey}, Prometheus endpoint: ${promApiEndpoint}`);
    
    const activeKeysResult = await queryActiveKeys(promApiEndpoint, targetKey);
    
    if (!activeKeysResult.success) {
      updateResults.errors.push(`Error querying active keys for ${hostname}: ${activeKeysResult.error}`);
      return updateResults;
    }

    const activeKeys = activeKeysResult.data;
    if (isDebug) {
      updateResults.debugInfo.prometheusQuery = activeKeysResult.debugInfo;
    }
    await processKey(targetKey, activeKeys, isDryRun, updateResults, isDebug);
  } catch (error) {
    logError(`Error processing target key ${targetKey}:`, error);
    updateResults.errors.push(`Error processing target key ${targetKey}: ${error.message}`);
  }

  return updateResults;
}

async function updateAccessKeys(isDryRun, startCursor, isDebug) {
  const updateResults = {
    updatedKeys: [],
    errors: [],
    nextCursor: null,
    debugInfo: isDebug ? {} : undefined
  };

  let globalKeyCount = 0;
  const hostnames = await retry(() => API_ENDPOINTS_NAMESPACE.list());
  let startHostname = null;
  let currentCursor = null;

  if (startCursor) {
    [startHostname, currentCursor] = startCursor.split(':');
  }

  for (const hostname of hostnames.keys) {
    if (startHostname && hostname.name !== startHostname) continue;
    startHostname = null;

    try {
      const endpointDataStr = await retry(() => API_ENDPOINTS_NAMESPACE.get(hostname.name));
      
      if (!endpointDataStr) {
        updateResults.errors.push(`Endpoint not found for hostname: ${hostname.name}`);
        continue;
      }
      
      let promApiEndpoint;
      try {
        const endpointData = JSON.parse(endpointDataStr);
        promApiEndpoint = endpointData.prometheusUrl;
      } catch (e) {
        updateResults.errors.push(`Invalid endpoint data for hostname: ${hostname.name}`);
        continue;
      }
      
      logInfo(`Processing hostname: ${hostname.name}, Prometheus endpoint: ${promApiEndpoint}`);
      const activeKeysResult = await queryActiveKeys(promApiEndpoint);
      
      if (!activeKeysResult.success) {
        updateResults.errors.push(`Error querying active keys for ${hostname.name}: ${activeKeysResult.error}`);
        continue;
      }

      const activeKeys = activeKeysResult.data;
      const { processedKeys, nextCursor } = await processKeysForHostname(hostname.name, activeKeys, isDryRun, updateResults, MAX_KEYS_PER_RUN - globalKeyCount, currentCursor, isDebug);
      
      globalKeyCount += processedKeys;
      if (globalKeyCount >= MAX_KEYS_PER_RUN) {
        updateResults.nextCursor = `${hostname.name}:${nextCursor}`;
        break;
      }
      currentCursor = null;
    } catch (error) {
      logError(`Error processing hostname ${hostname.name}:`, error);
      updateResults.errors.push(`Error processing hostname ${hostname.name}: ${error.message}`);
    }
  }

  return updateResults;
}

async function processKeysForHostname(hostname, activeKeys, isDryRun, updateResults, remainingKeys, startCursor, isDebug) {
  let cursor = startCursor;
  let processedKeys = 0;

  do {
    const listResult = await retry(() => ACCESS_KEYS_NAMESPACE.list({ prefix: `${hostname}-key-`, cursor, limit: Math.min(remainingKeys, 1000) }));
    
    for (const key of listResult.keys) {
      await processKey(key.name, activeKeys, isDryRun, updateResults, isDebug);
      processedKeys++;
      remainingKeys--;
      if (remainingKeys <= 0) break;
    }

    cursor = listResult.cursor;
  } while (cursor && remainingKeys > 0);

  return { processedKeys, nextCursor: cursor };
}

async function processKey(key, activeKeys, isDryRun, updateResults, isDebug) {
  try {
    const keyData = await retry(() => ACCESS_KEYS_NAMESPACE.get(key).then(JSON.parse));
    
    // Populate missing fields
    const updatedKeyData = {
      ...keyData,
      deletionTime: keyData.deletionTime ?? null,
      lastSeen: keyData.lastSeen ?? null,
      currentlyConnected: keyData.currentlyConnected ?? null
    };

    // Check if we need to update the key data due to missing fields
    const needsUpdate = JSON.stringify(keyData) !== JSON.stringify(updatedKeyData);

    if (needsUpdate) {
      if (isDryRun) {
        updateResults.updatedKeys.push({
          key: key,
          before: keyData,
          after: updatedKeyData,
          changes: {
            deletionTime: keyData.deletionTime === undefined ? 'added' : 'unchanged',
            lastSeen: keyData.lastSeen === undefined ? 'added' : 'unchanged',
            currentlyConnected: keyData.currentlyConnected === undefined ? 'added' : 'unchanged'
          }
        });
      } else {
        await retry(() => ACCESS_KEYS_NAMESPACE.put(key, JSON.stringify(updatedKeyData)));
        updateResults.updatedKeys.push({
          key: key,
          changes: {
            deletionTime: keyData.deletionTime === undefined ? 'added' : 'unchanged',
            lastSeen: keyData.lastSeen === undefined ? 'added' : 'unchanged',
            currentlyConnected: keyData.currentlyConnected === undefined ? 'added' : 'unchanged'
          }
        });
      }
      logInfo(`Updated key ${key} with missing fields`);
      return; // Skip Prometheus comparison for this run
    }

    if (updatedKeyData.deletionTime) return; // Skip deleted keys

    const accessKeyId = key.split('-').pop(); // This correctly extracts the key ID
    const isActive = accessKeyId in activeKeys && activeKeys[accessKeyId].totalBytes > 0;
    const now = new Date().toISOString();

    const finalKeyData = {
      ...updatedKeyData,
      currentlyConnected: isActive,
      lastSeen: isActive ? activeKeys[accessKeyId].lastSeen : updatedKeyData.lastSeen
    };

    let hasChanges = isActive || updatedKeyData.currentlyConnected !== isActive || (isActive && updatedKeyData.lastSeen !== finalKeyData.lastSeen);

    const keyUpdateInfo = {
      key: key,
      before: updatedKeyData,
      after: finalKeyData,
      changes: {
        currentlyConnected: isActive !== updatedKeyData.currentlyConnected ? isActive : 'unchanged',
        lastSeen: isActive ? finalKeyData.lastSeen : 'unchanged'
      }
    };

    if (isDebug) {
      keyUpdateInfo.debugInfo = {
        accessKeyId,
        isActiveInPrometheusData: isActive,
        activeKeysData: activeKeys[accessKeyId]
      };
    }

    if (hasChanges) {
      if (isDryRun) {
        updateResults.updatedKeys.push(keyUpdateInfo);
      } else {
        await retry(() => ACCESS_KEYS_NAMESPACE.put(key, JSON.stringify(finalKeyData)));
        updateResults.updatedKeys.push(keyUpdateInfo);
      }
    }

    logInfo(`Processed key ${key}: isActive=${isActive}, lastSeen=${finalKeyData.lastSeen}`);
  } catch (error) {
    logError(`Error processing key ${key}:`, error);
    updateResults.errors.push(`Error processing key ${key}: ${error.message}`);
  }
}

async function queryActiveKeys(promApiEndpoint, targetKey = null) {
  const query = `increase(shadowsocks_data_bytes{dir=~"c<p|p>t"}[30m]) > 0`;
  
  try {
    logInfo(`Querying Prometheus for ${promApiEndpoint} with query: ${query}`);
    
    const queryResult = await retry(() => queryPrometheus(promApiEndpoint, query, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET));

    logInfo(`Raw Prometheus response for ${promApiEndpoint}:`, JSON.stringify(queryResult, null, 2));

    if (!queryResult.success) {
      return { success: false, error: `Prometheus query unsuccessful: ${JSON.stringify(queryResult)}` };
    }

    if (!queryResult.data || !Array.isArray(queryResult.data)) {
      return { success: false, error: `Unexpected Prometheus response structure: ${JSON.stringify(queryResult)}` };
    }

    const activeKeys = {};
    queryResult.data.forEach(item => {
      if (item && item.metric && item.metric.access_key && Array.isArray(item.value) && item.value.length === 2) {
        const accessKey = item.metric.access_key;
        const timestamp = new Date(item.value[0] * 1000).toISOString();
        const bytes = parseFloat(item.value[1]);

        if (!activeKeys[accessKey]) {
          activeKeys[accessKey] = {
            totalBytes: 0,
            lastSeen: timestamp
          };
        }
        activeKeys[accessKey].totalBytes += bytes;
        if (timestamp > activeKeys[accessKey].lastSeen) {
          activeKeys[accessKey].lastSeen = timestamp;
        }
      }
    });

    logInfo(`Processed active keys for ${promApiEndpoint}:`, JSON.stringify(activeKeys));
    
    const result = { success: true, data: activeKeys };
    
    if (targetKey) {
      const targetAccessKey = targetKey.split('-').pop();
      result.debugInfo = {
        query,
        targetKeyInfo: activeKeys[targetAccessKey] || null,
        rawResponse: queryResult
      };
    }
    
    return result;
  } catch (error) {
    logError(`Error querying Prometheus for ${promApiEndpoint}:`, error);
    return { success: false, error: `Error querying Prometheus: ${error.message}` };
  }
}