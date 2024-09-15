import {
  AUTH_TOKEN,
  ACCESS_KEYS_NAMESPACE,
  API_ENDPOINTS_NAMESPACE,
  EXPIRATION_DAYS,
  MAX_RETRIES,
  RETRY_DELAY,
  STATE_NAMESPACE,
  MAX_KEYS_PER_RUN
} from '../config/constants.js';
import { verifyAuth } from '../utils/authentication.js';
import { handleError, logError, logInfo } from '../utils/errorHandling.js';

const DELETE_CURSOR_KEY = 'delete_script_cursor';

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
  const targetServer = request && request.headers.get('X-Target-Server');
  const targetKey = request && request.headers.get('X-Target-Key');

  if (!isCronTriggered) {
    const isAuthorized = await verifyAuth(request, AUTH_TOKEN);
    if (!isAuthorized) {
      return handleError('Unauthorized', 401);
    }
  }

  try {
    let deleteResults;
    if (targetKey) {
      deleteResults = await processKeys([targetKey], isDryRun, targetServer);
    } else if (targetServer) {
      deleteResults = await processKeysForServer(targetServer, isDryRun);
    } else {
      const startCursor = await retry(() => STATE_NAMESPACE.get(DELETE_CURSOR_KEY));
      deleteResults = await processAllKeys(isDryRun, startCursor);
      
      if (!isDryRun && deleteResults.nextCursor) {
        await retry(() => STATE_NAMESPACE.put(DELETE_CURSOR_KEY, deleteResults.nextCursor));
      } else if (!isDryRun && !deleteResults.nextCursor) {
        await retry(() => STATE_NAMESPACE.delete(DELETE_CURSOR_KEY));
      }
    }

    deleteResults.isDryRun = isDryRun;
    deleteResults.targetServer = targetServer || null;
    deleteResults.targetKey = targetKey || null;
    deleteResults.expirationDays = EXPIRATION_DAYS;

    return new Response(JSON.stringify(deleteResults, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return handleError('Error deleting access keys', 500, error);
  }
}

async function processKeys(keys, isDryRun, targetServer) {
  const deleteResults = {
    processedKeys: [],
    errors: []
  };

  for (const key of keys) {
    try {
      if (targetServer && !key.startsWith(`${targetServer}-key-`)) {
        deleteResults.errors.push(`Key ${key} does not match target server ${targetServer}`);
        continue;
      }

      const keyData = await retry(() => ACCESS_KEYS_NAMESPACE.get(key));
      if (!keyData) {
        deleteResults.errors.push(`Key not found: ${key}`);
        continue;
      }

      await processKeyForDeletion(key, JSON.parse(keyData), isDryRun, deleteResults);
    } catch (error) {
      logError(`Error processing key ${key}:`, error);
      deleteResults.errors.push(`Error processing key ${key}: ${error.message}`);
    }
  }

  return deleteResults;
}

async function processKeysForServer(targetServer, isDryRun) {
  const deleteResults = {
    processedKeys: [],
    errors: [],
    nextCursor: null
  };

  let cursor = null;
  let processedCount = 0;

  do {
    const listResult = await retry(() => ACCESS_KEYS_NAMESPACE.list({ prefix: `${targetServer}-key-`, cursor, limit: Math.min(MAX_KEYS_PER_RUN - processedCount, 1000) }));

    for (const key of listResult.keys) {
      try {
        const keyData = JSON.parse(await ACCESS_KEYS_NAMESPACE.get(key.name));
        await processKeyForDeletion(key.name, keyData, isDryRun, deleteResults);
        processedCount++;
      } catch (error) {
        logError(`Error processing key ${key.name}:`, error);
        deleteResults.errors.push(`Error processing key ${key.name}: ${error.message}`);
      }

      if (processedCount >= MAX_KEYS_PER_RUN) {
        deleteResults.nextCursor = `${targetServer}:${listResult.cursor}`;
        return deleteResults;
      }
    }

    cursor = listResult.cursor;
  } while (cursor);

  return deleteResults;
}

async function processAllKeys(isDryRun, startCursor) {
  const deleteResults = {
    processedKeys: [],
    errors: [],
    nextCursor: null
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
      const { processedKeys, nextCursor } = await processKeysForServer(hostname.name, isDryRun);
      deleteResults.processedKeys.push(...processedKeys);
      deleteResults.errors.push(...processedKeys.errors);
      
      globalKeyCount += processedKeys.length;
      if (globalKeyCount >= MAX_KEYS_PER_RUN) {
        deleteResults.nextCursor = `${hostname.name}:${nextCursor}`;
        break;
      }
      currentCursor = null;
    } catch (error) {
      logError(`Error processing hostname ${hostname.name}:`, error);
      deleteResults.errors.push(`Error processing hostname ${hostname.name}: ${error.message}`);
    }
  }

  return deleteResults;
}

async function processKeyForDeletion(keyName, keyData, isDryRun, deleteResults) {
  const now = new Date();
  const lastSeen = new Date(keyData.lastSeen);
  const daysSinceLastSeen = (now - lastSeen) / (1000 * 60 * 60 * 24);

  const keyInfo = {
    key: keyName,
    lastSeen: keyData.lastSeen,
    daysSinceLastSeen: daysSinceLastSeen.toFixed(2),
    currentlyConnected: keyData.currentlyConnected,
    expirationDays: EXPIRATION_DAYS,
    creationTime: keyData.creationTime,
    deletionTime: keyData.deletionTime
  };

  const shouldDelete = daysSinceLastSeen > EXPIRATION_DAYS && !keyData.currentlyConnected;

  if (shouldDelete) {
    keyInfo.status = isDryRun ? 'Would delete' : 'Deleted';
    keyInfo.reason = `Last seen ${daysSinceLastSeen.toFixed(2)} days ago (> ${EXPIRATION_DAYS} days), not currently connected`;

    if (!isDryRun) {
      try {
        const [hostname, accessKey] = keyName.split('-key-');
        const apiEndpointUrl = await retry(() => API_ENDPOINTS_NAMESPACE.get(hostname));

        if (!apiEndpointUrl) {
          throw new Error(`API endpoint URL not found for hostname: ${hostname}`);
        }

        const deleteResult = await sendDeleteRequest(`${apiEndpointUrl}/access-keys/${accessKey}`);
        
        if (deleteResult.success) {
          keyData.deletionTime = now.toISOString();
          keyData.currentlyConnected = null;
          await retry(() => ACCESS_KEYS_NAMESPACE.put(keyName, JSON.stringify(keyData)));
          keyInfo.deletionTime = keyData.deletionTime;
          keyInfo.currentlyConnected = keyData.currentlyConnected;
        } else {
          throw new Error(`Failed to delete key: ${deleteResult.error}`);
        }
      } catch (error) {
        logError(`Error deleting key ${keyName}:`, error);
        keyInfo.status = 'Error';
        keyInfo.error = error.message;
      }
    }
  } else {
    keyInfo.status = 'Not deleted';
    keyInfo.reason = keyData.currentlyConnected 
      ? 'Currently connected' 
      : `Last seen ${daysSinceLastSeen.toFixed(2)} days ago (<= ${EXPIRATION_DAYS} days)`;
  }

  deleteResults.processedKeys.push(keyInfo);
}

async function sendDeleteRequest(url) {
  try {
    logInfo(`Sending DELETE request to: ${url}`);
    const response = await fetch(url, { method: 'DELETE' });
    if (!response.ok) {
      const responseBody = await response.text();
      logError(`Failed to delete key. Status: ${response.status}, StatusText: ${response.statusText}`);
      logError(`Response body: ${responseBody}`);
      return { success: false, error: `Status: ${response.status}, Response: ${responseBody}` };
    }
    return { success: true };
  } catch (error) {
    logError(`Error in sendDeleteRequest:`, error);
    return { success: false, error: error.message };
  }
}