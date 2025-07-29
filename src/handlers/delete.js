import {
  AUTH_TOKEN,
  ACCESS_KEYS_NAMESPACE,
  API_ENDPOINTS_NAMESPACE,
  EXPIRATION_DAYS,
  MAX_RETRIES,
  RETRY_DELAY,
  STATE_NAMESPACE,
  MAX_KEYS_PER_RUN,
  DELETE_DRY_RUN,
  DELETE_S3_OBJECTS
} from '../config/constants.js';
import { verifyAuth } from '../utils/authentication.js';
import { handleError, logError, logInfo } from '../utils/errorHandling.js';
import { parseS3Providers, deleteFromMultipleS3 } from '../utils/s3Storage.js';

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

export async function handleRequest(request, isCronTriggered, env) {
  logInfo(`handleRequest triggered, isCronTriggered: ${isCronTriggered}`);

  // Default to dry run mode unless explicitly disabled
  const isDryRun = request ? 
    (request.headers.get('X-Dry-Run') !== 'false') : 
    DELETE_DRY_RUN;
  
  const targetServer = request && request.headers.get('X-Target-Server');
  const targetKey = request && request.headers.get('X-Target-Key');
  
  // Parse S3 providers for deletion
  const s3Providers = DELETE_S3_OBJECTS ? parseS3Providers(env) : [];

  if (!isCronTriggered) {
    const isAuthorized = await verifyAuth(request, AUTH_TOKEN);
    if (!isAuthorized) {
      return handleError('Unauthorized', 401);
    }
  }

  try {
    let deleteResults;
    if (targetKey) {
      deleteResults = await processKeys([targetKey], isDryRun, targetServer, s3Providers);
    } else if (targetServer) {
      deleteResults = await processKeysForServer(targetServer, isDryRun, s3Providers);
    } else {
      const startCursor = await retry(() => STATE_NAMESPACE.get(DELETE_CURSOR_KEY));
      deleteResults = await processAllKeys(isDryRun, startCursor, s3Providers);
      
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

async function processKeys(keys, isDryRun, targetServer, s3Providers) {
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

      await processKeyForDeletion(key, JSON.parse(keyData), isDryRun, deleteResults, s3Providers);
    } catch (error) {
      logError(`Error processing key ${key}:`, error);
      deleteResults.errors.push(`Error processing key ${key}: ${error.message}`);
    }
  }

  return deleteResults;
}

async function processKeysForServer(targetServer, isDryRun, s3Providers) {
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
        await processKeyForDeletion(key.name, keyData, isDryRun, deleteResults, s3Providers);
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

async function processAllKeys(isDryRun, startCursor, s3Providers) {
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
      const { processedKeys, nextCursor } = await processKeysForServer(hostname.name, isDryRun, s3Providers);
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

async function processKeyForDeletion(keyName, keyData, isDryRun, deleteResults, s3Providers) {
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
    deletionTime: keyData.deletionTime,
    isWebSocket: keyData.isWebSocket || false,
    s3Paths: keyData.s3Paths || []
  };

  const shouldDelete = daysSinceLastSeen > EXPIRATION_DAYS && !keyData.currentlyConnected;

  if (shouldDelete) {
    keyInfo.status = isDryRun ? 'Would delete' : 'Deleted';
    keyInfo.reason = `Last seen ${daysSinceLastSeen.toFixed(2)} days ago (> ${EXPIRATION_DAYS} days), not currently connected`;

    if (!isDryRun) {
      try {
        const [hostname, accessKey] = keyName.split('-key-');
        const endpointDataStr = await retry(() => API_ENDPOINTS_NAMESPACE.get(hostname));

        if (!endpointDataStr) {
          throw new Error(`API endpoint not found for hostname: ${hostname}`);
        }
        
        let apiEndpointUrl;
        try {
          const endpointData = JSON.parse(endpointDataStr);
          apiEndpointUrl = endpointData.apiUrl;
        } catch (e) {
          // Backward compatibility
          apiEndpointUrl = endpointDataStr;
        }

        const deleteResult = await sendDeleteRequest(`${apiEndpointUrl}/access-keys/${accessKey}`);
        
        if (deleteResult.success) {
          // Delete S3 objects if configured and present
          if (DELETE_S3_OBJECTS && keyData.s3Paths && keyData.s3Paths.length > 0 && s3Providers.length > 0) {
            try {
              const s3DeleteSuccess = await deleteFromMultipleS3(s3Providers, keyData.s3Paths);
              keyInfo.s3DeleteStatus = s3DeleteSuccess ? 'Deleted' : 'Partial failure';
              logInfo(`S3 deletion for key ${keyName}: ${keyInfo.s3DeleteStatus}`);
            } catch (s3Error) {
              logError(`S3 deletion error for key ${keyName}:`, s3Error);
              keyInfo.s3DeleteStatus = 'Failed';
              keyInfo.s3DeleteError = s3Error.message;
            }
          } else if (keyData.s3Paths && keyData.s3Paths.length > 0) {
            keyInfo.s3DeleteStatus = isDryRun ? 'Would delete' : 'Skipped (S3 deletion disabled)';
          }
          
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