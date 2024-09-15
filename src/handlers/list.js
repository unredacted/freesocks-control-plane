import { AUTH_TOKEN, ACCESS_KEYS_NAMESPACE } from '../config/constants.js';
import { verifyAuth } from '../utils/authentication.js';
import { handleError, logError } from '../utils/errorHandling.js';

export async function handleRequest(request) {
  console.log('List request received');
  const isAuthorized = await verifyAuth(request, AUTH_TOKEN);
  if (!isAuthorized) {
    logError('Unauthorized access attempt to list keys');
    return handleError('Unauthorized', 401);
  }

  try {
    const filters = getFiltersFromHeaders(request.headers);
    const { keys, counts } = await listKeys(filters);
    return new Response(JSON.stringify({ keys, counts }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return handleError('Error listing keys', 500, error);
  }
}

function getFiltersFromHeaders(headers) {
  return {
    currentlyConnected: headers.get('X-Filter-Connected') === 'true',
    createdOn: headers.get('X-Filter-Created-On'),
    createdInMonth: headers.get('X-Filter-Created-In-Month'),
    lastSeenOn: headers.get('X-Filter-Last-Seen-On'),
    lastSeenInMonth: headers.get('X-Filter-Last-Seen-In-Month')
  };
}

async function listKeys(filters) {
  const keys = {};
  const counts = {
    total: 0,
    currentlyConnected: 0,
    createdOnDate: 0,
    createdInMonth: 0,
    lastSeenOnDate: 0,
    lastSeenInMonth: 0
  };
  let cursor = undefined;
  let done = false;

  while (!done) {
    try {
      const listResult = await ACCESS_KEYS_NAMESPACE.list({ cursor });
      for (const key of listResult.keys) {
        await processKey(key, keys, counts, filters);
      }
      cursor = listResult.cursor;
      done = listResult.list_complete;
    } catch (error) {
      logError('Error listing keys:', error);
      throw new Error(`Failed to list keys: ${error.message}`);
    }
  }

  return { keys, counts };
}

async function processKey(key, keys, counts, filters) {
  try {
    const value = await ACCESS_KEYS_NAMESPACE.get(key.name);
    const keyData = JSON.parse(value);
    counts.total++;

    if (applyFilters(keyData, filters)) {
      keys[key.name] = keyData;
      updateCounts(keyData, counts);
    }
  } catch (error) {
    logError(`Error processing key ${key.name}:`, error);
    keys[key.name] = { error: `Failed to parse: ${error.message}` };
  }
}

function applyFilters(keyData, filters) {
  if (filters.currentlyConnected && !keyData.currentlyConnected) return false;
  if (filters.createdOn && !isOnDate(keyData.creationTime, filters.createdOn)) return false;
  if (filters.createdInMonth && !isInMonth(keyData.creationTime, filters.createdInMonth)) return false;
  if (filters.lastSeenOn && !isOnDate(keyData.lastSeen, filters.lastSeenOn)) return false;
  if (filters.lastSeenInMonth && !isInMonth(keyData.lastSeen, filters.lastSeenInMonth)) return false;
  return true;
}

function updateCounts(keyData, counts) {
  if (keyData.currentlyConnected) counts.currentlyConnected++;
  // Add other count updates as needed
}

function isOnDate(timestamp, targetDate) {
  if (!timestamp) return false;
  const date = new Date(timestamp);
  const target = new Date(targetDate);
  return date.toDateString() === target.toDateString();
}

function isInMonth(timestamp, targetMonth) {
  if (!timestamp) return false;
  const date = new Date(timestamp);
  const [year, month] = targetMonth.split('-');
  return date.getFullYear() === parseInt(year) && date.getMonth() === parseInt(month) - 1;
}