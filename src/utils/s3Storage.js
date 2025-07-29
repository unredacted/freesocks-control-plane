import { logError, logInfo } from './errorHandling.js';

/**
 * S3 storage utilities for uploading and managing dynamic access keys
 */

/**
 * Parse S3 provider configuration from environment variables
 */
export function parseS3Providers(env) {
  const providers = [];
  // In service worker syntax, we need to access globals directly
  const providerCount = parseInt(globalThis.VAR_S3_PROVIDER_COUNT || '0');
  
  logInfo(`parseS3Providers: VAR_S3_PROVIDER_COUNT = ${providerCount}`);
  
  for (let i = 1; i <= providerCount; i++) {
    const name = globalThis[`VAR_S3_PROVIDER_${i}_NAME`];
    const endpoint = globalThis[`VAR_S3_PROVIDER_${i}_ENDPOINT`];
    const bucket = globalThis[`VAR_S3_PROVIDER_${i}_BUCKET`];
    const publicUrl = globalThis[`VAR_S3_PROVIDER_${i}_PUBLIC_URL`];
    const region = globalThis[`VAR_S3_PROVIDER_${i}_REGION`] || 'us-east-1';
    // Secrets are accessed the same way as globals
    const accessKeyId = globalThis[`S3_PROVIDER_${i}_ACCESS_KEY_ID`];
    const secretAccessKey = globalThis[`S3_PROVIDER_${i}_SECRET_ACCESS_KEY`];
    
    if (name && endpoint && bucket && publicUrl && accessKeyId && secretAccessKey) {
      providers.push({
        name,
        endpoint,
        bucket,
        publicUrl,
        region,
        accessKeyId,
        secretAccessKey
      });
      logInfo(`S3 Provider ${i} configured: ${name} at ${endpoint}`);
    } else {
      // Log what's missing for debugging
      logError(`S3 Provider ${i} incomplete config:`, {
        name: !!name,
        endpoint: !!endpoint,
        bucket: !!bucket,
        publicUrl: !!publicUrl,
        accessKeyId: !!accessKeyId,
        secretAccessKey: !!secretAccessKey
      });
      logError(`Provider ${i} values:`, {
        name: name || 'MISSING',
        endpoint: endpoint || 'MISSING',
        bucket: bucket || 'MISSING',
        publicUrl: publicUrl || 'MISSING',
        accessKeyId: accessKeyId ? 'SET' : 'MISSING',
        secretAccessKey: secretAccessKey ? 'SET' : 'MISSING'
      });
    }
  }
  
  return providers;
}

/**
 * Generate S3 object path for a key
 */
export function generateS3Path(serverName, keyId) {
  // Generate cryptographically secure random string
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  const randomString = Array.from(randomBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return `keys/${serverName}-${randomString}/${keyId}`;
}

/**
 * Extract server name from WebSocket domain
 * e.g., "clinks-hoot-champed.freesocks.work" -> "clinks-hoot-champed"
 */
export function extractServerName(domain) {
  if (!domain) return 'unknown';
  const parts = domain.split('.');
  return parts[0] || 'unknown';
}

/**
 * Create AWS Signature V4 for S3 requests
 */
async function createAWSSignature(method, url, headers, credentials) {
  // Use the datetime from headers to ensure consistency
  const datetime = headers['x-amz-date'];
  const date = datetime.substring(0, 8);
  
  const parsedUrl = new URL(url);
  const canonicalUri = parsedUrl.pathname;
  const canonicalQueryString = parsedUrl.searchParams.toString();
  
  // Create canonical headers
  const signedHeaders = Object.keys(headers)
    .sort()
    .map(k => k.toLowerCase())
    .join(';');
  
  const canonicalHeaders = Object.keys(headers)
    .sort()
    .map(k => `${k.toLowerCase()}:${headers[k].trim()}`)
    .join('\n') + '\n';
  
  // Use the payload hash from headers to ensure consistency
  const payloadHashHex = headers['x-amz-content-sha256'];
  
  // Create canonical request
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHashHex
  ].join('\n');
  
  // Create string to sign
  const encoder = new TextEncoder();
  const requestHash = await crypto.subtle.digest('SHA-256', encoder.encode(canonicalRequest));
  const requestHashHex = Array.from(new Uint8Array(requestHash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  const credentialScope = `${date}/${credentials.region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    datetime,
    credentialScope,
    requestHashHex
  ].join('\n');
  
  // Create signing key
  const kDate = await hmac(`AWS4${credentials.secretAccessKey}`, date);
  const kRegion = await hmac(kDate, credentials.region);
  const kService = await hmac(kRegion, 's3');
  const kSigning = await hmac(kService, 'aws4_request');
  
  // Create signature
  const signature = await hmac(kSigning, stringToSign);
  const signatureHex = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  // Create authorization header
  const authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signatureHex}`;
  
  return {
    authorization
  };
}

/**
 * HMAC helper function
 */
async function hmac(key, data) {
  const encoder = new TextEncoder();
  const keyData = typeof key === 'string' ? encoder.encode(key) : key;
  const dataArray = encoder.encode(data);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  return await crypto.subtle.sign('HMAC', cryptoKey, dataArray);
}

/**
 * Upload content to S3 with retry logic
 */
export async function uploadToS3(provider, path, content, maxRetries = 3) {
  const url = `${provider.endpoint}/${provider.bucket}/${path}`;
  logInfo(`Uploading to ${provider.name}: ${url}`);
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logInfo(`Upload attempt ${attempt}/${maxRetries} to ${provider.name}`);
      
      // Calculate the payload hash first
      const encoder = new TextEncoder();
      const payloadData = encoder.encode(content);
      const payloadHash = await crypto.subtle.digest('SHA-256', payloadData);
      const payloadHashHex = Array.from(new Uint8Array(payloadHash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      
      const datetime = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
      const headers = {
        'Host': new URL(provider.endpoint).hostname,
        'Content-Type': 'text/plain',
        'x-amz-date': datetime,
        'x-amz-content-sha256': payloadHashHex
      };
      
      const signature = await createAWSSignature(
        'PUT',
        url,
        headers,
        {
          accessKeyId: provider.accessKeyId,
          secretAccessKey: provider.secretAccessKey,
          region: provider.region
        }
      );
      
      headers['Authorization'] = signature.authorization;
      
      const response = await fetch(url, {
        method: 'PUT',
        headers,
        body: content
      });
      
      logInfo(`S3 response status: ${response.status} ${response.statusText}`);
      
      if (response.ok) {
        const publicUrl = `${provider.publicUrl}/${path}`;
        logInfo(`Upload successful to ${provider.name}: ${publicUrl}`);
        return publicUrl;
      }
      
      const responseText = await response.text();
      logError(`S3 upload failed:`, {
        status: response.status,
        statusText: response.statusText,
        body: responseText,
        provider: provider.name,
        url: url
      });
      
      if (response.status < 500 && response.status !== 429) {
        // Don't retry on client errors (except rate limits)
        throw new Error(`S3 upload failed with status ${response.status}: ${responseText}`);
      }
      
      // Log retry attempt
      if (attempt < maxRetries) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
        logError(`S3 upload attempt ${attempt} failed, retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
      
    } catch (error) {
      if (attempt === maxRetries) {
        throw error;
      }
      logError(`S3 upload attempt ${attempt} error:`, error);
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  throw new Error(`Failed to upload to S3 after ${maxRetries} attempts`);
}

/**
 * Upload content to multiple S3 providers
 */
export async function uploadToMultipleS3(providers, serverName, keyId, content) {
  const path = generateS3Path(serverName, keyId);
  logInfo(`Generated S3 path: ${path}`);
  logInfo(`Uploading to ${providers.length} S3 providers...`);
  
  const uploadPromises = providers.map(provider => 
    uploadToS3(provider, path, content)
      .then(url => ({ success: true, url, provider: provider.name }))
      .catch(error => ({ success: false, error, provider: provider.name }))
  );
  
  const results = await Promise.all(uploadPromises);
  const successfulUploads = results.filter(r => r.success);
  
  if (successfulUploads.length === 0) {
    const errors = results.map(r => `${r.provider}: ${r.error?.message}`).join(', ');
    throw new Error(`All S3 uploads failed: ${errors}`);
  }
  
  // Log partial failures for monitoring
  const failedUploads = results.filter(r => !r.success);
  if (failedUploads.length > 0) {
    logError('Some S3 uploads failed:', failedUploads);
  }
  
  return successfulUploads.map(r => r.url);
}

/**
 * Delete object from S3
 */
export async function deleteFromS3(provider, path) {
  const url = `${provider.endpoint}/${provider.bucket}/${path}`;
  
  try {
    // For DELETE, we use empty body hash
    const emptyBodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const datetime = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    
    const headers = {
      'Host': new URL(provider.endpoint).hostname,
      'x-amz-date': datetime,
      'x-amz-content-sha256': emptyBodyHash
    };
    
    const signature = await createAWSSignature(
      'DELETE',
      url,
      headers,
      {
        accessKeyId: provider.accessKeyId,
        secretAccessKey: provider.secretAccessKey,
        region: provider.region
      }
    );
    
    headers['Authorization'] = signature.authorization;
    
    const response = await fetch(url, {
      method: 'DELETE',
      headers
    });
    
    if (!response.ok && response.status !== 404) {
      throw new Error(`S3 delete failed with status ${response.status}`);
    }
    
    return true;
  } catch (error) {
    logError(`Failed to delete from S3:`, error);
    return false;
  }
}

/**
 * Delete object from multiple S3 providers
 */
export async function deleteFromMultipleS3(providers, s3Urls) {
  const deletePromises = s3Urls.map(async (url) => {
    // Extract provider and path from URL
    const provider = providers.find(p => url.startsWith(p.publicUrl));
    if (!provider) {
      logError(`No provider found for URL: ${url}`);
      return false;
    }
    
    const path = url.replace(provider.publicUrl + '/', '');
    return await deleteFromS3(provider, path);
  });
  
  const results = await Promise.all(deletePromises);
  const successCount = results.filter(r => r).length;
  
  if (successCount < results.length) {
    logError(`Only ${successCount}/${results.length} S3 deletions succeeded`);
  }
  
  return successCount > 0;
}