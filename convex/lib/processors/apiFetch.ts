/** Credential-bearing processor requests must end at the configured API. */
export function fetchProcessorApi(url: string, init: RequestInit): Promise<Response> {
  return fetch(url, { ...init, redirect: 'error' });
}
