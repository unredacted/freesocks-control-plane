import { withErrorHandling } from './utils/errorHandling.js';

// For compatibility with service worker syntax
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduledEvent(event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const env = event.env || {};

  switch (path) {
    case '/get':
      const getModule = await import('./handlers/get.js');
      return withErrorHandling(getModule.handleRequest)(request, env);
    case '/delete':
      const deleteModule = await import('./handlers/delete.js');
      return withErrorHandling(deleteModule.handleRequest)(request, false, env);
    case '/update':
      const updateModule = await import('./handlers/update.js');
      return withErrorHandling(updateModule.handleRequest)(request, false, env);
    case '/list':
      const listModule = await import('./handlers/list.js');
      return withErrorHandling(listModule.handleRequest)(request, env);
    default:
      return new Response('Not found', { status: 404 });
  }
}

async function handleScheduledEvent(event) {
  console.log('Scheduled event triggered');
  const env = event.env || {};
  
  try {
// Temporarily disable delete crons while update script gathers data    
//    const deleteModule = await import('./handlers/delete.js');
//    await deleteModule.handleRequest(null, true, env);
    
    const updateModule = await import('./handlers/update.js');
    await updateModule.handleRequest(null, true, env);
    
    console.log('Scheduled tasks completed successfully');
  } catch (error) {
    console.error('Error in scheduled tasks:', error);
  }
}