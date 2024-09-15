import { withErrorHandling } from './utils/errorHandling.js';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduledEvent(event));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  switch (path) {
    case '/get':
      const getModule = await import('./handlers/get.js');
      return withErrorHandling(getModule.handleRequest)(request);
    case '/delete':
      const deleteModule = await import('./handlers/delete.js');
      return withErrorHandling(deleteModule.handleRequest)(request, false);
    case '/update':
      const updateModule = await import('./handlers/update.js');
      return withErrorHandling(updateModule.handleRequest)(request, false);
    case '/list':
      const listModule = await import('./handlers/list.js');
      return withErrorHandling(listModule.handleRequest)(request);
    default:
      return new Response('Not found', { status: 404 });
  }
}

async function handleScheduledEvent(event) {
  console.log('Scheduled event triggered');
  
  try {
// Temporarily disable delete crons while update script gathers data    
//    const deleteModule = await import('./handlers/delete.js');
//    await deleteModule.handleRequest(null, true);
    
    const updateModule = await import('./handlers/update.js');
    await updateModule.handleRequest(null, true);
    
    console.log('Scheduled tasks completed successfully');
  } catch (error) {
    console.error('Error in scheduled tasks:', error);
  }
}