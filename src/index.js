addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
  })
  
  async function handleRequest(request) {
    const url = new URL(request.url)
    const path = url.pathname
  
    if (path === '/get') {
      const getModule = await import('./get.js')
      return getModule.handleRequest(request)
    } else if (path === '/delete') {
      const deleteModule = await import('./delete.js')
      return deleteModule.handleRequest(request)
    } else {
      return new Response('Not found', { status: 404 })
    }
  }
  