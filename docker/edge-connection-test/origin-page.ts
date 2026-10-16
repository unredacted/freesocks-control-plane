/**
 * The web page a member fetches through the tunnel in the edge connection
 * test. It sits on a network only the relay nodes join, so receiving its
 * per-run token is proof the request crossed a node; the requested path is
 * echoed back so every fetch can carry its own nonce. `/generate_204` is the
 * neutral 204 FCP's L7 front proof fetches through the front (in production a
 * public page; here this one, the only page the nodes can reach).
 */
const token = process.env.EC_ORIGIN_TOKEN;
if (!token) throw new Error('EC_ORIGIN_TOKEN is required');

Bun.serve({
  port: 80,
  hostname: '0.0.0.0',
  fetch(req, server) {
    if (new URL(req.url).pathname === '/generate_204') return new Response(null, { status: 204 });
    return Response.json({
      token,
      path: new URL(req.url).pathname,
      peer: server.requestIP(req)?.address ?? null,
    });
  },
});
