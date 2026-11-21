import http from 'node:http';
import fs from 'node:fs';
import handler from './api/index.js';

function parseBody(raw, contentType) {
  if (!raw) return {};
  const type = String(contentType || '').split(';', 1)[0].trim().toLowerCase();
  if (type === 'application/x-www-form-urlencoded') {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  if (type === 'application/json' || type === 'application/json-rpc' || type === '') {
    return JSON.parse(raw);
  }
  throw new Error('Unsupported content type');
}

http.createServer(async (req, res) => {
  if (req.url.startsWith('/api')) {
    let raw = '';
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 2000000) {
        res.writeHead(413);
        return res.end();
      }
    }
    try {
      req.body = parseBody(raw, req.headers['content-type']);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify({ error: 'invalid_request', error_description: 'Malformed or unsupported request body' }));
    }
    return handler(req, res);
  }
  if (req.url === '/' || req.url === '/index.html') {
    res.setHeader('Content-Type', 'text/html');
    res.end(fs.readFileSync(new URL('./index.html', import.meta.url)));
  } else {
    res.writeHead(404);
    res.end();
  }
}).listen(process.env.PORT || 3000, () => console.log('LoveSpain dashboard listening'));
