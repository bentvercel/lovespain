import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

test('production server accepts OAuth form token POST without Invalid JSON', async () => {
  const port = 20000 + Math.floor(Math.random() * 30000);
  const child = spawn(process.execPath, ['server.js'], {
    env: {
      ...process.env, PORT: String(port),
      MCP_PUBLIC_ORIGIN: 'https://lovespain.vercel.app',
      MCP_OAUTH_SECRET: randomBytes(32).toString('hex'),
      N8N_ADMIN_PASSWORD: randomBytes(32).toString('hex'),
      N8N_BACKUP_KEY: randomBytes(32).toString('base64'),
      N8N_BASE_URL: 'https://lovespain.app.n8n.cloud',
      N8N_API_KEY: 'test-placeholder',
      SUPABASE_URL: 'https://example.supabase.co',
      SUPABASE_SERVICE_ROLE_KEY: 'test-placeholder'
    },
    stdio: 'ignore'
  });
  try {
    let response;
    for (let i = 0; i < 50; i++) {
      try {
        response = await fetch('http://127.0.0.1:' + port + '/api/mcp?mode=token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'invalid-client', code: 'invalid-code' })
        });
        break;
      } catch {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    assert.ok(response, 'Server failed to start');
    assert.equal(response.status, 400);
    assert.match(response.headers.get('content-type') || '', /application\/json/);
    assert.deepEqual(await response.json(), { error: 'invalid_client' });
  } finally {
    child.kill();
  }
});
