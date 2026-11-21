import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import handler from './api/ghl-mcp.js';

const keys=['MCP_PUBLIC_ORIGIN','MCP_OAUTH_SECRET','GHL_ADMIN_PASSWORD','GHL_API_TOKEN','GHL_LOCATION_ID','GHL_API_BASE_URL','SUPABASE_URL','SUPABASE_SERVICE_ROLE_KEY'];
const previous=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
function setup(){
 Object.assign(process.env,{
  MCP_PUBLIC_ORIGIN:'https://lovespain.vercel.app',
  MCP_OAUTH_SECRET:'test-secret-should-be-at-least-32-characters',
  GHL_ADMIN_PASSWORD:'test-admin-password-at-least-20-characters',
  GHL_API_TOKEN:'test-token',
  GHL_LOCATION_ID:'test-location',
  GHL_API_BASE_URL:'https://services.leadconnectorhq.com',
  SUPABASE_URL:'https://example.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY:'test-service-key'
 });
}
async function request(url,method='GET',body={},headers={}){
 const req={url,method,body,headers};
 const res=new EventEmitter();res.headers={};res.statusCode=200;
 res.setHeader=(key,value)=>{res.headers[key.toLowerCase()]=value};
 res.end=value=>{res.payload=value;res.emit('done')};
 await handler(req,res);
 return {status:res.statusCode,headers:res.headers,body:JSON.parse(res.payload||'{}')};
}
test('GHL MCP has separate discovery and read-only scope',async()=>{
 setup();
 const m=await request('/api/ghl-mcp?mode=oauth_metadata');
 assert.equal(m.status,200);
 assert.deepEqual(m.body.scopes_supported,['ghl:read']);
 assert.match(m.body.authorization_endpoint,/\/api\/ghl-mcp\?mode=authorize$/);
 const p=await request('/api/ghl-mcp?mode=protected_metadata');
 assert.equal(p.status,200);
 assert.equal(p.body.resource,'https://lovespain.vercel.app/api/ghl-mcp');
});
test('GHL MCP rejects unauthenticated tool calls without contacting GHL',async()=>{
 setup();
 const r=await request('/api/ghl-mcp','POST',{jsonrpc:'2.0',id:1,method:'tools/list'});
 assert.equal(r.status,401);
 assert.equal(r.body.error,'unauthorized');
});
test('GHL MCP requires its own strong administrator password',async()=>{
 setup();
 process.env.GHL_ADMIN_PASSWORD='short';
 const r=await request('/api/ghl-mcp?mode=oauth_metadata');
 assert.equal(r.status,503);
});
test('GHL OAuth refuses malformed registrations',async()=>{
 setup();
 const r=await request('/api/ghl-mcp?mode=register','POST',{redirect_uris:['https://evil.example/callback']});
 assert.equal(r.status,400);
 assert.equal(r.body.error,'invalid_client_metadata');
});
test.after(()=>{for(const k of keys){if(previous[k]===undefined)delete process.env[k];else process.env[k]=previous[k]}});
