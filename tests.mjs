import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import handler from './api/index.js';
import {fingerprint} from './api/n8n-management.js';

process.env.SUPABASE_URL='https://example.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY='test-service-role';
process.env.SESSION_SECRET='test-session-secret';
process.env.REVIEW_PASSWORD='test-review-password';
process.env.INGEST_TOKEN='test-ingest-token';
process.env.N8N_BASE_URL='https://lovespain.app.n8n.cloud';
process.env.N8N_API_KEY='test-api-key';

const token=Buffer.from(JSON.stringify({reviewer:'Test',exp:Date.now()+60000,csrf:'test-csrf'})).toString('base64url');
const signature=createHmac('sha256',process.env.SESSION_SECRET).update(token).digest('hex');
const cookie='ls_session='+token+'.'+signature;
async function request(action,authorized=true){
 const headers={host:'localhost:3000'};
 if(authorized)headers.cookie=cookie;
 let data;
 const res={
  statusCode:200,
  headers:{},
  setHeader(key,value){this.headers[key.toLowerCase()]=value},
  end(body){data=JSON.parse(body)}
 };
 await handler({url:'/api/index?action='+action,method:'GET',headers},res);
 return {status:res.statusCode,data};
}
const oldFetch=globalThis.fetch;
test.after(()=>{globalThis.fetch=oldFetch});

test('workflow inspection rejects anonymous callers before contacting n8n',async()=>{
 globalThis.fetch=()=>{throw Error('Unexpected upstream request')};
 const response=await request('n8n_inspect&id=abc',false);
 assert.equal(response.status,401);
});

test('workflow inspection validates IDs and prevents path injection',async()=>{
 globalThis.fetch=()=>{throw Error('Unexpected upstream request')};
 const response=await request('n8n_inspect&id=..%2Fcredentials');
 assert.equal(response.status,400);
});

test('workflow inspection returns graph metadata but no parameters or credentials',async()=>{
 let requested;
 globalThis.fetch=async(url,options)=>{
  requested={url:String(url),options};
  return {ok:true,status:200,json:async()=>({
   id:'abc',name:'EDEN BEACH - Workflow 3',active:true,updatedAt:'2026-11-20T00:00:00Z',
   nodes:[
    {id:'1',name:'Dropbox',type:'n8n-nodes-base.dropbox',typeVersion:1,parameters:{accessToken:'VERY_SECRET'},credentials:{dropboxOAuth2Api:{id:'private'}}},
    {id:'2',name:'Creatomate',type:'n8n-nodes-base.httpRequest',typeVersion:4,parameters:{url:'https://secret.example'},disabled:true}
   ],
   connections:{Dropbox:{main:[[{node:'Creatomate',type:'main',index:0}]]}},
   staticData:{private:'SENSITIVE'},pinData:{Dropbox:{email:'test@example.com'}}
  })};
 };
 const response=await request('n8n_inspect&id=abc');
 assert.equal(response.status,200);
 assert.equal(requested.url,'https://lovespain.app.n8n.cloud/api/v1/workflows/abc');
 assert.equal(requested.options.method,'GET');
 assert.equal(requested.options.headers['X-N8N-API-KEY'],'test-api-key');
 assert.equal(response.data.inspection.nodeCount,2);
 assert.equal(response.data.inspection.nodes[1].disabled,true);
 assert.deepEqual(response.data.inspection.connections[0],{from:'Dropbox',to:'Creatomate',output:'main',outputIndex:0,input:'main',inputIndex:0});
 const serialized=JSON.stringify(response.data);
 for(const secret of ['VERY_SECRET','SENSITIVE','test@example.com','secret.example','private']){
  assert.equal(serialized.includes(secret),false,'Leaked '+secret);
 }
 assert.match(serialized,/not a restorable workflow backup/i);
});

test('n8n inspection handles upstream failure without leaking key',async()=>{
 globalThis.fetch=async()=>({ok:false,status:403});
 const response=await request('n8n_inspect&id=abc');
 assert.equal(response.status,502);
 assert.equal(JSON.stringify(response.data).includes('test-api-key'),false);
});


test('execution health requests only metadata and excludes execution payloads',async()=>{
 let requested;
 globalThis.fetch=async(url,options)=>{
  requested={url:String(url),options};
  return {ok:true,status:200,json:async()=>({
   nextCursor:'older-executions',
   data:[{id:'501',workflowId:'w3',status:'error',startedAt:'2026-11-20T12:00:00Z',stoppedAt:'2026-11-20T12:01:00Z',finished:true,
    data:{resultData:{runData:{secret:'SENSITIVE_PAYLOAD'}}},workflowData:{nodes:[{parameters:{token:'DO_NOT_EXPOSE'}}]}}]
  })};
 };
 const response=await request('n8n_executions');
 assert.equal(response.status,200);
 assert.equal(requested.url,'https://lovespain.app.n8n.cloud/api/v1/executions?limit=100&includeData=false');
 assert.equal(requested.options.method,'GET');
 assert.equal(response.data.hasMore,true);
 assert.equal(response.data.executions.length,1);
 assert.deepEqual(response.data.executions[0],{
  id:'501',workflowId:'w3',status:'error',startedAt:'2026-11-20T12:00:00Z',stoppedAt:'2026-11-20T12:01:00Z',finished:true
 });
 assert.equal(JSON.stringify(response.data).includes('SENSITIVE_PAYLOAD'),false);
 assert.equal(JSON.stringify(response.data).includes('DO_NOT_EXPOSE'),false);
});


async function deploymentRequest(action,body,authorized=true,csrfValue='test-csrf'){
 const headers={host:'localhost:3000','x-csrf-token':csrfValue};
 if(authorized)headers.cookie=cookie;
 let data;
 const res={statusCode:200,headers:{},setHeader(key,value){this.headers[key.toLowerCase()]=value},end(raw){data=JSON.parse(raw)}};
 await handler({url:'/api/index?action='+action,method:'POST',headers,body},res);
 return {status:res.statusCode,data};
}
test('n8n deployment cannot be called by anonymous users',async()=>{
 globalThis.fetch=()=>{throw Error('Upstream access forbidden')};
 process.env.N8N_DEPLOY_ENABLED='true';
 process.env.N8N_DEPLOY_PASSWORD='a-long-and-separate-admin-password';
 const result=await deploymentRequest('n8n_deploy_apply',{adminPassword:process.env.N8N_DEPLOY_PASSWORD},false);
 assert.equal(result.status,401);
});
test('n8n deployment remains disabled unless feature flag is explicitly set',async()=>{
 globalThis.fetch=()=>{throw Error('Upstream access forbidden')};
 process.env.N8N_DEPLOY_ENABLED='false';
 const result=await deploymentRequest('n8n_deploy_plan',{adminPassword:'a-long-and-separate-admin-password'});
 assert.equal(result.status,503);
 assert.match(result.data.error,/disabled/);
});
test('n8n deployment requires separate administrator password and CSRF',async()=>{
 globalThis.fetch=()=>{throw Error('Upstream access forbidden')};
 process.env.N8N_DEPLOY_ENABLED='true';
 process.env.N8N_DEPLOY_PASSWORD='a-long-and-separate-admin-password';
 const missingCsrf=await deploymentRequest('n8n_deploy_plan',{adminPassword:process.env.N8N_DEPLOY_PASSWORD},true,'wrong');
 assert.equal(missingCsrf.status,403);
 const badPassword=await deploymentRequest('n8n_deploy_plan',{adminPassword:'incorrect'});
 assert.equal(badPassword.status,403);
 process.env.N8N_DEPLOY_PASSWORD=process.env.REVIEW_PASSWORD;
 const reusedPassword=await deploymentRequest('n8n_deploy_plan',{adminPassword:process.env.REVIEW_PASSWORD});
 assert.equal(reusedPassword.status,503);
 process.env.N8N_DEPLOY_PASSWORD='a-long-and-separate-admin-password';
});
test('n8n deployment rejects unapproved workflow IDs and arbitrary JSON without upstream writes',async()=>{
 globalThis.fetch=()=>{throw Error('Upstream access forbidden')};
 process.env.N8N_DEPLOY_ENABLED='true';
 process.env.N8N_DEPLOY_PASSWORD='a-long-and-separate-admin-password';
 const invalid=await deploymentRequest('n8n_deploy_apply',{id:'arbitrary',adminPassword:process.env.N8N_DEPLOY_PASSWORD,original:{},candidate:{}});
 assert.equal(invalid.status,400);
 const fake={id:'j0sOv1mefGZEduOz',name:'Fake',nodes:[],connections:{},settings:{}};
 const notApproved=await deploymentRequest('n8n_deploy_apply',{id:fake.id,adminPassword:process.env.N8N_DEPLOY_PASSWORD,original:fake,candidate:fake});
 assert.equal(notApproved.status,400);
});

test('workflow fingerprint ignores JSON property ordering but detects node changes',()=>{
 const a={name:'Example',nodes:[{id:'1',name:'Node',type:'n8n-nodes-base.code',parameters:{jsCode:'return [];'}}],connections:{},settings:{executionOrder:'v1'}};
 const b={settings:{executionOrder:'v1'},connections:{},nodes:[{parameters:{jsCode:'return [];'},type:'n8n-nodes-base.code',name:'Node',id:'1'}],name:'Example'};
 assert.equal(fingerprint(a),fingerprint(b));
 b.nodes[0].parameters.jsCode='return [1];';
 assert.notEqual(fingerprint(a),fingerprint(b));
});

test('MCP OAuth metadata survives dashboard API routing fallback',async()=>{
 process.env.MCP_PUBLIC_ORIGIN='https://lovespain.vercel.app';
 process.env.MCP_OAUTH_SECRET='test-only-mcp-oauth-secret-32-chars';
 process.env.N8N_ADMIN_PASSWORD='test-only-admin-password-32-chars';
 process.env.N8N_BACKUP_KEY=Buffer.alloc(32,3).toString('base64');
 async function routed(url,method='GET'){
  let raw='',status=200,headers={};
  const res={set statusCode(v){status=v},get statusCode(){return status},setHeader(k,v){headers[k.toLowerCase()]=v},end(v=''){raw=v}};
  await handler({url,method,headers:{host:'lovespain.vercel.app'}},res);
  return {status,headers,body:JSON.parse(raw)};
 }
 const viaIndex=await routed('/api/index?mode=oauth_metadata');
 assert.equal(viaIndex.status,200);
 assert.equal(viaIndex.body.authorization_endpoint,'https://lovespain.vercel.app/api/mcp?mode=authorize');
 assert.equal(viaIndex.body.registration_endpoint,'https://lovespain.vercel.app/api/mcp?mode=register');
 const direct=await routed('/api/mcp?mode=oauth_metadata&utm_source=chatgpt.com');
 assert.equal(direct.status,200);
 assert.deepEqual(direct.body,viaIndex.body);
 const discovery=await routed('/.well-known/oauth-authorization-server');
 assert.equal(discovery.status,200);
 assert.deepEqual(discovery.body,viaIndex.body);
 const protectedDiscovery=await routed('/.well-known/oauth-protected-resource/api/mcp');
 assert.equal(protectedDiscovery.status,200);
 assert.equal(protectedDiscovery.body.resource,'https://lovespain.vercel.app/api/mcp');
 const unauthenticated=await routed('/api/mcp','POST');
 assert.equal(unauthenticated.status,401);
 assert.match(unauthenticated.headers['www-authenticate'],/oauth-protected-resource/);
});

test('MCP configuration diagnostics require reviewer session and never return secret values',async()=>{
 const anonymous=await request('mcp_diagnostics',false);
 assert.equal(anonymous.status,401);
 const saved={
  MCP_PUBLIC_ORIGIN:process.env.MCP_PUBLIC_ORIGIN,
  MCP_OAUTH_SECRET:process.env.MCP_OAUTH_SECRET,
  N8N_ADMIN_PASSWORD:process.env.N8N_ADMIN_PASSWORD,
  N8N_BACKUP_KEY:process.env.N8N_BACKUP_KEY
 };
 try{
  process.env.MCP_PUBLIC_ORIGIN='https://lovespain.vercel.app';
  process.env.MCP_OAUTH_SECRET='a'.repeat(64);
  process.env.N8N_ADMIN_PASSWORD='too-short';
  process.env.N8N_BACKUP_KEY=Buffer.alloc(32,7).toString('base64');
  const bad=await request('mcp_diagnostics');
  assert.equal(bad.status,200);
  assert.equal(bad.data.ready,false);
  assert.equal(bad.data.checks.N8N_ADMIN_PASSWORD,false);
  assert.equal(bad.data.checks.N8N_BACKUP_KEY,true);
  assert.equal(JSON.stringify(bad.data).includes('too-short'),false);
  process.env.N8N_ADMIN_PASSWORD='b'.repeat(64);
  const good=await request('mcp_diagnostics');
  assert.equal(good.data.ready,true);
  assert.equal(Object.values(good.data.checks).every(Boolean),true);
  process.env.N8N_BACKUP_KEY='invalid';
  const invalidBackup=await request('mcp_diagnostics');
  assert.equal(invalidBackup.data.ready,false);
  assert.equal(invalidBackup.data.checks.N8N_BACKUP_KEY,false);
 }finally{
  for(const [key,value] of Object.entries(saved)){
   if(value===undefined)delete process.env[key];
   else process.env[key]=value;
  }
 }
});

test('OAuth progress diagnostics are reviewer-only and never reveal codes or tokens',async()=>{
 const anon=await request('mcp_oauth_diagnostics',false);
 assert.equal(anon.status,401);
 const originalFetch=globalThis.fetch;
 globalThis.fetch=async(url,options)=>{
  const u=new URL(url);
  assert.equal(u.hostname,'example.supabase.co');
  assert.equal(options.headers.apikey,'test-service-role');
  assert.equal(u.searchParams.get('limit'),'1');
  if(u.pathname.endsWith('/ls_mcp_auth_codes')){
   assert.equal(u.searchParams.get('select'),'created_at,used_at');
   return {ok:true,status:200,json:async()=>[{created_at:'2026-11-20T10:00:00Z',used_at:null,code_hash:'PRIVATE_CODE_HASH'}]};
  }
  if(u.pathname.endsWith('/ls_mcp_tokens')){
   assert.equal(u.searchParams.get('select'),'created_at');
   return {ok:true,status:200,json:async()=>[{created_at:'2026-11-20T10:01:00Z',access_hash:'PRIVATE_ACCESS_HASH'}]};
  }
  throw Error('Unexpected table');
 };
 try{
  const response=await request('mcp_oauth_diagnostics');
  assert.equal(response.status,200);
  assert.deepEqual(response.data,{
   lastAuthorizationAt:'2026-11-20T10:00:00Z',
   lastAuthorizationCodeExchanged:false,
   lastTokenIssuedAt:'2026-11-20T10:01:00Z'
  });
  assert.equal(JSON.stringify(response.data).includes('PRIVATE_'),false);
 }finally{globalThis.fetch=originalFetch;}
});
