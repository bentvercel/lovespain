import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import handler from './api/mcp.js';

Object.assign(process.env,{
 MCP_PUBLIC_ORIGIN:'https://lovespain.vercel.app',
 MCP_OAUTH_SECRET:'test-only-'.repeat(8),
 N8N_ADMIN_PASSWORD:'test-only-admin-password-long-enough',
 N8N_BACKUP_KEY:randomBytes(32).toString('base64'),
 N8N_BASE_URL:'https://lovespain.app.n8n.cloud',
 N8N_API_KEY:'PRIVATE_N8N_KEY',
 SUPABASE_URL:'https://example.supabase.co',
 SUPABASE_SERVICE_ROLE_KEY:'PRIVATE_SUPABASE_KEY'
});
const db={ls_mcp_auth_codes:[],ls_mcp_tokens:[],ls_n8n_change_sets:[],ls_n8n_admin_audit:[]};
const original={id:'safe-workflow',name:'LoveSpain Approval',active:true,versionId:'v1',updatedAt:'2026-11-20',nodes:[
 {id:'n1',name:'Input',type:'n8n-nodes-base.executeWorkflowTrigger',parameters:{}},
 {id:'n2',name:'Gate',type:'n8n-nodes-base.code',parameters:{jsCode:'return [{json:{ok:false}}];',password:'NEVER_LEAK_THIS'},credentials:{httpHeaderAuth:{id:'SECRET_CREDENTIAL_ID',name:'Private'}}}
],connections:{Input:{main:[[{node:'Gate',type:'main',index:0}]]}},settings:{executionOrder:'v1'}};
let live=structuredClone(original),writes=0,reads=0;
const previousFetch=globalThis.fetch;
function clone(v){return structuredClone(v);}
function match(row,params){
 for(const [key,value] of params){
  if(['select','order','limit'].includes(key))continue;
  if(value==='is.null'&&row[key]!=null)return false;
  if(value.startsWith('eq.')&&String(row[key])!==decodeURIComponent(value.slice(3)))return false;
 }
 return true;
}
globalThis.fetch=async(url,opts={})=>{
 const u=new URL(String(url));
 if(u.hostname==='lovespain.app.n8n.cloud'){
  assert.equal(opts.headers['X-N8N-API-KEY'],'PRIVATE_N8N_KEY');
  if(u.pathname==='/api/v1/workflows/safe-workflow'){
   if(opts.method==='GET'){reads++;return {ok:true,status:200,json:async()=>clone(live)};}
   if(opts.method==='PUT'){writes++;const payload=JSON.parse(opts.body);live={...clone(payload),id:'safe-workflow',active:true,versionId:'v'+(writes+1),updatedAt:new Date().toISOString()};return {ok:true,status:200,json:async()=>clone(live)};}
  }
  if(u.pathname==='/api/v1/workflows')return {ok:true,status:200,json:async()=>({data:[{id:live.id,name:live.name,active:live.active,versionId:live.versionId}],nextCursor:null})};
  throw Error('Unexpected n8n route '+u.pathname);
 }
 if(u.hostname==='example.supabase.co'){
  const table=u.pathname.split('/rest/v1/')[1],rows=db[table];
  assert.ok(rows,'Unexpected Supabase table '+table);
  const selected=rows.filter(r=>match(r,u.searchParams));
  const method=opts.method||'GET';
  if(method==='GET')return {ok:true,status:200,json:async()=>clone(selected.slice(0,Number(u.searchParams.get('limit')||100)))};
  const data=JSON.parse(opts.body);
  if(method==='POST'){rows.push({...clone(data),created_at:new Date().toISOString()});return {ok:true,status:201,json:async()=>[clone(rows.at(-1))]};}
  if(method==='PATCH'){selected.forEach(r=>Object.assign(r,clone(data)));return {ok:true,status:200,json:async()=>clone(selected)};}
 }
 throw Error('Unexpected external request: '+url);
};
test.after(()=>{globalThis.fetch=previousFetch});
async function req(url,method='GET',body,headers={}){
 let raw='',status=200,replyHeaders={};
 const res={set statusCode(v){status=v},get statusCode(){return status},setHeader(k,v){replyHeaders[k.toLowerCase()]=v},end(v=''){raw=v}};
 await handler({url,method,body,headers:{host:'lovespain.vercel.app',...headers}},res);
 let data;try{data=JSON.parse(raw)}catch{data=raw}
 return {status,headers:replyHeaders,data};
}
const rpc=(token,id,method,params={})=>req('/api/mcp','POST',{jsonrpc:'2.0',id,method,params},{authorization:'Bearer '+token});
let access,clientId;
test('OAuth discovery is configured and refuses anonymous MCP calls',async()=>{
 const metadata=await req('/api/mcp?mode=oauth_metadata');
 assert.equal(metadata.status,200);
 assert.equal(metadata.data.token_endpoint,'https://lovespain.vercel.app/api/mcp?mode=token');
 const unauth=await req('/api/mcp','POST',{jsonrpc:'2.0',id:1,method:'tools/list'});
 assert.equal(unauth.status,401);
 assert.match(unauth.headers['www-authenticate'],/oauth-protected-resource/);
});
test('OAuth registration rejects external redirect URIs',async()=>{
 const r=await req('/api/mcp?mode=register','POST',{redirect_uris:['https://evil.example/callback']});
 assert.equal(r.status,400);
});
test('OAuth PKCE login issues a bearer token only after separate admin authorization',async()=>{
 const reg=await req('/api/mcp?mode=register','POST',{redirect_uris:['https://chatgpt.com/connector_platform_oauth_redirect']});
 assert.equal(reg.status,201);clientId=reg.data.client_id;
 const verifier='a'.repeat(64),challenge=createHash('sha256').update(verifier).digest('base64url');
 const fields={client_id:clientId,redirect_uri:'https://chatgpt.com/connector_platform_oauth_redirect',response_type:'code',code_challenge:challenge,code_challenge_method:'S256',state:'random-state-1234',scope:'n8n:manage'};
 const login=await req('/api/mcp?mode=authorize','GET');
 assert.equal(login.status,400);
 const browserForm=await req('/api/mcp?mode=authorize&'+new URLSearchParams(fields).toString(),'GET');
 assert.equal(browserForm.status,200);
 assert.ok(browserForm.data.includes("'Content-Type':'application/json'"));
 assert.ok(browserForm.data.includes('window.location.assign'));
 assert.match(browserForm.headers['content-security-policy'],/script-src 'nonce-/);
 assert.match(browserForm.headers['content-security-policy'],/connect-src 'self'/);
 assert.equal(browserForm.data.includes(process.env.N8N_ADMIN_PASSWORD),false);
 const denied=await req('/api/mcp?mode=authorize','POST',{...fields,password:'wrong'},{origin:'https://lovespain.vercel.app'});
 assert.equal(denied.status,401);
 assert.match(denied.headers['content-type'],/text\/html/);
 assert.match(denied.data,/password was not accepted/);
 assert.equal(db.ls_n8n_admin_audit.at(-1).details.stage,'password_rejected');
 assert.equal(JSON.stringify(db.ls_n8n_admin_audit).includes('wrong'),false);
 const jsonHeaders={origin:'https://lovespain.vercel.app',accept:'application/json','content-type':'application/json'};
 const deniedJson=await req('/api/mcp?mode=authorize','POST',JSON.stringify({...fields,password:'wrong'}),jsonHeaders);
 assert.equal(deniedJson.status,401);
 assert.ok(deniedJson.headers['content-type'].includes('application/json'));
 assert.match(deniedJson.data.error,/password was not accepted/);
 const accepted=await req('/api/mcp?mode=authorize','POST',JSON.stringify({...fields,password:process.env.N8N_ADMIN_PASSWORD}),jsonHeaders);
 assert.equal(accepted.status,200);
 assert.equal(db.ls_n8n_admin_audit.at(-1).details.stage,'code_issued');
 assert.equal(accepted.headers.location,undefined);
 const code=new URL(accepted.data.redirect_to).searchParams.get('code');
 const bad=await req('/api/mcp?mode=token','POST',{grant_type:'authorization_code',client_id:clientId,redirect_uri:fields.redirect_uri,code,code_verifier:'b'.repeat(64)});
 assert.equal(bad.status,400);
 const tok=await req('/api/mcp?mode=token','POST',Buffer.from(new URLSearchParams({grant_type:'authorization_code',client_id:clientId,redirect_uri:fields.redirect_uri,code,code_verifier:verifier}).toString()));
 assert.equal(tok.status,200);access=tok.data.access_token;
 assert.equal(typeof access,'string');
 const replay=await req('/api/mcp?mode=token','POST',{grant_type:'authorization_code',client_id:clientId,redirect_uri:fields.redirect_uri,code,code_verifier:verifier});
 assert.equal(replay.status,400);
 assert.equal(JSON.stringify(db).includes(access),false,'Only token hashes may be stored');
});
test('MCP tools are available and read hides credentials and embedded secret fields',async()=>{
 const tools=await rpc(access,1,'tools/list');
 assert.equal(tools.status,200);
 assert.ok(tools.data.result.tools.some(t=>t.name==='n8n_stage_update'));
 const result=await rpc(access,2,'tools/call',{name:'n8n_inspect_workflow',arguments:{workflowId:'safe-workflow'}});
 assert.equal(result.status,200);
 const content=result.data.result.content[0].text;
 assert.ok(!content.includes('SECRET_CREDENTIAL_ID'));
 assert.ok(!content.includes('NEVER_LEAK_THIS'));
 assert.equal(JSON.parse(content).candidate.nodes[1].parameters.password,'[REDACTED]');
});
test('Staging creates encrypted backup, requires exact confirmation, saves and verifies, then rolls back',async()=>{
 const candidate=clone(original);candidate.nodes[1].parameters.jsCode='return [{json:{ok:true}}];';
 delete candidate.nodes[1].credentials;
 candidate.nodes[1].parameters.password='[REDACTED]';
 const staged=await rpc(access,3,'tools/call',{name:'n8n_stage_update',arguments:{workflowId:'safe-workflow',candidate}});
 assert.equal(staged.status,200);
 const s=JSON.parse(staged.data.result.content[0].text);
 assert.equal(s.status,'STAGED_NOT_APPLIED');
 assert.equal(writes,0);
 assert.ok(!JSON.stringify(db.ls_n8n_change_sets).includes('NEVER_LEAK_THIS'));
 const wrong=await rpc(access,4,'tools/call',{name:'n8n_commit_update',arguments:{changeSetId:s.changeSetId,confirmation:'yes'}});
 assert.equal(wrong.data.result.isError,true);
 assert.equal(writes,0);
 const deployed=await rpc(access,5,'tools/call',{name:'n8n_commit_update',arguments:{changeSetId:s.changeSetId,confirmation:s.confirmation}});
 assert.equal(deployed.data.result.isError,undefined,JSON.stringify(deployed.data));
 assert.equal(JSON.parse(deployed.data.result.content[0].text).status,'DEPLOYED_VERIFIED');
 assert.equal(live.nodes[1].parameters.jsCode,'return [{json:{ok:true}}];');
 assert.equal(live.nodes[1].parameters.password,'NEVER_LEAK_THIS');
 assert.equal(live.nodes[1].credentials.httpHeaderAuth.id,'SECRET_CREDENTIAL_ID');
 assert.equal(live.active,true);
 const roll='ROLLBACK '+s.changeSetId+' '+s.baselineHash.slice(0,12);
 const rolled=await rpc(access,6,'tools/call',{name:'n8n_rollback_update',arguments:{changeSetId:s.changeSetId,confirmation:roll}});
 assert.equal(JSON.parse(rolled.data.result.content[0].text).status,'ROLLED_BACK_VERIFIED');
 assert.equal(live.nodes[1].parameters.jsCode,original.nodes[1].parameters.jsCode);
 assert.equal(writes,2);
});
test('Staged update refuses a changed live baseline',async()=>{
 const candidate=clone(live);candidate.nodes[1].parameters.jsCode='return [{json:{new:true}}];';
 const staged=await rpc(access,7,'tools/call',{name:'n8n_stage_update',arguments:{workflowId:'safe-workflow',candidate}});
 const s=JSON.parse(staged.data.result.content[0].text);
 live.versionId='other-editor-updated';
 const deployed=await rpc(access,8,'tools/call',{name:'n8n_commit_update',arguments:{changeSetId:s.changeSetId,confirmation:s.confirmation}});
 assert.equal(deployed.data.result.isError,true);
 assert.equal(writes,2);
});
