import { randomBytes, randomUUID, createHash, createHmac, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';

const json=(res,status,body,extra={})=>{res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');for(const [k,v] of Object.entries(extra))res.setHeader(k,v);res.end(JSON.stringify(body));};
const hash=s=>createHash('sha256').update(typeof s==='string'?s:JSON.stringify(s)).digest('hex');
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const bytes=n=>randomBytes(n).toString('base64url');
const origin=req=>{const host=process.env.MCP_PUBLIC_ORIGIN;try{const u=new URL(host);if(u.protocol!=='https:'||u.pathname!=='/'||u.search||u.hash||u.username||u.password)throw Error();return u.origin;}catch{return null;}};
const secret=()=>process.env.MCP_OAUTH_SECRET||'';
// Return only pass/fail statuses, never environment variable values or lengths.
// Expose this through the authenticated reviewer dashboard, not the public MCP endpoint.
export function mcpConfigurationStatus(){
 const checks={
  MCP_PUBLIC_ORIGIN:!!origin(),
  MCP_OAUTH_SECRET:secret().length>=32,
  N8N_ADMIN_PASSWORD:(process.env.N8N_ADMIN_PASSWORD||'').length>=20,
  N8N_BACKUP_KEY:(()=>{
   const v=process.env.N8N_BACKUP_KEY||'';
   return /^[A-Za-z0-9+/]{43}=$/.test(v)&&Buffer.from(v,'base64').length===32;
  })(),
  N8N_BASE_URL:!!process.env.N8N_BASE_URL,
  N8N_API_KEY:!!process.env.N8N_API_KEY,
  SUPABASE_URL:!!process.env.SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY:!!process.env.SUPABASE_SERVICE_ROLE_KEY
 };
 return {ready:Object.values(checks).every(Boolean),checks};
}
const adminReady=()=>mcpConfigurationStatus().ready;
const hmac=s=>createHmac('sha256',secret()).update(s).digest('base64url');
const pack=obj=>{const p=Buffer.from(JSON.stringify(obj)).toString('base64url');return p+'.'+hmac(p);};
const unpack=value=>{try{const [p,s,...extra]=String(value).split('.');if(extra.length||!same(s,hmac(p)))return null;return JSON.parse(Buffer.from(p,'base64url').toString('utf8'));}catch{return null;}};
const validRedirect=value=>{try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash&&['chatgpt.com','chat.openai.com','platform.openai.com','auth.openai.com'].includes(u.hostname);}catch{return false;}};
const getClient=id=>{const c=unpack(id);return c?.kind==='mcp-client'&&c.exp>Date.now()&&Array.isArray(c.redirect_uris)&&c.redirect_uris.every(validRedirect)?c:null;};
const base64url=s=>Buffer.from(s).toString('base64url');
const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const reqBody=req=>{if(typeof req.body==='string'){try{return JSON.parse(req.body)}catch{return Object.fromEntries(new URLSearchParams(req.body))}}return req.body||{};};
const formBody=req=>{if(typeof req.body==='string')return Object.fromEntries(new URLSearchParams(req.body));return req.body||{};};
async function store(table,query='',method='GET',body){
 const url=process.env.SUPABASE_URL+'/rest/v1/'+table+(query?'?'+query:'');
 const response=await fetch(url,{method,headers:{apikey:process.env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+process.env.SUPABASE_SERVICE_ROLE_KEY,'Content-Type':'application/json',Prefer:'return=representation'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok)throw Error('Secure storage unavailable');
 return response.status===204?[]:response.json();
}
const q=s=>encodeURIComponent(s);
async function audit(action,workflowId,changeSetId,details={}){
 await store('ls_n8n_admin_audit','','POST',{action,workflow_id:workflowId||null,change_set_id:changeSetId||null,details});
}
const aesKey=()=>{const k=Buffer.from(process.env.N8N_BACKUP_KEY||'','base64');if(k.length!==32)throw Error('Backup encryption key is not configured');return k;};
function encrypt(data){const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',aesKey(),iv);const ct=Buffer.concat([cipher.update(JSON.stringify(data),'utf8'),cipher.final()]);return ['v1',iv.toString('base64url'),cipher.getAuthTag().toString('base64url'),ct.toString('base64url')].join('.');}
function decrypt(value){const [v,i,t,c]=String(value).split('.');if(v!=='v1')throw Error('Unknown backup format');const decipher=createDecipheriv('aes-256-gcm',aesKey(),Buffer.from(i,'base64url'));decipher.setAuthTag(Buffer.from(t,'base64url'));return JSON.parse(Buffer.concat([decipher.update(Buffer.from(c,'base64url')),decipher.final()]).toString('utf8'));}
const workflowId=id=>typeof id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(id);
function n8nUrl(path){
 const base=new URL(process.env.N8N_BASE_URL||'');
 if(base.protocol!=='https:'||base.pathname!=='/'||base.search||base.hash||base.username||base.password)throw Error('Invalid n8n origin');
 return new URL('/api/v1/'+path,base.origin).toString();
}
async function n8n(method,path,body){
 const response=await fetch(n8nUrl(path),{method,headers:{'X-N8N-API-KEY':process.env.N8N_API_KEY,Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(20000)});
 if(!response.ok)throw Error('n8n request failed (HTTP '+response.status+')');
 const data=await response.json();return data?.data&&typeof data.data==='object'&&!Array.isArray(data.data)?data.data:data;
}
const shape=w=>({name:w.name,nodes:w.nodes,connections:w.connections,settings:w.settings||{},...(w.staticData?{staticData:w.staticData}:{})});
const fingerprint=w=>hash(shape(w));
const version=w=>String(w.versionId||w.updatedAt||'');
const credentialSignature=n=>hash(n.credentials||{});
const sensitiveKey=/^(authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|password|client[-_]?secret|secret|private[-_]?key)$/i;
function redact(v,key=''){
 if(sensitiveKey.test(key))return '[REDACTED]';
 if(Array.isArray(v))return v.map(x=>redact(x));
 if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).filter(([k])=>!['credentials','pinData','staticData','webhookId'].includes(k)).map(([k,x])=>[k,redact(x,k)]));
 if(typeof v==='string'&&/(Bearer\s+[A-Za-z0-9._-]{16,}|sk-[A-Za-z0-9_-]{16,})/i.test(v))return '[REDACTED]';
 return v;
}
function preserve(original,candidate){
 if(candidate==='[REDACTED]')return original;
 if(Array.isArray(candidate))return candidate.map((v,i)=>preserve(original?.[i],v));
 if(candidate&&typeof candidate==='object'){
  const result={};
  for(const [k,v] of Object.entries(candidate))result[k]=preserve(original?.[k],v);
  if(original&&typeof original==='object')for(const [k,v] of Object.entries(original))if(sensitiveKey.test(k)&&!(k in result))result[k]=v;
  return result;
 }
 return candidate;
}
function validateCandidate(live,candidate){
 if(!candidate||typeof candidate!=='object'||Array.isArray(candidate))throw Error('Candidate workflow must be an object');
 if(candidate.id&&candidate.id!==live.id)throw Error('Workflow ID mismatch');
 if(candidate.active!==undefined&&candidate.active!==live.active)throw Error('Activation changes are not permitted');
 if(typeof candidate.name!=='string'||candidate.name.length<1||candidate.name.length>180)throw Error('Invalid workflow name');
 if(!Array.isArray(candidate.nodes)||candidate.nodes.length<1||candidate.nodes.length>300)throw Error('Invalid node count');
 if(!candidate.connections||typeof candidate.connections!=='object'||Array.isArray(candidate.connections))throw Error('Invalid connections');
 const names=new Set(),ids=new Set(),liveById=new Map(live.nodes.map(n=>[n.id,n]));
 const nodes=candidate.nodes.map(n=>{
  if(!n||!n.id||!n.name||!n.type||names.has(n.name)||ids.has(n.id))throw Error('Duplicate or invalid node identity');
  names.add(n.name);ids.add(n.id);
  const old=liveById.get(n.id);
  if(old&&old.type!==n.type)throw Error('Existing node types cannot be changed in place');
  if(n.credentials&&(!old||credentialSignature(n)!==credentialSignature(old)))throw Error('Credential changes are not permitted');
  const params=preserve(old?.parameters||{},n.parameters||{});
  return {...n,parameters:params,credentials:old?.credentials,webhookId:old?.webhookId||n.webhookId};
 });
 for(const [from,ports] of Object.entries(candidate.connections)){
  if(!names.has(from))throw Error('Connection source not found: '+from);
  for(const branches of Object.values(ports||{}))if(Array.isArray(branches))for(const edges of branches)if(Array.isArray(edges))for(const edge of edges)if(!names.has(edge.node))throw Error('Connection target not found: '+edge.node);
 }
 const safe={name:candidate.name,nodes,connections:candidate.connections,settings:candidate.settings||live.settings||{},...(live.staticData?{staticData:live.staticData}:{})};
 if(JSON.stringify(safe).length>750000)throw Error('Candidate too large');
 return safe;
}
async function bearer(req){
 const value=String(req.headers.authorization||'');
 if(!value.startsWith('Bearer '))return false;
 const token=value.slice(7);if(!/^[A-Za-z0-9_-]{32,128}$/.test(token))return false;
 const rows=await store('ls_mcp_tokens','select=access_hash,expires_at,revoked_at&access_hash=eq.'+q(hash(token))+'&limit=1');
 return rows.length===1&&!rows[0].revoked_at&&Date.parse(rows[0].expires_at)>Date.now();
}
const toolDefs=[
 {name:'n8n_list_workflows',description:'List n8n workflows. Read-only; no parameters or credentials.',inputSchema:{type:'object',properties:{},additionalProperties:false}},
 {name:'n8n_inspect_workflow',description:'Read sanitized workflow graph and configuration for editing. Credential objects and known secret fields are removed; avoid requesting confidential data unnecessarily.',inputSchema:{type:'object',properties:{workflowId:{type:'string'}},required:['workflowId'],additionalProperties:false}},
 {name:'n8n_stage_update',description:'Stage a candidate workflow, create an encrypted restorable live backup, and report a diff. NEVER deploys or activates. Use current live workflow ID and complete candidate nodes/connections. No paid runs.',inputSchema:{type:'object',properties:{workflowId:{type:'string'},candidate:{type:'object'}},required:['workflowId','candidate'],additionalProperties:false}},
 {name:'n8n_commit_update',description:'HIGH IMPACT: Saves a staged update into LIVE n8n. Only call after user explicitly confirms this exact change-set and confirmation phrase. Requires baseline revision match; verifies saved result and attempts rollback on failure. Never runs or activates.',inputSchema:{type:'object',properties:{changeSetId:{type:'string'},confirmation:{type:'string'}},required:['changeSetId','confirmation'],additionalProperties:false}},
 {name:'n8n_rollback_update',description:'HIGH IMPACT: Restore an encrypted backup of a deployed change set. Only after user explicitly confirms this exact rollback. Refuses if live workflow changed since deployment.',inputSchema:{type:'object',properties:{changeSetId:{type:'string'},confirmation:{type:'string'}},required:['changeSetId','confirmation'],additionalProperties:false}},
 {name:'n8n_list_changes',description:'List recent deployment stage IDs and statuses without exposing workflow configurations or backups.',inputSchema:{type:'object',properties:{},additionalProperties:false}}
];
async function callTool(name,args){
 if(name==='n8n_list_workflows'){
  const data=await n8n('GET','workflows?limit=100');
  return {workflows:(data.data||[]).map(w=>({id:w.id,name:w.name,active:w.active,updatedAt:w.updatedAt,versionId:w.versionId})),hasMore:!!data.nextCursor};
 }
 if(name==='n8n_inspect_workflow'){
  if(!workflowId(args.workflowId))throw Error('Invalid workflow ID');
  const w=await n8n('GET','workflows/'+args.workflowId);
  return {id:w.id,name:w.name,active:w.active,versionId:version(w),fingerprint:fingerprint(w),candidate: {id:w.id,active:w.active,name:w.name,nodes:redact(w.nodes),connections:w.connections,settings:redact(w.settings||{})},note:'Sanitized for editing. Redacted parameters are preserved from the live workflow when staged; credential references are never returned.'};
 }
 if(name==='n8n_stage_update'){
  if(!workflowId(args.workflowId))throw Error('Invalid workflow ID');
  const live=await n8n('GET','workflows/'+args.workflowId);
  const candidate=validateCandidate(live,args.candidate);
  const before=fingerprint(live),after=hash(candidate);
  if(before===after)throw Error('No changes to stage');
  const id=randomUUID();
  const liveNames=new Set(live.nodes.map(n=>n.name)),newNames=new Set(candidate.nodes.map(n=>n.name));
  const diff={addedNodes:[...newNames].filter(n=>!liveNames.has(n)),removedNodes:[...liveNames].filter(n=>!newNames.has(n)),nodeCountBefore:live.nodes.length,nodeCountAfter:candidate.nodes.length};
  await store('ls_n8n_change_sets','','POST',{id,workflow_id:live.id,baseline_version:version(live),baseline_hash:before,candidate_hash:after,backup_cipher:encrypt(shape(live)),candidate_cipher:encrypt(candidate),status:'staged',diff});
  await audit('STAGED',live.id,id,{baselineHash:before,candidateHash:after,diff});
  return {changeSetId:id,workflowId:live.id,baselineVersion:version(live),baselineHash:before,candidateHash:after,diff,confirmation:'DEPLOY '+id+' '+after.slice(0,12),status:'STAGED_NOT_APPLIED',warning:'Ask the user to confirm this exact change set before committing. No activation or execution is performed.'};
 }
 if(name==='n8n_list_changes'){
  const rows=await store('ls_n8n_change_sets','select=id,workflow_id,status,created_at,updated_at,baseline_hash,candidate_hash,diff&order=created_at.desc&limit=25');
  return {changes:rows};
 }
 if(name==='n8n_commit_update'||name==='n8n_rollback_update'){
  if(typeof args.changeSetId!=='string'||!/^[0-9a-f-]{36}$/.test(args.changeSetId))throw Error('Invalid change set');
  const rows=await store('ls_n8n_change_sets','id=eq.'+q(args.changeSetId)+'&limit=1');
  if(rows.length!==1)throw Error('Change set not found');
  const s=rows[0],commit=name==='n8n_commit_update';
  const phrase=(commit?'DEPLOY ':'ROLLBACK ')+s.id+' '+(commit?s.candidate_hash:s.baseline_hash).slice(0,12);
  if(args.confirmation!==phrase)throw Error('Exact confirmation phrase required: '+phrase);
  if(s.status!==(commit?'staged':'deployed'))throw Error('Change set is not in the required state');
  const live=await n8n('GET','workflows/'+s.workflow_id);
  if(commit&&(fingerprint(live)!==s.baseline_hash||version(live)!==s.baseline_version))throw Error('Live workflow changed since staging; stage a fresh update');
  if(!commit&&fingerprint(live)!==s.deployed_hash)throw Error('Live workflow changed since deployment; rollback refused');
  const expectedStatus=commit?'staged':'deployed',locked=commit?'deploying':'rolling_back';
  const lockedRows=await store('ls_n8n_change_sets','id=eq.'+q(s.id)+'&status=eq.'+expectedStatus,'PATCH',{status:locked,updated_at:new Date().toISOString()});
  if(lockedRows.length!==1)throw Error('Change set is already being processed');
  const desired=decrypt(commit?s.candidate_cipher:s.backup_cipher);
  try{
   await n8n('PUT','workflows/'+s.workflow_id,desired);
   const saved=await n8n('GET','workflows/'+s.workflow_id);
   const desiredHash=hash(desired),savedHash=fingerprint(saved);
   if(savedHash!==desiredHash)throw Error('Post-save verification mismatch');
   await store('ls_n8n_change_sets','id=eq.'+q(s.id),'PATCH',{status:commit?'deployed':'rolled_back',updated_at:new Date().toISOString(),...(commit?{deployed_hash:savedHash,deployed_version:version(saved)}:{})});
   await audit(commit?'DEPLOYED':'ROLLED_BACK',s.workflow_id,s.id,{savedHash,version:version(saved)});
   return {status:commit?'DEPLOYED_VERIFIED':'ROLLED_BACK_VERIFIED',workflowId:s.workflow_id,changeSetId:s.id,versionId:version(saved),fingerprint:savedHash,active:saved.active,note:'No activation or execution was requested.'};
  }catch(e){
   let restored=false;
   if(commit){
    try{
     const current=await n8n('GET','workflows/'+s.workflow_id);
     if(fingerprint(current)!==s.baseline_hash){
      const backup=decrypt(s.backup_cipher);
      await n8n('PUT','workflows/'+s.workflow_id,backup);
      const checked=await n8n('GET','workflows/'+s.workflow_id);
      restored=fingerprint(checked)===s.baseline_hash;
     }else restored=true;
    }catch{}
   }
   await store('ls_n8n_change_sets','id=eq.'+q(s.id),'PATCH',{status:commit?(restored?'failed_restored':'failed_review_required'):'rollback_failed_review_required',updated_at:new Date().toISOString()});
   await audit('DEPLOYMENT_ERROR',s.workflow_id,s.id,{restored,operation:commit?'deploy':'rollback'});
   throw Error('Save or verification failed. '+(restored?'Original backup restored.':'Manual administrator review required; do not retry blindly.'));
  }
 }
 throw Error('Unknown tool');
}
function oauthMeta(o){return {issuer:o,authorization_endpoint:o+'/api/mcp?mode=authorize',token_endpoint:o+'/api/mcp?mode=token',registration_endpoint:o+'/api/mcp?mode=register',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['n8n:manage']};}
function protectedMeta(o){return {resource:o+'/api/mcp',authorization_servers:[o],scopes_supported:['n8n:manage'],bearer_methods_supported:['header']};}
async function oauth(req,res,mode,o){
 if(mode==='register'&&req.method==='POST'){
  const b=reqBody(req),uris=b.redirect_uris;
  if(!Array.isArray(uris)||uris.length<1||uris.length>3||!uris.every(validRedirect)||JSON.stringify(b).length>4000)return json(res,400,{error:'invalid_client_metadata'});
  const now=Date.now(),id=pack({kind:'mcp-client',redirect_uris:uris,exp:now+90*86400000});
  return json(res,201,{client_id:id,client_id_issued_at:Math.floor(now/1000),client_id_expires_at:Math.floor((now+90*86400000)/1000),redirect_uris:uris,token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']});
 }
 if(mode==='authorize'&&(req.method==='GET'||req.method==='POST')){
  const p=req.method==='GET'?Object.fromEntries(new URL(req.url,'http://local').searchParams):formBody(req);
  const c=getClient(p.client_id);
  if(!c||!c.redirect_uris.includes(p.redirect_uri)||p.response_type!=='code'||p.code_challenge_method!=='S256'||!/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge||'')||typeof p.state!=='string'||p.state.length<8||p.state.length>512||p.scope!=='n8n:manage')return json(res,400,{error:'invalid_request'});
  if(req.method==='GET'){
   const fields=['client_id','redirect_uri','response_type','code_challenge','code_challenge_method','state','scope'].map(k=>'<input type="hidden" name="'+k+'" value="'+escape(p[k])+'">').join('');
   res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
   return res.end('<!doctype html><html><head><title>LoveSpain n8n Admin Authorization</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font:16px system-ui;max-width:480px;margin:10vh auto;padding:24px"><h1>Authorize LoveSpain n8n management</h1><p>This grants ChatGPT the ability to stage and, after explicit confirmation, save workflow changes. It cannot activate or run workflows.</p><form method="POST" action="/api/mcp?mode=authorize">'+fields+'<label>Separate n8n administrator password<br><input required type="password" name="password" autocomplete="current-password"></label><p><button type="submit">Authorize this connection</button></p></form></body></html>');
  }
  if(req.headers.origin&&req.headers.origin!==o)return json(res,403,{error:'invalid_origin'});
  if(!same(p.password,process.env.N8N_ADMIN_PASSWORD))return json(res,401,{error:'Administrator authorization failed'});
  const code=bytes(32);
  await store('ls_mcp_auth_codes','','POST',{code_hash:hash(code),client_id:p.client_id,redirect_uri:p.redirect_uri,challenge:p.code_challenge,expires_at:new Date(Date.now()+300000).toISOString()});
  const target=new URL(p.redirect_uri);target.searchParams.set('code',code);target.searchParams.set('state',p.state);
  res.statusCode=302;res.setHeader('Location',target.toString());res.setHeader('Cache-Control','no-store');return res.end();
 }
 if(mode==='token'&&req.method==='POST'){
  const p=formBody(req),c=getClient(p.client_id);
  if(!c)return json(res,400,{error:'invalid_client'});
  if(p.grant_type==='authorization_code'){
   if(!c.redirect_uris.includes(p.redirect_uri)||typeof p.code_verifier!=='string'||!/^[A-Za-z0-9._~-]{43,128}$/.test(p.code_verifier))return json(res,400,{error:'invalid_grant'});
   const rows=await store('ls_mcp_auth_codes','code_hash=eq.'+q(hash(p.code))+'&used_at=is.null&limit=1');
   const a=rows[0];
   if(!a||a.client_id!==p.client_id||a.redirect_uri!==p.redirect_uri||Date.parse(a.expires_at)<Date.now()||base64url(createHash('sha256').update(p.code_verifier).digest())!==a.challenge)return json(res,400,{error:'invalid_grant'});
   const used=await store('ls_mcp_auth_codes','code_hash=eq.'+q(hash(p.code))+'&used_at=is.null','PATCH',{used_at:new Date().toISOString()});
   if(used.length!==1)return json(res,400,{error:'invalid_grant'});
  }else if(p.grant_type==='refresh_token'){
   const rows=await store('ls_mcp_tokens','refresh_hash=eq.'+q(hash(p.refresh_token))+'&revoked_at=is.null&limit=1');
   const a=rows[0];
   if(!a||a.client_id!==p.client_id||Date.parse(a.refresh_expires_at)<Date.now())return json(res,400,{error:'invalid_grant'});
   const revoked=await store('ls_mcp_tokens','refresh_hash=eq.'+q(hash(p.refresh_token))+'&revoked_at=is.null','PATCH',{revoked_at:new Date().toISOString()});
   if(revoked.length!==1)return json(res,400,{error:'invalid_grant'});
  }else return json(res,400,{error:'unsupported_grant_type'});
  const access=bytes(48),refresh=bytes(48);
  await store('ls_mcp_tokens','','POST',{access_hash:hash(access),refresh_hash:hash(refresh),client_id:p.client_id,expires_at:new Date(Date.now()+3600000).toISOString(),refresh_expires_at:new Date(Date.now()+30*86400000).toISOString()});
  return json(res,200,{access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope:'n8n:manage'});
 }
 return json(res,405,{error:'method_not_allowed'});
}
export default async function handler(req,res){
 try{
  const o=origin(req);
  if(!o||!adminReady())return json(res,503,{error:'Secure n8n management is not configured'});
  const mode=new URL(req.url,'http://local').searchParams.get('mode');
  if(mode==='oauth_metadata'&&req.method==='GET')return json(res,200,oauthMeta(o));
  if(mode==='protected_metadata'&&req.method==='GET')return json(res,200,protectedMeta(o));
  if(['register','authorize','token'].includes(mode))return await oauth(req,res,mode,o);
  if(req.method!=='POST')return json(res,405,{error:'Use MCP Streamable HTTP POST'});
  if(!(await bearer(req)))return json(res,401,{error:'unauthorized'},{'WWW-Authenticate':'Bearer resource_metadata="'+o+'/.well-known/oauth-protected-resource/api/mcp"'});
  const b=reqBody(req);
  if(b.jsonrpc!=='2.0'||typeof b.method!=='string')return json(res,400,{jsonrpc:'2.0',id:b.id??null,error:{code:-32600,message:'Invalid JSON-RPC request'}});
  const response=(result)=>json(res,200,{jsonrpc:'2.0',id:b.id,result});
  if(b.method==='initialize')return response({protocolVersion:'2025-03-26',capabilities:{tools:{listChanged:false}},serverInfo:{name:'LoveSpain Secure n8n Manager',version:'1.0.0'}});
  if(b.method==='notifications/initialized')return json(res,202,{});
  if(b.method==='ping')return response({});
  if(b.method==='tools/list')return response({tools:toolDefs});
  if(b.method==='tools/call'){
   const name=b.params?.name,args=b.params?.arguments||{};
   if(!toolDefs.some(t=>t.name===name))return json(res,200,{jsonrpc:'2.0',id:b.id,error:{code:-32601,message:'Unknown tool'}});
   try{const result=await callTool(name,args);return response({content:[{type:'text',text:JSON.stringify(result)}]});}
   catch(e){return response({isError:true,content:[{type:'text',text:e.message.startsWith('n8n request')?e.message:String(e.message).slice(0,300)}]});}
  }
  return json(res,200,{jsonrpc:'2.0',id:b.id??null,error:{code:-32601,message:'Unknown method'}});
 }catch{return json(res,500,{error:'Secure management request failed; check server configuration and audit logs'});}
}
