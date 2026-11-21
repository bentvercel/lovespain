import {randomBytes,createHash,createHmac,timingSafeEqual} from 'node:crypto';

const send=(res,status,data,headers={})=>{res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');for(const [k,v] of Object.entries(headers))res.setHeader(k,v);res.end(JSON.stringify(data));};
const sha=s=>createHash('sha256').update(String(s)).digest('hex');
const eq=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const rand=()=>randomBytes(48).toString('base64url');
const origin=()=>{try{const u=new URL(process.env.MCP_PUBLIC_ORIGIN);return u.protocol==='https:'&&u.pathname==='/'&&!u.search&&!u.hash?u.origin:null}catch{return null}};
const secret=()=>process.env.MCP_OAUTH_SECRET||'';
const sign=s=>createHmac('sha256',secret()).update(s).digest('base64url');
const pack=o=>{const b=Buffer.from(JSON.stringify(o)).toString('base64url');return b+'.'+sign(b)};
const unpack=s=>{try{const [b,h,...rest]=String(s).split('.');return rest.length||!eq(h,sign(b))?null:JSON.parse(Buffer.from(b,'base64url').toString())}catch{return null}};
const redirectOK=s=>{try{const u=new URL(s);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash&&['chatgpt.com','chat.openai.com','platform.openai.com','auth.openai.com'].includes(u.hostname)}catch{return false}};
const client=id=>{const c=unpack(id);return c?.kind==='ghl-mcp-client'&&c.exp>Date.now()&&Array.isArray(c.redirect_uris)&&c.redirect_uris.every(redirectOK)?c:null};
const params=req=>{const b=req.body;if(typeof b==='string'){try{return JSON.parse(b)}catch{return Object.fromEntries(new URLSearchParams(b))}}return b&&typeof b==='object'?b:{}};
const form=req=>{const b=req.body;if(typeof b==='string')return Object.fromEntries(new URLSearchParams(b));if(Buffer.isBuffer(b))return Object.fromEntries(new URLSearchParams(b.toString()));return b||{}};
async function db(table,query='',method='GET',body){
 const url=process.env.SUPABASE_URL+'/rest/v1/'+table+(query?'?'+query:'');
 const r=await fetch(url,{method,headers:{apikey:process.env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+process.env.SUPABASE_SERVICE_ROLE_KEY,'Content-Type':'application/json',Prefer:'return=representation'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(12000)});
 if(!r.ok)throw Error('Secure token storage unavailable');
 return r.status===204?[]:r.json();
}
const q=encodeURIComponent;
async function authorized(req){
 const h=String(req.headers.authorization||'');if(!h.startsWith('Bearer '))return false;
 const token=h.slice(7);if(!/^[A-Za-z0-9_-]{32,128}$/.test(token))return false;
 const rows=await db('ls_mcp_tokens','select=client_id,expires_at,revoked_at&access_hash=eq.'+q(sha(token))+'&limit=1');
 return rows.length===1&&!rows[0].revoked_at&&Date.parse(rows[0].expires_at)>Date.now()&&!!client(rows[0].client_id);
}
const meta=o=>({issuer:o+'/ghl',authorization_endpoint:o+'/api/ghl-mcp?mode=authorize',token_endpoint:o+'/api/ghl-mcp?mode=token',registration_endpoint:o+'/api/ghl-mcp?mode=register',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['ghl:read']});
const protectedMeta=o=>({resource:o+'/api/ghl-mcp',authorization_servers:[o+'/ghl'],scopes_supported:['ghl:read'],bearer_methods_supported:['header']});
const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function oauth(req,res,mode,o){
 if(mode==='register'&&req.method==='POST'){
  const b=params(req),uris=b.redirect_uris;
  if(!Array.isArray(uris)||uris.length<1||uris.length>3||!uris.every(redirectOK)||JSON.stringify(b).length>4000)return send(res,400,{error:'invalid_client_metadata'});
  const now=Date.now(),id=pack({kind:'ghl-mcp-client',redirect_uris:uris,exp:now+90*86400000});
  return send(res,201,{client_id:id,client_id_issued_at:Math.floor(now/1000),client_id_expires_at:Math.floor((now+90*86400000)/1000),redirect_uris:uris,token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']});
 }
 if(mode==='authorize'&&['GET','POST'].includes(req.method)){
  const p=req.method==='GET'?Object.fromEntries(new URL(req.url,'http://local').searchParams):params(req);
  const c=client(p.client_id);
  if(!c||!c.redirect_uris.includes(p.redirect_uri)||p.response_type!=='code'||p.code_challenge_method!=='S256'||!/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge||'')||typeof p.state!=='string'||p.state.length<8||p.state.length>512||p.scope!=='ghl:read')return send(res,400,{error:'invalid_request'});
  if(req.method==='GET'){
   const fields=['client_id','redirect_uri','response_type','code_challenge','code_challenge_method','state','scope'].map(k=>'<input type="hidden" name="'+k+'" value="'+escape(p[k])+'">').join('');
   const nonce=randomBytes(18).toString('base64url');
   const script=`const form=document.getElementById('f'),error=document.getElementById('e');form.addEventListener('submit',async ev=>{ev.preventDefault();error.textContent='';try{const r=await fetch('/api/ghl-mcp?mode=authorize',{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(form))),cache:'no-store'});const j=await r.json();if(!r.ok||!j.redirect_to)throw Error('Authorization failed');location.assign(j.redirect_to)}catch{error.textContent='Authorization failed. Check credentials and retry.'}})`;
   res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
   return res.end('<!doctype html><html><head><title>LoveSpain GHL authorization</title></head><body style="font:16px system-ui;max-width:480px;margin:10vh auto;padding:24px"><h1>Authorize read-only LoveSpain GHL access</h1><p>This connection can read CRM records but cannot edit them or send messages.</p><form id="f">'+fields+'<label>GHL Manager administrator password <input type="password" name="password" required autocomplete="current-password"></label><p><button>Authorize</button></p></form><p id="e" role="alert"></p><script nonce="'+nonce+'">'+script+'</script></body></html>');
  }
  if(req.headers.origin&&req.headers.origin!==o)return send(res,403,{error:'invalid_origin'});
  if(!eq(p.password,process.env.GHL_ADMIN_PASSWORD))return send(res,401,{error:'invalid_credentials'});
  const code=rand();
  await db('ls_mcp_auth_codes','','POST',{code_hash:sha(code),client_id:p.client_id,redirect_uri:p.redirect_uri,challenge:p.code_challenge,expires_at:new Date(Date.now()+300000).toISOString()});
  const target=new URL(p.redirect_uri);target.searchParams.set('code',code);target.searchParams.set('state',p.state);
  return send(res,200,{redirect_to:target.toString()});
 }
 if(mode==='token'&&req.method==='POST'){
  const p=form(req),c=client(p.client_id);if(!c)return send(res,400,{error:'invalid_client'});
  if(p.grant_type==='authorization_code'){
   if(!c.redirect_uris.includes(p.redirect_uri)||typeof p.code_verifier!=='string'||!/^[A-Za-z0-9._~-]{43,128}$/.test(p.code_verifier))return send(res,400,{error:'invalid_grant'});
   const rows=await db('ls_mcp_auth_codes','code_hash=eq.'+q(sha(p.code))+'&used_at=is.null&limit=1');const a=rows[0];
   const challenge=createHash('sha256').update(p.code_verifier).digest('base64url');
   if(!a||a.client_id!==p.client_id||a.redirect_uri!==p.redirect_uri||Date.parse(a.expires_at)<Date.now()||challenge!==a.challenge)return send(res,400,{error:'invalid_grant'});
   const used=await db('ls_mcp_auth_codes','code_hash=eq.'+q(sha(p.code))+'&used_at=is.null','PATCH',{used_at:new Date().toISOString()});
   if(used.length!==1)return send(res,400,{error:'invalid_grant'});
  }else if(p.grant_type==='refresh_token'){
   const rows=await db('ls_mcp_tokens','refresh_hash=eq.'+q(sha(p.refresh_token))+'&revoked_at=is.null&limit=1');const a=rows[0];
   if(!a||a.client_id!==p.client_id||Date.parse(a.refresh_expires_at)<Date.now())return send(res,400,{error:'invalid_grant'});
   const revoked=await db('ls_mcp_tokens','refresh_hash=eq.'+q(sha(p.refresh_token))+'&revoked_at=is.null','PATCH',{revoked_at:new Date().toISOString()});
   if(revoked.length!==1)return send(res,400,{error:'invalid_grant'});
  }else return send(res,400,{error:'unsupported_grant_type'});
  const access=rand(),refresh=rand();
  await db('ls_mcp_tokens','','POST',{access_hash:sha(access),refresh_hash:sha(refresh),client_id:p.client_id,expires_at:new Date(Date.now()+3600000).toISOString(),refresh_expires_at:new Date(Date.now()+30*86400000).toISOString()});
  return send(res,200,{access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope:'ghl:read'});
 }
 return send(res,405,{error:'method_not_allowed'});
}
const definitions=[
 {name:'ghl_list_contacts',description:'Read-only search of contacts within the configured LoveSpain location. No mutations.',inputSchema:{type:'object',properties:{query:{type:'string',maxLength:120},limit:{type:'integer',minimum:1,maximum:50}},additionalProperties:false}},
 {name:'ghl_list_pipelines',description:'List LoveSpain opportunity pipelines.',inputSchema:{type:'object',properties:{},additionalProperties:false}},
 {name:'ghl_list_opportunities',description:'Search LoveSpain opportunities. Optional pipeline ID.',inputSchema:{type:'object',properties:{pipelineId:{type:'string',maxLength:100},limit:{type:'integer',minimum:1,maximum:50}},additionalProperties:false}},
 {name:'ghl_list_calendars',description:'List LoveSpain calendars.',inputSchema:{type:'object',properties:{},additionalProperties:false}},
 {name:'ghl_get_contact',description:'Read a contact by ID, restricted to LoveSpain location.',inputSchema:{type:'object',properties:{contactId:{type:'string',minLength:1,maxLength:100}},required:['contactId'],additionalProperties:false}},
 {name:'ghl_get_conversations',description:'List conversations for a LoveSpain contact.',inputSchema:{type:'object',properties:{contactId:{type:'string',minLength:1,maxLength:100},limit:{type:'integer',minimum:1,maximum:30}},required:['contactId'],additionalProperties:false}}
];
const safeId=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{1,100}$/.test(s);
async function ghl(path,query={}){
 const base=new URL(process.env.GHL_API_BASE_URL||'https://services.leadconnectorhq.com');
 if(base.origin!=='https://services.leadconnectorhq.com'||base.pathname!=='/'||base.search||base.hash)throw Error('GHL API origin is not allowed');
 const url=new URL(path,base);for(const [k,v] of Object.entries(query))if(v!==undefined&&v!==null&&v!=='')url.searchParams.set(k,String(v));
 const r=await fetch(url,{method:'GET',headers:{Authorization:'Bearer '+process.env.GHL_API_TOKEN,Version:'2021-07-28',Accept:'application/json'},redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)});
 if(!r.ok)throw Error('GHL request failed (HTTP '+r.status+')');
 return r.json();
}
async function tool(name,args){
 const locationId=process.env.GHL_LOCATION_ID;
 const limit=(n,max=50)=>Number.isInteger(n)&&n>=1&&n<=max?n:20;
 if(name==='ghl_list_contacts')return ghl('/contacts/',{locationId,limit:limit(args.limit),query:typeof args.query==='string'?args.query.slice(0,120):undefined});
 if(name==='ghl_list_pipelines')return ghl('/opportunities/pipelines',{locationId});
 if(name==='ghl_list_opportunities'){if(args.pipelineId!==undefined&&!safeId(args.pipelineId))throw Error('Invalid pipeline ID');return ghl('/opportunities/search',{location_id:locationId,pipeline_id:args.pipelineId,limit:limit(args.limit)})}
 if(name==='ghl_list_calendars')return ghl('/calendars/',{locationId});
 if(name==='ghl_get_contact'){
  if(!safeId(args.contactId))throw Error('Invalid contact ID');
  const data=await ghl('/contacts/'+encodeURIComponent(args.contactId));
  if(data.contact?.locationId!==locationId)throw Error('Contact is outside configured location');
  return data;
 }
 if(name==='ghl_get_conversations'){
  if(!safeId(args.contactId))throw Error('Invalid contact ID');
  const contact=await ghl('/contacts/'+encodeURIComponent(args.contactId));
  if(contact.contact?.locationId!==locationId)throw Error('Contact is outside configured location');
  return ghl('/conversations/search',{locationId,contactId:args.contactId,limit:limit(args.limit,30)});
 }
 throw Error('Unknown tool');
}
export default async function handler(req,res){
 try{
  const o=origin(),mode=new URL(req.url,'http://local').searchParams.get('mode');
  if(!o||secret().length<32||!(process.env.GHL_ADMIN_PASSWORD||'').length||!process.env.GHL_API_TOKEN||!process.env.GHL_LOCATION_ID||!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY)return send(res,503,{error:'GHL Manager is not configured'});
  if(mode==='oauth_metadata'&&req.method==='GET')return send(res,200,meta(o));
  if(mode==='protected_metadata'&&req.method==='GET')return send(res,200,protectedMeta(o));
  if(['register','authorize','token'].includes(mode))return oauth(req,res,mode,o);
  if(req.method!=='POST')return send(res,405,{error:'Use MCP Streamable HTTP POST'});
  if(!(await authorized(req)))return send(res,401,{error:'unauthorized'},{'WWW-Authenticate':'Bearer resource_metadata="'+o+'/.well-known/oauth-protected-resource/api/ghl-mcp"'});
  const b=params(req);if(b.jsonrpc!=='2.0'||typeof b.method!=='string')return send(res,400,{jsonrpc:'2.0',id:b.id??null,error:{code:-32600,message:'Invalid JSON-RPC request'}});
  const response=result=>send(res,200,{jsonrpc:'2.0',id:b.id,result});
  if(b.method==='initialize')return response({protocolVersion:'2025-03-26',capabilities:{tools:{listChanged:false}},serverInfo:{name:'LoveSpain GHL Manager',version:'1.0.0'}});
  if(b.method==='notifications/initialized')return send(res,202,{});
  if(b.method==='ping')return response({});
  if(b.method==='tools/list')return response({tools:definitions});
  if(b.method==='tools/call'){
   const name=b.params?.name,args=b.params?.arguments||{};
   if(!definitions.some(t=>t.name===name))return send(res,200,{jsonrpc:'2.0',id:b.id,error:{code:-32601,message:'Unknown tool'}});
   try{return response({content:[{type:'text',text:JSON.stringify(await tool(name,args))}]})}
   catch{return response({isError:true,content:[{type:'text',text:'GHL read failed. Verify the location, API scopes, and endpoint availability.'}]})}
  }
  return send(res,200,{jsonrpc:'2.0',id:b.id??null,error:{code:-32601,message:'Unknown method'}});
 }catch{return send(res,500,{error:'GHL Manager request failed'})}
}
