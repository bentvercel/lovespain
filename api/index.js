import {createHmac,timingSafeEqual,randomBytes,createHash} from 'node:crypto';
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const sign=s=>createHmac('sha256',process.env.SESSION_SECRET).update(s).digest('hex');
const send=(res,status,body)=>{res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify(body));};
async function db(path,method='GET',body){const r=await fetch(process.env.SUPABASE_URL+'/rest/v1/'+path,{method,headers:{apikey:process.env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+process.env.SUPABASE_SERVICE_ROLE_KEY,'Content-Type':'application/json',Prefer:'return=representation'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw new Error('Data service unavailable');return r.status===204?[]:r.json()}
function session(req){try{const value=(req.headers.cookie||'').split('; ').find(x=>x.startsWith('ls_session='))?.slice(11);const [b,s]=value.split('.');if(!equal(s,sign(b)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p:null}catch{return null}}
const sha=d=>createHash('sha256').update(JSON.stringify(d)).digest('hex');
const statuses=['approved','rejected','revision_requested'];

/* n8n credentials are server-only. Never proxy arbitrary URLs, nodes, or credential payloads. */
async function n8nGet(resource,query=''){
 const base=process.env.N8N_BASE_URL?.trim();
 const key=process.env.N8N_API_KEY?.trim();
 if(!base||!key)return {error:'n8n API is not configured in Vercel.',status:503};
 let url;
 try{
  const origin=new URL(base);
  if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new Error('Invalid URL');
  url=new URL('/api/v1/'+resource+query,origin.origin);
 }catch{return {error:'N8N_BASE_URL must be the HTTPS n8n workspace origin (no path).',status:503}}
 try{
  const response=await fetch(url,{method:'GET',headers:{'X-N8N-API-KEY':key,Accept:'application/json'},signal:AbortSignal.timeout(12000),redirect:'error',cache:'no-store'});
  if(response.status===401||response.status===403)return {error:'n8n rejected the API key or its permissions.',status:502};
  if(!response.ok)return {error:'n8n API request failed (HTTP '+response.status+').',status:502};
  return {data:await response.json(),status:200};
 }catch{return {error:'Could not reach n8n. Check the workspace URL and network access.',status:502}}
}

export default async function handler(req,res){
try{
const action=new URL(req.url,'http://local').searchParams.get('action')||'list';
if(action==='health')return send(res,200,{configured:!!(process.env.SUPABASE_URL&&process.env.SUPABASE_SERVICE_ROLE_KEY&&process.env.SESSION_SECRET&&process.env.REVIEW_PASSWORD&&process.env.INGEST_TOKEN)});
if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY||!process.env.SESSION_SECRET)return send(res,503,{error:'Live service is not configured. Use the explicitly labelled demo or complete server setup.'});
const method=req.method;let b=req.body;if(typeof b==='string')b=JSON.parse(b);b=b||{};
if(method==='POST'&&action!=='ingest'&&req.headers.origin&&req.headers.origin!==new URL(req.url,'https://'+req.headers.host).origin && req.headers.origin!=='https://'+req.headers.host && req.headers.origin!=='http://'+req.headers.host)return send(res,403,{error:'Origin mismatch'});
if(action==='login'&&method==='POST'){
 if(!process.env.REVIEW_PASSWORD||!equal(b.password,process.env.REVIEW_PASSWORD))return send(res,401,{error:'Incorrect password'});
 const token=Buffer.from(JSON.stringify({reviewer:'Bent',exp:Date.now()+8*3600000,csrf:randomBytes(24).toString('hex')})).toString('base64url');res.setHeader('Set-Cookie',`ls_session=${token}.${sign(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.NODE_ENV==='production'?'; Secure':''}`);return send(res,200,{ok:true});
}
if(action==='ingest'&&method==='POST'){
 if(!process.env.INGEST_TOKEN||!equal(req.headers.authorization,'Bearer '+process.env.INGEST_TOKEN))return send(res,401,{error:'Unauthorized'});
 if(!b.campaignId||!b.developmentId||!b.developmentName||!Array.isArray(b.assets)||!b.assets.length)return send(res,400,{error:'campaignId, developmentId, developmentName and nonempty assets required'});
 if(b.assets.length>30||new Set(b.assets.map(a=>a.id)).size!==b.assets.length||b.assets.some(a=>!a.id||!['copy','video','landing','social','images'].includes(a.type)))return send(res,400,{error:'Asset IDs must be unique and types supported'});
 const assets=b.assets.map(a=>({id:String(a.id),type:a.type,title:String(a.title||a.type),text:String(a.text||''),url:String(a.url||''),status:'pending',note:''}));
 const content={developmentId:String(b.developmentId),developmentName:String(b.developmentName),assets:assets.map(({status,note,...a})=>a)};const contentHash=sha(content);const id=String(b.campaignId);const old=(await db('ls_campaigns?id=eq.'+encodeURIComponent(id)))[0];
 if(old&&old.content_hash===contentHash)return send(res,200,{id,unchanged:true,revision:old.revision,contentHash});
 const row={id,development_id:String(b.developmentId),name:String(b.developmentName),content_hash:contentHash,revision:old?old.revision+1:1,assets,history:[...(old?.history||[]),{at:new Date().toISOString(),actor:'n8n',action:'Content submitted; approvals reset',hash:contentHash}],updated_at:new Date().toISOString()};
 if(old){const rows=await db('ls_campaigns?id=eq.'+encodeURIComponent(id)+'&revision=eq.'+old.revision,'PATCH',row);if(!rows.length)return send(res,409,{error:'Content changed concurrently; retry ingest'});}else await db('ls_campaigns','POST',row);
 return send(res,200,{id,revision:row.revision,contentHash});
}
if(action==='verified'&&method==='GET'){
 if(!process.env.INGEST_TOKEN||!equal(req.headers.authorization,'Bearer '+process.env.INGEST_TOKEN))return send(res,401,{error:'Unauthorized'});
 const q=new URL(req.url,'http://local').searchParams;const row=(await db('ls_campaigns?id=eq.'+encodeURIComponent(q.get('id')||'')))[0];if(!row)return send(res,404,{error:'Campaign not found'});
 const approved=row.assets.length>0&&row.assets.every(a=>a.status==='approved');const last=[...row.history].reverse().find(e=>e.hash===row.content_hash&&e.action==='approved');
 return send(res,200,{campaignId:row.id,developmentId:row.development_id,contentHash:row.content_hash,revision:row.revision,approvalStatus:approved?'approved':'pending',approvalVerified:approved,publicationAllowed:false,approvalDecision:{status:approved?'approved':'pending',reviewerId:approved?last?.actor:null,approvedAt:approved?last?.at:null,contentHash:row.content_hash},assets:row.assets,nextAction:'WORKFLOW_4_MUST_VERIFY_CURRENT_CONTENT_HASH'});
}
const user=session(req);if(!user)return send(res,401,{error:'Sign in required'});
if(action==='logout'&&method==='POST'){res.setHeader('Set-Cookie','ls_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return send(res,200,{ok:true});}
if(method==='GET'&&['n8n_status','n8n_workflows','n8n_executions'].includes(action)){
 const resource=action==='n8n_executions'?'executions':'workflows';
 const query=action==='n8n_status'?'?limit=1':action==='n8n_executions'?'?limit=20&includeData=false':'?limit=100';
 const result=await n8nGet(resource,query);
 if(result.error)return send(res,result.status,{connected:false,error:result.error});
 if(action==='n8n_status')return send(res,200,{connected:true,configured:true});
 if(action==='n8n_workflows'){
  const data=result.data||{};
  return send(res,200,{connected:true,workflows:(Array.isArray(data.data)?data.data:[]).map(w=>({id:String(w.id),name:String(w.name||'Untitled workflow'),active:!!w.active,updatedAt:w.updatedAt||null,createdAt:w.createdAt||null})),hasMore:!!data.nextCursor});
 }
 const data=result.data||{};
 return send(res,200,{connected:true,executions:(Array.isArray(data.data)?data.data:[]).map(e=>({id:String(e.id),workflowId:String(e.workflowId||''),status:String(e.status||'unknown'),startedAt:e.startedAt||null,stoppedAt:e.stoppedAt||null,finished:!!e.finished})),hasMore:!!data.nextCursor});
}
if(action==='list'&&method==='GET')return send(res,200,{reviewer:user.reviewer,csrf:user.csrf,campaigns:await db('ls_campaigns?order=updated_at.desc')});
if(action==='decision'&&method==='POST'){
 if(!equal(req.headers['x-csrf-token'],user.csrf))return send(res,403,{error:'Refresh your session'});
 if(!statuses.includes(b.status)||!b.id||!Number.isInteger(b.revision))return send(res,400,{error:'Invalid decision'});
 if(b.status!=='approved'&&!String(b.note||'').trim())return send(res,400,{error:'A reason is required'});
 const row=(await db('ls_campaigns?id=eq.'+encodeURIComponent(b.id)))[0];if(!row)return send(res,404,{error:'Campaign not found'});if(row.revision!==b.revision)return send(res,409,{error:'This content changed. Refresh before deciding.'});
 const target=row.assets.filter(a=>b.assetId==='all'||a.id===b.assetId);if(!target.length)return send(res,400,{error:'Asset not found'});
 if(b.status==='approved'&&target.some(a=>['video','landing','images'].includes(a.type)&&!/^https:\/\//.test(a.url)))return send(res,400,{error:'Media and landing-page assets need an HTTPS review URL before approval'});
 const at=new Date().toISOString();const assets=row.assets.map(a=>target.includes(a)?{...a,status:b.status,note:String(b.note||'').slice(0,4000),reviewer:user.reviewer,decidedAt:at}:a);
 const change={assets,revision:row.revision+1,updated_at:at,history:[...row.history,{at,actor:user.reviewer,action:b.status,assetId:b.assetId,note:String(b.note||'').slice(0,4000),hash:row.content_hash}]};
 const rows=await db('ls_campaigns?id=eq.'+encodeURIComponent(row.id)+'&revision=eq.'+row.revision,'PATCH',change);if(!rows.length)return send(res,409,{error:'Another review was saved. Refresh.'});return send(res,200,{campaign:rows[0]});
}
return send(res,404,{error:'Unknown action'});
}catch(e){return send(res,500,{error:'Request could not be completed. Check server configuration and retry.'})}
}
// n8n reads the authoritative record through its own service-token route, never browser-submitted approval flags.
