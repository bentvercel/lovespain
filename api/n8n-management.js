import {createHash,timingSafeEqual} from 'node:crypto';

const APPROVED={
 'j0sOv1mefGZEduOz':'c0981ebb7457c654fcd8364418499b07732bff97b42705eacc1024a6f41beff6',
 'TJZk68rJBhGbKFdq':'26b549368e6741f68a244751cca128d548524a8738be73c3ab09973d00ceb723',
 'qvRgjY8DCVXhOQGk':'c8fa1ccbc99dda9f89782cbd038d69e87286f9b00fa74d48005a9053a89872de',
 'eaIkhTfDXMoGDViG':'066783686767857f8190d6d73c9f85207f98565522d9bd1954f2ffbed2be727a'
};
const safeEqual=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const dataShape=w=>({name:w.name,nodes:w.nodes,connections:w.connections,settings:w.settings});
const canonical=x=>Array.isArray(x)?x.map(canonical):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;
export const fingerprint=w=>createHash('sha256').update(JSON.stringify(canonical(dataShape(w)))).digest('hex');
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v);
const workflowId=id=>typeof id==='string'&&/^[A-Za-z0-9_-]{1,100}$/.test(id);
const send=(res,status,data)=>{res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.end(JSON.stringify(data));};
function shapeOk(w,id){
 if(!plain(w)||w.id!==id||typeof w.name!=='string'||w.name.length>200||!Array.isArray(w.nodes)||w.nodes.length>300||!plain(w.connections)||!plain(w.settings))return false;
 const names=new Set(),ids=new Set();
 for(const n of w.nodes){
  if(!plain(n)||typeof n.id!=='string'||typeof n.name!=='string'||typeof n.type!=='string'||ids.has(n.id)||names.has(n.name))return false;
  ids.add(n.id);names.add(n.name);
 }
 for(const [from,outputs] of Object.entries(w.connections)){
  if(!names.has(from)||!plain(outputs))return false;
  for(const ports of Object.values(outputs)){
   if(!Array.isArray(ports))return false;
   for(const edges of ports){
    if(!Array.isArray(edges))return false;
    for(const e of edges)if(!plain(e)||!names.has(e.node))return false;
   }
  }
 }
 return true;
}
function stableReferences(a,b){
 if(a.nodes.length!==b.nodes.length)return false;
 const byId=new Map(b.nodes.map(n=>[n.id,n]));
 for(const n of a.nodes){
  const other=byId.get(n.id);
  if(!other||n.name!==other.name||n.type!==other.type||n.typeVersion!==other.typeVersion||JSON.stringify(canonical(n.credentials||{}))!==JSON.stringify(canonical(other.credentials||{})))return false;
 }
 return true;
}
function credentials(){
 const base=process.env.N8N_BASE_URL?.trim(),key=process.env.N8N_API_KEY?.trim();
 if(!base||!key)return null;
 try{
  const u=new URL(base);
  if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash)return null;
  return {origin:u.origin,key};
 }catch{return null}
}
async function n8nRequest(method,id,body){
 const c=credentials();if(!c)return {error:'n8n API is not configured.',status:503};
 try{
  const r=await fetch(c.origin+'/api/v1/workflows/'+encodeURIComponent(id),{
   method,headers:{'X-N8N-API-KEY':c.key,Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},
   body:body?JSON.stringify(body):undefined,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(20000)
  });
  if(!r.ok)return {error:r.status===401||r.status===403?'n8n API key lacks workflow management permission.':'n8n workflow request failed (HTTP '+r.status+').',status:502};
  const result=await r.json();return {data:plain(result.data)?result.data:result,status:200};
 }catch{return {error:'n8n workflow request failed. No result confirmed.',status:502}}
}
function auth(req,b,csrf){
 if(process.env.N8N_DEPLOY_ENABLED!=='true')return {status:503,error:'Workflow deployment is disabled until N8N_DEPLOY_ENABLED=true is set.'};
 const pass=process.env.N8N_DEPLOY_PASSWORD||'';
 if(pass.length<16||pass===process.env.REVIEW_PASSWORD)return {status:503,error:'Configure a separate N8N_DEPLOY_PASSWORD (at least 16 characters) in Vercel.'};
 if(!safeEqual(req.headers['x-csrf-token'],csrf))return {status:403,error:'Refresh the dashboard session.'};
 if(!safeEqual(b.adminPassword,pass))return {status:403,error:'Administrator authorization failed.'};
 return null;
}
export async function manageN8n(req,res,action,b,csrf){
 if(req.method!=='POST')return send(res,405,{error:'POST required.'});
 const rejected=auth(req,b,csrf);if(rejected)return send(res,rejected.status,{error:rejected.error});
 const {id,original,candidate}=b;
 if(!workflowId(id)||!Object.hasOwn(APPROVED,id)||!shapeOk(original,id)||!shapeOk(candidate,id)||!stableReferences(original,candidate)||fingerprint(candidate)!==APPROVED[id])
  return send(res,400,{error:'Not an approved Phase 4 release candidate or invalid workflow structure.'});
 const liveResponse=await n8nRequest('GET',id);
 if(liveResponse.error)return send(res,liveResponse.status,{error:liveResponse.error});
 const live=liveResponse.data;
 if(!shapeOk(live,id))return send(res,502,{error:'Unexpected live n8n workflow response; no changes made.'});
 const currentHash=fingerprint(live),originalHash=fingerprint(original),candidateHash=fingerprint(candidate);
 if(!stableReferences(live,original)||currentHash!==originalHash){
  return send(res,409,{error:'The live workflow differs from the supplied original. Deployment stopped to protect newer live changes.',id,liveVersionId:live.versionId||null});
 }
 if(action==='n8n_deploy_plan'){
  return send(res,200,{ready:true,id,name:live.name,liveVersionId:live.versionId||null,liveFingerprint:currentHash,candidateFingerprint:candidateHash,
   backup:live,warning:'Download and securely store the full live backup before applying. This is a real workflow backup, including credential references.'});
 }
 if(action!=='n8n_deploy_apply')return send(res,404,{error:'Unknown action.'});
 if(b.backupSaved!==true||b.confirm!=='APPLY '+id||!safeEqual(b.expectedLiveHash,currentHash)||String(b.expectedVersionId||'')!==String(live.versionId||''))
  return send(res,409,{error:'Backup, explicit confirmation or live version check failed. Re-run Prepare.'});
 // Only modify the approved graph/parameters. Never change the live active state or credentials.
 const payload=dataShape(candidate);
 const updated=await n8nRequest('PUT',id,payload);
 if(updated.error)return send(res,updated.status,{error:updated.error});
 const after=await n8nRequest('GET',id);
 if(after.error)return send(res,502,{error:'n8n accepted the update but verification failed. Inspect live workflow before retrying.'});
 if(fingerprint(after.data)!==candidateHash)return send(res,502,{error:'n8n accepted the update, but the live workflow differs from the candidate. Inspect it before proceeding.',id});
 console.info('LoveSpain n8n deployment applied',{workflowId:id,at:new Date().toISOString(),candidateFingerprint:candidateHash});
 return send(res,200,{applied:true,id,name:after.data.name,versionId:after.data.versionId||null,active:!!after.data.active,fingerprint:candidateHash});
}
