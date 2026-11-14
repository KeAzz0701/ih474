// 復号係：enc/ の暗号化ファイルを鍵で戻して渡す
const CFG={"salt":"E/lEnptucUTG3V70JY4m7w==","iter":600000,"hours":0};let KEY=null,EXP=0;
const TYPES={html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8',json:'application/json',csv:'text/csv; charset=utf-8',md:'text/plain; charset=utf-8',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',glb:'model/gltf-binary',mp4:'video/mp4',svg:'image/svg+xml'};
const DIRS=["viewer","photos","data"];
function db(){return new Promise((ok,ng)=>{const r=indexedDB.open('ih474',1);r.onupgradeneeded=()=>r.result.createObjectStore('k');r.onsuccess=()=>ok(r.result);r.onerror=()=>ng(r.error)})}
async function idb(op,v){const d=await db();return new Promise((ok,ng)=>{const t=d.transaction('k',op?'readwrite':'readonly'),s=t.objectStore('k');const r=op==='put'?s.put(v,'key'):op==='del'?s.delete('key'):s.get('key');r.onsuccess=()=>ok(r.result);r.onerror=()=>ng(r.error)})}
async function getKey(){if(KEY&&(!CFG.hours||Date.now()<EXP))return KEY;const v=await idb(null).catch(()=>null);if(v&&(!CFG.hours||Date.now()<v.exp)){KEY=await crypto.subtle.importKey('raw',v.raw,'AES-GCM',false,['decrypt']);EXP=v.exp;return KEY}KEY=null;return null}
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{const m=e.data||{};e.waitUntil((async()=>{
  if(m.type==='key'){const exp=CFG.hours?Date.now()+CFG.hours*3600e3:8.64e15;await idb('put',{raw:m.raw,exp});KEY=null;await getKey()}
  if(m.type==='logout'){await idb('del');KEY=null}
  e.source&&e.source.postMessage({type:'done'})})())});
async function hex(s){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
self.addEventListener('fetch',e=>{const u=new URL(e.request.url),base=new URL(self.registration.scope);
  if(u.origin!==base.origin||!u.pathname.startsWith(base.pathname))return;
  let rel=decodeURIComponent(u.pathname.slice(base.pathname.length));if(rel.endsWith('/'))rel+='index.html';
  if(!DIRS.some(d=>rel.startsWith(d+'/')))return;
  e.respondWith((async()=>{const k=await getKey();
    if(!k)return e.request.mode==='navigate'?Response.redirect(base.href+'?next='+encodeURIComponent(rel),302):new Response('ログインしてください',{status:401});
    const r=await fetch(base.href+'enc/'+await hex(rel),{cache:'no-cache'});if(!r.ok)return new Response('見つかりません',{status:404,headers:{'Content-Type':'text/plain; charset=utf-8'}});
    const b=new Uint8Array(await r.arrayBuffer());let p;try{p=await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},k,b.slice(12))}catch(_){await idb('del');KEY=null;return e.request.mode==='navigate'?Response.redirect(base.href+'?next='+encodeURIComponent(rel),302):new Response('合言葉が変わりました。ログインし直してください',{status:401})}
    const ext=rel.split('.').pop().toLowerCase();return new Response(p,{headers:{'Content-Type':TYPES[ext]||'application/octet-stream'}})})())});
