import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {parseStrictJson} from './json.mjs';
import {exact,requireKey,ID,SUBJECT,PROJECT,DEVICE,fail} from './security.mjs';

const PROOF_HEADER='x-sdp-origin-proof';
const FIELDS=['v','method','path','appId','subjectId','projectId','deviceId','at','nonce'];
function reject(){fail('SDP_ORIGIN_REJECTED');}
function valid(value){
  exact(value,FIELDS);
  if(value.v!==1||!['GET','HEAD'].includes(value.method)
    ||typeof value.path!=='string'||value.path.length>2048||!value.path.startsWith('/')||value.path.startsWith('//')||/[\\\x00-\x20\x7f]/.test(value.path)
    ||typeof value.appId!=='string'||!ID.test(value.appId)
    ||typeof value.subjectId!=='string'||!SUBJECT.test(value.subjectId)
    ||typeof value.projectId!=='string'||!PROJECT.test(value.projectId)
    ||typeof value.deviceId!=='string'||!DEVICE.test(value.deviceId)
    ||!Number.isSafeInteger(value.at)||value.at<=0
    ||typeof value.nonce!=='string'||!/^[0-9a-f]{32}$/.test(value.nonce))reject();
}

// Only the gateway owns this key. Browser credentials never reach the origin.
export function createOriginProof(key,{method,path,appId,subjectId,projectId,deviceId}){
  requireKey(key);
  const value={v:1,method,path,appId,subjectId,projectId,deviceId,at:Date.now(),nonce:randomBytes(16).toString('hex')};
  valid(value);
  const encoded=Buffer.from(JSON.stringify(value)).toString('base64url');
  return encoded+'.'+createHmac('sha256',key).update(encoded).digest('base64url');
}

export function createOriginGuard({key,appId,ttlMs=10000,maxNonces=4096}){
  requireKey(key);
  if(typeof appId!=='string'||!ID.test(appId)||!Number.isInteger(ttlMs)||ttlMs<1000||ttlMs>30000
    ||!Number.isInteger(maxNonces)||maxNonces<1||maxNonces>100000)reject();
  const secret=Buffer.from(key),nonces=new Map();
  return Object.freeze({
    verify(req){
      try{
        if(req.rawHeaders.filter((_,i)=>i%2===0&&req.rawHeaders[i].toLowerCase()===PROOF_HEADER).length!==1)reject();
        const token=req.headers[PROOF_HEADER];
        if(typeof token!=='string'||token.length>4096||req.headers['transfer-encoding']!==undefined
          ||req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')reject();
        const parts=token.split('.');
        if(parts.length!==2||!/^[A-Za-z0-9_-]+$/.test(parts[0])||!/^[A-Za-z0-9_-]{43}$/.test(parts[1]))reject();
        const signature=Buffer.from(parts[1],'base64url'),expected=createHmac('sha256',secret).update(parts[0]).digest();
        if(signature.length!==expected.length||signature.toString('base64url')!==parts[1]||!timingSafeEqual(signature,expected))reject();
        const bytes=Buffer.from(parts[0],'base64url');
        if(bytes.toString('base64url')!==parts[0])reject();
        const value=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
        valid(value);
        const now=Date.now();
        if(value.appId!==appId||value.method!==req.method||value.path!==req.url||value.at>now+1000||now-value.at>ttlMs)reject();
        for(const [nonce,expires] of nonces)if(expires<now)nonces.delete(nonce);
        if(nonces.has(value.nonce)||nonces.size>=maxNonces)reject();
        nonces.set(value.nonce,value.at+ttlMs);
        return Object.freeze({appId,subjectId:value.subjectId,projectId:value.projectId,deviceId:value.deviceId});
      }catch{reject();}
    },
  });
}

// Install before every protected route; it is not enough to add it to one URL.
// The handler receives verified identity as its third argument, never by trusting headers.
export function createProtectedOriginHandler(configuration,handler){
  if(typeof handler!=='function')reject();
  const guard=createOriginGuard(configuration);
  return function protectedOrigin(req,res){
    let context;
    try{context=guard.verify(req);}catch{
      res.writeHead(403,{'content-type':'application/json','cache-control':'no-store'});
      res.end('{"ok":false,"error":{"code":"SDP_ORIGIN_REJECTED"}}');
      return;
    }
    for(const name of Object.keys(req.headers))if(name.startsWith('x-sdp-'))delete req.headers[name];
    for(let i=req.rawHeaders.length-2;i>=0;i-=2)if(req.rawHeaders[i].toLowerCase().startsWith('x-sdp-'))req.rawHeaders.splice(i,2);
    return handler(req,res,context);
  };
}
