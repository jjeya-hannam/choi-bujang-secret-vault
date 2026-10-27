import {parseStrictJson} from './json.mjs';
import {createServer} from 'node:https';
import {request as httpRequest} from 'node:http';
import {createHash,randomUUID} from 'node:crypto';
import {readRegistry} from './registry.mjs';
import {verifyToken,requireKey,exact,ID,SUBJECT,fail} from './security.mjs';
import {createOriginProof} from './origin-proof.mjs';
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const basic=['appId','audience','projectId'];
function send(res,status,body,requestId){if(res.destroyed||res.writableEnded)return;
  const bytes=Buffer.from(JSON.stringify(body));
  res.writeHead(status,{'content-type':'application/json','content-length':bytes.length,'cache-control':'no-store','x-content-type-options':'nosniff',...(requestId?{'x-sdp-request-id':requestId}:{})});
  res.end(bytes);
}
function header(req,name){if(req.rawHeaders.filter((_,i)=>i%2===0&&req.rawHeaders[i].toLowerCase()===name).length!==1)fail();
  return req.headers[name];
}
function authenticate(req,options){if(!req.socket.authorized)fail();
  const peer=req.socket.getPeerCertificate();
  if(!peer?.raw)fail();
  const fingerprint=createHash('sha256').update(peer.raw).digest('hex'),authorization=header(req,'authorization');
  if(typeof authorization!=='string'||!/^Bearer [A-Za-z0-9_.-]+$/.test(authorization))fail();
  const claims=verifyToken(authorization.slice(7),options.jwt,fingerprint),registry=readRegistry(options.registryPath),device=registry.devices.find(d=>d.deviceId===claims.deviceId);
  if(!device||device.revoked||device.certificateFingerprint!==fingerprint||device.subjectId!==claims.sub||device.projectId!==claims.projectId)fail();
  return {claims,registry,device};
}
function context(a){const now=Date.now();
  return {subjectId:a.claims.sub,projectId:a.claims.projectId,classId:'self-hosted',deviceId:a.claims.deviceId,sessionId:a.claims.sid,policyRevision:a.registry.revision,registryDigest:digest(a.registry),catalogDigest:digest(a.apps),observedAtMs:now,validUntilMs:Math.min(now+5000,a.claims.exp*1000),deviceStatus:'unknown'};
}
function allowed(a,app){return !!app&&a.device.apps.includes(app.id)&&app.subjects.includes(a.claims.sub);
}
function validateOptions(options){if(!options||typeof options!=='object')fail();
  requireKey(options.jwt?.key);
  if(typeof options.jwt.issuer!=='string'||!options.jwt.issuer||typeof options.jwt.audience!=='string'||!options.jwt.audience||typeof options.registryPath!=='string'||!Array.isArray(options.apps)||options.apps.length>100)fail('SDP_INVALID_CONFIGURATION');
  const ids=new Set();
  for(const app of options.apps){exact(app,['id','name','upstream','subjects']);
    if(typeof app.id!=='string'||!ID.test(app.id)||ids.has(app.id)||typeof app.name!=='string'||!app.name||app.name.length>80||/[\x00-\x1f\x7f]/.test(app.name)||!Array.isArray(app.subjects)||app.subjects.some(s=>typeof s!=='string'||!SUBJECT.test(s))||new Set(app.subjects).size!==app.subjects.length)fail('SDP_INVALID_CONFIGURATION');
    ids.add(app.id);
    let u;
    try{u=new URL(app.upstream);
    }
    catch{fail();
    }if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port||u.username||u.password||u.pathname!=='/'||u.search||u.hash)fail('SDP_INVALID_UPSTREAM');
  }
  if(options.originKeys!==undefined){
    if(!options.originKeys||typeof options.originKeys!=='object'||Array.isArray(options.originKeys))fail('SDP_INVALID_CONFIGURATION');
    for(const [appId,key] of Object.entries(options.originKeys)){
      if(!ids.has(appId))fail('SDP_INVALID_CONFIGURATION');
      requireKey(key);
      if(key.equals(options.jwt.key))fail('SDP_DISTINCT_KEY_REQUIRED');
    }
  }
  if(options.xdrBridge!==undefined&&(!options.xdrBridge||typeof options.xdrBridge.inspect!=='function'))fail('SDP_INVALID_CONFIGURATION');
  readRegistry(options.registryPath);
}
async function body(req){if(header(req,'content-type')!=='application/json'||req.headers['content-encoding']!==undefined||req.headers['transfer-encoding']!==undefined)fail();
  const length=header(req,'content-length');
  if(typeof length!=='string'||!/^\d{1,4}$/.test(length)||Number(length)>4096)fail();
  let size=0;
  const chunks=[];
  for await(const chunk of req){size+=chunk.length;
    if(size>4096)fail();
    chunks.push(chunk);
  }if(size!==Number(length))fail();
  try{return parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
  }
  catch{fail();
  }}
function proxy(req,res,options,a,app,path){return new Promise(resolve=>{let completed=false,upstream,response;
    const finish=(status,code)=>{if(completed)return;
      completed=true;
      clearTimeout(timer);
      upstream?.destroy();
      response?.destroy();
      send(res,status,{ok:false,error:{code}});
      resolve();
    };
    const timer=setTimeout(()=>finish(504,'SDP_UPSTREAM_TIMEOUT'),3000);
    res.once('close',()=>{if(!completed)finish(502,'SDP_UPSTREAM_CLOSED');
    });
    try{const current=authenticate(req,options);
      if(!allowed(current,app)||current.claims.sid!==a.claims.sid)fail();
      const key=options.originKeys[app.id];
      if(!key)fail('SDP_ORIGIN_KEY_REQUIRED');
      const proof=createOriginProof(key,{method:req.method,path,appId:app.id,subjectId:a.claims.sub,projectId:a.claims.projectId,deviceId:a.claims.deviceId});
      const base=new URL(app.upstream);
      upstream=httpRequest({hostname:'127.0.0.1',port:base.port,path,method:req.method,agent:false,headers:{accept:'application/json, text/plain, text/html','x-sdp-origin-proof':proof}},reply=>{response=reply;
        if(reply.statusCode>=300&&reply.statusCode<400){finish(502,'SDP_UPSTREAM_REDIRECT');
          return;
        }if(!Number.isInteger(reply.statusCode)||reply.statusCode<200||reply.statusCode>599){finish(502,'SDP_UPSTREAM_INVALID');
          return;
        }let size=0;
        const chunks=[];
        reply.on('data',chunk=>{size+=chunk.length;
          if(size>1024*1024){finish(502,'SDP_UPSTREAM_TOO_LARGE');
            return;
          }chunks.push(chunk);
        });
        reply.on('error',()=>finish(502,'SDP_UPSTREAM_FAILED'));
        reply.on('aborted',()=>finish(502,'SDP_UPSTREAM_FAILED'));
        reply.on('end',()=>{if(completed)return;
          try{const current=authenticate(req,options);
            if(!allowed(current,app)||current.claims.sid!==a.claims.sid)fail();
            const payload=Buffer.concat(chunks),type=reply.headers['content-type'];
            const safeType=typeof type==='string'&&!/[\r\n]/.test(type)?type:'application/octet-stream';
            res.writeHead(reply.statusCode,{'content-type':safeType,'content-length':payload.length,'cache-control':'no-store','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; frame-ancestors 'none'; sandbox"});
            res.end(req.method==='HEAD'?undefined:payload);
            completed=true;
            clearTimeout(timer);
            resolve();
          }
          catch{finish(403,'SDP_REJECTED');
          }});
      });
      upstream.on('error',()=>finish(502,'SDP_UPSTREAM_FAILED'));
      upstream.end();
    }
    catch{finish(502,'SDP_UPSTREAM_FAILED');
    }});
}
export function createSdpServer(input){validateOptions(input);
  const options={...input,jwt:{...input.jwt,key:Buffer.from(input.jwt.key)},apps:structuredClone(input.apps),originKeys:Object.fromEntries(Object.entries(input.originKeys??{}).map(([id,key])=>[id,Buffer.from(key)]))};
  const server=createServer({...options.tls,requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.3',maxHeaderSize:8192},async(req,res)=>{try{const host=header(req,'host');
      if(typeof host!=='string'||!host||req.url.length>2048||!req.url.startsWith('/')||req.url.startsWith('//')||/[\\\x00-\x20\x7f]/.test(req.url))fail();
      const rawPath=req.url.split('?')[0];
      if(/%2f|%5c|%2e/i.test(rawPath)||rawPath.split('/').some(s=>s==='.'||s==='..'))fail();
      const url=new URL(req.url,'https://sdp.invalid');
      const a=authenticate(req,options);
      a.apps=options.apps;
      if(url.pathname.startsWith('/protected/')){if(!['GET','HEAD'].includes(req.method)||req.headers['transfer-encoding']!==undefined||req.headers['content-length']!==undefined&&req.headers['content-length']!=='0')fail();
        const match=/^\/protected\/([A-Za-z0-9][A-Za-z0-9._:-]{0,79})(\/.*)$/.exec(url.pathname);
        if(!match)fail();
        const app=options.apps.find(v=>v.id===match[1]);
        if(!allowed(a,app)){send(res,403,{ok:false,error:{code:'SDP_APP_DENIED'}});
          return;
        }
        if(!Object.hasOwn(options.originKeys,app.id)){send(res,403,{ok:false,error:{code:'SDP_ORIGIN_KEY_REQUIRED'}});return;}
        if(options.xdrBridge){
          const headers=Object.fromEntries(Object.entries(req.headers).filter(([name])=>!['authorization','proxy-authorization','cookie'].includes(name)&&!name.startsWith('x-sdp-')));
          const finding=options.xdrBridge.inspect({binding:{subjectId:a.claims.sub,projectId:a.claims.projectId,deviceId:a.claims.deviceId,certificateFingerprint:a.device.certificateFingerprint},request:{method:req.method,path:req.url,headers}});
          if(!finding||!['block','alert','record'].includes(finding.action))fail();
          if(finding.action==='block'){send(res,403,{ok:false,error:{code:'SDP_XDR_BLOCKED'}});return;}
        }
        await proxy(req,res,options,a,app,match[2]+url.search);
        return;
      }
      if(req.method!=='POST'||url.search||!['/alekov/context','/alekov/apps','/alekov/decision'].includes(url.pathname)){send(res,404,{ok:false,error:{code:'SDP_ROUTE_UNSUPPORTED'}});
        return;
      }
      const kind=url.pathname.slice('/alekov/'.length),data=await body(req),keys=kind==='context'?basic:kind==='apps'?[...basic,'sessionId']:[...basic,'sessionId','targetAppId','clientRequestId'];
      exact(data,keys);
      if(data.appId!=='aleph-on'||data.audience!=='on-client'||data.projectId!==a.claims.projectId||kind!=='context'&&data.sessionId!==a.claims.sid)fail();
      if(kind==='decision'&&(typeof data.targetAppId!=='string'||!ID.test(data.targetAppId)||typeof data.clientRequestId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(data.clientRequestId)))fail();
      const latest=authenticate(req,options);
      latest.apps=options.apps;
      const engineRequestId=randomUUID(),c=context(latest),out={schema:'alekov.sdp.admission.v1',kind,engineRequestId,context:c};
      if(kind==='apps')out.apps=options.apps.filter(app=>allowed(latest,app)).map(app=>({id:app.id,name:app.name,subjectId:c.subjectId,projectId:c.projectId}));
      if(kind==='decision'){const yes=allowed(latest,options.apps.find(app=>app.id===data.targetAppId));
        out.decision={appId:data.targetAppId,clientRequestId:data.clientRequestId,engineRequestId,decision:yes?'allow':'deny',reason:yes?'device_app_allowed':'device_app_denied',ruleIds:[yes?'device_app_allowed':'device_app_denied'],checkedAt:new Date(c.observedAtMs).toISOString(),subjectId:c.subjectId,projectId:c.projectId,sessionId:c.sessionId};
      }send(res,200,out,engineRequestId);
    }
    catch{send(res,403,{ok:false,error:{code:'SDP_REJECTED'}});
    }});
  server.headersTimeout=5000;
  server.requestTimeout=6000;
  server.keepAliveTimeout=1000;
  server.maxRequestsPerSocket=20;
  const listen=server.listen.bind(server);
  server.listen=(...args)=>{const first=args[0];
    if(typeof first==='object'){if(first.host!=='127.0.0.1')fail('SDP_LOOPBACK_REQUIRED');
    }
    else if(args[1]!=='127.0.0.1')fail('SDP_LOOPBACK_REQUIRED');
    return listen(...args);
  };
  return server;
}
