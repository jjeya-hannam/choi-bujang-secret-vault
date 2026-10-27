import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm,realpath,chmod,symlink,link,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createServer as createOrigin} from 'node:http';
import {request} from 'node:https';
import {createHmac,randomBytes,X509Certificate} from 'node:crypto';
import {createSdpServer} from '../src/server.mjs';
import {createProtectedOriginHandler} from '../src/origin-proof.mjs';
import {createToken} from '../src/security.mjs';
import {loadConfiguration,outsideSource,readPrivateFile} from '../src/config.mjs';
import {initializeRegistry,enrollDevice,revokeDevice} from '../src/registry.mjs';
import {readSdpHostConfiguration} from '../../on-client/src/engine/sdp-host-config.mjs';
import {createSdpHostEngine} from '../../on-client/src/engine/sdp-host.mjs';
import {createStudentServer} from '../../on-client/student/pc-server.mjs';

const subjectId='a'.repeat(64),projectId='sample-project',deviceId='1'.repeat(16),sessionId='session-one';
const listen=server=>new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',()=>{server.removeListener('error',fail);ok(server.address().port);});});
const close=server=>new Promise(resolve=>server.close(resolve));

async function certificates(directory){
  const run=(...args)=>execFileSync('openssl',args,{cwd:directory,stdio:'ignore'});
  run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=SDP Synthetic Test CA');
  for(const name of ['server','client','other']){
    run('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN=SDP Synthetic '+name);
    await writeFile(join(directory,name+'.ext'),name==='server'?'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n':'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n');
    run('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','2','-extfile',name+'.ext');
  }
  run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','foreign.key','-out','foreign.pem','-days','2','-subj','/CN=Untrusted Synthetic Client');
  const file=name=>readFile(join(directory,name));
  return {ca:await file('ca.pem'),server:{cert:await file('server.pem'),key:await file('server.key')},client:{cert:await file('client.pem'),key:await file('client.key')},other:{cert:await file('other.pem'),key:await file('other.key')},foreign:{cert:await file('foreign.pem'),key:await file('foreign.key')}};
}

function call(port,tls,path,{token,method='POST',body,headers={}}={}){
  return new Promise((ok,fail)=>{
    const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));
    const req=request({hostname:'127.0.0.1',port,path,servername:'localhost',...tls,rejectUnauthorized:true,agent:false,method,headers:{...(token?{authorization:'Bearer '+token}:{}),...(bytes?{'content-type':'application/json','content-length':bytes.length}:{}),...headers}},res=>{
      const chunks=[];res.on('data',x=>chunks.push(x));res.once('error',fail);res.once('end',()=>{const text=Buffer.concat(chunks).toString();let data;try{data=JSON.parse(text);}catch{}ok({status:res.statusCode,headers:res.headers,text,data});});
    });
    req.setTimeout(4000,()=>req.destroy(new Error('TEST_TIMEOUT')));req.once('error',fail);req.end(bytes);
  });
}

test('standalone SDP: real TLS, identity binding, host compatibility, gateway and persistent revocation',async t=>{
  const directory=await realpath(await mkdtemp(join(tmpdir(),'sdp-synthetic-')));
  let server,origin,host,student;
  try{
    const certs=await certificates(directory),key=randomBytes(48),originKey=randomBytes(48),issuer='synthetic-sdp',audience='synthetic-client';
    const fingerprint=new X509Certificate(certs.client.cert).fingerprint256.replaceAll(':','').toLowerCase();
    const registryPath=join(directory,'registry.json');
    await initializeRegistry(registryPath);
    await enrollDevice(registryPath,{subjectId,projectId,deviceId,certificateFingerprint:fingerprint,apps:['vault']});
    const seen=[];let pendingResponse,pendingStarted;const pendingReady=new Promise(r=>{pendingStarted=r;});
    origin=createOrigin(createProtectedOriginHandler({key:originKey,appId:'vault'},(req,res)=>{
      seen.push({url:req.url,headers:req.headers});
      if(req.url==='/pending'){pendingResponse=res;pendingStarted();return;}
      if(req.url==='/redirect'){res.writeHead(302,{location:'http://127.0.0.1:1/never'});res.end();return;}
      res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({ok:true}));
    }));
    const upstreamPort=await listen(origin);
    const options={tls:{...certs.server,ca:certs.ca},jwt:{key,issuer,audience},registryPath,originKeys:{vault:originKey},apps:[{id:'vault',name:'Synthetic Vault',upstream:`http://127.0.0.1:${upstreamPort}`,subjects:[subjectId]}]};
    server=createSdpServer(options);let port=await listen(server);
    const tokenOptions={key,issuer,audience,subjectId,projectId,deviceId,certificateFingerprint:fingerprint,sessionId,ttlSeconds:300};
    const token=await createToken(tokenOptions),tls={...certs.client,ca:certs.ca},base={appId:'aleph-on',audience:'on-client',projectId};

    await t.test('private configuration rejects source children, links and permissive files',async()=>{
      for(const name of ['ca.pem','server.pem','server.key'])await chmod(join(directory,name),0o600);
      const keyPath=join(directory,'signing-key.bin');await writeFile(keyPath,key,{mode:0o600});
      const configPath=join(directory,'server-config.json');
      await writeFile(configPath,JSON.stringify({schema:'student.sdp.server.v1',host:'127.0.0.1',port:7443,caFile:join(directory,'ca.pem'),certFile:join(directory,'server.pem'),keyFile:join(directory,'server.key'),jwtKeyFile:keyPath,issuer,audience,registryFile:registryPath,apps:options.apps}),{mode:0o600});
      assert.equal(loadConfiguration(configPath).registryPath,registryPath);
      assert.throws(()=>outsideSource(resolve(import.meta.dirname,'../..','..private','missing.json')));
      const soft=join(directory,'soft.bin');await symlink(keyPath,soft);assert.throws(()=>readPrivateFile(soft));
      const hard=join(directory,'hard.bin');await link(keyPath,hard);assert.throws(()=>readPrivateFile(hard));await unlink(hard);
      await chmod(keyPath,0o644);assert.throws(()=>loadConfiguration(configPath));await chmod(keyPath,0o600);
    });
    await t.test('approved mTLS device and bound JWT receive real context',async()=>{
      const result=await call(port,tls,'/alekov/context',{token,body:base});
      assert.equal(result.status,200);assert.equal(result.data.context.subjectId,subjectId);assert.equal(result.data.context.deviceId,deviceId);
      assert.equal(result.data.engineRequestId,result.headers['x-sdp-request-id']);
    });
    await t.test('no client certificate and foreign certificate cannot enter',async()=>{
      for(const identity of [{ca:certs.ca},{...certs.foreign,ca:certs.ca}]){
        await assert.rejects(call(port,identity,'/alekov/context',{token,body:base}));
      }
    });
    await t.test('missing token, certificate replay and unregistered device are rejected',async()=>{
      assert.equal((await call(port,tls,'/alekov/context',{body:base})).status,403);
      assert.equal((await call(port,{...certs.other,ca:certs.ca},'/alekov/context',{token,body:base})).status,403);
      const unknown=await createToken({...tokenOptions,deviceId:'2'.repeat(16)});
      assert.equal((await call(port,tls,'/alekov/context',{token:unknown,body:base})).status,403);
    });
    await t.test('tampered and expired signed tokens fail closed',async()=>{
      const parts=token.split('.'),payload=JSON.parse(Buffer.from(parts[1],'base64url'));
      payload.exp=Math.floor(Date.now()/1000)-1;payload.iat=payload.exp-300;payload.nbf=payload.iat;
      const expiredPayload=Buffer.from(JSON.stringify(payload)).toString('base64url'),unsigned=parts[0]+'.'+expiredPayload;
      const expired=unsigned+'.'+createHmac('sha256',key).update(unsigned).digest('base64url');
      for(const value of [token.slice(0,-2)+'xx',expired])assert.equal((await call(port,tls,'/alekov/context',{token:value,body:base})).status,403);
    });
    await t.test('existing app host reads identity/apps and obtains allow plus deny',async()=>{
      const tokenPath=join(directory,'access-token.txt');await writeFile(tokenPath,token+'\n',{mode:0o600});
      const configurationPath=join(directory,'host.json');
      await writeFile(configurationPath,JSON.stringify({schema:'alekov.sdp.host.v1',projectId,host:'127.0.0.1',port,servername:'localhost',caFile:join(directory,'ca.pem'),certFile:join(directory,'client.pem'),keyFile:join(directory,'client.key'),tokenFile:tokenPath}),{mode:0o600});
      host=createSdpHostEngine(await readSdpHostConfiguration(configurationPath,{projectRoot:resolve(import.meta.dirname,'../../on-client')}));
      const identity=await host.readIdentity();assert.equal(identity.user.id,subjectId);
      const scope={subjectId,projectId,appId:'aleph-on',audience:'on-client'};
      assert.deepEqual((await host.readApps(scope)).map(x=>x.id),['vault']);
      assert.equal((await host.decideAccess({appId:'vault',requestId:'11111111-1111-4111-8111-111111111111'},scope)).decision,'allow');
      assert.equal((await host.decideAccess({appId:'unknown',requestId:'22222222-2222-4222-8222-222222222222'},scope)).decision,'deny');
      student=createStudentServer({sdpHost:host});const studentPort=await listen(student);
      const response=await fetch(`http://127.0.0.1:${studentPort}/api/me`);assert.equal(response.status,200);assert.equal((await response.json()).data.user.id,subjectId);
    });
    await t.test('gateway authorizes a real request and removes caller credentials/spoofing headers',async()=>{
      const result=await call(port,tls,'/protected/vault/hello',{token,method:'GET',headers:{cookie:'synthetic-secret=discard','x-forwarded-for':'203.0.113.10','x-real-ip':'203.0.113.11'}});
      assert.equal(result.status,200);assert.equal(seen.at(-1).url,'/hello');
      for(const name of ['authorization','cookie','x-forwarded-for','x-real-ip'])assert.equal(seen.at(-1).headers[name],undefined);
      const before=seen.length;assert.notEqual((await call(port,tls,'/protected/unknown/hello',{token,method:'GET'})).status,200);assert.equal(seen.length,before);
    });
    await t.test('upstream redirects are not followed or exposed as successful protected content',async()=>{
      const result=await call(port,tls,'/protected/vault/redirect',{token,method:'GET'});
      assert.ok(result.status>=400);assert.equal(result.headers.location,undefined);
    });
    await t.test('revocation rejects the old token immediately and after restart',async()=>{
      const pending=call(port,tls,'/protected/vault/pending',{token,method:'GET'});await pendingReady;
      await revokeDevice(registryPath,deviceId);
      pendingResponse.writeHead(200,{'content-type':'text/plain'});pendingResponse.end('synthetic-protected-marker');
      const held=await pending;assert.equal(held.status,403);assert.ok(!held.text.includes('synthetic-protected-marker'));
      if(student){const response=await fetch(`http://127.0.0.1:${student.address().port}/api/me`);assert.ok(response.status>=400);}
      assert.equal((await call(port,tls,'/alekov/context',{token,body:base})).status,403);
      const before=seen.length;assert.equal((await call(port,tls,'/protected/vault/hello',{token,method:'GET'})).status,403);assert.equal(seen.length,before);
      await close(server);server=createSdpServer(options);port=await listen(server);
      assert.equal((await call(port,tls,'/alekov/context',{token,body:base})).status,403);
    });
  }finally{
    if(student?.listening)await close(student);host?.close();if(server?.listening)await close(server);if(origin?.listening)await close(origin);await rm(directory,{recursive:true,force:true});
  }
});
