import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,realpath,readFile,writeFile,rm,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {initializeLocal,parseInitArguments} from '../tools/init-local.mjs';
import {loadConfiguration,readPrivateFile} from '../src/config.mjs';
import {readRegistry} from '../src/registry.mjs';
import {verifyToken} from '../src/security.mjs';
import {createSdpServer} from '../src/server.mjs';
import {readSdpHostConfiguration} from '../../on-client/src/engine/sdp-host-config.mjs';
import {createSdpHostEngine} from '../../on-client/src/engine/sdp-host.mjs';
import {createDemoOrigin} from '../tools/demo-origin.mjs';
import {createOriginProof} from '../src/origin-proof.mjs';
const listen=server=>new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',()=>ok(server.address().port));});
const close=server=>new Promise(ok=>server.close(ok));

test('bootstrap rejects missing, relative, extra and noncanonical paths',()=>{
  for(const args of [[],['--private-dir','relative','--openssl','/usr/bin/openssl'],['--private-dir','/one/../two','--openssl','/usr/bin/openssl'],['--private-dir','/one','--openssl','/usr/bin/openssl','extra']])assert.throws(()=>parseInitArguments(args),/SDP_LOCAL_INIT_FAILED/);
});

test('real local bootstrap makes independent private credentials and refuses overwrite',{skip:process.platform==='win32'},async()=>{
  const parent=await realpath(await mkdtemp(join(tmpdir(),'sdp-bootstrap-'))),privateDir=join(parent,'private files');
  let server,host,origin;
  try {
    const openssl=await realpath('/usr/bin/openssl');
    const result=initializeLocal({privateDir,openssl});
    assert.deepEqual(result,{status:'SDP_LOCAL_INITIALIZED',localOnly:true,tokenLifetimeSeconds:300});
    const config=loadConfiguration(join(privateDir,'server.json')),registry=readRegistry(config.registryPath);
    assert.equal(config.host,'127.0.0.1');assert.equal(registry.devices.length,1);
    assert.notDeepEqual(config.jwt.key,config.originKeys.vault);assert.notDeepEqual(config.jwt.key,config.xdr.evidenceKey);
    const device=registry.devices[0],token=readPrivateFile(join(privateDir,'access-token.txt')).toString().trim();
    assert.equal(verifyToken(token,config.jwt,device.certificateFingerprint).sub,device.subjectId);
    const client=JSON.parse(await readFile(join(privateDir,'client.json'),'utf8'));
    assert.equal(client.projectId,device.projectId);assert.equal(client.servername,'localhost');
    assert.equal((await stat(join(privateDir,'device.key'))).mode&0o777,0o600);
    server=createSdpServer(config);const port=await listen(server);
    client.port=port;await writeFile(join(privateDir,'client.json'),JSON.stringify(client));
    host=createSdpHostEngine(await readSdpHostConfiguration(join(privateDir,'client.json'),{projectRoot:join(import.meta.dirname,'../../on-client')}));
    assert.equal((await host.readIdentity()).device.id,device.deviceId);
    origin=createDemoOrigin(config);const originPort=await listen(origin),url=`http://127.0.0.1:${originPort}/sample`;
    assert.equal((await fetch(url)).status,403);
    const proof=createOriginProof(config.originKeys.vault,{method:'GET',path:'/sample',appId:'vault',subjectId:device.subjectId,projectId:device.projectId,deviceId:device.deviceId});
    const response=await fetch(url,{headers:{'x-sdp-origin-proof':proof}});
    assert.equal(response.status,200);assert.equal((await response.json()).realVaultConnected,false);
    const before=await readFile(join(privateDir,'server.json'));
    assert.throws(()=>initializeLocal({privateDir,openssl}));
    assert.deepEqual(await readFile(join(privateDir,'server.json')),before);
  } finally {host?.close();if(server)await close(server);if(origin)await close(origin);await rm(parent,{recursive:true,force:true});}
});
