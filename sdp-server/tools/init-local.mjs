// Explicit local-only bootstrap. It does not install trust or open network ports.
import {execFileSync} from 'node:child_process';
import {mkdirSync,lstatSync,writeFileSync,readdirSync,chmodSync,realpathSync} from 'node:fs';
import {resolve,isAbsolute,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,X509Certificate} from 'node:crypto';
import {outsideSource,readPrivateFile} from '../src/config.mjs';
import {initializeRegistry,enrollDevice} from '../src/registry.mjs';
import {createToken} from '../src/security.mjs';
import {validateWindowsLaunch} from './windows-preflight.mjs';

const fail=()=>{throw Error('SDP_LOCAL_INIT_FAILED');};
export function parseInitArguments(args){
  if(args.length!==4||args[0]!=='--private-dir'||args[2]!=='--openssl')fail();
  for(const value of [args[1],args[3]])if(typeof value!=='string'||!isAbsolute(value)||resolve(value)!==value||/[\x00-\x1f]/.test(value))fail();
  return {privateDir:args[1],openssl:args[3]};
}
export function initializeLocal({privateDir,openssl}){
  const version=/^(\d+)\.(\d+)\.(\d+)$/.exec(process.versions.node);
  if(!version||Number(version[1])!==24||Number(version[2])<19)fail();
  parseInitArguments(['--private-dir',privateDir,'--openssl',openssl]);
  if(process.platform==='win32')for(const configPath of [privateDir,openssl])validateWindowsLaunch({platform:process.platform,nodeVersion:process.versions.node,mode:'server',configPath});
  outsideSource(privateDir);
  const executable=lstatSync(openssl);
  if(!executable.isFile()||executable.isSymbolicLink()||realpathSync(openssl)!==openssl)fail();
  // A single atomic mkdir refuses every pre-existing destination.
  mkdirSync(privateDir,{mode:0o700});
  if(process.platform==='win32'){
    execFileSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',[
      '-NoLogo','-NoProfile','-NonInteractive','-File',fileURLToPath(new URL('../windows/create-private-directory.ps1',import.meta.url)),
      '-PrivateDirectory',privateDir,
    ],{shell:false,windowsHide:true,stdio:'ignore',timeout:10000});
  }
  const write=(name,value)=>writeFileSync(join(privateDir,name),value,{flag:'wx',mode:0o600});
  write('openssl.cnf','[req]\ndistinguished_name=req_distinguished_name\nx509_extensions=ca_extensions\n[req_distinguished_name]\n[ca_extensions]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n');
  // Do not inherit provider/config/seed locations that can redirect OpenSSL.
  const env=process.platform==='win32'?{SystemRoot:'C:\\Windows',WINDIR:'C:\\Windows',PATH:'C:\\Windows\\System32',TEMP:privateDir,TMP:privateDir}:{PATH:'/usr/bin:/bin',TMPDIR:privateDir};
  env.OPENSSL_CONF=join(privateDir,'openssl.cnf');
  env.RANDFILE=join(privateDir,'.rnd');
  const run=(...args)=>execFileSync(openssl,args,{cwd:privateDir,env,shell:false,windowsHide:true,stdio:'ignore',timeout:30000});
  run('req','-x509','-newkey','rsa:3072','-nodes','-keyout','ca.key','-out','ca.pem','-days','365','-subj','/CN=SDP Local Development CA');
  for(const name of ['server','device']){
    run('req','-newkey','rsa:3072','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj',name==='server'?'/CN=localhost':'/CN=SDP Local Development Device');
    write(name+'.ext',name==='server'?'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n':'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n');
    run('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','30','-extfile',name+'.ext');
  }
  // OpenSSL-created certificate files inherit umask on POSIX; restrict before reads.
  if(process.platform!=='win32')for(const name of readdirSync(privateDir))chmodSync(join(privateDir,name),0o600);
  const jwtKey=randomBytes(48),originKey=randomBytes(48),evidenceKey=randomBytes(48);
  write('jwt.key',jwtKey);write('vault-origin.key',originKey);write('xdr-evidence.key',evidenceKey);
  const subjectId=randomBytes(32).toString('hex'),deviceId=randomBytes(8).toString('hex'),projectId='local-project';
  const fingerprint=new X509Certificate(readPrivateFile(join(privateDir,'device.pem'))).fingerprint256.replaceAll(':','').toLowerCase();
  const registryPath=join(privateDir,'registry.json');
  initializeRegistry(registryPath);
  enrollDevice(registryPath,{subjectId,projectId,deviceId,certificateFingerprint:fingerprint,apps:['vault']});
  write('access-token.txt',createToken({key:jwtKey,issuer:'local-sdp',audience:'local-sdp-client',subjectId,projectId,deviceId,certificateFingerprint:fingerprint})+'\n');
  const path=name=>join(privateDir,name),json=value=>JSON.stringify(value,null,2)+'\n';
  write('server.json',json({schema:'student.sdp.server.v1',host:'127.0.0.1',port:7443,caFile:path('ca.pem'),certFile:path('server.pem'),keyFile:path('server.key'),jwtKeyFile:path('jwt.key'),issuer:'local-sdp',audience:'local-sdp-client',registryFile:registryPath,originKeyFiles:{vault:path('vault-origin.key')},xdrEvidenceFile:path('xdr-proposals.json'),xdrEvidenceKeyFile:path('xdr-evidence.key'),apps:[{id:'vault',name:'Local example resource',upstream:'http://127.0.0.1:8080',subjects:[subjectId]}]}));
  write('client.json',json({schema:'alekov.sdp.host.v1',projectId,host:'127.0.0.1',port:7443,servername:'localhost',caFile:path('ca.pem'),certFile:path('device.pem'),keyFile:path('device.key'),tokenFile:path('access-token.txt')}));
  write('response.json',json({schema:'student.sdp.response.v1',registryFile:registryPath,evidenceFile:path('xdr-proposals.json'),evidenceKeyFile:path('xdr-evidence.key')}));
  write('LOCAL_ONLY.txt','Local development identity only. Not proof of a real user. No global trust, firewall rule or server was installed. Token expires after 5 minutes.\n');
  return Object.freeze({status:'SDP_LOCAL_INITIALIZED',localOnly:true,tokenLifetimeSeconds:300});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{initializeLocal(parseInitArguments(process.argv.slice(2)));console.log('SDP_LOCAL_INITIALIZED');}
  catch{console.error('SDP_LOCAL_INIT_FAILED');process.exitCode=1;}
}
