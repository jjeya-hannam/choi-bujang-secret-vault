import {parseStrictJson} from './json.mjs';
import {readSync,lstatSync,fstatSync,openSync,closeSync,constants} from 'node:fs';
import {resolve,isAbsolute,relative,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {exact,fail,requireKey,ID} from './security.mjs';
const sourceRoot=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
export function outsideSource(path){if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path)fail('SDP_PRIVATE_PATH_REQUIRED');
  const rel=relative(sourceRoot,path);
  if(!(rel==='..'||rel.startsWith('..'+sep)||isAbsolute(rel)))fail('SDP_PRIVATE_PATH_REQUIRED');
  let current=path;
  for(;;){try{if(lstatSync(current).isSymbolicLink())fail('SDP_PRIVATE_PATH_REQUIRED');
    }
    catch(error){if(error.code!=='ENOENT')throw error;
    }const parent=dirname(current);
    if(parent===current)break;
    current=parent;
  }return path;
}
export function readPrivateFile(path,max=65536){outsideSource(path);
  const valid=st=>st.isFile()&&st.nlink===1&&st.size<=max&&(process.platform==='win32'||(st.mode&0o077)===0),same=(a,b)=>['dev','ino','size','mtimeMs','ctimeMs'].every(k=>a[k]===b[k]);
  const before=lstatSync(path);
  if(!valid(before)||before.isSymbolicLink())fail('SDP_PRIVATE_FILE_REQUIRED');
  const fd=openSync(path,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{const opened=fstatSync(fd);
    if(!valid(opened)||!same(before,opened))fail('SDP_PRIVATE_FILE_REQUIRED');
    const buffer=Buffer.alloc(max+1);
    let size=0;
    while(size<buffer.length){const count=readSync(fd,buffer,size,buffer.length-size,size);if(count===0)break;size+=count;}
    const bytes=buffer.subarray(0,size);
    const after=fstatSync(fd),named=lstatSync(path);
    outsideSource(path);
    if(bytes.length>max||bytes.length!==opened.size||!valid(after)||!same(opened,after)||!same(after,named)||named.isSymbolicLink())fail('SDP_PRIVATE_FILE_REQUIRED');
    return bytes;
  }
  finally{closeSync(fd);
  }}
export function loadConfiguration(path){let c;
  try{c=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(readPrivateFile(path,65536)));
  }
  catch{fail('SDP_INVALID_CONFIGURATION');
  }
  const optional=['originKeyFiles','xdrEvidenceFile','xdrEvidenceKeyFile'];
  exact(c,['schema','host','port','caFile','certFile','keyFile','jwtKeyFile','issuer','audience','registryFile','apps',...optional.filter(name=>Object.hasOwn(c,name))]);
  if(c.schema!=='student.sdp.server.v1'||c.host!=='127.0.0.1'||!Number.isInteger(c.port)||c.port<1024||c.port>65535)fail('SDP_INVALID_CONFIGURATION');
  outsideSource(c.registryFile);
  const key=readPrivateFile(c.jwtKeyFile,128);
  requireKey(key);
  const originKeys=Object.create(null);
  if(Object.hasOwn(c,'originKeyFiles')){
    if(!c.originKeyFiles||typeof c.originKeyFiles!=='object'||Array.isArray(c.originKeyFiles)||Object.keys(c.originKeyFiles).length>100)fail('SDP_INVALID_CONFIGURATION');
    for(const [appId,path] of Object.entries(c.originKeyFiles)){
      if(!ID.test(appId)||!Array.isArray(c.apps)||!c.apps.some(app=>app.id===appId))fail('SDP_INVALID_CONFIGURATION');
      const originKey=readPrivateFile(path,128);
      requireKey(originKey);
      if(originKey.equals(key))fail('SDP_DISTINCT_KEY_REQUIRED');
      originKeys[appId]=originKey;
    }
  }
  const hasEvidence=Object.hasOwn(c,'xdrEvidenceFile'),hasEvidenceKey=Object.hasOwn(c,'xdrEvidenceKeyFile');
  if(hasEvidence!==hasEvidenceKey)fail('SDP_INVALID_CONFIGURATION');
  let xdr;
  if(hasEvidence){
    const evidencePath=outsideSource(c.xdrEvidenceFile),evidenceKey=readPrivateFile(c.xdrEvidenceKeyFile,128);
    requireKey(evidenceKey);
    if(evidenceKey.equals(key)||Object.values(originKeys).some(originKey=>originKey.equals(evidenceKey)))fail('SDP_DISTINCT_KEY_REQUIRED');
    xdr={evidencePath,evidenceKey};
  }
  return {host:c.host,port:c.port,tls:{ca:readPrivateFile(c.caFile),cert:readPrivateFile(c.certFile),key:readPrivateFile(c.keyFile)},jwt:{key,issuer:c.issuer,audience:c.audience},registryPath:c.registryFile,apps:c.apps,originKeys,...(xdr?{xdr}:{})};
}
