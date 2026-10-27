import {parseStrictJson} from './json.mjs';
import {readFileSync,writeFileSync,lstatSync,renameSync,unlinkSync,openSync,closeSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {SUBJECT,DEVICE,PROJECT,ID,HASH,exact,fail} from './security.mjs';
import {outsideSource,readPrivateFile} from './config.mjs';
const LIMIT=1024*1024;
export function validateDevice(d){exact(d,['subjectId','projectId','deviceId','certificateFingerprint','apps','revoked']);
  if(!SUBJECT.test(d.subjectId)||!PROJECT.test(d.projectId)||!DEVICE.test(d.deviceId)||!HASH.test(d.certificateFingerprint)||typeof d.revoked!=='boolean'||!Array.isArray(d.apps)||d.apps.length>100||new Set(d.apps).size!==d.apps.length||d.apps.some(v=>typeof v!=='string'||!ID.test(v)))fail('SDP_INVALID_REGISTRY');
  return d;
}
export function readRegistry(path){const raw=readPrivateFile(path,LIMIT);
  let data;
  try{data=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  }
  catch{fail('SDP_INVALID_REGISTRY');
  }exact(data,['schema','revision','devices']);
  if(data.schema!=='student.sdp.registry.v1'||!Number.isSafeInteger(data.revision)||data.revision<0||!Array.isArray(data.devices)||data.devices.length>1000)fail('SDP_INVALID_REGISTRY');
  const ids=new Set(),certs=new Set();
  for(const d of data.devices){validateDevice(d);
    if(ids.has(d.deviceId)||certs.has(d.certificateFingerprint))fail('SDP_INVALID_REGISTRY');
    ids.add(d.deviceId);
    certs.add(d.certificateFingerprint);
  }return data;
}
export function initializeRegistry(path){outsideSource(path);
  const fd=openSync(path,'wx',0o600);
  try{writeFileSync(fd,JSON.stringify({schema:'student.sdp.registry.v1',revision:0,devices:[]}));
  }
  finally{closeSync(fd);
  }}
function mutate(path,fn){outsideSource(path);
  const lock=path+'.lock';
  const fd=openSync(lock,'wx',0o600);
  let temporary;
  try{const registry=readRegistry(path);
    if(registry.revision>=Number.MAX_SAFE_INTEGER)fail('SDP_INVALID_REGISTRY');
    fn(registry);
    registry.revision++;
    outsideSource(path);
    temporary=join(dirname(path),'.sdp-'+randomUUID()+'.tmp');
    writeFileSync(temporary,JSON.stringify(registry),{flag:'wx',mode:0o600});
    renameSync(temporary,path);
    temporary=null;
  }
  finally{if(temporary)try{unlinkSync(temporary);
    }
    catch{}closeSync(fd);
    unlinkSync(lock);
  }}
export function enrollDevice(path,input){exact(input,['subjectId','projectId','deviceId','certificateFingerprint','apps']);
  const device=validateDevice({...input,revoked:false});
  mutate(path,r=>{if(r.devices.some(d=>d.deviceId===device.deviceId||d.certificateFingerprint===device.certificateFingerprint))fail('SDP_DEVICE_EXISTS');
    if(r.devices.length>=1000)fail();
    r.devices.push(device);
  });
}
export function revokeDevice(path,deviceId){if(typeof deviceId!=='string'||!DEVICE.test(deviceId))fail();
  mutate(path,r=>{const d=r.devices.find(d=>d.deviceId===deviceId);
    if(!d)fail('SDP_DEVICE_UNKNOWN');
    d.revoked=true;
  });
}
