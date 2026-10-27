import {writeFileSync,openSync,closeSync} from 'node:fs';
import {X509Certificate,createHash} from 'node:crypto';
import {loadConfiguration,readPrivateFile,outsideSource} from '../src/config.mjs';
import {initializeRegistry,enrollDevice,revokeDevice,readRegistry} from '../src/registry.mjs';
import {createToken} from '../src/security.mjs';
try{const [path,operation,...args]=process.argv.slice(2);
  if(!path)throw Error();
  const c=loadConfiguration(path);
  if(operation==='init'&&args.length===0)initializeRegistry(c.registryPath);
  else if(operation==='enroll'&&args.length===5){const [subjectId,projectId,deviceId,certFile,apps]=args,cert=new X509Certificate(readPrivateFile(certFile));
    if(cert.ca||Date.parse(cert.validFrom)>Date.now()||Date.parse(cert.validTo)<=Date.now())throw Error();
    enrollDevice(c.registryPath,{subjectId,projectId,deviceId,certificateFingerprint:createHash('sha256').update(cert.raw).digest('hex'),apps:apps.split(',')});
  }
  else if(operation==='revoke'&&args.length===1)revokeDevice(c.registryPath,args[0]);
  else if(operation==='issue'&&args.length===2){const [deviceId,output]=args;
    outsideSource(output);
    const device=readRegistry(c.registryPath).devices.find(d=>d.deviceId===deviceId&&!d.revoked);
    if(!device)throw Error();
    const token=createToken({key:c.jwt.key,issuer:c.jwt.issuer,audience:c.jwt.audience,...device});
    const fd=openSync(output,'wx',0o600);
    try{writeFileSync(fd,token+'\n');
    }
    finally{closeSync(fd);
    }}
  else throw Error();
  console.log('SDP_ADMIN_COMPLETED');
}
catch{console.error('SDP_ADMIN_FAILED');
  process.exitCode=1;
}
