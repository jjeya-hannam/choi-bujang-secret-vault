import {createSdpServer} from './server.mjs';
import {loadConfiguration} from './config.mjs';
import {createXdrBridge} from './xdr-bridge.mjs';
try{if(process.argv.length!==3)throw Error();
  const options=loadConfiguration(process.argv[2]);
  if(options.xdr)options.xdrBridge=createXdrBridge({registryPath:options.registryPath,...options.xdr});
  const server=createSdpServer(options);
  server.on('error',()=>{console.error('SDP_START_FAILED');
    process.exitCode=1;
  });
  server.listen(options.port,options.host,()=>console.log('SDP_LOCAL_READY'));
  for(const sig of ['SIGINT','SIGTERM'])process.once(sig,()=>server.close());
}
catch{console.error('SDP_START_FAILED');
  process.exitCode=1;
}
