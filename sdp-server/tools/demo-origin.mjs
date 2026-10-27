// Local sample resource only. This does not connect or change the real vault.
import {createServer} from 'node:http';
import {loadConfiguration} from '../src/config.mjs';
import {createProtectedOriginHandler} from '../src/origin-proof.mjs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function createDemoOrigin(configuration){
  const app=configuration.apps.find(item=>item.id==='vault'),key=configuration.originKeys.vault;
  if(!app||!key)throw Error();
  const upstream=new URL(app.upstream),port=Number(upstream.port);
  if(upstream.protocol!=='http:'||upstream.hostname!=='127.0.0.1'||upstream.username||upstream.password||upstream.pathname!=='/'||upstream.search||upstream.hash||port!==8080)throw Error('SDP_DEMO_ORIGIN_FAILED');
  return createServer(createProtectedOriginHandler({key,appId:'vault'},(req,res)=>{
    const bytes=Buffer.from(JSON.stringify({ok:true,kind:'local-example-resource',realVaultConnected:false}));
    res.writeHead(200,{'content-type':'application/json','content-length':bytes.length,'cache-control':'no-store'});
    res.end(req.method==='HEAD'?undefined:bytes);
  }));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try {
  if(process.argv.length!==3)throw Error();
  const server=createDemoOrigin(loadConfiguration(process.argv[2]));
  server.once('error',()=>{console.error('SDP_DEMO_ORIGIN_FAILED');process.exitCode=1;});
  server.listen(8080,'127.0.0.1',()=>console.log('SDP_DEMO_ORIGIN_READY'));
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close());
}catch{console.error('SDP_DEMO_ORIGIN_FAILED');process.exitCode=1;}
