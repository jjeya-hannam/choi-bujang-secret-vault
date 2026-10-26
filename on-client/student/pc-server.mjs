// Student-owned local wrapper. The provided server and its security policy stay intact.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { createOnServer } from '../src/server.mjs';
import { demoEngine } from '../src/engine.mjs';
import { createPcCollector, sanitizePcStatus } from './pc-status.mjs';

const CSP="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'";
const messages={PC_REQUEST_REJECTED:'허용된 로컬 화면에서만 조회할 수 있습니다.',PC_METHOD_REJECTED:'읽기 전용 GET 요청만 허용됩니다.',PC_BUSY:'PC 점검이 진행 중입니다. 끝난 뒤 직접 다시 조회하세요.',PC_TIMEOUT:'PC 점검 시간이 초과됐습니다. 결과를 확인할 수 없습니다.',PC_UNAVAILABLE:'PC 점검 결과를 확인할 수 없습니다.',PC_ASSET_UNAVAILABLE:'학생 화면을 불러올 수 없습니다.'};
export function parseStudentPort(value='5189') { if(typeof value!=='string'||!/^\d{1,5}$/.test(value)||Number(value)<1024||Number(value)>65535)throw Error('PC_INVALID_PORT');return Number(value); }
export function createStudentServer({demo=false,collectPcStatus=createPcCollector(),sensorTimeoutMs=5000}={}) {
  if(typeof demo!=='boolean'||typeof collectPcStatus!=='function'||!Number.isInteger(sensorTimeoutMs)||sensorTimeoutMs<50||sensorTimeoutMs>10000)throw Error('PC_INVALID_CONFIGURATION');
  // No AI keys, adapters, vault or account sessions are picked up from the environment.
  const server=createOnServer({engine:demo?demoEngine():{evidenceMode:'disconnected'},aiEnv:{}});
  const delegate=server.listeners('request')[0];server.removeAllListeners('request');
  let inFlight=false;
  const headers={'cache-control':'no-store','content-security-policy':CSP,'x-content-type-options':'nosniff','referrer-policy':'no-referrer'};
  const send=(res,status,code)=>{if(res.destroyed||res.writableEnded)return;res.writeHead(status,{...headers,'content-type':'application/json; charset=utf-8'});res.end(JSON.stringify({ok:false,error:{code,message:messages[code]}}));};
  server.on('request',async(req,res)=>{
    const port=server.address()?.port;
    const count=name=>req.rawHeaders.filter((_,index)=>index%2===0&&req.rawHeaders[index].toLowerCase()===name).length;
    if(!port||req.socket.localAddress!=='127.0.0.1'||req.headers.host!==`127.0.0.1:${port}`||count('host')!==1){send(res,403,'PC_REQUEST_REJECTED');return;}
    let url;try{url=new URL(req.url,`http://127.0.0.1:${port}`);}catch{send(res,403,'PC_REQUEST_REJECTED');return;}
    const api=url.pathname==='/api/student/pc-status',asset=url.pathname==='/student/pc-view.mjs';
    if(!api&&!asset){delegate(req,res);return;}
    if(req.method!=='GET'){send(res,405,'PC_METHOD_REJECTED');return;}
    if(req.url!==url.pathname||url.search||url.hash||req.headers['sec-fetch-site']==='cross-site'){send(res,403,'PC_REQUEST_REJECTED');return;}
    const origin=`http://127.0.0.1:${port}`;
    if(api&&(req.headers['x-student-pc-read']!=='1'||count('x-student-pc-read')!==1||count('origin')>1
      ||(req.headers.origin!==undefined?req.headers.origin!==origin:req.headers['sec-fetch-site']!=='same-origin')
      ||req.headers['sec-fetch-site']!==undefined&&req.headers['sec-fetch-site']!=='same-origin')){send(res,403,'PC_REQUEST_REJECTED');return;}
    if(asset){try{const body=await readFile(new URL('./pc-view.mjs',import.meta.url));if(body.length>262144)throw Error();res.writeHead(200,{...headers,'content-type':'text/javascript; charset=utf-8'});res.end(body);}catch{send(res,404,'PC_ASSET_UNAVAILABLE');}return;}
    if(inFlight){send(res,429,'PC_BUSY');return;}
    inFlight=true;let timer;
    const observation=Promise.resolve().then(()=>collectPcStatus());
    // Keep the busy lock until the real observation settles, even after a deadline.
    observation.finally(()=>{inFlight=false;}).catch(()=>{});
    try{
      const value=await Promise.race([observation,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(Error('PC_TIMEOUT'),{code:'PC_TIMEOUT'})),sensorTimeoutMs);})]);
      const data=sanitizePcStatus(value);
      if(!res.destroyed&&!res.writableEnded){res.writeHead(200,{...headers,'content-type':'application/json; charset=utf-8'});res.end(JSON.stringify({ok:true,data}));}
    }catch(error){send(res,error?.code==='PC_TIMEOUT'?504:503,error?.code==='PC_TIMEOUT'?'PC_TIMEOUT':'PC_UNAVAILABLE');}
    finally{clearTimeout(timer);}
  });
  return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const args=process.argv.slice(2);if(args.length>1||args.some(arg=>arg!=='--demo'))throw Error('PC_INVALID_ARGUMENTS');
    const port=parseStudentPort(process.env.ON_PORT??'5189');const server=createStudentServer({demo:args.includes('--demo')});
    server.once('error',()=>{console.error('학생 로컬 서버를 시작하지 못했습니다. 포트와 실행 환경을 확인하세요.');process.exitCode=1;});
    server.listen(port,'127.0.0.1',()=>console.log(`학생 로컬 화면: http://127.0.0.1:${port}`));
  }catch{console.error('학생 로컬 서버의 실행 설정을 확인하세요.');process.exitCode=1;}
}
