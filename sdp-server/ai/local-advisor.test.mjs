import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createLocalAdvisor} from './local-advisor.mjs';

const event = {decision:'deny',ruleIds:['device.revoked'],signalCounts:{deniedRequests:3}};
async function fixture(t,handler) {
  const server=createServer(handler);
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
  return server.address().port;
}
function answer(res,content) {res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({done:true,message:{role:'assistant',content:JSON.stringify(content)}}));}

test('disabled default does not invoke local HTTP', async t=>{
  let calls=0; const port=await fixture(t,(_req,res)=>{calls++;answer(res,{summary:'unused'});});
  assert.deepEqual(await createLocalAdvisor({port}).explain(event),{status:'disabled',summary:'',executed:false,requiresHumanConfirmation:true});
  assert.equal(calls,0);
});
test('local fake transport receives only minimized evidence; result is advisory',async t=>{
  let received;
  const port=await fixture(t,(req,res)=>{const chunks=[];req.on('data',c=>chunks.push(c));req.on('end',()=>{received={method:req.method,url:req.url,headers:req.headers,body:JSON.parse(Buffer.concat(chunks))};answer(res,{summary:'등록이 철회된 기기의 요청을 거부했습니다.'});});});
  const result=await createLocalAdvisor({enabled:true,model:'local-test-model',port}).explain(event);
  assert.equal(result.status,'explained');assert.equal(result.executed,false);assert.equal(result.requiresHumanConfirmation,true);
  assert.equal(received.url,'/api/chat');assert.equal(received.method,'POST');assert.equal(received.headers.authorization,undefined);
  assert.deepEqual(JSON.parse(received.body.messages[1].content),event);
  assert.equal(received.body.stream,false);assert.equal(received.body.tools,undefined);
});
test('unapproved input, arbitrary destinations and cloud identifiers rejected',async()=>{
  assert.throws(()=>createLocalAdvisor({enabled:true,model:'test:cloud'}),/AI_INVALID_CONFIGURATION/);
  assert.throws(()=>createLocalAdvisor({enabled:true,model:'local',host:'external.invalid'}),/AI_INVALID_INPUT/);
  const advisor=createLocalAdvisor({enabled:true,model:'local'});
  await assert.rejects(advisor.explain({...event,rawLog:'not allowed'}),/AI_INVALID_INPUT/);
  await assert.rejects(advisor.explain({...event,ruleIds:['bad value']}),/AI_INVALID_INPUT/);
  await assert.rejects(advisor.explain({...event,signalCounts:{unknown:1}}),/AI_INVALID_INPUT/);
});
test('redirects are not followed',async t=>{
  const port=await fixture(t,(_req,res)=>{res.writeHead(302,{location:'http://external.invalid'});res.end();});
  assert.equal((await createLocalAdvisor({enabled:true,model:'local',port}).explain(event)).status,'unavailable');
});
test('malformed, oversized, tool and secret-looking outputs fail closed',async t=>{
  let mode='malformed';
  const port=await fixture(t,(_req,res)=>{
    if(mode==='oversized') answer(res,{summary:'x'.repeat(20000)});
    else if(mode==='tools') {res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({done:true,message:{role:'assistant',content:'{"summary":"text"}',tool_calls:[{}]}}));}
    else if(mode==='secret') answer(res,{summary:'access_token=synthetic'});
    else {res.writeHead(200,{'content-type':'application/json'});res.end('malformed');}
  });
  const advisor=createLocalAdvisor({enabled:true,model:'local',port});
  for (mode of ['malformed','oversized','tools','secret']) assert.equal((await advisor.explain(event)).status,'unavailable');
});
test('single flight and timeout cannot report success',async t=>{
  let calls=0;
  const port=await fixture(t,()=>{calls++;});
  const advisor=createLocalAdvisor({enabled:true,model:'local',port,timeoutMs:50});
  const first=advisor.explain(event);
  assert.equal((await advisor.explain(event)).status,'unavailable');
  assert.equal((await first).status,'unavailable');assert.equal(calls,1);
});
