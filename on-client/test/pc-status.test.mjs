import test from 'node:test';
import assert from 'node:assert/strict';
import {createPcCollector,sanitizePcStatus} from '../student/pc-status.mjs';
const checkedAt='2026-10-26T00:00:00.000Z';
const snapshot=(user,idle)=>[{times:{user,nice:0,sys:0,idle,irq:0},model:'DO_NOT_FORWARD_MODEL'}];
const setup=(overrides={})=>{
  let calls=0;
  const osImpl={cpus:()=>++calls===1?snapshot(50,50):snapshot(80,120),totalmem:()=>8000,freemem:()=>2000,
    networkInterfaces:()=>({privateName:[{address:'DO_NOT_FORWARD_ADDRESS',mac:'DO_NOT_FORWARD_MAC'}],empty:[]})};
  return {osImpl,statfsImpl:async()=>({bsize:4n,blocks:1000n,bfree:500n,bavail:400n}),platform:'darwin',appDirectory:'DO_NOT_FORWARD_PATH',sampleMs:100,clock:()=>new Date(checkedAt),...overrides};
};
test('CPU sample delta, physical memory, app drive bytes and only interface counts are observed',async()=>{
  const value=await createPcCollector(setup())();
  assert.equal(value.cpu.observed,30);assert.deepEqual(value.memory.observed,{total:8000,free:2000});
  assert.deepEqual(value.disk.observed,{total:4000,free:1600});assert.deepEqual(value.network.observed,{interfaces:1});
  assert.equal(value.source,'local_pc');assert.equal(value.checkedAt,checkedAt);
  assert.doesNotMatch(JSON.stringify(value),/DO_NOT_FORWARD|privateName|address|hostname|username|model|mac/i);
});
test('disk reports user-available blocks instead of reserved free blocks',async()=>{
  const options=setup({statfsImpl:async()=>({bsize:8n,blocks:100n,bfree:60n,bavail:40n})});
  const value=await createPcCollector(options)();
  assert.deepEqual(value.disk.observed,{total:800,free:320});assert.notEqual(value.disk.observed.free,480);
});
test('non-Windows does not invoke PowerShell and represents Windows fields as unsupported',async()=>{
  let commands=0;
  const value=await createPcCollector(setup({execFileImpl:()=>{commands++;throw Error();}}))();
  assert.equal(commands,0);
  for(const key of ['firewall','eventLogs']){assert.equal(value[key].status,'unknown');assert.equal(value[key].code,'UNSUPPORTED_PLATFORM');assert.equal(value[key].observed,null);}
});
test('failed disk permissions do not leak errors or destroy other observations',async()=>{
  const value=await createPcCollector(setup({statfsImpl:async()=>{throw Error('DO_NOT_FORWARD_PATH');}}))();
  assert.equal(value.disk.status,'unknown');assert.equal(value.disk.code,'OBSERVATION_FAILED');assert.equal(value.cpu.status,'observed');
  assert.doesNotMatch(JSON.stringify(value),/DO_NOT_FORWARD/);
});
test('invalid memory and disk numbers become unknown without fabricated counts',async()=>{
  const options=setup();options.osImpl.freemem=()=>9000;options.statfsImpl=async()=>({bsize:4n,blocks:1n,bfree:2n,bavail:2n});
  const value=await createPcCollector(options)();
  for(const key of ['memory','disk']){assert.equal(value[key].code,'INVALID_OBSERVATION');assert.equal(value[key].observed,null);}
});
test('non-monotonic CPU clocks become unknown',async()=>{
  const options=setup();let calls=0;options.osImpl.cpus=()=>++calls===1?snapshot(50,50):snapshot(40,40);
  const value=await createPcCollector(options)();assert.equal(value.cpu.status,'unknown');assert.equal(value.cpu.observed,null);
});
test('CPU inventory changes do not silently compare incompatible samples',async()=>{
  const options=setup();let calls=0;options.osImpl.cpus=()=>++calls===1?snapshot(50,50):[...snapshot(80,120),...snapshot(80,120)];
  const value=await createPcCollector(options)();assert.equal(value.cpu.status,'unknown');
});
test('fixed Windows commands return only aggregate counts with bounded execution',async()=>{
  const commands=[];
  const execFileImpl=(file,args,options,callback)=>{
    commands.push({file,args,options});
    callback(null,args.at(-1).includes('Get-NetFirewallProfile')?'{"enabled":2,"disabled":1}':'{"system":4,"application":7,"windowHours":24}');
  };
  const value=await createPcCollector(setup({platform:'win32',execFileImpl}))();
  assert.deepEqual(value.firewall.observed,{enabled:2,disabled:1});assert.deepEqual(value.eventLogs.observed,{system:4,application:7,windowHours:24});
  assert.equal(commands.length,2);assert.match(commands.find(x=>x.args.at(-1).includes('Get-NetFirewallProfile')).args.at(-1),/Get-NetFirewallProfile -PolicyStore ActiveStore/);
  for(const command of commands){assert.equal(command.file,'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');assert.deepEqual(command.args.slice(0,4),['-NoLogo','-NoProfile','-NonInteractive','-Command']);assert.equal(command.options.shell,false);assert.equal(command.options.timeout,2500);assert.equal(command.options.maxBuffer,4096);assert.equal(command.options.windowsHide,true);assert.doesNotMatch(command.args.at(-1),/Set-Net|Remove-|Start-Process|RunAs|ComputerName|UserID|Select-Object/);}
  assert.match(commands.find(x=>x.args.at(-1).includes('Get-WinEvent')).args.at(-1),/LogName=\$log;Level=2,3;StartTime=\$start;EndTime=\$end/);
});
test('Windows command timeout stays unknown instead of zero warnings or enabled firewall',async()=>{
  const execFileImpl=(_file,_args,_options,callback)=>callback(Object.assign(Error('DO_NOT_FORWARD_DETAIL'),{killed:true}));
  const value=await createPcCollector(setup({platform:'win32',execFileImpl}))();
  for(const key of ['firewall','eventLogs']){assert.equal(value[key].code,'OBSERVATION_TIMEOUT');assert.equal(value[key].observed,null);}
  assert.doesNotMatch(JSON.stringify(value),/DO_NOT_FORWARD/);
});
test('unexpected Windows output and provider extra properties are not reflected',async()=>{
  const execFileImpl=(_file,args,_options,callback)=>callback(null,args.at(-1).includes('Get-NetFirewallProfile')?'DO_NOT_FORWARD_DETAIL':'{"system":1,"application":2,"windowHours":24,"message":"DO_NOT_FORWARD_DETAIL"}');
  const value=await createPcCollector(setup({platform:'win32',execFileImpl}))();
  assert.equal(value.firewall.status,'unknown');assert.equal(value.eventLogs.status,'unknown');assert.doesNotMatch(JSON.stringify(value),/DO_NOT_FORWARD/);
});
test('sensor output sanitizer rejects fake status, units, source and leaked properties',async()=>{
  const value=await createPcCollector(setup())();
  assert.throws(()=>sanitizePcStatus({...value,hostname:'DO_NOT_FORWARD'}));
  assert.throws(()=>sanitizePcStatus({...value,source:'remote'}));
  assert.throws(()=>sanitizePcStatus({...value,cpu:{...value.cpu,status:'ok'}}));
  assert.throws(()=>sanitizePcStatus({...value,cpu:{...value.cpu,unit:'bytes'}}));
  assert.throws(()=>sanitizePcStatus({...value,cpu:{...value.cpu,observed:101}}));
});
test('sample configuration rejects unsafe and unbounded intervals',()=>{
  for(const sampleMs of [0,99,251,Infinity,'150'])assert.throws(()=>createPcCollector({sampleMs}));
});
