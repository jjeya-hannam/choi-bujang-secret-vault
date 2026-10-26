// Local read-only observations. Never return addresses, names, paths or log contents.
import os from 'node:os';
import { statfs } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const FIREWALL_SCRIPT = "$ErrorActionPreference='Stop';try{$p=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop);if($p.Count -ne 3){exit 2};$enabled=@($p|Where-Object {$_.Enabled -eq 'True'}).Count;$disabled=@($p|Where-Object {$_.Enabled -eq 'False'}).Count;if(($enabled+$disabled) -ne 3){exit 2};@{enabled=$enabled;disabled=$disabled}|ConvertTo-Json -Compress}catch{exit 2}";
const EVENT_SCRIPT = "$ErrorActionPreference='Stop';function Count-Recent($log,$start,$end){try{return [long]((Get-WinEvent -FilterHashtable @{LogName=$log;Level=2,3;StartTime=$start;EndTime=$end} -ErrorAction Stop|Measure-Object).Count)}catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){return 0};throw}};try{$end=Get-Date;$start=$end.AddHours(-24);@{system=(Count-Recent 'System' $start $end);application=(Count-Recent 'Application' $start $end);windowHours=24}|ConvertTo-Json -Compress}catch{exit 2}";
const integer = value => Number.isSafeInteger(value) && value >= 0;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const iso = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value));
const units = Object.freeze({cpu:'percent',memory:'bytes',disk:'bytes',network:'count',firewall:'profiles',eventLogs:'count'});
const unknownCodes = ['UNSUPPORTED_PLATFORM','OBSERVATION_FAILED','OBSERVATION_TIMEOUT','INVALID_OBSERVATION'];

// Reconstruct a finite payload instead of forwarding provider objects to the browser.
export function sanitizePcStatus(value) {
  const keys = ['schema','source','checkedAt','platform',...Object.keys(units)];
  if (!exact(value, keys) || value.schema !== 'student.pc-status.v1' || value.source !== 'local_pc' || !iso(value.checkedAt)
    || !['win32','darwin','linux','other'].includes(value.platform)) throw Error('PC_INVALID_OBSERVATION');
  const result = {schema:value.schema,source:value.source,checkedAt:value.checkedAt,platform:value.platform};
  for (const [key, unit] of Object.entries(units)) {
    const f = value[key];
    if (!exact(f,['status','code','unit','checkedAt','observed']) || f.unit !== unit || !iso(f.checkedAt)) throw Error('PC_INVALID_OBSERVATION');
    if (f.status === 'unknown' && unknownCodes.includes(f.code) && f.observed === null) {
      result[key] = {status:'unknown',code:f.code,unit,checkedAt:f.checkedAt,observed:null}; continue;
    }
    if (f.status !== 'observed' || f.code !== 'OK') throw Error('PC_INVALID_OBSERVATION');
    const n = f.observed;
    const valid = key === 'cpu' ? typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 100
      : ['memory','disk'].includes(key) ? exact(n,['total','free']) && integer(n.total) && n.total > 0 && integer(n.free) && n.free <= n.total
      : key === 'network' ? exact(n,['interfaces']) && integer(n.interfaces)
      : key === 'firewall' ? exact(n,['enabled','disabled']) && integer(n.enabled) && integer(n.disabled) && n.enabled+n.disabled === 3
      : exact(n,['system','application','windowHours']) && integer(n.system) && integer(n.application) && n.windowHours === 24;
    if (!valid || ['firewall','eventLogs'].includes(key) && value.platform !== 'win32') throw Error('PC_INVALID_OBSERVATION');
    result[key] = {status:'observed',code:'OK',unit,checkedAt:f.checkedAt,observed:record(n) ? {...n} : n};
  }
  return result;
}

export function createPcCollector({osImpl=os,statfsImpl=statfs,execFileImpl=execFile,sampleMs=150,platform=os.platform(),
  appDirectory=fileURLToPath(new URL('../',import.meta.url)),clock=()=>new Date()}={}) {
  if (!Number.isInteger(sampleMs) || sampleMs < 100 || sampleMs > 250) throw Error('PC_INVALID_SAMPLE');
  const now = () => { const value=clock().toISOString(); if(!iso(value))throw Error('PC_INVALID_CLOCK'); return value; };
  const field = async (key, operation) => {
    try { const observed=await operation();return {status:'observed',code:'OK',unit:units[key],checkedAt:now(),observed}; }
    catch(error) { return {status:'unknown',code:error?.code==='PC_TIMEOUT'?'OBSERVATION_TIMEOUT':error?.code==='PC_UNSUPPORTED'?'UNSUPPORTED_PLATFORM':'OBSERVATION_FAILED',unit:units[key],checkedAt:now(),observed:null}; }
  };
  const powershell = script => new Promise((resolve,reject) => {
    execFileImpl(POWERSHELL,['-NoLogo','-NoProfile','-NonInteractive','-Command',script],
      {encoding:'utf8',timeout:2500,maxBuffer:4096,windowsHide:true,shell:false,killSignal:'SIGKILL'},(error,stdout) => {
        if(error) { reject(Object.assign(Error('PC_READ_FAILED'),{code:error.killed?'PC_TIMEOUT':'PC_READ_FAILED'})); return; }
        try { if(typeof stdout!=='string'||stdout.length>4096)throw Error(); resolve(JSON.parse(stdout.replace(/^\uFEFF/,''))); }
        catch { reject(Error('PC_READ_FAILED')); }
      });
  });
  const windows = async script => { if(platform!=='win32')throw Object.assign(Error('PC_UNSUPPORTED'),{code:'PC_UNSUPPORTED'}); return powershell(script); };
  const cpuSnapshot = () => {
    const cpus=osImpl.cpus();
    if(!Array.isArray(cpus)||cpus.length<1)throw Error();
    let total=0,idle=0;
    for(const cpu of cpus){const t=cpu.times;if(!t||['user','nice','sys','idle','irq'].some(k=>!integer(t[k])))throw Error(); idle+=t.idle; total+=t.user+t.nice+t.sys+t.idle+t.irq;}
    if(!integer(total)||!integer(idle))throw Error(); return {count:cpus.length,total,idle};
  };
  return async function collectPcStatus() {
    const entries=await Promise.all([
      field('cpu',async()=>{const a=cpuSnapshot();await new Promise(resolve=>setTimeout(resolve,sampleMs));const b=cpuSnapshot();const total=b.total-a.total,idle=b.idle-a.idle;if(a.count!==b.count||total<=0||idle<0||idle>total)throw Error();return Math.round((1-idle/total)*10000)/100;}),
      field('memory',()=>({total:osImpl.totalmem(),free:osImpl.freemem()})),
      field('disk',async()=>{const x=await statfsImpl(appDirectory,{bigint:true});const total=BigInt(x.bsize)*BigInt(x.blocks),free=BigInt(x.bsize)*BigInt(x.bavail);if(total>BigInt(Number.MAX_SAFE_INTEGER)||free>BigInt(Number.MAX_SAFE_INTEGER))throw Error();return {total:Number(total),free:Number(free)};}),
      field('network',()=>({interfaces:Object.values(osImpl.networkInterfaces()).filter(rows=>Array.isArray(rows)&&rows.length>0).length})),
      field('firewall',()=>windows(FIREWALL_SCRIPT)),
      field('eventLogs',()=>windows(EVENT_SCRIPT)),
    ]);
    const raw={schema:'student.pc-status.v1',source:'local_pc',checkedAt:now(),platform:['win32','darwin','linux'].includes(platform)?platform:'other'};
    for(const [index,key]of Object.keys(units).entries()){
      raw[key]=entries[index];
      // Invalid numeric/provider data affects only that field, never invent a value.
      try { sanitizePcStatus({...raw,...Object.fromEntries(Object.entries(units).filter(([k])=>!Object.hasOwn(raw,k)).map(([k,u])=>[k,{status:'unknown',code:'OBSERVATION_FAILED',unit:u,checkedAt:raw.checkedAt,observed:null}]))}); }
      catch { raw[key]={status:'unknown',code:'INVALID_OBSERVATION',unit:units[key],checkedAt:raw.checkedAt,observed:null}; }
    }
    return sanitizePcStatus(raw);
  };
}
