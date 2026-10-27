import {createHmac,randomUUID,timingSafeEqual} from 'node:crypto';
import {openSync,closeSync,writeFileSync,renameSync,unlinkSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {decide} from '../../xdr/known-cve/decide.mjs';
import {outsideSource,readPrivateFile} from './config.mjs';
import {readRegistry} from './registry.mjs';
import {parseStrictJson} from './json.mjs';
import {SUBJECT,PROJECT,DEVICE,HASH,exact,requireKey,fail} from './security.mjs';

const SCHEMA='student.sdp.xdr.proposals.v1';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LIMIT=1024*1024,MAX_EVENTS=256;
const STRONG_PATTERNS=['header_jndi_lookup','parameter_jndi_lookup'];
const BINDING_KEYS=['subjectId','projectId','deviceId','certificateFingerprint'];
const ENTRY_KEYS=['eventId','detectedAtMs','registryRevision','binding','detectionAction','confidence','reason','proposal','status','completedAtMs'];

function validateBinding(raw){
  exact(raw,BINDING_KEYS);
  if(!SUBJECT.test(raw.subjectId)||!PROJECT.test(raw.projectId)||!DEVICE.test(raw.deviceId)||!HASH.test(raw.certificateFingerprint))fail('SDP_XDR_INVALID_BINDING');
  return Object.fromEntries(BINDING_KEYS.map(k=>[k,raw[k]]));
}
const sameBinding=(device,binding)=>BINDING_KEYS.every(k=>device[k]===binding[k]);
function validateEntry(entry){
  exact(entry,ENTRY_KEYS);validateBinding(entry.binding);
  if(!UUID.test(entry.eventId)||!Number.isSafeInteger(entry.detectedAtMs)||entry.detectedAtMs<1
    ||!Number.isSafeInteger(entry.registryRevision)||entry.registryRevision<0
    ||entry.detectionAction!=='alert'||entry.confidence!==0.72||!STRONG_PATTERNS.includes(entry.reason)
    ||entry.proposal!=='propose_revocation'||!['pending','applied','already_revoked'].includes(entry.status)
    ||(entry.status==='pending'?entry.completedAtMs!==null:!Number.isSafeInteger(entry.completedAtMs)||entry.completedAtMs<entry.detectedAtMs))fail('SDP_XDR_INVALID_EVIDENCE');
  return entry;
}
const payload=entries=>({schema:SCHEMA,entries});
const mac=(entries,key)=>createHmac('sha256',key).update(JSON.stringify(payload(entries))).digest('hex');
function readLedger(path,key){
  const document=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(readPrivateFile(path,LIMIT)));
  exact(document,['schema','entries','signature']);
  if(document.schema!==SCHEMA||!Array.isArray(document.entries)||document.entries.length>MAX_EVENTS||!HASH.test(document.signature))fail('SDP_XDR_INVALID_EVIDENCE');
  const expected=Buffer.from(mac(document.entries,key),'hex'),actual=Buffer.from(document.signature,'hex');
  if(actual.length!==expected.length||!timingSafeEqual(actual,expected))fail('SDP_XDR_INVALID_EVIDENCE');
  const ids=new Set();
  for(const entry of document.entries){validateEntry(entry);if(ids.has(entry.eventId))fail('SDP_XDR_INVALID_EVIDENCE');ids.add(entry.eventId);}
  return document.entries;
}
function writeAtomic(path,document){
  outsideSource(path);
  const bytes=Buffer.from(JSON.stringify(document));if(bytes.length>LIMIT)fail('SDP_XDR_STORAGE_FULL');
  const temporary=join(dirname(path),'.sdp-xdr-'+randomUUID()+'.tmp');let created=false;
  try{writeFileSync(temporary,bytes,{flag:'wx',mode:0o600});created=true;outsideSource(path);renameSync(temporary,path);created=false;}
  finally{if(created)try{unlinkSync(temporary);}catch{}}
}
function lock(path,operation){
  outsideSource(path);const name=path+'.lock',fd=openSync(name,'wx',0o600);
  try{return operation();}finally{closeSync(fd);unlinkSync(name);}
}
function saveLedger(path,entries,key){writeAtomic(path,{...payload(entries),signature:mac(entries,key)});}
function initializeLedger(path,key){
  outsideSource(path);
  try{const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,JSON.stringify({...payload([]),signature:mac([],key)}));}finally{closeSync(fd);}}
  catch(error){if(error.code!=='EEXIST')throw error;}
  readLedger(path,key);
}
function requestAlert(raw){
  exact(raw,['method','path','headers']);
  if(!['GET','HEAD'].includes(raw.method)||typeof raw.path!=='string'||raw.path.length>2048||!raw.headers||typeof raw.headers!=='object'||Array.isArray(raw.headers))fail('SDP_XDR_INVALID_REQUEST');
  const headers=Object.create(null);let length=0;
  for(const [name,value] of Object.entries(raw.headers)){
    if(/authorization|cookie|token|secret|password|api.?key/i.test(name))continue;
    if(typeof value!=='string')continue;
    length+=name.length+value.length;if(length>8192)fail('SDP_XDR_INVALID_REQUEST');
    headers[name]=value;
  }
  let query=raw.path;
  try{query=decodeURIComponent(raw.path);}catch{}
  // Raw ingress has no verified Wazuh severity/technique context. Preserve the
  // detector's review-only 0.72 result; never manufacture a high-severity alert.
  return {rule:{level:0,description:'gateway request inspection; exploit success unverified',mitre:[]},data:{headers,url:raw.path,query}};
}

export function createXdrBridge({registryPath,evidencePath,evidenceKey}){
  requireKey(evidenceKey);outsideSource(registryPath);outsideSource(evidencePath);
  if(registryPath===evidencePath||registryPath+'.lock'===evidencePath||evidencePath+'.lock'===registryPath)fail('SDP_XDR_INVALID_CONFIGURATION');
  const key=Buffer.from(evidenceKey);readRegistry(registryPath);initializeLedger(evidencePath,key);
  return Object.freeze({
    inspect({binding:rawBinding,request}){
      const binding=validateBinding(rawBinding),registry=readRegistry(registryPath);
      const device=registry.devices.find(d=>sameBinding(d,binding)&&!d.revoked);
      if(!device)fail('SDP_XDR_INVALID_BINDING');
      const detection=decide(requestAlert(request));
      const proposed=detection.action==='alert'&&detection.confidence===0.72&&STRONG_PATTERNS.includes(detection.reason);
      if(!proposed)return Object.freeze({...detection,eventId:null,proposeRevocation:false});
      const eventId=randomUUID(),entry={eventId,detectedAtMs:Date.now(),registryRevision:registry.revision,binding,detectionAction:detection.action,confidence:detection.confidence,reason:detection.reason,proposal:'propose_revocation',status:'pending',completedAtMs:null};
      lock(evidencePath,()=>{const entries=readLedger(evidencePath,key);if(entries.length>=MAX_EVENTS)fail('SDP_XDR_STORAGE_FULL');entries.push(entry);saveLedger(evidencePath,entries,key);});
      return Object.freeze({...detection,eventId,proposeRevocation:true});
    },
    listProposals(){return readLedger(evidencePath,key).map(entry=>Object.freeze(structuredClone(entry)));},
    approve(eventId){
      if(typeof eventId!=='string'||!UUID.test(eventId))fail('SDP_XDR_INVALID_EVENT');
      return lock(evidencePath,()=>{
        const entries=readLedger(evidencePath,key),entry=entries.find(e=>e.eventId===eventId);
        if(!entry)fail('SDP_XDR_UNKNOWN_EVENT');
        if(entry.status!=='pending')return Object.freeze({eventId,status:entry.status==='applied'?'already_applied':'already_revoked',applied:false});
        const age=Date.now()-entry.detectedAtMs;
        if(age<0||age>15*60*1000)fail('SDP_XDR_STALE_EVENT');
        return lock(registryPath,()=>{
          const registry=readRegistry(registryPath),device=registry.devices.find(d=>sameBinding(d,entry.binding));
          if(!device)fail('SDP_XDR_STALE_BINDING');
          let status='already_revoked',applied=false;
          if(!device.revoked){
            if(registry.revision!==entry.registryRevision||registry.revision>=Number.MAX_SAFE_INTEGER)fail('SDP_XDR_STALE_BINDING');
            device.revoked=true;registry.revision++;writeAtomic(registryPath,registry);status='applied';applied=true;
          }
          entry.status=status;entry.completedAtMs=Math.max(entry.detectedAtMs,Date.now());
          try{saveLedger(evidencePath,entries,key);}
          catch{
            // Registry and ledger are separate atomic files. Do not report a
            // complete success if the revocation happened but its receipt did
            // not commit. A retry observes already_revoked, never applies twice.
            try{const current=readRegistry(registryPath).devices.find(d=>sameBinding(d,entry.binding));
              if(current?.revoked)return Object.freeze({eventId,status:'revoked_record_unconfirmed',applied,recorded:false});
            }catch{}
            return Object.freeze({eventId,status:'outcome_unknown',applied:null,recorded:false});
          }
          return Object.freeze({eventId,status,applied});
        });
      });
    },
  });
}
