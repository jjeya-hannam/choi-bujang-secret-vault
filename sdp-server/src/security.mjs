import {parseStrictJson} from './json.mjs';
import {createHmac,timingSafeEqual,randomUUID} from 'node:crypto';
export const SUBJECT=/^[0-9a-f]{64}$/, DEVICE=/^[0-9a-f]{16}$/, PROJECT=/^[a-z][a-z0-9_-]{0,63}$/, ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/, HASH=/^[0-9a-f]{64}$/;
export function fail(code='SDP_REJECTED'){const error=new Error(code);
  error.code=code;
  throw error;
}
export function exact(value,keys){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)))fail();
  return value;
}
export function requireKey(key){if(!Buffer.isBuffer(key)||key.length<32||key.length>128)fail('SDP_INVALID_KEY');
}
const segment=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
function decode(value){if(typeof value!=='string'||!value||!/^[A-Za-z0-9_-]+$/.test(value))fail();
  const bytes=Buffer.from(value,'base64url');
  if(bytes.toString('base64url')!==value)fail();
  try{return parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  }
  catch{fail();
  }}
function claimsValid(c){exact(c,['iss','aud','sub','projectId','deviceId','cnf','sid','iat','nbf','exp']);
  if(typeof c.iss!=='string'||!c.iss||c.iss.length>200||typeof c.aud!=='string'||!c.aud||c.aud.length>100||!SUBJECT.test(c.sub)||!PROJECT.test(c.projectId)||!DEVICE.test(c.deviceId)||!HASH.test(c.cnf)||!ID.test(c.sid)||![c.iat,c.nbf,c.exp].every(Number.isSafeInteger)||c.nbf!==c.iat||c.exp<=c.iat||c.exp-c.iat>900)fail();
}
export function createToken({key,issuer,audience,subjectId,projectId,deviceId,certificateFingerprint,sessionId=randomUUID(),ttlSeconds=300}){requireKey(key);
  const now=Math.floor(Date.now()/1000);
  if(!Number.isInteger(ttlSeconds)||ttlSeconds<1||ttlSeconds>900)fail();
  const payload={iss:issuer,aud:audience,sub:subjectId,projectId,deviceId,cnf:certificateFingerprint,sid:sessionId,iat:now,nbf:now,exp:now+ttlSeconds};
  claimsValid(payload);
  const body=segment({alg:'HS256',typ:'JWT'})+'.'+segment(payload);
  return body+'.'+createHmac('sha256',key).update(body).digest('base64url');
}
export function verifyToken(token,{key,issuer,audience},fingerprint){requireKey(key);
  if(typeof token!=='string'||token.length>4096)fail();
  const parts=token.split('.');
  if(parts.length!==3)fail();
  const header=exact(decode(parts[0]),['alg','typ']);
  if(header.alg!=='HS256'||header.typ!=='JWT'||!/^[A-Za-z0-9_-]{43}$/.test(parts[2]))fail();
  const sig=Buffer.from(parts[2],'base64url'),wanted=createHmac('sha256',key).update(parts[0]+'.'+parts[1]).digest();
  if(sig.length!==wanted.length||!timingSafeEqual(sig,wanted)||sig.toString('base64url')!==parts[2])fail();
  const c=decode(parts[1]);
  claimsValid(c);
  const now=Math.floor(Date.now()/1000);
  if(c.iss!==issuer||c.aud!==audience||c.cnf!==fingerprint||c.nbf>now||c.iat>now||c.exp<=now)fail();
  return Object.freeze(c);
}
