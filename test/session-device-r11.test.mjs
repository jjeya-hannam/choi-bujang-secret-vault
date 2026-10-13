import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createAuthHandler } from '../api/auth.js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';
import { createRequestLoginVerifier, newCredential, hashCredential, readCredential,
  SESSION_COOKIE, DEVICE_COOKIE } from '../src/browser-session.mjs';

const config = { publicAppUrl: 'https://student-defense.vercel.app',
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  identityProvider: { issuer: 'https://student-project.supabase.co/auth/v1', audience: 'authenticated',
    jwksUrl: 'https://student-project.supabase.co/auth/v1/.well-known/jwks.json' } };
function response() { return { headers: {}, setHeader(name,value) { this.headers[name]=value; },
  status(value) { this.statusCode=value; return this; }, json(value) { this.body=value; return this; } }; }
const originHeaders = { origin: config.publicAppUrl, 'content-type':'application/json', 'sec-fetch-site':'same-origin' };
const cookieHeader = (session,device) => `${SESSION_COOKIE}=${session}; ${DEVICE_COOKIE}=${device}`;

test('password authentication issues opaque HttpOnly cookies and only stores credential hashes', async () => {
  const user = randomUUID(), calls=[];
  const db = { async rpc(name,args) { calls.push({name,args}); return {data:{deviceStatus:'pending'}}; } };
  const handler = createAuthHandler(() => ({ config, db, createAuthClient: () => ({ auth: {
    async signInWithPassword() { return {data:{user:{id:user},session:{expires_at:Math.floor(Date.now()/1000)+3600}}}; },
  } }) }));
  const res=response();
  await handler({method:'POST',headers:originHeaders,body:{action:'signIn',email:'synthetic@example.test',password:'synthetic fixture only'}},res);
  assert.equal(res.statusCode,200); assert.deepEqual(res.body,{signedIn:true,deviceStatus:'pending'});
  assert.equal(res.headers['Cache-Control'],'no-store');
  const cookies=res.headers['Set-Cookie']; assert.equal(cookies.length,2);
  for(const value of cookies) assert.match(value,/; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d+$/u);
  const req={headers:{cookie:cookies.map(value=>value.split(';')[0]).join('; ')}};
  const session=readCredential(req,SESSION_COOKIE),device=readCredential(req,DEVICE_COOKIE);
  assert.match(session,/^[A-Za-z0-9_-]{43}$/u); assert.notEqual(session,device);
  assert.equal(calls[0].name,'stage11_create_browser_session');
  assert.equal(calls[0].args.p_session_hash,hashCredential(session)); assert.equal(calls[0].args.p_device_hash,hashCredential(device));
  assert.equal(JSON.stringify(calls).includes(session),false); assert.equal(JSON.stringify(calls).includes(device),false);
  assert.equal(JSON.stringify(res.body).includes(user),false);
  assert.deepEqual(Object.keys(res.body).sort(),['deviceStatus','signedIn']);
});

test('new pending devices cannot self-approve, and signout revokes the server session', async () => {
  const user=randomUUID(),session=newCredential(),device=newCredential(),calls=[];
  const handler=createAuthHandler(()=>({config,db:{async rpc(name,args) { calls.push({name,args});
    return name==='stage11_lookup_browser_session'?{data:{signedIn:true,userId:user,deviceStatus:'pending'}}:{data:null}; }}}));
  const headers={...originHeaders,cookie:cookieHeader(session,device)};
  const requested=response();
  await handler({method:'POST',headers,body:{action:'requestDevice',approved:true,role:'admin'}},requested);
  assert.deepEqual(requested.body,{signedIn:true,deviceStatus:'pending'});
  assert.equal(calls[0].name,'stage11_lookup_browser_session');
  const attempted=response(); await handler({method:'POST',headers,body:{action:'approveDevice'}},attempted);
  assert.equal(attempted.statusCode,400);
  const signedOut=response(); await handler({method:'POST',headers,body:{action:'signOut'}},signedOut);
  assert.deepEqual(signedOut.body,{signedIn:false,deviceStatus:'unrequested'});
  assert.equal(calls.at(-1).name,'stage11_revoke_browser_session');
  assert.match(signedOut.headers['Set-Cookie'],/Max-Age=0$/u);
  assert.equal(calls.some(call=>call.name.includes('approve')),false);
});

test('email confirmation signup has no session or browser secrets; cross-site auth is rejected',async()=>{
  let requests=0;
  const handler=createAuthHandler(()=>({config,db:{rpc(){throw new Error('no_session_expected');}},createAuthClient:()=>({auth:{async signUp(){requests++;return {data:{session:null}};}}})}));
  const signup=response();await handler({method:'POST',headers:originHeaders,body:{action:'signUp',email:'synthetic@example.test',password:'synthetic fixture only'}},signup);
  assert.equal(signup.statusCode,200); assert.deepEqual(signup.body,{signedIn:false,deviceStatus:'unrequested',confirmationRequired:true});
  assert.equal(signup.headers['Set-Cookie'],undefined);
  for(const headers of [{...originHeaders,origin:'https://attacker.example.test'},
    {...originHeaders,'sec-fetch-site':'cross-site'},{...originHeaders,'content-type':'text/plain'}]) {
    const denied=response();await handler({method:'POST',headers,body:{action:'signUp',email:'synthetic@example.test',password:'synthetic fixture only'}},denied);
    assert.equal(denied.statusCode,403);
  }
  assert.equal(requests,1);
});

test('student notes require live approved device binding; student bearer cannot bypass it',async()=>{
  const user=randomUUID(),session=newCredential(),device=newCredential();let state='pending',queries=0;
  const db={async rpc(){return {data:state==='expired'?{signedIn:false}:{signedIn:true,userId:user,deviceStatus:state}};},
    from(){queries++;return {select(){return this;},eq(field,value){assert.equal(field,'owner_id');assert.equal(value,user);return this;},async order(){return {data:[]};}};}};
  const verify=createRequestLoginVerifier({db,config,verifyBearer:async()=>({kind:'student',userId:user})});
  const handler=createNotesHandler(()=>({db,verify}),()=>{});
  async function get(headers){const result=response();await handler({method:'GET',url:'/api/notes',headers},result);return result;}
  const headers={cookie:cookieHeader(session,device)};
  for(state of ['pending','revoked']) assert.equal((await get(headers)).statusCode,403);
  assert.equal(queries,0);
  state='expired';assert.equal((await get(headers)).statusCode,401);
  state='approved';assert.equal((await get(headers)).statusCode,200);assert.equal(queries,1);
  assert.equal((await get({...headers,authorization:'synthetic student bearer'})).statusCode,403);
  assert.equal((await get({cookie:`${SESSION_COOKIE}=${session}`})).statusCode,401);
  assert.equal(queries,1);
  const altered=response();await handler({method:'PUT',url:`/api/notes/${randomUUID()}`,body:{title:'Synthetic',body:'Synthetic'},
    headers:{...headers,...originHeaders,origin:'https://attacker.example.test'}},altered);
  assert.equal(altered.statusCode,401);assert.equal(queries,1);
});

test('cookie adapter preserves genuinely ES256-verified synthetic judge A/B',async()=>{
  const pair=await generateKeyPair('ES256'),publicKey=await exportJWK(pair.publicKey);
  const verifyBearer=createLoginVerifier({config,judgeKeySet:createLocalJWKSet({keys:[{...publicKey,kid:'ephemeral',alg:'ES256',use:'sig'}]}),
    supabaseClient:{auth:{getClaims:async()=>({error:new Error('unused')})}}});
  const verify=createRequestLoginVerifier({verifyBearer,config,db:{rpc(){throw new Error('judge_does_not_use_browser_sessions');}}});
  for(const identity of ['a','b']) {
    const now=Math.floor(Date.now()/1000),user=randomUUID();
    const token=await new SignJWT({iss:config.judgeIssuer,aud:'student-defense.vercel.app',sub:user,aleph_role:'judge',aleph_identity:identity,
      aleph_run:randomUUID(),iat:now,exp:now+300}).setProtectedHeader({alg:'ES256',kid:'ephemeral'}).sign(pair.privateKey);
    const result=await verify(`Bearer ${token}`,{method:'GET',headers:{}});
    assert.equal(result.kind,'judge');assert.equal(result.identity,identity);assert.equal(result.userId,user);
  }
});
