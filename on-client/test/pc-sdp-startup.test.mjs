import test from 'node:test';
import assert from 'node:assert/strict';
import {parseStudentArguments,createStudentServer} from '../student/pc-server.mjs';

test('SDP startup requires an explicit profile and excludes demo or duplicate options',()=>{
  assert.deepEqual(parseStudentArguments([]),{demo:false,sdpPath:undefined});
  assert.deepEqual(parseStudentArguments(['--sdp-host-config','/private/profile.json']),{demo:false,sdpPath:'/private/profile.json'});
  for(const args of [['--demo','--sdp-host-config','/private/profile.json'],['--demo','--demo'],['--sdp-host-config'],['--sdp-host-config','--demo'],['--sdp-host-config','a','--sdp-host-config','b'],['--unknown']]){
    assert.throws(()=>parseStudentArguments(args),/PC_INVALID_ARGUMENTS/);
  }
});

test('a connected label or arbitrary object cannot impersonate an owned SDP host',()=>{
  for(const sdpHost of [null,{}, {evidenceMode:'connected',readIdentity(){}}])assert.throws(()=>createStudentServer({sdpHost}),/PC_INVALID_CONFIGURATION/);
});
