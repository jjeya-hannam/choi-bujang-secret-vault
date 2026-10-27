import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateWindowsLaunch,checkWindowsLaunch} from '../tools/windows-preflight.mjs';

test('Windows launch accepts only supported runtime and explicit canonical drive config',()=>{
  const good={platform:'win32',nodeVersion:'24.19.0',mode:'server',configPath:'C:\\Private SDP\\server.json'};
  assert.deepEqual(validateWindowsLaunch(good),{mode:good.mode,configPath:good.configPath});
  assert.doesNotThrow(()=>validateWindowsLaunch({...good,mode:'client',nodeVersion:'24.20.1'}));
  for(const patch of [{platform:'darwin'},{nodeVersion:'24.18.9'},{nodeVersion:'25.0.0'},{nodeVersion:'24.19.0-rc.1'},{mode:'demo'},{configPath:'server.json'},{configPath:'\\\\host\\share\\server.json'},{configPath:'C:\\private\\..\\server.json'},{configPath:'C:\\private\\server.json:stream'},{configPath:'C:\\private\\server & other.json'},{configPath:'C:\\private\\%TOKEN%.json'},{configPath:'C:\\private\\server.json '}])assert.throws(()=>validateWindowsLaunch({...good,...patch}));
});

test('non-Windows preflight fails before reading config or running platform tools',async()=>{
  if(process.platform!=='win32')await assert.rejects(checkWindowsLaunch('server','C:\\not-present\\server.json'),/SDP_WINDOWS_PREFLIGHT_FAILED/);
});

test('launchers and ACL check are explicit, readonly and do not widen access',async()=>{
  const server=await readFile(new URL('../windows/start-server.cmd',import.meta.url),'utf8');
  const client=await readFile(new URL('../windows/start-client.cmd',import.meta.url),'utf8');
  const acl=await readFile(new URL('../windows/check-private-acl.ps1',import.meta.url),'utf8');
  for(const script of [server,client]){
    assert.match(script,/setlocal DisableDelayedExpansion/);
    assert.match(script,/windows-preflight\.mjs/);
    assert.doesNotMatch(script,/%~[1-9]|%\*/);
    assert.doesNotMatch(script,/--demo|netsh|schtasks|ExecutionPolicy|runas|icacls/i);
  }
  assert.match(client,/windows-preflight\.mjs client/);
  assert.match(client,/set "ON_PORT=5189"/);
  assert.match(acl,/Get-Acl -LiteralPath/);
  assert.match(acl,/ReparsePoint/);
  assert.match(acl,/DeleteSubdirectoriesAndFiles/);
  assert.match(acl,/InheritOnly/);
  assert.match(acl,/S-1-5-18/);
  assert.doesNotMatch(acl,/Set-Acl|Remove-Item|Set-ExecutionPolicy|Write-Host|Format-List/i);
});
