import {win32,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync,spawn} from 'node:child_process';
import {createInterface} from 'node:readline/promises';
import {loadConfiguration,readPrivateFile} from '../src/config.mjs';
import {parseStrictJson} from '../src/json.mjs';
import {readRegistry} from '../src/registry.mjs';
import {readSdpHostConfiguration} from '../../on-client/src/engine/sdp-host-config.mjs';

const POWER_SHELL='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
export function validateWindowsLaunch({platform,nodeVersion,mode,configPath}){
  const version=/^(\d+)\.(\d+)\.(\d+)$/.exec(nodeVersion??'');
  if(platform!=='win32'||!version||Number(version[1])!==24||Number(version[2])<19
    ||!['server','client'].includes(mode)||typeof configPath!=='string'
    ||!/^[A-Za-z]:\\/.test(configPath)||configPath.length>4096
    ||/[\x00-\x1f\x7f"&|<>^!%]/.test(configPath)||configPath.slice(2).includes(':')
    ||win32.normalize(configPath)!==configPath||configPath.slice(3).split('\\').some(p=>!p||/[. ]$/.test(p)))throw Error('SDP_WINDOWS_PREFLIGHT_FAILED');
  return Object.freeze({mode,configPath});
}

export async function checkWindowsLaunch(mode,configPath){
  validateWindowsLaunch({platform:process.platform,nodeVersion:process.versions.node,mode,configPath});
  if(mode==='server'){
    const configuration=loadConfiguration(configPath);
    readRegistry(configuration.registryPath);
  }else{
    await readSdpHostConfiguration(configPath,{projectRoot:resolve(dirname(fileURLToPath(import.meta.url)),'../../on-client')});
  }
  // The strict parser runs before PowerShell's JSON parser. No file contents or
  // account/ACL details are emitted by the read-only PowerShell check.
  parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(readPrivateFile(configPath,65536)));
  const script=fileURLToPath(new URL('../windows/check-private-acl.ps1',import.meta.url));
  const result=spawnSync(POWER_SHELL,['-NoLogo','-NoProfile','-NonInteractive','-File',script,'-Mode',mode,'-ConfigPath',configPath],{
    shell:false,windowsHide:true,timeout:10000,maxBuffer:4096,stdio:['ignore','pipe','pipe'],
  });
  if(result.error||result.signal||result.status!==0||result.stdout.toString().trim()!=='SDP_PRIVATE_ACL_OK')throw Error('SDP_WINDOWS_PREFLIGHT_FAILED');
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    if(![3,4].includes(process.argv.length)||process.platform!=='win32')throw Error();
    const mode=process.argv[2];
    let configPath=process.argv[3];
    const launch=configPath===undefined;
    if(launch){
      const prompt=createInterface({input:process.stdin,output:process.stdout});
      try{configPath=await prompt.question('SDP configuration absolute path: ');}finally{prompt.close();}
    }
    await checkWindowsLaunch(mode,configPath);
    console.log('SDP_WINDOWS_PREFLIGHT_OK');
    if(launch){
      const entry=fileURLToPath(new URL(mode==='server'?'../src/main.mjs':'../../on-client/student/pc-server.mjs',import.meta.url));
      const args=mode==='server'?[entry,configPath]:[entry,'--sdp-host-config',configPath];
      const env={...process.env,ON_ENGINE_ADAPTER:'',ON_AI_BASE_URL:'',ON_AI_APP_KEY:'',OPENAI_API_KEY:'',...(mode==='client'?{ON_PORT:'5189'}:{})};
      const child=spawn(process.execPath,args,{shell:false,stdio:'inherit',env});
      child.once('error',()=>{console.error('SDP_WINDOWS_START_FAILED');process.exitCode=1;});
      child.once('exit',code=>{process.exitCode=code??1;});
    }
  }catch{console.error('SDP_WINDOWS_PREFLIGHT_FAILED');process.exitCode=1;}
}
