import {readPrivateFile} from '../src/config.mjs';
import {parseStrictJson} from '../src/json.mjs';
import {exact} from '../src/security.mjs';
import {createXdrBridge} from '../src/xdr-bridge.mjs';

// Separate operator-only profile. Never accept a device target or event payload
// from the command line: the signed server proposal determines the target.
try{
  const args=process.argv.slice(2);
  const listing=args.length===3&&args[0]==='--config'&&args[2]==='--list';
  const approving=args.length===5&&args[0]==='--config'&&args[2]==='--event'&&args[4]==='--approve';
  if(!listing&&!approving)throw Error();
  const configuration=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(readPrivateFile(args[1],8192)));
  exact(configuration,['schema','registryFile','evidenceFile','evidenceKeyFile']);
  if(configuration.schema!=='student.sdp.response.v1')throw Error();
  const bridge=createXdrBridge({registryPath:configuration.registryFile,evidencePath:configuration.evidenceFile,evidenceKey:readPrivateFile(configuration.evidenceKeyFile,128)});
  if(listing){
    console.log(JSON.stringify(bridge.listProposals().map(({eventId,detectionAction,confidence,reason,status})=>({eventId,detectionAction,confidence,reason,status}))));
  }else{
    const result=bridge.approve(args[3]);
    console.log(JSON.stringify({status:result.status,applied:result.applied,...(result.recorded===false?{recorded:false}:{})}));
    if(result.recorded===false)process.exitCode=2;
  }
}catch{console.error('SDP_RESPONSE_FAILED');process.exitCode=1;}
