// Reject duplicate keys and prototype keys before JSON interpretation.
export function parseStrictJson(source){
  let at=0;
  const fail=()=>{throw new Error('SDP_INVALID_JSON');};
  const white=()=>{while(at<source.length&&/[\x20\t\r\n]/.test(source[at]))at++;};
  function string(){
    if(source[at]!=='"')return fail();const start=at++;
    while(at<source.length){const c=source[at++];if(c==='"'){try{return JSON.parse(source.slice(start,at));}catch{return fail();}}if(c==='\\'){if(at>=source.length)return fail();at++;}else if(c.charCodeAt(0)<32)return fail();}
    return fail();
  }
  function value(depth){
    if(depth>16)return fail();white();const c=source[at];
    if(c==='"')return string();
    if(c==='{'){
      at++;white();const out=Object.create(null),seen=new Set();if(source[at]==='}'){at++;return out;}
      while(at<source.length){white();const key=string();if(seen.has(key)||['__proto__','prototype','constructor'].includes(key))return fail();seen.add(key);white();if(source[at++]!==':')return fail();out[key]=value(depth+1);white();const end=source[at++];if(end==='}')return out;if(end!==',')return fail();}
      return fail();
    }
    if(c==='['){at++;white();const out=[];if(source[at]===']'){at++;return out;}while(at<source.length){out.push(value(depth+1));white();const end=source[at++];if(end===']')return out;if(end!==',')return fail();}return fail();}
    for(const literal of ['true','false','null'])if(source.startsWith(literal,at)){at+=literal.length;return literal==='true'?true:literal==='false'?false:null;}
    const number=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(at));
    if(!number)return fail();at+=number[0].length;const n=Number(number[0]);if(!Number.isFinite(n))return fail();return n;
  }
  if(typeof source!=='string')return fail();const result=value(0);white();if(at!==source.length)return fail();return result;
}
