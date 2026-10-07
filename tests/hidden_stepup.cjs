// Drive the public browser client through step-up with real cryptographic proofs.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync(process.argv[2],'utf8');
async function run({refused=false, badUrl=false}={}) {
  const frames=[];let removed=0, proofSubmitted=false;
  const document={createElement(tag){
    assert.equal(tag,'iframe');
    return {style:{setProperty(key,value,priority){this[key]=value;this.priority=priority;}},setAttribute(key,value){this[key]=value;},remove(){removed++;}};
  },body:{appendChild(frame){frames.push(frame);}}};
  const context={document,crypto:crypto.webcrypto,URL,TextEncoder,Uint8Array,DataView,atob,btoa,module:{exports:{}},setTimeout,top:null,self:null};
  vm.runInNewContext(source,context);
  const B=context.module.exports;
  const C=Buffer.alloc(32,1),cid=Buffer.alloc(16,2),secret=Buffer.alloc(32,3),ip=Buffer.alloc(16,4);
  const challenge={protocol:1,draft:'0.8',C:B.b64encode(C),cid:B.b64encode(cid),authority:'https://authority.example',person_origin:'https://person.example'};
  let attestation;
  const fetchImpl=async(url,init)=>{
    const body=JSON.parse(init.body);
    const response=(status,result)=>({ok:status<400,status,json:async()=>result});
    if(url==='/challenge')return response(200,challenge);
    if(url.endsWith('/attestation')) {
      assert.equal(frames.length,0,'base attestation precedes embedding');attestation=body;
      return response(202,{step_up:{url:badUrl?'https://unexpected.example/step-up/app':'https://person.example/step-up/app',handoff:B.b64encode(Buffer.alloc(32,5)),completion:B.b64encode(Buffer.alloc(32,6))}});
    }
    if(url.endsWith('/attestation/result')) {
      const frame=frames[0];assert.ok(frame);assert.equal(frame.hidden,true);
      assert.equal(frame.style.display,'none');assert.equal(frame.style.priority,'important');
      assert.equal(frame.tabIndex,-1);assert.equal(frame['aria-hidden'],'true');
      assert.ok(frame.allow.includes('publickey-credentials-get https://person.example'));
      assert.equal(init.credentials,'omit');assert.equal(body.N,attestation.N);assert.equal(body.H1,attestation.H1);
      if(refused)return response(403,{});
      const h1=Buffer.from(B.b64decode(body.H1,32)),n=Buffer.from(B.b64decode(body.N,32));
      const label=Buffer.from(B.LABELS.session.h2),iv=Buffer.alloc(12,7);
      const key=crypto.hkdfSync('sha256',C,h1,label,32),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
      cipher.setAAD(Buffer.concat([label,cid,n,h1]));
      const encrypted=Buffer.concat([cipher.update(Buffer.concat([ip,secret])),cipher.final()]);
      return response(200,{H2:B.b64encode(Buffer.concat([iv,encrypted,cipher.getAuthTag()]))});
    }
    assert.equal(url,'/proof');proofSubmitted=true;
    assert.equal(body.R,B.b64encode(await B.computeR('session',secret,cid,C,ip)));
    return response(200,{verified:true});
  };
  if(refused || badUrl) await assert.rejects(B.session('/challenge','/proof',fetchImpl),error=>error.step==='step-up');
  else assert.equal((await B.session('/challenge','/proof',fetchImpl)).verified,true);
  assert.equal(frames.length,badUrl?0:1);assert.equal(removed,badUrl?0:1,'frame is removed on success and failure');
  assert.equal(proofSubmitted,!(refused||badUrl));
}
(async()=>{await run();await run({refused:true});await run({badUrl:true});console.log('hidden frame, proof, refusal, URL validation and cleanup passed');})().catch(error=>{console.error(error);process.exit(1);});
