// Exercise the shipped UI with a small DOM and controlled browser/service edges.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag, root=false) { this.tag=tag;this.children=[];this.textContent='';this.value='';this.root=root;this.disabled=false; }
  appendChild(child) { child.parent=this;this.children.push(child);return child; }
  replaceChildren() { this.children.forEach(child=>{child.parent=null;});this.children=[]; }
  setAttribute(key,value) { this[key]=value; }
  focus() { this.focused=true; }
  get isConnected() { return this.root || Boolean(this.parent && this.parent.isConnected); }
  querySelectorAll(tag) { return this.children.flatMap(child=>[...(child.tag===tag?[child]:[]),...child.querySelectorAll(tag)]); }
}
const source=fs.readFileSync(process.argv[2],'utf8');
const pk=create=>({publicKey:{challenge:'AQ',...(create?{user:{id:'Ag',name:'Invited person'},excludeCredentials:[]}:{allowCredentials:[]})}});
const flush=async()=>{for(let i=0;i<6;i++) await new Promise(resolve=>setImmediate(resolve));};
function browser(mode='enroll', supported=true, cancelInitially=false, delegated=true) {
  const nodes=Object.fromEntries(['status','controls','heading','intro'].map(id=>[id,new Element('div',true)]));
  const requests=[], native=[];let inClick=false, cancelled=cancelInitially, refused=false, logins=0, verified=0;
  const document={getElementById:id=>nodes[id],createElement:tag=>new Element(tag),body:{dataset:{mode,rp:'app'}},permissionsPolicy:{allowsFeature:()=>delegated}};
  const credential={id:'AQ',rawId:new Uint8Array([1]).buffer,type:'public-key',getClientExtensionResults:()=>({credProps:{rk:true}}),response:{clientDataJSON:new Uint8Array([2]).buffer,attestationObject:new Uint8Array([3]).buffer,authenticatorData:new Uint8Array([4]).buffer,signature:new Uint8Array([5]).buffer,userHandle:new Uint8Array([6]).buffer}};
  const getOrCreate=kind=>options=>{
    assert.equal(inClick,mode!=='stepup','only hidden step-up invokes WebAuthn without a frame-local click');
    assert.ok(options.publicKey.challenge instanceof Uint8Array);
    native.push(kind);
    return cancelled?Promise.reject(Object.assign(new Error(),{name:'NotAllowedError'})):Promise.resolve(credential);
  };
  const fetch=async(path,init)=>{
    assert.equal(init.credentials,'omit');assert.equal(init.redirect,'error');
    const body=JSON.parse(init.body);requests.push({path,body,token:init.headers['X-ByteBind-Attempt']});
    let result={ok:true};
    if(path==='/enroll/begin') result={token:'registration',options:pk(true)};
    if(path==='/manage/begin') result={token:`login-${++logins}`,options:pk(false)};
    if(path==='/manage/verify') result={token:`management-${++verified}`};
    if(path==='/manage/list') result={credentials:[{id:'private-credential-id',name:'Laptop',active:true}]};
    if(path==='/step-up/handoff') result={token:'stepup',options:pk(false)};
    return {ok:!refused,status:refused?403:200,json:async()=>structuredClone(result)};
  };
  const location={hash:'#one-use-handoff',pathname:'/step-up/app'};
  vm.runInNewContext(source,{document,fetch,navigator:{credentials:{create:getOrCreate('create'),get:getOrCreate('get')}},PublicKeyCredential:supported?class {}:undefined,location,history:{replaceState(){location.hash='';}},atob,btoa,Uint8Array,Promise});
  const click=async text=>{
    const b=nodes.controls.querySelectorAll('button').find(b=>b.textContent===text);
    assert.ok(b,`button exists: ${text}`);assert.equal(b.disabled,false);
    inClick=true;b.onclick();inClick=false;await flush();
  };
  return {nodes,requests,native,location,click,refuse:()=>{refused=true;},cancel:()=>{cancelled=true;}};
}
(async()=>{
  const b=browser();await flush();
  assert.equal(b.requests.length,0,'loading enrollment must not consume an invite');
  assert.deepEqual(b.nodes.controls.querySelectorAll('button').map(b=>b.textContent),['Continue']);
  assert.equal(b.nodes.controls.querySelectorAll('input').length,1);
  await b.click('Continue');assert.equal(b.requests.length,0,'blank invites never reach the service');
  b.nodes.controls.querySelectorAll('input')[0].value='  invite  ';
  await b.click('Continue');
  assert.deepEqual(b.requests[0].body,{invite:'invite'});
  assert.equal(b.native.length,0,'options are fetched before the native click');
  await b.click('Create passkey');
  assert.deepEqual(b.native,['create']);
  assert.equal(b.requests[1].body.name,'Passkey');assert.equal(b.requests[1].token,'registration');
  assert.equal(b.nodes.heading.textContent,'Your passkey is ready');

  const cancelled=browser();await flush();cancelled.nodes.controls.querySelectorAll('input')[0].value='invite';
  await cancelled.click('Continue');cancelled.cancel();await cancelled.click('Create passkey');
  assert.equal(cancelled.requests.length,1,'cancelled creation is not submitted or automatically retried');
  assert.equal(cancelled.nodes.heading.textContent,'Passkey not created');
  await cancelled.click('Enter a new invite');assert.equal(cancelled.requests.length,1);

  const denied=browser();await flush();denied.refuse();denied.nodes.controls.querySelectorAll('input')[0].value='bad';
  await denied.click('Continue');assert.match(denied.nodes.status.textContent,/invalid or expired/);
  assert.equal(denied.nodes.controls.querySelectorAll('button')[0].disabled,false);

  const m=browser('manage');await flush();await m.click('Verify with passkey');
  assert.equal(m.requests.find(r=>r.path==='/manage/list').token,'management-1');
  assert.equal(m.nodes.controls.querySelectorAll('input').length,0,'credential IDs are never requested');
  assert.equal(m.nodes.controls.querySelectorAll('h2')[0].textContent,'Laptop');
  await m.click('Rename');m.nodes.controls.querySelectorAll('input')[0].value='My laptop';
  await m.click('Continue');
  assert.equal(m.requests.filter(r=>r.path==='/manage/rename').length,0,'no rename before fresh UV');
  await m.click('Confirm with passkey');
  const rename=m.requests.find(r=>r.path==='/manage/rename');
  assert.equal(rename.token,'management-2');assert.deepEqual(rename.body,{credential_id:'private-credential-id',name:'My laptop'});
  assert.deepEqual(m.native,['get','get']);

  const adding=browser('manage');await flush();await adding.click('Verify with passkey');
  await adding.click('Add a passkey');await adding.click('Confirm with passkey');
  assert.equal(adding.requests.find(r=>r.path==='/enroll/begin').token,'management-2');
  await adding.click('Create passkey');assert.deepEqual(adding.native,['get','get','create']);

  const removing=browser('manage');await flush();await removing.click('Verify with passkey');
  await removing.click('Remove');assert.equal(removing.requests.filter(r=>r.path==='/manage/revoke').length,0);
  await removing.click('Confirm with passkey');assert.equal(removing.requests.find(r=>r.path==='/manage/revoke').token,'management-2');

  const step=browser('stepup');await flush();assert.equal(step.location.hash,'');
  assert.deepEqual(step.native,['get']);assert.equal(step.requests[1].token,'stepup');
  assert.deepEqual(step.requests.map(r=>r.path),['/step-up/handoff','/step-up/assertion']);
  assert.equal(step.nodes.controls.children.length,0,'hidden step-up never requires a frame-local control');
  const cancelledStep=browser('stepup',true,true);await flush();
  assert.deepEqual(cancelledStep.native,['get'],'cancellation must not retry');
  assert.deepEqual(cancelledStep.requests.map(r=>r.path),['/step-up/handoff','/step-up/abort']);
  assert.equal(cancelledStep.requests[1].token,'stepup');
  const unavailable=browser('stepup',false);await flush();
  assert.equal(unavailable.location.hash,'');assert.equal(unavailable.requests.length,0,'unsupported frames must not consume the handoff');
  const blocked=browser('stepup',true,false,false);await flush();assert.equal(blocked.requests.length,0);
  console.log('enrollment, management, cancellation, and step-up passed');
})().catch(error=>{console.error(error);process.exit(1);});
