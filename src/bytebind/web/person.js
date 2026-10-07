// Authority-origin only: no embedder messages, base attestation, H2, or RP claims.
"use strict";
(() => {
  const status = document.getElementById("status"), controls = document.getElementById("controls");
  let token;
  const decode = text => Uint8Array.from(atob(text.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-text.length%4)%4)), c=>c.charCodeAt(0));
  const encode = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  async function post(path, body) {
    const response = await fetch(path, {method:"POST",credentials:"omit",redirect:"error",headers:{"Content-Type":"application/json", ...(token?{"X-ByteBind-Attempt":token}:{})},body:JSON.stringify(body)});
    if (!response.ok) throw new Error("Person verification unavailable");
    return response.json();
  }
  function options(value, create=false) {
    const pk=value.publicKey; pk.challenge=decode(pk.challenge);
    if (create) pk.user.id=decode(pk.user.id);
    for (const key of ["allowCredentials","excludeCredentials"]) for (const cred of pk[key]||[]) cred.id=decode(cred.id);
    return {publicKey:pk};
  }
  function credential(value,create=false) {
    const r=value.response;
    return {id:value.id,rawId:encode(value.rawId),type:value.type,clientExtensionResults:value.getClientExtensionResults(),response:create?
      {clientDataJSON:encode(r.clientDataJSON),attestationObject:encode(r.attestationObject)}:
      {clientDataJSON:encode(r.clientDataJSON),authenticatorData:encode(r.authenticatorData),signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null}};
  }
  function button(text, handler) {
    const b=document.createElement("button");b.textContent=text;controls.appendChild(b);
    b.onclick=()=>{b.disabled=true;Promise.resolve(handler()).catch(()=>{status.textContent="Verification failed. Start a new attempt.";});};return b;
  }
  function field(label) {
    const node=document.createElement("input"); node.setAttribute("aria-label",label);node.placeholder=label;controls.appendChild(node);return node;
  }
  async function load() {
    const mode=document.body.dataset.mode;
    if(mode==="stepup") {
      const handoff=location.hash.slice(1);history.replaceState(null,"",location.pathname);
      const policy=document.permissionsPolicy||document.featurePolicy;
      if(!globalThis.PublicKeyCredential || !navigator.credentials || (policy && !policy.allowsFeature("publickey-credentials-get"))) {
        status.textContent="This browser or page configuration cannot verify a person.";return;
      }
      const exchange=await post("/step-up/handoff",{handoff,rp_id:document.body.dataset.rp});token=exchange.token;
      const ready=options(exchange.options);
      button("Verify with passkey",()=>{
        // get() starts synchronously from the click, with preloaded options.
        const assertion=navigator.credentials.get(ready);
        return assertion.then(c=>post("/step-up/assertion",{credential:credential(c)})).then(()=>{token=undefined;status.textContent="Verified. You can continue in the application.";});
      });
      button("Cancel",()=>post("/step-up/abort",{}).then(()=>{token=undefined;status.textContent="Cancelled";}));
    } else {
      const name=field("Passkey name"), invite=field("Enrollment invite");
      let registration;
      const register=button("Create passkey",()=>{
        const pending=navigator.credentials.create(registration);
        return pending.then(c=>post("/enroll/complete",{credential:credential(c,true),name:name.value})).then(()=>{token=undefined;status.textContent="Passkey registered";});
      });register.disabled=true;
      button("Prepare enrollment",async()=>{const result=await post("/enroll/begin",{invite:invite.value});token=result.token;registration=options(result.options,true);register.disabled=false;});
      let login;
      const verify=button("Verify existing passkey",()=>{
        const pending=navigator.credentials.get(login);
        return pending.then(c=>post("/manage/verify",{credential:credential(c)})).then(result=>{token=result.token;status.textContent="Verified. Choose one credential action.";});
      });verify.disabled=true;
      button("Prepare credential management",async()=>{const result=await post("/manage/begin",{});token=result.token;login=options(result.options);verify.disabled=false;});
      button("Add a passkey",async()=>{const result=await post("/enroll/begin",{});token=result.token;registration=options(result.options,true);register.disabled=false;});
      button("List passkeys",async()=>{const result=await post("/manage/list",{});token=undefined;status.textContent=JSON.stringify(result.credentials);});
      const credentialId=field("Credential ID from your list");
      button("Rename passkey",async()=>{await post("/manage/rename",{credential_id:credentialId.value,name:name.value});token=undefined;status.textContent="Renamed";});
      button("Revoke passkey",async()=>{await post("/manage/revoke",{credential_id:credentialId.value});token=undefined;status.textContent="Revoked";});
    }
  }
  load().catch(()=>{status.textContent="Person verification unavailable. Start a new attempt.";});
})();
