// Authority-origin only: no embedder messages, base attestation, H2, or RP claims.
"use strict";
(() => {
  const status = document.getElementById("status"), controls = document.getElementById("controls");
  const heading = document.getElementById("heading"), intro = document.getElementById("intro");
  let token;
  const decode = text => Uint8Array.from(atob(text.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-text.length%4)%4)), c=>c.charCodeAt(0));
  const encode = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  async function post(path, body) {
    const response = await fetch(path, {method:"POST",credentials:"omit",redirect:"error",headers:{"Content-Type":"application/json", ...(token?{"X-ByteBind-Attempt":token}:{})},body:JSON.stringify(body)});
    if (!response.ok) {
      const error = new Error("Request refused"); error.status = response.status; throw error;
    }
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
  function view(title, description) {
    controls.replaceChildren(); heading.textContent=title; intro.textContent=description; status.textContent="";
  }
  function note(text, parent=controls) {
    const p=document.createElement("p");p.textContent=text;parent.appendChild(p);return p;
  }
  function link(text, href) {
    const a=document.createElement("a");a.textContent=text;a.href=href;controls.appendChild(a);
  }
  function button(text, handler, onError, parent=controls) {
    const b=document.createElement("button");b.type="button";b.textContent=text;parent.appendChild(b);
    b.onclick=()=>{
      const buttons=Array.from(controls.querySelectorAll("button"));buttons.forEach(node=>{node.disabled=true;});
      let pending;
      // Invoke before any await so native passkey calls retain the click activation.
      try { pending=handler(); } catch(error) { pending=Promise.reject(error); }
      Promise.resolve(pending).catch(error=>{
        token=undefined;
        if(onError) onError(error); else status.textContent=errorMessage(error);
      }).finally(()=>{buttons.forEach(node=>{if(node.isConnected) node.disabled=false;});});
    };return b;
  }
  function field(label, parent=controls) {
    const wrapper=document.createElement("label"), text=document.createElement("span"), input=document.createElement("input");
    text.textContent=label;wrapper.appendChild(text);wrapper.appendChild(input);parent.appendChild(wrapper);
    input.type="text";input.autocomplete="off";return input;
  }
  function errorMessage(error) {
    if(error.status===429) return "Too many attempts. Wait up to 15 minutes, then try again.";
    if(error.status===403) return "This attempt was refused or expired. Start a new attempt.";
    if(error.name==="NotAllowedError") return "Passkey verification was cancelled or timed out.";
    return "Could not reach the passkey service. Check your connection and try again.";
  }
  function supported() {
    if(globalThis.PublicKeyCredential && navigator.credentials) return true;
    view("Passkeys unavailable", "Open this page in a browser that supports passkeys, using its secure HTTPS address.");
    return false;
  }
  function enrollment(message="") {
    token=undefined;
    view("Create your passkey", "Paste the invite your operator gave you.");
    const invite=field("Enrollment invite");invite.spellcheck=false;invite.placeholder="AB12-CD34";
    button("Continue",async()=>{
      if(!invite.value.trim()) { status.textContent="Paste your enrollment invite first.";invite.focus();return; }
      const result=await post("/enroll/begin",{invite:invite.value.trim()});
      invite.value="";token=result.token;
      registration(options(result.options,true),false);
    },error=>{
      if(error.status===403) status.textContent="The invite is invalid or expired, or this device is not allowed to enroll. Ask your operator for help.";
      else status.textContent=errorMessage(error);
    });
    link("Already have a passkey? Manage passkeys", "/manage");
    status.textContent=message;
  }
  function registration(ready, managing) {
    view("Create your passkey", "Your browser will ask you to use a fingerprint, face, PIN, or security key.");
    const details=document.createElement("details"), summary=document.createElement("summary");
    summary.textContent="Name this passkey (optional)";details.appendChild(summary);controls.appendChild(details);
    const name=field("Passkey name",details);name.maxLength=128;name.placeholder="Passkey";
    button("Create passkey",()=>{
      const pending=navigator.credentials.create(ready);
      return pending.then(c=>post("/enroll/complete",{credential:credential(c,true),name:name.value.trim()||"Passkey"})).then(()=>{
        token=undefined;view("Your passkey is ready", "Return to the application to continue.");
        link("Manage passkeys", "/manage");
      });
    },error=>{
      token=undefined;
      view("Passkey not created", error.name==="NotAllowedError" ? "Creation was cancelled or timed out." : errorMessage(error));
      if(managing) button("Back to passkeys",()=>management());
      else { note("Ask your operator for a new invite to try again.");button("Enter a new invite",()=>enrollment()); }
    });
  }
  async function management(message="") {
    token=undefined;view("Your passkeys", "Verify with an existing passkey to see your list.");status.textContent=message;
    try {
      const result=await post("/manage/begin",{});token=result.token;const ready=options(result.options);
      button("Verify with passkey",()=>{
        const pending=navigator.credentials.get(ready);
        return pending.then(c=>post("/manage/verify",{credential:credential(c)})).then(async result=>{
          token=result.token;const list=await post("/manage/list",{});token=undefined;passkeys(list.credentials);
        });
      },error=>managementFailure(error));
      link("Have an invite? Create a passkey", "/enroll");
    } catch(error) { managementFailure(error); }
  }
  function managementFailure(error) {
    token=undefined;view("Could not verify",errorMessage(error));
    button("Try again",()=>management());link("Create a passkey with an invite", "/enroll");
  }
  async function prepareAction(title, description, action) {
    token=undefined;view(title,description);
    try {
      const result=await post("/manage/begin",{});token=result.token;const ready=options(result.options);
      button("Confirm with passkey",()=>{
        const pending=navigator.credentials.get(ready);
        return pending.then(c=>post("/manage/verify",{credential:credential(c)})).then(result=>{
          token=result.token;return action();
        });
      },error=>managementFailure(error));
      button("Back to passkeys",()=>management());
    } catch(error) { managementFailure(error); }
  }
  function actionDone(text) {
    token=undefined;view(text,"Verify again to see your updated passkey list.");button("View passkeys",()=>management());
  }
  function passkeys(list) {
    view("Your passkeys", "Choose a passkey to rename or remove. Each change asks you to verify again.");
    for(const item of list) {
      const card=document.createElement("section");card.className="passkey";controls.appendChild(card);
      const title=document.createElement("h2");title.textContent=item.name;card.appendChild(title);
      if(!item.active) { note("Removed",card);continue; }
      button("Rename",()=>{
        view("Rename passkey", "Choose a name you will recognize.");const name=field("Passkey name");name.value=item.name;name.maxLength=128;
        button("Continue",()=>{
          const label=name.value.trim();if(!label) { status.textContent="Enter a name first.";name.focus();return; }
          return prepareAction("Rename passkey",`Rename “${item.name}” to “${label}”.`,async()=>{
            await post("/manage/rename",{credential_id:item.id,name:label});actionDone("Passkey renamed");
          });
        });button("Back to passkeys",()=>passkeys(list));
      },null,card);
      button("Remove",()=>prepareAction("Remove passkey",`Remove “${item.name}”? Keep another passkey so you can still verify.`,async()=>{
        await post("/manage/revoke",{credential_id:item.id});actionDone("Passkey removed");
      }),null,card);
    }
    button("Add a passkey",()=>prepareAction("Add a passkey", "Verify with an existing passkey, then create another for the same person.",async()=>{
      const result=await post("/enroll/begin",{});token=result.token;registration(options(result.options,true),true);
    }));
  }
  async function load() {
    const mode=document.body.dataset.mode;
    if(mode==="stepup") {
      const handoff=location.hash.slice(1);history.replaceState(null,"",location.pathname);
      const policy=document.permissionsPolicy||document.featurePolicy;
      if(!supported() || (policy && !policy.allowsFeature("publickey-credentials-get"))) {
        status.textContent="This browser or page configuration cannot verify a person.";return;
      }
      const exchange=await post("/step-up/handoff",{handoff,rp_id:document.body.dataset.rp});token=exchange.token;
      const ready=options(exchange.options);
      try {
        // The frame is hidden; consent and verification belong to the browser's native UI.
        const assertion=await navigator.credentials.get(ready);
        await post("/step-up/assertion",{credential:credential(assertion)});
      } catch(error) {
        // Burn this attempt so the RP's result poll terminates after cancellation or refusal.
        try { await post("/step-up/abort",{}); } catch(_) { /* Otherwise the attempt expires. */ }
        throw error;
      } finally { token=undefined; }
    } else if(supported()) {
      if(mode==="enroll") enrollment(); else if(mode==="manage") await management();
    }
  }
  load().catch(error=>{token=undefined;status.textContent=errorMessage(error);});
})();
