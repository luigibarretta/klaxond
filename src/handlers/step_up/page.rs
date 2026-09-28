use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};

pub(in crate::handlers) fn step_up_page() -> Response<Body> {
    let html = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Klaxond step-up</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="passkey-login"><section class="card"><h1>Klaxond</h1><h2>Second factor required</h2>
<p id="summary" class="muted">Loading challenge...</p>
<div id="passkey-panel" class="hidden">
<button id="passkey-login" class="primary">Use passkey</button>
<div id="passkey-register-panel" class="hidden"><label>Passkey name <input id="passkey-name" autocomplete="off" value="step-up passkey"></label>
<button id="passkey-register" class="btn">Register passkey</button></div></div>
<div id="totp-panel" class="hidden"><label>Code <input id="totp-code" inputmode="numeric" autocomplete="one-time-code" placeholder="000000"></label>
<button id="totp-verify" class="primary">Verify code</button>
<div id="totp-setup-panel" class="hidden"><button id="totp-start" class="btn">Set up authenticator</button>
<label>Secret <input id="totp-secret" readonly autocomplete="off"></label>
<label>Authenticator URI <input id="totp-uri" readonly autocomplete="off"></label>
<label>First code <input id="totp-setup-code" inputmode="numeric" autocomplete="one-time-code" placeholder="000000"></label>
<button id="totp-confirm" class="btn">Enable and continue</button></div></div>
<p id="status" class="muted"></p></section></main>
<script>
const params=new URLSearchParams(location.search);const token=params.get('token')||'';const fallback=params.get('return_to')||'/status';let totpRequestId='';
const $=id=>document.getElementById(id);const status=m=>{$('status').textContent=m||''};
function show(id,on=true){$(id)?.classList.toggle('hidden',!on)}
async function post(url,data){const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data),redirect:'manual'});if(!r.ok)throw new Error(await r.text());return r.json()}
function go(body){location.href=body.return_to||fallback||'/status'}
const b64uToBuf=s=>{s=String(s).replace(/-/g,'+').replace(/_/g,'/');s+='==='.slice((s.length+3)%4);const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer};
const bufToB64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function publicKeyGetOptions(pk){pk={...pk,challenge:b64uToBuf(pk.challenge)};(pk.allowCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));return pk}
function publicKeyCreateOptions(pk){pk={...pk,challenge:b64uToBuf(pk.challenge),user:{...pk.user,id:b64uToBuf(pk.user.id)}};(pk.excludeCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));return pk}
function credentialGetPayload(c){return{id:c.id,rawId:bufToB64u(c.rawId),type:c.type,response:{authenticatorData:bufToB64u(c.response.authenticatorData),clientDataJSON:bufToB64u(c.response.clientDataJSON),signature:bufToB64u(c.response.signature),userHandle:c.response.userHandle?bufToB64u(c.response.userHandle):null},extensions:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
function credentialCreatePayload(c){return{id:c.id,rawId:bufToB64u(c.rawId),type:c.type,response:{attestationObject:bufToB64u(c.response.attestationObject),clientDataJSON:bufToB64u(c.response.clientDataJSON)},extensions:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
async function load(){try{if(!token)throw new Error('missing step-up token');const r=await fetch('/api/auth/step-up/status?token='+encodeURIComponent(token),{redirect:'manual'});if(!r.ok)throw new Error(await r.text());const j=await r.json();const name=j.user?.name||j.user?.email||j.user?.sub||'user';$('summary').textContent=`Confirm ${j.factor} for ${name}.`;if(j.factor==='totp'){show('totp-panel');show('totp-setup-panel',!j.totp_registered);$('totp-verify').disabled=!j.totp_registered}else{show('passkey-panel');show('passkey-register-panel',!j.passkey_registered)}}catch(e){status(e.message||String(e))}}
$('passkey-login').onclick=async()=>{try{status('Waiting for passkey...');const start=await post('/api/auth/passkey/login/options',{step_up:token});const cred=await navigator.credentials.get({publicKey:publicKeyGetOptions(start.publicKey)});go(await post('/api/auth/passkey/login/verify',{request_id:start.request_id,credential:credentialGetPayload(cred)}))}catch(e){status(e.message||String(e))}};
$('passkey-register').onclick=async()=>{try{status('Creating passkey...');const start=await post('/api/auth/step-up/passkey/register/options',{step_up:token,name:$('passkey-name').value.trim()||'step-up passkey'});const cred=await navigator.credentials.create({publicKey:publicKeyCreateOptions(start.publicKey)});go(await post('/api/auth/step-up/passkey/register/verify',{request_id:start.request_id,credential:credentialCreatePayload(cred)}))}catch(e){status(e.message||String(e))}};
$('totp-verify').onclick=async()=>{try{go(await post('/api/auth/step-up/totp/verify',{step_up:token,code:$('totp-code').value.trim()}))}catch(e){status(e.message||String(e))}};
$('totp-start').onclick=async()=>{try{const r=await post('/api/auth/step-up/totp/setup/start',{step_up:token});totpRequestId=r.request_id;$('totp-secret').value=r.secret||'';$('totp-uri').value=r.otpauth_uri||'';status('Scan the authenticator URI, then enter the first code.')}catch(e){status(e.message||String(e))}};
$('totp-confirm').onclick=async()=>{try{go(await post('/api/auth/step-up/totp/setup/confirm',{request_id:totpRequestId,code:$('totp-setup-code').value.trim()}))}catch(e){status(e.message||String(e))}};
load();
</script></body></html>"#;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .expect("static step-up response headers are valid")
}
