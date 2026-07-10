use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};

pub(in crate::handlers) fn passkey_login_page() -> Response<Body> {
    let html = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>klaxond passkey login</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><main class="passkey-login"><section class="card"><h1>klaxond</h1><h2>Passkey login</h2>
<label>User, email or subject <input id="user" autocomplete="username webauthn"></label>
<button id="login" class="primary">Use passkey</button><p id="status" class="muted"></p>
<p><a href="/status">Back to UI</a></p></section></main>
<script>
const b64uToBuf=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');s+='==='.slice((s.length+3)%4);const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer};
const bufToB64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function publicKeyGetOptions(pk){pk.challenge=b64uToBuf(pk.challenge);(pk.allowCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));return pk}
function credentialGetPayload(c){return {id:c.id,rawId:bufToB64u(c.rawId),type:c.type,response:{authenticatorData:bufToB64u(c.response.authenticatorData),clientDataJSON:bufToB64u(c.response.clientDataJSON),signature:bufToB64u(c.response.signature),userHandle:c.response.userHandle?bufToB64u(c.response.userHandle):null},extensions:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
document.getElementById('login').onclick=async()=>{const s=document.getElementById('status');try{const user=document.getElementById('user').value.trim();const a=await fetch('/api/auth/passkey/login/options',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({user})});if(!a.ok)throw new Error(await a.text());const ch=await a.json();const cred=await navigator.credentials.get({publicKey:publicKeyGetOptions(ch.publicKey)});const f=await fetch('/api/auth/passkey/login/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:ch.request_id,credential:credentialGetPayload(cred)})});if(!f.ok)throw new Error(await f.text());const done=await f.json().catch(()=>({}));location.href=done.return_to||'/status'}catch(e){s.textContent=e.message||String(e);s.style.color='var(--red)'}};
</script></body></html>"#;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}
