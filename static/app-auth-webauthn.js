function b64urlToBuffer(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  s += "===".slice((s.length + 3) % 4);
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

function bufferToB64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function webauthnCreateOptions(publicKey) {
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  publicKey.user.id = b64urlToBuffer(publicKey.user.id);
  (publicKey.excludeCredentials || []).forEach(cred => { cred.id = b64urlToBuffer(cred.id); });
  return publicKey;
}

export function webauthnCreatePayload(credential) {
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToB64url(credential.response.attestationObject),
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : undefined,
    },
    extensions: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

function webauthnGetOptions(publicKey) {
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  (publicKey.allowCredentials || []).forEach(cred => { cred.id = b64urlToBuffer(cred.id); });
  return publicKey;
}

function webauthnGetPayload(credential) {
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToB64url(credential.response.authenticatorData),
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      signature: bufferToB64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToB64url(credential.response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

