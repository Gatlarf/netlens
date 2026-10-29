// Security keys and passkeys in the browser (navigator.credentials). The server sends options as JSON with base64url values; the browser wants ArrayBuffers.
// Only https pages (and localhost) may use it.

const b64 = {
  toBytes(text) {
    const pad = "=".repeat((4 - (text.length % 4)) % 4);
    const raw = atob((text + pad).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  },
  fromBuffer(buf) {
    let s = "";
    for (const byte of new Uint8Array(buf)) s += String.fromCharCode(byte);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

export function supported() {
  return Boolean(window.isSecureContext && window.PublicKeyCredential && navigator.credentials);
}

export function whyNot() {
  if (!window.isSecureContext) return "Security keys work only on pages served over https (or on localhost): put Netlens behind HTTPS first.";
  if (!window.PublicKeyCredential) return "This browser does not support security keys.";
  return "";
}

function friendly(err) {
  if (err && err.name === "NotAllowedError") return new Error("The security key was not used (cancelled or timed out).");
  if (err && err.name === "InvalidStateError") return new Error("This key is already registered.");
  return err instanceof Error ? err : new Error("The security key could not be used.");
}

// options from POST /api/me/webauthn/begin -> what to send to /finish
export async function create(options) {
  const publicKey = {
    ...options,
    challenge: b64.toBytes(options.challenge),
    user: { ...options.user, id: b64.toBytes(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64.toBytes(c.id) })),
  };
  let cred;
  try { cred = await navigator.credentials.create({ publicKey }); } catch (err) { throw friendly(err); }
  return {
    id: cred.id, rawId: b64.fromBuffer(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64.fromBuffer(cred.response.clientDataJSON), attestationObject: b64.fromBuffer(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [] },
  };
}

// options from the sign-in or the confirmation -> what the key signed
export async function get(options) {
  const publicKey = { ...options, challenge: b64.toBytes(options.challenge), allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64.toBytes(c.id) })) };
  let cred;
  try { cred = await navigator.credentials.get({ publicKey }); } catch (err) { throw friendly(err); }
  return {
    id: cred.id, rawId: b64.fromBuffer(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64.fromBuffer(cred.response.clientDataJSON), authenticatorData: b64.fromBuffer(cred.response.authenticatorData),
      signature: b64.fromBuffer(cred.response.signature), userHandle: cred.response.userHandle ? b64.fromBuffer(cred.response.userHandle) : null },
  };
}
