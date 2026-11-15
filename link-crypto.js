// Sealing Google's sign-in code for one TV. Must match the TV's
// dev.megh.core.auth.LinkCrypto and LinkSignIn.topic: P-256 ECDH,
// HKDF-SHA256 (empty salt, info "megh-link-v1"), AES-256-GCM.

const subtle = globalThis.crypto.subtle;
const text = new TextEncoder();

export function base64Url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value) {
  const s = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** Relay topic for one side of a sign-in: "megh-" + first 32 hex of SHA-256. */
export async function topic(kind, code) {
  const hash = new Uint8Array(await subtle.digest("SHA-256", text.encode(`megh-${kind}:${code}`)));
  return "megh-" + Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

/** Encrypts [message] so only the TV holding [tvKey] (base64url raw P-256 point) can read it. */
export async function seal(tvKey, message) {
  const tv = await subtle.importKey("raw", fromBase64Url(tvKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const mine = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const shared = await subtle.deriveBits({ name: "ECDH", public: tv }, mine.privateKey, 256);
  const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aes = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: text.encode("megh-link-v1") },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, aes, text.encode(message));
  const epk = await subtle.exportKey("raw", mine.publicKey);
  return { v: 1, epk: base64Url(epk), iv: base64Url(iv), ct: base64Url(ct) };
}

/** Typed codes: uppercase, no spaces or dashes. */
export function normalizeCode(value) {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, "");
}
