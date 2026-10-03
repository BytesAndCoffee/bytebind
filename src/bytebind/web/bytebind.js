// ByteBind v1 browser client (SPEC.md sections 9 to 13). WebCrypto only; no dependencies.
// Usable as a classic script (window.ByteBind) or from Node for tests (module.exports).
"use strict";

const ByteBind = (() => {
  const encoder = new TextEncoder();
  const subtle = globalThis.crypto.subtle;
  const LABELS = {
    session: { h1: "bytebind/v1/h1", h2: "bytebind/v1/h2", redeem: "bytebind/v1/redeem" },
    tx: { h1: "bytebind/v1/tx/h1", h2: "bytebind/v1/tx/h2", redeem: "bytebind/v1/tx/redeem" },
  };
  const REQUEST_LABEL = "bytebind/v1/tx/request";
  const SIZES = { cid: 16, secret: 32, ip: 16, h2: 76 };

  const bytes = (text) => encoder.encode(text);

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  }

  function b64encode(value) {
    let text = "";
    for (const byte of value) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64decode(text, size) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length !== Math.floor((size * 4 + 2) / 3)) {
      throw new Error("malformed base64url");
    }
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
    const out = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (out.length !== size || b64encode(out) !== text) throw new Error("non-canonical base64url");
    return out;
  }

  function labels(profile, q) {
    if (!LABELS[profile]) throw new Error(`unknown profile ${profile}`);
    if ((profile === "tx") !== (q !== undefined && q !== null)) throw new Error("Q is required by tx and forbidden in session");
    return LABELS[profile];
  }

  function prefixed(value) {
    const length = new Uint8Array(8);
    new DataView(length.buffer).setBigUint64(0, BigInt(value.length), false);
    return concat(length, value);
  }

  function canonicalHeaders(headers) {
    const lines = Object.entries(headers).map(([name, value]) => `${name.trim().toLowerCase()}:${String(value).trim()}`);
    lines.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return bytes(lines.join("\n"));
  }

  // Q: the browser computes it from the request it sent; it never trusts a Q from the server.
  async function requestDigest(method, target, headers, body) {
    const data = concat(bytes(REQUEST_LABEL), prefixed(bytes(method.toUpperCase())), prefixed(bytes(target)),
      prefixed(canonicalHeaders(headers)), prefixed(body));
    return new Uint8Array(await subtle.digest("SHA-256", data));
  }

  async function hmac(key, message) {
    const imported = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", imported, message));
  }

  const computeH1 = (profile, c, cid, n, q) => hmac(c, concat(bytes(labels(profile, q).h1), cid, n, q || new Uint8Array()));

  async function openH2(profile, c, cid, n, h1, h2) {
    if (h2.length !== SIZES.h2) throw new Error("malformed H2");
    const info = bytes(LABELS[profile].h2);
    const ikm = await subtle.importKey("raw", c, "HKDF", false, ["deriveKey"]);
    const key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: h1, info }, ikm, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plain = new Uint8Array(await subtle.decrypt(
      { name: "AES-GCM", iv: h2.slice(0, 12), additionalData: concat(info, cid, n, h1), tagLength: 128 }, key, h2.slice(12),
    ));
    return { ip: plain.slice(0, SIZES.ip), s: plain.slice(SIZES.ip) };
  }

  const computeR = (profile, s, cid, c, ip, q) => hmac(s, concat(bytes(labels(profile, q).redeem), cid, c, ip, q || new Uint8Array()));

  class CeremonyFailure extends Error {
    constructor(step, status) { super(`${step} failed`); this.step = step; this.status = status; }
  }

  // PROVE -> ATTEST, then compute R. Returns the AFFIRM body.
  async function proveAndAffirmBody(who, profile, q, fetchImpl) {
    const cid = b64decode(who.cid, SIZES.cid);
    const c = b64decode(who.C, SIZES.secret);
    const n = globalThis.crypto.getRandomValues(new Uint8Array(SIZES.secret));
    const h1 = await computeH1(profile, c, cid, n, q);
    let attested;
    try {
      attested = await fetchImpl(`${who.authority}/attest`, {
        method: "POST", mode: "cors", credentials: "omit", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cid: who.cid, N: b64encode(n), H1: b64encode(h1) }),
      });
    } catch (_) {
      throw new CeremonyFailure("PROVE", 0);  // not on the private network, or blocked by the browser
    }
    if (!attested.ok) throw new CeremonyFailure("ATTEST", attested.status);
    const { ip, s } = await openH2(profile, c, cid, n, h1, b64decode((await attested.json()).H2, SIZES.h2));
    return { cid: who.cid, R: b64encode(await computeR(profile, s, cid, c, ip, q)) };
  }

  const jsonPost = (fetchImpl, url, body) => fetchImpl(url, {
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });

  // Session profile: PLEASE a lease, then AFFIRM. Resolves to the RESPONSE body.
  async function session(pleaseUrl, affirmUrl, fetchImpl = globalThis.fetch.bind(globalThis)) {
    const pleased = await jsonPost(fetchImpl, pleaseUrl, {});
    if (!pleased.ok) throw new CeremonyFailure("PLEASE", pleased.status);
    const affirmBody = await proveAndAffirmBody(await pleased.json(), "session", undefined, fetchImpl);
    const response = await jsonPost(fetchImpl, affirmUrl, affirmBody);
    if (!response.ok) throw new CeremonyFailure("AFFIRM", response.status);
    return response.json();
  }

  // Transaction-bound profile: PLEASE carries the protected request itself.
  // The server answers 202 with WHO; RESPONSE is the protected operation's own response.
  async function transaction(url, { method = "POST", body = "", contentType = "application/json" } = {}, affirmUrl,
    fetchImpl = globalThis.fetch.bind(globalThis)) {
    const bodyBytes = typeof body === "string" ? bytes(body) : body;
    const target = new URL(url, globalThis.location ? globalThis.location.href : undefined);
    const pleased = await fetchImpl(target.href, {
      method, credentials: "same-origin", headers: { "Content-Type": contentType }, body: bodyBytes,
    });
    if (pleased.status !== 202) throw new CeremonyFailure("PLEASE", pleased.status);
    const q = await requestDigest(method, target.pathname + target.search, { "content-type": contentType }, bodyBytes);
    const affirmBody = await proveAndAffirmBody(await pleased.json(), "tx", q, fetchImpl);
    return jsonPost(fetchImpl, affirmUrl, affirmBody);
  }

  return { b64encode, b64decode, requestDigest, computeH1, openH2, computeR, session, transaction, CeremonyFailure, LABELS };
})();

if (typeof module !== "undefined" && module.exports) module.exports = ByteBind;
if (typeof window !== "undefined") window.ByteBind = ByteBind;
