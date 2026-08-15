'use strict';
/* =====================================================================
   Socle commun aux fonctions Strava (etape A : OAuth seul).

   REGLES DURES
   - STRAVA_CLIENT_SECRET n'est JAMAIS renvoye, journalise, ni inclus dans
     un message d'erreur. Seuls des NOMS de variables peuvent apparaitre,
     et uniquement apres authentification par la cle d'appareil.
   - Le refresh token n'est JAMAIS renvoye au client, ni en corps, ni en
     URL, ni en cookie. Il ne vit que dans Netlify Blobs.
   - Fail-closed : si APP_ACCESS_KEY est absente ou trop courte, TOUT est
     refuse. Jamais d'ouverture par defaut.
   ===================================================================== */
const crypto = require('crypto');

const STATE_TTL_MS = 10 * 60 * 1000;   // 10 min
const NONCE_PREFIX = 'oauth-nonce/';
const TOKEN_KEY = 'strava/token';
const STORE_NAME = 'coaching-trail-strava';
const MIN_KEY_LEN = 16;
const HTTP_TIMEOUT_MS = 10000;

/* ---------- comparaison a temps constant, insensible a la longueur ----------
   Le sel aleatoire par processus fait que l'on compare toujours deux
   condensats de 32 octets : ni la longueur ni le contenu ne fuient. */
const CMP_SALT = crypto.randomBytes(32);
function safeEqual(a, b) {
  try {
    const ha = crypto.createHmac('sha256', CMP_SALT).update(String(a == null ? '' : a)).digest();
    const hb = crypto.createHmac('sha256', CMP_SALT).update(String(b == null ? '' : b)).digest();
    return crypto.timingSafeEqual(ha, hb);
  } catch (e) { return false; }
}

function env(name) {
  const v = process.env[name];
  return (typeof v === 'string' && v.trim()) ? v.trim() : '';
}

function siteOrigin() {
  const u = env('URL') || env('DEPLOY_PRIME_URL') || '';
  try { return u ? new URL(u).origin : ''; } catch (e) { return ''; }
}

/* ---------- reponses ---------- */
function baseHeaders() {
  const h = { 'Cache-Control': 'no-store', 'Vary': 'Origin' };
  const o = siteOrigin();
  if (o) {                                   // CORS restreint a l'origine du site
    h['Access-Control-Allow-Origin'] = o;
    h['Access-Control-Allow-Headers'] = 'content-type, x-app-key';
  }
  return h;
}
function json(statusCode, body, extra) {
  return {
    statusCode: statusCode,
    headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, baseHeaders(), extra || {}),
    body: JSON.stringify(body === undefined ? null : body)
  };
}
function preflight(allowed) {
  return {
    statusCode: 204,
    headers: Object.assign({}, baseHeaders(), { 'Access-Control-Allow-Methods': allowed.join(', ') }),
    body: ''
  };
}
function methodNotAllowed(allowed) {
  return json(405, { error: 'method_not_allowed' }, { 'Allow': allowed.join(', ') });
}

/* ---------- cle d'appareil ---------- */
function accessKey() {
  const k = env('APP_ACCESS_KEY');
  return k.length >= MIN_KEY_LEN ? k : '';
}
function headerValue(event, name) {
  const h = (event && event.headers) || {};
  const lower = name.toLowerCase();
  for (const k in h) { if (Object.prototype.hasOwnProperty.call(h, k) && k.toLowerCase() === lower) return h[k]; }
  return '';
}
/* Renvoie null si l'acces est accorde, sinon une reponse deja formee.
   Cle absente, vide ou fausse -> reponse STRICTEMENT identique. */
function checkKey(event) {
  const expected = accessKey();
  if (!expected) {
    console.warn('[strava] APP_ACCESS_KEY absente ou trop courte : acces ferme.');
    return json(503, { error: 'unavailable' });
  }
  if (!safeEqual(headerValue(event, 'x-app-key'), expected)) {
    return json(401, { error: 'unauthorized' });
  }
  return null;
}

/* ---------- state signe (HMAC) ---------- */
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
/* Secret de signature DERIVE de la cle d'appareil : la cle elle-meme ne
   sert jamais directement de cle HMAC. */
function stateSecret(key) {
  return crypto.createHmac('sha256', key).update('strava-oauth-state-v1').digest();
}
function signState(key, nonce, exp) {
  const payload = b64url(JSON.stringify({ n: nonce, e: exp }));
  const sig = b64url(crypto.createHmac('sha256', stateSecret(key)).update(payload).digest());
  return payload + '.' + sig;
}
function parseState(key, state) {
  if (typeof state !== 'string' || !state) return null;
  const i = state.lastIndexOf('.');
  if (i <= 0) return null;
  const payload = state.slice(0, i), sig = state.slice(i + 1);
  const expect = b64url(crypto.createHmac('sha256', stateSecret(key)).update(payload).digest());
  if (!safeEqual(sig, expect)) return null;
  let o;
  try { o = JSON.parse(unb64url(payload)); } catch (e) { return null; }
  if (!o || typeof o.n !== 'string' || !o.n || typeof o.e !== 'number') return null;
  if (Date.now() > o.e) return null;
  return o;
}

/* ---------- stockage (Netlify Blobs) ----------
   `setStoreFactory` est une couture d'injection de dependance, utilisee par
   le banc de test pour substituer un stockage simule. En production elle
   n'est jamais appelee et l'implementation reelle est chargee a la demande. */
let storeFactory = null;
function setStoreFactory(fn) { storeFactory = fn; }
async function getStore() {
  if (storeFactory) return storeFactory(STORE_NAME);
  const mod = await import('@netlify/blobs');
  return mod.getStore({ name: STORE_NAME, consistency: 'strong' });
}
async function readToken() {
  const store = await getStore();
  const v = await store.get(TOKEN_KEY, { type: 'json' });
  return v || null;
}
async function writeToken(obj) {
  const store = await getStore();
  await store.setJSON(TOKEN_KEY, obj);
}
async function deleteToken() {
  const store = await getStore();
  await store.delete(TOKEN_KEY);
}
async function putNonce(nonce, exp) {
  const store = await getStore();
  await store.setJSON(NONCE_PREFIX + nonce, { e: exp });
}
/* Usage unique : la lecture consomme le nonce. Un state rejoue ne trouve
   plus rien et est donc refuse. */
async function takeNonce(nonce) {
  const store = await getStore();
  const k = NONCE_PREFIX + nonce;
  const v = await store.get(k, { type: 'json' });
  if (!v) return null;
  try { await store.delete(k); } catch (e) { /* best effort */ }
  return v;
}

/* ---------- echange du code OAuth ----------
   Aucune valeur de secret dans les erreurs levees ni dans les journaux. */
async function exchangeCode(clientId, clientSecret, code) {
  const ctl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  let timer = null;
  try {
    const guard = new Promise(function (_, reject) {
      timer = setTimeout(function () {
        if (ctl) { try { ctl.abort(); } catch (e) {} }
        reject(new Error('timeout'));
      }, HTTP_TIMEOUT_MS);
    });
    const work = (async function () {
      const res = await fetch('https://www.strava.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code: code,
          grant_type: 'authorization_code'
        }),
        signal: ctl ? ctl.signal : undefined
      });
      if (!res || !res.ok) throw new Error('http_' + (res ? res.status : 'no_response'));
      return await res.json();
    })();
    return await Promise.race([work, guard]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

module.exports = {
  STATE_TTL_MS: STATE_TTL_MS,
  MIN_KEY_LEN: MIN_KEY_LEN,
  safeEqual: safeEqual,
  env: env,
  siteOrigin: siteOrigin,
  json: json,
  preflight: preflight,
  methodNotAllowed: methodNotAllowed,
  accessKey: accessKey,
  checkKey: checkKey,
  signState: signState,
  parseState: parseState,
  setStoreFactory: setStoreFactory,
  readToken: readToken,
  writeToken: writeToken,
  deleteToken: deleteToken,
  putNonce: putNonce,
  takeNonce: takeNonce,
  exchangeCode: exchangeCode
};
