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
   Quatre modes de defaillance a NE PAS confondre :
     - 'module'       : import('@netlify/blobs') a echoue (paquet absent du
       bundle de la fonction).
     - 'lambda'       : aucun contexte Blobs nulle part (ni dans l'event, ni
       dans l'environnement) et aucune configuration explicite. Voir plus bas.
     - 'unconfigured' : le module est la, le contexte semble la, mais
       mod.getStore() refuse d'initialiser le magasin.
     - 'io'           : le magasin existe mais la lecture/ecriture echoue.
   Le client a besoin de cette distinction pour afficher un message honnete.

   MODE DE COMPATIBILITE LAMBDA : ces fonctions sont ecrites en Functions
   API v1 (exports.handler). Dans ce mode le runtime Netlify n'injecte PAS
   NETLIFY_BLOBS_CONTEXT dans l'environnement ; le contexte arrive dans
   l'objet event (event.blobs + en-tetes x-nf-site-id / x-nf-deploy-id).
   Il faut donc appeler mod.connectLambda(event) JUSTE avant mod.getStore().
   C'est pourquoi toutes les fonctions de stockage prennent l'event en
   premier parametre : la dependance est explicite et tracable, aucun etat
   de module mutable ne la porte en douce.

   `setStoreFactory` est une couture d'injection de dependance, utilisee par
   le banc de test pour substituer un stockage simule. En production elle
   n'est jamais appelee et l'implementation reelle est chargee a la demande. */
function StoreError(reason, cause) {
  const e = new Error('store_' + reason);
  e.name = 'StoreError';
  e.reason = reason;                                  // 'module' | 'lambda' | 'unconfigured' | 'io'
  e.causeName = (cause && cause.name) || '';          // NOM seulement, jamais le message
  return e;
}
function isStoreError(e) { return !!e && e.name === 'StoreError'; }

let storeFactory = null;
function setStoreFactory(fn) { storeFactory = fn; }

/* Options du magasin.
   Par defaut : configuration AUTOMATIQUE fournie par le runtime Netlify.
   Si (et seulement si) les deux variables optionnelles sont presentes, on
   bascule en configuration EXPLICITE. Aucune valeur en dur, aucun defaut.
   Enzo n'a a les renseigner que si la configuration automatique echoue :
     NETLIFY_BLOBS_SITE_ID = l'API ID du site (Site configuration > General)
     NETLIFY_BLOBS_TOKEN   = un jeton d'acces personnel Netlify
   `consistency: 'strong'` n'est pas supporte partout : il n'est active que
   si NETLIFY_BLOBS_CONSISTENCY vaut exactement "strong". */
function storeOptions() {
  const opts = { name: STORE_NAME };
  const siteID = env('NETLIFY_BLOBS_SITE_ID');
  const token = env('NETLIFY_BLOBS_TOKEN');
  if (siteID && token) { opts.siteID = siteID; opts.token = token; }
  if (env('NETLIFY_BLOBS_CONSISTENCY') === 'strong') opts.consistency = 'strong';
  return opts;
}
/* Le contexte Blobs est-il present dans l'event Lambda ?
   On teste la PRESENCE de la chaine, jamais son contenu : event.blobs est un
   secret (il porte l'URL et le jeton du magasin). Il ne doit apparaitre dans
   aucun journal, ni brut ni decode. */
function hasLambdaBlobs(event) {
  return !!(event && typeof event.blobs === 'string' && event.blobs);
}
/* Configuration EXPLICITE : les deux variables optionnelles renseignees.
   Elle a la priorite sur le contexte du runtime (cf. getStore). */
function hasExplicitConfig() {
  return !!(env('NETLIFY_BLOBS_SITE_ID') && env('NETLIFY_BLOBS_TOKEN'));
}
/* Un contexte Blobs est-il DEJA dans l'environnement ? Meme detection que la
   bibliotheque (getEnvironmentContext) : la variable globale d'abord, la
   variable d'environnement ensuite. Cas de « netlify dev » en local, ou d'un
   runtime qui injecterait le contexte de lui-meme.
   Meme contrat que la bibliotheque : seule une CHAINE NON VIDE compte. Un
   objet, un tableau ou un nombre ne sont pas un contexte.
   PRESENCE seulement : cette valeur porte un jeton, elle n'est ni lue en
   detail ni journalisee. */
function hasEnvContext() {
  const g = globalThis.netlifyBlobsContext;
  const fromGlobal = (typeof g === 'string') && !!g.trim();
  return fromGlobal || !!env('NETLIFY_BLOBS_CONTEXT');   // env() : chaine non vide, deja trimee
}
/* Etat du contexte d'environnement AU DEMARRAGE DU CONTENEUR, fige avant que
   la moindre invocation ait pu appeler connectLambda.
   POURQUOI : connectLambda() ecrit lui-meme process.env.NETLIFY_BLOBS_CONTEXT
   (setEnvironmentContext). Sur un conteneur chaud, une relecture "live" verrait
   donc une variable posee par NOUS et le journal affirmerait a tort que le
   runtime fournit le contexte — soit l'inverse du diagnostic reel. Seule cette
   photo initiale repond a la question « le runtime nous a-t-il fourni un
   contexte ? ». */
const BOOT_ENV_CONTEXT = hasEnvContext();

/* Ordre de precedence :
     a. couture de test posee            -> on l'utilise telle quelle
     b. configuration explicite presente -> storeOptions() suffit, pas de
        connectLambda (l'explicite gagne)
     c. contexte dans l'event (lambda)   -> connectLambda(event) puis getStore.
        Prioritaire sur (d) : le contexte de l'invocation est le plus frais.
     d. contexte deja dans l'environnement -> getStore direct, sans
        connectLambda. Ne concerne PAS la production en mode Lambda, ou
        NETLIFY_BLOBS_CONTEXT est justement absent ; sert au local.
     e. rien de tout cela                -> StoreError('lambda') */
async function getStore(event) {
  if (storeFactory) {
    try {
      // La couture de test suit exactement le meme chemin que la production :
      // un echec d'obtention du magasin est un echec d'INITIALISATION.
      return storeFactory(STORE_NAME);
    } catch (e) {
      console.error('[strava] initialisation du magasin impossible (fabrique de test) :', (e && e.name) || 'Error');
      throw StoreError('unconfigured', e);
    }
  }

  let mod;
  try {
    mod = await import('@netlify/blobs');
  } catch (e) {
    console.error('[strava] module @netlify/blobs introuvable :', (e && e.name) || 'Error');
    throw StoreError('module', e);
  }

  const explicit = hasExplicitConfig();
  if (!explicit) {
    const hasBlobs = hasLambdaBlobs(event);
    const envNow = hasEnvContext();
    /* Ligne d'INFORMATION (console.log) : un succes ne doit pas remplir les
       journaux Netlify de lignes ERROR, sinon le prochain incident sera
       illisible. Booleens uniquement : jamais la valeur.
       Les deux mesures d'environnement sont distinguees car elles ne disent
       pas la meme chose : « au demarrage » = ce que le runtime a fourni ;
       « maintenant » = ce qui est en place, connectLambda compris. */
    console.log('[strava] contexte blobs | event :', hasBlobs ? 'present' : 'absent',
      '| environnement au demarrage du conteneur :', BOOT_ENV_CONTEXT ? 'present' : 'absent',
      '| environnement maintenant :', envNow ? 'present' : 'absent');
    if (hasBlobs) {
      if (typeof mod.connectLambda !== 'function') {
        console.error('[strava] connectLambda absent du module @netlify/blobs');
        throw StoreError('lambda');
      }
      try {
        mod.connectLambda(event);         // doit preceder immediatement getStore
      } catch (e) {
        console.error('[strava] contexte blobs lambda inexploitable :', (e && e.name) || 'Error');
        throw StoreError('unconfigured', e);
      }
    } else if (!envNow) {
      // Ni event.blobs, ni contexte d'environnement, ni configuration
      // explicite : le magasin ne peut pas etre initialise. Chemin d'echec,
      // donc ERROR assume.
      console.error('[strava] aucun contexte blobs : event absent, environnement au demarrage du conteneur :',
        BOOT_ENV_CONTEXT ? 'present' : 'absent');
      throw StoreError('lambda');
    }
    // else : contexte deja en place, mod.getStore() se debrouille seul.
  }

  try {
    // Cas typique : « The environment has not been configured to use Netlify Blobs ».
    return mod.getStore(storeOptions());
  } catch (e) {
    console.error('[strava] initialisation du magasin impossible :', (e && e.name) || 'Error',
      '| configuration explicite :', explicit ? 'oui' : 'non',
      '| consistency :', env('NETLIFY_BLOBS_CONSISTENCY') || 'defaut');
    throw StoreError('unconfigured', e);
  }
}
/* Enveloppe toute erreur d'E/S en StoreError('io'), en laissant passer les
   StoreError d'initialisation levees par getStore(). */
async function withStore(event, fn) {
  const store = await getStore(event);
  try {
    return await fn(store);
  } catch (e) {
    console.error('[strava] operation de stockage en echec :', (e && e.name) || 'Error');
    throw StoreError('io', e);
  }
}
async function readToken(event) {
  return withStore(event, async function (s) {
    const v = await s.get(TOKEN_KEY, { type: 'json' });
    return v || null;
  });
}
async function writeToken(event, obj) {
  return withStore(event, function (s) { return s.setJSON(TOKEN_KEY, obj); });
}
async function deleteToken(event) {
  return withStore(event, function (s) { return s.delete(TOKEN_KEY); });
}
async function putNonce(event, nonce, exp) {
  return withStore(event, function (s) { return s.setJSON(NONCE_PREFIX + nonce, { e: exp }); });
}
/* Usage unique : la lecture consomme le nonce. Un state rejoue ne trouve
   plus rien et est donc refuse. */
async function takeNonce(event, nonce) {
  return withStore(event, async function (s) {
    const k = NONCE_PREFIX + nonce;
    const v = await s.get(k, { type: 'json' });
    if (!v) return null;
    try { await s.delete(k); } catch (e) { /* best effort */ }
    return v;
  });
}

/* Reponse 503 normalisee : le client doit pouvoir dire « stockage serveur »
   plutot que « hors-ligne ». */
function storeFailure(e) {
  const reason = isStoreError(e) ? e.reason : 'io';
  return json(503, { error: 'blobs', reason: reason });
}

/* Variables d'environnement requises pour le flux OAuth. Renvoie la liste
   des NOMS manquants (jamais de valeur). */
function configMissing() {
  const missing = [];
  if (!env('STRAVA_CLIENT_ID')) missing.push('STRAVA_CLIENT_ID');
  if (!env('STRAVA_CLIENT_SECRET')) missing.push('STRAVA_CLIENT_SECRET');
  if (!siteOrigin()) missing.push('URL');
  return missing;
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
  isStoreError: isStoreError,
  storeFailure: storeFailure,
  configMissing: configMissing,
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
