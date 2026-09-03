'use strict';
/* =====================================================================
   Socle commun aux fonctions Strava (etape A : OAuth seul).

   REGLES DURES
   - STRAVA_CLIENT_SECRET n'est JAMAIS renvoye, journalise, ni inclus dans
     un message d'erreur. Seuls des NOMS de variables peuvent apparaitre,
     et uniquement apres authentification par la cle d'acces.
   - Le refresh token n'est JAMAIS renvoye au client, ni en corps, ni en
     URL, ni en cookie. Il ne vit que dans Netlify Blobs.
   - Fail-closed : sans profil authentifie, TOUT est refuse. Jamais
     d'ouverture par defaut.
   - MULTI-PROFILS (chantier 3, etape 2). Le profil est un RESULTAT de
     l'authentification, JAMAIS une entree fournie par le client. Aucune
     fonction ne lit un identifiant de profil dans une URL, un en-tete, un
     corps ou un cookie : il se deduit de la cle presentee, qui le porte.
     Format de cle : <profil>.<secret>. Un seul en-tete x-app-key suffit, et
     la confusion entre deux profils devient structurellement impossible au
     lieu d'etre verifiee par un test.
   - La cle d'un profil n'est stockee NULLE PART en clair : seuls un sel
     aleatoire et un condensat scrypt vivent dans Blobs. Une cle perdue est
     regeneree, jamais retrouvee.
   - ADMIN_KEY (variable d'environnement) protege la seule fonction
     d'administration. Ce n'est ni un profil, ni une cle d'acces aux donnees.
   ===================================================================== */
const crypto = require('crypto');

const STATE_TTL_MS = 10 * 60 * 1000;   // 10 min
/* Espaces de nommage dans Blobs. TOUT ce qui appartient a un utilisateur est
   range sous un segment de chemin egal a son identifiant de profil. C'est ce
   qui rend l'isolation structurelle et non declarative : sans identifiant de
   profil valide, on ne peut nommer aucune donnee d'utilisateur.
   CHAQUE segment variable d'une cle est REVALIDE ici, au moment de construire
   la cle, et pas seulement a l'entree de la fonction appelante : une
   injection de '/' ou de '..' serait une traversee de chemin. Profil ET
   nonce sont concernes -- un nonce est tout autant un segment de chemin
   qu'un identifiant de profil. Ces barrieres ne dependent d'aucun appelant :
   c'est ce qui rend la promesse d'isolation verifiable en lisant ces trois
   lignes, sans avoir a auditer chaque point d'appel. */
const PROFILE_PREFIX = 'profiles/';
const NONCE_PREFIX = 'oauth-nonce/';
function nonceKey(profileId, nonce) { return NONCE_PREFIX + assertProfileId(profileId) + '/' + assertNonce(nonce); }
function tokenKey(profileId) { return 'strava/' + assertProfileId(profileId) + '/token'; }
const STORE_NAME = 'coaching-trail-strava';
const MIN_KEY_LEN = 16;
const HTTP_TIMEOUT_MS = 10000;
const TOKEN_REFRESH_MARGIN_S = 300;    // marge avant expiration : en deca, on rafraichit
const FALLBACK_TOKEN_TTL_S = 360;      // duree de vie supposee si Strava n'en annonce aucune
const CALL_RESERVE_MS = 750;           // reserve gardee sous l'echeance a chaque appel

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

/* ---------- identifiant de profil ----------
   Alphabet STRICT et longueur bornee. Cet identifiant sert de segment de
   chemin dans Blobs et de prefixe de cle : il ne doit jamais pouvoir porter
   '/', '.', '..', d'espace, de majuscule ni d'unicode.
   Il est aussi la partie gauche de la cle d'acces, avant le separateur '.' :
   c'est pourquoi '.' est exclu de l'alphabet.
   Sont refuses par construction : '__proto__' (underscore hors alphabet), la
   chaine vide, les chaines trop longues. */
const PROFILE_ID_RE = /^[a-z0-9][a-z0-9-]{1,23}$/;
const PROFILE_ID_MAX = 24;
function isProfileId(v) {
  if (typeof v !== 'string' || v.length > PROFILE_ID_MAX || !PROFILE_ID_RE.test(v)) return false;
  /* 'constructor' passe l'alphabet mais est un nom de propriete d'Object.prototype :
     un identifiant pareil, employe un jour comme cle d'un objet nu, donnerait une
     valeur heritee la ou on attend 'absent'. On refuse a la SOURCE plutot que de
     compter sur chaque futur appelant. ('__proto__' et 'toString' sont deja hors
     alphabet : underscore et majuscule.) */
  if (Object.prototype.hasOwnProperty.call(Object.prototype, v)) return false;
  return true;
}
/* Derniere barriere avant toute construction de cle de stockage. Leve plutot
   que de renvoyer une valeur : un identifiant invalide ne doit JAMAIS aboutir
   a une lecture ou une ecriture, meme degradee. Le message ne porte pas la
   valeur fautive. */
function assertProfileId(v) {
  if (!isProfileId(v)) throw new Error('bad_profile_id');
  return v;
}

/* ---------- nonce OAuth ----------
   Meme raisonnement que pour l'identifiant de profil : le nonce est un
   SEGMENT DE CHEMIN dans Blobs, sa forme est donc contrainte au point de
   construction de la cle, et pas seulement chez l'appelant.
   Aujourd'hui auth-start tire 18 octets aleatoires rendus en hexadecimal (36
   caracteres) et parseStatePayload impose deja le meme motif. Cette borne-ci
   existe pour que la garantie tienne encore si l'un des deux venait a
   changer : c'est la seule qu'on puisse verifier sans quitter ce fichier. */
const NONCE_RE = /^[0-9a-f]{16,64}$/;
function isNonce(v) { return typeof v === 'string' && NONCE_RE.test(v); }
function assertNonce(v) {
  if (!isNonce(v)) throw new Error('bad_nonce');       // jamais la valeur
  return v;
}

/* ---------- cle d'acces d'un profil ----------
   Format : <profil>.<secret>. Le secret est encode dans un alphabet sans
   ambiguite visuelle (Crockford base32 en minuscules : ni i, ni l, ni o, ni
   u), pour qu'une cle recopiee a la main ne soit pas fausse a cause d'un 1
   lu pour un l.
   parseAppKey ne fait AUCUN acces reseau ni disque : elle decoupe et valide
   la forme, rien de plus. */
const SECRET_ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';   // 32 symboles
const SECRET_BYTES = 32;                                      // 256 bits
const SECRET_MIN_LEN = 32;
const SECRET_MAX_LEN = 128;
const SECRET_RE = /^[0-9abcdefghjkmnpqrstvwxyz]+$/;

function encodeSecret(buf) {
  let out = '', acc = 0, bits = 0;
  for (let i = 0; i < buf.length; i++) {
    acc = (acc * 256) + buf[i]; bits += 8;
    while (bits >= 5) { bits -= 5; out += SECRET_ALPHABET[Math.floor(acc / Math.pow(2, bits)) & 31]; acc = acc % Math.pow(2, bits); }
  }
  if (bits > 0) out += SECRET_ALPHABET[(acc * Math.pow(2, 5 - bits)) & 31];
  return out;
}
function generateSecret() { return encodeSecret(crypto.randomBytes(SECRET_BYTES)); }

/* Decoupe sur le PREMIER '.' : ni l'identifiant ni le secret ne peuvent en
   contenir. Renvoie null des que la forme n'est pas exacte. */
function parseAppKey(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v || v.length < MIN_KEY_LEN || v.length > (PROFILE_ID_MAX + 1 + SECRET_MAX_LEN)) return null;
  const i = v.indexOf('.');
  if (i <= 0) return null;
  const id = v.slice(0, i), secret = v.slice(i + 1);
  if (!isProfileId(id)) return null;
  if (secret.length < SECRET_MIN_LEN || secret.length > SECRET_MAX_LEN) return null;
  if (!SECRET_RE.test(secret)) return null;
  return { id: id, secret: secret };
}

/* ---------- condensat de la cle ----------
   scrypt, sel aleatoire par profil, parametres STOCKES avec le condensat pour
   qu'un durcissement futur n'invalide pas les profils existants.
   La cle en clair n'existe qu'en memoire, le temps du calcul. */
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, len: 32 };
const SALT_BYTES = 16;
/* Bornes de securite A LA RELECTURE : un document corrompu ou trafique ne
   doit pas pouvoir commander une allocation memoire deraisonnable. */
function sanitizeParams(o) {
  const src = (o && typeof o === 'object') ? o : {};
  const N = Number(src.N), r = Number(src.r), pp = Number(src.p), len = Number(src.len);
  const ok = Number.isInteger(N) && N >= 1024 && N <= 262144 && (N & (N - 1)) === 0
    && Number.isInteger(r) && r >= 1 && r <= 32
    && Number.isInteger(pp) && pp >= 1 && pp <= 16
    && Number.isInteger(len) && len >= 16 && len <= 64;
  return ok ? { N: N, r: r, p: pp, len: len } : null;
}
function scryptHash(secret, saltB64, params) {
  return new Promise(function (resolve, reject) {
    if (!params) return reject(new Error('bad_params'));
    let salt;
    try { salt = Buffer.from(String(saltB64), 'base64'); } catch (e) { return reject(new Error('bad_salt')); }
    if (!salt.length) return reject(new Error('bad_salt'));
    const opts = { N: params.N, r: params.r, p: params.p, maxmem: 256 * params.N * params.r };
    crypto.scrypt(String(secret), salt, params.len, opts, function (err, dk) {
      if (err) return reject(err);
      resolve(dk.toString('base64'));
    });
  });
}
/* Materiel de hachage neuf pour un profil : sel aleatoire + parametres du
   jour. Ne renvoie jamais le secret. */
async function hashSecret(secret) {
  const salt = crypto.randomBytes(SALT_BYTES).toString('base64');
  const params = { N: SCRYPT_PARAMS.N, r: SCRYPT_PARAMS.r, p: SCRYPT_PARAMS.p, len: SCRYPT_PARAMS.len };
  const hash = await scryptHash(secret, salt, params);
  return { alg: 'scrypt', params: params, salt: salt, hash: hash };
}
/* Leurre de temps : quand le profil n'existe pas, on depense QUAND MEME le
   cout d'un scrypt. Sans cela, la duree de reponse distinguerait « profil
   inconnu » de « cle fausse » et offrirait un oracle d'enumeration des
   profils sur un site public. Le sel est tire au demarrage du conteneur et
   ne correspond a aucun profil. */
const DECOY = {
  salt: crypto.randomBytes(SALT_BYTES).toString('base64'),
  params: { N: SCRYPT_PARAMS.N, r: SCRYPT_PARAMS.r, p: SCRYPT_PARAMS.p, len: SCRYPT_PARAMS.len }
};
async function burnHash(secret) {
  try { await scryptHash(secret || 'x', DECOY.salt, DECOY.params); } catch (e) { /* seul le cout compte */ }
}

/* ---------- documents de profil (Netlify Blobs) ----------
   Forme EXACTE du document range sous 'profiles/<id>' :
     { v:1, id, name, alg:'scrypt', params:{N,r,p,len}, salt, hash,
       created_at, rotated_at, active }
   'salt' et 'hash' sont en base64 et ne sortent JAMAIS de ce module : ni
   dans une reponse, ni dans un journal, ni dans une URL. publicProfile() est
   la SEULE projection autorisee vers l'exterieur. */
function publicProfile(prof) {
  if (!prof) return null;
  return {
    id: prof.id,
    name: (typeof prof.name === 'string') ? prof.name : '',
    created_at: (typeof prof.created_at === 'string') ? prof.created_at : '',
    rotated_at: (typeof prof.rotated_at === 'string') ? prof.rotated_at : '',
    active: prof.active !== false
  };
}
function validProfileDoc(o) {
  return !!(o && typeof o === 'object'
    && isProfileId(o.id)
    && typeof o.salt === 'string' && o.salt
    && typeof o.hash === 'string' && o.hash
    && o.alg === 'scrypt'
    && sanitizeParams(o.params));
}
async function readProfile(event, profileId) {
  if (!isProfileId(profileId)) return null;
  const doc = await withStore(event, async function (st) {
    return await st.get(PROFILE_PREFIX + profileId, { type: 'json' });
  });
  if (!validProfileDoc(doc)) return null;
  /* L'identifiant PORTE PAR LE DOCUMENT doit coincider avec celui du chemin :
     un document copie sous un autre chemin ne doit pas pouvoir se faire
     passer pour un autre profil. */
  if (doc.id !== profileId) return null;
  return doc;
}
async function writeProfile(event, doc) {
  assertProfileId(doc && doc.id);
  return withStore(event, function (st) { return st.setJSON(PROFILE_PREFIX + doc.id, doc); });
}
async function listProfiles(event) {
  const keys = await withStore(event, async function (st) {
    const res = await st.list({ prefix: PROFILE_PREFIX });
    const blobs = (res && Array.isArray(res.blobs)) ? res.blobs : [];
    return blobs.map(function (b) { return String((b && b.key) || ''); });
  });
  const out = [];
  for (let i = 0; i < keys.length; i++) {
    const id = keys[i].slice(PROFILE_PREFIX.length);
    if (!isProfileId(id)) continue;              // cle parasite : ignoree
    const doc = await readProfile(event, id);
    if (doc) out.push(publicProfile(doc));
  }
  out.sort(function (a, b) { return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0); });
  return out;
}

function headerValue(event, name) {
  const h = (event && event.headers) || {};
  const lower = name.toLowerCase();
  for (const k in h) { if (Object.prototype.hasOwnProperty.call(h, k) && k.toLowerCase() === lower) return h[k]; }
  return '';
}
/* Authentification par cle de profil.
   Renvoie TOUJOURS un objet : { denied: <reponse>, profile: null } ou
   { denied: null, profile: <document> }.
   L'appelant fait « const auth = await C.checkKey(event); if (auth.denied)
   return auth.denied; » puis n'utilise QUE auth.profile.id pour nommer ses
   donnees. Il ne lit jamais d'identifiant de profil ailleurs.

   INDISCERNABILITE. Cle absente, malformee, profil inexistant, cle fausse et
   profil desactive produisent la MEME reponse (401 { error:'unauthorized' })
   et, autant que le permet un runtime partage, le meme temps de calcul : un
   scrypt est depense meme quand le profil n'existe pas, et la desactivation
   n'est examinee qu'APRES la verification. Sans cela, un site public
   offrirait un oracle d'enumeration des profils.
   Seule une panne de stockage se distingue (503 blobs) : elle ne dit rien
   d'un profil en particulier. */
async function checkKey(event) {
  const DENY = { denied: json(401, { error: 'unauthorized' }), profile: null };
  const parsed = parseAppKey(headerValue(event, 'x-app-key'));

  let prof = null;
  try {
    prof = parsed ? await readProfile(event, parsed.id) : null;
  } catch (e) {
    // Panne de stockage : on ne peut ni accorder l'acces, ni le refuser en
    // connaissance de cause. Fail-closed, mais avec le bon diagnostic.
    console.error('[strava] lecture du profil impossible | motif :', (isStoreError(e) && e.reason) || 'io');
    return { denied: storeFailure(e), profile: null };
  }

  if (!parsed || !prof) {
    await burnHash(parsed ? parsed.secret : '');
    return DENY;
  }

  let computed = '';
  try {
    computed = await scryptHash(parsed.secret, prof.salt, sanitizeParams(prof.params));
  } catch (e) {
    console.error('[strava] verification de cle impossible :', (e && e.name) || 'Error');
    return DENY;
  }
  // Comparaison a temps constant : jamais ===.
  if (!safeEqual(computed, prof.hash)) return DENY;
  // Un profil desactive est refuse EXACTEMENT comme une cle fausse.
  if (prof.active === false) return DENY;

  return { denied: null, profile: prof };
}

/* Garde de la fonction d'administration. ADMIN_KEY est une variable
   d'environnement, distincte de toute cle de profil : elle ne donne acces a
   aucune donnee d'utilisateur, seulement a la gestion des profils.
   Fail-closed : absente ou trop courte -> tout est refuse, exactement comme
   le faisait checkKey avant le multi-profils. */
function checkAdminKey(event) {
  const expected = env('ADMIN_KEY');
  if (expected.length < MIN_KEY_LEN) {
    console.warn('[strava] ADMIN_KEY absente ou trop courte : administration fermee.');
    return json(503, { error: 'unavailable' });
  }
  if (!safeEqual(headerValue(event, 'x-admin-key'), expected)) {
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
/* Secret de signature DERIVE du materiel de hachage du PROFIL (condensat +
   sel). Trois consequences voulues :
     - il n'existe pas de secret global : chaque profil signe avec le sien,
       donc personne ne peut forger un state au nom d'un autre profil ;
     - ce materiel ne quitte jamais le serveur (il n'est ni renvoye, ni
       journalise), contrairement a la cle d'acces qui, elle, est detenue par
       l'utilisateur ;
     - une rotation de cle invalide les states en vol de ce profil. C'est
       souhaitable, et sans consequence : leur TTL est de 10 minutes.
   Le condensat n'est jamais utilise tel quel comme cle HMAC : il passe par
   cette derivation, avec l'identifiant du profil dans le message. */
function stateSecret(prof) {
  const material = Buffer.concat([
    Buffer.from(String(prof.hash), 'base64'),
    Buffer.from(String(prof.salt), 'base64')
  ]);
  return crypto.createHmac('sha256', material).update('strava-oauth-state-v1|' + prof.id).digest();
}
/* Le state PORTE le profil (champ p) et la signature le scelle : auth-callback
   n'a pas d'en-tete a sa disposition, c'est donc le seul lien possible entre
   la redirection et le profil qui a initie la demande. Le profil reste un
   RESULTAT : il n'est retenu qu'une fois la signature verifiee avec le secret
   de ce profil-la. */
function signState(prof, nonce, exp) {
  const payload = b64url(JSON.stringify({ p: prof.id, n: nonce, e: exp }));
  const sig = b64url(crypto.createHmac('sha256', stateSecret(prof)).update(payload).digest());
  return payload + '.' + sig;
}
/* Lecture NON AUTHENTIFIEE du state : sert uniquement a savoir QUEL document
   de profil charger pour pouvoir verifier la signature. Sa sortie n'autorise
   rien ; l'identifiant y est valide par isProfileId avant tout usage comme
   segment de chemin. Le nonce est contraint a de l'hexadecimal borne : il
   sert lui aussi de segment de cle de stockage. */
function parseStatePayload(state) {
  if (typeof state !== 'string' || !state || state.length > 1024) return null;
  const i = state.lastIndexOf('.');
  if (i <= 0) return null;
  let o;
  try { o = JSON.parse(unb64url(state.slice(0, i))); } catch (e) { return null; }
  if (!o || typeof o !== 'object') return null;
  if (!isProfileId(o.p)) return null;
  if (typeof o.n !== 'string' || !/^[0-9a-f]{16,64}$/.test(o.n)) return null;
  if (typeof o.e !== 'number' || !Number.isFinite(o.e)) return null;
  return { p: o.p, n: o.n, e: o.e };
}
/* Verification COMPLETE : signature par le secret du profil presume, puis
   coherence du contenu et expiration. Renvoie le payload ou null.
   Un state signe par le profil A et presente avec le document du profil B
   echoue a la signature ; un state dont le champ p ne correspond pas au
   document echoue au controle de coherence. Les deux verrous sont voulus. */
function parseState(prof, state) {
  if (!prof || !prof.id) return null;
  const o = parseStatePayload(state);
  if (!o) return null;
  if (o.p !== prof.id) return null;
  const i = state.lastIndexOf('.');
  const payload = state.slice(0, i), sig = state.slice(i + 1);
  const expect = b64url(crypto.createHmac('sha256', stateSecret(prof)).update(payload).digest());
  if (!safeEqual(sig, expect)) return null;
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
/* ISOLATION. Toutes ces fonctions prennent l'identifiant de profil en second
   parametre, et tokenKey/nonceKey REVALIDENT chaque segment variable -- le
   profil, et le nonce -- avant d'en faire un morceau de chemin. La cle est
   construite AVANT d'entrer dans withStore : un segment refuse leve donc
   sans qu'aucun acces au magasin ait eu lieu.
   Il n'existe aucun chemin de code capable de lire ou d'ecrire sans nommer
   un profil valide : l'isolation ne repose pas sur la discipline des
   appelants. */
async function readToken(event, profileId) {
  const k = tokenKey(profileId);
  return withStore(event, async function (s) {
    const v = await s.get(k, { type: 'json' });
    return v || null;
  });
}
async function writeToken(event, profileId, obj) {
  const k = tokenKey(profileId);
  return withStore(event, function (s) { return s.setJSON(k, obj); });
}
async function deleteToken(event, profileId) {
  const k = tokenKey(profileId);
  return withStore(event, function (s) { return s.delete(k); });
}
/* Le nonce est range SOUS le profil, et le document porte lui aussi son
   identifiant : meme si deux profils tiraient le meme nonce, ils ne se
   marcheraient pas dessus, et un callback ne peut pas consommer le nonce
   d'un autre. */
async function putNonce(event, profileId, nonce, exp) {
  const k = nonceKey(profileId, nonce);
  const id = profileId;
  return withStore(event, function (s) { return s.setJSON(k, { e: exp, p: id }); });
}
/* ---------- purge des nonces abandonnes ----------
   POURQUOI. Un « Connecter Strava » qu'on n'acheve pas laisse un nonce
   derriere lui. Rien ne le relisait ni ne le supprimait passe sa TTL : la
   croissance etait monotone. Ce n'est pas un probleme de securite -- la
   consommation verifie l'expiration, un nonce perime est refuse -- c'est un
   espace qui ne se libere jamais.

   COMMENT. Balayage opportuniste declenche par auth-start, STRICTEMENT BORNE
   sur trois axes A LA FOIS : entrees examinees, suppressions, et temps. Une
   connexion Strava ne doit jamais devenir une operation longue ; le premier
   des trois plafonds atteint arrete tout.

   TROIS REGLES DE PRUDENCE, par ordre d'importance :
     1. On ne supprime JAMAIS un nonce encore valide. La comparaison porte
        sur l'expiration RELUE dans le document, augmentee d'une marge : un
        nonce qui expire pendant qu'un callback est en vol survit un tour.
     2. On ne supprime jamais ce qu'on ne comprend pas. Document illisible,
        expiration absente ou non numerique -> on passe. Une entree orpheline
        coute moins cher qu'une suppression a l'aveugle.
     3. Le balayage ne sort pas de l'espace du profil appelant : la liste est
        prefixee, ET chaque cle est re-verifiee contre ce prefixe avant tout
        acces. Aucune lecture croisee, meme si le magasin repondait autre
        chose que ce qu'on lui a demande.
   La fonction ne LEVE JAMAIS : elle rend un compte rendu de nombres. Une
   purge en echec est un non-evenement, jamais un echec de connexion. */
const NONCE_SWEEP_MAX_SCAN = 25;        // entrees examinees au plus
const NONCE_SWEEP_MAX_DELETE = 10;      // suppressions au plus
const NONCE_SWEEP_BUDGET_MS = 1200;     // temps consacre au plus
const NONCE_SWEEP_GRACE_MS = 60 * 1000; // marge au-dela de l'expiration
async function sweepExpiredNonces(event, profileId, nowMs) {
  const res = { scanned: 0, deleted: 0, halted: false };
  try {
    const prefix = NONCE_PREFIX + assertProfileId(profileId) + '/';
    const start = Number.isFinite(nowMs) ? nowMs : Date.now();
    const until = start + NONCE_SWEEP_BUDGET_MS;
    await withStore(event, async function (st) {
      const listed = await st.list({ prefix: prefix });
      const blobs = (listed && Array.isArray(listed.blobs)) ? listed.blobs : [];
      for (let i = 0; i < blobs.length; i++) {
        if (res.scanned >= NONCE_SWEEP_MAX_SCAN
          || res.deleted >= NONCE_SWEEP_MAX_DELETE
          || Date.now() > until) { res.halted = true; break; }
        const key = String((blobs[i] && blobs[i].key) || '');
        // Regle 3 : jamais un octet hors de l'espace du profil appelant.
        if (key.indexOf(prefix) !== 0) continue;
        if (!isNonce(key.slice(prefix.length))) continue;
        res.scanned++;
        let v = null;
        try { v = await st.get(key, { type: 'json' }); } catch (e) { continue; }
        // Regle 2 : on ne supprime pas ce qu'on ne comprend pas.
        if (!v || typeof v.e !== 'number' || !Number.isFinite(v.e)) continue;
        // Regle 1 : jamais un nonce encore valide, marge comprise.
        if (Date.now() <= (v.e + NONCE_SWEEP_GRACE_MS)) continue;
        try { await st.delete(key); res.deleted++; } catch (e) { /* best effort */ }
      }
    });
  } catch (e) {
    // Panne de stockage, identifiant refuse, reponse inattendue : sans
    // consequence. Le NOM du motif seul, jamais une cle ni une valeur.
    res.halted = true;
    console.warn('[strava] purge des nonces interrompue :', (isStoreError(e) && e.reason) || (e && e.name) || 'Error');
  }
  return res;
}

/* Usage unique : la lecture consomme le nonce. Un state rejoue ne trouve
   plus rien et est donc refuse. */
async function takeNonce(event, profileId, nonce) {
  const k = nonceKey(profileId, nonce);
  const id = profileId;
  return withStore(event, async function (s) {
    const v = await s.get(k, { type: 'json' });
    if (!v) return null;
    try { await s.delete(k); } catch (e) { /* best effort */ }
    // Controle de coherence : le nonce doit appartenir au profil demande.
    if (v.p !== id) return null;
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

/* Variables requises pour un simple appel d'API (lecture des activites) :
   ni redirection, ni URL de site. Une URL mal renseignee ne doit pas
   casser une fonction qui n'en depend pas. */
function configMissingApi() {
  const missing = [];
  if (!env('STRAVA_CLIENT_ID')) missing.push('STRAVA_CLIENT_ID');
  if (!env('STRAVA_CLIENT_SECRET')) missing.push('STRAVA_CLIENT_SECRET');
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

/* ---------- erreurs Strava ----------
   Une panne d'API n'est pas une panne de stockage : motifs separes, pour que
   le client puisse dire la verite a Enzo.
     'reauth'       : Strava refuse le refresh token (400/401). Revoque ou
                      perime cote Strava -> il faut se reconnecter. Le jeton
                      stocke n'est PAS supprime : c'est a l'utilisateur de
                      decider (auth-logout).
     'quota'        : 429. Strava limite a 100 requetes / 15 min et 1000 / jour.
     'timeout'      : pas de reponse dans HTTP_TIMEOUT_MS.
     'network'      : fetch a rejete (DNS, TLS, coupure).
     'upstream'     : autre code HTTP non 2xx.
     'bad_response' : reponse 2xx mais corps inexploitable ou incomplet.
     'config'       : identifiants d application absents cote serveur.
     'token_lost'   : le jeton renouvele n'a pas pu etre persiste (deux
                      tentatives). Le refresh token ayant tourne, la
                      connexion est perdue : reconnexion necessaire.
   Aucun de ces objets ne porte de valeur de secret : ni message d'origine,
   ni corps de reponse. Seulement un motif et un code HTTP. */
function StravaError(reason, status) {
  const e = new Error('strava_' + reason);
  e.name = 'StravaError';
  e.reason = reason;
  e.status = Number(status) || 0;
  return e;
}
function isStravaError(e) { return !!e && e.name === 'StravaError'; }

/* Plafond de temps d'UN appel reseau, sous l'echeance globale.

   POURQUOI UNE RESERVE. Si le plafond par appel valait exactement le budget
   restant, un appel qui PEND consommerait tout : a la reprise il ne resterait
   jamais de temps, et une panne de Strava serait etiquetee « budget epuise ».
   Deux incidents differents recevraient le meme diagnostic, et le mauvais :
   Enzo reduirait la fenetre de jours, ce qui ne changerait rien.
   En gardant CALL_RESERVE_MS de cote, un appel qui pend expire alors qu'il
   RESTE du temps -- l'appelant peut donc conclure « Strava n'a pas repondu »
   et non « je manque de temps ».

   L'echeance globale reste un plafond ABSOLU : ce calcul ne fait que rester
   strictement en dessous, il ne la repousse jamais.

   Sans echeance (appel hors invocation bornee), HTTP_TIMEOUT_MS s'applique.
   Resultat <= 0 : il ne reste pas de quoi tenter l'appel, l'appelant doit
   echouer immediatement SANS toucher au reseau. */
function callTimeout(deadline, nowMs) {
  if (!Number.isFinite(deadline)) return HTTP_TIMEOUT_MS;
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  return Math.min(HTTP_TIMEOUT_MS, (deadline - now) - CALL_RESERVE_MS);
}

/* Appel HTTP JSON vers Strava, calque sur exchangeCode : meme AbortController,
   meme Promise.race, meme classification.
   `reauthStatuses` varie selon le point d'appel : sur /oauth/token un 400 est
   un refresh token refuse, alors que sur /athlete/activities un 400 est une
   requete mal formee (donc 'upstream', pas une invitation a se reconnecter).
   `deadline` (millisecondes epoch, optionnel) est l'ECHEANCE GLOBALE de
   l'invocation. Sans elle, trois appels de 10 s tiendraient dans une seule
   invocation et la plate-forme couperait AVANT nous -- en renvoyant du HTML,
   donc hors du contrat JSON. Le plafond effectif est calcule par
   callTimeout() : strictement sous le temps restant, reserve comprise.
   Plus de quoi tenter l'appel -> echec immediat, sans toucher au reseau. */
async function stravaJson(url, init, reauthStatuses, deadline) {
  const reauth = Array.isArray(reauthStatuses) ? reauthStatuses : [401];
  const ms = callTimeout(deadline);
  if (!(ms > 0)) throw StravaError('timeout', 0);

  const ctl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  let timer = null;
  try {
    const guard = new Promise(function (_, reject) {
      timer = setTimeout(function () {
        if (ctl) { try { ctl.abort(); } catch (e) {} }
        reject(StravaError('timeout', 0));
      }, ms);
    });
    const work = (async function () {
      let res;
      try {
        res = await fetch(url, Object.assign({}, init || {}, { signal: ctl ? ctl.signal : undefined }));
      } catch (e) {
        // Le message d'origine peut contenir l'URL : on ne garde que le nom.
        throw StravaError('network', 0);
      }
      if (!res) throw StravaError('network', 0);
      if (!res.ok) {
        const st = Number(res.status) || 0;
        if (st === 429) throw StravaError('quota', st);
        if (reauth.indexOf(st) !== -1) throw StravaError('reauth', st);
        throw StravaError('upstream', st);
      }
      let data;
      try { data = await res.json(); } catch (e) { throw StravaError('bad_response', 0); }
      return data;
    })();
    return await Promise.race([work, guard]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/* ---------- rafraichissement du jeton d'acces ----------
   Le refresh token ne sort d'ici que vers Strava, dans le corps d'un POST.
   Il n'est ni journalise, ni renvoye, ni place dans une URL. */
async function refreshAccessToken(clientId, clientSecret, refreshTokenValue, deadline) {
  return stravaJson('https://www.strava.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshTokenValue
    })
  }, [400, 401], deadline);
}

/* Le jeton d'acces stocke est-il utilisable tel quel ?
   Marge de TOKEN_REFRESH_MARGIN_S : un jeton qui expire dans 30 s serait
   perime au milieu de la pagination. */
function accessTokenIsFresh(token, nowSec) {
  if (!token) return false;
  if (typeof token.access_token !== 'string' || !token.access_token) return false;
  const exp = Number(token.expires_at);
  if (!Number.isFinite(exp) || exp <= 0) return false;
  const now = Number.isFinite(nowSec) ? nowSec : Math.floor(Date.now() / 1000);
  return (exp - now) > TOKEN_REFRESH_MARGIN_S;
}

/* Date d'expiration a partir d'une reponse de Strava.
   Strava envoie expires_at ET expires_in ; on accepte l'un ou l'autre, et a
   defaut on SOUS-ESTIME volontairement (FALLBACK_TOKEN_TTL_S).
   POURQUOI ne jamais echouer ici : le refresh token vient d'etre consomme
   cote Strava. Refuser d'ecrire pour une expiration manquante jetterait un
   jeton neuf et deconnecterait Enzo. Une expiration sous-estimee ne coute
   qu'un rafraichissement de plus. */
function deriveExpiry(data, nowSec) {
  const at = data ? Number(data.expires_at) : NaN;
  if (Number.isFinite(at) && at > nowSec) return Math.floor(at);
  const inS = data ? Number(data.expires_in) : NaN;
  if (Number.isFinite(inS) && inS > 0) return nowSec + Math.floor(inS);
  return nowSec + FALLBACK_TOKEN_TTL_S;
}
/* Garantit un jeton d'acces valide, et PERSISTE avant de rendre la main.

   ORDRE IMPERATIF -- ne jamais reordonner :
     1. rafraichir aupres de Strava
     2. ecrire le jeton complet dans Blobs (avec UNE seconde tentative)
     3. seulement ensuite l'appelant peut interroger l'API
   Strava FAIT TOURNER le refresh token : la reponse peut en contenir un
   NOUVEAU, et l'ancien devient invalide des qu'il a servi.

   DEUX ECHECS D'ECRITURE DIFFERENTS, a ne pas confondre :
     - le refresh token est INCHANGE -> la base reste valable, on n'a perdu
       qu'un access token. La StoreError est propagee telle quelle et
       l'appelant repond storeFailure : c'est bien une panne de stockage.
     - le refresh token a TOURNE et les deux ecritures echouent -> avant de
       conclure, UNE relecture de controle. Une ecriture peut avoir abouti et
       n'avoir echoue qu'a l'accuse de reception ; annoncer une connexion
       morte ferait refaire une reconnexion inutile.
         . la base porte deja le nouveau refresh token -> l'ecriture avait
           abouti, on continue avec le contenu RELU (qui fait foi).
         . la base ne l'a pas, OU la relecture echoue -> StravaError
           ('token_lost') : le client doit dire « reconnecte Strava », pas
           « le stockage est en panne ». Conservateur par choix : une
           reconnexion inutile coute moins qu'une connexion morte ignoree.
   Sauf relecture concluante, on s'arrete : l'appelant n'interroge pas l'API.

   Les champs existants (athlete_id, scope, connected_at) sont conserves par
   recopie de l'objet : connected_at reste la date de la PREMIERE connexion,
   sinon l'app afficherait une fausse anciennete. */
async function ensureAccessToken(event, profileId, token, deadline) {
  if (!token || typeof token.refresh_token !== 'string' || !token.refresh_token) {
    throw StravaError('reauth', 0);
  }
  if (accessTokenIsFresh(token)) {
    return { token: token, access_token: token.access_token, refreshed: false };
  }

  const clientId = env('STRAVA_CLIENT_ID');
  const clientSecret = env('STRAVA_CLIENT_SECRET');
  if (!clientId || !clientSecret) {
    console.warn('[strava] identifiants d application absents : rafraichissement impossible.');
    throw StravaError('config', 0);
  }

  const data = await refreshAccessToken(clientId, clientSecret, token.refresh_token, deadline);
  const access = (data && typeof data.access_token === 'string' && data.access_token) ? data.access_token : '';
  if (!access) {
    // SEUL cas d'echec : sans access token il n'y a rien d'exploitable.
    console.error('[strava] reponse de rafraichissement sans jeton d acces');
    throw StravaError('bad_response', 0);
  }
  // refresh_token absent de la reponse -> on garde celui de la base. Ne rien
  // ecrire l'y laisserait de toute facon : ecrire est strictement meilleur,
  // on gagne un access token valide.
  const nextRefresh = (data && typeof data.refresh_token === 'string' && data.refresh_token)
    ? data.refresh_token : token.refresh_token;
  const rotated = nextRefresh !== token.refresh_token;

  const next = Object.assign({}, token, {
    access_token: access,
    refresh_token: nextRefresh,             // le NOUVEAU des que Strava en donne un
    expires_at: deriveExpiry(data, Math.floor(Date.now() / 1000))
  });

  // Ecriture, avec UNE seule reprise immediate.
  try {
    await writeToken(event, profileId, next);
  } catch (e1) {
    console.error('[strava] ecriture du jeton en echec | motif :', (isStoreError(e1) && e1.reason) || 'io',
      '| refresh token renouvele :', rotated ? 'oui' : 'non', '| seconde tentative');
    try {
      await writeToken(event, profileId, next);
    } catch (e2) {
      if (!rotated) throw e2;                 // base intacte : vraie panne de stockage

      /* ACCUSE PERDU : l'ecriture peut avoir ABOUTI et n'avoir echoue qu'a
         l'accuse de reception. Declarer la connexion morte sans verifier
         ferait refaire a Enzo une reconnexion parfaitement inutile.
         UNE seule relecture de controle, jamais de boucle. */
      let stored = null, readOk = false;
      try {
        stored = await readToken(event, profileId);
        readOk = true;
      } catch (e3) {
        // La relecture ne doit pas masquer le motif d'origine : on note son
        // echec et on retombe sur le cas conservateur ci-dessous.
        console.error('[strava] relecture de controle impossible :', (isStoreError(e3) && e3.reason) || 'io');
      }
      const persisted = !!(readOk && stored && stored.refresh_token === nextRefresh);
      if (!persisted) {
        // Base pas a jour, ou relecture en echec : dans le doute on reste
        // conservateur. Une reconnexion inutile coute moins qu'une connexion
        // morte ignoree.
        console.error('[strava] jeton renouvele NON persiste (verifie) : la connexion Strava est perdue',
          '| relecture :', readOk ? 'aboutie' : 'en echec');
        throw StravaError('token_lost', 0);
      }
      /* La base porte bien le jeton neuf : l'ecriture avait abouti. On
         continue avec le contenu RELU, qui fait foi -- si une invocation
         concurrente a ecrit un autre access token, c'est le sien qui est
         valide, pas celui qu'on avait en main. */
      const storedAccess = (typeof stored.access_token === 'string' && stored.access_token)
        ? stored.access_token : access;
      console.warn('[strava] ecriture signalee en echec mais base a jour : on continue');
      return { token: stored, access_token: storedAccess, refreshed: true };
    }
  }
  // Booleens uniquement : aucune valeur de jeton dans les journaux.
  console.log('[strava] jeton rafraichi | refresh token renouvele par Strava :', rotated ? 'oui' : 'non');
  return { token: next, access_token: access, refreshed: true };
}

/* ---------- lecture des activites ----------
   Le jeton d'acces voyage dans l'en-tete Authorization, jamais dans l'URL
   (une URL finit dans les journaux d'acces). */
async function fetchActivitiesPage(accessToken, afterEpoch, page, perPage, deadline) {
  const url = 'https://www.strava.com/api/v3/athlete/activities'
    + '?after=' + encodeURIComponent(String(afterEpoch))
    + '&per_page=' + encodeURIComponent(String(perPage))
    + '&page=' + encodeURIComponent(String(page));
  return stravaJson(url, {
    method: 'GET',
    headers: { 'Authorization': 'Bearer ' + accessToken, 'Accept': 'application/json' }
  }, [401], deadline);
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
  checkKey: checkKey,
  checkAdminKey: checkAdminKey,
  isProfileId: isProfileId,
  parseAppKey: parseAppKey,
  generateSecret: generateSecret,
  hashSecret: hashSecret,
  publicProfile: publicProfile,
  readProfile: readProfile,
  writeProfile: writeProfile,
  listProfiles: listProfiles,
  parseStatePayload: parseStatePayload,
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
  sweepExpiredNonces: sweepExpiredNonces,
  takeNonce: takeNonce,
  exchangeCode: exchangeCode,
  TOKEN_REFRESH_MARGIN_S: TOKEN_REFRESH_MARGIN_S,
  HTTP_TIMEOUT_MS: HTTP_TIMEOUT_MS,
  isStravaError: isStravaError,
  refreshAccessToken: refreshAccessToken,
  accessTokenIsFresh: accessTokenIsFresh,
  ensureAccessToken: ensureAccessToken,
  fetchActivitiesPage: fetchActivitiesPage,
  deriveExpiry: deriveExpiry,
  configMissingApi: configMissingApi,
  FALLBACK_TOKEN_TTL_S: FALLBACK_TOKEN_TTL_S,
  CALL_RESERVE_MS: CALL_RESERVE_MS,
  callTimeout: callTimeout
};
