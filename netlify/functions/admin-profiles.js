'use strict';
/* =====================================================================
   admin-profiles — gestion des profils. OUTIL D'ADMINISTRATION.

   Il n'existe AUCUNE interface publique de creation de compte : cette
   fonction est appelee par Enzo, en ligne de commande, avec l'en-tete
   x-admin-key. Le client (public/index.html) ne l'appelle jamais.

   REGLES DURES
   - ADMIN_KEY est une variable d'environnement Netlify. Elle n'est ni un
     profil, ni utilisable comme cle d'acces aux donnees. Fail-closed :
     absente ou trop courte -> 503, tout est refuse.
   - La cle d'un profil n'est renvoyee QU'UNE SEULE FOIS, a la creation ou a
     la rotation. Elle n'est stockee nulle part en clair : seul un condensat
     scrypt et son sel vivent dans Blobs. Perdue, elle est REGENEREE, jamais
     retrouvee.
   - 'list' ne renvoie JAMAIS de cle, de sel ni de condensat. La projection
     publicProfile() de common.js est la seule sortie autorisee.
   - Aucune valeur secrete dans un journal : uniquement l'action, un
     identifiant de profil et des booleens.
   - La ROTATION NE TOUCHE AUCUNE DONNEE. L'identifiant de profil est le
     prefixe des donnees ; la cle n'est qu'un moyen d'acces. Le jeton Strava
     et tout ce qui est range sous 'strava/<profil>/...' restent strictement
     intacts. C'est le point qu'Enzo doit pouvoir tenir pour acquis.
   - Aucune action de SUPPRESSION : desactiver, oui ; effacer des donnees,
     non. Ce serait une perte de donnees utilisateur, hors du perimetre.

   ---------------------------------------------------------------------
   CONTRAT
   ---------------------------------------------------------------------
   POST  en-tete : x-admin-key
         corps JSON : { action, ... }

     { action:'create',  id, name }
       201 { ok:true, key:'<id>.<secret>', key_shown_once:true,
             profile:{ id, name, created_at, rotated_at, active } }
       409 { error:'exists' }          un profil porte deja cet identifiant

     { action:'list' }
       200 { ok:true, profiles:[ { id, name, created_at, rotated_at, active } ] }

     { action:'rotate',  id }
       200 { ok:true, key:'<id>.<secret>', key_shown_once:true, profile:{...} }
       404 { error:'not_found' }

     { action:'set-active', id, active:<booleen> }
       200 { ok:true, profile:{...} }
       404 { error:'not_found' }

     { action:'invite',  id, ttl_days? }        ttl_days : entier 1..30, defaut 7
       201 { ok:true, code:'<code>', code_shown_once:true,
             url:'https://<site>/?invite=<code>', expires_at:'<iso>',
             profile_id:'<id>', profile_exists:<booleen> }
       Le profil n'a PAS besoin d'exister : l'invitation le creera. S'il
       existe, elle regenerera sa cle sans toucher a ses donnees. Le code
       n'est renvoye qu'ici, une seule fois, et n'est stocke que hache.

   ERREURS communes
     503 { error:'unavailable' }                ADMIN_KEY absente / trop courte
     401 { error:'unauthorized' }               x-admin-key absente ou fausse
     405 { error:'method_not_allowed' }         + en-tete Allow
     400 { error:'bad_request', field:'<nom>' } champ absent ou invalide.
          'field' ne porte JAMAIS la valeur fautive, seulement le nom du champ.
     503 { error:'blobs', reason:... }          panne de stockage serveur
     500 { error:'server_error' }               jamais d'exception nue

   Les 404 / 409 ne sont emis qu'APRES authentification par ADMIN_KEY : un
   inconnu ne peut donc rien deduire de l'existence d'un profil.
   ===================================================================== */
const C = require('./lib/common.js');

const ALLOWED = ['POST'];
const NAME_MAX = 60;
const BODY_MAX = 4096;

function bad(field) { return C.json(400, { error: 'bad_request', field: field }); }

/* Corps de requete : borne en taille, decode si Netlify l'a encode en base64
   (cas d'un client qui n'annonce pas de type texte). */
function readBody(event) {
  let raw = (event && typeof event.body === 'string') ? event.body : '';
  if (!raw) return null;
  if (event && event.isBase64Encoded) {
    try { raw = Buffer.from(raw, 'base64').toString('utf8'); } catch (e) { return null; }
  }
  if (raw.length > BODY_MAX) return null;
  try {
    const o = JSON.parse(raw);
    return (o && typeof o === 'object' && !Array.isArray(o)) ? o : null;
  } catch (e) { return null; }
}

/* Nom d'affichage : chaine courte, sans caractere de controle. Il est stocke
   tel quel et ne sert JAMAIS de segment de chemin (contrairement a l'id). */
function cleanName(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s || s.length > NAME_MAX) return null;
  // Caracteres de controle refuses (U+0000 a U+001F et U+007F).
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c < 32 || c === 127) return null; }
  return s;
}

/* Materiel de cle neuf pour un profil. Le secret en clair ne quitte cette
   fonction que par le corps de la reponse, une seule fois.
   L'implementation vit dans common.js depuis l'etape 3 : la fonction de
   remise d'invitation doit produire EXACTEMENT le meme materiel, et deux
   copies de ce calcul finiraient par diverger. */
const freshKey = C.freshKey;

/* Duree de vie d'une invitation, en jours. Bornee : une invitation qui ne
   perime pas est une cle d'acces deguisee. */
function ttlDays(v) {
  if (v === undefined || v === null) return C.INVITE_TTL_DAYS_DEFAULT;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > C.INVITE_TTL_DAYS_MAX) return null;
  return n;
}

exports.handler = async function (event) {
  try {
    // 1. ADMIN_KEY d'abord : fail-closed, avant meme de dire si la methode
    //    est bonne. Aucun signal a un inconnu.
    const denied = C.checkAdminKey(event);
    if (denied) return denied;

    // 2. Methode, seulement une fois l'administrateur authentifie.
    //    Pas de reponse au preflight OPTIONS : cette fonction n'est pas faite
    //    pour etre appelee depuis un navigateur, et x-admin-key n'est pas
    //    dans les en-tetes autorises par le CORS du site.
    const method = ((event && event.httpMethod) || '').toUpperCase();
    if (method !== 'POST') return C.methodNotAllowed(ALLOWED);

    const body = readBody(event);
    if (!body) return bad('body');

    const action = (typeof body.action === 'string') ? body.action.trim() : '';
    const now = new Date().toISOString();

    /* ---------------- list ---------------- */
    if (action === 'list') {
      let profiles;
      try { profiles = await C.listProfiles(event); }     // event : invariant connectLambda
      catch (e) { return C.storeFailure(e); }
      console.log('[strava] admin | action : list | profils :', profiles.length);
      return C.json(200, { ok: true, profiles: profiles });
    }

    /* Les autres actions portent toutes sur UN profil : identifiant valide
       obligatoire, verifie avant tout acces au stockage. */
    if (action !== 'create' && action !== 'rotate' && action !== 'set-active' && action !== 'invite') return bad('action');

    const id = (typeof body.id === 'string') ? body.id : '';
    if (!C.isProfileId(id)) return bad('id');

    let existing = null;
    try { existing = await C.readProfile(event, id); }
    catch (e) { return C.storeFailure(e); }

    /* ---------------- invite ----------------
       Fabrique un jeton JETABLE qu'Enzo transmet par SMS. Il ne donne acces
       a rien : il autorise seulement la fonction publique 'join' a remettre
       UNE cle pour CE profil. Le profil n'a pas besoin d'exister -- c'est
       justement la voie de creation --, et s'il existe, l'invitation servira
       a regenerer sa cle (changement de telephone) sans toucher a ses
       donnees.
       Le code ne part QUE dans ce corps de reponse : il n'est ni journalise,
       ni stocke en clair (seul son condensat SHA-256 nomme le document). */
    if (action === 'invite') {
      const days = ttlDays(body.ttl_days);
      if (days === null) return bad('ttl_days');
      const code = C.generateInviteCode();
      const expMs = Date.now() + days * 24 * 60 * 60 * 1000;
      const doc = { v: 1, profile: id, exp: expMs, created_at: now };
      try { await C.writeInvite(event, C.inviteHash(code), doc); }
      catch (e) { return C.storeFailure(e); }

      // Le lien est le chemin principal pour une personne non technique. Si
      // l'origine du site n'est pas connue du runtime, on rend le code seul
      // plutot qu'une URL fausse.
      const origin = C.siteOrigin();
      console.log('[strava] admin | action : invite | profil :', id,
        '| profil existant :', existing ? 'oui' : 'non', '| jours :', days);
      return C.json(201, {
        ok: true,
        code: code,
        code_shown_once: true,
        url: origin ? (origin + '/?invite=' + code) : '',
        expires_at: new Date(expMs).toISOString(),
        profile_id: id,
        profile_exists: !!existing
      });
    }

    /* ---------------- create ---------------- */
    if (action === 'create') {
      if (existing) return C.json(409, { error: 'exists' });
      const name = cleanName(body.name);
      if (!name) return bad('name');

      const fresh = await freshKey(id);
      const doc = {
        v: 1,
        id: id,
        name: name,
        alg: fresh.material.alg,
        params: fresh.material.params,
        salt: fresh.material.salt,
        hash: fresh.material.hash,
        created_at: now,
        rotated_at: now,
        active: true
      };
      try { await C.writeProfile(event, doc); }
      catch (e) { return C.storeFailure(e); }

      console.log('[strava] admin | action : create | profil :', id, '| actif : oui');
      return C.json(201, { ok: true, key: fresh.key, key_shown_once: true, profile: C.publicProfile(doc) });
    }

    if (!existing) return C.json(404, { error: 'not_found' });

    /* ---------------- rotate ----------------
       On RECOPIE le document existant et on ne remplace que le materiel de
       cle. Rien d'autre n'est touche : ni created_at, ni active, ni le nom,
       et surtout aucune donnee rangee sous 'strava/<id>/...'. */
    if (action === 'rotate') {
      const fresh = await freshKey(id);
      const doc = Object.assign({}, existing, {
        alg: fresh.material.alg,
        params: fresh.material.params,
        salt: fresh.material.salt,
        hash: fresh.material.hash,
        rotated_at: now
      });
      try { await C.writeProfile(event, doc); }
      catch (e) { return C.storeFailure(e); }

      // L'ancienne cle cesse de fonctionner des cette ecriture : elle ne
      // correspond plus au sel ni au condensat stockes.
      console.log('[strava] admin | action : rotate | profil :', id);
      return C.json(200, { ok: true, key: fresh.key, key_shown_once: true, profile: C.publicProfile(doc) });
    }

    /* ---------------- set-active ---------------- */
    if (typeof body.active !== 'boolean') return bad('active');
    const doc = Object.assign({}, existing, { active: body.active });
    try { await C.writeProfile(event, doc); }
    catch (e) { return C.storeFailure(e); }

    console.log('[strava] admin | action : set-active | profil :', id, '| actif :', body.active ? 'oui' : 'non');
    return C.json(200, { ok: true, profile: C.publicProfile(doc) });
  } catch (e) {
    console.error('[strava] admin-profiles : erreur inattendue');
    return C.json(500, { error: 'server_error' });
  }
};
