'use strict';
/* =====================================================================
   join — remise d'une cle d'acces contre une invitation.

   C'est la SEULE fonction publique qui ecrit dans l'espace des profils, et
   la seule exception encadree a la regle « le profil est un RESULTAT de
   l'authentification, jamais une entree du client » : l'appelant presente
   un CODE, jamais un identifiant de profil. L'identifiant vient du document
   d'invitation, ecrit par Enzo via admin-profiles. Un appelant ne peut donc
   pas choisir le profil qu'il rejoint.

   REGLES DURES
   - REFUS INDISCERNABLE. Code absent, malforme, inconnu, deja consomme,
     expire, visant un profil desactive ou SUPPRIME : MEME statut, MEME
     corps, et un acces au stockage dans tous les cas pour que la duree ne
     trahisse rien.
   - UN PROFIL SUPPRIME NE REVIENT JAMAIS A LA VIE ICI (etape 5). La
     suppression pose une PIERRE TOMBALE ('deleted/<id>') AVANT de commencer
     a effacer quoi que ce soit ; cette fonction la consulte a chaque remise.
     Sans elle, une seule invitation oubliee -- par une enumeration
     eventuellement coherente, ou par une purge interrompue -- suffisait a
     recreer un profil ACTIF, avec une cle valide, pour quiconque detenait
     encore le code.
     Sans cela, le site offrirait un oracle d'existence des codes ET des
     profils. Seule une panne de stockage se distingue (503), comme partout
     ailleurs : elle ne dit rien d'un profil en particulier.
   - LA CLE N'EST RENVOYEE QU'UNE FOIS. Elle n'est stockee nulle part en
     clair. Perdue, elle est regeneree par une nouvelle invitation.
   - LA REGENERATION NE TOUCHE AUCUNE DONNEE. On RECOPIE le document de
     profil existant et on ne remplace que le materiel de cle : le jeton
     Strava range sous 'strava/<id>/...' et tout le reste sont strictement
     intacts. Meme propriete que 'rotate', pour la meme raison : un
     changement de telephone ne doit rien couter.
   - UN PROFIL DESACTIVE N'EST JAMAIS REACTIVE ICI. Enzo l'a desactive
     volontairement ; une invitation ne doit pas pouvoir defaire cette
     decision. Le refus est indiscernable, et l'invitation n'est PAS
     consommee -- elle redeviendra utilisable si Enzo reactive le profil.
     MEME REGLE POUR UN DOCUMENT DE PROFIL ABIME : « illisible » n'est pas
     « inexistant ». Recreer aurait remis active:true et un created_at neuf
     sur un profil qu'Enzo avait justement desactive. On refuse, on n'ecrit
     rien, et Enzo reparera le document depuis admin-profiles.
   - COUT DE STOCKAGE IDENTIQUE DANS TOUS LES REFUS que l'appelant peut
     provoquer : EXACTEMENT une lecture d'invitation, une lecture de profil,
     puis une lecture de pierre tombale, dans cet ordre. Deux ecarts avaient survecu a la premiere
     ecriture, et chacun etait un oracle : l'invitation EXPIREE coutait un
     'delete' de plus (« ce code a existe » devenait mesurable), et le profil
     n'etait lu QUE si l'invitation etait valide (un 'get' de moins dans les
     autres refus). On lit donc toujours un profil -- celui de l'invitation,
     ou un LEURRE tire au hasard qui n'existe pas -- et un refus ne supprime
     plus rien.
   - AUCUNE VALEUR SECRETE DANS UN JOURNAL : ni le code, ni la cle, ni un
     condensat. Le nom du profil et des booleens, rien d'autre.
   - Le nom d'affichage est la seule chaine libre acceptee d'un inconnu :
     validation stricte (cleanDisplayName), et il n'est JAMAIS employe comme
     segment de chemin -- l'identifiant, lui, vient de l'invitation.

   ---------------------------------------------------------------------
   CONTRAT
   ---------------------------------------------------------------------
   POST  corps JSON : { code, name }

     200 { ok:true, key:'<id>.<secret>', key_shown_once:true,
           created:<booleen>, profile:{ id, name, created_at, rotated_at, active } }

     400 { error:'bad_request', field:'name' }   nom absent ou invalide.
          Verifie AVANT le code : cette reponse ne depend donc que du nom et
          ne dit rien de l'existence d'une invitation.
     403 { error:'invitation' }                  refus unique, indiscernable
     405 { error:'method_not_allowed' }          + en-tete Allow
     503 { error:'blobs', reason:... }           panne de stockage serveur
     500 { error:'server_error' }                jamais d'exception nue
   ===================================================================== */
const C = require('./lib/common.js');
const crypto = require('crypto');

const ALLOWED = ['POST', 'OPTIONS'];
const BODY_MAX = 4096;

/* Refus unique. Une seule construction dans tout le fichier : c'est ce qui
   rend l'indiscernabilite verifiable en lisant les points d'appel. */
function refuse() { return C.json(403, { error: 'invitation' }); }

/* Corps de requete : borne en taille, decode si Netlify l'a encode en
   base64. Meme lecture que admin-profiles. */
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

/* Identifiant de profil LEURRE, tire au hasard a chaque requete. Il sert a
   lire un profil meme quand il n'y a pas d'invitation a laquelle en
   rattacher un : sans cela, le nombre d'acces au stockage distinguerait
   « code inconnu » de « code valide visant un profil desactive ».
   Tire au hasard, et non fixe, pour qu'il ne puisse pas etre cree a l'avance
   ni distingue par un cache. Respecte la grammaire de isProfileId : la
   fabrication de la cle de stockage la revalide de toute facon. */
function decoyProfileId() {
  return 'zz-' + crypto.randomBytes(8).toString('hex');
}

/* Condensat a chercher dans le magasin.
   Un code ABSENT ou MALFORME ne doit pas court-circuiter la recherche :
   sinon la reponse reviendrait sans acces au stockage, et sa rapidite
   distinguerait « code de forme invalide » de « code inconnu ». On cherche
   donc un condensat LEURRE, qui ne correspond a aucune invitation. */
function lookupHash(code) {
  return C.isInviteCode(code) ? C.inviteHash(code) : C.inviteHash('leurre:' + Math.random());
}

exports.handler = async function (event) {
  try {
    const method = ((event && event.httpMethod) || '').toUpperCase();
    if (method === 'OPTIONS') return C.preflight(ALLOWED);
    if (method !== 'POST') return C.methodNotAllowed(ALLOWED);

    const body = readBody(event) || {};

    // 1. Le NOM d'abord. Sa validation ne depend d'aucune donnee stockee :
    //    la reponse 400 ne peut donc rien reveler d'une invitation.
    const name = C.cleanDisplayName(body.name);
    if (!name) return C.json(400, { error: 'bad_request', field: 'name' });

    // 2. Le CODE. Normalise (espaces, tirets, majuscules d'une recopie
    //    manuelle) avant validation de forme.
    const code = C.normalizeInviteCode(body.code);
    const hash = lookupHash(code);
    const now = new Date();
    const nowIso = now.toISOString();

    let invite = null;
    try { invite = await C.readInvite(event, hash); }
    catch (e) { return C.storeFailure(e); }

    /* L'invitation est-elle UTILISABLE ? Inconnue, illisible, deja
       revendiquee ou expiree : non. On ne refuse pas encore -- refuser ici
       ferait l'economie de la lecture de profil qui suit, et cette economie
       serait mesurable. Rien n'est supprime : une invitation expiree n'est
       plus consommable de toute facon, et son 'delete' etait un oracle. */
    const usable = !!(invite && !invite.claim
      && typeof invite.exp === 'number' && Number.isFinite(invite.exp)
      && now.getTime() <= invite.exp);

    // 3. Le profil vise. Il vient de l'INVITATION, jamais de l'appelant.
    //    Faute d'invitation utilisable, on lit un LEURRE : meme nombre
    //    d'acces au stockage, dans le meme ordre, quel que soit le refus.
    const id = usable ? invite.profile : decoyProfileId();
    let found = { state: 'absent', doc: null };
    try { found = await C.readProfileState(event, id); }
    catch (e) { return C.storeFailure(e); }

    /* 3 bis. LE PROFIL A-T-IL ETE SUPPRIME ? (chantier 3, etape 5)
       C'est la barriere qui empeche un code residuel de RESSUSCITER un
       profil qu'Enzo a supprime. Elle ne depend ni de l'ordre des
       suppressions, ni de la coherence de l'enumeration des invitations, ni
       de la survie du document de profil -- c'est-a-dire d'aucune des trois
       choses qui peuvent manquer au pire moment. La marque est posee AVANT
       la purge : une suppression interrompue laisse donc un profil
       injoignable, jamais un profil a moitie efface et rejoignable.
       LECTURE SYSTEMATIQUE, y compris pour le LEURRE : le cout de stockage
       d'un refus reste identique dans tous les cas (une invitation, un
       profil, une pierre tombale, dans cet ordre), et l'indiscernabilite est
       preservee. Une panne de lecture repond 503, comme les deux autres. */
    let tomb = { state: 'none', doc: null };
    try { tomb = await C.readProfileTombstone(event, id); }
    catch (e) { return C.storeFailure(e); }

    // Les refus provoquables par l'appelant, tous au meme cout :
    if (!usable) return refuse();
    /* Profil SUPPRIME (ou marque illisible : on ne ressuscite personne sur
       la foi d'un document qu'on n'a pas su lire). Refus indiscernable, et
       l'invitation n'est PAS consommee -- elle ne vaut de toute facon plus
       rien, et Enzo peut lever la marque par 'create' s'il veut reutiliser
       l'identifiant. */
    if (tomb.state !== 'none') return refuse();
    // Document de profil ABIME : refus. On ne recree pas par-dessus -- ce
    // serait rendre actif, avec un created_at neuf, un profil desactive.
    if (found.state === 'invalid') return refuse();
    const existing = found.doc;
    // Profil desactive : refus indiscernable, SANS consommer l'invitation.
    if (existing && existing.active === false) return refuse();

    // 4. CONSOMMATION AVANT GENERATION. Si la revendication est perdue
    //    (autre remise simultanee du meme code), on s'arrete ici : aucune
    //    cle n'est fabriquee.
    let claimed = false;
    try { claimed = await C.claimInvite(event, hash, invite, nowIso); }
    catch (e) { return C.storeFailure(e); }
    if (!claimed) return refuse();

    // L'invitation est consommee : on la supprime pour de bon. Un echec ici
    // est benin, le jeton de revendication suffit deja a la rendre inutile.
    try { await C.deleteInvite(event, hash); } catch (e) { /* sans consequence */ }

    // 5. Cle neuve. A partir d'ici, l'invitation ne vaut plus rien : meme si
    //    la suite echoue, elle ne sera pas rejouable. Enzo en emet une autre.
    const fresh = await C.freshKey(id);
    const doc = existing
      /* CHANGEMENT DE TELEPHONE : recopie integrale, seul le materiel de cle
         change. created_at, active et tout champ futur sont preserves ; le
         jeton Strava n'est meme pas lu. */
      ? Object.assign({}, existing, {
        name: name,
        alg: fresh.material.alg,
        params: fresh.material.params,
        salt: fresh.material.salt,
        hash: fresh.material.hash,
        rotated_at: nowIso
      })
      /* PREMIERE ARRIVEE : le profil n'existait pas, l'invitation le cree. */
      : {
        v: 1,
        id: id,
        name: name,
        alg: fresh.material.alg,
        params: fresh.material.params,
        salt: fresh.material.salt,
        hash: fresh.material.hash,
        created_at: nowIso,
        rotated_at: nowIso,
        active: true
      };

    try { await C.writeProfile(event, doc); }
    catch (e) { return C.storeFailure(e); }

    console.log('[strava] join | profil :', id, '| cree :', existing ? 'non' : 'oui');
    return C.json(200, {
      ok: true,
      key: fresh.key,
      key_shown_once: true,
      created: !existing,
      profile: C.publicProfile(doc)
    });
  } catch (e) {
    console.error('[strava] join : erreur inattendue');
    return C.json(500, { error: 'server_error' });
  }
};
