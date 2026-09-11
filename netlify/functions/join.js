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
     Sans cela, le site offrirait un oracle d'existence des codes ET des
     profils. Seule une panne de stockage se distingue (503), comme partout
     ailleurs : elle ne dit rien d'un profil en particulier.
   - UN PROFIL SUPPRIME NE REVIENT JAMAIS A LA VIE ICI (etape 5). La
     suppression pose une PIERRE TOMBALE ('deleted/<id>') AVANT de commencer
     a effacer quoi que ce soit ; cette fonction la consulte a chaque remise.
     Sans elle, une seule invitation oubliee -- par une enumeration
     eventuellement coherente, ou par une purge interrompue -- suffisait a
     recreer un profil ACTIF, avec une cle valide, pour quiconque detenait
     encore le code.
   - LA CLE N'EST RENVOYEE QU'UNE FOIS. Elle n'est stockee nulle part en
     clair. Perdue, elle est regeneree par une nouvelle invitation.
   - UNE INVITATION REVENDIQUEE EST CONSOMMEE, POINT (etape 5, defaut m-c).
     Rien ne la rend jamais, meme si la remise echoue ensuite. Un mecanisme
     qui la rendait a existe ; il est RETIRE : une invitation rendue
     survivait a une suppression et pouvait prendre un profil recree plus
     tard sous le meme identifiant, et deux remises simultanees pouvaient
     rouvrir un code deja utilise avec succes. Limite assumee, dite a
     l'etape 5 du handler : remise ratee apres la prise du code -> la
     personne demande un nouveau lien a Enzo.
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
     Sur 503 et 500, l'appelant NE SAIT PAS si l'invitation a ete consommee :
     l'echec a pu survenir avant sa revendication (le meme code resservira)
     ou apres (il sera refuse ; il faut un nouveau lien). MEME INCERTITUDE
     SANS AUCUNE REPONSE (delai depasse cote client, ou connexion perdue) :
     la requete a pu ne jamais arriver, ou etre traitee jusqu'au bout -- code
     pris, voire cle remise -- et sa reponse perdue en route. Dans les quatre
     cas, le message du client est ecrit pour etre vrai quelle que soit
     l'issue : reessayer avec le meme code ; s'il est refuse, demander un
     nouveau lien a Enzo.
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
       l'invitation n'est PAS consommee. Elle ne sert a rien TANT QUE la
       marque est la ; mais si Enzo leve la marque par 'create' pour
       reutiliser l'identifiant, elle REDEVIENT UTILISABLE jusqu'a son
       expiration, et prend le profil recree. D'ou la consigne de
       docs/suppression-profil.md (« Recreer plus tard un profil du meme
       identifiant ») : ne recreer un identifiant supprime qu'une fois
       expirees toutes ses invitations, ou prendre un autre identifiant. */
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

    /* 5. Cle neuve. L'invitation est CONSOMMEE : a partir d'ici, rien ne la
       rend, quel que soit l'echec qui suit (defaut m-c).
       LIMITE ASSUMEE (m-c) : si la remise echoue apres la prise du code
       -- fabrication de la cle en echec (500 server_error), panne de
       stockage a l'ecriture du profil ou a la relecture de la pierre tombale
       (503 blobs) --, la personne n'obtient pas de cle et le rejeu du meme
       code est refuse. Meme issue si la reponse, meme 200, se perd en route
       (delai depasse cote client, connexion coupee). Sur un changement de
       telephone, l'ancienne cle peut en outre etre deja morte (document
       reecrit avec la nouvelle empreinte). Remede : Enzo emet un nouveau
       lien. C'est rare, sans perte de donnees -- les donnees d'entrainement
       vivent sur l'appareil, le jeton Strava n'est jamais touche -- et Enzo
       administre moins de dix profils.
       POURQUOI NE PAS RENDRE L'INVITATION : ce rattrapage a existe et a ete
       retire. Une invitation rendue survivait a une suppression repondue
       404 {tombstone:true} et pouvait prendre un profil RECREE plus tard
       sous le meme identifiant ; deux remises simultanees du meme code
       pouvaient rouvrir un code deja utilise avec succes (et tuer la cle de
       celui qui l'avait obtenue) ; et une invitation pouvait expirer pendant
       la remise ratee. Chaque cas etait plus grave que celui qu'il
       rattrapait. */
    let fresh;
    try { fresh = await C.freshKey(id); }
    catch (e) { return C.json(500, { error: 'server_error' }); }
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

    // Ecriture en echec (ou peut-etre aboutie malgre l'erreur) : 503, et
    // l'invitation reste consommee (limite m-c, cf. 5).
    try { await C.writeProfile(event, doc); }
    catch (e) { return C.storeFailure(e); }

    /* 6. COURSE AVEC UNE SUPPRESSION (etape 5, defaut m7). La pierre tombale
       a ete lue a l'etape 3 bis ; si Enzo supprime ce profil ENTRE cette
       lecture et l'ecriture ci-dessus, l'ecriture recreait un document ACTIF,
       avec une cle valide -- un profil supprime ressuscite. On RELIT donc la
       marque APRES avoir ecrit :
         - marque presente (ou illisible) : la suppression a gagne. On retire
           le document qu'on vient d'ecrire et on refuse ; la cle neuve n'est
           remise a personne.
         - relecture en ECHEC : on ne sait pas. On ne remet pas la cle (503),
           on ne supprime rien non plus -- sur un simple changement de
           telephone, effacer le document detruirait un profil que personne
           n'a demande de supprimer. L'invitation reste consommee (limite
           m-c, cf. 5) : il faudra un nouveau lien.
       La suppression fait le pendant : apres avoir pose sa marque, elle
       relit le document de profil (sonde ou purge), et efface celui qu'une
       remise concurrente aurait ecrit juste avant. Chacune ecrit PUIS relit
       l'objet de l'autre : au moins une des deux voit l'autre -- sous
       reserve de la coherence du magasin (limite documentee dans
       docs/suppression-profil.md).
       LIMITE CONNUE, NON TRAITEE (M1) : cette relecture ne voit que l'etat
       PRESENT de la marque. Si Enzo enchaine 'delete' PUIS 'create' du meme
       identifiant pendant qu'une remise est en vol -- les deux dans la
       fenetre tres courte -- 43 ms mesurees sur un magasin en memoire, sans
       latence reseau ; en production, trois a quatre allers-retours Blobs --
       qui separe
       la lecture 3 bis de cette relecture --, la marque a ete posee puis
       levee entre les deux : la remise REUSSIT, sur le profil RECREE. Selon
       l'ordre des ecritures, le document ecrit par 'create' est remplace par
       celui de la remise (la cle du detenteur de l'ancien code ouvre le
       nouveau profil, celle de 'create' est morte), ou l'inverse (la cle
       remise ici est deja morte). Aucun mecanisme n'est ajoute pour ce cas.
       Consigne, dans docs/suppression-profil.md : apres un 'delete',
       attendre avant un 'create' du meme identifiant, et emettre
       l'invitation APRES le 'create'. */
    let after = { state: 'none', doc: null };
    try { after = await C.readProfileTombstone(event, id); }
    catch (e) { return C.storeFailure(e); }
    if (after.state !== 'none') {
      /* La suppression a gagne : l'invitation, consommee, ne vaut plus
         rien. Si le retrait du document echoue, il reste un document
         ACTIF (copie de celui qu'on a lu) : la suppression rejouee repond
         alors 409 profile_active, et il faut d'abord refaire 'set-active'
         a false, puis rejouer 'delete' jusqu'a 404 -- c'est la marche a
         suivre de docs/suppression-profil.md. */
      try { await C.deleteProfileDoc(event, id); } catch (e) { /* cf. ci-dessus */ }
      console.log('[strava] join | profil :', id, '| supprime pendant la remise : cle annulee');
      return refuse();
    }

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
