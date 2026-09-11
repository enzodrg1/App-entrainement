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
   - LA SUPPRESSION ('delete', chantier 3, etape 5) EST LA SEULE OPERATION
     IRREVERSIBLE. Elle existe parce qu'effacer les donnees de quelqu'un qui
     le demande est une obligation legale, pas un confort. Elle est protegee
     par DEUX garde-fous cumulatifs : profil prealablement DESACTIVE, et
     identifiant RETAPE dans un champ distinct. Elle ne touche JAMAIS un
     autre profil, et elle ENUMERE plutot que de deviner.
     Le garde-fou « desactive » se verifie sur le DOCUMENT de profil. S'il
     n'y a plus de document, il n'y a plus de profil a desactiver ni de cle
     qui fonctionne : le nettoyage des residus reste possible, et
     'confirm_id' reste exige.
     ELLE POSE UNE PIERRE TOMBALE AVANT DE COMMENCER. C'est ce qui rend la
     suppression definitive independante de la reussite de la purge : une
     invitation oubliee ne peut plus ressusciter le profil. Seul 'create'
     leve cette marque.
   - LA SUPPRESSION NE COUVRE QUE LE SERVEUR. Les seances cochees, le
     journal, les genes et les courses vivent dans le localStorage du
     TELEPHONE : le serveur ne peut pas les atteindre. La personne doit
     utiliser « Supprimer mes données de cet appareil » dans l'onglet Zones.
     Procedure complete : docs/suppression-profil.md.

   ---------------------------------------------------------------------
   CONTRAT
   ---------------------------------------------------------------------
   POST  en-tete : x-admin-key
         corps JSON : { action, ... }

     { action:'create',  id, name }
       201 { ok:true, key:'<id>.<secret>', key_shown_once:true,
             tombstone_cleared:<booleen>,
             profile:{ id, name, created_at, rotated_at, active } }
       409 { error:'exists' }          un profil porte deja cet identifiant
       SEUL endroit qui LEVE la pierre tombale posee par 'delete' : un
       identifiant supprime redevient utilisable, sur geste explicite.
       tombstone_cleared:false -> la marque n'a pas pu etre levee, et 'join'
       refusera encore toute invitation pour cet identifiant.

     { action:'list' }
       200 { ok:true, profiles:[ { id, name, created_at, rotated_at, active } ] }

     { action:'rotate',  id }
       200 { ok:true, key:'<id>.<secret>', key_shown_once:true, profile:{...} }
       404 { error:'not_found' }

     { action:'set-active', id, active:<booleen> }
       200 { ok:true, profile:{...} }
       404 { error:'not_found' }

     { action:'delete',  id, confirm_id }       SUPPRESSION DEFINITIVE
       Le profil doit avoir ete DESACTIVE au prealable, et 'confirm_id' doit
       repeter 'id' A L'IDENTIQUE (comparaison stricte : ni trim, ni casse
       ignoree). Efface le document de profil, le jeton Strava, les nonces
       OAuth et les invitations qui visent ce profil -- et rien d'autre.
       Revoque au passage l'autorisation Strava, APRES la purge et avec ce
       qui reste du budget ; un echec de revocation n'empeche JAMAIS la
       suppression, il est rapporte.
       ORDRE DE SUPPRESSION : le document de profil part EN DERNIER, et
       SEULEMENT si tout le reste est parti. Sinon il est CONSERVE
       ('kept_profile'), et c'est lui qui rend le rejeu possible.
       REJEU : l'action sait finir le travail meme si le document a DEJA
       disparu -- elle sonde les residus avant de conclure « rien a faire ».
       Pose d'abord une PIERRE TOMBALE ('deleted/<id>'), AVANT toute
       suppression : elle rend le profil injoignable meme si la purge est
       interrompue, meme si une invitation echappe a l'enumeration. Sans
       elle, une seule invitation oubliee recreait un profil ACTIF, avec une
       cle valide, pour quiconque detenait encore le code.
       200 { ok:true, complete:true, id, verified, tombstone, deleted:{...},
             scanned:{...}, remaining:{...}, unreadable_invites,
             kept_profile, strava:{ attempted, revoked, reason },
             warnings:[...] }
       500 { ok:false, error:'incomplete', ... }  suppression PARTIELLE :
             le detail dit ce qui reste. REJOUE : le rejeu reprend ou l'on
             en etait, il ne repond pas 404 tant qu'il reste des residus.
       404 { error:'not_found', tombstone }  ni document, ni residu : il n'y
             a rien a supprimer sous cet identifiant. La pierre tombale est
             posee quand meme -- y compris sur un identifiant inconnu.
       409 { error:'profile_active' }        profil actif : desactiver d'abord
       409 { error:'profile_unreadable' }    document de profil abime
       400 { error:'bad_request', field:'confirm_id' }

     { action:'invite',  id, ttl_days? }        ttl_days : entier 1..30, defaut 7
       201 { ok:true, code:'<code>', code_shown_once:true,
             url:'https://<site>/?invite=<code>', expires_at:'<iso>',
             profile_id:'<id>', profile_exists:<booleen>,
             profile_deleted:<booleen> }
       profile_deleted:true -> l'identifiant a ete SUPPRIME : 'join' refusera
       ce code tant qu'un 'create' n'aura pas leve la marque.
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
/* Budget de temps consacre a la revocation Strava pendant une suppression
   (rafraichissement eventuel + appel de revocation).

   DEUX PROTECTIONS, parce qu'une seule ne suffisait pas. Le budget etait
   borne, mais la revocation passait AVANT la purge : un Strava qui PEND
   consommait plus de cinq secondes sur une invocation d'environ dix, et la
   purge d'un profil charge pouvait etre coupee en plein milieu -- exactement
   le « echouer a cause de Strava » que ce budget est cense empecher.
   Desormais : la PURGE D'ABORD (l'obligation legale), la revocation ENSUITE
   (le bonus), avec ce qui reste du budget total et jamais plus. Le jeton est
   lu AVANT la purge, puisque la purge l'efface ; sa valeur ne sert qu'a la
   revocation et ne quitte pas cette fonction. */
const DELETE_STRAVA_BUDGET_MS = 3000;
/* Enveloppe de l'action complete, sous l'echeance d'invocation (~10 s) :
   au-dela, on ne tente plus le reseau du tout. */
const DELETE_TOTAL_BUDGET_MS = 9000;
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
    if (action !== 'create' && action !== 'rotate' && action !== 'set-active'
      && action !== 'invite' && action !== 'delete') return bad('action');

    const id = (typeof body.id === 'string') ? body.id : '';
    if (!C.isProfileId(id)) return bad('id');

    /* ---------------- delete ----------------
       LA SEULE OPERATION IRREVERSIBLE DU SYSTEME. Elle efface les donnees de
       sante d'une personne : c'est une obligation legale, et il n'existe
       aucune corbeille.

       DEUX GARDE-FOUS, non negociables et verifies DANS CET ORDRE :
         1. L'identifiant doit etre RETAPE dans un champ distinct
            ('confirm_id'). Comparaison STRICTE : ni trim, ni casse ignoree.
            Une faute de frappe ne doit pas detruire le mauvais profil, et
            un identifiant recopie avec un espace n'est pas le meme.
            Verifie AVANT tout acces au stockage.
         2. Le profil doit avoir ete DESACTIVE au prealable (set-active
            false). Un profil actif ne se supprime pas d'un seul geste : la
            desactivation est le temps de reflexion, et elle ferme deja
            l'acces (checkKey refuse un profil desactive).

       Un document de profil ABIME ('invalid') n'est PAS supprimable ici :
       on ne peut pas verifier qu'il etait desactive, et l'effacer
       reviendrait a supprimer sur la foi d'un document qu'on n'a pas su
       lire. Chemin de reparation : docs/suppression-profil.md.

       REVOCATION STRAVA AU MIEUX, JAMAIS BLOQUANTE : une panne de Strava ne
       doit pas empecher une suppression legale. Le compte rendu dit
       exactement s'il reste une autorisation a retirer a la main. */
    if (action === 'delete') {
      const confirm = (typeof body.confirm_id === 'string') ? body.confirm_id : '';
      if (confirm !== id) return bad('confirm_id');
      const started = Date.now();

      /* readProfileState, et non readProfile : « absent » et « present mais
         illisible » ne se traitent pas pareil quand on s'apprete a effacer. */
      let found;
      try { found = await C.readProfileState(event, id); }
      catch (e) { return C.storeFailure(e); }
      if (found.state === 'invalid') return C.json(409, { error: 'profile_unreadable' });
      if (found.state === 'ok' && found.doc.active !== false) return C.json(409, { error: 'profile_active' });

      /* PIERRE TOMBALE D'ABORD, ET AVANT TOUTE SUPPRESSION.
         C'est la seule barriere qui empeche une invitation oubliee de
         RESSUSCITER ce profil, et elle ne vaut que si elle est posee AVANT :
         une purge interrompue doit laisser un profil injoignable, pas un
         profil a moitie efface et rejoignable. Elle est posee meme quand il
         n'y a apparemment rien a supprimer -- c'est justement le cas ou une
         enumeration eventuellement coherente peut nous cacher une invitation
         qui apparaitra une seconde plus tard.
         CONSEQUENCE ASSUMEE : un 'delete' sur un identifiant inconnu marque
         cet identifiant. Il redevient utilisable par un 'create' explicite.
         Fail-closed : mieux vaut un identifiant a rouvrir a la main qu'un
         profil supprime qui revient a la vie. */
      const tombstone = await C.markProfileDeleted(event, id, now);

      /* DOCUMENT ABSENT : « deja supprime » N'EST PAS LA SEULE EXPLICATION.
         Une suppression partielle anterieure a pu emporter le document et
         laisser derriere elle un jeton, des nonces ou -- le pire -- une
         INVITATION qui vise encore ce profil : remise a 'join', elle recree
         un profil ACTIF avec une cle valide. Repondre 404 sans regarder
         rendait ces objets inatteignables pour toujours.
         On SONDE donc, en lecture seule. Rien derriere : 404, comme avant.
         Quelque chose derriere (ou une sonde qui n'a pas abouti) : on
         continue, la purge finit le travail. Le garde-fou « profil
         desactive » n'est pas contourne pour autant -- sans document, il n'y
         a plus de profil a activer, la cle d'acces ne fonctionne plus
         (checkKey lit le document), et 'confirm_id' reste exige. */
      if (found.state === 'absent') {
        let residue;
        try { residue = await C.probeProfileResidue(event, id); }
        catch (e) { return C.storeFailure(e); }
        /* 'unreadable' N'EST PAS UN RESIDU DE CE PROFIL : c'est un compte
           GLOBAL de documents d'invitation abimes, dont on ignore justement
           qui ils visent. L'y compter faisait repondre « il reste quelque
           chose » pour tous les profils a la fois, y compris ceux qui n'ont
           jamais existe. */
        /* `residue.profile` : le document etait absent a la PREMIERE lecture,
           mais la sonde passe APRES la pierre tombale. S'il est la
           maintenant, une remise 'join' concurrente vient de le recreer
           (defaut m7) : on ne repond pas 404 par-dessus un profil
           ressuscite, la purge le retire. */
        const leftovers = !!(residue.profile || residue.token || residue.nonces
          || residue.invites || !residue.checked);
        if (!leftovers) return C.json(404, { error: 'not_found', tombstone: tombstone });
      }

      /* Le jeton est lu MAINTENANT : la purge va l'effacer, et la revocation
         a besoin de sa valeur. Aucune valeur de jeton ne sort d'ici. */
      let token = null, tokenRead = true;
      try { token = await C.readToken(event, id); }
      catch (e) { tokenRead = false; }

      /* LA PURGE D'ABORD. C'est l'obligation legale ; la revocation Strava
         est un bonus qui ne doit jamais lui manger son temps. */
      let purge;
      try { purge = await C.purgeProfileData(event, id); }
      catch (e) { return C.storeFailure(e); }   // rien n'a pu etre tente

      /* REVOCATION ENSUITE, AU MIEUX, avec ce qui reste du budget. Si la
         purge a tout consomme, on ne touche pas au reseau et on le DIT :
         'no_time' n'est pas 'no_token'. */
      let strava = { attempted: false, revoked: false, reason: 'no_token' };
      if (!tokenRead) strava = { attempted: false, revoked: false, reason: 'token_unreadable' };
      else if (token) {
        const left = Math.min(DELETE_STRAVA_BUDGET_MS,
          (started + DELETE_TOTAL_BUDGET_MS) - Date.now());
        if (!(left > 0)) strava = { attempted: false, revoked: false, reason: 'no_time' };
        else {
          try { strava = await C.revokeStravaToken(token, Date.now() + left); }
          catch (e) { strava = { attempted: true, revoked: false, reason: 'error' }; }
        }
      }

      const rem = purge.remaining;
      /* COMPLET = mesure, pas deduction : le controle par relecture a abouti,
         il ne reste rien pour CE profil, aucune suppression unitaire n'a
         echoue, et la pierre tombale est bien posee.
         LES INVITATIONS ILLISIBLES NE COMPTENT PAS. Elles n'appartiennent a
         aucun profil identifiable : les imputer a celui-ci rendait le 404 --
         le seul controle de fin recommande -- litteralement inatteignable,
         pour ce profil comme pour tous les autres, et cela pour toujours.
         Elles restent un avertissement, global, plus bas.
         LA PIERRE TOMBALE, ELLE, COMPTE : sans elle, un code residuel peut
         encore ressusciter le profil, et ce n'est pas une suppression. */
      const complete = !!(rem.checked && tombstone
        && !rem.profile && !rem.token && rem.nonces === 0 && rem.invites === 0
        && !purge.failed.profile && !purge.failed.token
        && !purge.failed.nonces && !purge.failed.invites);

      /* Ce qui merite un coup d'oeil d'Enzo, en clair. Codes courts, aucune
         valeur secrete, aucun chemin de stockage. */
      const warnings = [];
      if (!tombstone) warnings.push('pierre_tombale_absente');
      if (!strava.revoked) warnings.push('strava_non_revoque:' + strava.reason);
      /* GLOBAL, et le suffixe le dit : ces documents ne sont pas un residu de
         ce profil-ci, ils sont dans le magasin, tous profils confondus. */
      if (purge.unreadable_invites) warnings.push('invitations_illisibles_globales:' + purge.unreadable_invites);
      if (purge.truncated) warnings.push('enumeration_tronquee');
      if (!rem.checked) warnings.push('verification_impossible');

      console.log('[strava] admin | action : delete | profil :', id,
        '| complet :', complete ? 'oui' : 'non',
        '| pierre tombale :', tombstone ? 'posee' : 'ABSENTE',
        '| strava revoque :', strava.revoked ? 'oui' : 'non',
        '| motif strava :', strava.reason);

      const payload = {
        id: id,
        complete: complete,
        verified: !!rem.checked,
        /* true = le profil est desormais INJOIGNABLE, quoi qu'il reste :
           aucun code d'invitation residuel ne peut le recreer. */
        tombstone: tombstone,
        deleted: purge.deleted,
        scanned: purge.scanned,
        remaining: {
          profile: rem.profile, token: rem.token,
          nonces: rem.nonces, invites: rem.invites
        },
        unreadable_invites: purge.unreadable_invites,
        /* true = le document de profil a ete GARDE volontairement, parce
           qu'il reste des objets a viser. C'est lui qui rend le rejeu
           possible : ne le supprime pas a la main. */
        kept_profile: !!purge.kept_profile,
        strava: { attempted: strava.attempted, revoked: strava.revoked, reason: strava.reason },
        warnings: warnings
      };
      /* PAS DE SUCCES SILENCIEUX PARTIEL : une suppression incomplete sort en
         500 avec le detail de ce qui reste, pour qu'un script qui ne lit que
         le code HTTP ne la prenne pas pour un succes. */
      if (!complete) return C.json(500, Object.assign({ ok: false, error: 'incomplete' }, payload));
      return C.json(200, Object.assign({ ok: true }, payload));
    }

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

      /* PROFIL SUPPRIME : l'invitation est ecrite, mais 'join' la refusera --
         la pierre tombale prime, et c'est ce qui empeche un profil supprime
         de revenir a la vie. Emettre un code qui ne peut pas fonctionner sans
         le dire serait un piege : on le SIGNALE, sans rien decider a la place
         d'Enzo (il lui suffit d'un 'create' pour rouvrir l'identifiant).
         Une lecture en echec est signalee comme un profil supprime :
         fail-closed, on ne promet pas ce qu'on n'a pas verifie. */
      let deletedMark = true;
      try {
        const t = await C.readProfileTombstone(event, id);
        deletedMark = (t.state !== 'none');
      } catch (e) { deletedMark = true; }

      // Le lien est le chemin principal pour une personne non technique. Si
      // l'origine du site n'est pas connue du runtime, on rend le code seul
      // plutot qu'une URL fausse.
      const origin = C.siteOrigin();
      console.log('[strava] admin | action : invite | profil :', id,
        '| profil existant :', existing ? 'oui' : 'non',
        '| profil supprime :', deletedMark ? 'oui' : 'non', '| jours :', days);
      return C.json(201, {
        ok: true,
        code: code,
        code_shown_once: true,
        url: origin ? (origin + '/?invite=' + code) : '',
        expires_at: new Date(expMs).toISOString(),
        profile_id: id,
        profile_exists: !!existing,
        /* true = cet identifiant a ete supprime : 'join' refusera ce code
           tant qu'un 'create' explicite n'aura pas leve la marque. */
        profile_deleted: deletedMark
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

      /* LEVEE DE LA PIERRE TOMBALE, et c'est le SEUL endroit ou elle a lieu.
         Un identifiant supprime doit pouvoir resservir, mais seulement sur un
         geste explicite d'Enzo, authentifie par ADMIN_KEY.
         APRES l'ecriture du document, jamais avant : la lever d'abord et
         echouer ensuite rouvrirait la porte aux codes residuels sans qu'aucun
         profil n'existe pour les recevoir.
         Si la levee echoue, on le DIT : 'join' continuerait de refuser toutes
         les invitations de ce profil, et rien dans la reponse ne l'aurait
         laisse deviner.
         LIMITE, dite : la levee ne PURGE AUCUNE INVITATION. Toute invitation
         encore valable pour cet identifiant redevient utilisable ici. Rejouer
         'delete' jusqu'a 404 purge ce qui est VISIBLE, mais ce 404 dit
         seulement qu'aucune invitation n'etait visible au moment du rejeu :
         l'enumeration list() peut etre en retard. Le seul filet complet est
         l'EXPIRATION : 30 jours au plus apres l'emission (INVITE_TTL_DAYS_MAX).
         D'ou la consigne (docs/suppression-profil.md, « Recreer plus tard ») :
         ne recreer un identifiant supprime que 30 jours apres sa derniere
         invitation, ou prendre un autre identifiant.
         purgeProfileData n'est pas employee ici : elle efface aussi le
         jeton, les nonces et le document de profil, et un 'create' qui la
         lancerait devrait gerer une purge incomplete. */
      let cleared = false;
      try { cleared = await C.clearProfileTombstone(event, id); }
      catch (e) { cleared = false; }

      console.log('[strava] admin | action : create | profil :', id, '| actif : oui',
        '| pierre tombale levee :', cleared ? 'oui' : 'non');
      return C.json(201, {
        ok: true, key: fresh.key, key_shown_once: true,
        tombstone_cleared: cleared,
        profile: C.publicProfile(doc)
      });
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
