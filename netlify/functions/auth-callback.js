'use strict';
/* =====================================================================
   auth-callback — appele par Strava en redirection.

   Aucun en-tete n'est possible sur cette navigation : l'authentification
   repose donc entierement sur le `state` signe emis par auth-start
   (HMAC derive du materiel de hachage DU PROFIL + nonce a usage unique +
   expiration). State absent, falsifie, expire ou rejoue -> refus.

   MULTI-PROFILS. Le state porte l'identifiant du profil, mais celui-ci
   n'est retenu qu'apres verification de la signature avec le secret de ce
   profil : le profil reste un RESULTAT, jamais une entree de confiance.
   Consequence : un callback ne peut ecrire le jeton que dans l'espace du
   profil qui a reellement initie la demande. Le nonce est lui aussi
   consomme sous ce profil, donc un nonce d'autrui est introuvable.

   Ne renvoie JAMAIS le token : ni en corps, ni en URL, ni en cookie.
   Il est ecrit dans Netlify Blobs, puis on redirige vers l'app avec un
   simple code de resultat.
   ===================================================================== */
const C = require('./lib/common.js');

const ALLOWED = ['GET'];

/* Motifs de StoreError qui signalent un magasin non initialisable (par
   opposition a 'io', une simple panne d'operation). Ils sont tous rapportes
   a l'app sous le code 'blobs'. */
function isInitFailure(e) {
  return C.isStoreError(e) && (e.reason === 'unconfigured' || e.reason === 'lambda' || e.reason === 'module');
}

/* Codes de resultat volontairement grossiers : ils n'exposent aucun detail
   de configuration ni de reponse Strava. */
function back(status) {
  const origin = C.siteOrigin();
  return {
    statusCode: 302,
    headers: {
      'Location': (origin || '') + '/?strava=' + encodeURIComponent(status),
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer'
    },
    body: ''
  };
}

exports.handler = async function (event) {
  try {
    const method = ((event && event.httpMethod) || '').toUpperCase();
    if (method !== 'GET') return C.methodNotAllowed(ALLOWED);

    const q = (event && event.queryStringParameters) || {};

    // L'utilisateur a refuse l'autorisation cote Strava.
    if (q.error) return back('denied');

    /* 1. Lecture NON AUTHENTIFIEE du state : elle n'autorise rien, elle
          designe seulement le document de profil a charger. */
    const claim = C.parseStatePayload(q.state);
    if (!claim) return back('state');

    /* 2. Chargement du profil REVENDIQUE.

          OUI, CETTE LECTURE PRECEDE L'AUTHENTIFICATION, ET C'EST VOULU.
          Un identifiant fourni par le client sert ici a lire un document
          dans Blobs avant que quoi que ce soit ait ete verifie. Ce n'est
          pas un oubli : c'est structurellement inevitable. Une redirection
          depuis Strava ne peut porter aucun en-tete, donc la seule chose
          dont on dispose est le state ; et pour verifier sa signature il
          faut d'abord le secret du profil, donc son document. L'ordre ne
          peut pas etre inverse.

          CE QUI LA REND INOFFENSIVE :
            - claim.p a deja traverse isProfileId (parseStatePayload) et le
              retraverse dans readProfile : pas de traversee de chemin.
            - la lecture n'AUTORISE rien. Elle ne fait que designer la cle
              publique de verification ; l'authentification, c'est l'etape
              3, et elle exige une signature que seul le serveur peut
              produire.
            - profil inconnu, desactive, ou signature fausse donnent la
              MEME redirection 'state'. Aucun oracle d'existence : c'est ce
              que verifie le banc, ecart de temps compris.
            - rien n'est ecrit avant l'etape 3, donc un state forge ne
              laisse aucune trace.

          CE QU'ELLE COUTE : une lecture Blobs par requete, sans limitation
          de debit, declenchable par un inconnu. C'est le plafond du risque
          et il est assume -- une lecture, pas une ecriture, pas un scrypt.
          Si un jour ce cout devenait genant, le remede serait un limiteur
          de debit sur cette fonction, pas un changement de cet ordre.

          Un profil inconnu ou desactive donne le meme resultat qu'un state
          invalide : 'state'. */
    let profile = null;
    try {
      profile = await C.readProfile(event, claim.p);
    } catch (e) {
      return back(isInitFailure(e) ? 'blobs' : 'unavailable');
    }
    if (!profile || profile.active === false) return back('state');

    /* 3. VERIFICATION de la signature avec le secret de ce profil. C'est
          ici, et seulement ici, que le profil devient authentifie. */
    const parsed = C.parseState(profile, q.state);   // signature + coherence + expiration
    if (!parsed) return back('state');

    let nonce = null;
    try {
      nonce = await C.takeNonce(event, profile.id, parsed.n);   // consommation : usage unique
    } catch (e) {
      // Redirection : on ne peut pas renvoyer de JSON, on distingue tout de
      // meme le stockage non configure d'une panne d'E/S.
      return back(isInitFailure(e) ? 'blobs' : 'unavailable');
    }
    if (!nonce) return back('state');                                  // inconnu ou deja utilise
    if (typeof nonce.e === 'number' && Date.now() > nonce.e) return back('state');

    if (typeof q.code !== 'string' || !q.code) return back('code');

    const clientId = C.env('STRAVA_CLIENT_ID');
    const clientSecret = C.env('STRAVA_CLIENT_SECRET');
    if (!clientId || !clientSecret) {
      console.warn('[strava] identifiants d application absents : echange impossible.');
      return back('config');
    }

    let data = null;
    try {
      data = await C.exchangeCode(clientId, clientSecret, q.code);
    } catch (e) {
      // On ne journalise ni la reponse de Strava ni le secret.
      console.error('[strava] echange du code refuse ou injoignable');
      return back('exchange');
    }
    if (!data || typeof data.refresh_token !== 'string' || !data.refresh_token) {
      console.error('[strava] reponse d echange inexploitable');
      return back('exchange');   // rien n'est stocke
    }

    try {
      await C.writeToken(event, profile.id, {
        refresh_token: data.refresh_token,
        access_token: (typeof data.access_token === 'string') ? data.access_token : '',
        expires_at: Number(data.expires_at) || 0,
        athlete_id: (data.athlete && Number(data.athlete.id)) || 0,
        scope: (typeof q.scope === 'string') ? q.scope : '',
        connected_at: new Date().toISOString()
      });
    } catch (e) {
      return back(isInitFailure(e) ? 'blobs' : 'store');
    }

    return back('ok');
  } catch (e) {
    console.error('[strava] auth-callback : erreur inattendue');
    return back('error');
  }
};
