'use strict';
/* =====================================================================
   auth-callback — appele par Strava en redirection.

   Aucun en-tete n'est possible sur cette navigation : l'authentification
   repose donc entierement sur le `state` signe emis par auth-start
   (HMAC derive de APP_ACCESS_KEY + nonce a usage unique + expiration).
   State absent, falsifie, expire ou rejoue -> refus.

   Ne renvoie JAMAIS le token : ni en corps, ni en URL, ni en cookie.
   Il est ecrit dans Netlify Blobs, puis on redirige vers l'app avec un
   simple code de resultat.
   ===================================================================== */
const C = require('./lib/common.js');

const ALLOWED = ['GET'];

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

    const key = C.accessKey();
    if (!key) {
      console.warn('[strava] APP_ACCESS_KEY absente : callback refuse.');
      return back('unavailable');
    }

    const q = (event && event.queryStringParameters) || {};

    // L'utilisateur a refuse l'autorisation cote Strava.
    if (q.error) return back('denied');

    const parsed = C.parseState(key, q.state);   // signature + expiration
    if (!parsed) return back('state');

    let nonce = null;
    try {
      nonce = await C.takeNonce(parsed.n);       // consommation : usage unique
    } catch (e) {
      // Redirection : on ne peut pas renvoyer de JSON, on distingue tout de
      // meme le stockage non configure d'une panne d'E/S.
      return back(C.isStoreError(e) && e.reason === 'unconfigured' ? 'blobs' : 'unavailable');
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
      await C.writeToken({
        refresh_token: data.refresh_token,
        access_token: (typeof data.access_token === 'string') ? data.access_token : '',
        expires_at: Number(data.expires_at) || 0,
        athlete_id: (data.athlete && Number(data.athlete.id)) || 0,
        scope: (typeof q.scope === 'string') ? q.scope : '',
        connected_at: new Date().toISOString()
      });
    } catch (e) {
      return back(C.isStoreError(e) && e.reason === 'unconfigured' ? 'blobs' : 'store');
    }

    return back('ok');
  } catch (e) {
    console.error('[strava] auth-callback : erreur inattendue');
    return back('error');
  }
};
