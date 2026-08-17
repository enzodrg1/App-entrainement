'use strict';
/* =====================================================================
   auth-start — prepare la connexion Strava.

   Ne renvoie PAS de 302 : une navigation de redirection ne peut pas porter
   d'en-tete, et faire transiter la cle d'appareil en parametre d'URL la
   ferait fuir dans les journaux, l'historique et le Referer.
   Le client appelle donc cette fonction en POST avec l'en-tete x-app-key,
   recoit { url }, et ouvre lui-meme cette URL.
   ===================================================================== */
const crypto = require('crypto');
const C = require('./lib/common.js');

const ALLOWED = ['POST', 'OPTIONS'];

exports.handler = async function (event) {
  try {
    const method = ((event && event.httpMethod) || '').toUpperCase();
    if (method === 'OPTIONS') return C.preflight(ALLOWED);
    if (method !== 'POST') return C.methodNotAllowed(ALLOWED);

    const denied = C.checkKey(event);
    if (denied) return denied;
    // A partir d'ici, l'appelant est authentifie.

    const clientId = C.env('STRAVA_CLIENT_ID');
    const origin = C.siteOrigin();
    // Presence seulement : la VALEUR du secret n'est ni lue ici, ni renvoyee.
    const missing = C.configMissing();
    if (missing.length) {
      console.warn('[strava] variables d environnement manquantes :', missing.join(', '));
      return C.json(500, { error: 'config', missing: missing });
    }

    const nonce = crypto.randomBytes(18).toString('hex');
    const exp = Date.now() + C.STATE_TTL_MS;
    try {
      await C.putNonce(nonce, exp);
    } catch (e) {
      return C.storeFailure(e);
    }

    const state = C.signState(C.accessKey(), nonce, exp);
    const redirectUri = origin + '/.netlify/functions/auth-callback';
    const url = 'https://www.strava.com/oauth/authorize'
      + '?client_id=' + encodeURIComponent(clientId)
      + '&redirect_uri=' + encodeURIComponent(redirectUri)
      + '&response_type=code'
      + '&approval_prompt=auto'
      + '&scope=' + encodeURIComponent('activity:read_all')
      + '&state=' + encodeURIComponent(state);

    return C.json(200, { url: url, expires: exp });
  } catch (e) {
    console.error('[strava] auth-start : erreur inattendue');
    return C.json(500, { error: 'server_error' });
  }
};
