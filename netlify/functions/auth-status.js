'use strict';
/* =====================================================================
   auth-status — etat de la connexion Strava.
   Renvoie UNIQUEMENT { connected, since }. Jamais de token, jamais
   d'identifiant d'athlete, jamais de portee detaillee.
   ===================================================================== */
const C = require('./lib/common.js');

const ALLOWED = ['GET', 'OPTIONS'];

exports.handler = async function (event) {
  try {
    const method = ((event && event.httpMethod) || '').toUpperCase();
    if (method === 'OPTIONS') return C.preflight(ALLOWED);
    if (method !== 'GET') return C.methodNotAllowed(ALLOWED);

    const denied = C.checkKey(event);
    if (denied) return denied;
    // A partir d'ici l'appelant est authentifie : le detail de diagnostic
    // qui suit n'est jamais visible d'un inconnu.

    // Aligne sur auth-start : une configuration incomplete se dit, elle ne
    // se deguise pas en « service indisponible ».
    const missing = C.configMissing();
    if (missing.length) {
      console.warn('[strava] variables d environnement manquantes :', missing.join(', '));
      return C.json(500, { error: 'config', missing: missing });
    }

    let token = null;
    try {
      token = await C.readToken(event);
    } catch (e) {
      // 'unconfigured' = Blobs non provisionne ; 'io' = lecture en echec.
      return C.storeFailure(e);
    }

    if (!token || typeof token.refresh_token !== 'string' || !token.refresh_token) {
      return C.json(200, { connected: false });
    }
    return C.json(200, {
      connected: true,
      since: (typeof token.connected_at === 'string') ? token.connected_at : null
    });
  } catch (e) {
    console.error('[strava] auth-status : erreur inattendue');
    return C.json(500, { error: 'server_error' });
  }
};
