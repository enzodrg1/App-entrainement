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

    let token = null;
    try {
      token = await C.readToken();
    } catch (e) {
      console.error('[strava] lecture du stockage impossible');
      return C.json(503, { error: 'unavailable' });
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
