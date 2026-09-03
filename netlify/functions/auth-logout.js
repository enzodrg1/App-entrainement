'use strict';
/* =====================================================================
   auth-logout — supprime le token stocke cote serveur POUR LE PROFIL
   authentifie, et lui seul.
   Protege par la cle d'acces, comme auth-start et auth-status.
   ===================================================================== */
const C = require('./lib/common.js');

const ALLOWED = ['POST', 'OPTIONS'];

exports.handler = async function (event) {
  try {
    const method = ((event && event.httpMethod) || '').toUpperCase();
    if (method === 'OPTIONS') return C.preflight(ALLOWED);
    if (method !== 'POST') return C.methodNotAllowed(ALLOWED);

    const auth = await C.checkKey(event);
    if (auth.denied) return auth.denied;

    try {
      await C.deleteToken(event, auth.profile.id);
    } catch (e) {
      return C.storeFailure(e);
    }
    return C.json(200, { connected: false });
  } catch (e) {
    console.error('[strava] auth-logout : erreur inattendue');
    return C.json(500, { error: 'server_error' });
  }
};
