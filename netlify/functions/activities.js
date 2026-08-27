'use strict';
/* =====================================================================
   activities - lecture des activites Strava recentes.

   Le serveur TRANSPORTE, il n'arbitre pas : aucun filtrage par type ici.
   C'est le client qui decidera ce qui coche une seance et ce qui s'affiche
   a part.

   ---------------------------------------------------------------------
   CONTRAT DE REPONSE (le client B2/B3 est ecrit contre lui : stable)
   ---------------------------------------------------------------------
   204  (pas de corps)            reponse au preflight OPTIONS. Le preflight
        n'exige PAS la cle d'appareil : un preflight CORS ne peut pas porter
        d'en-tete personnalise.

   200  { connected:false, activities:[] }
        Aucun jeton stocke. Etat NORMAL, pas une panne : l'app doit rester
        pleinement utilisable sans Strava. Aucun autre champ n'est present.

   200  { connected:true, days, after, count, truncated, partial, stop,
          activities:[ ... ] }
        days      nombre de jours couverts APRES bornage serveur
                  (defaut 90, minimum 1, maximum 120)
        after     borne basse, en secondes epoch
        count     activities.length
        truncated liste incomplete, quelle qu'en soit la cause
        partial   liste incomplete a cause d'un ECHEC de lecture : une page
                  n'a pas pu etre obtenue et ce qui avait deja ete lu est
                  renvoye quand meme, plutot que jete
        stop      cause exacte, c'est le champ a lire pour choisir le
                  message affiche :
                    'complete'   tout a ete lu       truncated=false partial=false
                    'page_limit' limite de 2 pages   truncated=true  partial=false
                    'budget'     le TEMPS de l'invocation a manque, sans
                                 qu'une page ait echoue : le cas courant est
                                 des appels qui repondent, mais trop lentement
                                 pour en enchainer un de plus. Un gel du
                                 processus au-dela de la reserve par appel
                                 (GC, demarrage a froid) aboutit ici aussi,
                                 meme si l'appel n'a pas repondu : le temps a
                                 bien ete consomme. Reduire days ne changera
                                 pas grand-chose ; reessayer, si.
                                                     truncated=true  partial=false
                    'error'      une page n'a pas abouti : Strava n'a pas
                                 repondu dans le plafond par appel, a refuse
                                 la page (quota, 5xx) ou a renvoye un corps
                                 inexploitable. Chaque appel etant plafonne
                                 SOUS l'echeance globale, un Strava muet
                                 arrive normalement ici et non en 'budget' --
                                 sauf gel du processus, cf. ci-dessus.
                                                     truncated=true  partial=true
                  Invariants garantis : truncated === (stop !== 'complete')
                  et partial === (stop === 'error'). 'budget' n'est JAMAIS
                  etiquete 'error' : une liste trop longue a charger et une
                  panne Strava sont deux problemes distincts.
        activities ordre renvoye par Strava, tel quel. Le serveur ne trie
                  pas : le client ne doit RIEN supposer de l'ordre.
        truncated, partial et stop sont TOUJOURS presents.
        count peut valoir 0 avec stop:'budget' : le temps a manque avant
        meme la premiere page. C est un 200, pas une erreur ; la liste
        est simplement vide et signalee incomplete.

   Chaque activite ne contient QUE ces 12 champs, jamais d'autres :
     id, name, sport_type, type, date, distance, elevation, moving_time,
     elapsed_time, average_speed, average_heartrate, max_heartrate
   Tout champ absent, non fini, d'un type inattendu ou (pour date) d'une
   date impossible vaut null -- y compris id et date. Une activite non
   datable reste dans la liste : la perdre en silence serait pire.
   Unites : distance en metres, elevation en metres, temps en secondes,
   average_speed en m/s, date en 'AAAA-MM-JJ' LOCALE (deja localisee par
   Strava, aucun fuseau n'est recalcule ici).

   ERREURS -- table complete, aucune autre forme n'est emise
     401 { error:'unauthorized' }           cle d'appareil absente ou fausse
     405 { error:'method_not_allowed' }     + en-tete Allow
     500 { error:'config', missing:[noms] } STRAVA_CLIENT_ID / _SECRET absents
     503 { error:'unavailable' }            APP_ACCESS_KEY absente ou trop
          courte cote serveur. ATTENTION : ce corps n'a PAS de champ reason.
     503 { error:'blobs', reason:'module'|'lambda'|'unconfigured'|'io' }
                                            panne de stockage serveur
     409 { error:'strava', reason:'reauth' }      reconnexion necessaire
     409 { error:'strava', reason:'token_lost' }  jeton renouvele non persiste
          apres deux ecritures ET une relecture de controle qui confirme que
          la base ne l'a pas (ou qui echoue). La connexion est perdue :
          reconnexion necessaire. Distinct de 'blobs' : ce n'est pas qu'un
          disque. Si la relecture montre que l'ecriture avait abouti, aucune
          erreur n'est emise et la lecture se poursuit normalement.
     429 { error:'strava', reason:'quota' }       quota Strava (100 / 15 min)
     504 { error:'strava', reason:'timeout' }       Strava n a pas repondu
          dans le delai. Emis UNIQUEMENT si aucune activite n a pu etre
          lue : des qu une page a ete obtenue, un timeout ulterieur
          devient un 200 avec partial ou stop:'budget'.
     502 { error:'strava', reason:'network'|'upstream'|'bad_response' }
     500 { error:'server_error' }                 jamais d'exception nue
   Le 409 est volontairement distinct du 401 : 401 = cle d'appareil refusee,
   409 = Strava demande une reconnexion. Le client ne doit pas confondre.

   INTERDITS ABSOLUS dans la reponse : access_token, refresh_token, athlete /
   athlete_id, start_latlng, end_latlng, map, polyline, et tout champ hors
   liste blanche. Ce sont des donnees de localisation personnelles.
   ===================================================================== */
const C = require('./lib/common.js');

const ALLOWED = ['GET', 'OPTIONS'];

const DEFAULT_DAYS = 90;    // le bloc d'Enzo fait 17 semaines : 60 jours perdraient novembre
const MIN_DAYS = 1;
const MAX_DAYS = 120;
const PER_PAGE = 200;
const MAX_PAGES = 2;        // 400 activites au plus, jamais de boucle non bornee
const NAME_MAX = 300;
const DAY_S = 86400;

/* Budget de temps de TOUTE l'invocation. La plate-forme coupe vers 10 s et
   repond alors du HTML, hors de ce contrat : on tient dans 9 s par
   construction, echeance calculee des l'entree et descendue jusqu'a chaque
   appel reseau.

   DIMENSIONNEMENT, et pourquoi ces trois valeurs vont ensemble :
     - TOTAL_BUDGET_MS 9000 : une seconde de marge sous la coupure a 10 s.
     - C.CALL_RESERVE_MS 750 : chaque appel reseau est plafonne STRICTEMENT
       sous le temps restant. Un appel qui pend expire donc alors qu'il reste
       ~750 ms, ce qui permet de dire « Strava n'a pas repondu » plutot que
       « je manque de temps » -- sans cette reserve, un Strava muet et une
       lecture trop longue produisaient le meme diagnostic, et le mauvais.
       750 ms : bien au-dessus de l'imprecision de setTimeout (quelques ms),
       assez petit pour ne rien changer au chemin normal (rafraichissement
       ~0,5 s + deux pages ~1 s chacune, plafonds effectifs > 6 s).
     - PAGE_MIN_BUDGET_MS 2000 : en dessous, on n'entame plus une page. Une
       page entamee dispose ainsi toujours d'au moins 1250 ms de plafond,
       soit plus qu'un temps de reponse normal de Strava (< 1 s) : on evite
       d'etiqueter « Strava n'a pas repondu » ce qui n'est qu'une fin de
       budget. On rend alors ce qu'on a, avec truncated et stop:'budget'. */
const TOTAL_BUDGET_MS = 9000;
const PAGE_MIN_BUDGET_MS = 2000;

/* Codes HTTP par motif d'echec Strava. Un motif inconnu -> 502. */
const STRAVA_STATUS = {
  reauth: 409,
  token_lost: 409,
  quota: 429,
  timeout: 504,
  network: 502,
  upstream: 502,
  bad_response: 502,
  config: 500
};

/* days borne cote serveur : la valeur vient du client, elle n'est pas de
   confiance. Non numerique -> defaut ; hors bornes -> ramene dans les bornes. */
function boundDays(raw) {
  // Netlify passe des chaines ; on tolere un nombre par robustesse.
  const src = (typeof raw === 'number') ? raw : (typeof raw === 'string' ? raw.trim() : '');
  if (src === '') return DEFAULT_DAYS;
  const n = Number(src);
  if (!Number.isFinite(n)) return DEFAULT_DAYS;
  const i = Math.floor(n);
  if (i < MIN_DAYS) return MIN_DAYS;
  if (i > MAX_DAYS) return MAX_DAYS;
  return i;
}

/* ---------- liste blanche ----------
   On ne nettoie pas l'objet Strava : on en CONSTRUIT un autre, champ par
   champ. Aucun champ inconnu ne peut donc traverser, quoi que Strava ajoute
   a son format demain. */
function numOrNull(v) {
  return (typeof v === 'number' && Number.isFinite(v)) ? v : null;
}
function strOrNull(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s) return null;
  return s.length > max ? s.slice(0, max) : s;
}
/* start_date_local est DEJA localisee par Strava : on tronque, on ne
   recalcule aucun fuseau (une conversion ici decalerait les sorties du soir
   ou du petit matin d'un jour).
   La forme ne suffit pas : '2026-13-45', '2026-02-30' ou '0000-00-00'
   passent une regex mais donnent Invalid Date cote client. On valide donc
   par aller-retour : la date doit se reconstruire a l'identique. */
function localDate(v) {
  if (typeof v !== 'string' || v.length < 10) return null;
  const d = v.slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return null;
  const t = new Date(d + 'T00:00:00Z');
  if (!(t instanceof Date) || !Number.isFinite(t.getTime())) return null;
  // Ecarte 2026-02-30 (glisse au 2 mars) comme 0000-00-00.
  return (t.toISOString().slice(0, 10) === d) ? d : null;
}
function pickActivity(a) {
  const o = (a && typeof a === 'object') ? a : {};
  return {
    id: numOrNull(o.id),
    name: strOrNull(o.name, NAME_MAX),
    sport_type: strOrNull(o.sport_type, 40),
    type: strOrNull(o.type, 40),
    date: localDate(o.start_date_local),
    distance: numOrNull(o.distance),
    elevation: numOrNull(o.total_elevation_gain),
    moving_time: numOrNull(o.moving_time),
    elapsed_time: numOrNull(o.elapsed_time),
    average_speed: numOrNull(o.average_speed),
    average_heartrate: numOrNull(o.average_heartrate),
    max_heartrate: numOrNull(o.max_heartrate)
  };
}

/* Reponse d'echec a partir d'un MOTIF deja determine. */
function stravaFailureByReason(reason) {
  // 'config' est deja intercepte plus haut par configMissingApi() ; par
  // securite on ne le deguise pas en panne reseau.
  if (reason === 'config') return C.json(500, { error: 'config', missing: C.configMissingApi() });
  return C.json(STRAVA_STATUS[reason] || 502, { error: 'strava', reason: reason });
}
function stravaFailure(e) {
  return stravaFailureByReason(C.isStravaError(e) ? e.reason : 'upstream');
}

exports.handler = async function (event) {
  // Echeance globale : posee AVANT tout appel reseau, valable pour
  // l'invocation entiere (rafraichissement compris).
  const deadline = Date.now() + TOTAL_BUDGET_MS;
  try {
    const method = ((event && event.httpMethod) || '').toUpperCase();

    // 1. Preflight AVANT la cle : un preflight CORS ne peut pas porter
    //    d'en-tete personnalise, il doit rester ouvert.
    if (method === 'OPTIONS') return C.preflight(ALLOWED);
    // 2. Cle d'appareil : fail-closed, avant tout traitement et avant meme
    //    de dire si la methode est bonne (aucun signal a un inconnu).
    const denied = C.checkKey(event);
    if (denied) return denied;
    // 3. Methode, seulement une fois l'appelant authentifie.
    if (method !== 'GET') return C.methodNotAllowed(ALLOWED);

    // Lire des activites n'exige aucune URL de redirection : on ne verifie
    // que ce dont cette fonction depend vraiment.
    const missing = C.configMissingApi();
    if (missing.length) {
      console.warn('[strava] variables d environnement manquantes :', missing.join(', '));
      return C.json(500, { error: 'config', missing: missing });
    }

    const q = (event && event.queryStringParameters) || {};
    const days = boundDays(q.days);
    const after = Math.floor(Date.now() / 1000) - (days * DAY_S);

    let token = null;
    try {
      token = await C.readToken(event);           // event : invariant connectLambda
    } catch (e) {
      return C.storeFailure(e);
    }
    // Absence de connexion = etat normal, pas une panne.
    if (!token || typeof token.refresh_token !== 'string' || !token.refresh_token) {
      return C.json(200, { connected: false, activities: [] });
    }

    // Rafraichissement SI necessaire, puis ecriture, puis seulement l'API.
    // On s'arrete net sur echec : jamais d'appel d'API avec un jeton non
    // persiste. 'token_lost' (409) et 'blobs' (503) ne disent pas la meme
    // chose -- voir ensureAccessToken.
    let access = '';
    try {
      const ensured = await C.ensureAccessToken(event, token, deadline);
      access = ensured.access_token;
    } catch (e) {
      if (C.isStoreError(e)) return C.storeFailure(e);
      console.error('[strava] rafraichissement impossible | motif :', (C.isStravaError(e) && e.reason) || 'inconnu');
      return stravaFailure(e);
    }

    const raw = [];
    let truncated = false, partial = false, stop = 'complete';
    for (let page = 1; page <= MAX_PAGES; page++) {
      // Budget epuise : on n'entame pas une page qu'on ne pourra pas finir.
      if ((deadline - Date.now()) < PAGE_MIN_BUDGET_MS) {
        truncated = true; stop = 'budget';
        console.warn('[strava] budget de temps epuise avant la page', page);
        break;
      }
      let batch;
      try {
        batch = await C.fetchActivitiesPage(access, after, page, PER_PAGE, deadline);
        if (!Array.isArray(batch)) throw new Error('not_an_array');
      } catch (e) {
        const reason = C.isStravaError(e) ? e.reason : 'bad_response';
        /* Un timeout a DEUX causes possibles, et elles n'appellent pas le
           meme message. Chaque appel est plafonne STRICTEMENT sous l'echeance
           (C.CALL_RESERVE_MS) : un appel qui PEND expire donc alors qu'il
           reste du temps -> c'est bien Strava qui s'est tu, 'error'.
           Si en revanche l'echeance est deja franchie au moment de la reprise,
           c'est que le temps a ete reellement CONSOMME par des appels qui, eux,
           ont repondu -> 'budget'. Enzo doit lire « Strava n'a pas repondu »
           dans le premier cas et « liste trop longue a charger » dans le
           second : deux problemes differents, deux remedes differents. */
        const parBudget = (reason === 'timeout') && ((deadline - Date.now()) <= 0);
        console.error('[strava] lecture des activites interrompue | page :', page,
          '| motif :', reason, '| cause :', parBudget ? 'budget' : 'echec');
        // Rien n'a encore ete lu : il n'y a rien a sauver, on dit l'echec.
        if (!raw.length) return stravaFailureByReason(reason);
        // Sinon on rend ce qui a ete lu plutot que de le jeter.
        truncated = true;
        partial = !parBudget;                     // budget epuise != echec
        stop = parBudget ? 'budget' : 'error';
        break;
      }
      for (let i = 0; i < batch.length; i++) raw.push(batch[i]);
      if (batch.length < PER_PAGE) break;         // derniere page atteinte
      if (page === MAX_PAGES) { truncated = true; stop = 'page_limit'; }
    }

    const activities = raw.map(pickActivity);
    console.log('[strava] activites lues :', activities.length, '| jours :', days,
      '| tronque :', truncated ? 'oui' : 'non', '| partiel :', partial ? 'oui' : 'non', '| arret :', stop);
    return C.json(200, {
      connected: true,
      days: days,
      after: after,
      count: activities.length,
      truncated: truncated,
      partial: partial,
      stop: stop,
      activities: activities
    });
  } catch (e) {
    console.error('[strava] activities : erreur inattendue');
    return C.json(500, { error: 'server_error' });
  }
};
