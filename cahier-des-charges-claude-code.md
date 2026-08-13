# Cahier des charges — Évolution de l'app d'entraînement

**À donner à Claude Code.** Projet existant : PWA statique déployée sur Netlify, dépôt GitHub `enzodrg1/App-entrainement`, site `coaching-trail.netlify.app`.

---

## Contexte

Enzo, 22 ans, coureur de trail à Limoges. L'app actuelle est un **fichier `index.html` unique** (~112 Ko, HTML + CSS + JS vanilla, aucun framework, aucun build) contenant :

- Un plan d'entraînement de 17 semaines codé en dur dans une constante JS `WEEKS`
- 4 onglets : **Plan** (calendrier + courbe de charge + carte du jour + barre de progression), **Courses** (calendrier de courses, ajout/suppression), **Journal** (ressenti, allure/FC, sommeil, FC repos, gênes physiques), **Zones** (allures/FC + fiches méthodo)
- Persistance via `localStorage` (avec fallback `window.storage` si présent)
- Un service worker (`sw.js`) en network-first pour le HTML, cache-first pour les assets
- Manifest PWA + icônes, installable sur écran d'accueil iOS/Android

**Objectif de la refonte : deux chantiers.**

---

## Chantier 1 — Sortir le plan du code (PRIORITÉ ABSOLUE)

### Problème actuel

Le plan est codé en dur dans `index.html`. Chaque ajustement (une séance déplacée, un volume revu) oblige à remplacer un fichier de 112 Ko sur GitHub via l'interface web. C'est le principal point de friction.

### Solution demandée

**1. Externaliser le plan dans `plan.json`**

Extraire la constante `WEEKS` (ainsi que `ZONES`, `SEED_RACES`, `RACE_DAY` et les métadonnées de course affichées dans l'en-tête) vers un fichier `plan.json` à la racine, chargé au démarrage via `fetch('./plan.json')`.

Prévoir un champ `version` (entier) et `updated` (date ISO) à la racine du JSON.

**2. Import de plan depuis l'interface — LA fonctionnalité clé**

Ajouter dans l'app (onglet Zones ou un nouvel onglet Réglages) une zone « Mettre à jour le plan » :

- Un `<textarea>` où coller un JSON de plan
- Un bouton **Valider** qui : parse le JSON, vérifie sa structure (voir schéma ci-dessous), affiche un résumé avant application (« 17 semaines, 119 jours, du 10/08 au 06/12 — appliquer ? »), puis le stocke dans `localStorage` sous la clé `plan-override`
- Un bouton **Revenir au plan par défaut** qui supprime l'override et recharge `plan.json`
- Support aussi de l'import par **fichier** (`<input type="file" accept=".json">`)

**Logique de chargement au démarrage :** si `plan-override` existe dans `localStorage` ET que sa `version` est ≥ à celle de `plan.json`, on l'utilise ; sinon on charge `plan.json`. Afficher discrètement quelque part la version du plan actif et sa date.

**Validation stricte à l'import**, avec messages d'erreur clairs et refus d'appliquer un plan invalide :
- `weeks` est un tableau non vide
- chaque semaine a `id`, `label`, `phase`, et `days` (tableau)
- chaque jour a `d` (date ISO `YYYY-MM-DD` valide), `t` (∈ `off|easy|qual|long|renfo|race`), `title`
- pas de dates en double sur l'ensemble du plan
- `det` est un objet dont chaque valeur est un tableau de chaînes

**3. Invariant à préserver impérativement**

Le kilométrage hebdomadaire doit **toujours** être calculé comme la somme des `km` des séances de la semaine (fonction `weekKm()` déjà présente). Ne jamais faire confiance à un champ `km` déclaré au niveau de la semaine — c'est une source d'incohérence déjà rencontrée et corrigée.

**4. Ne pas casser les données existantes**

Les clés `localStorage` actuellement utilisées sont `tgcm-done`, `tgcm-log`, `tgcm-races`. **Les conserver telles quelles** (ne pas renommer), les données du journal et les séances cochées doivent survivre à la migration. Les entrées du journal sont indexées par date ISO — un changement de plan ne doit pas les effacer.

### Schéma de `plan.json`

```json
{
  "version": 8,
  "updated": "2026-08-12",
  "race": {
    "name": "L'Adonis Trail",
    "eyebrow": "Objectif · perf + index UTMB",
    "subtitle": "26 km · 1121 m D+ · Roquefort-sur-Soulzon · dim. 6 déc",
    "date": "2026-12-06"
  },
  "zones": [
    ["Récup / easy", "~5:15 – 5:25", "142 – 150"]
  ],
  "races": [
    {
      "id": "seed-adonis",
      "name": "L'Adonis Trail",
      "date": "2026-12-06",
      "dist": "26 km",
      "dplus": "1121 m",
      "notes": "OBJECTIF",
      "seed": true,
      "target": true
    }
  ],
  "weeks": [
    {
      "id": 1,
      "label": "S1 · 10 → 16 août",
      "phase": "Reprise post-maladie",
      "days": [
        {
          "d": "2026-08-10",
          "t": "easy",
          "title": "Footing easy 7 km",
          "km": 7,
          "fc": "142-150",
          "pace": "5:15-5:25",
          "dplus": "300 m",
          "det": {
            "Séance": ["Ligne 1", "Ligne 2"],
            "Vigilance": ["Texte d'alerte"]
          }
        }
      ]
    }
  ]
}
```

Note : la section `det` est un objet ordonné dont les clés servent de titres de section dans la fiche de séance. La clé `Vigilance` est rendue avec un style d'alerte (ambre) — conserver ce comportement.

---

## Chantier 2 — Synchronisation Strava

### Objectif

Que les activités Strava d'Enzo remontent automatiquement dans l'app, pour comparer **prévu vs réalisé** sans saisie manuelle.

### Prérequis à créer (Enzo doit le faire)

1. Aller sur https://www.strava.com/settings/api et créer une application
2. Récupérer `Client ID` et `Client Secret`
3. Renseigner comme *Authorization Callback Domain* : `coaching-trail.netlify.app`

### Architecture demandée

L'hébergement est actuellement **statique**. Il faut ajouter des **Netlify Functions** (dossier `netlify/functions/`) car le `Client Secret` ne doit jamais se trouver dans le code client.

**Fonctions serverless à créer :**

- `auth-start` → redirige vers l'écran d'autorisation Strava (scope `activity:read_all`)
- `auth-callback` → échange le `code` contre `access_token` + `refresh_token`
- `activities` → appelle l'API Strava, rafraîchit le token si expiré, renvoie les activités

**Secrets** : `STRAVA_CLIENT_ID` et `STRAVA_CLIENT_SECRET` en variables d'environnement Netlify (jamais dans le dépôt).

**Stockage des tokens** : usage strictement mono-utilisateur. Utiliser Netlify Blobs, ou à défaut un cookie httpOnly sécurisé. Ne jamais exposer le `refresh_token` au client.

### Fonctionnalité côté app

**Rapprochement prévu / réalisé.** Pour chaque jour du plan, chercher une activité Strava à la même date. Si trouvée, afficher sur la carte du jour et dans la fiche de séance :

- Distance réelle, dénivelé, temps, allure moyenne, FC moyenne et max
- Une comparaison visuelle simple avec le prévu (ex. `≈ 12 km prévu → 11,8 km réalisé`)
- Cocher automatiquement la séance comme faite si une activité de course est trouvée ce jour-là — **mais laisser Enzo décocher manuellement** (la coche manuelle doit primer sur l'auto)

**Types d'activité** : ne considérer que `Run`, `TrailRun`, `Workout`. Les activités `Ride`, `Swim`, `WeightTraining` sont affichées séparément (utile : Enzo fait du vélo et de la natation en récupération) mais ne cochent pas une séance de course.

**Cas limites à gérer :**
- Plusieurs activités le même jour → les additionner et le signaler
- Séance faite avec un jour de décalage → ne PAS tenter de deviner, afficher l'activité à sa date réelle
- Pas de connexion / API indisponible → l'app doit rester **pleinement fonctionnelle hors-ligne** avec les données locales. La synchro Strava est un bonus, jamais un prérequis.
- Mettre en cache la dernière synchro dans `localStorage` pour éviter de rappeler l'API à chaque ouverture (rafraîchir au maximum toutes les 30 min, plus un bouton de synchro manuelle)

**Vie privée** : le site est public (URL Netlify sans authentification). Ne rien afficher de sensible sans réflexion, et ne pas exposer les tokens côté client.

---

## Contraintes générales

- **Pas de framework, pas de build step.** Rester en HTML/CSS/JS vanilla, comme actuellement. Le déploiement doit continuer à fonctionner par simple push GitHub → Netlify.
- **Conserver l'identité visuelle** : palette sombre (`--bg:#0E1B16`, `--orange:#FF6B35`, `--moss:#86B49A`), typographies Barlow Condensed (titres) et Barlow (corps), style « montagne/trail ».
- **Mobile-first**, utilisation quotidienne sur iPhone en PWA installée. Respecter les `env(safe-area-inset-*)`.
- **Incrémenter le nom du cache dans `sw.js`** à chaque modification, sinon les mises à jour ne s'appliquent pas (problème déjà rencontré).
- Le service worker doit rester **network-first sur le HTML** et ne jamais mettre en cache les réponses de l'API Strava.
- Garder l'export/import de sauvegarde existant, et y **inclure le plan actif**.

## Ordre de réalisation recommandé

1. Chantier 1 en entier (externalisation + import de plan) — c'est le gain immédiat
2. Vérifier que rien n'est cassé : données du journal préservées, calcul des km cohérent, PWA toujours installable
3. Chantier 2 (Strava), en commençant par l'OAuth seul, puis l'affichage des activités, puis le rapprochement

---

## Ce qui ne change pas

L'ajustement du contenu d'entraînement (décaler une séance, revoir un volume, réagir à une blessure) continue de se faire en conversation avec Claude, qui produit un JSON de plan à jour. L'app doit simplement rendre son application **triviale** : copier-coller dans le champ d'import, valider, terminé.
