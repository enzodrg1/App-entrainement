# App d'entraînement trail — contexte projet

## Ce que c'est

PWA d'entraînement personnelle pour Enzo, coureur de trail. Déployée sur Netlify
(`coaching-trail.netlify.app`), dépôt GitHub `enzodrg1/App-entrainement`.
Usage quotidien sur iPhone, installée sur l'écran d'accueil.

**Objectif en cours :** L'Adonis Trail, 26 km / 1121 m D+, le 6 décembre 2026.

## Stack — non négociable

- **HTML/CSS/JS vanilla dans un seul `index.html`.** Pas de framework, pas de bundler,
  pas d'étape de build. Le déploiement se fait par simple push GitHub → Netlify.
- Service worker (`sw.js`) : network-first sur le HTML, cache-first sur les assets.
- Persistance : `localStorage`, avec fallback `window.storage` si présent.
- Mobile-first. Respecter les `env(safe-area-inset-*)`.

## Identité visuelle — à préserver

```
--bg:#0E1B16  --panel:#15251E  --panel2:#1B2E26
--ink:#EFE9DB --muted:#8FA69A  --dim:#5C7268
--orange:#FF6B35  --moss:#86B49A  --amber:#E0A83E
```
Typo : Barlow Condensed (titres, uppercase) + Barlow (corps). Esprit montagne/trail.

## Invariants — à ne JAMAIS casser

1. **Le kilométrage hebdomadaire est TOUJOURS calculé comme la somme des `km` des
   séances de la semaine** (fonction `weekKm()`). Ne jamais faire confiance à un champ
   `km` déclaré au niveau de la semaine. Cette incohérence s'est déjà produite et a été
   corrigée — elle ne doit pas revenir.
2. **Les clés `localStorage` `tgcm-done`, `tgcm-log`, `tgcm-races` ne doivent pas être
   renommées.** Elles contiennent l'historique réel d'Enzo (séances faites, journal de
   ressenti, blessures). Toute migration doit les préserver.
3. **Le nom du cache dans `sw.js` doit être incrémenté à chaque modification.** Sinon la
   mise à jour ne s'applique pas sur le téléphone. Problème déjà rencontré.
4. **L'app doit rester pleinement fonctionnelle hors-ligne.** Toute intégration réseau
   (Strava, API) est un bonus, jamais un prérequis au fonctionnement.
5. **Aucun secret dans le code client.** Clés API et tokens vivent exclusivement dans les
   variables d'environnement Netlify et les fonctions serverless.

## Contexte santé — important

Enzo a trois problèmes physiques actifs (tendinopathie d'Achille gauche, instabilité des
tendons fibulaires à la malléole droite, syndrome de l'essuie-glace au genou). L'app
comporte des sections « Vigilance » rendues avec un style d'alerte ambre, et un suivi des
gênes dans le journal.

**Ces éléments ne sont pas décoratifs.** Ne jamais supprimer, masquer ou banaliser un
avertissement de sécurité ou une section « Vigilance » lors d'un refactor.

## Workflow d'équipe

- **Agent principal (orchestrateur)** : découpe le travail, délègue, arbitre, valide.
- **`developpeur`** : implémente. Ne s'auto-valide jamais.
- **`testeur`** : vérifie, tente de casser, remonte les bugs. Ne corrige pas lui-même.

Boucle : orchestrateur → développeur → testeur → (bugs ?) → développeur → testeur → OK.

Ne jamais considérer une tâche comme terminée sans un passage du `testeur`.

## Limites — demander à Enzo, ne pas décider seul

- Toute modification du **contenu d'entraînement** (séances, volumes, intensités,
  progression) : c'est du ressort du coaching, pas du développement. L'app est un
  contenant, elle n'invente pas le plan.
- Toute action sur GitHub/Netlify ayant un effet en production.
- Toute manipulation de clés API ou de secrets.
- Toute suppression de données utilisateur.
