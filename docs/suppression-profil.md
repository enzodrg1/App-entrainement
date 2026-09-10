# Effacer toutes les données de quelqu'un — procédure complète

**C'est une obligation légale, pas un confort.** Quand un ami demande l'effacement de
ses données, il faut aller au bout des trois moitiés : le serveur, son téléphone, et
Strava. Aucune des trois ne fait le travail des autres.

Ce document est écrit pour quelqu'un qui a tout oublié depuis six mois. Suis les étapes
dans l'ordre, elles se supposent l'une l'autre.

---

## Avant de commencer : où sont les données, exactement

| Où | Quoi | Qui peut l'effacer |
|---|---|---|
| **Netlify Blobs** (serveur) | document de profil, jeton Strava, nonces OAuth, invitations, **pierre tombale** | Enzo, via `admin-profiles` |
| **Le téléphone de la personne** (`localStorage`) | séances cochées, journal (ressentis et **gênes**), courses, plan importé, clé d'appareil, caches | **elle seule**, depuis l'app |
| **Le compte Strava de la personne** | l'autorisation accordée à l'application | elle, ou la révocation tentée par la suppression serveur |

Le serveur **ne peut pas** atteindre le téléphone. Les données de santé sont sur le
téléphone. Une suppression serveur seule ne règle donc **rien** de l'essentiel.

### La pierre tombale, en une phrase

Supprimer un profil laisse derrière lui **un seul objet**, minuscule et sans aucune
donnée : une marque `deleted/<id>` qui dit « cet identifiant a été supprimé ». Elle est
écrite **avant** que quoi que ce soit ne soit effacé, et `join` la consulte à chaque
tentative. C'est elle qui garantit qu'un code d'invitation oublié quelque part ne pourra
plus jamais recréer le profil — même si la purge est interrompue, même si l'énumération
du magasin n'a pas encore vu la dernière invitation émise. Seule l'action `create` la
lève, et c'est volontaire : réutiliser un identifiant supprimé doit être un geste
explicite (voir « Cas particuliers »).

---

## PowerShell : trois pièges, à lire une fois

1. Sous Windows, **`curl` est un alias de `Invoke-WebRequest`** et n'accepte pas les
   options de `curl` (`-H`, `-d`…). Les commandes ci-dessous n'utilisent pas `curl`.
2. **Guillemets simples obligatoires** autour des valeurs. Avec des guillemets doubles,
   PowerShell interprète `$`, et une clé qui en contient part tronquée — l'erreur
   ressemble alors à « clé refusée » et fait chercher au mauvais endroit.
3. **`Invoke-RestMethod` cache le corps des réponses d'erreur.** Sur Windows PowerShell
   5.1 (la version installée ici), tout code HTTP non-2xx lève une exception et
   n'affiche que « Le serveur distant a retourné une erreur : (500) Erreur interne du
   serveur. ». `$_.ErrorDetails` est **vide**. Or toute cette procédure repose sur la
   lecture du corps : c'est lui qui dit ce qui reste. La fonction d'aide ci-dessous
   règle le problème une fois pour toutes — **utilise-la pour tous les appels.**

Pose ceci dans la session PowerShell, en une fois :

```powershell
$site  = 'https://coaching-trail.netlify.app'
$admin = '<colle ici ADMIN_KEY>'

function Invoke-Admin {
  param([Parameter(Mandatory=$true)][hashtable]$Corps)
  $uri  = "$site/.netlify/functions/admin-profiles"
  $ent  = @{ 'x-admin-key' = $admin }
  $json = $Corps | ConvertTo-Json -Compress
  try {
    $r = Invoke-WebRequest -Method Post -Uri $uri -Headers $ent `
           -ContentType 'application/json' -Body $json -UseBasicParsing
    Write-Host "HTTP $([int]$r.StatusCode)" -ForegroundColor Green
    $r.Content
  } catch {
    $rep = $_.Exception.Response
    if ($rep -ne $null) {
      $code = [int]$rep.StatusCode
      $flux = New-Object System.IO.StreamReader($rep.GetResponseStream())
      $corpsErreur = $flux.ReadToEnd()
      $flux.Close()
      Write-Host "HTTP $code" -ForegroundColor Yellow
      $corpsErreur
    } else {
      Write-Host "Pas de reponse du serveur : $($_.Exception.Message)" -ForegroundColor Red
    }
  }
}
```

Elle affiche **toujours** le code HTTP puis le corps, succès ou erreur. Le contre-exemple
ci-dessous a été vérifié par exécution sur PowerShell 5.1.26100.9278 ; les corps qui le
précèdent sortent de la vraie fonction, exécutée sur banc avec un magasin simulé (Strava
injoignable, une suppression de nonce en échec au premier passage) :

```
--- 400 : confirm_id qui ne repete pas id ---
HTTP 400
{"error":"bad_request","field":"confirm_id"}

--- 409 : profil encore actif ---
HTTP 409
{"error":"profile_active"}

--- 500 : suppression partielle ---
HTTP 500
{"ok":false,"error":"incomplete","id":"partiel","complete":false,"verified":true,
 "tombstone":true,
 "deleted":{"profile":false,"token":true,"nonces":0,"invites":1},
 "scanned":{"nonces":1,"invites":1},
 "remaining":{"profile":true,"token":false,"nonces":1,"invites":0},
 "unreadable_invites":0,"kept_profile":true,
 "strava":{"attempted":true,"revoked":false,"reason":"network"},
 "warnings":["strava_non_revoque:network"]}

--- 200 : le rejeu finit le travail ---
HTTP 200
{"ok":true,"id":"partiel","complete":true,"verified":true,"tombstone":true,
 "deleted":{"profile":true,"token":false,"nonces":1,"invites":0},
 "scanned":{"nonces":1,"invites":0},
 "remaining":{"profile":false,"token":false,"nonces":0,"invites":0},
 "unreadable_invites":0,"kept_profile":false,
 "strava":{"attempted":false,"revoked":false,"reason":"no_token"},
 "warnings":["strava_non_revoque:no_token"]}
   (deleted.token vaut false : le jeton etait deja parti au premier passage.
    Ce n'est pas un echec — remaining.token, lui, dit qu'il ne reste rien.)

--- 404 : controle final, et identifiant inconnu ---
HTTP 404
{"error":"not_found","tombstone":true}

--- contre-exemple : Invoke-RestMethod nu ---
EXCEPTION : Le serveur distant a retourné une erreur : (500) Erreur interne du serveur.
ErrorDetails : []
```

Le contre-exemple est la raison d'être de la fonction : sans elle, tu ne vois **rien**
de ce qui reste.

*(Si tu préfères `curl.exe` — le vrai curl, avec le `.exe`, pas l'alias — il imprime le
corps tel quel sur toutes les erreurs. Mais le JSON en ligne de commande se fait
massacrer par les guillemets de PowerShell : la fonction ci-dessus évite ce piège.)*

`ADMIN_KEY` vit dans les variables d'environnement Netlify
(*Site configuration › Environment variables*). **Ne la mets jamais dans un fichier du
dépôt, ni dans un message.**

---

## Étape 1 — Retrouver l'identifiant exact du profil

```powershell
(Invoke-Admin @{ action = 'list' } | ConvertFrom-Json).profiles |
  Format-Table id, name, active, created_at
```

Note l'`id` **au caractère près**. Il te sera demandé deux fois à l'étape 3, et une
faute de frappe est refusée (c'est voulu).

**Ce qui reste après cette étape :** tout. Cette commande ne fait que lire.

---

## Étape 2 — Désactiver le profil

Un profil actif **ne se supprime pas d'un seul geste**. La désactivation est le temps de
réflexion, et elle ferme déjà l'accès : la clé de la personne cesse immédiatement de
fonctionner.

```powershell
$id = 'julie'          # remplace par l'identifiant relevé à l'étape 1

Invoke-Admin @{ action = 'set-active'; id = $id; active = $false }
```

**Ce qui reste après cette étape :** absolument toutes les données, serveur et
téléphone. Seul l'accès est coupé. **C'est réversible** (`active = $true` le rouvre).

C'est ici qu'il faut s'arrêter si tu as le moindre doute. L'étape suivante, non.

---

## Étape 3 — Supprimer le profil et ses données serveur ⚠ IRRÉVERSIBLE

```powershell
Invoke-Admin @{ action = 'delete'; id = $id; confirm_id = $id }
```

`confirm_id` doit répéter `id` **à l'identique**. La comparaison est stricte : pas de
`trim`, pas de casse ignorée. `'Julie'`, `' julie'` ou `'julie '` sont refusés — ce
garde-fou existe pour qu'une faute de frappe ne détruise pas le mauvais profil.

### Lire la réponse

```json
{
  "ok": true, "complete": true, "id": "julie", "verified": true,
  "tombstone": true,
  "deleted":   { "profile": true, "token": true, "nonces": 2, "invites": 1 },
  "scanned":   { "nonces": 2, "invites": 4 },
  "remaining": { "profile": false, "token": false, "nonces": 0, "invites": 0 },
  "unreadable_invites": 0,
  "kept_profile": false,
  "strava": { "attempted": true, "revoked": true, "reason": "ok" },
  "warnings": []
}
```

* `complete: true` → **il ne reste rien** côté serveur pour ce profil, **et** la pierre
  tombale est posée. Ce n'est pas une déduction : `remaining` est **relu** dans le
  magasin après la suppression, et la marque est **relue** après avoir été écrite.
* `tombstone: true` → le profil est désormais **injoignable, quoi qu'il reste**. Aucun
  code d'invitation, même oublié dans un SMS, ne peut le recréer. C'est la garantie la
  plus forte de toute la procédure, et elle ne dépend ni de la réussite de la purge, ni
  de la fraîcheur de l'énumération du magasin.
* `tombstone: false` → **la seule ligne qui doit t'inquiéter.** La marque n'a pas pu être
  écrite (panne de stockage) : tant qu'elle manque, un code résiduel pourrait ressusciter
  le profil. `complete` vaut alors `false` et la réponse sort en `500`. **Rejoue.**
* `verified: false` → le contrôle par relecture n'a pas pu se faire. Ne conclus rien,
  **rejoue la commande** : le rejeu reprend le travail là où il s'est arrêté (voir plus
  bas).
* `deleted.token: true` → il y avait bien un jeton Strava, et il a été supprimé. `false`
  veut dire « il n'y en avait pas » (ou « je n'ai pas pu vérifier qu'il y en avait un »),
  jamais « la suppression a échoué » — ça, c'est `remaining.token`.
* `kept_profile: true` → il restait quelque chose, alors le **document de profil a été
  gardé volontairement**. C'est lui qui rend le rejeu possible. **Ne le supprime pas à
  la main.** Le profil reste désactivé : il ne donne accès à rien.
* `warnings` liste ce qui mérite ton attention. Les codes possibles :
  * `pierre_tombale_absente` → cf. `tombstone: false` ci-dessus. **Le plus important.**
  * `strava_non_revoque:<motif>` → tableau des motifs à l'étape 5. **Tous ne veulent pas
    dire « il reste une autorisation à retirer ».**
  * `invitations_illisibles_globales:<n>` → des documents d'invitation sont abîmés
    **quelque part dans le magasin**. Ils n'appartiennent à **aucun** profil identifiable
    (c'est justement pourquoi ils sont illisibles) : ce n'est **pas** un résidu de celui
    que tu viens de supprimer, et ça **ne bloque pas** `complete`. Voir « Cas
    particuliers » ;
  * `enumeration_tronquee` → plus de 2000 entrées balayées. Ne devrait jamais arriver à
    cette échelle ; rejoue la commande ;
  * `verification_impossible` → cf. `verified` ci-dessus.

### HTTP 500 `error: "incomplete"` — suppression partielle

Ce n'est pas un plantage. Le corps dit exactement ce qui reste dans `remaining` (et la
fonction d'aide te le montre — c'est tout l'intérêt).

**Rejoue exactement la même commande.** Le rejeu n'est pas seulement sans danger, il est
**utile** : il reprend le travail. Deux cas :

* le document de profil a été gardé (`kept_profile: true`) → le rejeu le retrouve
  normalement ;
* le document a déjà disparu (état laissé par une version antérieure de la fonction) →
  le rejeu **sonde d'abord les résidus** et les purge. Il ne répond `404` que s'il n'y a
  vraiment plus rien.

Autrement dit : **tant qu'il reste quelque chose, un `delete` ne répond jamais `404`.**
C'est ce qui rend le contrôle ci-dessous fiable.

### Vérifier qu'il ne reste vraiment rien

Le `list` de l'étape 1 **ne suffit pas** : il ne voit ni les nonces, ni les invitations.
Le seul contrôle qui couvre tout, c'est de rejouer la suppression :

```powershell
Invoke-Admin @{ action = 'delete'; id = $id; confirm_id = $id }
```

* `HTTP 404 not_found` → il ne reste **rien** : ni document, ni jeton, ni nonce, ni
  invitation visant ce profil. C'est le résultat attendu, et c'est une bonne nouvelle.
  Le corps porte `tombstone` : il doit valoir `true`.
* `HTTP 200 complete: true` → il restait des résidus, ils viennent d'être purgés.
  Rejoue encore une fois : tu dois obtenir `404`.
* `HTTP 500` → lis `remaining` et `tombstone`, et recommence quand la cause est levée.

Ce contrôle **aboutit toujours** si le magasin répond : un document d'invitation abîmé
ailleurs dans le magasin ne l'empêche plus (c'était un défaut, il est corrigé).

### Réponses d'erreur

| Code | Corps | Ce que ça veut dire |
|---|---|---|
| 400 | `bad_request`, `field: confirm_id` | `confirm_id` ne répète pas `id` exactement |
| 400 | `bad_request`, `field: id` | l'identifiant ne respecte pas la grammaire des profils |
| 404 | `not_found`, `tombstone` | ni document, ni résidu : il n'y a rien à supprimer. La pierre tombale est posée quand même — **y compris sur un identifiant qui n'a jamais existé** (voir « Cas particuliers ») |
| 409 | `profile_active` | tu as sauté l'étape 2 |
| 409 | `profile_unreadable` | le document de profil est abîmé (voir plus bas) |
| 401 | `unauthorized` | `x-admin-key` absente ou fausse |
| 503 | `unavailable` | `ADMIN_KEY` absente ou trop courte côté Netlify |
| 503 | `blobs` (+ `reason`) | panne de stockage serveur — **rien n'a été supprimé**, réessaie |

Le corps d'un `503 blobs` porte toujours un champ `reason` en plus de `error`, par
exemple `{"error":"blobs","reason":"io"}`. Quatre valeurs, à ne pas confondre :

| `reason` | Ce que ça veut dire | Réessayer ? |
|---|---|---|
| `io` | le magasin répond mais la lecture ou l'écriture a échoué | oui, c'est en général passager |
| `unconfigured` | le magasin n'a pas pu être initialisé | non, il y a une configuration à corriger |
| `lambda` | aucun contexte Blobs — la fonction ne tourne pas dans le mode attendu | non, c'est un problème de déploiement |
| `module` | le paquet `@netlify/blobs` est absent du bundle de la fonction | non, c'est un problème de déploiement |

Dans les quatre cas **rien n'a été supprimé**. En revanche la pierre tombale, elle, a
pu être posée avant la panne : c'est voulu (fail-closed), le profil reste injoignable
tant que la suppression n'a pas abouti. Réessaie la même commande.

**Ce qui reste après cette étape :**

* côté serveur : **rien** pour ce profil, si `complete: true` — hormis la pierre
  tombale, qui ne contient aucune donnée et dont c'est le rôle de rester ;
* sur son téléphone : **tout** — c'est l'étape 4, et le serveur ne peut pas la faire ;
* chez Strava : l'autorisation, **sauf** si `strava.revoked: true`.

**Ce qui est irréversible :** tout ce que cette commande a supprimé. Il n'y a pas de
corbeille, pas de sauvegarde serveur. Le profil est effacé pour de bon.

---

## Étape 4 — La personne supprime les données de son téléphone

**Cette étape, seule la personne peut la faire, et sur chacun de ses appareils.** Les
séances cochées, le journal (ressentis et **gênes**) et les courses ne sortent jamais de
son téléphone.

À lui transmettre tel quel :

> 1. Ouvre l'app, onglet **Zones**, descends tout en bas.
> 2. Si tu veux garder une copie : onglet **Journal › Exporter**, d'abord.
> 3. Tape **« Supprimer mes données de cet appareil »** et lis la confirmation en
>    entier : elle dit ce qui est effacé **et ce qui ne l'est pas**.
> 4. Il n'y a **qu'une seule question**. Elle porte sur ce qui est enregistré sous ton
>    profil, et sur rien d'autre.
> 5. Lis le compte rendu jusqu'au bout. S'il commence par **« ⚠ Suppression
>    INCOMPLÈTE »**, recommence. S'il contient une ligne **« À VÉRIFIER »**, la
>    suppression a bien eu lieu, mais un point n'a pas pu être mesuré : lis-le. S'il dit
>    **« L'app n'a rien trouvé à supprimer »**, c'est qu'il n'y avait rien sous ton
>    profil sur cet appareil : rien n'a été effacé, et c'est dit tel quel plutôt que
>    présenté comme un succès.
> 6. Recommence sur **chaque appareil** où tu as utilisé l'app.

Ça fonctionne **hors-ligne** : aucun appel réseau.

### Ce que cette suppression ne fait pas

**Elle ne touche pas aux copies « sans profil ».** Certaines données peuvent exister sur
un appareil sous des clés qui ne portent aucun identifiant de profil : ce sont les copies
d'avant la mise à jour de l'app (chantier 3, étape 1). **Cette version ne sait pas les
effacer, et aucun chemin de code ne le peut** — la seule écriture hors préfixe de tout le
fichier est l'ancre `profile-id`, et elle ne prend même pas de nom de clé en paramètre.

En pratique, **un seul appareil au monde en porte : celui d'Enzo.** Les amis arrivent par
invitation, et un appareil qui rejoint n'écrit jamais que sous son préfixe. Ces copies
**restent donc sur le téléphone d'Enzo**, gelées, jusqu'à une version prévue pour les
effacer.

Une **seconde question** (« Effacer aussi tes anciennes copies ? ») a existé pendant le
développement de l'étape 5. **Elle a été retirée**, sur arbitrage d'Enzo : quatre passes
de test y ont trouvé quatre défauts différents, tous nés du croisement entre « à qui sont
ces copies », « les a-t-on gardées » et « qu'a-t-on réussi à effacer ». Le dernier était
sérieux : un effacement qui échoue laissait les copies en place, l'app affirmait ensuite
qu'elles n'étaient pas à la personne, et la marque écrite au passage refermait
définitivement la porte. Si tu croises une capture d'écran ou une note qui mentionne
cette seconde question, **elle est périmée**.

Ce qui reste du mécanisme, et c'est voulu : la suppression **ferme le repli** sur ces
copies (elle écrit `<profil>:legacy-owner` à `false`). Fermer le repli n'efface rien —
c'est ce qui garantit que les données ne réapparaissent pas juste après que la personne a
demandé leur effacement.

**État de l'app après coup, et c'est voulu :** même profil, app vide. L'app ne repasse
pas par l'écran de première connexion — l'ancre `profile-id`, qui ne contient qu'un
identifiant et aucune donnée de santé, est conservée. Rien ne réapparaît au rechargement.
Si la personne veut revenir plus tard, une nouvelle clé d'appareil saisie dans Zones
suffit — **mais si tu as fait l'étape 3, ce profil n'existe plus, et une invitation ne
suffira pas non plus** : il faut d'abord rouvrir l'identifiant avec `create` (voir « Cas
particuliers »), sans quoi `join` refusera le code.

**Si l'app lui affichait des données venues de ses anciennes copies** (cas d'un
téléphone utilisé avant la mise à jour), le compte rendu commence par le dire : « Ce que
l'app t'affichait venait de tes anciennes copies SANS PROFIL… ». C'est plus honnête que
d'annoncer « aucune donnée n'était enregistrée sous ton profil » à quelqu'un qui voyait
son historique une seconde plus tôt — les deux phrases sont vraies, mais dans cet
ordre-là seulement.

Le panneau **« Vérifier mes données »** (onglet Zones) dit ensuite la vérité sur ce qui
reste sur l'appareil. **Il ne dit jamais à qui sont les copies sans profil**, ni dans un
sens ni dans l'autre : il décrit ce que l'app en fait — « l'app ne les affiche pas, ne
les modifie pas et ne les supprime pas ». C'est vrai pour quelqu'un arrivé par invitation
(ces copies ne sont pas les siennes) **comme** pour Enzo après sa propre suppression
(elles sont les siennes, mais le repli est fermé). L'app ne sait pas distinguer les deux
cas, et une version antérieure affirmait le premier dans les deux — elle disait donc à
Enzo que ses propres données n'étaient pas les siennes.

Il dit **la même chose que le compte rendu**, y compris sur les téléphones dont le
stockage ne sait pas retirer une clé et se contente d'en écraser le contenu : une clé
vidée y est comptée pour ce qu'elle est, une absence.

**Ce qui reste après cette étape :** rien sous son profil sur cet appareil-là. Les copies
sans profil, elles, restent (voir « Ce que cette suppression ne fait pas »). Les autres
appareils sont intacts.

---

## Étape 5 — Vérifier l'autorisation Strava

L'app avait longtemps un défaut : la déconnexion Strava (`auth-logout`) ne supprime que
la copie serveur du jeton, et l'autorisation reste active dans le compte Strava de la
personne. L'étape 3 tente désormais de la révoquer — **au mieux**, jamais en bloquant la
suppression, et **après** la purge des données (une panne de Strava ne doit pas manger
le temps de l'effacement).

Le motif renvoyé dans `strava.reason` ne veut pas dire la même chose selon les cas :

| `reason` | Ce que ça veut dire | Ce que tu fais |
|---|---|---|
| `ok` | l'autorisation a été retirée côté Strava | rien |
| `no_token` | **aucun jeton côté serveur : il n'y avait rien à révoquer.** Soit l'app n'a jamais été autorisée, soit la personne s'était déconnectée dans l'app (ce qui ne révoque pas) | rien à faire de ton côté. Par précaution, dis-lui de jeter un œil à ses applications Strava |
| `no_time` | la purge a consommé le budget : aucune tentative réseau | fais-lui vérifier |
| `config` | les identifiants Strava manquent côté Netlify **et** le jeton stocké était périmé : aucune tentative n'a eu lieu | corrige les variables d'environnement pour les prochaines fois ; fais-lui vérifier pour celle-ci |
| `token_unreadable` | le jeton n'a pas pu être lu | fais-lui vérifier |
| `no_access_token` | jeton inexploitable | fais-lui vérifier |
| `reauth` | Strava a refusé le jeton : il était probablement déjà expiré ou révoqué | fais-lui vérifier |
| `timeout`, `network`, `quota`, `upstream`, `bad_response`, `error` | Strava n'a pas confirmé la révocation | fais-lui vérifier |

**`config` ne couvre pas tous les cas de configuration manquante, et c'est voulu.** Il
n'apparaît que si le jeton stocké était périmé *et* inutilisable en l'état. Si le jeton
d'accès était encore frais, la révocation est tentée quand même — elle n'a pas besoin des
identifiants d'application pour aboutir —, et si elle échoue tu verras `reauth`,
`network`, `timeout`… et non `config`. Autrement dit : **une variable Netlify manquante
peut se manifester sous n'importe lequel de ces motifs.** Si tu vois un motif inattendu,
vérifie `STRAVA_CLIENT_ID` / `STRAVA_CLIENT_SECRET` avant de conclure à une panne de
Strava.

« Fais-lui vérifier » veut dire :
**strava.com › Paramètres › Mes applications** → <https://www.strava.com/settings/apps>
→ retirer l'accès de l'application.

Toi, Enzo, tu ne peux pas le faire à sa place une fois le jeton supprimé : il n'existe
plus. **C'est pour ça qu'il faut lire `warnings` à l'étape 3 avant de clore le dossier.**

---

## Étape 6 — Clore

Récapitule à la personne, par écrit :

* profil serveur supprimé le … (avec `complete: true` **et** `tombstone: true`, puis un
  `404` au contrôle) ;
* données de ses appareils : supprimées par elle sur *n* appareils ;
* autorisation Strava : révoquée automatiquement / retirée à la main par elle ;
* ce qui subsiste ailleurs et qui n'appartient pas à l'app : ses activités **sur Strava
  lui-même** (l'app n'en a jamais été propriétaire), et les exports JSON qu'elle ou toi
  auriez enregistrés hors de l'app.

Ce dernier point compte : si tu as reçu un fichier `suquet-sauvegarde.json` d'elle pour
discuter du plan, **il faut le supprimer aussi**. Il contient son journal.

---

## Cas particuliers

**Document de profil abîmé — deux cas à ne pas confondre.** Si le document est du JSON
**valide** mais de forme invalide (champs manquants), tu reçois `409 profile_unreadable`.
Si son JSON est carrément **illisible**, la lecture échoue au niveau du stockage et tu
reçois `503 blobs`. Dans les deux cas **rien n'a été supprimé**, et le même chemin de
réparation s'applique.

**« profile_unreadable » (409).** On ne peut pas vérifier que le profil était désactivé,
et l'effacer sur la foi d'un document illisible serait supprimer à l'aveugle. Chemin de
réparation :

```powershell
# 1. recreer un document propre par-dessus (l'action 'create' ne voit pas
#    un document invalide et ecrit un document neuf)
Invoke-Admin @{ action = 'create'; id = $id; name = 'a supprimer' }
# 2. puis reprendre a l'etape 2 (set-active false), puis l'etape 3.
```

La clé renvoyée par ce `create` est à jeter : elle n'existe que le temps de reprendre la
procédure.

**Profil déjà supprimé.** Un second `delete` répond `404 not_found` **s'il ne reste
vraiment rien**. S'il restait des résidus, il les purge et répond `200` — c'est
justement le contrôle recommandé plus haut. Dans les deux cas, rien n'est recréé.

**Invitations illisibles (`invitations_illisibles_globales:<n>`).** Un document
d'invitation abîmé n'est supprimé par personne : il ne dit pas quel profil il vise, et
l'effacer pourrait dépasser le profil visé. Conséquences concrètes :

* il **ne peut ressusciter aucun profil** : `join` refuse un document d'invitation qui
  ne passe pas sa validation, et il n'en existe pas d'autre chemin ;
* il **n'appartient à aucun profil** — c'est précisément ce qu'on ne sait pas de lui. Il
  n'est donc **plus** compté comme un résidu du profil que tu supprimes : `complete: true`
  et le `404` final restent atteignables. (Ce n'était pas le cas avant : une seule
  invitation abîmée bloquait à `500` la suppression de **tous** les profils, y compris
  ceux qui n'avaient jamais existé, et pour toujours. C'était un défaut, pas une
  précaution.)
* l'avertissement, lui, reste affiché à chaque `delete`, avec le suffixe `_globales`
  pour rappeler qu'il ne parle pas du profil visé ;
* les invitations expirent d'elles-mêmes (30 jours au maximum). Si le rappel persiste
  au-delà, c'est un document réellement corrompu : à retirer à la main dans l'interface
  Netlify Blobs, sous `invites/`.

**Recréer plus tard un profil du même identifiant.** C'est possible et propre, mais il y
a **un geste obligatoire** : la pierre tombale bloque `join` tant qu'elle est là. Une
invitation seule ne suffit donc plus.

```powershell
# 1. rouvrir l'identifiant (leve la pierre tombale)
Invoke-Admin @{ action = 'create'; id = $id; name = 'Julie' }
#    -> verifie "tombstone_cleared": true dans la reponse. La cle renvoyee ici
#       est a jeter : l'invitation ci-dessous en regenerera une.
# 2. inviter la personne normalement
Invoke-Admin @{ action = 'invite'; id = $id }
#    -> "profile_deleted": false confirme que le code fonctionnera.
```

Si tu émets une invitation **sans** avoir fait le `create`, la réponse porte
`"profile_deleted": true` : le code sera refusé par `join`, silencieusement (le refus est
volontairement indiscernable, la personne ne verra qu'« invitation invalide »).

**`delete` sur un identifiant qui n'a jamais existé.** Il répond `404` — et il pose quand
même la pierre tombale. C'est assumé : le serveur ne peut pas distinguer « cet
identifiant n'a jamais servi » de « une suppression précédente a laissé des résidus que
l'énumération ne voit pas encore », et fail-closed est le bon choix quand l'autre issue
est un profil qui ressuscite. Conséquence pratique : si tu as tapé un identifiant par
erreur et que tu veux t'en servir plus tard, passe par `create` (ci-dessus).

**Suppression seulement côté téléphone, sans toucher au serveur.** C'est un cas légitime
(changement de téléphone, prêt d'un appareil) : l'étape 4 seule suffit, elle ne prévient
pas le serveur et ne casse rien. Le profil continue d'exister ; la personne pourra
revenir avec une clé d'appareil.

**Appareil « ambigu » (plusieurs profils dessus, ou aucun qui corresponde).** L'app ne
choisit pas à la place de la personne : elle affiche un écran qui indique **combien** de
profils ont été trouvés — sans les nommer, parce que cet écran s'affiche avant toute
identification et qu'un appareil peut être familial ou prêté — et propose deux sorties :
rejoindre avec une invitation (ce qui tranche
définitivement et rend visibles les données rangées sous ce profil), ou continuer en
lecture seule. Rejoindre **n'efface rien** et ne touche pas aux données des autres
profils. Si elle te demande une invitation dans ce cas, émets-la pour **son** profil
existant (`action = 'invite'`, même `id`) : sa clé est régénérée, ses données ne bougent
pas, et si les anciennes copies sans profil de cet appareil étaient déjà les siennes,
elle les retrouve.

Cet écran ne s'affiche que si l'app a **réellement pu lire** le stockage. Si une lecture
échoue ou si le profil enregistré est corrompu, l'app démarre en lecture seule **sans**
proposer de rejoindre : proposer de rejoindre à quelqu'un dont on n'a pas su lire
l'historique, ce serait lui proposer de passer par-dessus.

---

## Ce qu'aucune étape ne fait

* **`auth-logout` ne révoque rien.** Il supprime la copie serveur du jeton, c'est tout.
  C'est délibéré : c'est l'outil de dépannage d'Enzo, et il ne doit pas obliger à
  repasser par l'écran d'autorisation Strava à chaque fois. La révocation n'a lieu qu'à
  la **suppression**.
* **La désactivation n'efface rien.** Elle ferme l'accès, elle ne supprime aucune donnée.
* **La rotation de clé n'efface rien** non plus. Elle change le moyen d'accès, pas les
  données.
* **Aucune commande ne touche les données d'un autre profil.** C'est l'invariant de
  l'étape 5 du chantier 3 : la suppression énumère et vérifie chaque clé contre le
  préfixe du profil visé avant d'y toucher — y compris quand un identifiant est le
  préfixe d'un autre (`ju` ne touche jamais `julie`). La pierre tombale suit la même
  règle : `delete ju` pose `deleted/ju`, jamais `deleted/julie`.
* **La pierre tombale n'efface rien et ne contient rien.** Elle ne fait qu'interdire à
  `join` de recréer l'identifiant. Elle ne bloque ni `list`, ni `set-active`, ni
  `rotate`, et elle n'empêche pas une clé d'accès existante de fonctionner — de toute
  façon, après une suppression complète, il n'existe plus de document de profil pour la
  vérifier.
* **Rien de tout cela ne touche `auth-logout`.** Il reste ce qu'il était.
