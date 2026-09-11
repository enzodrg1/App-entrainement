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
du magasin n'a pas encore vu la dernière invitation émise. (Seul un code remis
*exactement pendant* la suppression demande une précaution : voir « Limite connue : une
invitation remise pendant la suppression », à l'étape 3.) Seule l'action `create` la
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

* `complete: true` → **plus rien de visible** côté serveur pour ce profil au moment de
  l'appel, **et** la pierre tombale est posée. Ce n'est pas une déduction : `remaining`
  est **relu** dans le magasin après la suppression, et la marque est **relue** après
  avoir été écrite. Mais les nonces et les invitations sont retrouvés par
  **énumération**, qui peut être en retard : une invitation émise juste avant peut ne pas
  encore y figurer. Le filet complet est l'expiration des invitations (30 jours au plus),
  voir « Recréer plus tard un profil du même identifiant » dans « Cas particuliers ».
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
  le rejeu **sonde d'abord les résidus** et les purge. Il ne répond `404` que s'il ne
  voit plus rien.

Autrement dit : **tant qu'il reste quelque chose de visible à l'énumération au moment de
l'appel, un `delete` ne répond jamais `404`.** C'est ce qui rend le contrôle ci-dessous
fiable, dans cette limite : une invitation que l'énumération ne montre pas encore
échappe au contrôle. Le filet complet est l'expiration des invitations (30 jours au
plus), voir « Recréer plus tard un profil du même identifiant » dans « Cas
particuliers ».

### Vérifier qu'il ne reste vraiment rien

Le `list` de l'étape 1 **ne suffit pas** : il ne voit ni les nonces, ni les invitations.
Le seul contrôle qui couvre tout, c'est de rejouer la suppression :

```powershell
Invoke-Admin @{ action = 'delete'; id = $id; confirm_id = $id }
```

* `HTTP 404 not_found` → **à l'instant de la relecture**, le magasin ne montrait plus
  rien pour ce profil : ni document, ni jeton, ni nonce, ni invitation. C'est le
  résultat attendu. Le corps porte `tombstone` : il doit valoir `true`.
* `HTTP 200 complete: true` → il restait des résidus (ou un document de profil réapparu,
  voir la limite ci-dessous), ils viennent d'être purgés. Rejoue encore une fois : tu dois
  obtenir `404`.
* `HTTP 500` → lis `remaining` et `tombstone`, et recommence quand la cause est levée.
* `HTTP 409 profile_active` **alors que tu avais bien désactivé le profil** → une
  invitation a été remise pendant la suppression (voir la limite ci-dessous). Refais
  l'étape 2 (`set-active` à `$false`), puis rejoue la suppression.

Ce contrôle **aboutit toujours** si le magasin répond : un document d'invitation abîmé
ailleurs dans le magasin ne l'empêche plus (c'était un défaut, il est corrigé).

### Limite connue : une invitation remise pendant la suppression

Si la personne utilise un code d'invitation **exactement pendant** que tu supprimes son
profil, les deux opérations se croisent. Chacune se protège de l'autre :

* `join` relit la pierre tombale **après** avoir écrit le profil ; s'il la trouve, il
  retire le document qu'il vient d'écrire et refuse le code — la clé neuve n'est remise
  à personne. Si cette relecture échoue, il répond `503` sans remettre la clé et sans
  rien supprimer (ce pourrait être un simple changement de téléphone). Le code, lui,
  est **consommé** : il ne resservira pas (voir « Connexion qui échoue après la prise
  du code (limite connue) », dans « Cas particuliers ») ;
* `delete` relit le document de profil **après** avoir posé la pierre tombale ; s'il le
  trouve, il le purge au lieu de répondre `404`.

Chacune écrit **puis** relit l'objet de l'autre : au moins une des deux voit l'autre. Cette
garantie suppose que le magasin rende immédiatement visible ce qui vient d'être écrit. Par
défaut, Netlify Blobs ne le promet pas (cohérence « à terme », sauf si la variable
`NETLIFY_BLOBS_CONSISTENCY` vaut `strong`). Dans une fenêtre très courte, un profil peut
donc encore réapparaître. **Marche à suivre, qui couvre ce cas :** désactive d'abord le
profil (étape 2) — ce qui ferme déjà l'accès —, supprime (étape 3), puis **rejoue la
suppression jusqu'à obtenir `404`**, en refaisant l'étape 2 si tu reçois
`409 profile_active`.

**Cas non couvert : `delete` puis `create` du même identifiant, coup sur coup.** La
relecture de `join` ne voit que l'état **présent** de la pierre tombale. Si tu enchaînes
`delete` **puis** `create` du même identifiant pendant qu'une remise est en vol — les deux
dans une fenêtre très courte (43 ms mesurées sur un magasin en mémoire, sans latence
réseau ; en production elle contient trois à quatre allers-retours Blobs, donc
vraisemblablement un ordre de grandeur de plus) —, la marque a été
posée puis levée avant que `join` ne la relise : la remise **réussit, sur le profil
recréé**. Selon l'ordre des écritures, soit la clé du détenteur de l'ancien code ouvre le
nouveau profil (et la clé renvoyée par `create` ne marche plus), soit l'inverse. Rien
dans le code ne l'empêche. **Consigne :** après un `delete`, **attends** avant un `create`
du même identifiant — quelques minutes suffisent pour ce cas précis, bien au-delà de la
durée d'une remise —, et émets l'invitation **après** le `create`, jamais avant. (La
consigne de « Recréer plus tard un profil du même identifiant », dans « Cas
particuliers », est plus stricte et couvre aussi ce cas.)

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
> 4. Il n'y a **qu'une seule question**. Elle porte sur tes données, enregistrées sous
>    ton profil, et sur rien d'autre.
> 5. Le compte rendu n'a que **deux formes possibles** :
>    * **« Tes données ont été supprimées de cet appareil. »** → c'est fini pour cet
>      appareil ;
>    * **« La suppression n'est pas complète : une partie de tes données est peut-être
>      encore sur cet appareil. Réessaie ; si ça persiste, contacte Enzo. »** →
>      recommence ; si le message revient, préviens Enzo.
>
>    Les deux sont suivis des trois rappels « ne sont pas supprimés » (autre appareil,
>    compte serveur, autorisation Strava).
> 6. Recommence sur **chaque appareil** où tu as utilisé l'app.

Ça fonctionne **hors-ligne** : aucun appel réseau.

### Comment l'app décide entre les deux messages

Le premier message ne s'affiche **que si une relecture le prouve**, après la
suppression :

1. chaque clé visée sous le profil est **relue absente** ;
2. le stockage, **ré-énuméré**, ne porte plus rien sous le préfixe du profil, hormis
   deux marques techniques que la suppression garde exprès : `<profil>:legacy-owner`
   (un booléen) et `<profil>:storage-removed` (une liste de noms de clés retirées,
   voir plus bas). Elles ne sont acceptées que si leur **valeur, relue**, a exactement
   la forme que l'app leur donne : `true` ou `false` pour la première, une liste dont
   chaque nom est `plan-override`, `tgcm-strava-cache` ou `tgcm-probe` pour la seconde.
   C'est ce contrôle qui permet d'affirmer qu'**aucune des deux ne contient de donnée
   d'entraînement ou de santé** ; toute autre valeur donne le second message ;
3. **aucune ancienne copie sans profil** n'est lisible pour ce profil (voir « Ce que
   cette suppression ne fait pas »).

Tout le reste donne le second message — y compris quand la cause est bénigne. L'app ne
cherche plus à dire *pourquoi* : chaque explication précise (décomptes, provenance,
promesses) avait fini par être fausse dans une combinaison d'états, sur cinq passes de
test. Cas où le second message est **attendu** et ne se résout pas en réessayant :

* **le téléphone d'Enzo** (voir ci-dessous) ;
* un stockage qui **ne sait pas lister ses clés** (l'app ne peut pas prouver qu'il ne
  reste rien) ;
* un stockage qui **ne sait pas retirer une clé** et se contente d'en écraser le contenu
  par `null` : la donnée est détruite, mais la clé est toujours là ;
* une des **deux marques techniques** du point 2 dont la valeur relue n'a pas la forme
  attendue : ni `rememberLegacyOwner()` ni `tombAdd()` ne réécrivent une valeur déjà
  présente, donc aucun geste dans l'app n'en sort — et c'est voulu, puisque l'app ne peut
  pas prouver que cette valeur ne porte pas de donnée.

Les deux cas de stockage ci-dessus ne concernent pas un iPhone (qui utilise `localStorage`).

Après la suppression, **quel que soit le message**, l'app **relit le stockage** et
affiche exactement ce qui s'y trouve encore. Une suppression partielle ne peut donc plus
laisser l'app vide alors que des séances sont toujours enregistrées — la coche suivante
les aurait écrasées. **Le plan aussi** est choisi de nouveau, comme au démarrage, à
partir du stockage : un plan importé qui vient d'être effacé ne reste ni actif, ni
affiché (« plan importé »), ni dans un export fait juste après. Le plan par défaut
reprend sa place ; l'app le prend dans sa mémoire (c'est `plan.json`, le même pour tout
le monde), sans appel réseau. Si ce plan par défaut venait du cache hors-ligne, que la
suppression vient d'effacer, la ligne de version le dit : « plan par défaut (hors-ligne,
en mémoire seulement) ». S'il n'y en a pas du tout en mémoire — app ouverte hors-ligne
avec un plan importé —, l'écran « Plan indisponible » s'affiche avec **un seul**
message, vrai : « Aucun plan n'est enregistré sur cet appareil. Touche « Réessayer »
pour charger le plan par défaut (une connexion est nécessaire). » Et si `plan.json` est
simplement **encore en route** (réseau lent) pour le chargement du plan — au démarrage,
ou après « Réessayer » —, l'app affiche « Chargement du plan… » au lieu de « Plan
indisponible », puis le plan dès son arrivée. **Exception : le bouton « Plan par
défaut ».** S'il était en cours au moment de la suppression, et qu'aucun plan n'est en
mémoire, l'app affiche « Plan indisponible » avec le message ci-dessus — c'est vrai à
cet instant —, et le plan que ce bouton télécharge est **jeté à son arrivée** (il n'est
ni affiché, ni enregistré). « Réessayer » charge alors le plan par défaut normalement.

La fenêtre de confirmation ne promet rien qu'elle ne puisse tenir : elle dit ce qui
sera effacé, ce qui ne le sera pas, et que **si une partie ne peut pas être effacée,
l'app le dira à la fin**. Sur le téléphone d'Enzo seulement, elle ajoute que ses
anciennes copies d'avant la mise à jour ne sont pas effacées et restent affichables.
(Une version précédente affirmait « l'app repart vide » : c'était faux chez Enzo et
après toute suppression partielle.)

### Ce que cette suppression ne fait pas

**Elle ne touche pas aux copies « sans profil ».** Certaines données peuvent exister sur
un appareil sous des clés qui ne portent aucun identifiant de profil : ce sont les copies
d'avant la mise à jour de l'app (chantier 3, étape 1). **Cette version ne sait pas les
effacer, et aucun chemin de code ne le peut** — la seule écriture hors préfixe de tout le
fichier est l'ancre `profile-id`, et elle ne prend même pas de nom de clé en paramètre.

En pratique, **seul le téléphone d'Enzo en porte** : ce sont ses données d'avant la
mise à jour. Les amis arrivent par invitation, et l'app n'écrit jamais d'ancienne clé —
la seule clé sans préfixe qu'elle écrive est l'ancre `profile-id`, qui ne contient qu'un
identifiant. Ces copies **restent donc sur le téléphone d'Enzo**, gelées, jusqu'à une
version prévue pour les effacer.

Une **seconde question** (« Effacer aussi tes anciennes copies ? ») a existé pendant le
développement de l'étape 5. **Elle a été retirée**, sur arbitrage d'Enzo : quatre passes
de test y ont trouvé quatre défauts différents, tous nés du croisement entre « à qui sont
ces copies », « les a-t-on gardées » et « qu'a-t-on réussi à effacer ». Le dernier était
sérieux : un effacement qui échoue laissait les copies en place, l'app affirmait ensuite
qu'elles n'étaient pas à la personne, et la marque écrite au passage refermait
définitivement la porte. Si tu croises une capture d'écran ou une note qui mentionne
cette seconde question, **elle est périmée**.

**La suppression ne ferme plus aucun « repli ».** Une version précédente écrivait
`<profil>:legacy-owner` à `false` pour que ces copies ne soient plus lues, et promettait
qu'elles ne réapparaîtraient pas. Cette écriture et cette promesse **ont été retirées**.
La marque `<profil>:legacy-owner` n'est désormais **ni effacée ni réécrite** par la
suppression :

* **pour un ami** (profil arrivé par invitation), elle vaut `false` et le reste : l'app
  ne lit jamais les copies sans profil de l'appareil, ni avant ni après, et sa première
  coche après la suppression n'enregistre que la sienne. La garder permet aussi à l'app
  de redémarrer normalement sur un appareil partagé ;
* **pour Enzo sur son propre téléphone**, elle vaut `true` : ses anciennes copies sont
  les siennes, elles restent lisibles par l'app après la suppression, et l'app les
  affiche de nouveau. Le compte rendu dit donc **« La suppression n'est pas
  complète »** — c'est vrai, et c'est voulu : ses données d'avant la mise à jour sont
  toujours sur le téléphone. Comme avant la suppression, la première coche qui suit les
  enregistre sous `enzo:`.

**État de l'app après coup :** même profil, et l'app affiche ce que le stockage contient
encore — rien pour un ami dont la suppression a réussi, et le plan par défaut à la
place d'un plan importé effacé. Elle ne repasse pas par l'écran
de première connexion : l'ancre `profile-id`, qui ne contient qu'un identifiant et aucune
donnée de santé, est conservée. Si la personne veut revenir plus tard, une nouvelle clé
d'appareil saisie dans Zones suffit — **mais si tu as fait l'étape 3, ce profil n'existe
plus, et une invitation ne suffira pas non plus** : il faut d'abord rouvrir
l'identifiant avec `create` (voir « Cas particuliers »), sans quoi `join` refusera le
code.

Le panneau **« Vérifier mes données »** (onglet Zones) ne montre à un ami **que ses
propres données** : l'app n'y lit même pas les copies sans profil, et n'affiche donc
jamais ni leur existence, ni un décompte, ni une comparaison. Seul le propriétaire prouvé
de ces copies (Enzo sur son téléphone) voit, en plus, ce que l'app lit depuis son
ancienne copie et la comparaison caractère par caractère.

Sur un stockage qui écrase au lieu de retirer, le panneau compte une clé vidée (`null`)
comme une absence — son contenu est parti — pendant que le compte rendu dit « pas
complète » — la clé, elle, est toujours là. Les deux sont exacts.

**La liste des retraits `<profil>:storage-removed` n'est pas effacée non plus.** L'app
n'y écrit que des **noms de clés** (au plus : `plan-override`, `tgcm-strava-cache`,
`tgcm-probe`), aucune donnée d'entraînement ni de santé — et la suppression le
**vérifie** : une liste qui contiendrait autre chose donne « La suppression n'est pas
complète », sans que la liste soit effacée ni réécrite. Elle se remplit **toute seule
dès le premier démarrage** : l'app vérifie qu'elle peut écrire sur une clé jetable
(`tgcm-probe`) puis la retire, et ce retrait y inscrit `tgcm-probe`. Elle se remplit
aussi quand la personne retire elle-même quelque chose : « Plan par défaut » (plan
importé retiré), « Déconnecter » Strava (cache d'activités purgé). Sur le téléphone d'Enzo, elle empêche
l'app de relire l'**ancienne** copie sans profil de ces clés. Une version précédente
l'effaçait avec le reste : l'ancien plan importé qu'Enzo avait retiré, et l'ancien cache
Strava qu'il avait purgé, réapparaissaient après la suppression. Pour un ami, elle ne
change rien : son app ne lit jamais les copies sans profil.

**Ce qui reste après cette étape**, quand le compte rendu dit « Tes données ont été
supprimées de cet appareil » : sous son profil, au plus les deux marques techniques
`<profil>:legacy-owner` (relue : `true` ou `false`) et `<profil>:storage-removed`
(relue : une liste de noms de clés parmi les trois admis) — aucune donnée ; hors profil,
l'ancre `profile-id` (un identifiant). Les copies sans profil, s'il y en a, restent (voir
« Ce que cette suppression ne fait pas »). Les autres appareils sont intacts.

Cela reste vrai **après** coup, même si une opération réseau était en cours au moment
de la suppression : synchro Strava, « Vérifier », « Connecter Strava », « Déconnecter »,
« Plan par défaut », ou chargement du plan. À son retour, elle n'écrit plus rien sous
le profil et n'affiche aucun message (auparavant, « Plan par défaut » réécrivait le cache
du plan et « Déconnecter » une liste de retraits, après le compte rendu « supprimées »).

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
* données de ses appareils : supprimées par elle sur *n* appareils (sur chacun, le
  compte rendu doit être « Tes données ont été supprimées de cet appareil. ») ;
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

**Profil déjà supprimé.** Un second `delete` répond `404 not_found` **s'il ne voit plus
rien** au moment de l'appel — l'énumération des nonces et des invitations peut être en
retard, voir « Recréer plus tard un profil du même identifiant » ci-dessous pour le filet
complet (expiration des invitations, 30 jours au plus). S'il restait des résidus
visibles, il les purge et répond `200` — c'est justement le contrôle recommandé plus
haut. Dans les deux cas, rien n'est recréé.

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

**Avant ce `create`, ce qui peut rester.** `create` lève la pierre tombale sans purger
quoi que ce soit : toute invitation encore valable pour cet identifiant redevient
utilisable, et elle régénérerait la clé du **nouveau** profil — la nouvelle personne
perdrait son accès au profit du détenteur de l'ancien code. Rejouer `delete` jusqu'à
`404` reste utile (ça purge ce qui est visible), mais ce `404` dit seulement
qu'**aucune invitation n'était visible au moment du rejeu** : l'énumération du magasin
peut être en retard et ne pas encore montrer la dernière invitation émise. Ce n'est pas
une garantie qu'il n'en reste aucune.

Le seul filet complet est l'**expiration** : une invitation cesse de fonctionner au
plus tard **30 jours après son émission** (`ttl_days` vaut 7 par défaut, 30 au maximum ;
la date exacte est dans `expires_at`, dans la réponse de `invite`). **Recommandation :
ne recrée un identifiant supprimé que 30 jours après la dernière invitation émise pour
lui** (avant ou après la suppression), **ou prends un autre identifiant** (`julie2`, par
exemple) — les données éventuellement restées sur un appareil sous l'ancien
identifiant n'apparaîtront alors pas sous le nouveau. Ce délai couvre aussi le cas
« `delete` puis `create` coup sur coup » de l'étape 3. (Faire purger ces invitations par
`create` lui-même demanderait un mécanisme nouveau ; ce n'est pas fait.) Même raison
pour l'ordre recommandé ci-dessus : une invitation émise **avant** le `create`, pendant
que l'identifiant est marqué, deviendra valable dès la levée de la marque — émets-la
plutôt **après**.

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

**« Cet appareil ne peut pas être rattaché à un profil pour l'instant ».** L'appareil
porte une ancienne clé d'appareil sans profil, au format d'avant l'étape 2 (ou vidée),
et aucune marque d'héritage : l'app ne peut pas décider à qui sont les données déjà
présentes, et elle refuse d'enregistrer un profil par-dessus. Elle le sait **avant**
d'appeler le serveur : **le code d'invitation n'est pas utilisé**, la personne peut le
garder. Elle lui dit de ne pas réessayer et de te contacter. Cette version n'a aucun
geste dans l'app pour débloquer ce cas : c'est à toi de voir à qui est cet appareil
avant toute chose. (Avant, chaque essai consommait une invitation, et le message
laissait croire que la suivante marcherait.) Si l'échec n'est pas certain à l'avance,
l'appel a lieu comme avant ; s'il échoue ensuite sur l'appareil, le message ne
promet plus qu'une nouvelle invitation suffira : il demande de t'en parler d'abord.

**Connexion qui échoue après la prise du code (limite connue).** Une
invitation prise par `join` est **consommée, point** : rien ne la rend, même si la
remise de la clé échoue ensuite. Trois façons d'y arriver :

* le stockage Netlify tombe en panne à l'écriture du profil ou à la relecture de la
  pierre tombale → « La connexion n'a pas abouti (HTTP 503 · blobs) » ;
* la fabrication de la clé échoue → « La connexion n'a pas abouti (HTTP 500 ·
  server_error) » ;
* la **réponse se perd en route** : le serveur a pu traiter la demande jusqu'au bout
  (code pris, voire clé fabriquée et profil réécrit), mais le téléphone ne reçoit
  rien → « Le serveur n'a pas répondu en 12 s » (délai dépassé) ou « Aucune réponse
  du serveur » (pas de connexion, connexion coupée, site inaccessible).

Dans tous ces cas la personne n'a pas de clé, et son code sera refusé au nouvel essai
**s'il avait été pris**. Sur un changement de téléphone, son **ancienne** clé peut aussi
avoir cessé de marcher (le profil a pu être réécrit avec la nouvelle). **Remède : envoie
un nouveau lien** (`action = 'invite'`, même `id`). Aucune donnée n'est perdue : les
séances et le journal sont sur son téléphone, le jeton Strava n'est pas touché. L'app ne
peut pas savoir si le code a été consommé ou non — sans réponse, elle ne sait même pas
si la demande est arrivée ; ses messages sont donc écrits pour être vrais dans les deux
cas, et se terminent tous les quatre par la même consigne : réessayer « avec le même
code ; s'il est refusé, demande un nouveau lien à Enzo ».
*Pourquoi on ne rend pas le code :* un mécanisme qui le rendait a existé pendant le
développement de l'étape 5, et **il a été retiré**. Un code rendu survivait à une
suppression pourtant terminée par `404`, et pouvait ensuite prendre un profil recréé plus
tard sous le même identifiant ; deux remises simultanées pouvaient rouvrir un code déjà
utilisé avec succès et tuer la clé de celui qui l'avait obtenue ; et un code pouvait
expirer pendant la remise ratée. Chacun de ces défauts était plus grave que la panne
qu'il rattrapait. Si tu croises une note qui dit « le même code resservira », **elle est
périmée**.

**Deux personnes utilisent le même code au même moment (limite connue, antérieure à
l'étape 5).** La prise du code s'écrit puis se relit ; le magasin n'offre pas d'opération
atomique pour la rendre exclusive. Si deux remises du même code se croisent exactement
(deux appareils, ou le lien ouvert dans deux onglets), les deux peuvent recevoir une
clé, et **seule la dernière écrite fonctionne**. Un même écran de connexion n'envoie
jamais deux remises à la fois ; le cas suppose donc un code utilisé à deux endroits en
même temps. Le symptôme : une personne connectée dont la clé d'appareil est ensuite
refusée par le serveur. **Remède : un nouveau lien** pour elle. Rien n'est perdu.

**Téléphone d'Enzo dans l'état « ambigu » : rejoindre un AUTRE profil (limite connue,
téléphone d'Enzo uniquement).** La vérification faite avant d'appeler le serveur
(« Cet appareil ne peut pas être rattaché à un profil pour l'instant ») ne sait
conclure que s'il n'y a **aucune** marque de profil sur l'appareil. Sur le téléphone
d'Enzo, sa propre marque `enzo:legacy-owner` existe : si l'appareil est dans l'état
« ambigu » (plusieurs profils, ancre perdue), que son ancienne clé d'appareil sans
profil n'est pas attribuable, et qu'on y utilise une invitation pour un profil **qui
n'a pas encore de marque sur cet appareil** (un nouvel ami, par exemple), l'appel a
lieu, le code est consommé, et l'app répond « L'invitation a été acceptée, mais cet
appareil n'a pas pu enregistrer ton profil ». Rien n'est effacé ni écrit sous un profil.
Le cas ne peut pas se produire ailleurs : seul le téléphone d'Enzo porte des anciennes
clés. **Remède :** ne pas rattacher d'autre profil au téléphone d'Enzo ; si c'est
arrivé, émettre un nouveau lien pour la personne et l'utiliser sur **son** appareil.
Rejoindre **son propre** profil (`enzo`) depuis ce téléphone fonctionne.

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
  `rotate`, et **elle n'est pas consultée par la vérification des clés d'accès** : ce qui
  rend une clé inutilisable, c'est l'absence du document de profil (ou sa
  désactivation). D'où l'ordre de la procédure — désactiver **avant** de supprimer — et
  le contrôle final par `404`, qui relit que le document n'existe plus (voir « Limite
  connue : une invitation remise pendant la suppression »).
* **Rien de tout cela ne touche `auth-logout`.** Il reste ce qu'il était.
